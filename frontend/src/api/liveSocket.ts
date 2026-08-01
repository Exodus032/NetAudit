// Singleton live-data manager. Wraps the real `/ws/live` websocket with
// exponential backoff reconnect, and transparently swaps to the in-memory
// mock ticker (src/mocks/store.ts) when mocks are forced or the real socket
// can't be reached after a few attempts. Mock mode is never a one-way door:
// while on mock frames the manager keeps probing the real socket in the
// background, and jumps back immediately once REST reports the backend is
// reachable. Frames are fanned out to any number of subscribers regardless
// of type, order, or gaps.

import { getBackendMode, setBackendMode, subscribeBackendMode } from "./backendMode";
import { ensureToken, invalidateToken } from "./auth";
import { startMockTicker, stopMockTicker, subscribe as subscribeMockTicker } from "../mocks/store";
import type { WsFrame } from "./types";

export type ConnectionState = "connecting" | "open" | "reconnecting" | "closed";

const FORCE_MOCKS = import.meta.env.VITE_USE_MOCKS === "1";
const MAX_REAL_ATTEMPTS = 3;
const BASE_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 30_000;
const MOCK_RETRY_MS = 30_000;

type FrameHandler = (frame: WsFrame) => void;
type StateHandler = (state: ConnectionState) => void;

class LiveSocketManager {
  private ws: WebSocket | null = null;
  private frameHandlers = new Set<FrameHandler>();
  private stateHandlers = new Set<StateHandler>();
  private state: ConnectionState = "connecting";
  private attempts = 0;
  private usingMock = false;
  private connectingReal = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private mockRetryTimer: ReturnType<typeof setInterval> | null = null;
  private unsubMock: (() => void) | null = null;
  private unsubBackendMode: (() => void) | null = null;
  private started = false;

  start(): void {
    if (this.started) return;
    this.started = true;
    if (!FORCE_MOCKS) {
      // If REST reaches the real backend while we're feeding mock frames,
      // those fabricated frames would silently overwrite real data — drop
      // them and reconnect the real socket instead.
      this.unsubBackendMode = subscribeBackendMode(() => {
        if (getBackendMode() === "real" && this.usingMock) this.resumeReal();
      });
    }
    if (FORCE_MOCKS || getBackendMode() === "fallback-mock") {
      this.connectMock();
    } else {
      this.connectReal();
    }
  }

  getState(): ConnectionState {
    return this.state;
  }

  onFrame(fn: FrameHandler): () => void {
    this.frameHandlers.add(fn);
    return () => this.frameHandlers.delete(fn);
  }

  onState(fn: StateHandler): () => void {
    this.stateHandlers.add(fn);
    fn(this.state);
    return () => this.stateHandlers.delete(fn);
  }

  private setState(s: ConnectionState) {
    this.state = s;
    for (const h of this.stateHandlers) h(s);
  }

  private emit(frame: WsFrame) {
    for (const h of this.frameHandlers) h(frame);
  }

  private connectMock() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.usingMock = true;
    setBackendMode(FORCE_MOCKS ? "forced-mock" : "fallback-mock");
    startMockTicker();
    this.setState("connecting");
    // simulate a brief connect handshake so the UI's connecting state is visible
    setTimeout(() => {
      if (!this.usingMock) return;
      this.setState("open");
      this.unsubMock?.();
      this.unsubMock = subscribeMockTicker((frame) => this.emit(frame as WsFrame));
    }, 250);
    // Keep probing the real socket while in fallback mock mode. connectReal()
    // leaves the mock feed running until a real connection actually opens.
    if (!FORCE_MOCKS && !this.mockRetryTimer) {
      this.mockRetryTimer = setInterval(() => this.connectReal(), MOCK_RETRY_MS);
    }
  }

  /** Stops mock frame delivery, the mock ticker, and the background retry
   * loop. Called the moment real data takes over so no fabricated frame can
   * be delivered alongside (or after) real ones. */
  private detachMock() {
    this.usingMock = false;
    this.unsubMock?.();
    this.unsubMock = null;
    if (this.mockRetryTimer) {
      clearInterval(this.mockRetryTimer);
      this.mockRetryTimer = null;
    }
    stopMockTicker();
  }

  /** REST reached the real backend while we were on mock frames: stop the
   * fabricated feed immediately and reconnect the real socket. */
  private resumeReal() {
    if (!this.usingMock) return;
    this.detachMock();
    this.attempts = 0;
    this.setState("reconnecting");
    this.connectReal();
  }

  /** Tears down whichever transport is active. Not currently called by the
   * app (the manager lives for the page's lifetime) but keeps cleanup
   * centralized for tests / future use. */
  dispose(): void {
    this.unsubMock?.();
    this.unsubMock = null;
    this.unsubBackendMode?.();
    this.unsubBackendMode = null;
    clearTimeout(this.reconnectTimer ?? undefined);
    clearInterval(this.mockRetryTimer ?? undefined);
    this.reconnectTimer = null;
    this.mockRetryTimer = null;
    this.ws?.close();
    this.ws = null;
  }

  private async connectReal() {
    if (this.connectingReal || this.ws) return;
    this.connectingReal = true;
    // When probing from mock mode, keep the mock feed (and its "open" state)
    // running; subscribers only switch over once the real socket opens.
    if (!this.usingMock) this.setState(this.attempts === 0 ? "connecting" : "reconnecting");

    // Per docs/API_CONTRACT_V2_SECURITY.md Part C item 2: the socket must
    // carry the bootstrap token as ?token=. If we can't get one, treat it the
    // same as any other connect failure (backoff, eventually fall to mocks).
    let token: string;
    try {
      token = await ensureToken();
    } catch {
      this.connectingReal = false;
      this.handleRealFailure();
      return;
    }

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${proto}//${window.location.host}/ws/live?token=${encodeURIComponent(token)}`;
    let socket: WebSocket;
    try {
      socket = new WebSocket(url);
    } catch {
      this.connectingReal = false;
      this.handleRealFailure();
      return;
    }
    this.ws = socket;
    this.connectingReal = false;

    socket.addEventListener("open", () => {
      this.attempts = 0;
      // A real connection is live: the mock feed (if any) stops here.
      this.detachMock();
      setBackendMode("real");
      this.setState("open");
      try {
        socket.send(JSON.stringify({ type: "subscribe", channels: ["stats", "log", "alerts", "connections", "capture"] }));
      } catch {
        // best-effort; backend may ignore or not require this
      }
    });

    socket.addEventListener("message", (ev) => {
      try {
        const frame = JSON.parse(ev.data) as WsFrame;
        if (frame && typeof frame.type === "string") this.emit(frame);
      } catch {
        // ignore malformed frames rather than tearing down the connection
      }
    });

    socket.addEventListener("close", () => {
      if (this.ws !== socket) return; // superseded (e.g. mock fallback closed us)
      this.handleRealFailure();
    });

    socket.addEventListener("error", () => {
      // "close" always follows "error" for browser WebSocket; let close handle retry
    });
  }

  private handleRealFailure() {
    this.ws = null;
    this.attempts += 1;
    // The token may be stale (backend restarted, rotated it) or simply wrong
    // — drop it so the next attempt re-bootstraps rather than retrying the
    // same rejected token in a loop.
    invalidateToken();
    if (this.usingMock) {
      // A background probe from mock mode failed — stay on the mock feed and
      // let the retry timer (or a REST success) trigger the next attempt.
      return;
    }
    if (this.attempts >= MAX_REAL_ATTEMPTS && getBackendMode() !== "real") {
      this.connectMock();
      return;
    }
    this.setState("reconnecting");
    const backoff = Math.min(MAX_BACKOFF_MS, BASE_BACKOFF_MS * 2 ** (this.attempts - 1));
    const jitter = backoff * (0.85 + Math.random() * 0.3);
    clearTimeout(this.reconnectTimer ?? undefined);
    this.reconnectTimer = setTimeout(() => this.connectReal(), jitter);
  }
}

export const liveSocket = new LiveSocketManager();
