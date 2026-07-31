// Singleton live-data manager. Wraps the real `/ws/live` websocket with
// exponential backoff reconnect, and transparently swaps to the in-memory
// mock ticker (src/mocks/store.ts) when mocks are forced or the real socket
// can't be reached after a few attempts. Frames are fanned out to any number
// of subscribers regardless of type, order, or gaps.

import { getBackendMode, setBackendMode } from "./backendMode";
import { ensureToken, invalidateToken } from "./auth";
import { startMockTicker, subscribe as subscribeMockTicker } from "../mocks/store";
import type { WsFrame } from "./types";

export type ConnectionState = "connecting" | "open" | "reconnecting" | "closed";

const FORCE_MOCKS = import.meta.env.VITE_USE_MOCKS === "1";
const MAX_REAL_ATTEMPTS = 3;
const BASE_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 30_000;

type FrameHandler = (frame: WsFrame) => void;
type StateHandler = (state: ConnectionState) => void;

class LiveSocketManager {
  private ws: WebSocket | null = null;
  private frameHandlers = new Set<FrameHandler>();
  private stateHandlers = new Set<StateHandler>();
  private state: ConnectionState = "connecting";
  private attempts = 0;
  private usingMock = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private unsubMock: (() => void) | null = null;
  private started = false;

  start(): void {
    if (this.started) return;
    this.started = true;
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
  }

  /** Tears down whichever transport is active. Not currently called by the
   * app (the manager lives for the page's lifetime) but keeps cleanup
   * centralized for tests / future use. */
  dispose(): void {
    this.unsubMock?.();
    this.unsubMock = null;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.ws?.close();
    this.ws = null;
  }

  private async connectReal() {
    if (this.usingMock) return;
    this.setState(this.attempts === 0 ? "connecting" : "reconnecting");

    // Per docs/API_CONTRACT_V2_SECURITY.md Part C item 2: the socket must
    // carry the bootstrap token as ?token=. If we can't get one, treat it the
    // same as any other connect failure (backoff, eventually fall to mocks).
    let token: string;
    try {
      token = await ensureToken();
    } catch {
      this.handleRealFailure();
      return;
    }
    if (this.usingMock) return; // a mock fallback may have started while we awaited

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${proto}//${window.location.host}/ws/live?token=${encodeURIComponent(token)}`;
    let socket: WebSocket;
    try {
      socket = new WebSocket(url);
    } catch {
      this.handleRealFailure();
      return;
    }
    this.ws = socket;

    socket.addEventListener("open", () => {
      this.attempts = 0;
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
      if (this.usingMock) return;
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
    if (this.attempts >= MAX_REAL_ATTEMPTS && getBackendMode() !== "real") {
      this.connectMock();
      return;
    }
    this.setState("reconnecting");
    const backoff = Math.min(MAX_BACKOFF_MS, BASE_BACKOFF_MS * 2 ** (this.attempts - 1));
    const jitter = backoff * (0.85 + Math.random() * 0.3);
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = setTimeout(() => this.connectReal(), jitter);
  }
}

export const liveSocket = new LiveSocketManager();
