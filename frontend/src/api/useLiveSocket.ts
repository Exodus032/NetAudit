import { useEffect, useRef } from "react";
import { useSyncExternalStore } from "react";
import { liveSocket, type ConnectionState } from "./liveSocket";
import type { WsFrame } from "./types";

/** Starts (once) and reports the shared live-socket connection state. */
export function useConnectionState(): ConnectionState {
  useEffect(() => {
    liveSocket.start();
  }, []);
  return useSyncExternalStore(
    (cb) => liveSocket.onState(cb),
    () => liveSocket.getState(),
  );
}

/** Subscribes to every live frame; call-site filters by `frame.type`. Handler identity may change freely. */
export function useLiveFrames(handler: (frame: WsFrame) => void): void {
  const handlerRef = useRef(handler);
  handlerRef.current = handler;
  useEffect(() => {
    liveSocket.start();
    return liveSocket.onFrame((frame) => handlerRef.current(frame));
  }, []);
}
