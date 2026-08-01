import type { CaptureStatus } from "../../api/types";
import "./DegradedBanner.css";

const MODE_EXPLANATION: Record<CaptureStatus["mode"], string> = {
  npcap: "Full packet capture is active — all protocols, both directions, process attribution.",
  rawsocket: "Running on raw sockets: IPv4 packet headers only via promiscuous capture. Install Npcap and run as Administrator for full protocol coverage and process attribution.",
  polling: "Running in polling mode: connection-table deltas only (flows and byte counts), no per-packet detail. Install Npcap and run as Administrator to enable full capture.",
  off: "Capture is off. No traffic is being observed.",
};

export function DegradedBanner({ capture }: { capture: CaptureStatus }) {
  const isDegraded = capture.mode !== "npcap" || !capture.elevated;
  if (!isDegraded) return null;

  return (
    <div className="degraded-banner" data-tour="capture-tier-banner" role="alert">
      <span className="degraded-icon" aria-hidden="true">▲</span>
      <div className="degraded-body">
        <div className="degraded-title">
          Running in reduced-visibility mode ({capture.mode}
          {!capture.elevated ? ", not elevated" : ""})
        </div>
        {capture.degraded_reason && <div className="degraded-reason">{capture.degraded_reason}</div>}
        <div className="degraded-explain">{MODE_EXPLANATION[capture.mode]}</div>
      </div>
    </div>
  );
}
