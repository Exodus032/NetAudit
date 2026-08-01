import { Drawer } from "../../components/common/Drawer";
import { RiskBadge } from "../../components/common/Badge";
import { ExplainChip } from "../../components/learn/ExplainChip";
import type { TrafficLogEntry } from "../../api/types";
import { formatBytes, formatDateTime } from "../../lib/format";
import "./LogDetailDrawer.css";

export function LogDetailDrawer({ entry, onClose }: { entry: TrafficLogEntry | null; onClose: () => void }) {
  return (
    <Drawer open={entry !== null} onClose={onClose} title={entry ? `Packet #${entry.id}` : "Detail"}>
      {entry && (
        <div className="log-detail" data-tour="traffic-log-row-detail">
          <div className="log-detail-summary">{entry.summary}</div>
          <dl className="log-detail-grid">
            <dt>Time</dt>
            <dd className="tabular">{formatDateTime(entry.ts)}</dd>
            <dt>Protocol</dt>
            <dd>{entry.protocol.toUpperCase()}</dd>
            <dt>Direction</dt>
            <dd>{entry.direction}</dd>
            <dt>Source</dt>
            <dd className="mono">{entry.src_addr}:{entry.src_port}</dd>
            <dt>Destination</dt>
            <dd className="mono">{entry.dst_addr}:{entry.dst_port}</dd>
            <dt>Remote host</dt>
            <dd>{entry.remote_host || "—"}</dd>
            <dt>Length</dt>
            <dd className="tabular">{formatBytes(entry.length)}</dd>
            <dt>Flags</dt>
            <dd className="mono">{entry.flags || "—"}</dd>
            <dt>Process</dt>
            <dd>{entry.process_name} (pid {entry.pid})</dd>
            <dt>External</dt>
            <dd>{entry.is_external ? "Yes" : "No (local network)"}</dd>
            <dt>Encrypted</dt>
            <dd>{entry.is_encrypted ? "Yes" : "No"}</dd>
            <dt>
              Risk
              <ExplainChip kind="metric" id="risk" label="Risk" />
            </dt>
            <dd><RiskBadge risk={entry.risk} /></dd>
          </dl>
        </div>
      )}
    </Drawer>
  );
}
