import { useDevices } from "../../hooks/useDevices";
import { RiskBadge } from "../../components/common/Badge";
import { SkeletonRows, EmptyState, ErrorState } from "../../components/common/States";
import { formatBytes, formatRelativeTime } from "../../lib/format";
import "./DevicesPanel.css";

export function DevicesPanel() {
  const { devices, loading, error } = useDevices();

  if (error) return <ErrorState title="Couldn't load devices" detail={error} />;
  if (loading && devices.length === 0) return <SkeletonRows rows={6} height={26} />;
  if (!loading && devices.length === 0) return <EmptyState title="No devices discovered yet" />;

  return (
    <div className="table-container">
      <table className="data-table">
        <thead>
          <tr>
            <th>IP</th>
            <th>MAC</th>
            <th>Vendor</th>
            <th>Hostname</th>
            <th>Open ports</th>
            <th>Last seen</th>
            <th>Total bytes</th>
            <th>Badges</th>
            <th>Risk</th>
          </tr>
        </thead>
        <tbody>
          {devices.map((d) => (
            <tr key={d.ip}>
              <td className="mono">{d.ip}</td>
              <td className="mono">{d.mac}</td>
              <td>{d.vendor || "—"}</td>
              <td>{d.hostname || "—"}</td>
              <td className="mono">{d.open_ports.length ? d.open_ports.join(", ") : "—"}</td>
              <td className="tabular">{formatRelativeTime(d.last_seen)}</td>
              <td className="tabular">{formatBytes(d.bytes_total)}</td>
              <td>
                {d.is_gateway && <span className="device-flag device-flag-gateway">Gateway</span>}
                {d.is_self && <span className="device-flag device-flag-self">This device</span>}
              </td>
              <td><RiskBadge risk={d.risk} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
