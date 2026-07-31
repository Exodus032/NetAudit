import { useMemo } from "react";
import { useConnections } from "../../hooks/useConnections";
import { RiskBadge } from "../../components/common/Badge";
import { SkeletonRows, EmptyState, ErrorState } from "../../components/common/States";
import { formatBytes, formatRelativeTime } from "../../lib/format";
import type { Connection } from "../../api/types";
import "./ConnectionsPanel.css";

function groupByProcess(connections: Connection[]): Map<string, Connection[]> {
  const groups = new Map<string, Connection[]>();
  for (const c of connections) {
    const key = `${c.process_name} (pid ${c.pid})`;
    const arr = groups.get(key) ?? [];
    arr.push(c);
    groups.set(key, arr);
  }
  return groups;
}

export function ConnectionsPanel() {
  const { connections, loading, error } = useConnections();

  const groups = useMemo(() => {
    const grouped = groupByProcess(connections);
    return Array.from(grouped.entries())
      .map(([process, conns]) => ({
        process,
        conns: conns.sort((a, b) => b.bytes_in + b.bytes_out - (a.bytes_in + a.bytes_out)),
        totalBytes: conns.reduce((s, c) => s + c.bytes_in + c.bytes_out, 0),
      }))
      .sort((a, b) => b.totalBytes - a.totalBytes);
  }, [connections]);

  if (error) return <ErrorState title="Couldn't load connections" detail={error} />;
  if (loading && connections.length === 0) return <SkeletonRows rows={8} height={26} />;
  if (!loading && connections.length === 0) return <EmptyState title="No active connections" detail="Connections will appear as traffic flows." />;

  return (
    <div className="conn-groups">
      {groups.map((g) => (
        <div className="conn-group" key={g.process}>
          <div className="conn-group-header">
            <span className="conn-group-process">{g.process}</span>
            <span className="conn-group-total tabular">{formatBytes(g.totalBytes)}</span>
          </div>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>State</th>
                  <th>Peer</th>
                  <th>Direction</th>
                  <th>In</th>
                  <th>Out</th>
                  <th>Last seen</th>
                  <th>Risk</th>
                </tr>
              </thead>
              <tbody>
                {g.conns.map((c) => (
                  <tr key={c.id}>
                    <td>{c.state}</td>
                    <td className="mono">
                      {c.remote_host && c.remote_host !== c.remote_addr ? `${c.remote_host} (${c.remote_addr})` : c.remote_addr}
                      :{c.remote_port}
                    </td>
                    <td>{c.direction}</td>
                    <td className="tabular">{formatBytes(c.bytes_in)}</td>
                    <td className="tabular">{formatBytes(c.bytes_out)}</td>
                    <td className="tabular">{formatRelativeTime(c.last_seen)}</td>
                    <td><RiskBadge risk={c.risk} reasons={c.risk_reasons} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ))}
    </div>
  );
}
