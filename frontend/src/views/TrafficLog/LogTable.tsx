import { useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { TrafficLogEntry } from "../../api/types";
import { RiskBadge } from "../../components/common/Badge";
import { formatBytes, formatTime } from "../../lib/format";
import "./LogTable.css";

interface LogTableProps {
  entries: TrafficLogEntry[];
  sort: "time" | "bytes";
  order: "asc" | "desc";
  onSortChange: (sort: "time" | "bytes", order: "asc" | "desc") => void;
  onRowClick: (entry: TrafficLogEntry) => void;
  onScrollStateChange: (scrolledAway: boolean) => void;
  selectedId: number | null;
}

function peerPort(e: TrafficLogEntry): number {
  return e.direction === "inbound" ? e.src_port : e.dst_port;
}

// Shared column widths (px) so the header <table> and each virtualized row's
// own <table> layout context stay aligned.
const COLS = [
  { key: "time", label: "Time", width: 96, sortable: true },
  { key: "protocol", label: "Proto", width: 56, sortable: false },
  { key: "direction", label: "Dir", width: 76, sortable: false },
  { key: "source", label: "Source", width: 150, sortable: false },
  { key: "destination", label: "Destination", width: 150, sortable: false },
  { key: "remote_host", label: "Remote host", width: 170, sortable: false },
  { key: "port", label: "Port", width: 64, sortable: false },
  { key: "process", label: "Process", width: 130, sortable: false },
  { key: "bytes", label: "Bytes", width: 90, sortable: true },
  { key: "risk", label: "Risk", width: 108, sortable: false },
] as const;

const ROW_WIDTH = COLS.reduce((s, c) => s + c.width, 0);

export function LogTable({ entries, sort, order, onSortChange, onRowClick, onScrollStateChange, selectedId }: LogTableProps) {
  const parentRef = useRef<HTMLDivElement>(null);

  const virtualizer = useVirtualizer({
    count: entries.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 32,
    overscan: 12,
  });

  const handleHeaderClick = (col: "time" | "bytes") => {
    if (sort === col) onSortChange(col, order === "asc" ? "desc" : "asc");
    else onSortChange(col, "desc");
  };

  const handleScroll = () => {
    const el = parentRef.current;
    if (!el) return;
    onScrollStateChange(el.scrollTop > 24);
  };

  const items = virtualizer.getVirtualItems();

  return (
    <div className="log-table-container scroll-y" ref={parentRef} onScroll={handleScroll}>
      <table className="data-table log-table" role="table" aria-label="Traffic log entries" aria-rowcount={entries.length} style={{ minWidth: ROW_WIDTH }}>
        <colgroup>
          {COLS.map((c) => (
            <col key={c.key} style={{ width: c.width }} />
          ))}
        </colgroup>
        <thead>
          <tr>
            {COLS.map((c) =>
              c.sortable ? (
                <th key={c.key}>
                  <button
                    onClick={() => handleHeaderClick(c.key as "time" | "bytes")}
                    aria-sort={sort === c.key ? (order === "asc" ? "ascending" : "descending") : "none"}
                  >
                    {c.label} {sort === c.key && (order === "asc" ? "↑" : "↓")}
                  </button>
                </th>
              ) : (
                <th key={c.key}>{c.label}</th>
              ),
            )}
          </tr>
        </thead>
      </table>
      <div style={{ position: "relative", height: virtualizer.getTotalSize(), minWidth: ROW_WIDTH }}>
        <table className="data-table log-table log-table-body" style={{ minWidth: ROW_WIDTH }}>
          <colgroup>
            {COLS.map((c) => (
              <col key={c.key} style={{ width: c.width }} />
            ))}
          </colgroup>
          <tbody>
            {items.map((vi) => {
              const e = entries[vi.index];
              return (
                <tr
                  key={e.id}
                  data-index={vi.index}
                  onClick={() => onRowClick(e)}
                  tabIndex={0}
                  onKeyDown={(ev) => {
                    if (ev.key === "Enter" || ev.key === " ") {
                      ev.preventDefault();
                      onRowClick(e);
                    }
                  }}
                  className={`log-row${selectedId === e.id ? " selected" : ""}`}
                  style={{ position: "absolute", top: 0, left: 0, right: 0, transform: `translateY(${vi.start}px)` }}
                  aria-label={`${e.protocol} ${e.direction} ${e.remote_host || e.dst_addr}, ${formatBytes(e.length)}, ${e.risk} risk`}
                >
                  <td className="mono tabular">{formatTime(e.ts)}</td>
                  <td>{e.protocol.toUpperCase()}</td>
                  <td>{e.direction}</td>
                  <td className="mono">{e.src_addr}</td>
                  <td className="mono">{e.dst_addr}</td>
                  <td>{e.remote_host || "—"}</td>
                  <td className="mono tabular">{peerPort(e)}</td>
                  <td>{e.process_name}</td>
                  <td className="tabular">{formatBytes(e.length)}</td>
                  <td><RiskBadge risk={e.risk} /></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
