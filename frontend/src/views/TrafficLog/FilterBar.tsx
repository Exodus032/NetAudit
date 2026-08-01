import type { ConnectionDirection } from "../../api/types";
import "./FilterBar.css";

export interface LogFilters {
  q: string;
  protocol: string; // "" = all
  direction: ConnectionDirection | "";
  minBytes: string;
  timeRange: "5m" | "15m" | "1h" | "24h" | "all";
}

interface FilterBarProps {
  filters: LogFilters;
  onChange: (next: LogFilters) => void;
  liveTailOn: boolean;
  onToggleLiveTail: () => void;
  onExport: (format: "csv" | "json") => void;
  totalLabel: string;
}

export function FilterBar({ filters, onChange, liveTailOn, onToggleLiveTail, onExport, totalLabel }: FilterBarProps) {
  const set = <K extends keyof LogFilters>(key: K, value: LogFilters[K]) => onChange({ ...filters, [key]: value });

  return (
    <div className="filter-bar" data-tour="traffic-log-filter">
      <input
        type="search"
        className="filter-input filter-q"
        placeholder="Search host, process, port, address…"
        value={filters.q}
        onChange={(e) => set("q", e.target.value)}
        aria-label="Free-text search"
      />
      <select className="filter-input" value={filters.protocol} onChange={(e) => set("protocol", e.target.value)} aria-label="Protocol filter">
        <option value="">All protocols</option>
        <option value="tcp">TCP</option>
        <option value="udp">UDP</option>
        <option value="icmp">ICMP</option>
        <option value="other">Other</option>
      </select>
      <select
        className="filter-input"
        value={filters.direction}
        onChange={(e) => set("direction", e.target.value as LogFilters["direction"])}
        aria-label="Direction filter"
      >
        <option value="">Any direction</option>
        <option value="inbound">Inbound</option>
        <option value="outbound">Outbound</option>
        <option value="local">Local</option>
      </select>
      <input
        type="number"
        min={0}
        className="filter-input filter-bytes"
        placeholder="Min bytes"
        value={filters.minBytes}
        onChange={(e) => set("minBytes", e.target.value)}
        aria-label="Minimum bytes"
      />
      <select
        className="filter-input"
        value={filters.timeRange}
        onChange={(e) => set("timeRange", e.target.value as LogFilters["timeRange"])}
        aria-label="Time range"
      >
        <option value="5m">Last 5m</option>
        <option value="15m">Last 15m</option>
        <option value="1h">Last 1h</option>
        <option value="24h">Last 24h</option>
        <option value="all">All time</option>
      </select>

      <div className="filter-spacer" />
      <span className="filter-total">{totalLabel}</span>
      <button
        className={`filter-tail-btn${liveTailOn ? " active" : ""}`}
        onClick={onToggleLiveTail}
        aria-pressed={liveTailOn}
      >
        <span className="filter-tail-dot" aria-hidden="true" />
        Live tail
      </button>
      <div className="filter-export">
        <button className="filter-export-btn" onClick={() => onExport("csv")}>Export CSV</button>
        <button className="filter-export-btn" onClick={() => onExport("json")}>JSON</button>
      </div>
    </div>
  );
}
