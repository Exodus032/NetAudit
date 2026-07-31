import type { Severity, ThreatCategory, ThreatStatus } from "../../api/types";
import "./ThreatFilters.css";

const CATEGORY_OPTIONS: { value: ThreatCategory; label: string }[] = [
  { value: "command_and_control", label: "Command & control" },
  { value: "exfiltration", label: "Exfiltration" },
  { value: "reconnaissance", label: "Reconnaissance" },
  { value: "lateral_movement", label: "Lateral movement" },
  { value: "credential_exposure", label: "Credential exposure" },
  { value: "dns_abuse", label: "DNS abuse" },
  { value: "spoofing", label: "Spoofing" },
  { value: "malicious_peer", label: "Malicious peer" },
  { value: "policy_violation", label: "Policy violation" },
  { value: "anomaly", label: "Anomaly" },
];

export interface ThreatFilterState {
  q: string;
  severity: Severity | "";
  category: ThreatCategory | "";
  status: ThreatStatus | "";
  includeAcknowledged: boolean;
}

export function ThreatFilters({
  filters,
  onChange,
  totalLabel,
}: {
  filters: ThreatFilterState;
  onChange: (next: ThreatFilterState) => void;
  totalLabel: string;
}) {
  const set = <K extends keyof ThreatFilterState>(key: K, value: ThreatFilterState[K]) => onChange({ ...filters, [key]: value });

  return (
    <div className="threat-filters">
      <input
        type="search"
        className="threat-filter-input threat-filter-q"
        placeholder="Search title or summary…"
        value={filters.q}
        onChange={(e) => set("q", e.target.value)}
        aria-label="Search threats"
      />
      <select
        className="threat-filter-input"
        value={filters.severity}
        onChange={(e) => set("severity", e.target.value as ThreatFilterState["severity"])}
        aria-label="Filter by severity"
      >
        <option value="">All severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="info">Info</option>
      </select>
      <select
        className="threat-filter-input"
        value={filters.category}
        onChange={(e) => set("category", e.target.value as ThreatFilterState["category"])}
        aria-label="Filter by category"
      >
        <option value="">All categories</option>
        {CATEGORY_OPTIONS.map((c) => (
          <option key={c.value} value={c.value}>{c.label}</option>
        ))}
      </select>
      <select
        className="threat-filter-input"
        value={filters.status}
        onChange={(e) => set("status", e.target.value as ThreatFilterState["status"])}
        aria-label="Filter by status"
      >
        <option value="">All statuses</option>
        <option value="active">Active</option>
        <option value="acknowledged">Acknowledged</option>
        <option value="resolved">Resolved</option>
      </select>
      <label className="threat-filter-toggle">
        <input
          type="checkbox"
          checked={filters.includeAcknowledged}
          onChange={(e) => set("includeAcknowledged", e.target.checked)}
        />
        Include acknowledged
      </label>
      <div className="threat-filter-spacer" />
      <span className="threat-filter-total">{totalLabel}</span>
    </div>
  );
}
