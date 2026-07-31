import type { RiskLevel, Severity } from "../../api/types";
import { riskVisual, severityVisual } from "../../lib/severity";
import "./Badge.css";

export function SeverityBadge({ severity }: { severity: Severity }) {
  const v = severityVisual(severity);
  return (
    <span className="badge" style={{ color: `var(${v.colorVar})`, borderColor: `var(${v.colorVar})` }}>
      <span aria-hidden="true">{v.icon}</span> {v.label}
    </span>
  );
}

export function RiskBadge({ risk, reasons }: { risk: RiskLevel; reasons?: string[] }) {
  const v = riskVisual(risk);
  const title = reasons && reasons.length ? reasons.join("; ") : undefined;
  return (
    <span className="badge" title={title} style={{ color: `var(${v.colorVar})`, borderColor: `var(${v.colorVar})` }}>
      <span aria-hidden="true">{v.icon}</span> {v.label}
    </span>
  );
}

export function CategoryChip({ category }: { category: string }) {
  return <span className="chip">{category.replace(/_/g, " ")}</span>;
}

export function ProtocolTag({ protocol }: { protocol: string }) {
  return <span className="tag mono">{protocol.toUpperCase()}</span>;
}
