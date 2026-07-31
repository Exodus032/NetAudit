// Maps contract enums onto the dataviz skill's fixed status scale
// (good / warning / serious / critical). Status colors are reserved for
// state and always paired with an icon + label, never color alone.
import type { CheckStatus, RiskLevel, Severity, ThreatStatus } from "../api/types";

export interface StatusVisual {
  colorVar: string; // CSS custom property name
  label: string;
  icon: string; // single glyph, decorative (label carries meaning)
}

export function severityVisual(severity: Severity): StatusVisual {
  switch (severity) {
    case "critical":
      return { colorVar: "--status-critical", label: "Critical", icon: "✖" }; // ✖
    case "high":
      return { colorVar: "--status-serious", label: "High", icon: "▲" }; // ▲
    case "medium":
      return { colorVar: "--status-warning", label: "Medium", icon: "▲" }; // ▲
    case "low":
      return { colorVar: "--status-good", label: "Low", icon: "●" }; // ●
    case "info":
    default:
      return { colorVar: "--text-muted", label: "Info", icon: "ℹ" }; // ℹ
  }
}

export function riskVisual(risk: RiskLevel): StatusVisual {
  switch (risk) {
    case "high":
      return { colorVar: "--status-critical", label: "High risk", icon: "✖" };
    case "medium":
      return { colorVar: "--status-warning", label: "Medium risk", icon: "▲" };
    case "low":
    default:
      return { colorVar: "--status-good", label: "Low risk", icon: "●" };
  }
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Posture check status — deliberately NOT derived from severity. `error`
 * and `skipped` mean "couldn't check" and get a neutral/muted treatment with
 * wording that says so, so they never read as "insecure" the way `fail`
 * does. */
export function checkStatusVisual(status: CheckStatus): StatusVisual {
  switch (status) {
    case "pass":
      return { colorVar: "--status-good", label: "Pass", icon: "✓" };
    case "warn":
      return { colorVar: "--status-warning", label: "Warn", icon: "▲" };
    case "fail":
      return { colorVar: "--status-critical", label: "Fail", icon: "✖" };
    case "error":
      return { colorVar: "--text-muted", label: "Couldn't check", icon: "?" };
    case "skipped":
    default:
      return { colorVar: "--text-muted", label: "Skipped", icon: "–" };
  }
}

export function threatStatusVisual(status: ThreatStatus): StatusVisual {
  switch (status) {
    case "active":
      return { colorVar: "--status-critical", label: "Active", icon: "●" };
    case "acknowledged":
      return { colorVar: "--status-warning", label: "Acknowledged", icon: "✓" };
    case "resolved":
    default:
      return { colorVar: "--status-good", label: "Resolved", icon: "✓" };
  }
}
