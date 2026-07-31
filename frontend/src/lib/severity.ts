// Maps contract enums onto the dataviz skill's fixed status scale
// (good / warning / serious / critical). Status colors are reserved for
// state and always paired with an icon + label, never color alone.
import type { RiskLevel, Severity } from "../api/types";

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
