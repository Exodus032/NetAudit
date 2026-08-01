import { LEARN_NAV_ITEMS } from "../../views/Learn";
import { PRO_NAV_ITEMS } from "../../views/Pro";
import "./Sidebar.css";

export type ViewId = string;

export interface NavItem {
  id: ViewId;
  label: string;
  icon: string;
}

/** The six views that were the whole app in v1. Everything here is about
 *  what this machine is doing right now. */
const MONITOR_ITEMS: NavItem[] = [
  { id: "overview", label: "Overview", icon: "▤" },
  { id: "traffic", label: "Traffic log", icon: "≡" },
  { id: "connections", label: "Connections & devices", icon: "⇄" },
  { id: "recommendations", label: "Recommended actions", icon: "◆" },
  { id: "posture", label: "Security posture", icon: "⛨" },
  { id: "threats", label: "Threats", icon: "⚠" },
];

/** Eighteen flat links is a wall. Grouping splits the sidebar by what you
 *  came here to do: watch the network, learn how it works, or run a piece
 *  of professional workflow over it. */
const NAV_SECTIONS: { label: string; items: NavItem[] }[] = [
  { label: "Monitor", items: MONITOR_ITEMS },
  { label: "Learn", items: LEARN_NAV_ITEMS },
  { label: "Professional", items: PRO_NAV_ITEMS },
];

export const ALL_NAV_ITEMS: NavItem[] = NAV_SECTIONS.flatMap((s) => s.items);

export const VIEW_TITLES: Record<string, string> = Object.fromEntries(
  ALL_NAV_ITEMS.map((item) => [item.id, item.label]),
);

export function Sidebar({ active, onChange }: { active: ViewId; onChange: (v: ViewId) => void }) {
  return (
    <nav className="sidebar" aria-label="Primary">
      <div className="sidebar-brand">
        <span className="sidebar-brand-mark" aria-hidden="true">◈</span>
        <span>NetAudit</span>
      </div>
      <div className="sidebar-scroll">
        {NAV_SECTIONS.map((section) => (
          <div className="sidebar-section" key={section.label}>
            <h2 className="sidebar-section-label">{section.label}</h2>
            <ul className="sidebar-nav">
              {section.items.map((item) => (
                <li key={item.id}>
                  <button
                    className={`sidebar-link${active === item.id ? " active" : ""}`}
                    onClick={() => onChange(item.id)}
                    aria-current={active === item.id ? "page" : undefined}
                  >
                    <span className="sidebar-icon" aria-hidden="true">{item.icon}</span>
                    {item.label}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      <div className="sidebar-footer">
        <span>Local network audit</span>
      </div>
    </nav>
  );
}
