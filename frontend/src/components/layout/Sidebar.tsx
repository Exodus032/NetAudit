import "./Sidebar.css";

export type ViewId = "overview" | "traffic" | "connections" | "recommendations";

const NAV_ITEMS: { id: ViewId; label: string; icon: string }[] = [
  { id: "overview", label: "Overview", icon: "▤" },
  { id: "traffic", label: "Traffic log", icon: "≡" },
  { id: "connections", label: "Connections & devices", icon: "⇄" },
  { id: "recommendations", label: "Recommended actions", icon: "◆" },
];

export function Sidebar({ active, onChange }: { active: ViewId; onChange: (v: ViewId) => void }) {
  return (
    <nav className="sidebar" aria-label="Primary">
      <div className="sidebar-brand">
        <span className="sidebar-brand-mark" aria-hidden="true">◈</span>
        <span>NetAudit</span>
      </div>
      <ul className="sidebar-nav">
        {NAV_ITEMS.map((item) => (
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
      <div className="sidebar-footer">
        <span>Local network audit</span>
      </div>
    </nav>
  );
}
