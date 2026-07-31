import { useSyncExternalStore } from "react";
import type { ConnectionState } from "../../api/liveSocket";
import { getBackendMode, subscribeBackendMode } from "../../api/backendMode";
import type { Theme } from "../../state/useTheme";
import "./Header.css";

const VIEW_TITLES: Record<string, string> = {
  overview: "Overview",
  traffic: "Traffic log",
  connections: "Connections & devices",
  recommendations: "Recommended actions",
  posture: "Security posture",
  threats: "Threats",
};

const STATE_LABEL: Record<ConnectionState, string> = {
  connecting: "Connecting…",
  open: "Live",
  reconnecting: "Reconnecting…",
  closed: "Disconnected",
};

export function Header({
  viewId,
  connectionState,
  theme,
  onToggleTheme,
}: {
  viewId: string;
  connectionState: ConnectionState;
  theme: Theme;
  onToggleTheme: () => void;
}) {
  const backendMode = useSyncExternalStore(subscribeBackendMode, getBackendMode);
  const usingMocks = backendMode === "forced-mock" || backendMode === "fallback-mock";

  return (
    <header className="app-header">
      <h1 className="app-header-title">{VIEW_TITLES[viewId] ?? "NetAudit"}</h1>
      <div className="app-header-actions">
        {usingMocks && <span className="mock-pill">Mock data</span>}
        <span className={`conn-indicator conn-${connectionState}`}>
          <span className="conn-dot" aria-hidden="true" />
          {STATE_LABEL[connectionState]}
        </span>
        <button
          className="theme-toggle"
          onClick={onToggleTheme}
          aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
          title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
        >
          {theme === "dark" ? "☀" : "☾"}
        </button>
      </div>
    </header>
  );
}
