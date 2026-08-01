import { useSyncExternalStore } from "react";
import type { ConnectionState } from "../../api/liveSocket";
import { getBackendMode, subscribeBackendMode } from "../../api/backendMode";
import type { Theme } from "../../state/useTheme";
import { VIEW_TITLES } from "./Sidebar";
import "./Header.css";

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
  onExplainNetwork,
  learningMode,
  onToggleLearningMode,
}: {
  viewId: string;
  connectionState: ConnectionState;
  theme: Theme;
  onToggleTheme: () => void;
  onExplainNetwork: () => void;
  learningMode: boolean;
  onToggleLearningMode: () => void;
}) {
  const backendMode = useSyncExternalStore(subscribeBackendMode, getBackendMode);
  const usingMocks = backendMode === "forced-mock" || backendMode === "fallback-mock";

  return (
    <header className="app-header">
      <h1 className="app-header-title">{VIEW_TITLES[viewId] ?? "NetAudit"}</h1>
      <div className="app-header-actions">
        {usingMocks && <span className="mock-pill">Mock data</span>}
        <button
          type="button"
          className="explain-network-toggle"
          onClick={onExplainNetwork}
        >
          Explain my network
        </button>
        {/* Lives in the header rather than in the Learn view because it
            governs the explain chips scattered across every other view --
            a professional who wants them gone should be able to say so
            from wherever they happen to be. */}
        <button
          className={`learn-toggle${learningMode ? " on" : ""}`}
          onClick={onToggleLearningMode}
          aria-pressed={learningMode}
          title={
            learningMode
              ? "Learning mode on: plain-English explanations appear next to jargon"
              : "Learning mode off: explanation chips are hidden"
          }
        >
          <span aria-hidden="true">?</span>
          Learn
        </button>
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
