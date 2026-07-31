import { useEffect, useState } from "react";
import { Sidebar, type ViewId } from "./components/layout/Sidebar";
import { Header } from "./components/layout/Header";
import { useTheme } from "./state/useTheme";
import { useConnectionState } from "./api/useLiveSocket";
import { ensureToken, isMockForced } from "./api/auth";
import { OverviewView } from "./views/Overview/OverviewView";
import { TrafficLogView } from "./views/TrafficLog/TrafficLogView";
import { ConnectionsView } from "./views/Connections/ConnectionsView";
import { RecommendationsView } from "./views/Recommendations/RecommendationsView";
import "./App.css";

function App() {
  const [view, setView] = useState<ViewId>("overview");
  const { theme, toggleTheme } = useTheme();
  const connectionState = useConnectionState();

  // Fetch the local auth token once at startup (docs/API_CONTRACT_V2_SECURITY.md
  // Part C item 2) so it's already cached before the first real REST/WS call.
  // Skipped in forced mock mode; failures here are swallowed because every
  // real API call already retries bootstrap and falls back to mocks on its own.
  useEffect(() => {
    if (isMockForced()) return;
    ensureToken().catch(() => {
      // best-effort — individual calls handle bootstrap failure themselves
    });
  }, []);

  return (
    <div className="app-shell">
      <a href="#main-content" className="skip-link">Skip to content</a>
      <Sidebar active={view} onChange={setView} />
      <div className="app-main-col">
        <Header viewId={view} connectionState={connectionState} theme={theme} onToggleTheme={toggleTheme} />
        <main id="main-content" className="app-content" tabIndex={-1}>
          {view === "overview" && <OverviewView />}
          {view === "traffic" && <TrafficLogView />}
          {view === "connections" && <ConnectionsView />}
          {view === "recommendations" && <RecommendationsView />}
        </main>
      </div>
    </div>
  );
}

export default App;
