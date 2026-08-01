import { useCallback, useEffect, useState } from "react";
import { Sidebar, type ViewId } from "./components/layout/Sidebar";
import { Header } from "./components/layout/Header";
import { useTheme } from "./state/useTheme";
import { useConnectionState } from "./api/useLiveSocket";
import { ensureToken, isMockForced } from "./api/auth";
import { OverviewView } from "./views/Overview/OverviewView";
import { TrafficLogView } from "./views/TrafficLog/TrafficLogView";
import { ConnectionsView } from "./views/Connections/ConnectionsView";
import { RecommendationsView } from "./views/Recommendations/RecommendationsView";
import { PostureView } from "./views/Posture/PostureView";
import { ThreatsView } from "./views/Threats/ThreatsView";
import { LEARN_VIEWS, GuidedTour, useLearningMode } from "./views/Learn";
import { PRO_VIEWS } from "./views/Pro";
import "./App.css";

// Required rather than optional: App always has a navigate function to hand,
// and OverviewView's cross-links depend on receiving one. Views that ignore
// it (most of them) still satisfy this.
type ViewComponent = React.ComponentType<{ onNavigate: (v: string) => void }>;

// One registry rather than a chain of `view === "x" && <X/>`: the Learn and
// Pro packages each own their own map, so adding a view there does not need
// an edit here.
const VIEWS: Record<string, ViewComponent> = {
  overview: OverviewView,
  traffic: TrafficLogView,
  connections: ConnectionsView,
  recommendations: RecommendationsView,
  posture: PostureView,
  threats: ThreatsView,
  ...LEARN_VIEWS,
  ...PRO_VIEWS,
};

// The Learn package speaks the contract's vocabulary for view ids; the
// sidebar has used its own since v1. Translating here means neither side
// has to change, and a lesson deep-link lands on the right screen.
const VIEW_ID_ALIASES: Record<string, string> = {
  "traffic-log": "traffic",
  devices: "connections",
  security: "posture",
};

const TOUR_VIEW_ALIASES: Record<string, string> = {
  traffic: "traffic-log",
};

function App() {
  const [view, setView] = useState<ViewId>("overview");
  const { theme, toggleTheme } = useTheme();
  const connectionState = useConnectionState();
  const { enabled: learningMode, toggle: toggleLearningMode } = useLearningMode();

  // Stable identity: GuidedTour navigates from an effect keyed on this.
  const navigate = useCallback((next: string) => {
    setView(VIEW_ID_ALIASES[next] ?? next);
  }, []);

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

  const ActiveView = VIEWS[view] ?? OverviewView;

  return (
    <div className="app-shell">
      <a href="#main-content" className="skip-link">Skip to content</a>
      <Sidebar active={view} onChange={setView} />
      <div className="app-main-col">
        <Header
          viewId={view}
          connectionState={connectionState}
          theme={theme}
          onToggleTheme={toggleTheme}
          learningMode={learningMode}
          onToggleLearningMode={toggleLearningMode}
        />
        <main id="main-content" className="app-content" tabIndex={-1}>
          <ActiveView onNavigate={navigate} />
        </main>
      </div>
      <GuidedTour currentView={TOUR_VIEW_ALIASES[view] ?? view} />
    </div>
  );
}

export default App;
