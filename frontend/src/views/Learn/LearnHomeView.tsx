import { useLearningMode } from "../../hooks/useLearningMode";
import { useLessons } from "../../hooks/useLessons";
import { useGlossary } from "../../hooks/useGlossary";
import { usePrioritisedFindings } from "../../hooks/usePrioritisedFindings";
import { requestTourRestart, isTourCompleted } from "../../hooks/useTour";
import "./LearnHomeView.css";

interface LearnHomeViewProps {
  onNavigate?: (view: string) => void;
}

/** Hub view: the learning-mode toggle lives here (contract requirement 6),
 * plus a way to restart the guided tour and quick links into the rest of
 * this package's views. */
export function LearnHomeView({ onNavigate }: LearnHomeViewProps) {
  const { enabled, setEnabled } = useLearningMode();
  const { lessons, progressFor } = useLessons();
  const { terms } = useGlossary();
  const { items } = usePrioritisedFindings();

  const lessonsDone = lessons.filter((l) => !!progressFor(l.id).completedAt).length;

  return (
    <div>
      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Learn</span>
        </div>
        <p className="learnhome-intro">
          Everything here explains what NetAudit is showing you, in plain language, without changing what it reports. Turn
          it off any time — the rest of the app works exactly the same either way.
        </p>
      </section>

      <section className="view-section">
        <div className="panel learnhome-toggle-panel">
          <div>
            <div className="learnhome-toggle-title">Learning mode</div>
            <div className="learnhome-toggle-detail">
              Shows "?" explain buttons next to jargon-heavy labels around the app, and auto-opens the guided tour for a
              first-time visitor. Off means a clean, professional view with none of that.
            </div>
          </div>
          <label className="learnhome-switch">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} aria-label="Toggle learning mode" />
            <span className="learnhome-switch-track" aria-hidden="true">
              <span className="learnhome-switch-thumb" />
            </span>
            <span className="learnhome-switch-label">{enabled ? "On" : "Off"}</span>
          </label>
        </div>
      </section>

      <section className="view-section">
        <div className="panel learnhome-tour-panel">
          <div>
            <div className="learnhome-toggle-title">Guided tour</div>
            <div className="learnhome-toggle-detail">
              A 15-step walkthrough of the whole app, highlighting what each screen shows.
              {isTourCompleted() ? " You've already been through it." : " You haven't finished it yet."}
            </div>
          </div>
          <button className="learnhome-tour-btn" onClick={requestTourRestart}>
            {isTourCompleted() ? "Take it again" : "Start the tour"}
          </button>
        </div>
      </section>

      <section className="view-section learnhome-cards">
        <button className="learnhome-card" onClick={() => onNavigate?.("learn-glossary")}>
          <div className="learnhome-card-title">Glossary</div>
          <div className="learnhome-card-stat">{terms.length || 48} terms</div>
          <div className="learnhome-card-detail">Look up any acronym or term NetAudit uses, with why it matters.</div>
        </button>
        <button className="learnhome-card" onClick={() => onNavigate?.("learn-lessons")}>
          <div className="learnhome-card-title">Lessons</div>
          <div className="learnhome-card-stat">
            {lessonsDone} / {lessons.length || 7} complete
          </div>
          <div className="learnhome-card-detail">Short guided exercises that use your own live network data.</div>
        </button>
        <button className="learnhome-card" onClick={() => onNavigate?.("learn-fix-first")}>
          <div className="learnhome-card-title">Fix this first</div>
          <div className="learnhome-card-stat">{items.length} open items</div>
          <div className="learnhome-card-detail">One ranked list of what to fix, across posture, threats and hygiene.</div>
        </button>
      </section>
    </div>
  );
}
