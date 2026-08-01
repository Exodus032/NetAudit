import { useState } from "react";
import { useLessons } from "../../hooks/useLessons";
import { ErrorState, SkeletonRows } from "../../components/common/States";
import type { LessonStep } from "../../api/typesLearn";
import "./LessonsView.css";

const DIFFICULTY_RANK: Record<string, number> = { beginner: 0, intermediate: 1, advanced: 2 };
const DIFFICULTY_LABELS: Record<string, string> = { beginner: "Beginner", intermediate: "Intermediate", advanced: "Advanced" };

// The Learn API's ViewId vocabulary ("traffic-log") doesn't match the main
// app's internal view ids ("traffic") — see docs/API_CONTRACT_V3.md Part D's
// ViewId literal vs. src/components/layout/Sidebar.tsx's ViewId. This is the
// only place that translation needs to happen, for the lesson steps' deep
// links via onNavigate.
const VIEW_ID_MAP: Record<string, string> = {
  overview: "overview",
  "traffic-log": "traffic",
  connections: "connections",
  recommendations: "recommendations",
  posture: "posture",
  threats: "threats",
};

const VIEW_LABELS: Record<string, string> = {
  overview: "Overview",
  "traffic-log": "Traffic log",
  connections: "Connections & devices",
  recommendations: "Recommended actions",
  posture: "Security posture",
  threats: "Threats",
};

interface LessonsViewProps {
  onNavigate?: (view: string) => void;
}

export function LessonsView({ onNavigate }: LessonsViewProps) {
  const { lessons, loading, error, progressFor, toggleStep, resetLesson, reload } = useLessons();
  const [openId, setOpenId] = useState<string | null>(null);

  if (error) return <ErrorState title="Couldn't load lessons" detail={error} action={<button onClick={reload}>Retry</button>} />;
  if (loading && lessons.length === 0) return <SkeletonRows rows={6} height={60} />;

  const ordered = [...lessons].sort(
    (a, b) => (DIFFICULTY_RANK[a.difficulty] ?? 9) - (DIFFICULTY_RANK[b.difficulty] ?? 9) || a.id.localeCompare(b.id),
  );

  const byId = new Map(lessons.map((l) => [l.id, l]));

  return (
    <div>
      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Lessons</span>
          <span className="lessons-count">{lessons.length} lessons, beginner to advanced</span>
        </div>
      </section>

      <section className="view-section lessons-path">
        {ordered.map((lesson, i) => {
          const progress = progressFor(lesson.id);
          const done = progress.completedSteps.length;
          const total = lesson.steps.length;
          const isComplete = !!progress.completedAt;
          const open = openId === lesson.id;
          const prereqTitles = lesson.prerequisites.map((id) => byId.get(id)?.title ?? id);

          return (
            <div key={lesson.id} className={`lesson-card${isComplete ? " lesson-complete" : ""}`}>
              <button className="lesson-card-head" onClick={() => setOpenId(open ? null : lesson.id)} aria-expanded={open}>
                <span className="lesson-order">{i + 1}</span>
                <span className="lesson-head-main">
                  <span className="lesson-title-row">
                    <span className="lesson-title">{lesson.title}</span>
                    <span className={`chip lesson-difficulty-${lesson.difficulty}`}>{DIFFICULTY_LABELS[lesson.difficulty]}</span>
                  </span>
                  <span className="lesson-summary">{lesson.summary}</span>
                </span>
                <span className="lesson-meta">
                  <span className="lesson-minutes">{lesson.estimated_minutes} min</span>
                  <span className="lesson-progress-label">{isComplete ? "Done" : `${done}/${total} steps`}</span>
                </span>
              </button>

              {open && (
                <div className="lesson-card-body">
                  {prereqTitles.length > 0 && (
                    <div className="lesson-prereqs">Suggested first: {prereqTitles.join(", ")}</div>
                  )}

                  <div className="lesson-objectives">
                    <div className="lesson-section-label">You'll be able to</div>
                    <ul>
                      {lesson.objectives.map((o, idx) => (
                        <li key={idx}>{o}</li>
                      ))}
                    </ul>
                  </div>

                  <ol className="lesson-steps">
                    {lesson.steps.map((step) => (
                      <LessonStepRow
                        key={step.order}
                        step={step}
                        checked={progress.completedSteps.includes(step.order)}
                        onToggle={() => toggleStep(lesson.id, step.order, total)}
                        onNavigate={onNavigate}
                      />
                    ))}
                  </ol>

                  {lesson.uses_live_data && (
                    <p className="lesson-live-note">This lesson uses your own live data as the example.</p>
                  )}

                  {done > 0 && (
                    <button className="lesson-reset-btn" onClick={() => resetLesson(lesson.id)}>
                      Reset progress
                    </button>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </section>
    </div>
  );
}

function LessonStepRow({
  step,
  checked,
  onToggle,
  onNavigate,
}: {
  step: LessonStep;
  checked: boolean;
  onToggle: () => void;
  onNavigate?: (view: string) => void;
}) {
  const targetView = step.check.kind === "view_visited" ? VIEW_ID_MAP[step.check.value] : undefined;

  return (
    <li className="lesson-step">
      <label className="lesson-step-check">
        <input type="checkbox" checked={checked} onChange={onToggle} />
        <span className="lesson-step-instruction">{step.instruction}</span>
      </label>
      <p className="lesson-step-explanation">{step.explanation}</p>
      {targetView && onNavigate && (
        <button className="lesson-step-deeplink" onClick={() => onNavigate(targetView)}>
          Open {VIEW_LABELS[step.check.value] ?? step.check.value} ↗
        </button>
      )}
      {step.glossary_terms.length > 0 && (
        <div className="lesson-step-terms">
          {step.glossary_terms.map((t) => (
            <span key={t} className="lesson-step-term">{t.replace(/_/g, " ")}</span>
          ))}
        </div>
      )}
    </li>
  );
}
