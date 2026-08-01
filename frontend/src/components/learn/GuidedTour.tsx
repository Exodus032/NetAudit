import { useEffect, useRef, useState, type CSSProperties } from "react";
import { useTour } from "../../hooks/useTour";
import "./GuidedTour.css";

function panelPosition(rect: DOMRect): CSSProperties {
  const margin = 14;
  const panelWidth = 340;
  const viewportW = window.innerWidth;
  const viewportH = window.innerHeight;
  let top = rect.bottom + margin;
  const left = Math.min(Math.max(rect.left, margin), Math.max(margin, viewportW - panelWidth - margin));
  if (top + 240 > viewportH) top = Math.max(margin, rect.top - margin - 240);
  return { position: "fixed", top, left, width: panelWidth, transform: "none" };
}

/** App-level overlay driven by GET /api/tour. It presents only the segment
 * belonging to the active view; later segments appear when the visitor
 * navigates to their pages. */
export function GuidedTour({ currentView }: { currentView: string }) {
  const { step, index, total, open, next, back, skip } = useTour(currentView);
  const [rect, setRect] = useState<DOMRect | null>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (open) {
      previouslyFocused.current = document.activeElement as HTMLElement | null;
    } else if (previouslyFocused.current) {
      previouslyFocused.current.focus();
      previouslyFocused.current = null;
    }
  }, [open]);

  useEffect(() => {
    if (!open || !step) {
      setRect(null);
      return;
    }
    const update = () => {
      const el = step.target ? document.querySelector(step.target) : null;
      setRect(el ? el.getBoundingClientRect() : null);
    };
    update();
    const el = step.target ? document.querySelector(step.target) : null;
    el?.scrollIntoView({ block: "center", behavior: "smooth" });
    window.addEventListener("resize", update);
    window.addEventListener("scroll", update, true);
    const settleTimer = window.setTimeout(update, 260);
    const raf = requestAnimationFrame(() => panelRef.current?.focus());
    return () => {
      window.removeEventListener("resize", update);
      window.removeEventListener("scroll", update, true);
      window.clearTimeout(settleTimer);
      cancelAnimationFrame(raf);
    };
  }, [open, step]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        skip();
        return;
      }
      if (e.key === "Tab") {
        const focusables = panelRef.current?.querySelectorAll<HTMLElement>(
          'button:not([disabled]), [href], input, [tabindex]:not([tabindex="-1"])',
        );
        if (!focusables || focusables.length === 0) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey, true);
    return () => document.removeEventListener("keydown", onKey, true);
  }, [open, skip]);

  if (!open || !step) return null;

  const hasTarget = !!rect;
  const spotlightPad = 6;

  return (
    <div className="tour-overlay">
      {hasTarget && rect && (
        <div
          className="tour-spotlight"
          style={{
            top: rect.top - spotlightPad,
            left: rect.left - spotlightPad,
            width: rect.width + spotlightPad * 2,
            height: rect.height + spotlightPad * 2,
          }}
        />
      )}
      <div
        ref={panelRef}
        className={`tour-panel${hasTarget ? "" : " tour-panel-centered"}`}
        role="dialog"
        aria-modal="true"
        aria-label={`Guided tour, step ${index + 1} of ${total}: ${step.title}`}
        tabIndex={-1}
        style={hasTarget && rect ? panelPosition(rect) : undefined}
      >
        <div className="tour-panel-head">
          <span className="tour-panel-step">
            Step {index + 1} of {total}
          </span>
          <button type="button" className="tour-panel-close" onClick={skip} aria-label="Close tour">
            ✕
          </button>
        </div>
        <h3 className="tour-panel-title">{step.title}</h3>
        <p className="tour-panel-body">{step.body}</p>

        {!hasTarget && step.action_hint && (
          <p className="tour-panel-hint">
            Nothing to highlight until you {step.action_hint}.
          </p>
        )}

        {step.action_hint && hasTarget && (
          <p className="tour-panel-action">» {step.action_hint}</p>
        )}

        {step.glossary_terms.length > 0 && (
          <div className="tour-panel-terms">
            {step.glossary_terms.map((t) => (
              <span key={t} className="tour-panel-term">
                {t.replace(/_/g, " ")}
              </span>
            ))}
          </div>
        )}

        <div className="tour-panel-actions">
          <button type="button" className="tour-btn tour-btn-ghost" onClick={skip}>
            Skip tour
          </button>
          <div className="tour-panel-actions-spacer" />
          <button type="button" className="tour-btn tour-btn-secondary" onClick={back} disabled={index === 0}>
            Back
          </button>
          <button type="button" className="tour-btn tour-btn-primary" onClick={next}>
            {index + 1 >= total ? "Done" : "Next"}
          </button>
        </div>
      </div>
    </div>
  );
}
