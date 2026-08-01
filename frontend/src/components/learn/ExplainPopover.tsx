import { useEffect, useRef } from "react";
import { useExplain } from "../../hooks/useExplain";
import type { ExplainKind } from "../../api/typesLearn";
import "./ExplainPopover.css";

interface ExplainPopoverProps {
  id: string;
  kind: ExplainKind;
  itemId: string;
  onClose: () => void;
}

/** Small "what does this mean" panel anchored under an <ExplainChip>. Not a
 * full modal — background stays interactive — but still gets a real focus
 * target and Escape-to-close so it behaves for keyboard/screen-reader users. */
export function ExplainPopover({ id, kind, itemId, onClose }: ExplainPopoverProps) {
  const { data, loading, error, load } = useExplain(kind, itemId);
  const panelRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      }
    };
    const onClickOutside = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) onClose();
    };
    document.addEventListener("keydown", onKey, true);
    document.addEventListener("mousedown", onClickOutside, true);
    return () => {
      document.removeEventListener("keydown", onKey, true);
      document.removeEventListener("mousedown", onClickOutside, true);
    };
  }, [onClose]);

  return (
    <div id={id} ref={panelRef} role="dialog" aria-modal="false" className="explain-popover" onClick={(e) => e.stopPropagation()}>
      <div className="explain-popover-head">
        <span className="explain-popover-title">{loading ? "Loading…" : data?.title ?? "Not explained yet"}</span>
        <button ref={closeRef} type="button" className="explain-popover-close" onClick={onClose} aria-label="Close explanation">
          ✕
        </button>
      </div>

      {loading && <p className="explain-popover-text">Loading…</p>}

      {!loading && error && <p className="explain-popover-text explain-popover-error">Couldn't load this explanation: {error}</p>}

      {!loading && !error && !data && (
        <p className="explain-popover-text">There's no explanation on file for this yet.</p>
      )}

      {!loading && !error && data && (
        <div className="explain-popover-body">
          <p className="explain-popover-text">{data.plain}</p>

          <div className="explain-popover-section">
            <div className="explain-popover-label">How it decides</div>
            <p className="explain-popover-text">{data.how_it_decides}</p>
          </div>

          <div className="explain-popover-section">
            <div className="explain-popover-label">What would make it wrong</div>
            <p className="explain-popover-text">{data.what_would_make_it_wrong}</p>
          </div>

          {data.worked_example && (
            <div className="explain-popover-section">
              <div className="explain-popover-label">Worked example</div>
              <p className="explain-popover-text">{data.worked_example.scenario}</p>
              <ol className="explain-popover-walkthrough">
                {data.worked_example.walkthrough.map((line, i) => (
                  <li key={i}>{line}</li>
                ))}
              </ol>
            </div>
          )}

          {data.glossary_terms.length > 0 && (
            <div className="explain-popover-terms">
              {data.glossary_terms.map((t) => (
                <span key={t} className="explain-popover-term-chip">{t.replace(/_/g, " ")}</span>
              ))}
            </div>
          )}

          {data.learn_more && <div className="explain-popover-learn-more">Learn more: {data.learn_more}</div>}
        </div>
      )}
    </div>
  );
}
