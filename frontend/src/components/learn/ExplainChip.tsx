import { useId, useRef, useState } from "react";
import { useLearningMode } from "../../hooks/useLearningMode";
import { ExplainPopover } from "./ExplainPopover";
import type { ExplainKind } from "../../api/typesLearn";
import "./ExplainChip.css";

interface ExplainChipProps {
  /** kind ∈ detector | rule | check | metric | field — see docs/API_CONTRACT_V3.md D3 */
  kind: ExplainKind;
  /** unprefixed id, e.g. "c2_beaconing" */
  id: string;
  /** what this chip explains, for the accessible name — e.g. "C2 beaconing" */
  label: string;
}

/** A small "?" affordance next to a jargon-heavy label. Fetches
 * GET /api/explain/{kind}/{id} on open and shows plain-English what/why/how.
 * Renders nothing when learning mode is off. Real <button>, so it's
 * focusable and Enter/Space-activated for free; Escape closes via
 * ExplainPopover. */
export function ExplainChip({ kind, id, label }: ExplainChipProps) {
  const { enabled } = useLearningMode();
  const [open, setOpen] = useState(false);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const popoverId = useId();

  if (!enabled) return null;

  const close = () => {
    setOpen(false);
    buttonRef.current?.focus();
  };

  return (
    <span className="explain-chip-wrap">
      <button
        ref={buttonRef}
        type="button"
        className="explain-chip"
        aria-label={`Explain: ${label}`}
        aria-expanded={open}
        aria-describedby={open ? popoverId : undefined}
        onClick={() => setOpen((o) => !o)}
      >
        ?
      </button>
      {open && <ExplainPopover id={popoverId} kind={kind} itemId={id} onClose={close} />}
    </span>
  );
}
