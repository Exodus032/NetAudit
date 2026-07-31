import "./ConfidenceMeter.css";

// Confidence is a distinct axis from severity, so it deliberately does NOT
// reuse the status color scale (reserved for severity/risk elsewhere) — it
// uses the sequential blue ramp instead, per the dataviz skill's rule that
// status colors are never repurposed for a different quantity. Four discrete
// steps (rather than a continuously-filled bar) make 15% vs 95% legible at a
// glance without having to read the percentage.
function confidenceTier(confidence: number): { label: string; colorVar: string; step: number } {
  if (confidence >= 0.8) return { label: "Very high confidence", colorVar: "--seq-700", step: 4 };
  if (confidence >= 0.6) return { label: "High confidence", colorVar: "--seq-500", step: 3 };
  if (confidence >= 0.35) return { label: "Moderate confidence", colorVar: "--seq-300", step: 2 };
  return { label: "Low confidence", colorVar: "--seq-100", step: 1 };
}

export function ConfidenceMeter({ confidence }: { confidence: number }) {
  const pct = Math.round(confidence * 100);
  const tier = confidenceTier(confidence);
  return (
    <span className="confidence-meter" title={`${tier.label} (${pct}%)`}>
      <span className="confidence-meter-track" aria-hidden="true">
        {[1, 2, 3, 4].map((step) => (
          <span
            key={step}
            className={`confidence-meter-seg${step <= tier.step ? " filled" : ""}`}
            style={step <= tier.step ? { background: `var(${tier.colorVar})` } : undefined}
          />
        ))}
      </span>
      <span className="confidence-meter-label">
        <span className="confidence-meter-pct tabular">{pct}%</span> {tier.label}
      </span>
    </span>
  );
}
