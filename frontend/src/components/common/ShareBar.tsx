import "./ShareBar.css";

interface ShareBarProps {
  share: number; // 0..1
  color?: string;
  label?: string;
}

/** Meter-style share bar: fill carries the value, track is a lighter step of
 * the same ramp so state reads across the whole bar (per marks-and-anatomy). */
export function ShareBar({ share, color = "var(--series-1)", label }: ShareBarProps) {
  const pct = Math.max(0, Math.min(1, share)) * 100;
  return (
    <div className="share-bar" role="img" aria-label={label ?? `${pct.toFixed(1)}%`}>
      <div className="share-bar-track">
        <div className="share-bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="share-bar-value tabular">{pct.toFixed(1)}%</span>
    </div>
  );
}
