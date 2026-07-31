import "./SegmentedBar.css";

export interface Segment {
  key: string;
  label: string;
  value: number;
  color: string; // CSS color, e.g. "var(--series-1)"
}

/** Single stacked bar (part-to-whole) with a 2px surface gap between segments
 * and a legend row beneath — the dataviz skill's preferred form over a donut. */
export function SegmentedBar({ segments, formatValue }: { segments: Segment[]; formatValue?: (v: number) => string }) {
  const total = segments.reduce((s, seg) => s + seg.value, 0) || 1;
  const nonZero = segments.filter((s) => s.value > 0);

  return (
    <div className="segmented-bar-wrap">
      <div className="segmented-bar" role="img" aria-label={segments.map((s) => `${s.label} ${((s.value / total) * 100).toFixed(0)}%`).join(", ")}>
        {nonZero.map((seg) => (
          <div
            key={seg.key}
            className="segmented-bar-piece"
            style={{ width: `${(seg.value / total) * 100}%`, background: seg.color }}
            title={`${seg.label}: ${((seg.value / total) * 100).toFixed(1)}%`}
          />
        ))}
      </div>
      <ul className="segmented-legend">
        {segments.map((seg) => (
          <li key={seg.key} className="segmented-legend-item">
            <span className="segmented-legend-swatch" style={{ background: seg.color }} aria-hidden="true" />
            <span className="segmented-legend-label">{seg.label}</span>
            <span className="segmented-legend-value tabular">
              {formatValue ? formatValue(seg.value) : seg.value} · {((seg.value / total) * 100).toFixed(1)}%
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
