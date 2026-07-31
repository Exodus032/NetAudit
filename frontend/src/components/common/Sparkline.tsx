interface SparklineProps {
  values: number[];
  width?: number;
  height?: number;
  color?: string; // CSS color for the line + end dot
}

/** Minimal 12-point trend line per the stat-tile figure contract: 2px line in a
 * de-emphasis tone, current-period end marked with an accent dot. */
export function Sparkline({ values, width = 72, height = 24, color = "var(--series-1)" }: SparklineProps) {
  if (values.length < 2) return null;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const stepX = width / (values.length - 1);
  const points = values.map((v, i) => {
    const x = i * stepX;
    const y = height - ((v - min) / range) * (height - 4) - 2;
    return [x, y] as const;
  });
  const path = points.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const [lastX, lastY] = points[points.length - 1];

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true" focusable="false">
      <path d={path} fill="none" stroke="var(--text-muted)" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" opacity={0.55} />
      <circle cx={lastX} cy={lastY} r={3} fill={color} stroke="var(--surface-1)" strokeWidth={2} />
    </svg>
  );
}
