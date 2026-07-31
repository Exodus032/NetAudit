import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { ThreatTimelinePoint } from "../../api/types";
import { formatTime } from "../../lib/format";
import { SkeletonRows } from "../../components/common/States";
// Reuses .chart-tooltip / .chart-empty from Overview/ThroughputChart.css (both
// bundled together app-wide) rather than redefining the same tooltip chrome.

type SeverityKey = "critical" | "high" | "medium" | "low" | "info";

const SERIES: { key: SeverityKey; label: string; color: string }[] = [
  { key: "critical", label: "Critical", color: "var(--status-critical)" },
  { key: "high", label: "High", color: "var(--status-serious)" },
  { key: "medium", label: "Medium", color: "var(--status-warning)" },
  { key: "low", label: "Low", color: "var(--status-good)" },
  { key: "info", label: "Info", color: "var(--text-muted)" },
];

interface TooltipPayloadEntry {
  dataKey: string;
  value: number;
}

function TooltipContent({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: TooltipPayloadEntry[];
  label?: string;
}) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div className="chart-tooltip">
      <div className="chart-tooltip-time">{label ? formatTime(label) : ""}</div>
      {SERIES.map((s) => {
        const v = payload.find((p) => p.dataKey === s.key)?.value ?? 0;
        if (!v) return null;
        return (
          <div className="chart-tooltip-row" key={s.key}>
            <span className="chart-tooltip-swatch" style={{ background: s.color }} />
            {s.label} <strong className="tabular">{v}</strong>
          </div>
        );
      })}
    </div>
  );
}

export function ThreatTimelineChart({ points, loading }: { points: ThreatTimelinePoint[]; loading: boolean }) {
  if (loading && points.length === 0) return <SkeletonRows rows={6} height={20} />;
  if (points.length === 0) {
    return <div className="chart-empty">No threat activity in this window.</div>;
  }

  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={points} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
        <CartesianGrid stroke="var(--gridline)" strokeDasharray="0" vertical={false} />
        <XAxis
          dataKey="t"
          tickFormatter={(v: string) => formatTime(v)}
          stroke="var(--baseline)"
          tick={{ fill: "var(--text-muted)", fontSize: 11 }}
          minTickGap={40}
        />
        <YAxis allowDecimals={false} stroke="var(--baseline)" tick={{ fill: "var(--text-muted)", fontSize: 11 }} width={28} />
        <Tooltip content={<TooltipContent />} />
        <Legend
          verticalAlign="top"
          height={28}
          formatter={(value) => <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>{value}</span>}
        />
        {SERIES.map((s) => (
          <Bar key={s.key} dataKey={s.key} name={s.label} stackId="severity" fill={s.color} isAnimationActive={false} />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
}
