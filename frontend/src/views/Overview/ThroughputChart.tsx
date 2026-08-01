import { Area, AreaChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { TimeseriesPoint } from "../../api/types";
import { formatBytes, formatTime } from "../../lib/format";
import { SkeletonRows } from "../../components/common/States";
import "./ThroughputChart.css";

function TooltipContent({
  active,
  payload,
  label,
  bucketSeconds,
}: {
  active?: boolean;
  payload?: Array<{ value: number; dataKey: string }>;
  label?: string;
  bucketSeconds: number;
}) {
  if (!active || !payload || payload.length === 0) return null;
  // Series values are bytes accumulated over one bucket (5s–900s depending on
  // the selected window), so divide by the bucket width before labelling the
  // number as a per-second rate.
  const inVal = (payload.find((p) => p.dataKey === "bytes_in")?.value ?? 0) / bucketSeconds;
  const outVal = (payload.find((p) => p.dataKey === "bytes_out")?.value ?? 0) / bucketSeconds;
  return (
    <div className="chart-tooltip">
      <div className="chart-tooltip-time">{label ? formatTime(label) : ""}</div>
      <div className="chart-tooltip-row">
        <span className="chart-tooltip-swatch" style={{ background: "var(--series-1)" }} />
        In <strong className="tabular">{formatBytes(inVal)}/s</strong>
      </div>
      <div className="chart-tooltip-row">
        <span className="chart-tooltip-swatch" style={{ background: "var(--series-2)" }} />
        Out <strong className="tabular">{formatBytes(outVal)}/s</strong>
      </div>
    </div>
  );
}

export function ThroughputChart({ points, loading, bucketSeconds }: { points: TimeseriesPoint[]; loading: boolean; bucketSeconds: number }) {
  if (loading && points.length === 0) return <SkeletonRows rows={6} height={20} />;
  if (points.length === 0) {
    return <div className="chart-empty">No traffic observed in this window yet.</div>;
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={points} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
        <defs>
          <linearGradient id="fillIn" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--series-1)" stopOpacity={0.28} />
            <stop offset="100%" stopColor="var(--series-1)" stopOpacity={0.02} />
          </linearGradient>
          <linearGradient id="fillOut" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--series-2)" stopOpacity={0.28} />
            <stop offset="100%" stopColor="var(--series-2)" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="var(--gridline)" strokeDasharray="0" vertical={false} />
        <XAxis
          dataKey="t"
          tickFormatter={(v: string) => formatTime(v)}
          stroke="var(--baseline)"
          tick={{ fill: "var(--text-muted)", fontSize: 11 }}
          minTickGap={40}
        />
        <YAxis
          tickFormatter={(v: number) => formatBytes(v)}
          stroke="var(--baseline)"
          tick={{ fill: "var(--text-muted)", fontSize: 11 }}
          width={64}
        />
        <Tooltip content={<TooltipContent bucketSeconds={bucketSeconds} />} />
        <Legend
          verticalAlign="top"
          height={28}
          formatter={(value) => <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>{value}</span>}
        />
        <Area type="monotone" dataKey="bytes_in" name="In" stroke="var(--series-1)" strokeWidth={2} fill="url(#fillIn)" isAnimationActive={false} />
        <Area type="monotone" dataKey="bytes_out" name="Out" stroke="var(--series-2)" strokeWidth={2} fill="url(#fillOut)" isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  );
}
