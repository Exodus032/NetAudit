import type { ReactNode } from "react";
import { Sparkline } from "./Sparkline";
import "./StatTile.css";

interface StatTileProps {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  delta?: number; // signed fraction, e.g. 0.12 = +12%
  deltaGoodDirection?: "up" | "down";
  trend?: number[];
  loading?: boolean;
}

export function StatTile({ label, value, sub, delta, deltaGoodDirection = "up", trend, loading }: StatTileProps) {
  if (loading) {
    return (
      <div className="stat-tile" aria-busy="true">
        <div className="stat-skel stat-skel-label" />
        <div className="stat-skel stat-skel-value" />
      </div>
    );
  }

  let deltaEl: ReactNode = null;
  if (typeof delta === "number" && Number.isFinite(delta)) {
    const isUp = delta >= 0;
    const isGood = isUp === (deltaGoodDirection === "up");
    const cls = isGood ? "stat-delta stat-delta-good" : "stat-delta stat-delta-bad";
    deltaEl = (
      <span className={cls}>
        {isUp ? "↑" : "↓"} {Math.abs(delta * 100).toFixed(1)}%
      </span>
    );
  }

  return (
    <div className="stat-tile">
      <div className="stat-label">{label}</div>
      <div className="stat-row">
        <div className="stat-value" title={typeof value === "string" ? value : undefined}>
          {value}
        </div>
        {trend && trend.length > 1 && (
          <div className="stat-trend">
            <Sparkline values={trend} width={44} height={20} />
          </div>
        )}
      </div>
      <div className="stat-footer">
        {deltaEl}
        {sub && <span className="stat-sub">{sub}</span>}
      </div>
    </div>
  );
}
