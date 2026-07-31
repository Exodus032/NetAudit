import { useState } from "react";
import type { StatsWindow, TopBy } from "../../api/types";
import { useTopStats } from "../../hooks/useTopStats";
import { ShareBar } from "../../components/common/ShareBar";
import { RiskBadge } from "../../components/common/Badge";
import { SkeletonRows } from "../../components/common/States";
import { EmptyState } from "../../components/common/States";
import { formatBytes } from "../../lib/format";
import "./TopTalkers.css";

const DIMENSIONS: { id: TopBy; label: string }[] = [
  { id: "host", label: "Host" },
  { id: "process", label: "Process" },
  { id: "port", label: "Port" },
  { id: "protocol", label: "Protocol" },
];

export function TopTalkers({ window }: { window: StatsWindow }) {
  const [by, setBy] = useState<TopBy>("host");
  const { items, loading, error } = useTopStats(by, window, 8);

  return (
    <div>
      <div className="top-talkers-tabs" role="tablist" aria-label="Top talkers dimension">
        {DIMENSIONS.map((d) => (
          <button
            key={d.id}
            role="tab"
            aria-selected={by === d.id}
            className={`top-talkers-tab${by === d.id ? " active" : ""}`}
            onClick={() => setBy(d.id)}
          >
            {d.label}
          </button>
        ))}
      </div>
      {loading && items.length === 0 && <SkeletonRows rows={6} height={30} />}
      {error && !loading && <EmptyState title="Couldn't load top talkers" detail={error} />}
      {!loading && !error && items.length === 0 && <EmptyState title="No traffic yet" detail="Top talkers will appear once traffic is observed." />}
      {items.length > 0 && (
        <ul className="top-talkers-list">
          {items.map((item) => (
            <li key={item.key} className="top-talkers-row">
              <div className="top-talkers-meta">
                <span className="top-talkers-label mono">{item.label}</span>
                {item.sublabel && <span className="top-talkers-sub">{item.sublabel}</span>}
                <RiskBadge risk={item.risk} />
              </div>
              <div className="top-talkers-bar-row">
                <ShareBar share={item.share} color="var(--series-1)" />
                <span className="top-talkers-bytes tabular">{formatBytes(item.bytes_total)}</span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
