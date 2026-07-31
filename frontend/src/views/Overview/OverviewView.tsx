import { useState } from "react";
import type { StatsWindow } from "../../api/types";
import { useStatsSummary } from "../../hooks/useStatsSummary";
import { useTimeseries } from "../../hooks/useTimeseries";
import { useCaptureStatus } from "../../hooks/useCaptureStatus";
import { StatTile } from "../../components/common/StatTile";
import { WindowSelector } from "../../components/common/WindowSelector";
import { ErrorState } from "../../components/common/States";
import { DegradedBanner } from "./DegradedBanner";
import { ThroughputChart } from "./ThroughputChart";
import { ProtocolBreakdown } from "./ProtocolBreakdown";
import { EncryptedSplit } from "./EncryptedSplit";
import { TopTalkers } from "./TopTalkers";
import { formatBitrate, formatBytes, formatNumber } from "../../lib/format";

export function OverviewView() {
  const [window, setWindow] = useState<StatsWindow>("5m");
  const { data: summary, loading: summaryLoading, error: summaryError, history } = useStatsSummary(window);
  const { points, loading: seriesLoading } = useTimeseries(window);
  const { capture } = useCaptureStatus();

  return (
    <div>
      {capture && <DegradedBanner capture={capture} />}

      {summaryError && <ErrorState title="Couldn't load stats summary" detail={summaryError} />}

      <section className="view-section">
        <div className="grid-stats">
          <StatTile
            label="Total traffic"
            value={summary ? formatBytes(summary.bytes_total) : "—"}
            sub={summary ? `${formatNumber(summary.packets_total)} packets` : undefined}
            loading={summaryLoading && !summary}
          />
          <StatTile
            label="In / out split"
            value={summary ? `${formatBytes(summary.bytes_in)} / ${formatBytes(summary.bytes_out)}` : "—"}
            loading={summaryLoading && !summary}
          />
          <StatTile
            label="Live throughput"
            value={summary ? formatBitrate(summary.throughput_bps_in + summary.throughput_bps_out) : "—"}
            sub={summary ? `peak ${formatBitrate(summary.peak_throughput_bps)}` : undefined}
            trend={history}
            loading={summaryLoading && !summary}
          />
          <StatTile
            label="Active flows"
            value={summary ? formatNumber(summary.active_flows) : "—"}
            loading={summaryLoading && !summary}
          />
          <StatTile
            label="Unique remote hosts"
            value={summary ? formatNumber(summary.unique_remote_hosts) : "—"}
            sub={summary ? `${formatNumber(summary.unique_processes)} processes` : undefined}
            loading={summaryLoading && !summary}
          />
          <StatTile
            label="Open alerts"
            value={summary ? formatNumber(summary.open_alerts) : "—"}
            sub={
              summary
                ? `${summary.alerts_by_severity.critical}C · ${summary.alerts_by_severity.high}H · ${summary.alerts_by_severity.medium}M · ${summary.alerts_by_severity.low}L`
                : undefined
            }
            deltaGoodDirection="down"
            loading={summaryLoading && !summary}
          />
        </div>
      </section>

      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Live throughput</span>
          <WindowSelector value={window} onChange={setWindow} />
        </div>
        <div className="panel">
          <ThroughputChart points={points} loading={seriesLoading} />
        </div>
      </section>

      <section className="view-section grid-2">
        <div className="panel">
          <div className="panel-title">Protocol breakdown</div>
          {summary ? <ProtocolBreakdown summary={summary} /> : <ErrorState title="No data yet" />}
        </div>
        <div className="panel">
          <div className="panel-title">Encrypted vs plaintext</div>
          {summary ? <EncryptedSplit summary={summary} /> : <ErrorState title="No data yet" />}
        </div>
      </section>

      <section className="view-section">
        <div className="panel">
          <div className="panel-title">Top talkers</div>
          <TopTalkers window={window} />
        </div>
      </section>
    </div>
  );
}
