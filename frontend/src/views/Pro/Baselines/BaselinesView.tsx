import { useEffect, useState } from "react";
import { useBaselineDiff, useBaselines, useBaselineSchedule } from "../../../hooks/useBaselines";
import { ErrorState, EmptyState, SkeletonRows } from "../../../components/common/States";
import { formatDateTime, formatNumber } from "../../../lib/format";
import "../../../components/pro/pro-common.css";
import "./BaselinesView.css";
import type { BaselineSchedule } from "../../../api/typesPro";

const SCHEDULE_INTERVALS: BaselineSchedule["interval_hours"][] = [6, 12, 24, 48, 168];


function Delta({ value }: { value: number }) {
  if (value === 0) return <span className="pro-muted">no change</span>;
  const good = value > 0;
  return <span className={good ? "baseline-delta-up" : "baseline-delta-down"}>{good ? "+" : ""}{value}</span>;
}

export function BaselinesView() {
  const { baselines, loading, error, capturing, captureError, capture } = useBaselines();
  const [label, setLabel] = useState("");
  const [fromId, setFromId] = useState("");
  const [toId, setToId] = useState("");
  const { diff, loading: diffLoading, error: diffError, run } = useBaselineDiff();
  const {
    schedule,
    loading: scheduleLoading,
    error: scheduleError,
    saving: scheduleSaving,
    saveError: scheduleSaveError,
    save: saveSchedule,
  } = useBaselineSchedule();
  const [scheduleDraft, setScheduleDraft] = useState<BaselineSchedule | null>(null);

  useEffect(() => {
    if (schedule) setScheduleDraft(schedule);
  }, [schedule]);

  const handleScheduleSave = () => {
    if (scheduleDraft) void saveSchedule(scheduleDraft).catch(() => undefined);
  };


  const handleCapture = async () => {
    if (!label.trim()) return;
    const created = await capture(label.trim());
    setLabel("");
    if (!fromId) setFromId(created.id);
    else if (!toId) setToId(created.id);
  };

  const handleDiff = () => {
    if (fromId && toId && fromId !== toId) void run(fromId, toId);
  };

  return (
    <div>
      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Scheduled monitoring</span>
        </div>

        {scheduleError && <ErrorState title="Couldn't load scheduled monitoring" detail={scheduleError} />}
        {!scheduleError && (scheduleLoading || !scheduleDraft) && (
          <div className="panel">
            <SkeletonRows rows={3} height={24} />
          </div>
        )}
        {!scheduleError && !scheduleLoading && scheduleDraft && (
          <div className="panel baselines-schedule">
            <div className="baselines-schedule-controls">
              <label className="pro-checkbox">
                <input
                  type="checkbox"
                  checked={scheduleDraft.enabled}
                  onChange={(e) => setScheduleDraft({ ...scheduleDraft, enabled: e.target.checked })}
                  disabled={scheduleSaving}
                />
                Scheduled monitoring enabled
              </label>
              <div className="pro-field">
                <label className="pro-field-label" htmlFor="baseline-schedule-interval">Capture interval</label>
                <select
                  id="baseline-schedule-interval"
                  className="pro-select"
                  value={scheduleDraft.interval_hours}
                  onChange={(e) => setScheduleDraft({
                    ...scheduleDraft,
                    interval_hours: Number(e.target.value) as BaselineSchedule["interval_hours"],
                  })}
                  disabled={scheduleSaving}
                >
                  {SCHEDULE_INTERVALS.map((interval) => (
                    <option key={interval} value={interval}>{interval === 168 ? "7d" : `${interval}h`}</option>
                  ))}
                </select>
              </div>
              <div className="baselines-schedule-actions">
                {scheduleSaveError && <span className="pro-inline-error">{scheduleSaveError}</span>}
                <button className="pro-btn pro-btn-primary" onClick={handleScheduleSave} disabled={scheduleSaving}>
                  {scheduleSaving ? "Saving…" : "Save schedule"}
                </button>
              </div>
            </div>

            <div className="baselines-schedule-status pro-muted">
              <span>
                Last success: {scheduleDraft.last_succeeded_at
                  ? formatDateTime(scheduleDraft.last_succeeded_at)
                  : "No successful scheduled capture yet"}
              </span>
              <span>
                Next due: {scheduleDraft.next_due_at
                  ? formatDateTime(scheduleDraft.next_due_at)
                  : scheduleDraft.enabled ? "Awaiting first scheduled capture" : "Disabled"}
              </span>
              <span className={scheduleDraft.last_error ? "baselines-schedule-last-error" : undefined}>
                Latest scheduler error: {scheduleDraft.last_error ?? "None"}
              </span>
            </div>
          </div>
        )}
      </section>

      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Capture a baseline</span>
        </div>
        <div className="panel baselines-capture">
          <input
            className="pro-input baselines-label-input"
            placeholder="Label, e.g. 'Before hardening'"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
          />
          <button className="pro-btn pro-btn-primary" onClick={handleCapture} disabled={capturing || !label.trim()}>
            {capturing ? "Capturing…" : "Capture snapshot"}
          </button>
        </div>
        {captureError && <div className="pro-inline-error">{captureError}</div>}
        <p className="pro-muted">
          A snapshot records current posture check results, the traffic profile (external peers, local listeners),
          and the composite security score, so you can answer "what changed since last time?".
        </p>
      </section>

      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Snapshots</span>
        </div>

        {error && <ErrorState title="Couldn't load baselines" detail={error} />}
        {!error && loading && <SkeletonRows rows={3} height={30} />}
        {!error && !loading && baselines.length === 0 && <EmptyState title="No snapshots yet" detail="Capture one above to get started." />}

        {baselines.length > 0 && (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Label</th>
                  <th>Origin</th>
                  <th>Captured</th>
                  <th>Checks</th>
                  <th>Peers</th>
                  <th>Listeners</th>
                  <th>Posture</th>
                  <th>Overall</th>
                </tr>
              </thead>
              <tbody>
                {baselines.map((b) => (
                  <tr key={b.id}>
                    <td>{b.label}</td>
                    <td>{b.origin === "scheduled" ? "Scheduled" : "Manual"}</td>
                    <td>{formatDateTime(b.captured_at)}</td>
                    <td>{formatNumber(b.checks_count)}</td>
                    <td>{formatNumber(b.peers_count)}</td>
                    <td>{formatNumber(b.listeners_count)}</td>
                    <td>{b.posture_score}</td>
                    <td>{b.overall_score}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {baselines.length >= 2 && (
        <section className="view-section">
          <div className="view-section-header">
            <span className="view-section-title">Diff two snapshots</span>
          </div>
          <div className="panel">
            <div className="pro-form-grid">
              <div className="pro-field">
                <label className="pro-field-label" htmlFor="baseline-from">From</label>
                <select id="baseline-from" className="pro-select" value={fromId} onChange={(e) => setFromId(e.target.value)}>
                  <option value="">Select…</option>
                  {baselines.map((b) => (
                    <option key={b.id} value={b.id}>{b.label}</option>
                  ))}
                </select>
              </div>
              <div className="pro-field">
                <label className="pro-field-label" htmlFor="baseline-to">To</label>
                <select id="baseline-to" className="pro-select" value={toId} onChange={(e) => setToId(e.target.value)}>
                  <option value="">Select…</option>
                  {baselines.map((b) => (
                    <option key={b.id} value={b.id}>{b.label}</option>
                  ))}
                </select>
              </div>
            </div>
            <button className="pro-btn pro-btn-primary" onClick={handleDiff} disabled={!fromId || !toId || fromId === toId || diffLoading}>
              {diffLoading ? "Comparing…" : "Compare"}
            </button>
            {diffError && <div className="pro-inline-error">{diffError}</div>}
          </div>

          {diff && (
            <div className="panel baselines-diff">
              <div className="baselines-diff-header">
                <span>{diff.from.label} ({formatDateTime(diff.from.captured_at)})</span>
                <span aria-hidden="true">→</span>
                <span>{diff.to.label} ({formatDateTime(diff.to.captured_at)})</span>
              </div>

              <div className="baselines-score-row">
                <div><span className="pro-field-label">Posture</span> <Delta value={diff.score_delta.posture} /></div>
                <div><span className="pro-field-label">Threats</span> <Delta value={diff.score_delta.threats} /></div>
                <div><span className="pro-field-label">Overall</span> <Delta value={diff.score_delta.overall} /></div>
              </div>

              <div className="baselines-groups">
                <DiffGroup title="Fixed" tone="good" empty="No checks improved.">
                  {diff.checks.fixed.map((c) => (
                    <li key={c.id}><span className="mono">{c.id}</span>: {c.from} → {c.to}</li>
                  ))}
                </DiffGroup>
                <DiffGroup title="Regressed" tone="bad" empty="Nothing got worse.">
                  {diff.checks.regressed.map((c) => (
                    <li key={c.id}><span className="mono">{c.id}</span>: {c.from} → {c.to}</li>
                  ))}
                </DiffGroup>
                <DiffGroup title="Added checks" tone="neutral" empty="No new checks since the first snapshot.">
                  {diff.checks.added.map((c) => (
                    <li key={c.id}><span className="mono">{c.id}</span>: now {c.status}</li>
                  ))}
                </DiffGroup>
                <DiffGroup title="Removed checks" tone="neutral" empty="No checks disappeared.">
                  {diff.checks.removed.map((c) => (
                    <li key={c.id}><span className="mono">{c.id}</span>: was {c.status}</li>
                  ))}
                </DiffGroup>
                {diff.checks.inconclusive.length > 0 && (
                  <DiffGroup title="Inconclusive" tone="neutral" empty="">
                    {diff.checks.inconclusive.map((c) => (
                      <li key={c.id}><span className="mono">{c.id}</span>: {c.from} → {c.to} (no usable evidence on one side)</li>
                    ))}
                  </DiffGroup>
                )}
                <div className="baselines-unchanged pro-muted">{diff.checks.unchanged_count} checks unchanged.</div>
              </div>

              <div className="baselines-groups">
                <DiffGroup title="New external peers" tone="neutral" empty="No new external peers.">
                  {diff.new_peers.map((p) => <li key={p} className="mono">{p}</li>)}
                </DiffGroup>
                <DiffGroup title="New listeners" tone="bad" empty="No new listeners.">
                  {diff.new_listeners.map((l) => <li key={`${l.port}-${l.process}`}>port {l.port} · {l.process}</li>)}
                </DiffGroup>
                <DiffGroup title="Removed listeners" tone="good" empty="No listeners removed.">
                  {diff.removed_listeners.map((l) => <li key={`${l.port}-${l.process}`}>port {l.port} · {l.process}</li>)}
                </DiffGroup>
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  );
}

function DiffGroup({ title, tone, empty, children }: { title: string; tone: "good" | "bad" | "neutral"; empty: string; children: React.ReactNode }) {
  const hasChildren = Array.isArray(children) ? children.length > 0 : Boolean(children);
  return (
    <div className={`baselines-diff-group baselines-diff-group-${tone}`}>
      <div className="baselines-diff-group-title">{title}</div>
      {hasChildren ? <ul className="baselines-diff-list">{children}</ul> : <div className="pro-muted">{empty}</div>}
    </div>
  );
}
