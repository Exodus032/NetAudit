import { useEffect, useState } from "react";
import { useAlertsConfig, useAlertsHistory, useAlertTest } from "../../../hooks/useAlerts";
import { ErrorState, EmptyState, SkeletonRows } from "../../../components/common/States";
import { formatDateTime } from "../../../lib/format";
import type { AlertChannel, AlertsConfig } from "../../../api/typesPro";
import type { Severity } from "../../../api/types";
import "../../../components/pro/pro-common.css";
import "./AlertsView.css";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function newWebhookChannel(): AlertChannel {
  return { id: `webhook-${Date.now().toString(36)}`, kind: "webhook", enabled: false, url: "", template: "json", last_status: null, last_attempt: null };
}

export function AlertsView() {
  const { config, loading, error, saving, saveError, save } = useAlertsConfig();
  const { pending, results, test } = useAlertTest();
  const { history, loading: historyLoading, error: historyError } = useAlertsHistory();

  const [draft, setDraft] = useState<AlertsConfig | null>(null);

  useEffect(() => {
    if (config) setDraft(config);
  }, [config]);

  if (loading || !draft) {
    return (
      <div className="panel">
        <SkeletonRows rows={4} height={30} />
      </div>
    );
  }

  const updateChannel = (id: string, patch: Partial<AlertChannel>) => {
    setDraft((cur) => cur && { ...cur, channels: cur.channels.map((c) => (c.id === id ? { ...c, ...patch } : c)) });
  };

  const addWebhook = () => {
    setDraft((cur) => cur && { ...cur, channels: [...cur.channels, newWebhookChannel()] });
  };

  const removeChannel = (id: string) => {
    setDraft((cur) => cur && { ...cur, channels: cur.channels.filter((c) => c.id !== id) });
  };

  const handleSave = () => {
    if (draft) void save(draft);
  };

  return (
    <div>
      {error && <ErrorState title="Couldn't load alert configuration" detail={error} />}

      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Alerting</span>
        </div>

        <div className="pro-notice">
          <span className="pro-notice-icon" aria-hidden="true">🛡</span>
          <div>
            A webhook URL is the only outbound network destination NetAudit will ever contact, and only after you
            enable it here. It must be <code className="mono">https</code>, and every send is re-validated against
            private/loopback address ranges — including DNS rebinding, at send time, not just when you save.
          </div>
        </div>

        <div className="panel alerts-config-panel">
          <div className="pro-form-grid">
            <label className="pro-checkbox alerts-enable-toggle">
              <input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} />
              Alerting enabled
            </label>
            <div className="pro-field">
              <label className="pro-field-label" htmlFor="alerts-min-sev">Minimum severity</label>
              <select
                id="alerts-min-sev"
                className="pro-select"
                value={draft.min_severity}
                onChange={(e) => setDraft({ ...draft, min_severity: e.target.value as Severity })}
              >
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
            <div className="pro-field">
              <label className="pro-field-label" htmlFor="alerts-rate">Rate limit / hour</label>
              <input
                id="alerts-rate"
                className="pro-input"
                type="number"
                min={1}
                value={draft.rate_limit_per_hour}
                onChange={(e) => setDraft({ ...draft, rate_limit_per_hour: Number(e.target.value) })}
              />
            </div>
            <div className="pro-field">
              <label className="pro-field-label">Quiet hours</label>
              <div className="alerts-quiet-hours">
                <input
                  type="time"
                  className="pro-input"
                  value={draft.quiet_hours?.start ?? ""}
                  onChange={(e) => setDraft({ ...draft, quiet_hours: { start: e.target.value, end: draft.quiet_hours?.end ?? "07:00" } })}
                />
                <span className="pro-muted">to</span>
                <input
                  type="time"
                  className="pro-input"
                  value={draft.quiet_hours?.end ?? ""}
                  onChange={(e) => setDraft({ ...draft, quiet_hours: { start: draft.quiet_hours?.start ?? "23:00", end: e.target.value } })}
                />
              </div>
            </div>
          </div>

          <div className="pro-field-label">Channels</div>
          <div className="pro-list">
            {draft.channels.map((c) => {
              const testResult = results[c.id];
              return (
                <div key={c.id} className="pro-card alerts-channel-card">
                  <div className="pro-card-main">
                    <div className="pro-card-title">
                      {c.kind === "desktop" ? "Desktop notification" : "Webhook"}
                      {c.last_status && <span className={`alerts-last-status alerts-status-${c.last_status}`}>{c.last_status}</span>}
                    </div>
                    {c.kind === "webhook" && (
                      <input
                        className="pro-input alerts-webhook-url"
                        placeholder="https://hooks.example.com/…"
                        value={c.url ?? ""}
                        onChange={(e) => updateChannel(c.id, { url: e.target.value })}
                      />
                    )}
                    <div className="pro-card-meta">
                      {c.last_attempt && <span>Last attempt {formatDateTime(c.last_attempt)}</span>}
                      {testResult && <span>Test: {testResult.status}{testResult.detail ? ` — ${testResult.detail}` : ""}</span>}
                    </div>
                  </div>
                  <div className="pro-card-actions">
                    <label className="pro-checkbox">
                      <input type="checkbox" checked={c.enabled} onChange={(e) => updateChannel(c.id, { enabled: e.target.checked })} />
                      Enabled
                    </label>
                    <button className="pro-btn" onClick={() => void test(c.id)} disabled={pending === c.id}>
                      {pending === c.id ? "Sending…" : "Send test alert"}
                    </button>
                    {c.kind === "webhook" && (
                      <button className="pro-btn pro-btn-danger" onClick={() => removeChannel(c.id)}>Remove</button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          <div className="pro-section-actions">
            <button className="pro-btn" onClick={addWebhook}>Add webhook channel</button>
            <span className="pro-spacer" />
            {saveError && <span className="pro-inline-error">{saveError}</span>}
            <button className="pro-btn pro-btn-primary" onClick={handleSave} disabled={saving}>
              {saving ? "Saving…" : "Save configuration"}
            </button>
          </div>
        </div>
      </section>

      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Delivery history</span>
        </div>

        {historyError && <ErrorState title="Couldn't load alert history" detail={historyError} />}
        {!historyError && historyLoading && <SkeletonRows rows={3} height={24} />}
        {!historyError && !historyLoading && history.length === 0 && <EmptyState title="No alerts sent yet" />}

        {history.length > 0 && (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Severity</th>
                  <th>Source</th>
                  <th>Title</th>
                  <th>Channels</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h) => (
                  <tr key={h.id}>
                    <td>{formatDateTime(h.ts)}</td>
                    <td>{h.severity}</td>
                    <td>{h.source}</td>
                    <td>{h.title}</td>
                    <td>
                      {h.channels.map((c) => (
                        <span key={c.id} className={`alerts-last-status alerts-status-${c.status}`}>
                          {c.id}: {c.status}
                        </span>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
