import { useEffect, useState } from "react";
import { useAlertsConfig, useAlertsHistory, useAlertTest, useEnrichmentConfig, useEnrichmentTest } from "../../../hooks/useAlerts";
import { ErrorState, EmptyState, SkeletonRows } from "../../../components/common/States";
import { formatDateTime } from "../../../lib/format";
import type { AlertChannel, AlertsConfig, EnrichmentConfig, EnrichmentProviderUpdate } from "../../../api/typesPro";
import type { Severity } from "../../../api/types";
import "../../../components/pro/pro-common.css";
import "./AlertsView.css";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function newWebhookChannel(): AlertChannel {
  return { id: `webhook-${Date.now().toString(36)}`, kind: "webhook", enabled: false, url: "", template: "json", last_status: null, last_attempt: null };
}

function newSlackChannel(): AlertChannel {
  return { id: `slack-${Date.now().toString(36)}`, kind: "slack", enabled: false, url: "", template: "json", last_status: null, last_attempt: null };
}

export function AlertsView() {
  const { config, loading, error, saving, saveError, save } = useAlertsConfig();
  const { pending, results, test } = useAlertTest();
  const { history, loading: historyLoading, error: historyError } = useAlertsHistory();
  const {
    config: enrichConfig,
    loading: enrichLoading,
    error: enrichError,
    saving: enrichSaving,
    saveError: enrichSaveError,
    save: saveEnrich,
  } = useEnrichmentConfig();
  const { pending: enrichPending, results: enrichTestResults, test: testEnrich } = useEnrichmentTest();

  const [draft, setDraft] = useState<AlertsConfig | null>(null);
  const [testErrors, setTestErrors] = useState<Record<string, string>>({});
  const [enrichDraft, setEnrichDraft] = useState<EnrichmentConfig | null>(null);
  const [keyDrafts, setKeyDrafts] = useState<Record<string, string>>({});
  const [enrichTestErrors, setEnrichTestErrors] = useState<Record<string, string>>({});

  const handleTest = (id: string) => {
    setTestErrors((cur) => {
      const next = { ...cur };
      delete next[id];
      return next;
    });
    test(id).catch((err) => {
      setTestErrors((cur) => ({ ...cur, [id]: err instanceof Error ? err.message : String(err) }));
    });
  };

  useEffect(() => {
    if (config) setDraft(config);
  }, [config]);

  useEffect(() => {
    if (enrichConfig) setEnrichDraft(enrichConfig);
  }, [enrichConfig]);

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

  const addSlack = () => {
    setDraft((cur) => cur && { ...cur, channels: [...cur.channels, newSlackChannel()] });
  };

  const removeChannel = (id: string) => {
    setDraft((cur) => cur && { ...cur, channels: cur.channels.filter((c) => c.id !== id) });
  };

  const handleSave = () => {
    if (draft) void save(draft);
  };

  const updateEnrichProvider = (id: string, patch: Partial<EnrichmentConfig["providers"][number]>) => {
    setEnrichDraft((cur) => cur && { ...cur, providers: cur.providers.map((p) => (p.id === id ? { ...p, ...patch } : p)) });
  };

  const handleEnrichTest = (id: string) => {
    setEnrichTestErrors((cur) => {
      const next = { ...cur };
      delete next[id];
      return next;
    });
    testEnrich(id).catch((err) => {
      setEnrichTestErrors((cur) => ({ ...cur, [id]: err instanceof Error ? err.message : String(err) }));
    });
  };

  const handleEnrichSave = () => {
    if (!enrichDraft) return;
    const providers: EnrichmentProviderUpdate[] = enrichDraft.providers.map((p) => {
      const typed = keyDrafts[p.id] ?? "";
      return {
        id: p.id,
        enabled: p.enabled,
        // An empty field on a provider that already has a key means "clear
        // it"; otherwise null means "keep whatever is stored".
        api_key: typed ? typed : null,
        clear_key: typed === "" && p.has_key,
      };
    });
    void saveEnrich({
      enabled: enrichDraft.enabled,
      min_severity: enrichDraft.min_severity,
      cache_ttl_hours: enrichDraft.cache_ttl_hours,
      providers,
    });
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
            Alert webhooks (generic or Slack) and IP reputation enrichment (AbuseIPDB/VirusTotal, below) are the only
            outbound network destinations NetAudit will ever contact, and only after you enable them here. Webhook URLs
            must be <code className="mono">https</code> and every send is re-validated against private/loopback address
            ranges — including DNS rebinding, at send time, not just when you save. Enrichment sends only public IPs,
            never internal addresses, and only when a provider is enabled with your own key.
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
                      {c.kind === "desktop" ? "Desktop notification" : c.kind === "slack" ? "Slack webhook" : "Webhook"}
                      {c.last_status && <span className={`alerts-last-status alerts-status-${c.last_status}`}>{c.last_status}</span>}
                    </div>
                    {(c.kind === "webhook" || c.kind === "slack") && (
                      <input
                        className="pro-input alerts-webhook-url"
                        placeholder={c.kind === "slack" ? "https://hooks.slack.com/services/…" : "https://hooks.example.com/…"}
                        value={c.url ?? ""}
                        onChange={(e) => updateChannel(c.id, { url: e.target.value })}
                      />
                    )}
                    <div className="pro-card-meta">
                      {c.last_attempt && <span>Last attempt {formatDateTime(c.last_attempt)}</span>}
                      {testResult && <span>Test: {testResult.status}{testResult.detail ? ` — ${testResult.detail}` : ""}</span>}
                      {testErrors[c.id] && <span className="pro-inline-error">Test failed: {testErrors[c.id]}</span>}
                    </div>
                  </div>
                  <div className="pro-card-actions">
                    <label className="pro-checkbox">
                      <input type="checkbox" checked={c.enabled} onChange={(e) => updateChannel(c.id, { enabled: e.target.checked })} />
                      Enabled
                    </label>
                    <button className="pro-btn" onClick={() => handleTest(c.id)} disabled={pending === c.id}>
                      {pending === c.id ? "Sending…" : "Send test alert"}
                    </button>
                    {c.kind !== "desktop" && (
                      <button className="pro-btn pro-btn-danger" onClick={() => removeChannel(c.id)}>Remove</button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          <div className="pro-section-actions">
            <button className="pro-btn" onClick={addWebhook}>Add webhook channel</button>
            <button className="pro-btn" onClick={addSlack}>Add Slack channel</button>
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
          <span className="view-section-title">IP enrichment</span>
        </div>

        {enrichError && <ErrorState title="Couldn't load enrichment config" detail={enrichError} />}

        {enrichLoading || !enrichDraft ? (
          <div className="panel">
            <SkeletonRows rows={3} height={30} />
          </div>
        ) : (
          <div className="panel alerts-config-panel">
            <div className="pro-form-grid">
              <label className="pro-checkbox alerts-enable-toggle">
                <input
                  type="checkbox"
                  checked={enrichDraft.enabled}
                  onChange={(e) => setEnrichDraft({ ...enrichDraft, enabled: e.target.checked })}
                />
                Enrichment enabled
              </label>
              <div className="pro-field">
                <label className="pro-field-label" htmlFor="enrich-min-sev">Minimum severity</label>
                <select
                  id="enrich-min-sev"
                  className="pro-select"
                  value={enrichDraft.min_severity}
                  onChange={(e) => setEnrichDraft({ ...enrichDraft, min_severity: e.target.value as Severity })}
                >
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </div>
              <div className="pro-field">
                <label className="pro-field-label" htmlFor="enrich-ttl">Cache TTL (hours)</label>
                <input
                  id="enrich-ttl"
                  className="pro-input"
                  type="number"
                  min={1}
                  value={enrichDraft.cache_ttl_hours}
                  onChange={(e) => setEnrichDraft({ ...enrichDraft, cache_ttl_hours: Number(e.target.value) })}
                />
              </div>
            </div>

            <div className="pro-list">
              {enrichDraft.providers.map((p) => {
                const testResult = enrichTestResults[p.id];
                return (
                  <div key={p.id} className="pro-card alerts-channel-card">
                    <div className="pro-card-main">
                      <div className="pro-card-title">
                        {p.id === "abuseipdb" ? "AbuseIPDB" : "VirusTotal"}
                        {p.last_status && <span className={`alerts-last-status alerts-status-${p.last_status}`}>{p.last_status}</span>}
                      </div>
                      <input
                        type="password"
                        className="pro-input alerts-webhook-url"
                        placeholder={p.has_key ? "API key stored — type to replace" : "Paste your own API key"}
                        value={keyDrafts[p.id] ?? ""}
                        onChange={(e) => setKeyDrafts((cur) => ({ ...cur, [p.id]: e.target.value }))}
                        autoComplete="off"
                      />
                      <div className="pro-card-meta">
                        {p.has_key && <span>Key saved</span>}
                        {p.last_attempt && <span>Last attempt {formatDateTime(p.last_attempt)}</span>}
                        {testResult && <span>Test: {testResult.status}{testResult.detail ? ` — ${testResult.detail}` : ""}</span>}
                        {enrichTestErrors[p.id] && <span className="pro-inline-error">Test failed: {enrichTestErrors[p.id]}</span>}
                      </div>
                    </div>
                    <div className="pro-card-actions">
                      <label className="pro-checkbox">
                        <input
                          type="checkbox"
                          checked={p.enabled}
                          onChange={(e) => updateEnrichProvider(p.id, { enabled: e.target.checked })}
                        />
                        Enabled
                      </label>
                      <button className="pro-btn" onClick={() => handleEnrichTest(p.id)} disabled={enrichPending === p.id}>
                        {enrichPending === p.id ? "Testing…" : "Test key"}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="pro-section-actions">
              <span className="pro-muted">Sends only public IPs to the providers you enable. Off until you save.</span>
              <span className="pro-spacer" />
              {enrichSaveError && <span className="pro-inline-error">{enrichSaveError}</span>}
              <button className="pro-btn pro-btn-primary" onClick={handleEnrichSave} disabled={enrichSaving}>
                {enrichSaving ? "Saving…" : "Save enrichment"}
              </button>
            </div>
          </div>
        )}
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
