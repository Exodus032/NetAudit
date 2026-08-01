import { useState } from "react";
import { useCaptureFilter } from "../../../hooks/useCaptureFilter";
import { ErrorState, Skeleton } from "../../../components/common/States";
import "../../../components/pro/pro-common.css";
import "./CaptureFilterView.css";

const EXAMPLES = [
  { expr: "tcp port 443 or udp port 53", note: "HTTPS traffic, plus DNS over UDP" },
  { expr: "host 192.168.1.1", note: "Anything to or from the router" },
  { expr: "net 192.168.1.0/24", note: "Anything on the local subnet" },
  { expr: "tcp and not port 22", note: "TCP traffic excluding SSH" },
  { expr: "(tcp port 80 or tcp port 443) and dst host 10.0.0.5", note: "Web traffic to one host" },
  { expr: "icmp", note: "Ping and other ICMP traffic only" },
];

const GRAMMAR_ROWS: { token: string; meaning: string }[] = [
  { token: "tcp / udp / icmp", meaning: "Match a protocol" },
  { token: "port N", meaning: "Match source or destination port N" },
  { token: "src / dst", meaning: "Qualify the next port/host/net to one direction" },
  { token: "host X", meaning: "Match an exact IP address, either side" },
  { token: "net X/Y", meaning: "Match a CIDR network, either side" },
  { token: "and / or / not", meaning: "Combine terms (juxtaposition also means AND, like tcpdump)" },
  { token: "( … )", meaning: "Group terms to control precedence" },
];

function Caret({ position, length }: { position: number; length: number }) {
  const clamped = Math.max(0, Math.min(position, length));
  return (
    <div className="capfilter-caret-row" aria-hidden="true">
      <span className="capfilter-caret-pad">{" ".repeat(clamped)}</span>
      <span className="capfilter-caret">▲</span>
    </div>
  );
}

export function CaptureFilterView() {
  const { state, loading, loadError, draft, setDraft, saving, saveError, apply, clear } = useCaptureFilter();
  const [justApplied, setJustApplied] = useState(false);

  const handleApply = async () => {
    setJustApplied(false);
    try {
      await apply(draft);
      setJustApplied(true);
      setTimeout(() => setJustApplied(false), 2000);
    } catch {
      // saveError already set by the hook
    }
  };

  return (
    <div>
      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Capture filter</span>
        </div>

        <div className="pro-notice">
          <span className="pro-notice-icon" aria-hidden="true">🛡</span>
          <div>
            <strong>Parsed, never executed.</strong> This expression is tokenised and parsed into a structural syntax
            tree by the backend. It is never passed to a shell and never evaluated with <code className="mono">eval</code>
            or similar — matching is done by walking the parsed tree against each packet's fields.
          </div>
        </div>

        {loadError && <ErrorState title="Couldn't load the capture filter" detail={loadError} />}

        {loading && !state ? (
          <div className="panel">
            <Skeleton height={80} />
          </div>
        ) : (
          state && (
            <div className="panel capfilter-panel">
              <div className="capfilter-status-row">
                <span className={`capfilter-status-pill${state.active ? " active" : ""}`}>
                  {state.active ? "Filter active" : "No filter — capturing everything"}
                </span>
                {state.applies_to_tier.length > 0 && (
                  <span className="pro-muted">Applies via: {state.applies_to_tier.join(", ")}</span>
                )}
              </div>

              <div className="pro-field">
                <label className="pro-field-label" htmlFor="capfilter-input">
                  Expression
                </label>
                <textarea
                  id="capfilter-input"
                  className="pro-input capfilter-textarea mono"
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  placeholder="e.g. tcp port 443 or udp port 53"
                  rows={2}
                  spellCheck={false}
                />
                {saveError && (
                  <div className="capfilter-error">
                    <Caret position={saveError.position} length={draft.length} />
                    <div className="pro-inline-error">
                      {saveError.message} (character {saveError.position})
                    </div>
                  </div>
                )}
              </div>

              <div className="pro-section-actions">
                <button className="pro-btn pro-btn-primary" onClick={handleApply} disabled={saving}>
                  {saving ? "Validating…" : "Apply filter"}
                </button>
                <button className="pro-btn" onClick={() => { setDraft(""); void clear(); }} disabled={saving || !state.active}>
                  Clear filter
                </button>
                {justApplied && <span className="capfilter-applied">Applied</span>}
              </div>

              {state.active && state.compiled_summary && (
                <div className="capfilter-summary">
                  <span className="pro-field-label">Compiled to</span>
                  <code className="mono">{state.compiled_summary}</code>
                </div>
              )}
            </div>
          )
        )}
      </section>

      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Example filters</span>
        </div>
        <div className="pro-list capfilter-examples">
          {EXAMPLES.map((ex) => (
            <button key={ex.expr} className="pro-card capfilter-example-btn" onClick={() => setDraft(ex.expr)}>
              <div className="pro-card-main">
                <div className="pro-card-title mono">{ex.expr}</div>
                <div className="pro-card-meta">{ex.note}</div>
              </div>
              <span className="pro-muted">Use</span>
            </button>
          ))}
        </div>
      </section>

      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Syntax cheat sheet</span>
        </div>
        <div className="panel">
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Token</th>
                  <th>Meaning</th>
                </tr>
              </thead>
              <tbody>
                {GRAMMAR_ROWS.map((row) => (
                  <tr key={row.token}>
                    <td className="mono">{row.token}</td>
                    <td>{row.meaning}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="pro-muted capfilter-footnote">
            This is a subset of real BPF/tcpdump syntax — enough for protocol, port, host and network filtering. It
            does not cover the full BPF language (byte-offset comparisons, link-layer qualifiers like{" "}
            <code className="mono">ether</code>, and so on).
          </p>
        </div>
      </section>
    </div>
  );
}
