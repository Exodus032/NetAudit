import { useState } from "react";
import type { RecommendationAction } from "../../api/types";
import "./ActionItem.css";

export function ActionItem({ action }: { action: RecommendationAction }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    if (!action.command) return;
    try {
      await navigator.clipboard.writeText(action.command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // clipboard API unavailable — no-op, command remains visible to copy manually
    }
  };

  return (
    <li className="action-item">
      <div className="action-item-head">
        <span className="action-item-label">{action.label}</span>
        {action.kind === "command" && action.requires_admin && (
          <span className="action-admin-warning">Requires administrator</span>
        )}
      </div>
      {action.detail && <p className="action-item-detail">{action.detail}</p>}

      {action.kind === "manual" && null}

      {action.kind === "link" && action.url && (
        <a className="action-link" href={action.url} target="_blank" rel="noreferrer noopener">
          Open link ↗
        </a>
      )}

      {action.kind === "command" && action.command && (
        <div className="action-command-block">
          <div className="action-command-notice">Copy only — NetAudit never runs commands for you.</div>
          <div className="action-command-row">
            <code className="action-command mono">{action.command}</code>
            <button className="action-copy-btn" onClick={handleCopy}>
              {copied ? "Copied" : "Copy"}
            </button>
          </div>
        </div>
      )}
    </li>
  );
}
