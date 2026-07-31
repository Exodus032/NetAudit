import { useState } from "react";
import "./CommandBlock.css";

interface CommandBlockProps {
  command: string;
  requiresAdmin?: boolean;
  riskNote?: string;
}

/** Copy-only command display, reused everywhere NetAudit shows a command to
 * the user (recommendations, posture remediation, threat actions). This is
 * the ONE mechanism for surfacing a command — there is deliberately no way
 * to execute it from the UI. */
export function CommandBlock({ command, requiresAdmin, riskNote }: CommandBlockProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // clipboard API unavailable — no-op, command remains visible to copy manually
    }
  };

  return (
    <div className="command-block">
      <div className="command-block-notice">
        Copy only — NetAudit never runs commands for you.
        {requiresAdmin && <span className="command-admin-warning">Requires administrator</span>}
      </div>
      <div className="command-block-row">
        <code className="command-block-code mono">{command}</code>
        <button className="command-copy-btn" onClick={handleCopy}>
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      {riskNote && <div className="command-risk-note">{riskNote}</div>}
    </div>
  );
}
