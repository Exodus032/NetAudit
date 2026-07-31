import type { RecommendationAction } from "../../api/types";
import { CommandBlock } from "../../components/common/CommandBlock";
import "./ActionItem.css";

export function ActionItem({ action }: { action: RecommendationAction }) {
  return (
    <li className="action-item">
      <div className="action-item-head">
        <span className="action-item-label">{action.label}</span>
      </div>
      {action.detail && <p className="action-item-detail">{action.detail}</p>}

      {action.kind === "link" && action.url && (
        <a className="action-link" href={action.url} target="_blank" rel="noreferrer noopener">
          Open link ↗
        </a>
      )}

      {action.kind === "command" && action.command && (
        <CommandBlock command={action.command} requiresAdmin={action.requires_admin} />
      )}
    </li>
  );
}
