import type { ReactNode } from "react";
import "./States.css";

export function Skeleton({ width = "100%", height = 14 }: { width?: string | number; height?: number }) {
  return <div className="skeleton" style={{ width, height }} aria-hidden="true" />;
}

export function SkeletonRows({ rows = 5, height = 16 }: { rows?: number; height?: number }) {
  return (
    <div className="skeleton-rows" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} height={height} width={`${88 - i * 6}%`} />
      ))}
    </div>
  );
}

export function EmptyState({ title, detail, icon = "◌" }: { title: string; detail?: string; icon?: string }) {
  return (
    <div className="state-panel empty-state">
      <div className="state-icon" aria-hidden="true">{icon}</div>
      <div className="state-title">{title}</div>
      {detail && <div className="state-detail">{detail}</div>}
    </div>
  );
}

export function ErrorState({ title, detail, action }: { title: string; detail?: string; action?: ReactNode }) {
  return (
    <div className="state-panel error-state" role="alert">
      <div className="state-icon" aria-hidden="true">⚠</div>
      <div className="state-title">{title}</div>
      {detail && <div className="state-detail">{detail}</div>}
      {action}
    </div>
  );
}

export function BackendUnreachableNotice() {
  return (
    <div className="backend-notice" role="status">
      <span className="backend-notice-icon" aria-hidden="true">⚠</span>
      <div>
        <strong>Backend unreachable — showing mock data.</strong>{" "}
        Start it with <code className="mono">cd backend &amp;&amp; python -m netaudit.server</code> (as Administrator for
        full capture) and reload.
      </div>
    </div>
  );
}
