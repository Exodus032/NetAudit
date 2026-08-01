import "./pro-common.css";

export function ProgressBar({
  percent,
  label,
  done,
  error,
}: {
  percent: number;
  label?: string;
  done?: boolean;
  error?: boolean;
}) {
  const clamped = Math.max(0, Math.min(100, percent));
  return (
    <div>
      <div className="pro-progress-track">
        <div
          className={`pro-progress-fill${done ? " pro-progress-done" : ""}${error ? " pro-progress-error" : ""}`}
          style={{ width: `${clamped}%` }}
        />
      </div>
      <div className="pro-progress-label">
        <span>{label}</span>
        <span className="tabular">{Math.round(clamped)}%</span>
      </div>
    </div>
  );
}
