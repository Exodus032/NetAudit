import type { StatsWindow } from "../../api/types";
import "./WindowSelector.css";

const WINDOWS: { id: StatsWindow; label: string }[] = [
  { id: "5m", label: "5m" },
  { id: "15m", label: "15m" },
  { id: "1h", label: "1h" },
  { id: "24h", label: "24h" },
];

export function WindowSelector({ value, onChange }: { value: StatsWindow; onChange: (w: StatsWindow) => void }) {
  return (
    <div className="window-selector" role="group" aria-label="Time window">
      {WINDOWS.map((w) => (
        <button
          key={w.id}
          className={`window-btn${value === w.id ? " active" : ""}`}
          aria-pressed={value === w.id}
          onClick={() => onChange(w.id)}
        >
          {w.label}
        </button>
      ))}
    </div>
  );
}
