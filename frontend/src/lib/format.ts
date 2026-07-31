// Shared formatting helpers — compact numbers, bytes, bitrate, relative time.

export function formatBytes(bytes: number, decimals = 1): string {
  if (!Number.isFinite(bytes)) return "0 B";
  if (bytes === 0) return "0 B";
  const sign = bytes < 0 ? "-" : "";
  const abs = Math.abs(bytes);
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(abs) / Math.log(1024)));
  const value = abs / 1024 ** i;
  return `${sign}${value.toFixed(i === 0 ? 0 : decimals)} ${units[i]}`;
}

/** Formats two byte values sharing a single unit suffix, e.g. "16.6 / 36.1 KB"
 * instead of "16.6 KB / 36.1 KB" — shorter, and reads fine since both values
 * are the same kind of quantity side by side. Unit is chosen from whichever
 * value is larger so the smaller one just gets more decimal precision. */
export function formatBytesPair(a: number, b: number, decimals = 1): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  const larger = Math.max(Math.abs(a), Math.abs(b), 1);
  const i = Math.min(units.length - 1, Math.floor(Math.log(larger) / Math.log(1024)));
  const scale = 1024 ** i;
  const fmt = (v: number) => (i === 0 ? Math.round(v / scale).toString() : (v / scale).toFixed(decimals));
  return `${fmt(a)} / ${fmt(b)} ${units[i]}`;
}

export function formatBitrate(bps: number): string {
  if (!Number.isFinite(bps) || bps === 0) return "0 bps";
  const units = ["bps", "Kbps", "Mbps", "Gbps"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(Math.abs(bps)) / Math.log(1000)));
  const value = bps / 1000 ** i;
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export function formatCompactNumber(n: number): string {
  if (!Number.isFinite(n)) return "0";
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

export function formatNumber(n: number): string {
  return new Intl.NumberFormat().format(n);
}

export function formatPercent(fraction: number, decimals = 0): string {
  return `${(fraction * 100).toFixed(decimals)}%`;
}

export function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString(undefined, { hour12: false });
}

export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { hour12: false });
}

export function formatRelativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const diffMs = Date.now() - then;
  const diffSec = Math.round(diffMs / 1000);
  if (diffSec < 5) return "just now";
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.round(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.round(diffHr / 24);
  return `${diffDay}d ago`;
}
