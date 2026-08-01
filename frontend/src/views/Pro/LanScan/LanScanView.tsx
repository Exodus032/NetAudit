import { useEffect, useState } from "react";
import { useLanScan } from "../../../hooks/useLanScan";
import { getInterfaces } from "../../../api/client";
import { EmptyState } from "../../../components/common/States";
import { ProgressBar } from "../../../components/pro/ProgressBar";
import { formatNumber } from "../../../lib/format";
import { LAN_SCAN_LIMITS } from "../../../api/typesPro";
import "../../../components/pro/pro-common.css";
import "./LanScanView.css";

const DEFAULT_PORTS = "22,80,443,445,3389";

/** `192.168.0.0` from `192.168.0.53` + `255.255.255.0`. Returns null for
 *  anything that isn't a plain IPv4 dotted quad and mask. */
function networkCidr(ipv4: string, netmask: string): string | null {
  const addr = ipv4.split(".").map(Number);
  const mask = netmask.split(".").map(Number);
  if (addr.length !== 4 || mask.length !== 4) return null;
  if ([...addr, ...mask].some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  const prefixLen = mask.reduce((bits, octet) => bits + ((octet >>> 0).toString(2).match(/1/g)?.length ?? 0), 0);
  const network = addr.map((octet, i) => octet & mask[i]).join(".");
  return `${network}/${prefixLen}`;
}

export function LanScanView() {
  const { job, starting, error, start, cancel } = useLanScan();
  // Seeded from whatever subnet this machine is actually on. The backend
  // refuses a subnet it has no interface on, so a hardcoded 192.168.1.0/24
  // guaranteed an error on the first click for anyone whose router hands
  // out anything else.
  const [subnet, setSubnet] = useState("");
  const [portsInput, setPortsInput] = useState(DEFAULT_PORTS);
  const [ratePps, setRatePps] = useState(50);

  useEffect(() => {
    let cancelled = false;
    getInterfaces()
      .then((res) => {
        if (cancelled) return;
        const usable = res.interfaces.find((i) => i.is_up && !i.is_loopback && i.ipv4 && i.netmask);
        const cidr = usable?.ipv4 && usable.netmask ? networkCidr(usable.ipv4, usable.netmask) : null;
        // Only /24 or narrower is scannable, so don't prefill a /16 the
        // backend would reject; leave it blank and let the user say.
        setSubnet(cidr && Number(cidr.split("/")[1]) >= 24 ? cidr : "");
      })
      .catch(() => {
        // Not worth an error state: the field is editable either way.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const parsedPorts = portsInput
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean)
    .map(Number)
    .filter((n) => Number.isInteger(n) && n >= 0 && n <= 65535);

  const tooManyPorts = parsedPorts.length > LAN_SCAN_LIMITS.maxPorts;
  const running = job?.status === "running";

  const handleStart = async () => {
    if (tooManyPorts || parsedPorts.length === 0 || !subnet.trim()) return;
    try {
      await start({ subnet, ports: parsedPorts, rate_limit_pps: Math.min(ratePps, LAN_SCAN_LIMITS.maxRatePps) });
    } catch {
      // useLanScan stored the message in `error`, rendered above the actions.
    }
  };

  const handleCancel = () => {
    cancel().catch(() => {
      // Same: the hook surfaces the failure through its `error` state.
    });
  };

  return (
    <div>
      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Active LAN scan</span>
        </div>

        <div className="pro-guarantees">
          <div className="pro-guarantee">
            <div className="pro-guarantee-value">RFC1918 only</div>
            <div className="pro-guarantee-label">Target must be a private subnet this machine has an interface on</div>
          </div>
          <div className="pro-guarantee">
            <div className="pro-guarantee-value">/{LAN_SCAN_LIMITS.maxPrefixLen} max</div>
            <div className="pro-guarantee-label">Largest subnet allowed per request</div>
          </div>
          <div className="pro-guarantee">
            <div className="pro-guarantee-value">{LAN_SCAN_LIMITS.maxPorts} ports max</div>
            <div className="pro-guarantee-label">Per scan request</div>
          </div>
          <div className="pro-guarantee">
            <div className="pro-guarantee-value">{LAN_SCAN_LIMITS.maxRatePps} pps cap</div>
            <div className="pro-guarantee-label">Rate limit enforced by real pacing, not just a stored number</div>
          </div>
          <div className="pro-guarantee">
            <div className="pro-guarantee-value">{LAN_SCAN_LIMITS.scanKind}</div>
            <div className="pro-guarantee-label">No SYN/stealth scanning, fingerprinting, or exploitation</div>
          </div>
        </div>

        <div className="pro-notice pro-notice-warn">
          <span className="pro-notice-icon" aria-hidden="true">⚠</span>
          <div>{job?.consent_notice ?? "This sends real TCP connection attempts to other devices on your local network. Only run it on a network you are authorised to test."}</div>
        </div>

        <div className="panel lanscan-form">
          <div className="pro-form-grid">
            <div className="pro-field">
              <label className="pro-field-label" htmlFor="lanscan-subnet">Subnet (CIDR)</label>
              <input
                id="lanscan-subnet"
                className="pro-input mono"
                value={subnet}
                placeholder="192.168.0.0/24"
                onChange={(e) => setSubnet(e.target.value)}
                disabled={running}
              />
            </div>
            <div className="pro-field">
              <label className="pro-field-label" htmlFor="lanscan-ports">Ports (comma-separated, max {LAN_SCAN_LIMITS.maxPorts})</label>
              <input id="lanscan-ports" className="pro-input mono" value={portsInput} onChange={(e) => setPortsInput(e.target.value)} disabled={running} />
            </div>
            <div className="pro-field">
              <label className="pro-field-label" htmlFor="lanscan-rate">Rate limit (pps, max {LAN_SCAN_LIMITS.maxRatePps})</label>
              <input
                id="lanscan-rate"
                className="pro-input"
                type="number"
                min={1}
                max={LAN_SCAN_LIMITS.maxRatePps}
                value={ratePps}
                onChange={(e) => setRatePps(Number(e.target.value))}
                disabled={running}
              />
            </div>
          </div>

          {tooManyPorts && <div className="pro-inline-error">Too many ports — {LAN_SCAN_LIMITS.maxPorts} max per scan.</div>}
          {error && <div className="pro-inline-error">{error}</div>}

          <div className="pro-section-actions">
            {!running ? (
              <button className="pro-btn pro-btn-primary" onClick={handleStart} disabled={starting || parsedPorts.length === 0 || tooManyPorts || !subnet.trim()}>
                {starting ? "Starting…" : "Start scan"}
              </button>
            ) : (
              <button className="pro-btn pro-btn-danger" onClick={handleCancel}>Cancel scan</button>
            )}
          </div>
        </div>
      </section>

      {job && (
        <section className="view-section">
          <div className="view-section-header">
            <span className="view-section-title">Scan status</span>
            <span className={`lanscan-status-pill lanscan-status-${job.status}`}>{job.status}</span>
          </div>
          <div className="panel">
            <ProgressBar
              percent={job.progress.total ? (job.progress.scanned / job.progress.total) * 100 : 0}
              label={`${formatNumber(job.progress.scanned)} / ${formatNumber(job.progress.total)} hosts scanned`}
              done={job.status === "completed"}
              error={job.status === "error"}
            />
            {job.error && <div className="pro-inline-error">{job.error}</div>}

            <div className="lanscan-results">
              {job.results.length === 0 ? (
                <EmptyState title="No responsive hosts yet" detail="Results appear here as the scan progresses." />
              ) : (
                <div className="table-container">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>IP address</th>
                        <th>Open ports</th>
                      </tr>
                    </thead>
                    <tbody>
                      {job.results.map((r) => (
                        <tr key={r.ip}>
                          <td className="mono">{r.ip}</td>
                          <td>{r.open_ports.length ? r.open_ports.join(", ") : <span className="pro-muted">none of the requested ports</span>}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </section>
      )}
    </div>
  );
}
