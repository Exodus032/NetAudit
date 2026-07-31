import { ConnectionsPanel } from "./ConnectionsPanel";
import { DevicesPanel } from "./DevicesPanel";

export function ConnectionsView() {
  return (
    <div>
      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Live connections</span>
        </div>
        <div className="panel">
          <ConnectionsPanel />
        </div>
      </section>
      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">LAN devices</span>
        </div>
        <div className="panel">
          <DevicesPanel />
        </div>
      </section>
    </div>
  );
}
