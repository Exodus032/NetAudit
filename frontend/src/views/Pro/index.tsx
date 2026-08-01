// Integration surface for the professional workflows views (Part E/F of
// docs/API_CONTRACT_V3.md). Consumed by App.tsx (owned by another agent) —
// nav ids are prefixed `pro-` so they can't collide with the base app's ids.
//
// The view components are lazy-loaded: this package (and recharts, which
// several of these views pull in) is the bulk of the professional workflow
// bundle a student on Overview/Learn never opens, so it shouldn't ship in
// the main chunk. App renders the active view directly with no Suspense
// boundary of its own, so each entry below wraps its lazy component in its
// own <Suspense> — a view here must never suspend into App.

import { lazy, Suspense, type ComponentType } from "react";
import { SkeletonRows } from "../../components/common/States";

const CaptureFilterView = lazy(() =>
  import("./CaptureFilter/CaptureFilterView").then((m) => ({ default: m.CaptureFilterView })),
);
const PcapView = lazy(() => import("./Pcap/PcapView").then((m) => ({ default: m.PcapView })));
const ReportsView = lazy(() => import("./Reports/ReportsView").then((m) => ({ default: m.ReportsView })));
const SiemExportView = lazy(() =>
  import("./SiemExport/SiemExportView").then((m) => ({ default: m.SiemExportView })),
);
const LanScanView = lazy(() => import("./LanScan/LanScanView").then((m) => ({ default: m.LanScanView })));
const BaselinesView = lazy(() => import("./Baselines/BaselinesView").then((m) => ({ default: m.BaselinesView })));
const ComplianceView = lazy(() =>
  import("./Compliance/ComplianceView").then((m) => ({ default: m.ComplianceView })),
);
const AlertsView = lazy(() => import("./Alerts/AlertsView").then((m) => ({ default: m.AlertsView })));

export const PRO_NAV_ITEMS: { id: string; label: string; icon: string }[] = [
  { id: "pro-capture-filter", label: "Capture filter", icon: "⌁" },
  { id: "pro-pcap", label: "PCAP export / import", icon: "⇵" },
  { id: "pro-reports", label: "Reports", icon: "▦" },
  { id: "pro-siem", label: "SIEM export", icon: "⇥" },
  { id: "pro-lanscan", label: "LAN scan", icon: "◎" },
  { id: "pro-baselines", label: "Baselines", icon: "⧉" },
  { id: "pro-compliance", label: "Compliance", icon: "☑" },
  { id: "pro-alerts", label: "Alerting", icon: "🔔" },
];

type ProViewProps = { onNavigate?: (v: string) => void };

// One Suspense-wrapped component per map entry, so a still-loading pro chunk
// never suspends past this boundary into App's own render.
function withSuspense(LazyView: ComponentType<ProViewProps>): ComponentType<ProViewProps> {
  return function SuspendedProView(props: ProViewProps) {
    return (
      <Suspense fallback={<SkeletonRows />}>
        <LazyView {...props} />
      </Suspense>
    );
  };
}

export const PRO_VIEWS: Record<string, ComponentType<ProViewProps>> = {
  "pro-capture-filter": withSuspense(CaptureFilterView),
  "pro-pcap": withSuspense(PcapView),
  "pro-reports": withSuspense(ReportsView),
  "pro-siem": withSuspense(SiemExportView),
  "pro-lanscan": withSuspense(LanScanView),
  "pro-baselines": withSuspense(BaselinesView),
  "pro-compliance": withSuspense(ComplianceView),
  "pro-alerts": withSuspense(AlertsView),
};
