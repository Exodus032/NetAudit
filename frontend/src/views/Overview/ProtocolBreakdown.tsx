import { SegmentedBar } from "../../components/common/SegmentedBar";
import { formatCompactNumber } from "../../lib/format";
import type { StatsSummary } from "../../api/types";

export function ProtocolBreakdown({ summary }: { summary: StatsSummary }) {
  const segments = [
    { key: "tcp", label: "TCP", value: summary.tcp_packets, color: "var(--series-1)" },
    { key: "udp", label: "UDP", value: summary.udp_packets, color: "var(--series-2)" },
    { key: "icmp", label: "ICMP", value: summary.icmp_packets, color: "var(--series-3)" },
    { key: "other", label: "Other", value: summary.other_packets, color: "var(--series-4)" },
  ];
  return <SegmentedBar segments={segments} formatValue={(v) => `${formatCompactNumber(v)} pkts`} />;
}
