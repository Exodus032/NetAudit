import { SegmentedBar } from "../../components/common/SegmentedBar";
import { formatBytes } from "../../lib/format";
import type { StatsSummary } from "../../api/types";

export function EncryptedSplit({ summary }: { summary: StatsSummary }) {
  const segments = [
    { key: "encrypted", label: "Encrypted", value: summary.encrypted_bytes, color: "var(--series-1)" },
    { key: "plaintext", label: "Plaintext", value: summary.plaintext_bytes, color: "var(--series-2)" },
  ];
  return <SegmentedBar segments={segments} formatValue={formatBytes} />;
}
