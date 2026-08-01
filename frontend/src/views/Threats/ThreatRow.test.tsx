import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { Threat } from "../../api/types";
import { ThreatRow } from "./ThreatRow";

const threat: Threat = {
  id: "thr-1",
  detector_id: "c2_beaconing",
  title: "Periodic beaconing to unknown host",
  severity: "high",
  confidence: 0.9,
  category: "command_and_control",
  status: "active",
  mitre: [],
  summary: "Regular outbound connections at a fixed interval.",
  detail: "Details.",
  evidence: [],
  indicators: [],
  metrics: {},
  first_seen: "2026-07-31T10:00:00Z",
  last_seen: "2026-07-31T12:00:00Z",
  occurrences: 12,
  related_connection_ids: [],
  related_log_ids: [],
  false_positive_notes: "",
  recommended_actions: [],
};

describe("ThreatRow", () => {
  it("surfaces an error when acknowledging fails", async () => {
    const onAcknowledge = vi.fn().mockRejectedValue(new Error("backend said no"));

    render(<ThreatRow threat={threat} onAcknowledge={onAcknowledge} onUnacknowledge={vi.fn()} />);

    fireEvent.click(screen.getByRole("button", { name: "Acknowledge" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("backend said no");
    expect(onAcknowledge).toHaveBeenCalledWith("thr-1");
  });

  it("shows no error when acknowledging succeeds", async () => {
    const onAcknowledge = vi.fn().mockResolvedValue(undefined);

    render(<ThreatRow threat={threat} onAcknowledge={onAcknowledge} onUnacknowledge={vi.fn()} />);

    fireEvent.click(screen.getByRole("button", { name: "Acknowledge" }));

    expect(await screen.findByRole("button", { name: "Acknowledge" })).toBeEnabled();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
