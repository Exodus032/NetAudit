import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { Recommendation } from "../../api/types";
import { RecommendationCard } from "./RecommendationCard";

const rec: Recommendation = {
  id: "rec-1",
  rule_id: "plaintext_http",
  title: "Plaintext HTTP to external host",
  severity: "medium",
  confidence: 0.8,
  category: "encryption",
  summary: "Unencrypted traffic observed.",
  detail: "Details.",
  evidence: [],
  actions: [],
  first_seen: "2026-07-31T10:00:00Z",
  last_seen: "2026-07-31T12:00:00Z",
  occurrences: 4,
  dismissed: false,
  related_connection_ids: [],
};

describe("RecommendationCard", () => {
  it("surfaces an error when dismissing fails", async () => {
    const onDismiss = vi.fn().mockRejectedValue(new Error("dismiss failed"));

    render(<RecommendationCard rec={rec} onDismiss={onDismiss} onRestore={vi.fn()} highlight={false} />);

    fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("dismiss failed");
    expect(onDismiss).toHaveBeenCalledWith("rec-1");
  });

  it("shows no error when dismissing succeeds", async () => {
    const onDismiss = vi.fn().mockResolvedValue(undefined);

    render(<RecommendationCard rec={rec} onDismiss={onDismiss} onRestore={vi.fn()} highlight={false} />);

    fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));

    expect(await screen.findByRole("button", { name: "Dismiss" })).toBeEnabled();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
