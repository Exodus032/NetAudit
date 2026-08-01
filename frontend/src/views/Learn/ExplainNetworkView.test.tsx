import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ExplainNetworkView } from "./ExplainNetworkView";

describe("ExplainNetworkView", () => {
  it("explains capture limits and confirms that observation never changes the system", () => {
    render(<ExplainNetworkView />);

    expect(
      screen.getByRole("heading", { name: "What is my network doing?" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/cannot prove that nothing is wrong/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/never changes your system/i)).toBeInTheDocument();
    expect(
      screen.getByText(/capture tier.*changes what NetAudit can observe/i),
    ).toBeInTheDocument();
  });

  it("navigates to each chapter in order", () => {
    const onNavigate = vi.fn();
    const navigationActions = [
      ["Open overview", "overview"],
      ["Open traffic log", "traffic"],
      ["Open connections and devices", "connections"],
      ["Open recommended actions", "recommendations"],
      ["Open security posture", "posture"],
      ["Open threats", "threats"],
      ["Review a suggested fix", "recommendations"],
    ] as const;

    render(<ExplainNetworkView onNavigate={onNavigate} />);

    navigationActions.forEach(([label]) => {
      fireEvent.click(screen.getByRole("button", { name: label }));
    });

    expect(onNavigate).toHaveBeenCalledTimes(navigationActions.length);
    navigationActions.forEach(([, view], index) => {
      expect(onNavigate).toHaveBeenNthCalledWith(index + 1, view);
    });
  });
});
