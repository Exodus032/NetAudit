import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Header } from "./Header";

describe("Header", () => {
  it("opens the network explanation when requested", () => {
    const onExplainNetwork = vi.fn();

    render(
      <Header
        viewId="overview"
        connectionState="open"
        theme="dark"
        onToggleTheme={vi.fn()}
        learningMode={false}
        onToggleLearningMode={vi.fn()}
        onExplainNetwork={onExplainNetwork}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Explain my network" }),
    );

    expect(onExplainNetwork).toHaveBeenCalledTimes(1);
  });
});
