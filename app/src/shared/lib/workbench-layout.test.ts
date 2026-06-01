import { describe, expect, it } from "vitest";

import {
  clampWorkbenchLayout,
  DEFAULT_WORKBENCH_LAYOUT,
  parseWorkbenchLayout,
  serializeWorkbenchLayout,
} from "./workbench-layout";

describe("workbench layout helpers", () => {
  it("falls back to defaults for invalid storage values", () => {
    expect(parseWorkbenchLayout("not-json")).toEqual(DEFAULT_WORKBENCH_LAYOUT);
  });

  it("clamps layout sizes to usable bounds", () => {
    expect(
      clampWorkbenchLayout(
        {
          leftWidth: 40,
          bottomHeight: 9999,
        },
        { width: 1366, height: 768 },
      ),
    ).toEqual({
      leftWidth: 260,
      bottomHeight: Math.floor(768 * 0.62),
    });
  });

  it("round-trips serialized layout", () => {
    const layout = { leftWidth: 320, bottomHeight: 280 };
    expect(parseWorkbenchLayout(serializeWorkbenchLayout(layout))).toEqual(layout);
  });
});
