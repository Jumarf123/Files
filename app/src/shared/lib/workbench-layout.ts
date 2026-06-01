export interface WorkbenchLayout {
  leftWidth: number;
  bottomHeight: number;
}

export interface WorkbenchBounds {
  width: number;
  height: number;
}

export const WORKBENCH_LAYOUT_KEY = "files.workbench.layout.v1";

export const DEFAULT_WORKBENCH_LAYOUT: WorkbenchLayout = {
  leftWidth: 312,
  bottomHeight: 300,
};

export function clampWorkbenchLayout(layout: WorkbenchLayout, bounds: WorkbenchBounds): WorkbenchLayout {
  const maxLeftWidth = Math.max(280, Math.floor(bounds.width * 0.45));
  const maxBottomHeight = Math.max(220, Math.floor(bounds.height * 0.62));

  return {
    leftWidth: clamp(layout.leftWidth, 260, maxLeftWidth),
    bottomHeight: clamp(layout.bottomHeight, 220, maxBottomHeight),
  };
}

export function parseWorkbenchLayout(raw: string | null | undefined): WorkbenchLayout {
  if (!raw) {
    return DEFAULT_WORKBENCH_LAYOUT;
  }

  try {
    const parsed = JSON.parse(raw) as Partial<WorkbenchLayout>;
    return {
      leftWidth:
        typeof parsed.leftWidth === "number" && Number.isFinite(parsed.leftWidth)
          ? parsed.leftWidth
          : DEFAULT_WORKBENCH_LAYOUT.leftWidth,
      bottomHeight:
        typeof parsed.bottomHeight === "number" && Number.isFinite(parsed.bottomHeight)
          ? parsed.bottomHeight
          : DEFAULT_WORKBENCH_LAYOUT.bottomHeight,
    };
  } catch {
    return DEFAULT_WORKBENCH_LAYOUT;
  }
}

export function serializeWorkbenchLayout(layout: WorkbenchLayout) {
  return JSON.stringify(layout);
}

function clamp(value: number, min: number, max: number) {
  return Math.min(Math.max(value, min), max);
}
