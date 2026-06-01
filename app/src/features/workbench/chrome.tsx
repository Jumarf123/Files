import { LoaderCircle } from "lucide-react";
import type { PointerEvent as ReactPointerEvent, ReactNode } from "react";

import { cn } from "@/shared/lib/cn";
import type { ScanMode } from "@/shared/types/api";

export type SplitterKind = "vertical" | "horizontal";

export function ModeToggle({
  onChange,
  value,
}: {
  onChange: (mode: ScanMode) => void;
  value: ScanMode;
}) {
  return (
    <div className="inline-flex rounded-md border border-white/8 bg-[#101217] p-1">
      {(["fast", "deep"] as const).map((mode) => (
        <button
          className={cn(
            "rounded px-3 py-1.5 text-xs font-medium transition",
            value === mode ? "bg-[#5865f2] text-white" : "text-slate-400 hover:bg-white/[0.04] hover:text-white",
          )}
          key={mode}
          onClick={() => onChange(mode)}
          type="button"
        >
          {mode === "fast" ? "Fast" : "Deep"}
        </button>
      ))}
    </div>
  );
}

export function ZoomControls({
  onDecrease,
  onIncrease,
  onReset,
  zoom,
}: {
  onDecrease: () => void;
  onIncrease: () => void;
  onReset: () => void;
  zoom: number;
}) {
  return (
    <div className="flex items-center gap-1 rounded-md border border-white/8 bg-[#101217] p-1" data-testid="zoom-controls">
      <button
        className="h-7 rounded px-2 text-sm text-slate-300 hover:bg-white/[0.04] hover:text-white"
        onClick={onDecrease}
        type="button"
      >
        -
      </button>
      <button className="h-7 min-w-14 rounded px-2 text-xs text-slate-400 hover:bg-white/[0.04]" onClick={onReset} type="button">
        {Math.round(zoom * 100)}%
      </button>
      <button
        className="h-7 rounded px-2 text-sm text-slate-300 hover:bg-white/[0.04] hover:text-white"
        onClick={onIncrease}
        type="button"
      >
        +
      </button>
    </div>
  );
}

export function StatFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="uppercase tracking-[0.18em] text-slate-500">{label}</span>
      <span className="font-mono text-slate-300">{value}</span>
    </div>
  );
}

export function Splitter({
  kind,
  onPointerDown,
}: {
  kind: SplitterKind;
  onPointerDown: (event: ReactPointerEvent<HTMLDivElement>) => void;
}) {
  return (
    <div
      className={cn(
        "relative bg-white/[0.03] hover:bg-[#5865f2]/30",
        kind === "vertical" ? "cursor-col-resize" : "cursor-row-resize",
      )}
      onPointerDown={onPointerDown}
      role="separator"
    >
      <div
        className={cn(
          "pointer-events-none absolute rounded-full bg-white/10",
          kind === "vertical"
            ? "left-1/2 top-1/2 h-10 w-1 -translate-x-1/2 -translate-y-1/2"
            : "left-1/2 top-1/2 h-1 w-16 -translate-x-1/2 -translate-y-1/2",
        )}
      />
    </div>
  );
}

export function TabButton({
  active,
  label,
  onClick,
}: {
  active: boolean;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      className={cn(
        "rounded px-3 py-1.5 text-sm transition",
        active ? "bg-[#1d2026] text-white" : "text-slate-400 hover:bg-white/[0.04] hover:text-white",
      )}
      onClick={onClick}
      type="button"
    >
      {label}
    </button>
  );
}

export function TabViewport({ children }: { children: ReactNode }) {
  return <div className="h-full overflow-auto overscroll-contain px-4 py-4">{children}</div>;
}

export function LoadingState({ label }: { label: string }) {
  return (
    <div className="flex h-full items-center justify-center gap-3 text-sm text-slate-500">
      <LoaderCircle className="size-4 animate-spin" />
      {label}
    </div>
  );
}

export function TabErrorState({ message }: { message: string }) {
  return <div className="flex h-full items-center justify-center px-6 text-sm text-rose-300">{message}</div>;
}
