import type { HTMLAttributes } from "react";

import { cn } from "@/shared/lib/cn";

const tones = {
  slate: "border-white/10 bg-white/6 text-slate-200",
  emerald: "border-emerald-400/20 bg-emerald-500/10 text-emerald-200",
  amber: "border-amber-400/20 bg-amber-500/10 text-amber-100",
  rose: "border-rose-400/20 bg-rose-500/10 text-rose-200",
  cyan: "border-cyan-400/20 bg-cyan-500/10 text-cyan-100",
};

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: keyof typeof tones;
}

export function Badge({ className, tone = "slate", ...props }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em]",
        tones[tone],
        className,
      )}
      {...props}
    />
  );
}
