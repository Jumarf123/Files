import * as React from "react";

import { cn } from "@/shared/lib/cn";

export type InputProps = React.InputHTMLAttributes<HTMLInputElement>;

export const Input = React.forwardRef<HTMLInputElement, InputProps>(({ className, ...props }, ref) => (
  <input
    ref={ref}
    className={cn(
      "flex h-11 w-full rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-2.5 text-sm text-slate-100 outline-none transition placeholder:text-slate-500 focus:border-cyan-300/35 focus:ring-2 focus:ring-cyan-400/10",
      className,
    )}
    {...props}
  />
));

Input.displayName = "Input";
