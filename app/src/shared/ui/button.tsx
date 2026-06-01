import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";

import { cn } from "@/shared/lib/cn";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 rounded-xl border text-sm font-medium transition disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        primary:
          "border-transparent bg-[#5865F2] px-4 py-2.5 text-white hover:bg-[#6974f3]",
        secondary:
          "border-white/8 bg-[#2b2d31] px-4 py-2.5 text-slate-100 hover:border-white/12 hover:bg-[#313338]",
        ghost: "border-transparent bg-transparent px-3 py-2 text-slate-300 hover:bg-white/6 hover:text-white",
        danger:
          "border-red-400/20 bg-red-500/10 px-4 py-2.5 text-red-100 hover:border-red-300/30 hover:bg-red-500/18",
      },
      size: {
        default: "h-11",
        sm: "h-9 rounded-xl px-3 text-xs",
        lg: "h-12 px-5 text-base",
        icon: "size-10 rounded-xl",
      },
    },
    defaultVariants: {
      variant: "primary",
      size: "default",
    },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => (
    <button ref={ref} className={cn(buttonVariants({ variant, size, className }))} {...props} />
  ),
);

Button.displayName = "Button";
