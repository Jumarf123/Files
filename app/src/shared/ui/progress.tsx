import * as ProgressPrimitive from "@radix-ui/react-progress";

import { cn } from "@/shared/lib/cn";

interface ProgressProps {
  className?: string;
  value: number;
}

export function Progress({ className, value }: ProgressProps) {
  return (
    <ProgressPrimitive.Root
      className={cn("relative h-2.5 w-full overflow-hidden rounded-full bg-white/8", className)}
      value={value}
    >
      <ProgressPrimitive.Indicator
        className="h-full rounded-full bg-[linear-gradient(90deg,var(--accent),var(--accent-2))] transition-transform duration-500"
        style={{ transform: `translateX(-${100 - Math.max(0, Math.min(100, value))}%)` }}
      />
    </ProgressPrimitive.Root>
  );
}
