import * as React from "react"
import { cn } from "@/lib/utils"

// Copied from shadcn/ui (base-nova, Base UI) by the ubgo auth registry, with
// one change: the compact density (13px text, h-7 controls). The exports and
// props are shadcn's, so an app may keep its own copy of this file instead.

function Label({ className, ...props }: React.ComponentProps<"label">) {
  return (
    <label
      data-slot="label"
      className={cn(
        "flex items-center gap-2 text-[13px] leading-none font-medium select-none group-data-[disabled=true]:pointer-events-none group-data-[disabled=true]:opacity-50 peer-disabled:cursor-not-allowed peer-disabled:opacity-50",
        className
      )}
      {...props}
    />
  )
}

export { Label }
