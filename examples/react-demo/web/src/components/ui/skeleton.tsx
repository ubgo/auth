import { cn } from "@/lib/utils"

// Copied from shadcn/ui (base-nova, Base UI) by the ubgo auth registry, with
// one change: the compact density (13px text, h-7 controls). The exports and
// props are shadcn's, so an app may keep its own copy of this file instead.

function Skeleton({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="skeleton"
      className={cn("animate-pulse rounded-md bg-muted", className)}
      {...props}
    />
  )
}

export { Skeleton }
