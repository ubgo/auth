import { cn } from "@/lib/utils"
import { Loader2Icon } from "lucide-react"

// Copied from shadcn/ui (base-nova, Base UI) by the ubgo auth registry, with
// one change: the compact density (13px text, h-7 controls). The exports and
// props are shadcn's, so an app may keep its own copy of this file instead.

function Spinner({ className, ...props }: React.ComponentProps<"svg">) {
  return (
    <Loader2Icon data-slot="spinner" role="status" aria-label="Loading" className={cn("size-4 animate-spin", className)} {...props} />
  )
}

export { Spinner }
