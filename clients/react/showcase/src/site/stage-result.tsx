// The line a component page shows when its component navigates after
// success: who is signed in now, where the app would go, a way to go there,
// and a way to run the component again from its starting state.

import { ArrowRight, RotateCcw } from "lucide-react"
import type { MouseEvent } from "react"
import { state } from "@/mock/state"
import { useMockState } from "@/site/mock-panel"
import { hrefOf, navigate } from "@/site/router"

/** The mock session in one sentence, as it stands after the component's call. */
function sessionLine(): string {
  const session = state.session
  if (session === null) return "Signed out."
  const name = state.users.find((u) => u.id === session.userId)?.name ?? "a new account"
  if (session.pending) return `${name} typed the password; the second factor is still owed.`
  return `Signed in as ${name}.`
}

/**
 * The result of a component's navigation, shown on the stage instead of
 * leaving the page. "Go there" makes the navigation the component asked for,
 * keeping the session it left; "Run again" remounts the component in the
 * state the page started it in.
 */
export function StageResult({ href, onRunAgain }: { href: string; onRunAgain: () => void }) {
  useMockState()
  function goThere(event: MouseEvent<HTMLAnchorElement>) {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
    event.preventDefault()
    navigate(href, { flow: true })
  }
  return (
    <div role="status" className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b bg-emerald-50 px-3 py-1.5 text-xs text-emerald-950 dark:bg-emerald-950/40 dark:text-emerald-100">
      <span>
        {sessionLine()} Your app would now go to <code className="font-mono break-all">{href}</code>.
      </span>
      <span className="flex items-center gap-1">
        <a href={hrefOf(href)} onClick={goThere} className="inline-flex h-6 items-center gap-1 rounded-md border border-emerald-300 px-2 font-medium hover:bg-emerald-100 dark:border-emerald-800 dark:hover:bg-emerald-900/50">
          Go there
          <ArrowRight className="size-3" aria-hidden />
        </a>
        <button type="button" onClick={onRunAgain} className="inline-flex h-6 items-center gap-1 rounded-md px-2 hover:bg-emerald-100 dark:hover:bg-emerald-900/50">
          <RotateCcw className="size-3" aria-hidden />
          Run again
        </button>
      </span>
    </div>
  )
}
