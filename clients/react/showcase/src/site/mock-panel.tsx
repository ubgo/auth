// The stage's controls over the mock: who is signed in, the switches, a
// reset, and the outbox of messages the mock pretended to send.

import { useQueryClient } from "@tanstack/react-query"
import { Mail, RotateCcw } from "lucide-react"
import { useSyncExternalStore } from "react"
import { cn } from "@/lib/utils"
import { reset, sessionKind, setSession, setSettings, state, subscribe, type MockSessionKind } from "@/mock/state"

/** A snapshot of the parts the panel shows, re-read on every change. */
function snapshot(): string {
  return JSON.stringify([sessionKind(), state.settings, state.outbox])
}

/** Re-renders the caller whenever the mock's state changes. */
export function useMockState(): void {
  useSyncExternalStore(subscribe, snapshot)
}

const SESSIONS: readonly { kind: MockSessionKind; label: string }[] = [
  { kind: "signed-out", label: "Signed out" },
  { kind: "ada", label: "Ada (admin)" },
  { kind: "grace", label: "Grace" },
  { kind: "grace-pending", label: "Grace, 2FA pending" },
]

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (next: boolean) => void }) {
  return (
    <label className="inline-flex h-6 cursor-pointer items-center gap-1.5 text-xs text-muted-foreground">
      <input type="checkbox" className="size-3.5 accent-foreground" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      {label}
    </label>
  )
}

/** The bar above the stage. onChange remounts the stage so forms start clean. */
export function MockPanel({ onChange }: { onChange: () => void }) {
  useMockState()
  const queryClient = useQueryClient()
  const kind = sessionKind()
  async function apply(action: () => void) {
    action()
    await queryClient.resetQueries()
    onChange()
  }
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b bg-muted/40 px-3 py-1.5">
      <div className="flex flex-wrap items-center gap-1" role="group" aria-label="Mock session">
        <span className="mr-1 text-xs text-muted-foreground">Session</span>
        {SESSIONS.map((s) => (
          <button
            key={s.kind}
            type="button"
            aria-pressed={kind === s.kind}
            onClick={() => apply(() => setSession(s.kind))}
            className={cn(
              "h-6 rounded-md border px-2 text-xs",
              kind === s.kind ? "border-foreground/30 bg-background font-medium text-foreground shadow-xs" : "border-transparent text-muted-foreground hover:bg-background",
            )}
          >
            {s.label}
          </button>
        ))}
        {kind === "other" ? <span className="text-xs text-muted-foreground">(another account)</span> : null}
      </div>
      <div className="flex items-center gap-3">
        <Toggle label="Slow network" checked={state.settings.slow} onChange={(slow) => setSettings({ slow })} />
        <Toggle label="OAuth providers" checked={state.settings.oauth} onChange={(oauth) => apply(() => setSettings({ oauth }))} />
        <button type="button" onClick={() => apply(reset)} className="inline-flex h-6 items-center gap-1 rounded-md px-1.5 text-xs text-muted-foreground hover:bg-background hover:text-foreground">
          <RotateCcw className="size-3" aria-hidden />
          Reset mock
        </button>
      </div>
    </div>
  )
}

/** The latest messages the mock "sent": reset links, codes, invitations. */
export function Outbox() {
  useMockState()
  if (state.outbox.length === 0) return null
  return (
    <div className="border-t bg-muted/30 px-3 py-2 text-xs">
      <div className="mb-1 flex items-center gap-1.5 font-medium text-muted-foreground">
        <Mail className="size-3.5" aria-hidden />
        Mock outbox (nothing is really sent)
      </div>
      <ul className="grid gap-0.5">
        {state.outbox.map((message, i) => (
          <li key={`${i}-${message}`} className={cn(i > 0 && "text-muted-foreground")}>
            {message}
          </li>
        ))}
      </ul>
    </div>
  )
}
