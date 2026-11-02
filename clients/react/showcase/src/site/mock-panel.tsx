// The stage's controls over the mock, limited to what changes the page in
// view: a "pretend signed in as" row when the session matters there, a
// "Mock settings" menu for the switches that matter and the reset, and the
// outbox of messages the mock pretended to send.

import { useQueryClient } from "@tanstack/react-query"
import { Mail, RotateCcw, SlidersHorizontal } from "lucide-react"
import { useSyncExternalStore } from "react"
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { cn } from "@/lib/utils"
import { reset, sessionKind, setSession, setSettings, state, subscribe, type MockSessionKind } from "@/mock/state"
import type { MockControls, SessionChoice } from "@/catalog"

/** A snapshot of the parts the controls show, re-read on every change. */
function snapshot(): string {
  return JSON.stringify([sessionKind(), state.settings, state.outbox])
}

/** Re-renders the caller whenever the mock's state changes. */
export function useMockState(): void {
  useSyncExternalStore(subscribe, snapshot)
}

/** What each demo session is called on every page; the page's own note says what it changes there. */
const SESSION_LABELS: Readonly<Record<MockSessionKind, string>> = {
  "signed-out": "Nobody",
  ada: "Ada (admin)",
  grace: "Grace (has 2FA)",
  "grace-pending": "Grace (waiting for 2FA code)",
}

/**
 * Applies a change to the mock, drops every cached answer and remounts the
 * stage (onChange), so the component reads the new state from a clean start.
 */
function useApply(onChange: () => void): (action: () => void) => Promise<void> {
  const queryClient = useQueryClient()
  return async (action) => {
    action()
    await queryClient.resetQueries()
    onChange()
  }
}

/** Whether a page shows any mock control at all. */
export function hasMockControls(mock: MockControls): boolean {
  return (mock.sessions?.length ?? 0) > 0 || mock.slow === true || mock.oauth === true
}

/**
 * The "pretend signed in as" row, for a page the session changes. Each
 * button's tooltip, and the line after the row for the chosen one, says what
 * that session changes on this page.
 */
export function SessionBar({ choices, onChange }: { choices: readonly SessionChoice[]; onChange: () => void }) {
  useMockState()
  const apply = useApply(onChange)
  const kind = sessionKind()
  const current = choices.find((c) => c.kind === kind)
  return (
    <div className="grid gap-0.5 border-b bg-muted/40 px-3 py-1.5">
      <div className="flex flex-wrap items-center gap-1" role="group" aria-label="Pretend signed in as">
        <span className="mr-1 text-xs text-muted-foreground">Pretend signed in as:</span>
        {choices.map((c) => (
          <button
            key={c.kind}
            type="button"
            title={c.note}
            aria-pressed={kind === c.kind}
            onClick={() => apply(() => setSession(c.kind))}
            className={cn(
              "h-6 rounded-md border px-2 text-xs",
              kind === c.kind ? "border-foreground/30 bg-background font-medium text-foreground shadow-xs" : "border-transparent text-muted-foreground hover:bg-background",
            )}
          >
            {SESSION_LABELS[c.kind]}
          </button>
        ))}
      </div>
      <p className="text-xs text-muted-foreground" aria-live="polite">
        {current?.note ?? (kind === "other" ? "Another account is signed in (one you created or are impersonating)." : "")}
      </p>
    </div>
  )
}

/** The switches that matter on this page, and the reset, in one compact menu on the stage toolbar. */
export function MockSettingsMenu({ mock, onChange }: { mock: MockControls; onChange: () => void }) {
  useMockState()
  const apply = useApply(onChange)
  return (
    <DropdownMenu>
      <DropdownMenuTrigger className="inline-flex h-7 items-center gap-1.5 rounded-md border px-2 text-xs text-muted-foreground hover:bg-accent hover:text-foreground">
        <SlidersHorizontal className="size-3.5" aria-hidden />
        Mock settings
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuGroup>
          <DropdownMenuLabel>Fake server, in your browser</DropdownMenuLabel>
          {mock.slow === true ? (
            <DropdownMenuCheckboxItem checked={state.settings.slow} onCheckedChange={(slow) => setSettings({ slow })} closeOnClick={false}>
              Slow network
            </DropdownMenuCheckboxItem>
          ) : null}
          {mock.oauth === true ? (
            <DropdownMenuCheckboxItem checked={state.settings.oauth} onCheckedChange={(oauth) => apply(() => setSettings({ oauth }))} closeOnClick={false}>
              OAuth providers
            </DropdownMenuCheckboxItem>
          ) : null}
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={() => apply(reset)}>
          <RotateCcw aria-hidden />
          Reset mock
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
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
