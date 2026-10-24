// /: the overview. Who is signed in (read with useSession), the seeded
// account, where each flow lives, and what is demo-only.

import { useSession } from "@ubgo/auth-react"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { RouterLink } from "@/components/demo-shell"
import { DEMO_NAV } from "@/demo-nav"
import { DEMO_USER } from "@/demo-user"

/** How often the overview re-reads the session, so a session revoked on another device leaves this page. */
const SESSION_POLL_MS = 30_000

export function HomePage() {
  const { session, isPending, isRefetching, error } = useSession({ refetchInterval: SESSION_POLL_MS })
  return (
    <div className="flex flex-col gap-4 px-4 py-5 lg:px-6">
      <header className="flex flex-col gap-0.5 border-b pb-3">
        <h1 className="text-[17px] font-semibold tracking-tight">ubgo/auth React UI kit</h1>
        <p className="text-[13px] text-muted-foreground">Every component from the registry, live against a real Go server. Try each flow by hand from the sidebar.</p>
      </header>
      <div className="grid gap-3 lg:grid-cols-3">
        <Card size="sm">
          <CardHeader>
            <CardTitle role="heading" aria-level={2}>
              {isPending ? "Loading…" : session === null ? "Signed out" : `Hello, ${session.user.name || "there"}`}
            </CardTitle>
            <CardDescription>{error !== null
                ? error.message
                : `Read with useSession({ refetchInterval: ${SESSION_POLL_MS / 1000} s }); updates after every sign-in and sign-out${isRefetching ? ", refreshing now…" : "."}`}</CardDescription>
          </CardHeader>
          {session !== null && (
            <CardContent>
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
                <dt className="text-muted-foreground">User</dt>
                <dd className="truncate font-mono tabular-nums" data-testid="session-user">
                  {session.user.id}
                </dd>
                <dt className="text-muted-foreground">Expires</dt>
                <dd className="font-mono tabular-nums">{new Date(session.expiresAt).toLocaleString()}</dd>
              </dl>
            </CardContent>
          )}
        </Card>
        <Card size="sm">
          <CardHeader>
            <CardTitle role="heading" aria-level={2}>
              Demo account
            </CardTitle>
            <CardDescription>Seeded on start, email already verified. `task demo:reset` recreates it.</CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
              <dt className="text-muted-foreground">Email</dt>
              <dd className="font-mono">{DEMO_USER.email}</dd>
              <dt className="text-muted-foreground">Password</dt>
              <dd className="font-mono">{DEMO_USER.password}</dd>
            </dl>
          </CardContent>
        </Card>
        <Card size="sm">
          <CardHeader>
            <CardTitle role="heading" aria-level={2}>
              Demo-only helpers
            </CardTitle>
            <CardDescription>Two things exist only in this demo so it needs no setup.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-1.5 text-muted-foreground">
            <p>
              <RouterLink href="/inbox" className="text-foreground underline underline-offset-3">
                Inbox
              </RouterLink>
              : mail is kept in the server's memory, not sent.
            </p>
            <p>
              <b className="font-medium text-foreground">Demo provider</b>: a pretend OAuth provider inside the server, so "Continue with…" works offline.
            </p>
          </CardContent>
        </Card>
      </div>
      <Card size="sm">
        <CardHeader>
          <CardTitle role="heading" aria-level={2}>
            Flows
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ul className="grid gap-x-4 gap-y-1 sm:grid-cols-2 lg:grid-cols-3">
            {DEMO_NAV.filter((i) => i.path !== "/" && !("hidden" in i)).map((i) => (
              <li key={i.path} className="flex items-baseline justify-between gap-2">
                <RouterLink href={i.path} className="underline-offset-3 hover:underline">
                  {i.label}
                </RouterLink>
                <span className="text-[12px] text-muted-foreground">{i.group}</span>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  )
}
