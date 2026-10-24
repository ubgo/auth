// The demo's chrome: a sidebar with a route per flow (a scrolling strip on a
// phone), the UserButton in the header, the demo-only Inbox with its unread
// count, and AuthProvider, mounted inside the router so the auth components
// navigate and link through it. The Language switch feeds its localization.

import { Outlet, useRouter, useRouterState } from "@tanstack/react-router"
import { AuthProvider, SessionTaskRedirect, type AuthLinkProps } from "@ubgo/auth-react"
import { InboxIcon } from "lucide-react"
import { useCallback, type MouseEvent } from "react"

import { auth } from "@/auth.ts"
import { ImpersonationBanner } from "@/components/auth/impersonation-banner"
import { UserButton } from "@/components/auth/user-button"
import { DemoCustomiseProvider, useDemoCustomise } from "@/demo/customise"
import { useInbox } from "@/demo/inbox"
import { GERMAN } from "@/demo/locales"
import { DEMO_NAV, type DemoNavItem } from "@/demo-nav"
import { cn } from "@/lib/utils"

/** A link that navigates through the router, the shape AuthProvider's Link takes. */
// ds:def id=routerlink-n2u39u8m owner=@khanakia stability=stable
export function RouterLink({ href, className, children }: AuthLinkProps) {
  const router = useRouter()
  const onClick = (e: MouseEvent<HTMLAnchorElement>) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return
    e.preventDefault()
    void router.navigate({ href })
  }
  return (
    <a href={href} className={className} onClick={onClick}>
      {children}
    </a>
  )
}

function InboxCount() {
  const { data } = useInbox()
  const n = data?.length ?? 0
  if (n === 0) return null
  return <span className="ml-auto rounded-full bg-primary px-1.5 font-mono text-[10px] leading-4 tabular-nums text-primary-foreground">{n}</span>
}

const GROUPS = [...new Set(DEMO_NAV.map((i) => i.group))]

function NavLink({ item, active }: { item: DemoNavItem; active: boolean }) {
  return (
    <RouterLink
      href={item.path}
      className={cn(
        "flex items-center gap-2 rounded-md px-2 py-1 text-[13px] whitespace-nowrap text-foreground/80 hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none",
        active && "bg-muted font-medium text-foreground",
      )}
    >
      {item.path === "/inbox" && <InboxIcon className="size-3.5" aria-hidden />}
      {item.label}
      {item.path === "/inbox" && <InboxCount />}
    </RouterLink>
  )
}

function Sidebar({ pathname }: { pathname: string }) {
  return (
    <nav aria-label="Demo flows" className="hidden w-52 shrink-0 flex-col gap-3 overflow-y-auto border-r p-3 md:flex">
      {GROUPS.map((group) => (
        <div key={group} className="flex flex-col gap-0.5">
          <div className="px-2 pb-0.5 text-[11px] font-semibold text-foreground/60">{group}</div>
          {DEMO_NAV.filter((i: DemoNavItem) => i.group === group && i.hidden !== true).map((item) => (
            <NavLink key={item.path} item={item} active={pathname === item.path} />
          ))}
        </div>
      ))}
    </nav>
  )
}

function MobileNav({ pathname }: { pathname: string }) {
  return (
    <nav aria-label="Demo flows" className="flex gap-1 overflow-x-auto border-b px-3 py-1.5 md:hidden">
      {DEMO_NAV.filter((i: DemoNavItem) => i.hidden !== true).map((item) => (
        <NavLink key={item.path} item={item} active={pathname === item.path} />
      ))}
    </nav>
  )
}

// ds:def id=shell-3sn7fvmr owner=@khanakia stability=stable
function Shell() {
  const router = useRouter()
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const { language } = useDemoCustomise()
  const navigate = useCallback((href: string) => void router.navigate({ href }), [router])
  return (
    <AuthProvider client={auth} navigate={navigate} Link={RouterLink} localization={language === "de" ? GERMAN : undefined}>
      <div className="flex h-svh flex-col bg-background text-[13px] text-foreground">
        <header className="flex h-11 shrink-0 items-center justify-between gap-2 border-b px-4">
          <RouterLink href="/" className="flex items-center gap-2 font-semibold tracking-tight">
            Acme
            <span className="rounded-md border px-1.5 text-[11px] font-normal text-muted-foreground">ubgo/auth React demo</span>
          </RouterLink>
          <UserButton showName />
        </header>
        <ImpersonationBanner adminHref="/admin" />
        <SessionTaskRedirect />
        <MobileNav pathname={pathname} />
        <div className="flex min-h-0 flex-1">
          <Sidebar pathname={pathname} />
          <main className="min-w-0 flex-1 overflow-y-auto">
            <Outlet />
          </main>
        </div>
      </div>
    </AuthProvider>
  )
}

export function DemoShell() {
  return (
    <DemoCustomiseProvider>
      <Shell />
    </DemoCustomiseProvider>
  )
}
