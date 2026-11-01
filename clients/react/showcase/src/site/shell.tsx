// The frame around every page: the mock banner, the header with the theme
// toggle, and the sidebar listing every component (a drawer on a phone).

import { Menu, Moon, Sun, X } from "lucide-react"
import { useEffect, useState, type ReactNode } from "react"
import { cn } from "@/lib/utils"
import { DEMO_2FA_EMAIL, DEMO_CODE, DEMO_EMAIL, DEMO_PASSWORD } from "@/mock/state"
import { CATALOG, GROUPS, REAL_DEMO_URL, REPO_URL } from "@/catalog"
import { CopyButton } from "./code"
import { Link } from "./router"
import { setTheme, useTheme } from "./theme"

function Sidebar({ path, onPick }: { path: string; onPick: () => void }) {
  return (
    <nav aria-label="Components" className="grid gap-4 text-[13px]" onClick={onPick}>
      <div className="grid gap-0.5">
        <Link href="/" aria-current={path === "/" ? "page" : undefined} className={navItem(path === "/")}>
          Overview
        </Link>
      </div>
      {GROUPS.map((group) => (
        <div key={group} className="grid gap-0.5">
          <p className="px-2 text-[11px] font-medium tracking-wide text-muted-foreground uppercase">{group}</p>
          {CATALOG.filter((e) => e.group === group).map((e) => {
            const active = path === `/${e.name}`
            return (
              <Link key={e.name} href={`/${e.name}`} aria-current={active ? "page" : undefined} className={navItem(active)}>
                {e.title}
              </Link>
            )
          })}
        </div>
      ))}
    </nav>
  )
}

function navItem(active: boolean): string {
  return cn("flex h-7 items-center rounded-md px-2", active ? "bg-accent font-medium text-accent-foreground" : "text-muted-foreground hover:bg-accent/60 hover:text-foreground")
}

/** The always-visible notice: no server, the demo credentials, and where the real demo is. */
function MockBanner() {
  return (
    <div role="note" className="border-b bg-amber-50 text-amber-950 dark:bg-amber-950/40 dark:text-amber-100">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-3 gap-y-1 px-4 py-1.5 text-xs">
        <span className="font-medium">Mock: no server.</span>
        <span>
          Every call is answered in your browser. Sign in with <code className="font-mono">{DEMO_EMAIL}</code> or <code className="font-mono">{DEMO_2FA_EMAIL}</code> (code{" "}
          <code className="font-mono">{DEMO_CODE}</code>), password <code className="font-mono">{DEMO_PASSWORD}</code>
        </span>
        <CopyButton text={DEMO_PASSWORD} label="Copy demo password" className="border-amber-300 bg-transparent text-amber-950 hover:bg-amber-100 dark:border-amber-800 dark:text-amber-100 dark:hover:bg-amber-900/50" />
        <a className="underline underline-offset-2" href={REAL_DEMO_URL} target="_blank" rel="noreferrer">
          Run the real demo
        </a>
      </div>
    </div>
  )
}

export function Shell({ path, children }: { path: string; children: ReactNode }) {
  const theme = useTheme()
  const [open, setOpen] = useState(false)
  useEffect(() => {
    if (!open) return
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false)
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [open])
  return (
    <div className="min-h-dvh text-[13px]">
      <MockBanner />
      <header className="sticky top-0 z-30 border-b bg-background/90 backdrop-blur">
        <div className="mx-auto flex h-11 max-w-7xl items-center gap-2 px-4">
          <button type="button" className="inline-flex size-7 items-center justify-center rounded-md hover:bg-accent md:hidden" aria-label={open ? "Close menu" : "Open menu"} aria-expanded={open} onClick={() => setOpen(!open)}>
            {open ? <X className="size-4" aria-hidden /> : <Menu className="size-4" aria-hidden />}
          </button>
          <Link href="/" className="font-semibold tracking-tight">
            ubgo/auth <span className="font-normal text-muted-foreground">React kit</span>
          </Link>
          <div className="ml-auto flex items-center gap-1">
            <a href={REPO_URL} target="_blank" rel="noreferrer" className="inline-flex h-7 items-center rounded-md px-2 text-xs text-muted-foreground hover:bg-accent hover:text-foreground">
              GitHub
            </a>
            <button
              type="button"
              className="inline-flex size-7 items-center justify-center rounded-md hover:bg-accent"
              aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            >
              {theme === "dark" ? <Sun className="size-4" aria-hidden /> : <Moon className="size-4" aria-hidden />}
            </button>
          </div>
        </div>
      </header>
      <div className="mx-auto flex max-w-7xl gap-8 px-4">
        <aside className="sticky top-11 hidden h-[calc(100dvh-2.75rem)] w-52 shrink-0 overflow-y-auto py-5 md:block">
          <Sidebar path={path} onPick={() => undefined} />
        </aside>
        {open ? (
          <div className="fixed inset-x-0 top-11 bottom-0 z-20 overflow-y-auto border-t bg-background px-4 py-4 md:hidden">
            <Sidebar path={path} onPick={() => setOpen(false)} />
          </div>
        ) : null}
        <main className="min-w-0 flex-1 py-6">{children}</main>
      </div>
    </div>
  )
}
