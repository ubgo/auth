// A small path router over the History API, enough for one page per
// component. Paths inside the app are written without the site's base
// ("/sign-in-form"); the browser's URL carries it ("/auth/sign-in-form").
// GitHub Pages serves 404.html (a copy of index.html) for any deep link, so
// a reload on any page lands back here.

import { useSyncExternalStore, type MouseEvent, type ReactNode } from "react"

/** The site's base without its trailing slash: "/auth" on GitHub Pages. */
export const BASE = import.meta.env.BASE_URL.replace(/\/+$/, "")

const CHANGE_EVENT = "showcase:navigate"

/** The current app path and query: "/sign-in-form?token=x". */
function currentPath(): string {
  const { pathname, search } = window.location
  const inside = pathname.startsWith(BASE) ? pathname.slice(BASE.length) : pathname
  return (inside === "" ? "/" : inside) + search
}

function subscribe(listener: () => void): () => void {
  window.addEventListener("popstate", listener)
  window.addEventListener(CHANGE_EVENT, listener)
  return () => {
    window.removeEventListener("popstate", listener)
    window.removeEventListener(CHANGE_EVENT, listener)
  }
}

/** The current app path with its query, re-rendering on every navigation. */
export function useLocation(): string {
  return useSyncExternalStore(subscribe, currentPath)
}

/** The browser URL of an app path. A full URL or one already under the base is kept as is. */
export function hrefOf(path: string): string {
  if (/^[a-z]+:\/\//i.test(path)) return path
  if (path === BASE || path.startsWith(`${BASE}/`)) return path
  return BASE + (path.startsWith("/") ? path : `/${path}`)
}

/** What a history entry carries: whether a component's flow (not the sidebar) opened it. */
type EntryState = { readonly flow: boolean }

/**
 * Goes to an app path (or a full URL, with a page load). flow marks a
 * navigation a component made (sign-in done, signed out), so the page it
 * opens keeps the session the flow left instead of preparing its own.
 */
export function navigate(path: string, options: { flow?: boolean } = {}): void {
  if (/^[a-z]+:\/\//i.test(path)) {
    window.location.assign(path)
    return
  }
  const entry: EntryState = { flow: options.flow ?? false }
  window.history.pushState(entry, "", hrefOf(path))
  window.scrollTo(0, 0)
  window.dispatchEvent(new Event(CHANGE_EVENT))
}

export type LinkProps = {
  readonly href: string
  readonly className?: string
  readonly children: ReactNode
  readonly "aria-current"?: "page" | undefined
}

/** An anchor that navigates without a page load; a modified click opens normally. */
export function Link({ href, className, children, ...rest }: LinkProps) {
  function onClick(event: MouseEvent<HTMLAnchorElement>) {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
    event.preventDefault()
    navigate(href)
  }
  return (
    <a href={hrefOf(href)} className={className} onClick={onClick} aria-current={rest["aria-current"]}>
      {children}
    </a>
  )
}

/** Whether the current history entry was opened by a component's flow. */
export function openedByFlow(): boolean {
  const entry: unknown = window.history.state
  return typeof entry === "object" && entry !== null && "flow" in entry && entry.flow === true
}
