// One component's page: the live component on a stage with its states, the
// install line, the usage snippet, and steps to try.

import { useQueryClient } from "@tanstack/react-query"
import { ExternalLink, Moon, Sun } from "lucide-react"
import { Suspense, useEffect, useRef, useState } from "react"
import { CommandLine, CodeBlock } from "@/site/code"
import { hasMockControls, MockSettingsMenu, Outbox, SessionBar } from "@/site/mock-panel"
import { interceptFlowNavigation, openedByFlow } from "@/site/router"
import { StageResult } from "@/site/stage-result"
import { CodeTab, PropsSection } from "@/site/component-docs"
import { setTheme, useTheme } from "@/site/theme"
import { cn } from "@/lib/utils"
import { installCommand, REPO_URL, type Entry } from "@/catalog"

const DOCS_COMPONENTS_URL = `${REPO_URL}/blob/main/docs/client/react-components.md`
const SOURCE_URL = `${REPO_URL}/blob/main/clients/react/registry/auth`

export function ComponentPage({ entry, query }: { entry: Entry; query: URLSearchParams }) {
  const queryClient = useQueryClient()
  const theme = useTheme()
  const [variantId, setVariantId] = useState(entry.variants[0]?.id ?? "")
  // The stage shows the live component or the files shadcn installs for it.
  const [view, setView] = useState<"preview" | "code">("preview")
  // Bumped to remount the stage, so a form starts empty after a switch.
  const [mount, setMount] = useState(0)
  const [ready, setReady] = useState(false)
  // Where the component asked to go after success, held here instead of
  // leaving the page; null until it navigates.
  const [result, setResult] = useState<string | null>(null)
  const variant = entry.variants.find((v) => v.id === variantId) ?? entry.variants[0]

  // Restaging happens in two steps, because the old stage must be gone
  // before the mock changes and the cache is reset: a reset refetches every
  // query still on screen, so a stage left mounted would re-run its calls
  // against the new state (a magic link signing in again as an "expired
  // link" state opens). restage unmounts the stage and queues the change;
  // the effect below applies it once that unmount is committed, resets the
  // cache and mounts a fresh stage.
  const [stageRequest, setStageRequest] = useState(0)
  const pendingChanges = useRef<(() => void)[]>([])
  // Whether a navigation comes from the stage on screen; false while it is
  // being replaced, so a late call from the old one cannot show a result.
  const acceptingNavigation = useRef(false)

  /** Replaces the stage after applying change to the mock, so the component starts from that state. */
  function restage(change: () => void) {
    acceptingNavigation.current = false
    pendingChanges.current.push(change)
    setReady(false)
    setStageRequest((n) => n + 1)
  }

  useEffect(() => {
    if (stageRequest === 0) return
    let live = true
    for (const change of pendingChanges.current.splice(0)) change()
    void queryClient.resetQueries().then(() => {
      if (!live) return
      setResult(null)
      setMount((n) => n + 1)
      setReady(true)
      acceptingNavigation.current = true
    })
    return () => {
      live = false
    }
  }, [stageRequest, queryClient])

  // A component that navigates (signed in, link confirmed) would move the
  // visitor to another page and its own could never be seen; the page holds
  // those navigations and shows where the app would go.
  useEffect(
    () =>
      interceptFlowNavigation((href) => {
        if (acceptingNavigation.current) setResult(href)
      }),
    [],
  )

  // Opening a page or a state puts the mock in that state first, so the
  // component's first read already sees it. A page a component's flow opened
  // (signed in, signed out) keeps the session that flow left.
  const keepSession = useRef(openedByFlow())
  /** Restages in the variant's starting state: on open, on a state tab and on "Run again". */
  function startVariant() {
    restage(() => {
      if (keepSession.current) keepSession.current = false
      else variant?.prepare()
    })
  }
  // startVariant is rebuilt every render; the variant is what the effect follows.
  const startRef = useRef(startVariant)
  startRef.current = startVariant
  useEffect(() => startRef.current(), [variant])

  return (
    <article className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-5">
      <header className="grid min-w-0 gap-1">
        <p className="text-xs font-medium text-muted-foreground">{entry.group}</p>
        <h1 className="text-xl font-semibold tracking-tight">{entry.title}</h1>
        <p className="max-w-2xl text-muted-foreground">{entry.description}</p>
      </header>

      <section aria-label="Live component" className="min-w-0 overflow-hidden rounded-lg border">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b px-2 py-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex rounded-md border p-0.5" role="tablist" aria-label="Stage">
              {(["preview", "code"] as const).map((v) => (
                <button
                  key={v}
                  type="button"
                  role="tab"
                  aria-selected={view === v}
                  onClick={() => setView(v)}
                  className={cn("h-6 rounded px-2.5 text-xs font-medium", view === v ? "bg-foreground text-background" : "text-muted-foreground hover:text-foreground")}
                >
                  {v === "preview" ? "Preview" : "Code"}
                </button>
              ))}
            </div>
            <div className="flex flex-wrap gap-1" role="tablist" aria-label="States" hidden={view !== "preview"}>
              {entry.variants.map((v) => (
                <button
                  key={v.id}
                  type="button"
                  role="tab"
                  aria-selected={v.id === variant?.id}
                  onClick={() => setVariantId(v.id)}
                  className={cn(
                    "h-7 rounded-md px-2.5 text-xs font-medium",
                    v.id === variant?.id ? "bg-secondary text-secondary-foreground" : "text-muted-foreground hover:bg-accent hover:text-foreground",
                  )}
                >
                  {v.label}
                </button>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-1.5">
            {hasMockControls(entry.mock) && view === "preview" ? <MockSettingsMenu mock={entry.mock} onApply={restage} /> : null}
            <button
              type="button"
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
              className="inline-flex h-7 items-center gap-1.5 rounded-md border px-2 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
            >
              {theme === "dark" ? <Sun className="size-3.5" aria-hidden /> : <Moon className="size-3.5" aria-hidden />}
              {theme === "dark" ? "Light" : "Dark"}
            </button>
          </div>
        </div>
        {/* The preview stays mounted while the code shows, so a half-filled form survives a look at the code. */}
        <div hidden={view !== "preview"}>
          {entry.mock.sessions !== undefined && entry.mock.sessions.length > 0 ? <SessionBar choices={entry.mock.sessions} onApply={restage} /> : null}
          {result !== null ? <StageResult href={result} onRunAgain={startVariant} /> : null}
          <div
            className={cn(
              "flex min-h-80 justify-center bg-[radial-gradient(var(--border)_1px,transparent_1px)] [background-size:16px_16px] px-3 py-8 sm:px-6",
              entry.width === "narrow" ? "items-start" : "items-stretch",
            )}
          >
            <div className={cn("w-full min-w-0", entry.width === "narrow" ? "max-w-sm" : "max-w-4xl")} key={mount}>
              {ready && variant !== undefined ? variant.render(query) : null}
            </div>
        </div>
        <Outbox />
        </div>
        {view === "code" ? (
          <Suspense fallback={<p className="px-3 py-8 text-center text-xs text-muted-foreground">Loading the code…</p>}>
            <CodeTab name={entry.name} />
          </Suspense>
        ) : null}
      </section>

      <section className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-2" aria-labelledby="install">
        <h2 id="install" className="text-sm font-semibold">
          Install
        </h2>
        <CommandLine command={installCommand(entry.name)} />
        <p className="text-xs text-muted-foreground">
          Copies the component and the primitives it needs into <code className="font-mono">components/</code>. It needs <code className="font-mono">@ubgo/auth-client</code> and{" "}
          <code className="font-mono">@ubgo/auth-react</code> linked in the app and an <code className="font-mono">AuthProvider</code> above it; see the home page.
        </p>
      </section>

      <section className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-2" aria-labelledby="usage">
        <h2 id="usage" className="text-sm font-semibold">
          Usage
        </h2>
        <CodeBlock code={entry.usage} title={`${entry.name}.tsx`} />
      </section>

      <Suspense fallback={null}>
        <PropsSection name={entry.name} />
      </Suspense>

      <section className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-2" aria-labelledby="try">
        <h2 id="try" className="text-sm font-semibold">
          Try this
        </h2>
        <ol className="grid list-decimal gap-1 pl-5 text-muted-foreground">
          {entry.tryThis.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
      </section>

      <footer className="flex flex-wrap gap-x-4 gap-y-1 border-t pt-3 text-xs">
        <a className="inline-flex items-center gap-1 text-muted-foreground hover:text-foreground" href={`${DOCS_COMPONENTS_URL}`} target="_blank" rel="noreferrer">
          Props, slots and errors <ExternalLink className="size-3" aria-hidden />
        </a>
        <a className="inline-flex items-center gap-1 text-muted-foreground hover:text-foreground" href={`${SOURCE_URL}/${entry.name}.tsx`} target="_blank" rel="noreferrer">
          Source <ExternalLink className="size-3" aria-hidden />
        </a>
      </footer>
    </article>
  )
}
