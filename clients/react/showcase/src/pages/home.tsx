// The home page: what the kit is, its three layers, and the setup every
// component page assumes.

import { ArrowRight, ExternalLink } from "lucide-react"
import { CATALOG, CLIENT_DOCS_URL, GROUPS, REAL_DEMO_URL, REPO_URL, SITE_URL } from "@/catalog"
import { CodeBlock, CommandLine } from "@/site/code"
import { Link } from "@/site/router"

const LAYERS = [
  {
    name: "Client",
    pkg: "@ubgo/auth-client",
    text: "A typed fetch client generated from the server's operation list: one method per operation, results as { data, error }, one plugin factory per server plugin.",
    doc: `${CLIENT_DOCS_URL}/README.md`,
  },
  {
    name: "Hooks",
    pkg: "@ubgo/auth-react",
    text: "Headless React on TanStack Query: AuthProvider, useSession, sign-out, plugin gating, organizations, admin, localization. Use it alone for your own UI.",
    doc: `${CLIENT_DOCS_URL}/react-hooks.md`,
  },
  {
    name: "Components",
    pkg: "shadcn registry",
    text: "Copy-in shadcn components on Base UI, compact and themed by your tokens. Installed with shadcn add, then yours to edit.",
    doc: `${CLIENT_DOCS_URL}/react-components.md`,
  },
] as const

const PROVIDER_SNIPPET = `// auth.ts: one plugin factory per plugin the Go server registers
import { createAuthClient, password, twofactor, oauth } from "@ubgo/auth-client"

export const auth = createAuthClient({
  baseURL: "/auth",
  plugins: [password(), twofactor(), oauth()],
})

// main.tsx
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { AuthProvider } from "@ubgo/auth-react"

const queryClient = new QueryClient()

root.render(
  <QueryClientProvider client={queryClient}>
    <AuthProvider client={auth} navigate={(href) => router.navigate({ to: href })}>
      <App />
    </AuthProvider>
  </QueryClientProvider>,
)`

const REGISTRY_SNIPPET = `// components.json: lets you write shadcn add @ubgo/<name>
{
  "registries": {
    "@ubgo": "${SITE_URL}/r/{name}.json"
  }
}`

export function HomePage() {
  return (
    <article className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-6">
      <header className="grid gap-2">
        <h1 className="text-2xl font-semibold tracking-tight">ubgo/auth React kit</h1>
        <p className="max-w-2xl text-muted-foreground">
          Every sign-in, account, organization and admin screen of{" "}
          <a className="underline underline-offset-2" href={REPO_URL} target="_blank" rel="noreferrer">
            github.com/ubgo/auth
          </a>
          , live. Each page renders the real component from the registry against a mock server in your browser, with the line that installs it and a snippet that uses it.
        </p>
        <div className="flex flex-wrap gap-2 pt-1">
          <Link href="/sign-in-form" className="inline-flex h-7 items-center gap-1 rounded-md bg-primary px-3 text-xs font-medium text-primary-foreground hover:bg-primary/90">
            Start with sign in <ArrowRight className="size-3.5" aria-hidden />
          </Link>
          <a href={REAL_DEMO_URL} target="_blank" rel="noreferrer" className="inline-flex h-7 items-center gap-1 rounded-md border px-3 text-xs font-medium hover:bg-accent">
            Run the real demo <ExternalLink className="size-3.5" aria-hidden />
          </a>
        </div>
      </header>

      <section className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-2" aria-labelledby="layers">
        <h2 id="layers" className="text-sm font-semibold">
          Three layers
        </h2>
        <div className="grid gap-2 sm:grid-cols-3">
          {LAYERS.map((layer) => (
            <a key={layer.name} href={layer.doc} target="_blank" rel="noreferrer" className="grid content-start gap-1 rounded-lg border p-3 hover:bg-accent/50">
              <span className="flex items-baseline justify-between gap-2">
                <span className="font-medium">{layer.name}</span>
                <code className="truncate font-mono text-[11px] text-muted-foreground">{layer.pkg}</code>
              </span>
              <span className="text-xs text-muted-foreground">{layer.text}</span>
            </a>
          ))}
        </div>
      </section>

      <section className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-2" aria-labelledby="setup">
        <h2 id="setup" className="text-sm font-semibold">
          Set up once
        </h2>
        <p className="text-muted-foreground">
          The packages are not on npm yet: link <code className="font-mono">@ubgo/auth-client</code> and <code className="font-mono">@ubgo/auth-react</code> from a checkout, serve the Go handler at <code className="font-mono">/auth</code> on the page's origin, and mount the provider. The{" "}
          <a className="underline underline-offset-2" href={`${CLIENT_DOCS_URL}/react.md`} target="_blank" rel="noreferrer">
            quickstart
          </a>{" "}
          has every step.
        </p>
        <CodeBlock code={PROVIDER_SNIPPET} title="auth.ts, main.tsx" />
        <p className="text-muted-foreground">Then add any component by its URL:</p>
        <CommandLine command={`npx shadcn@latest add ${SITE_URL}/r/sign-in-form.json`} />
        <p className="text-muted-foreground">Or name the registry once and use short names:</p>
        <CodeBlock code={REGISTRY_SNIPPET} title="components.json" />
      </section>

      <section className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-2" aria-labelledby="all">
        <h2 id="all" className="text-sm font-semibold">
          Components
        </h2>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {GROUPS.map((group) => (
            <div key={group} className="grid content-start gap-1">
              <h3 className="text-xs font-medium text-muted-foreground">{group}</h3>
              <ul className="grid gap-0.5">
                {CATALOG.filter((e) => e.group === group).map((e) => (
                  <li key={e.name}>
                    <Link href={`/${e.name}`} className="hover:underline">
                      {e.title}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>
    </article>
  )
}
