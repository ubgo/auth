import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { AuthProvider, type AuthLinkProps, type AuthPaths } from "@ubgo/auth-react"
import { StrictMode } from "react"
import { createRoot } from "react-dom/client"

import "./index.css"
import { auth } from "@/auth"
import { entryNamed } from "@/catalog"
import { ComponentPage } from "@/pages/component-page"
import { HomePage } from "@/pages/home"
import { OAuthProviderPage } from "@/pages/oauth-provider"
import { Link, navigate, useLocation } from "@/site/router"
import { Shell } from "@/site/shell"

// The pages the components send people to, mapped onto this site's pages.
const PATHS: AuthPaths = {
  signIn: "/sign-in-form",
  signUp: "/sign-up-form",
  forgotPassword: "/forgot-password-form",
  twoFactor: "/two-factor-challenge",
  setupTwoFactor: "/task-setup-mfa",
  account: "/account-settings",
  afterSignIn: "/account-settings",
  afterSignOut: "/sign-in-form",
}

const OAUTH_START = /^\/oauth\/([^/]+)\/start$/

/** A navigation a component made: the next page keeps the session it left. */
function flowNavigate(href: string): void {
  navigate(href, { flow: true })
}

function FlowLink(props: AuthLinkProps) {
  return <Link {...props} />
}

function NotFound({ path }: { path: string }) {
  return (
    <div className="grid gap-2">
      <h1 className="text-xl font-semibold">Not found</h1>
      <p className="text-muted-foreground">
        No page at <code className="font-mono">{path}</code>.{" "}
        <Link href="/" className="underline underline-offset-2">
          Back to the overview
        </Link>
      </p>
    </div>
  )
}

function App() {
  const location = useLocation()
  const [path = "/", search = ""] = location.split("?")
  const query = new URLSearchParams(search)
  const oauth = OAUTH_START.exec(path)
  const entry = entryNamed(path.slice(1))
  let page
  if (path === "/") page = <HomePage />
  else if (oauth !== null) page = <OAuthProviderPage provider={decodeURIComponent(oauth[1] ?? "")} query={query} />
  else if (entry !== undefined) page = <ComponentPage key={entry.name} entry={entry} query={query} />
  else page = <NotFound path={path} />
  return <Shell path={path}>{page}</Shell>
}

const queryClient = new QueryClient()

const root = document.getElementById("root")
if (root === null) throw new Error("index.html has no #root")

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuthProvider client={auth} navigate={flowNavigate} Link={FlowLink} paths={PATHS}>
        <App />
      </AuthProvider>
    </QueryClientProvider>
  </StrictMode>,
)
