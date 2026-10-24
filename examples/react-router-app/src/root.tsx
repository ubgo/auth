// The React Router wiring: the kit's Link becomes a router Link, its
// navigate becomes the router's, and the provider is mounted inside the root
// route's element, where useNavigate works. Every navigation the kit makes
// (sign-in, sign-out, the guard's redirect) is then client-side.

import { AuthProvider, SignedIn, useAuth, useSession, type AuthLinkProps } from "@ubgo/auth-react"
import { useCallback } from "react"
import { Link as RRLink, Outlet, useNavigate } from "react-router"

import { auth } from "./auth.ts"

/** The kit's Link contract (href) on top of React Router's Link (to). */
// ds:def id=rr-routerlink-axxx6va2
export function RouterLink({ href, className, children }: AuthLinkProps) {
  return (
    <RRLink to={href} className={className}>
      {children}
    </RRLink>
  )
}

/** The root route's element: the provider around every page. */
// ds:def id=rr-root-xzsjnkv5
export function Root() {
  const go = useNavigate()
  const navigate = useCallback((href: string) => void go(href), [go])
  return (
    <AuthProvider client={auth} navigate={navigate} Link={RouterLink}>
      <Header />
      <Outlet />
    </AuthProvider>
  )
}

/** Links between pages go through the provider's Link, the one the kit's components use. */
function Header() {
  const { Link, paths } = useAuth()
  const { user } = useSession()
  return (
    <nav aria-label="Main">
      <Link href="/">Home</Link> · <Link href={paths.account}>Account</Link>
      <SignedIn>
        <span className="muted"> · {user?.name}</span>
      </SignedIn>
    </nav>
  )
}
