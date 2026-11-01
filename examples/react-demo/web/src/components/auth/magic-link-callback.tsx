import { useQuery } from "@tanstack/react-query"
import type { AuthError } from "@ubgo/auth-client"
import {
  AUTH_QUERY_ROOT,
  useAuth,
  useErrorMessage,
  useLocalization,
  usePluginClient,
  useSafeRedirect,
  useSessionActions,
  type AuthComponentProps,
} from "@ubgo/auth-react"
import { useState } from "react"

import {
  MAGIC_LINK_CALLBACK_TEXT,
  MagicLinkCallbackView,
  type MagicLinkCallbackSlot,
  type MagicLinkCallbackStatus,
  type MagicLinkCallbackText,
} from "@/components/auth/magic-link-callback-view"

// MagicLinkCallback: the page a magic link opens. It reads the token from the
// address bar (?token=), signs in with it once, refreshes the session and
// moves on: to onSuccess, redirectTo or paths.afterSignIn, or to the second
// factor when the account has one. A used or expired link turns the card into
// a way back to the sign-in page, where a new link can be asked for.
//
// The card itself is MagicLinkCallbackView (magic-link-callback-view.tsx):
// this file only wires it to @ubgo/auth-react, the token, the call, the
// session and navigation.

export {
  MAGIC_LINK_CALLBACK_TEXT,
  MagicLinkCallbackView,
  type MagicLinkCallbackSlot,
  type MagicLinkCallbackStatus,
  type MagicLinkCallbackText,
  type MagicLinkCallbackViewProps,
} from "@/components/auth/magic-link-callback-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    magicLinkCallback: MagicLinkCallbackText
  }
}

/** Who signed in, and whether the account was created by this link. Handed to onSuccess. */
export type MagicLinkSuccess = {
  readonly userId: string
  /** True when the link created the account (a first sign-in by link). */
  readonly created: boolean
}

export type MagicLinkCallbackProps = AuthComponentProps<MagicLinkCallbackSlot, "magicLinkCallback", MagicLinkSuccess> & {
  /** The token from the magic link. Left out, it is read from the page's address (?token=). */
  readonly token?: string
  /** Called when the account has a second factor. Left out, the page navigates to paths.twoFactor. */
  readonly onSecondFactor?: () => void
}

/** The `token` query parameter of the page's address, or "" during server rendering or when it is absent. */
function tokenFromLocation(): string {
  if (typeof window === "undefined") return ""
  return new URLSearchParams(window.location.search).get("token") ?? ""
}

/** Appends `redirectTo` to a path, so the next step can finish where this one was headed. */
function withRedirect(path: string, redirectTo: string | undefined): string {
  if (redirectTo === undefined) return path
  const joiner = path.includes("?") ? "&" : "?"
  return `${path}${joiner}redirectTo=${encodeURIComponent(redirectTo)}`
}

/** What the one sign-in call came to. */
type SignInOutcome = { readonly ok: true } | { readonly ok: false; readonly error: AuthError }

export function MagicLinkCallback({ className, classNames, localization, onSuccess, redirectTo: requestedRedirectTo, headingLevel = 1, token: tokenProp, onSecondFactor }: MagicLinkCallbackProps) {
  const t = useLocalization("magicLinkCallback", MAGIC_LINK_CALLBACK_TEXT, localization)
  const messageFor = useErrorMessage()
  const { navigate, paths, Link } = useAuth()
  // redirectTo usually comes from the address bar: anything but a path on
  // this site (or an origin the provider allows) is dropped, so the default
  // applies and a crafted link cannot send the user to another site.
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const { refreshSession } = useSessionActions()
  const magiclink = usePluginClient("magiclink")
  const [token] = useState(() => tokenProp ?? tokenFromLocation())
  const target = redirectTo ?? paths.afterSignIn

  // The token is spent by exactly one POST. A query keyed on the token gives
  // that for free: React's double mount in development, a re-render and a
  // remount all share the one cached answer, and nothing refetches it.
  const signIn = useQuery({
    queryKey: [...AUTH_QUERY_ROOT, "magiclink-sign-in", token],
    enabled: magiclink !== null && token !== "",
    staleTime: Infinity,
    gcTime: Infinity,
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    queryFn: async (): Promise<SignInOutcome> => {
      if (magiclink === null) throw new Error("MagicLinkCallback: magiclink plugin missing")
      const { data, error } = await magiclink.signIn({ token })
      if (error !== null) return { ok: false, error }
      await refreshSession()
      if (data.secondFactorRequired) {
        if (onSecondFactor === undefined) navigate(withRedirect(paths.twoFactor, redirectTo))
        else onSecondFactor()
      } else if (onSuccess === undefined) navigate(target)
      else onSuccess({ userId: data.user.id, created: data.created })
      return { ok: true }
    },
  })

  if (magiclink === null) return null

  const outcome = signIn.data
  const failure = outcome?.ok === false ? outcome.error : null
  // Anything but an expired link (the network, a server fault) left the token unspent, so it can be retried.
  const status: MagicLinkCallbackStatus =
    token !== "" && outcome === undefined && signIn.error === null
      ? "signingIn"
      : outcome?.ok === true
        ? "signedIn"
        : signIn.error !== null || (failure !== null && failure.code !== "auth.token_invalid")
          ? "failed"
          : token === ""
            ? "missing"
            : "invalid"

  return (
    <MagicLinkCallbackView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      status={status}
      formError={failure === null ? null : messageFor(failure)}
      pending={signIn.isFetching}
      continueHref={target}
      signInHref={withRedirect(paths.signIn, redirectTo)}
      Link={Link}
      onRetry={() => void signIn.refetch()}
    />
  )
}
