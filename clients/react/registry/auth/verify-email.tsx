import { useMutation, useQuery } from "@tanstack/react-query"
import type { AuthError } from "@ubgo/auth-client"
import {
  AUTH_QUERY_ROOT,
  useAuth,
  useErrorMessage,
  useLocalization,
  usePluginClient,
  useSafeRedirect,
  useSession,
  useSessionActions,
  type AuthComponentProps,
} from "@ubgo/auth-react"
import { useState } from "react"

import { VERIFY_EMAIL_TEXT, VerifyEmailView, type VerifyEmailSlot, type VerifyEmailStatus, type VerifyEmailText } from "@/components/auth/verify-email-view"

// VerifyEmail: the page the verification link opens. It reads the token from
// the address bar (?token=) and posts it once; a link is never spent by a GET,
// so mail scanners that preview links cannot use it up. The answer decides
// the card: verified (and, when the server signs people in on verify, a
// refreshed session), or expired, which offers to mail a new link. Opened
// without a token, the card is just the "send me a new link" form.
//
// The card itself is VerifyEmailView (verify-email-view.tsx): this file only
// wires it to @ubgo/auth-react, the token, the calls, the session and
// navigation.

export {
  VERIFY_EMAIL_TEXT,
  VerifyEmailView,
  type VerifyEmailResendValues,
  type VerifyEmailSlot,
  type VerifyEmailStatus,
  type VerifyEmailText,
  type VerifyEmailViewProps,
} from "@/components/auth/verify-email-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    verifyEmail: VerifyEmailText
  }
}

/** The verified address, and whether the server signed the user in with it. Handed to onSuccess. */
export type VerifyEmailSuccess = {
  readonly email: string
  readonly signedIn: boolean
}

export type VerifyEmailProps = AuthComponentProps<VerifyEmailSlot, "verifyEmail", VerifyEmailSuccess> & {
  /** The token from the verification link. Left out, it is read from the page's address (?token=). */
  readonly token?: string
  /**
   * Called when verifying signed the user in and the session needs a second
   * factor. Left out, the page navigates to paths.twoFactor.
   */
  readonly onSecondFactor?: () => void
  /** Show the "Back to sign in" footer on the resend form. On by default. */
  readonly showSignIn?: boolean
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

/** What the one verify call came to. */
type VerifyOutcome = { readonly ok: true; readonly email: string; readonly signedIn: boolean } | { readonly ok: false; readonly error: AuthError }

export function VerifyEmail({
  className,
  classNames,
  localization,
  onSuccess,
  redirectTo: requestedRedirectTo,
  headingLevel = 1,
  token: tokenProp,
  onSecondFactor,
  showSignIn = true,
}: VerifyEmailProps) {
  const t = useLocalization("verifyEmail", VERIFY_EMAIL_TEXT, localization)
  const messageFor = useErrorMessage()
  const { navigate, paths, Link } = useAuth()
  // redirectTo usually comes from the address bar: anything but a path on
  // this site (or an origin the provider allows) is dropped, so the default
  // applies and a crafted link cannot send the user to another site.
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const { refreshSession } = useSessionActions()
  // Verifying in the browser that just signed up finds a session already there.
  const { user } = useSession()
  const email = usePluginClient("email")
  const [token] = useState(() => tokenProp ?? tokenFromLocation())
  const [resentTo, setResentTo] = useState<string | null>(null)
  const [resendError, setResendError] = useState<string | null>(null)

  // The token is spent by exactly one POST. A query (not an effect) keyed on
  // the token gives that for free: React's double mount in development, a
  // re-render and a remount all share the one cached answer, and nothing
  // refetches it on focus or reconnect.
  const verify = useQuery({
    queryKey: [...AUTH_QUERY_ROOT, "email-verify", token],
    enabled: email !== null && token !== "",
    staleTime: Infinity,
    gcTime: Infinity,
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    queryFn: async (): Promise<VerifyOutcome> => {
      if (email === null) throw new Error("VerifyEmail: email plugin missing")
      const { data, error } = await email.verify({ token })
      if (error !== null) return { ok: false, error }
      const signedIn = data.signedIn === true
      if (signedIn) await refreshSession()
      const result: VerifyEmailSuccess = { email: data.email, signedIn }
      if (data.secondFactorRequired === true) {
        if (onSecondFactor === undefined) navigate(withRedirect(paths.twoFactor, redirectTo))
        else onSecondFactor()
      } else if (onSuccess !== undefined) onSuccess(result)
      else if (redirectTo !== undefined && signedIn) navigate(redirectTo)
      return { ok: true, email: data.email, signedIn }
    },
  })

  const resend = useMutation({
    mutationFn: async (address: string) => {
      if (email === null) throw new Error("VerifyEmail: email plugin missing")
      return email.resend({ email: address })
    },
    onSuccess: ({ error }, address) => {
      if (error !== null) setResendError(messageFor(error))
      else setResentTo(address)
    },
  })

  if (email === null) return null

  const outcome = verify.data
  // An answer other than an expired link (the network, a server fault) can be retried: the token was not spent.
  const failure = outcome?.ok === false ? outcome.error : null
  const signedIn = outcome?.ok === true && (outcome.signedIn || user !== null)

  const status: VerifyEmailStatus =
    token !== "" && outcome === undefined && verify.error === null
      ? "verifying"
      : outcome?.ok === true
        ? "verified"
        : verify.error !== null || (failure !== null && failure.code !== "auth.token_invalid")
          ? "failed"
          : resentTo !== null
            ? "resent"
            : failure !== null
              ? "expired"
              : "resend"

  return (
    <VerifyEmailView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      status={status}
      email={outcome?.ok === true ? outcome.email : (resentTo ?? "")}
      signedIn={signedIn}
      verifiedHref={signedIn ? (redirectTo ?? paths.afterSignIn) : withRedirect(paths.signIn, redirectTo)}
      pending={status === "failed" ? verify.isFetching : resend.isPending}
      formError={status === "failed" ? (failure === null ? null : messageFor(failure)) : resendError}
      signInHref={showSignIn ? paths.signIn : undefined}
      Link={Link}
      onResend={async (values) => {
        setResendError(null)
        await resend.mutateAsync(values.email)
      }}
      onRetry={() => void verify.refetch()}
    />
  )
}
