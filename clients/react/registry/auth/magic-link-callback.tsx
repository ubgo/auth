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
import { CircleAlertIcon, CircleCheckIcon, LinkIcon } from "lucide-react"
import { useState } from "react"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// MagicLinkCallback: the page a magic link opens. It reads the token from the
// address bar (?token=), signs in with it once, refreshes the session and
// moves on: to onSuccess, redirectTo or paths.afterSignIn, or to the second
// factor when the account has one. A used or expired link turns the card into
// a way back to the sign-in page, where a new link can be asked for.

/** Every string MagicLinkCallback shows. */
export type MagicLinkCallbackText = {
  signingInTitle: string
  signingInDescription: string
  signedInTitle: string
  signedInDescription: string
  continue: string
  invalidTitle: string
  invalidDescription: string
  /** The title and text when the page was opened without a token at all. */
  missingTitle: string
  missingDescription: string
  backToSignIn: string
  errorTitle: string
  retry: string
}

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    magicLinkCallback: MagicLinkCallbackText
  }
}

/** The English defaults. Override per app (AuthProvider localization.magicLinkCallback) or per use (localization prop). */
export const MAGIC_LINK_CALLBACK_TEXT: MagicLinkCallbackText = {
  signingInTitle: "Signing you in",
  signingInDescription: "One moment…",
  signedInTitle: "You are signed in",
  signedInDescription: "Taking you to the app…",
  continue: "Continue",
  invalidTitle: "This link has expired",
  invalidDescription: "Sign-in links work once and expire after a few minutes. Ask for a new one from the sign-in page.",
  missingTitle: "Open the link from your email",
  missingDescription: "This page needs the link from your sign-in email. Open the link from the email, or ask for a new one.",
  backToSignIn: "Back to sign in",
  errorTitle: "Could not sign you in",
  retry: "Try again",
}

/** The named parts classNames can style. */
export type MagicLinkCallbackSlot = "root" | "header" | "title" | "description" | "content" | "formError" | "action"

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

  const root = cn("w-full max-w-sm", className, classNames?.root)
  const actionClass = cn(buttonVariants({ size: "lg" }), "w-full", classNames?.action)
  const outcome = signIn.data

  if (token !== "" && outcome === undefined && signIn.error === null) {
    return (
      <Card className={root} aria-busy>
        <CardHeader className={classNames?.header}>
          <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
            <Spinner aria-hidden className="text-muted-foreground" />
            {t.signingInTitle}
          </CardTitle>
          <CardDescription className={classNames?.description} role="status">
            {t.signingInDescription}
          </CardDescription>
        </CardHeader>
      </Card>
    )
  }

  if (outcome?.ok === true) {
    // Shown only for the moment before navigation, or for good when onSuccess chose to stay.
    return (
      <Card className={root}>
        <CardHeader className={classNames?.header}>
          <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
            <CircleCheckIcon aria-hidden className="size-4 text-muted-foreground" />
            {t.signedInTitle}
          </CardTitle>
          <CardDescription className={classNames?.description} role="status">
            {t.signedInDescription}
          </CardDescription>
        </CardHeader>
        <CardContent className={classNames?.content}>
          <Link href={target} className={actionClass}>
            {t.continue}
          </Link>
        </CardContent>
      </Card>
    )
  }

  const failure = outcome?.ok === false ? outcome.error : null
  // Anything but an expired link (the network, a server fault) left the token unspent, so it can be retried.
  if (signIn.error !== null || (failure !== null && failure.code !== "auth.token_invalid")) {
    return (
      <Card className={root}>
        <CardHeader className={classNames?.header}>
          <CardTitle className={classNames?.title} role="heading" aria-level={headingLevel}>
            {t.errorTitle}
          </CardTitle>
        </CardHeader>
        <CardContent className={cn("flex flex-col gap-3.5", classNames?.content)}>
          {failure !== null && (
            <Alert variant="destructive" className={classNames?.formError}>
              <CircleAlertIcon aria-hidden />
              <AlertDescription>{messageFor(failure)}</AlertDescription>
            </Alert>
          )}
          <Button type="button" size="lg" className={cn("w-full", classNames?.action)} disabled={signIn.isFetching} onClick={() => void signIn.refetch()}>
            {signIn.isFetching && <Spinner data-icon="inline-start" />}
            {t.retry}
          </Button>
        </CardContent>
      </Card>
    )
  }

  // No token, or a spent or expired one.
  return (
    <Card className={root}>
      <CardHeader className={classNames?.header}>
        <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
          <LinkIcon aria-hidden className="size-4 text-muted-foreground" />
          {token === "" ? t.missingTitle : t.invalidTitle}
        </CardTitle>
        <CardDescription className={classNames?.description} role="status">
          {token === "" ? t.missingDescription : t.invalidDescription}
        </CardDescription>
      </CardHeader>
      <CardContent className={classNames?.content}>
        <Link href={withRedirect(paths.signIn, redirectTo)} className={actionClass}>
          {t.backToSignIn}
        </Link>
      </CardContent>
    </Card>
  )
}
