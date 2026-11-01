import { CircleAlertIcon, CircleCheckIcon, LinkIcon } from "lucide-react"

import { AnchorLink, type ViewHeadingLevel, type ViewLinkComponent } from "@/components/auth/auth-view"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// MagicLinkCallbackView: the magic-link landing page with no data layer. The
// caller spends the token and says where things stand through `status`; the
// view renders that step: signing in, signed in, a failure that can be
// retried, or a used / expired / missing link with the way back.
// MagicLinkCallback (magic-link-callback.tsx) is this view wired to
// @ubgo/auth-react.

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

/**
 * The step the card shows. signingIn: the one call is running. signedIn:
 * done (usually shown only before navigation). failed: a retry can fix it,
 * the token was not spent. invalid: the link is used or expired. missing:
 * the page was opened without a token.
 */
export type MagicLinkCallbackStatus = "signingIn" | "signedIn" | "failed" | "invalid" | "missing"

/** The props of MagicLinkCallbackView: the step, its links, and the retry. */
export type MagicLinkCallbackViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<MagicLinkCallbackSlot, string>>
  /** Text overrides, merged over MAGIC_LINK_CALLBACK_TEXT. */
  readonly text?: Partial<MagicLinkCallbackText>
  /** The level of the title, 1 by default. */
  readonly headingLevel?: ViewHeadingLevel
  /** Which step shows; signing in by default. */
  readonly status?: MagicLinkCallbackStatus
  /** Why the call failed, on the failed step; no alert when left out. */
  readonly formError?: string | null
  /** The retry is running: its button is disabled and shows a spinner. */
  readonly pending?: boolean
  /** "Continue" on the signed-in step; hidden when left out. */
  readonly continueHref?: string
  /** "Back to sign in" on the invalid and missing steps; hidden when left out. */
  readonly signInHref?: string
  /** The link component, a plain anchor by default. */
  readonly Link?: ViewLinkComponent
  /** "Try again" on the failed step. */
  readonly onRetry?: () => void
}

/** The magic-link card for one step, rendered from props alone. */
export function MagicLinkCallbackView({
  className,
  classNames,
  text,
  headingLevel = 1,
  status = "signingIn",
  formError = null,
  pending = false,
  continueHref,
  signInHref,
  Link = AnchorLink,
  onRetry,
}: MagicLinkCallbackViewProps) {
  const t: MagicLinkCallbackText = { ...MAGIC_LINK_CALLBACK_TEXT, ...text }
  const root = cn("w-full max-w-sm", className, classNames?.root)
  const actionClass = cn(buttonVariants({ size: "lg" }), "w-full", classNames?.action)

  if (status === "signingIn") {
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

  if (status === "signedIn") {
    // Shown only for the moment before navigation, or for good when the caller chose to stay.
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
          {continueHref !== undefined && (
            <Link href={continueHref} className={actionClass}>
              {t.continue}
            </Link>
          )}
        </CardContent>
      </Card>
    )
  }

  if (status === "failed") {
    return (
      <Card className={root}>
        <CardHeader className={classNames?.header}>
          <CardTitle className={classNames?.title} role="heading" aria-level={headingLevel}>
            {t.errorTitle}
          </CardTitle>
        </CardHeader>
        <CardContent className={cn("flex flex-col gap-3.5", classNames?.content)}>
          {formError !== null && (
            <Alert variant="destructive" className={classNames?.formError}>
              <CircleAlertIcon aria-hidden />
              <AlertDescription>{formError}</AlertDescription>
            </Alert>
          )}
          <Button type="button" size="lg" className={cn("w-full", classNames?.action)} disabled={pending} onClick={() => onRetry?.()}>
            {pending && <Spinner data-icon="inline-start" />}
            {t.retry}
          </Button>
        </CardContent>
      </Card>
    )
  }

  // No token, or a spent or expired one.
  const missing = status === "missing"
  return (
    <Card className={root}>
      <CardHeader className={classNames?.header}>
        <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
          <LinkIcon aria-hidden className="size-4 text-muted-foreground" />
          {missing ? t.missingTitle : t.invalidTitle}
        </CardTitle>
        <CardDescription className={classNames?.description} role="status">
          {missing ? t.missingDescription : t.invalidDescription}
        </CardDescription>
      </CardHeader>
      <CardContent className={classNames?.content}>
        {signInHref !== undefined && (
          <Link href={signInHref} className={actionClass}>
            {t.backToSignIn}
          </Link>
        )}
      </CardContent>
    </Card>
  )
}
