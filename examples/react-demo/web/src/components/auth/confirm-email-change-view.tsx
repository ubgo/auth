import { CircleAlertIcon, CircleCheckIcon, LinkIcon, ShieldCheckIcon } from "lucide-react"
import type { ReactNode } from "react"

import { AnchorLink, fillText, type ViewHeadingLevel, type ViewLinkComponent } from "@/components/auth/auth-view"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// ConfirmEmailChangeView: the email-change landing page with no data layer.
// The caller posts the token and says where things stand through `status`;
// the view renders that step: no token, working, confirmed, undone, an
// expired link, or a failure that can be retried. ConfirmEmailChange
// (confirm-email-change.tsx) is this view wired to @ubgo/auth-react.

/** Every string ConfirmEmailChange shows, with `{name}` placeholders where a value is filled in. */
export type ConfirmEmailChangeText = {
  workingTitle: string
  workingDescription: string
  confirmedTitle: string
  /** `{email}` is the new address. */
  confirmedDescription: string
  undoneTitle: string
  undoneDescription: string
  invalidTitle: string
  invalidDescription: string
  missingTitle: string
  missingDescription: string
  continue: string
  signIn: string
  account: string
  retry: string
}

/** The English defaults. Override per app (AuthProvider localization.confirmEmailChange) or per use (localization prop). */
export const CONFIRM_EMAIL_CHANGE_TEXT: ConfirmEmailChangeText = {
  workingTitle: "Updating your email",
  workingDescription: "One moment…",
  confirmedTitle: "Email changed",
  confirmedDescription: "Your account now uses {email}.",
  undoneTitle: "Change undone",
  undoneDescription: "Your previous email address is back, and every session was signed out. Sign in, then change your password.",
  invalidTitle: "This link has expired",
  invalidDescription: "Email-change links work once and expire after a while. Start the change again from your account.",
  missingTitle: "No link to open",
  missingDescription: "Open this page from the link in your email.",
  continue: "Continue",
  signIn: "Sign in",
  account: "Back to your account",
  retry: "Try again",
}

/** The named parts classNames can style. */
export type ConfirmEmailChangeSlot = "root" | "header" | "title" | "description" | "content" | "formError" | "action"

/**
 * The step the card shows. missing: opened without a token. working: the
 * one call is running. confirmed: the new address is the account's.
 * undone: the old address is back and every session was signed out.
 * invalid: the link is used or expired. failed: a retry can fix it, the
 * token was not spent.
 */
export type ConfirmEmailChangeStatus = "missing" | "working" | "confirmed" | "undone" | "invalid" | "failed"

/** The props of ConfirmEmailChangeView: the step, its link, and the retry. */
export type ConfirmEmailChangeViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<ConfirmEmailChangeSlot, string>>
  /** Text overrides, merged over CONFIRM_EMAIL_CHANGE_TEXT. */
  readonly text?: Partial<ConfirmEmailChangeText>
  /** The level of the title, 1 by default. */
  readonly headingLevel?: ViewHeadingLevel
  /** Which step shows; working by default. */
  readonly status?: ConfirmEmailChangeStatus
  /** The new address, on the confirmed step. */
  readonly email?: string
  /** Someone is signed in: the action reads "Continue" or "Back to your account" instead of "Sign in" (never on the undone step). */
  readonly signedIn?: boolean
  /** Where the action on the missing, confirmed, undone and invalid steps goes; hidden when left out. */
  readonly actionHref?: string
  /** Why the call failed, on the failed step; no alert when left out. */
  readonly formError?: string | null
  /** The retry is running: its button is disabled and shows a spinner. */
  readonly pending?: boolean
  /** The link component, a plain anchor by default. */
  readonly Link?: ViewLinkComponent
  /** "Try again" on the failed step. */
  readonly onRetry?: () => void
}

/** The email-change card for one step, rendered from props alone. */
export function ConfirmEmailChangeView({
  className,
  classNames,
  text,
  headingLevel = 1,
  status = "working",
  email = "",
  signedIn = false,
  actionHref,
  formError = null,
  pending = false,
  Link = AnchorLink,
  onRetry,
}: ConfirmEmailChangeViewProps) {
  const t: ConfirmEmailChangeText = { ...CONFIRM_EMAIL_CHANGE_TEXT, ...text }
  const root = cn("w-full max-w-sm", className, classNames?.root)
  const actionClass = cn(buttonVariants({ size: "lg" }), "w-full", classNames?.action)
  /** The step's action link, or nothing without an href. */
  const action = (label: string) =>
    actionHref === undefined ? null : (
      <Link href={actionHref} className={actionClass}>
        {label}
      </Link>
    )

  if (status === "missing" || status === "invalid") {
    const missing = status === "missing"
    return (
      <StateCard
        headingLevel={headingLevel}
        root={root}
        classNames={classNames}
        icon={<LinkIcon aria-hidden className="size-4 text-muted-foreground" />}
        title={missing ? t.missingTitle : t.invalidTitle}
        description={missing ? t.missingDescription : t.invalidDescription}
      >
        {action(signedIn ? t.account : t.signIn)}
      </StateCard>
    )
  }

  if (status === "working") {
    return (
      <Card className={root} aria-busy>
        <CardHeader className={classNames?.header}>
          <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
            <Spinner aria-hidden className="text-muted-foreground" />
            {t.workingTitle}
          </CardTitle>
          <CardDescription className={classNames?.description} role="status">
            {t.workingDescription}
          </CardDescription>
        </CardHeader>
      </Card>
    )
  }

  if (status === "confirmed" || status === "undone") {
    const undone = status === "undone"
    return (
      <StateCard
        headingLevel={headingLevel}
        root={root}
        classNames={classNames}
        icon={undone ? <ShieldCheckIcon aria-hidden className="size-4 text-muted-foreground" /> : <CircleCheckIcon aria-hidden className="size-4 text-muted-foreground" />}
        title={undone ? t.undoneTitle : t.confirmedTitle}
        description={undone ? t.undoneDescription : fillText(t.confirmedDescription, { email })}
        status
      >
        {action(undone || !signedIn ? t.signIn : t.continue)}
      </StateCard>
    )
  }

  // The network or a server fault: the token was not spent, so it can be retried.
  return (
    <Card className={root}>
      <CardHeader className={classNames?.header}>
        <CardTitle className={classNames?.title} role="heading" aria-level={headingLevel}>
          {t.workingTitle}
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

/** One finished step: an icon and title, a description, and the action under them. */
function StateCard({
  root,
  classNames,
  icon,
  title,
  description,
  status = false,
  headingLevel,
  children,
}: {
  headingLevel: ViewHeadingLevel
  root: string
  classNames: ConfirmEmailChangeViewProps["classNames"]
  icon: ReactNode
  title: string
  description: string
  status?: boolean
  children: ReactNode
}) {
  return (
    <Card className={root}>
      <CardHeader className={classNames?.header}>
        <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
          {icon}
          {title}
        </CardTitle>
        <CardDescription className={classNames?.description} role={status ? "status" : undefined}>
          {description}
        </CardDescription>
      </CardHeader>
      <CardContent className={classNames?.content}>{children}</CardContent>
    </Card>
  )
}
