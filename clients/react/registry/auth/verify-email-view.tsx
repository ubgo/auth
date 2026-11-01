import { revalidateLogic, useForm } from "@tanstack/react-form"
import { CircleAlertIcon, CircleCheckIcon, LinkIcon, MailIcon } from "lucide-react"
import { useId, useRef } from "react"

import { AnchorLink, fillText, type ViewHeadingLevel, type ViewLinkComponent } from "@/components/auth/auth-view"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// VerifyEmailView: the email verification page with no data layer. The
// caller spends the token and says where things stand through `status`;
// the view renders that step: verifying, verified, a failure that can be
// retried, the resend form (fresh or after an expired link), or the "check
// your email" step after a resend. VerifyEmail (verify-email.tsx) is this
// view wired to @ubgo/auth-react.

/** Every string VerifyEmail shows, with `{name}` placeholders where a value is filled in. */
export type VerifyEmailText = {
  verifyingTitle: string
  verifyingDescription: string
  successTitle: string
  /** `{email}` is the verified address. */
  successDescription: string
  continue: string
  signIn: string
  invalidTitle: string
  invalidDescription: string
  /** The card opened without a token. */
  resendTitle: string
  resendDescription: string
  emailLabel: string
  emailPlaceholder: string
  emailRequired: string
  resend: string
  resending: string
  resentTitle: string
  /** `{email}` is the address typed. */
  resentDescription: string
  retry: string
  backToSignIn: string
}

/** The English defaults. Override per app (AuthProvider localization.verifyEmail) or per use (localization prop). */
export const VERIFY_EMAIL_TEXT: VerifyEmailText = {
  verifyingTitle: "Verifying your email",
  verifyingDescription: "One moment…",
  successTitle: "Email verified",
  successDescription: "{email} is verified. Thank you.",
  continue: "Continue",
  signIn: "Sign in",
  invalidTitle: "This link has expired",
  invalidDescription: "Verification links work once and expire after a while. Enter your email and we will send a new one.",
  resendTitle: "Verify your email",
  resendDescription: "Enter your email and we will send you a new verification link.",
  emailLabel: "Email",
  emailPlaceholder: "you@example.com",
  emailRequired: "Enter your email.",
  resend: "Send a new link",
  resending: "Sending…",
  resentTitle: "Check your email",
  resentDescription: "If {email} is waiting to be verified, a new link is on its way.",
  retry: "Try again",
  backToSignIn: "Back to sign in",
}

/** The named parts classNames can style. */
export type VerifyEmailSlot =
  | "root"
  | "header"
  | "title"
  | "description"
  | "content"
  | "form"
  | "field"
  | "label"
  | "input"
  | "fieldError"
  | "formError"
  | "submit"
  | "action"
  | "footer"
  | "link"

/**
 * The step the card shows. verifying: the one call is running. verified:
 * the address is verified. failed: the call failed in a way a retry can fix
 * (the token was not spent). resend: the resend form, for a page opened
 * without a token. expired: the same form, explaining the link is used or
 * expired. resent: a new link went out.
 */
export type VerifyEmailStatus = "verifying" | "verified" | "failed" | "resend" | "expired" | "resent"

/** What the resend form hands onResend: the address, trimmed. */
export type VerifyEmailResendValues = {
  readonly email: string
}

/** The props of VerifyEmailView: the step, its values, and the callbacks. */
export type VerifyEmailViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<VerifyEmailSlot, string>>
  /** Text overrides, merged over VERIFY_EMAIL_TEXT. */
  readonly text?: Partial<VerifyEmailText>
  /** The level of the title, 1 by default. */
  readonly headingLevel?: ViewHeadingLevel
  /** Which step shows; the resend form by default. */
  readonly status?: VerifyEmailStatus
  /** The verified address (verified) or the address a new link went to (resent). */
  readonly email?: string
  /** On the verified step: the user is signed in, so the action says "Continue" instead of "Sign in". */
  readonly signedIn?: boolean
  /** Where the verified step's action goes; the action is hidden when left out. */
  readonly verifiedHref?: string
  /** The running call: the resend on the form, the retry on the failed step. Disables its button. */
  readonly pending?: boolean
  /** A message in an alert: why the verify call failed (failed) or why the resend did (resend, expired). */
  readonly formError?: string | null
  /** The "Back to sign in" footer on the resend, expired and resent steps; hidden when left out. */
  readonly signInHref?: string
  /** The link component, a plain anchor by default. */
  readonly Link?: ViewLinkComponent
  /** The resend form passed its own checks. Awaited, so a slow call keeps the form submitting. */
  readonly onResend?: (values: VerifyEmailResendValues) => void | Promise<void>
  /** "Try again" on the failed step. */
  readonly onRetry?: () => void
}

/** The verification card for one step, rendered from props alone. */
export function VerifyEmailView({
  className,
  classNames,
  text,
  headingLevel = 1,
  status = "resend",
  email = "",
  signedIn = false,
  verifiedHref,
  pending = false,
  formError = null,
  signInHref,
  Link = AnchorLink,
  onResend,
  onRetry,
}: VerifyEmailViewProps) {
  const t: VerifyEmailText = { ...VERIFY_EMAIL_TEXT, ...text }
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)

  const form = useForm({
    defaultValues: { email: "" },
    // Check on submit, then re-check each field as it is edited: an error
    // stays until it is fixed, and never appears while a field is first typed.
    validationLogic: revalidateLogic(),
    onSubmit: async ({ value }) => {
      await onResend?.({ email: value.email.trim() })
    },
    onSubmitInvalid: () => {
      formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
    },
  })

  const root = cn("w-full max-w-sm", className, classNames?.root)
  const actionClass = cn(buttonVariants({ size: "lg" }), "w-full", classNames?.action)

  if (status === "verifying") {
    return (
      <Card className={root} aria-busy>
        <CardHeader className={classNames?.header}>
          <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
            <Spinner aria-hidden className="text-muted-foreground" />
            {t.verifyingTitle}
          </CardTitle>
          <CardDescription className={cn("wrap-anywhere", classNames?.description)} role="status">
            {t.verifyingDescription}
          </CardDescription>
        </CardHeader>
      </Card>
    )
  }

  if (status === "verified") {
    return (
      <Card className={root}>
        <CardHeader className={classNames?.header}>
          <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
            <CircleCheckIcon aria-hidden className="size-4 text-muted-foreground" />
            {t.successTitle}
          </CardTitle>
          <CardDescription className={cn("wrap-anywhere", classNames?.description)} role="status">
            {fillText(t.successDescription, { email })}
          </CardDescription>
        </CardHeader>
        <CardContent className={classNames?.content}>
          {verifiedHref !== undefined && (
            <Link href={verifiedHref} className={actionClass}>
              {signedIn ? t.continue : t.signIn}
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
            {t.verifyingTitle}
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

  const footer = signInHref !== undefined && (
    <CardFooter className={cn("justify-center text-[13px]", classNames?.footer)}>
      <Link
        href={signInHref}
        className={cn("text-muted-foreground underline-offset-4 hover:text-foreground hover:underline focus-visible:underline focus-visible:outline-none", classNames?.link)}
      >
        {t.backToSignIn}
      </Link>
    </CardFooter>
  )

  if (status === "resent") {
    return (
      <Card className={root}>
        <CardHeader className={classNames?.header}>
          <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
            <MailIcon aria-hidden className="size-4 text-muted-foreground" />
            {t.resentTitle}
          </CardTitle>
          <CardDescription className={cn("wrap-anywhere", classNames?.description)} role="status">
            {fillText(t.resentDescription, { email })}
          </CardDescription>
        </CardHeader>
        {footer}
      </Card>
    )
  }

  // No token, or an expired one: the resend form.
  const expired = status === "expired"
  const busy = pending
  return (
    <Card className={root}>
      <CardHeader className={classNames?.header}>
        <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
          {expired && <LinkIcon aria-hidden className="size-4 text-muted-foreground" />}
          {expired ? t.invalidTitle : t.resendTitle}
        </CardTitle>
        <CardDescription className={classNames?.description}>{expired ? t.invalidDescription : t.resendDescription}</CardDescription>
      </CardHeader>
      <CardContent className={cn("flex flex-col gap-3.5", classNames?.content)}>
        {formError !== null && (
          <Alert variant="destructive" className={classNames?.formError}>
            <CircleAlertIcon aria-hidden />
            <AlertDescription>{formError}</AlertDescription>
          </Alert>
        )}
        <form
          ref={formRef}
          id={formId}
          noValidate
          className={classNames?.form}
          onSubmit={(e) => {
            e.preventDefault()
            e.stopPropagation()
            void form.handleSubmit()
          }}
        >
          <FieldGroup>
            <form.Field name="email" validators={{ onDynamic: ({ value }) => (value.trim() === "" ? t.emailRequired : undefined) }}>
              {(field) => {
                const message = field.state.meta.errors[0]
                const invalid = message !== undefined
                return (
                  <Field data-invalid={invalid} className={classNames?.field}>
                    <FieldLabel htmlFor={`${formId}-email`} className={classNames?.label}>
                      {t.emailLabel}
                    </FieldLabel>
                    <Input
                      id={`${formId}-email`}
                      name="email"
                      type="email"
                      inputMode="email"
                      autoComplete="email"
                      autoCapitalize="none"
                      spellCheck={false}
                      required
                      placeholder={t.emailPlaceholder}
                      value={field.state.value}
                      onChange={(e) => field.handleChange(e.target.value)}
                      onBlur={field.handleBlur}
                      aria-invalid={invalid}
                      aria-describedby={invalid ? `${formId}-email-error` : undefined}
                      className={classNames?.input}
                    />
                    {invalid && (
                      <FieldError id={`${formId}-email-error`} className={classNames?.fieldError}>
                        {message}
                      </FieldError>
                    )}
                  </Field>
                )
              }}
            </form.Field>
            <Button type="submit" size="lg" className={cn("w-full", classNames?.submit)} disabled={busy} aria-busy={busy}>
              {busy && <Spinner data-icon="inline-start" />}
              {busy ? t.resending : t.resend}
            </Button>
          </FieldGroup>
        </form>
      </CardContent>
      {footer}
    </Card>
  )
}
