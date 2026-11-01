import { revalidateLogic, useForm } from "@tanstack/react-form"
import { ArrowLeftIcon, CircleAlertIcon, MailIcon } from "lucide-react"
import { useId, useRef } from "react"

import { AnchorLink, fillText, type ViewHeadingLevel, type ViewLinkComponent } from "@/components/auth/auth-view"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// ForgotPasswordFormView: step one of a password reset with no data layer.
// It asks for the identifier, validates it, and hands it to onSubmit; once
// the caller says a link went out (sentTo), it shows the "check your email"
// step, which never confirms the account exists. ForgotPasswordForm
// (forgot-password-form.tsx) is this view wired to @ubgo/auth-react.

/** Every string ForgotPasswordForm shows, with `{name}` placeholders where a value is filled in. */
export type ForgotPasswordFormText = {
  title: string
  description: string
  identifierLabel: string
  /** The label when the username plugin is on, so either can be typed. */
  identifierLabelWithUsername: string
  identifierPlaceholder: string
  identifierRequired: string
  submit: string
  submitting: string
  sentTitle: string
  /** `{identifier}` is what was typed. */
  sentDescription: string
  sendAgain: string
  useDifferentEmail: string
  backToSignIn: string
}

/** The English defaults. Override per app (AuthProvider localization.forgotPasswordForm) or per use (localization prop). */
export const FORGOT_PASSWORD_FORM_TEXT: ForgotPasswordFormText = {
  title: "Forgot your password?",
  description: "Enter your email and we will send you a link to choose a new one.",
  identifierLabel: "Email",
  identifierLabelWithUsername: "Email or username",
  identifierPlaceholder: "you@example.com",
  identifierRequired: "Enter your email.",
  submit: "Send reset link",
  submitting: "Sending…",
  sentTitle: "Check your email",
  sentDescription: "If an account exists for {identifier}, a link to reset its password is on its way. It works once and expires soon.",
  sendAgain: "Send it again",
  useDifferentEmail: "Use a different email",
  backToSignIn: "Back to sign in",
}

/** The named parts classNames can style. */
export type ForgotPasswordFormSlot =
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
  | "secondary"
  | "footer"
  | "link"

/** The fields that can carry their own error message. */
export type ForgotPasswordField = "identifier"

/** What the form hands onSubmit: the identifier, trimmed. */
export type ForgotPasswordFormValues = {
  readonly identifier: string
}

/** The props of ForgotPasswordFormView: what to render, what is running and failed, and the callbacks. */
export type ForgotPasswordFormViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<ForgotPasswordFormSlot, string>>
  /** Text overrides, merged over FORGOT_PASSWORD_FORM_TEXT. */
  readonly text?: Partial<ForgotPasswordFormText>
  /** The level of the title, 1 by default. */
  readonly headingLevel?: ViewHeadingLevel
  /** The identifier also accepts a username: the label says so and the input is a text field, not an email one. */
  readonly acceptsUsername?: boolean
  /** A starting value for the field. */
  readonly defaultIdentifier?: string
  /** Focus the field on mount. */
  readonly autoFocus?: boolean
  /** The request is running: the submit (or "Send it again") is disabled and shows its running label. */
  readonly pending?: boolean
  /** A message above the form or the sent step. */
  readonly formError?: string | null
  /** Messages under a field, by field. */
  readonly fieldErrors?: Partial<Record<ForgotPasswordField, string>>
  /** Set once a link went out: the card shows the "check your email" step for this identifier. */
  readonly sentTo?: string | null
  /** The "Back to sign in" footer link; the footer is hidden when left out. */
  readonly signInHref?: string
  /** The link component, a plain anchor by default. */
  readonly Link?: ViewLinkComponent
  /** The form passed its own checks. Awaited, so a slow call keeps the form submitting. */
  readonly onSubmit?: (values: ForgotPasswordFormValues) => void | Promise<void>
  /** "Send it again" on the sent step. */
  readonly onSendAgain?: () => void
  /** "Use a different email" on the sent step. */
  readonly onUseDifferentEmail?: () => void
}

/** The forgot-password card, or its "check your email" step, rendered from props alone. */
export function ForgotPasswordFormView({
  className,
  classNames,
  text,
  headingLevel = 1,
  acceptsUsername = false,
  defaultIdentifier = "",
  autoFocus = false,
  pending = false,
  formError = null,
  fieldErrors = {},
  sentTo = null,
  signInHref,
  Link = AnchorLink,
  onSubmit,
  onSendAgain,
  onUseDifferentEmail,
}: ForgotPasswordFormViewProps) {
  const t: ForgotPasswordFormText = { ...FORGOT_PASSWORD_FORM_TEXT, ...text }
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)

  const form = useForm({
    defaultValues: { identifier: defaultIdentifier },
    // Check on submit, then re-check each field as it is edited: an error
    // stays until it is fixed, and never appears while a field is first typed.
    validationLogic: revalidateLogic(),
    onSubmit: async ({ value }) => {
      await onSubmit?.({ identifier: value.identifier.trim() })
    },
    onSubmitInvalid: () => {
      formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
    },
  })

  const backLink = signInHref !== undefined && (
    <CardFooter className={cn("justify-center text-[13px]", classNames?.footer)}>
      <Link
        href={signInHref}
        className={cn(
          "inline-flex items-center gap-1 text-muted-foreground underline-offset-4 hover:text-foreground hover:underline focus-visible:underline focus-visible:outline-none",
          classNames?.link,
        )}
      >
        <ArrowLeftIcon aria-hidden className="size-3.5" />
        {t.backToSignIn}
      </Link>
    </CardFooter>
  )

  if (sentTo !== null) {
    return (
      <Card className={cn("w-full max-w-sm", className, classNames?.root)}>
        <CardHeader className={classNames?.header}>
          <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
            <MailIcon aria-hidden className="size-4 text-muted-foreground" />
            {t.sentTitle}
          </CardTitle>
          <CardDescription className={cn("wrap-anywhere", classNames?.description)} role="status">
            {fillText(t.sentDescription, { identifier: sentTo })}
          </CardDescription>
        </CardHeader>
        <CardContent className={cn("flex flex-col gap-2", classNames?.content)}>
          {formError !== null && (
            <Alert variant="destructive" className={classNames?.formError}>
              <CircleAlertIcon aria-hidden />
              <AlertDescription>{formError}</AlertDescription>
            </Alert>
          )}
          <Button
            type="button"
            variant="outline"
            className={cn("w-full", classNames?.secondary)}
            disabled={pending}
            aria-busy={pending}
            onClick={() => onSendAgain?.()}
          >
            {pending && <Spinner data-icon="inline-start" />}
            {pending ? t.submitting : t.sendAgain}
          </Button>
          <Button type="button" variant="ghost" className={cn("w-full text-muted-foreground", classNames?.secondary)} onClick={() => onUseDifferentEmail?.()}>
            {t.useDifferentEmail}
          </Button>
        </CardContent>
        {backLink}
      </Card>
    )
  }

  const busy = pending

  return (
    <Card className={cn("w-full max-w-sm", className, classNames?.root)}>
      <CardHeader className={classNames?.header}>
        <CardTitle className={classNames?.title} role="heading" aria-level={headingLevel}>
          {t.title}
        </CardTitle>
        <CardDescription className={classNames?.description}>{t.description}</CardDescription>
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
            <form.Field name="identifier" validators={{ onDynamic: ({ value }) => (value.trim() === "" ? t.identifierRequired : undefined) }}>
              {(field) => {
                const message = field.state.meta.errors[0] ?? fieldErrors.identifier
                const invalid = message !== undefined
                return (
                  <Field data-invalid={invalid} className={classNames?.field}>
                    <FieldLabel htmlFor={`${formId}-identifier`} className={classNames?.label}>
                      {acceptsUsername ? t.identifierLabelWithUsername : t.identifierLabel}
                    </FieldLabel>
                    <Input
                      id={`${formId}-identifier`}
                      name="identifier"
                      type={acceptsUsername ? "text" : "email"}
                      inputMode={acceptsUsername ? "text" : "email"}
                      autoComplete="username"
                      autoCapitalize="none"
                      spellCheck={false}
                      autoFocus={autoFocus}
                      required
                      placeholder={t.identifierPlaceholder}
                      value={field.state.value}
                      onChange={(e) => field.handleChange(e.target.value)}
                      onBlur={field.handleBlur}
                      aria-invalid={invalid}
                      aria-describedby={invalid ? `${formId}-identifier-error` : undefined}
                      className={classNames?.input}
                    />
                    {invalid && (
                      <FieldError id={`${formId}-identifier-error`} className={classNames?.fieldError}>
                        {message}
                      </FieldError>
                    )}
                  </Field>
                )
              }}
            </form.Field>
            <Button type="submit" size="lg" className={cn("w-full", classNames?.submit)} disabled={busy} aria-busy={busy}>
              {busy && <Spinner data-icon="inline-start" />}
              {busy ? t.submitting : t.submit}
            </Button>
          </FieldGroup>
        </form>
      </CardContent>
      {backLink}
    </Card>
  )
}
