import { revalidateLogic, useForm } from "@tanstack/react-form"
import { CircleAlertIcon, CircleCheckIcon, LinkIcon } from "lucide-react"
import { useEffect, useId, useRef } from "react"

import { AnchorLink, fillText, type ViewHeadingLevel, type ViewLinkComponent } from "@/components/auth/auth-view"
import { DEFAULT_PASSWORD_MIN_LENGTH, PasswordStrengthView, type PasswordStrengthText } from "@/components/auth/password-strength-view"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// ResetPasswordFormView: step two of a password reset with no data layer. It
// asks for the new password (twice by default), validates it, and hands it
// to onSubmit. Which step shows (the form, done, an expired link, no link at
// all) comes in as `status`; the token and the call stay with the caller.
// ResetPasswordForm (reset-password-form.tsx) is this view wired to
// @ubgo/auth-react.

/** Every string ResetPasswordForm shows, with `{name}` placeholders where a value is filled in. */
export type ResetPasswordFormText = {
  title: string
  description: string
  passwordLabel: string
  passwordRequired: string
  /** `{min}` is the shortest length the form asks for. */
  passwordTooShort: string
  confirmLabel: string
  confirmRequired: string
  confirmMismatch: string
  submit: string
  submitting: string
  successTitle: string
  successDescription: string
  continueToSignIn: string
  invalidTitle: string
  invalidDescription: string
  /** The title and text when the page was opened without a token at all. */
  missingTitle: string
  missingDescription: string
  requestNewLink: string
}

/** The English defaults. Override per app (AuthProvider localization.resetPasswordForm) or per use (localization prop). */
export const RESET_PASSWORD_FORM_TEXT: ResetPasswordFormText = {
  title: "Choose a new password",
  description: "Pick a password you do not use anywhere else.",
  passwordLabel: "New password",
  passwordRequired: "Choose a new password.",
  passwordTooShort: "Use {min} or more characters.",
  confirmLabel: "Confirm new password",
  confirmRequired: "Type the new password again.",
  confirmMismatch: "The two passwords do not match.",
  submit: "Reset password",
  submitting: "Resetting…",
  successTitle: "Password changed",
  successDescription: "Your password is reset. Sign in with the new one.",
  continueToSignIn: "Continue to sign in",
  invalidTitle: "This link has expired",
  invalidDescription: "Reset links work once and expire after a while. Ask for a new one and use the latest email.",
  missingTitle: "Open the link from your email",
  missingDescription: "This page needs the link from your reset email. Open the link from the email, or ask for a new one.",
  requestNewLink: "Request a new link",
}

/** The named parts classNames can style. */
export type ResetPasswordFormSlot =
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
  | "strength"
  | "submit"
  | "action"

/**
 * Which step the card shows: the form, the success step, the step for a
 * used or expired link, or the step for a page opened without a token.
 */
export type ResetPasswordStatus = "form" | "done" | "invalid" | "missing"

/** The fields that can carry a message from the server. */
export type ResetPasswordField = "password"

/** What the form hands onSubmit: the new password, exactly as typed. */
export type ResetPasswordFormValues = {
  readonly password: string
}

/** The props of ResetPasswordFormView: the step, what is running and failed, and the callbacks. */
export type ResetPasswordFormViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<ResetPasswordFormSlot, string>>
  /** Text overrides, merged over RESET_PASSWORD_FORM_TEXT. */
  readonly text?: Partial<ResetPasswordFormText>
  /** Text overrides for the password strength meter, merged over PASSWORD_STRENGTH_TEXT. */
  readonly strengthText?: Partial<PasswordStrengthText>
  /** The level of the title, 1 by default. */
  readonly headingLevel?: ViewHeadingLevel
  /** Which step shows; the form by default. */
  readonly status?: ResetPasswordStatus
  /** The shortest password the strength hint and the check before submit ask for. */
  readonly minPasswordLength?: number
  /** Ask for the new password twice. On by default. */
  readonly confirmPassword?: boolean
  /** Focus the first field on mount. */
  readonly autoFocus?: boolean
  /** The reset call is running: the submit is disabled and shows its running label. */
  readonly pending?: boolean
  /** A message above the form. */
  readonly formError?: string | null
  /** Messages under a field, by field. A newly set one moves focus to its field. */
  readonly fieldErrors?: Partial<Record<ResetPasswordField, string>>
  /** "Continue to sign in" on the done step; hidden when left out. */
  readonly signInHref?: string
  /** "Request a new link" on the invalid and missing steps; hidden when left out. */
  readonly forgotPasswordHref?: string
  /** The link component, a plain anchor by default. */
  readonly Link?: ViewLinkComponent
  /** The form passed its own checks. Awaited, so a slow call keeps the form submitting. */
  readonly onSubmit?: (values: ResetPasswordFormValues) => void | Promise<void>
  /** The password was edited while it showed a field error: the server's complaint is stale, a good moment to clear it. */
  readonly onPasswordChange?: () => void
}

/** The fieldErrors default, one object so the focus effect does not fire on every render. */
const NO_FIELD_ERRORS: Partial<Record<ResetPasswordField, string>> = {}

/** The reset card, or its done / expired / missing step, rendered from props alone. */
export function ResetPasswordFormView({
  className,
  classNames,
  text,
  strengthText,
  headingLevel = 1,
  status = "form",
  minPasswordLength = DEFAULT_PASSWORD_MIN_LENGTH,
  confirmPassword = true,
  autoFocus = false,
  pending = false,
  formError = null,
  fieldErrors = NO_FIELD_ERRORS,
  signInHref,
  forgotPasswordHref,
  Link = AnchorLink,
  onSubmit,
  onPasswordChange,
}: ResetPasswordFormViewProps) {
  const t: ResetPasswordFormText = { ...RESET_PASSWORD_FORM_TEXT, ...text }
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)
  const shownPasswordError = useRef<string | undefined>(undefined)

  // A server error about the password moves focus to the field, once, when it appears.
  useEffect(() => {
    const previous = shownPasswordError.current
    shownPasswordError.current = fieldErrors.password
    if (fieldErrors.password !== undefined && fieldErrors.password !== previous) {
      formRef.current?.querySelector<HTMLElement>('[name="password"]')?.focus()
    }
  }, [fieldErrors])

  const form = useForm({
    defaultValues: { password: "", confirm: "" },
    // Check on submit, then re-check each field as it is edited: an error
    // stays until it is fixed, and never appears while a field is first typed.
    validationLogic: revalidateLogic(),
    onSubmit: async ({ value }) => {
      await onSubmit?.({ password: value.password })
    },
    onSubmitInvalid: () => {
      formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
    },
  })

  if (status !== "form") {
    const done = status === "done"
    const Icon = done ? CircleCheckIcon : LinkIcon
    const actionHref = done ? signInHref : forgotPasswordHref
    return (
      <Card className={cn("w-full max-w-sm", className, classNames?.root)}>
        <CardHeader className={classNames?.header}>
          <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
            <Icon aria-hidden className="size-4 text-muted-foreground" />
            {done ? t.successTitle : status === "missing" ? t.missingTitle : t.invalidTitle}
          </CardTitle>
          <CardDescription className={classNames?.description} role="status">
            {done ? t.successDescription : status === "missing" ? t.missingDescription : t.invalidDescription}
          </CardDescription>
        </CardHeader>
        <CardContent className={classNames?.content}>
          {/* A link styled as the main button: it navigates, so it is an anchor for middle-click and screen readers. */}
          {actionHref !== undefined && (
            <Link href={actionHref} className={cn(buttonVariants({ size: "lg" }), "w-full", classNames?.action)}>
              {done ? t.continueToSignIn : t.requestNewLink}
            </Link>
          )}
        </CardContent>
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
          {/* Lets a password manager file the new password under the right account. */}
          <input type="text" name="username" autoComplete="username" hidden readOnly value="" />
          <FieldGroup>
            <form.Field
              name="password"
              validators={{
                onDynamic: ({ value }) =>
                  value === "" ? t.passwordRequired : [...value].length < minPasswordLength ? fillText(t.passwordTooShort, { min: minPasswordLength }) : undefined,
              }}
            >
              {(field) => {
                const message = field.state.meta.errors[0] ?? fieldErrors.password
                const invalid = message !== undefined
                const describedBy = [invalid ? `${formId}-password-error` : null, `${formId}-password-strength`].filter((x) => x !== null).join(" ")
                return (
                  <Field data-invalid={invalid} className={classNames?.field}>
                    <FieldLabel htmlFor={`${formId}-password`} className={classNames?.label}>
                      {t.passwordLabel}
                    </FieldLabel>
                    <Input
                      id={`${formId}-password`}
                      name="password"
                      type="password"
                      autoComplete="new-password"
                      autoFocus={autoFocus}
                      required
                      minLength={minPasswordLength}
                      value={field.state.value}
                      onChange={(e) => {
                        field.handleChange(e.target.value)
                        // A server complaint about the old value is stale once the user edits it.
                        if (fieldErrors.password !== undefined) onPasswordChange?.()
                      }}
                      onBlur={field.handleBlur}
                      aria-invalid={invalid}
                      aria-describedby={describedBy}
                      className={classNames?.input}
                    />
                    <PasswordStrengthView id={`${formId}-password-strength`} value={field.state.value} minLength={minPasswordLength} showHint={!invalid} className={classNames?.strength} text={strengthText} />
                    {invalid && (
                      <FieldError id={`${formId}-password-error`} className={classNames?.fieldError}>
                        {message}
                      </FieldError>
                    )}
                  </Field>
                )
              }}
            </form.Field>

            {confirmPassword && (
              <form.Field
                name="confirm"
                validators={{
                  onDynamic: ({ value, fieldApi }) =>
                    value === "" ? t.confirmRequired : value !== fieldApi.form.getFieldValue("password") ? t.confirmMismatch : undefined,
                }}
              >
                {(field) => {
                  const message = field.state.meta.errors[0]
                  const invalid = message !== undefined
                  return (
                    <Field data-invalid={invalid} className={classNames?.field}>
                      <FieldLabel htmlFor={`${formId}-confirm`} className={classNames?.label}>
                        {t.confirmLabel}
                      </FieldLabel>
                      <Input
                        id={`${formId}-confirm`}
                        name="confirm"
                        type="password"
                        autoComplete="new-password"
                        required
                        value={field.state.value}
                        onChange={(e) => field.handleChange(e.target.value)}
                        onBlur={field.handleBlur}
                        aria-invalid={invalid}
                        aria-describedby={invalid ? `${formId}-confirm-error` : undefined}
                        className={classNames?.input}
                      />
                      {invalid && (
                        <FieldError id={`${formId}-confirm-error`} className={classNames?.fieldError}>
                          {message}
                        </FieldError>
                      )}
                    </Field>
                  )
                }}
              </form.Field>
            )}

            <Button type="submit" size="lg" className={cn("w-full", classNames?.submit)} disabled={busy} aria-busy={busy}>
              {busy && <Spinner data-icon="inline-start" />}
              {busy ? t.submitting : t.submit}
            </Button>
          </FieldGroup>
        </form>
      </CardContent>
    </Card>
  )
}
