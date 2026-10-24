import { revalidateLogic, useForm } from "@tanstack/react-form"
import { useMutation } from "@tanstack/react-query"
import type { AuthError } from "@ubgo/auth-client"
import {
  format,
  useAuth,
  useErrorMessage,
  useLocalization,
  usePluginClient,
  useSafeRedirect,
  type AuthComponentProps,
} from "@ubgo/auth-react"
import { CircleAlertIcon, CircleCheckIcon, LinkIcon } from "lucide-react"
import { useId, useRef, useState } from "react"

import { DEFAULT_PASSWORD_MIN_LENGTH, PasswordStrength } from "@/components/auth/password-strength"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// ResetPasswordForm: step two of a password reset, on the page the mailed
// link opens. It reads the token from the address bar (?token=), asks for the
// new password twice, and posts both. The link works once: a used, expired or
// missing token turns the card into a "request a new link" step instead of
// leaving a form that can only fail. A reset signs nobody in, so success
// offers the sign-in page.

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

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    resetPasswordForm: ResetPasswordFormText
  }
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

/** The reset went through, handed to onSuccess. Nobody is signed in by it. */
export type ResetPasswordSuccess = {
  readonly reset: true
}

export type ResetPasswordFormProps = AuthComponentProps<ResetPasswordFormSlot, "resetPasswordForm", ResetPasswordSuccess> & {
  /**
   * The token from the reset link. Left out, it is read from the page's
   * address (?token=), which is where the server's link puts it.
   */
  readonly token?: string
  /** The shortest password the strength hint and the check before submit ask for; match the server's password.MinLength. */
  readonly minPasswordLength?: number
  /** Ask for the new password twice. On by default. */
  readonly confirmPassword?: boolean
  /** Focus the first field on mount. */
  readonly autoFocus?: boolean
}

/** The `token` query parameter of the page's address, or "" during server rendering or when it is absent. */
function tokenFromLocation(): string {
  if (typeof window === "undefined") return ""
  return new URLSearchParams(window.location.search).get("token") ?? ""
}

/** Codes about the new password, shown under its field. */
const PASSWORD_ERRORS: ReadonlySet<string> = new Set(["password.too_short", "password.too_long", "password.weak", "password.breached", "password.reused"])

export function ResetPasswordForm({
  className,
  classNames,
  localization,
  onSuccess,
  redirectTo: requestedRedirectTo,
  headingLevel = 1,
  token: tokenProp,
  minPasswordLength = DEFAULT_PASSWORD_MIN_LENGTH,
  confirmPassword = true,
  autoFocus = false,
}: ResetPasswordFormProps) {
  const t = useLocalization("resetPasswordForm", RESET_PASSWORD_FORM_TEXT, localization)
  const messageFor = useErrorMessage()
  const { navigate, paths, Link } = useAuth()
  // redirectTo usually comes from the address bar: anything but a path on
  // this site (or an origin the provider allows) is dropped, so the default
  // applies and a crafted link cannot send the user to another site.
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const password = usePluginClient("password")
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)
  // Read once: the address does not change under the form, and a router
  // that strips the query after mount must not blank the token mid-typing.
  const [token] = useState(() => tokenProp ?? tokenFromLocation())

  const [formError, setFormError] = useState<string | null>(null)
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const [state, setState] = useState<"form" | "done" | "invalid">(token === "" ? "invalid" : "form")

  function showError(error: AuthError) {
    if (error.code === "auth.token_invalid") setState("invalid")
    else if (PASSWORD_ERRORS.has(error.code)) {
      setPasswordError(messageFor(error))
      requestAnimationFrame(() => formRef.current?.querySelector<HTMLElement>('[name="password"]')?.focus())
    } else setFormError(messageFor(error))
  }

  const reset = useMutation({
    mutationFn: async (newPassword: string) => {
      if (password === null) throw new Error("ResetPasswordForm: password plugin missing")
      return password.reset({ token, password: newPassword })
    },
    onSuccess: ({ error }) => {
      if (error !== null) {
        showError(error)
        return
      }
      if (onSuccess !== undefined) onSuccess({ reset: true })
      else if (redirectTo !== undefined) navigate(redirectTo)
      else setState("done")
    },
  })

  const form = useForm({
    defaultValues: { password: "", confirm: "" },
    // Check on submit, then re-check each field as it is edited: an error
    // stays until it is fixed, and never appears while a field is first typed.
    validationLogic: revalidateLogic(),
    onSubmit: async ({ value }) => {
      setFormError(null)
      setPasswordError(null)
      await reset.mutateAsync(value.password)
    },
    onSubmitInvalid: () => {
      formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
    },
  })

  if (password === null) return null

  if (state !== "form") {
    const done = state === "done"
    const Icon = done ? CircleCheckIcon : LinkIcon
    return (
      <Card className={cn("w-full max-w-sm", className, classNames?.root)}>
        <CardHeader className={classNames?.header}>
          <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
            <Icon aria-hidden className="size-4 text-muted-foreground" />
            {done ? t.successTitle : token === "" ? t.missingTitle : t.invalidTitle}
          </CardTitle>
          <CardDescription className={classNames?.description} role="status">
            {done ? t.successDescription : token === "" ? t.missingDescription : t.invalidDescription}
          </CardDescription>
        </CardHeader>
        <CardContent className={classNames?.content}>
          {/* A link styled as the main button: it navigates, so it is an anchor for middle-click and screen readers. */}
          <Link
            href={done ? paths.signIn : paths.forgotPassword}
            className={cn(buttonVariants({ size: "lg" }), "w-full", classNames?.action)}
          >
            {done ? t.continueToSignIn : t.requestNewLink}
          </Link>
        </CardContent>
      </Card>
    )
  }

  const busy = reset.isPending

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
                  value === "" ? t.passwordRequired : [...value].length < minPasswordLength ? format(t.passwordTooShort, { min: minPasswordLength }) : undefined,
              }}
            >
              {(field) => {
                const message = field.state.meta.errors[0] ?? passwordError ?? undefined
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
                        if (passwordError !== null) setPasswordError(null)
                      }}
                      onBlur={field.handleBlur}
                      aria-invalid={invalid}
                      aria-describedby={describedBy}
                      className={classNames?.input}
                    />
                    <PasswordStrength id={`${formId}-password-strength`} value={field.state.value} minLength={minPasswordLength} showHint={!invalid} className={classNames?.strength} />
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
