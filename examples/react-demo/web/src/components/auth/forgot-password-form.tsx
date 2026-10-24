import { revalidateLogic, useForm } from "@tanstack/react-form"
import { useMutation } from "@tanstack/react-query"
import {
  format,
  useAuth,
  useErrorMessage,
  useLocalization,
  usePluginClient,
  useSafeRedirect,
  type AuthComponentProps,
} from "@ubgo/auth-react"
import { ArrowLeftIcon, CircleAlertIcon, MailIcon } from "lucide-react"
import { useId, useRef, useState } from "react"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// ForgotPasswordForm: step one of a password reset. It asks for the email
// (or username, with the username plugin) and asks the server to mail a
// reset link to the account's verified recovery address. The server answers
// the same whether or not the account exists, so the "check your email" step
// that follows says "if an account exists" and never confirms one.

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

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    forgotPasswordForm: ForgotPasswordFormText
  }
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

/** What was asked for, handed to onSuccess. The server never says whether the account exists. */
export type ForgotPasswordSuccess = {
  readonly identifier: string
}

export type ForgotPasswordFormProps = AuthComponentProps<ForgotPasswordFormSlot, "forgotPasswordForm", ForgotPasswordSuccess> & {
  /**
   * The page the reset link opens, when it is not the server's default
   * (/reset-password on the app's base URL). The server accepts only a page
   * it trusts and answers password.redirect_invalid otherwise.
   */
  readonly resetPageURL?: string
  /** A starting value for the field, such as the address typed on the sign-in page. */
  readonly defaultIdentifier?: string
  /** Show the "Back to sign in" footer. On by default. */
  readonly showSignIn?: boolean
  /** Focus the field on mount, for a page whose only job is this. */
  readonly autoFocus?: boolean
}

/** Error codes that belong under the field rather than above the form. */
const FIELD_ERRORS: ReadonlySet<string> = new Set(["auth.identifier_invalid"])

export function ForgotPasswordForm({
  className,
  classNames,
  localization,
  onSuccess,
  redirectTo: requestedRedirectTo,
  headingLevel = 1,
  resetPageURL,
  defaultIdentifier = "",
  showSignIn = true,
  autoFocus = false,
}: ForgotPasswordFormProps) {
  const t = useLocalization("forgotPasswordForm", FORGOT_PASSWORD_FORM_TEXT, localization)
  const messageFor = useErrorMessage()
  const { navigate, paths, Link } = useAuth()
  // redirectTo usually comes from the address bar: anything but a path on
  // this site (or an origin the provider allows) is dropped, so the default
  // applies and a crafted link cannot send the user to another site.
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const password = usePluginClient("password")
  const username = usePluginClient("username")
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)

  const [formError, setFormError] = useState<string | null>(null)
  const [fieldError, setFieldError] = useState<string | null>(null)
  const [sentTo, setSentTo] = useState<string | null>(null)

  const forgot = useMutation({
    mutationFn: async (identifier: string) => {
      if (password === null) throw new Error("ForgotPasswordForm: password plugin missing")
      return password.forgot({ identifier, ...(resetPageURL === undefined ? {} : { redirectTo: resetPageURL }) })
    },
    onSuccess: ({ error }, identifier) => {
      if (error !== null) {
        if (FIELD_ERRORS.has(error.code)) setFieldError(messageFor(error))
        else setFormError(messageFor(error))
        return
      }
      if (onSuccess !== undefined) onSuccess({ identifier })
      else if (redirectTo !== undefined) navigate(redirectTo)
      else setSentTo(identifier)
    },
  })

  const form = useForm({
    defaultValues: { identifier: defaultIdentifier },
    // Check on submit, then re-check each field as it is edited: an error
    // stays until it is fixed, and never appears while a field is first typed.
    validationLogic: revalidateLogic(),
    onSubmit: async ({ value }) => {
      setFormError(null)
      setFieldError(null)
      await forgot.mutateAsync(value.identifier.trim())
    },
    onSubmitInvalid: () => {
      formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
    },
  })

  // Without the password plugin there is no password to reset.
  if (password === null) return null

  const backLink = showSignIn && (
    <CardFooter className={cn("justify-center text-[13px]", classNames?.footer)}>
      <Link
        href={paths.signIn}
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
            {format(t.sentDescription, { identifier: sentTo })}
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
            disabled={forgot.isPending}
            aria-busy={forgot.isPending}
            onClick={() => {
              setFormError(null)
              forgot.mutate(sentTo)
            }}
          >
            {forgot.isPending && <Spinner data-icon="inline-start" />}
            {forgot.isPending ? t.submitting : t.sendAgain}
          </Button>
          <Button
            type="button"
            variant="ghost"
            className={cn("w-full text-muted-foreground", classNames?.secondary)}
            onClick={() => {
              setSentTo(null)
              setFormError(null)
              forgot.reset()
            }}
          >
            {t.useDifferentEmail}
          </Button>
        </CardContent>
        {backLink}
      </Card>
    )
  }

  const busy = forgot.isPending

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
                const message = field.state.meta.errors[0] ?? fieldError ?? undefined
                const invalid = message !== undefined
                return (
                  <Field data-invalid={invalid} className={classNames?.field}>
                    <FieldLabel htmlFor={`${formId}-identifier`} className={classNames?.label}>
                      {username === null ? t.identifierLabel : t.identifierLabelWithUsername}
                    </FieldLabel>
                    <Input
                      id={`${formId}-identifier`}
                      name="identifier"
                      type={username === null ? "email" : "text"}
                      inputMode={username === null ? "email" : "text"}
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
