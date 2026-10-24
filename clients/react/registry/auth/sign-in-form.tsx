import { revalidateLogic, useForm } from "@tanstack/react-form"
import { useMutation } from "@tanstack/react-query"
import type { AuthError } from "@ubgo/auth-client"
import {
  format,
  getPasskeyCredential,
  oauthStartURL,
  supportsPasskeys,
  useAuth,
  useErrorMessage,
  useLocalization,
  useOAuthProviders,
  usePasskeyAutofill,
  usePluginClient,
  useSafeRedirect,
  useSessionActions,
  type AuthComponentProps,
  type PasskeyFailure,
} from "@ubgo/auth-react"
import { CircleAlertIcon, KeyRoundIcon, MailIcon } from "lucide-react"
import { useId, useRef, useState, type ReactNode } from "react"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldError, FieldGroup, FieldLabel, FieldSeparator } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// SignInForm: every sign-in method the client has, in one card. Password and
// magic link share the identifier field; OAuth providers come from the
// server's list; the passkey button shows when the plugin is on and the
// browser can run the ceremony, and the same passkeys are offered in the
// identifier field's autofill (conditional mediation) where the browser
// supports it. A sign-in that needs a second factor hands
// off to onSecondFactor (or paths.twoFactor) instead of finishing.

/** Every string SignInForm shows, with `{name}` placeholders where a value is filled in. */
export type SignInFormText = {
  title: string
  description: string
  identifierLabel: string
  /** The label when the username plugin is on, so either can be typed. */
  identifierLabelWithUsername: string
  identifierPlaceholder: string
  identifierRequired: string
  passwordLabel: string
  passwordRequired: string
  forgotPassword: string
  submit: string
  submitting: string
  magicLinkSubmit: string
  magicLinkSubmitting: string
  useMagicLink: string
  usePassword: string
  magicLinkSentTitle: string
  /** `{identifier}` is the address the link went to. */
  magicLinkSentDescription: string
  useDifferentEmail: string
  /** `{provider}` is the provider's display name. */
  continueWith: string
  passkey: string
  passkeyPending: string
  passkeyCancelled: string
  passkeyUnsupported: string
  separator: string
  noAccount: string
  signUp: string
}

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    signInForm: SignInFormText
  }
}

/** The English defaults. Override per app (AuthProvider localization.signInForm) or per use (localization prop). */
export const SIGN_IN_FORM_TEXT: SignInFormText = {
  title: "Sign in",
  description: "Welcome back. Sign in to continue.",
  identifierLabel: "Email",
  identifierLabelWithUsername: "Email or username",
  identifierPlaceholder: "you@example.com",
  identifierRequired: "Enter your email.",
  passwordLabel: "Password",
  passwordRequired: "Enter your password.",
  forgotPassword: "Forgot password?",
  submit: "Sign in",
  submitting: "Signing in…",
  magicLinkSubmit: "Email me a sign-in link",
  magicLinkSubmitting: "Sending…",
  useMagicLink: "Email me a link instead",
  usePassword: "Use my password instead",
  magicLinkSentTitle: "Check your email",
  magicLinkSentDescription: "If an account exists for {identifier}, a sign-in link is on its way. It works once.",
  useDifferentEmail: "Use a different email",
  continueWith: "Continue with {provider}",
  passkey: "Sign in with a passkey",
  passkeyPending: "Waiting for your passkey…",
  passkeyCancelled: "No passkey was used. Try again, or sign in another way.",
  passkeyUnsupported: "This browser cannot use passkeys.",
  separator: "or",
  noAccount: "No account yet?",
  signUp: "Sign up",
}

/** The named parts classNames can style. */
export type SignInFormSlot =
  | "root"
  | "header"
  | "title"
  | "description"
  | "content"
  | "methods"
  | "providerButton"
  | "passkeyButton"
  | "separator"
  | "form"
  | "field"
  | "label"
  | "input"
  | "fieldError"
  | "formError"
  | "submit"
  | "toggle"
  | "footer"
  | "link"

/** How the sign-in finished, handed to onSuccess. */
export type SignInSuccess = {
  readonly method: "password" | "passkey"
  readonly userId: string
}

/** The form's two ways of using the identifier field. */
export type SignInMode = "password" | "magiclink"

export type SignInFormProps = AuthComponentProps<SignInFormSlot, "signInForm", SignInSuccess> & {
  /**
   * Called when the account has a second factor: the session is pending and
   * TwoFactorChallenge must finish it. Left out, the form navigates to
   * paths.twoFactor, carrying redirectTo along.
   */
  readonly onSecondFactor?: () => void
  /** Which form shows first when both password and magic link are on. Password by default. */
  readonly defaultMode?: SignInMode
  /** Show the "No account yet? Sign up" footer. On by default. */
  readonly showSignUp?: boolean
  /** Focus the identifier field on mount, for a page whose only job is signing in. */
  readonly autoFocus?: boolean
  /** Icons per provider id, over the built-in GitHub and Google marks; other providers show their initial. */
  readonly providerIcons?: Readonly<Record<string, ReactNode>>
  /**
   * Offer passkeys in the identifier field's autofill (WebAuthn conditional
   * mediation) when the passkey plugin is on and the browser supports it.
   * On by default; picking one signs in like the passkey button.
   */
  readonly passkeyAutofill?: boolean
}

/** Error codes that belong under a field rather than above the form. */
const FIELD_OF_ERROR: Readonly<Partial<Record<string, "identifier" | "password">>> = {
  "auth.identifier_invalid": "identifier",
  "password.too_long": "password",
}

/** Appends `redirectTo` to a path, so the next step can finish where this one was headed. */
function withRedirect(path: string, redirectTo: string | undefined): string {
  if (redirectTo === undefined) return path
  const joiner = path.includes("?") ? "&" : "?"
  return `${path}${joiner}redirectTo=${encodeURIComponent(redirectTo)}`
}

export function SignInForm({
  className,
  classNames,
  localization,
  onSuccess,
  redirectTo: requestedRedirectTo,
  onSecondFactor,
  defaultMode = "password",
  showSignUp = true,
  autoFocus = false,
  providerIcons,
  passkeyAutofill = true,
  headingLevel = 1,
}: SignInFormProps) {
  const t = useLocalization("signInForm", SIGN_IN_FORM_TEXT, localization)
  const messageFor = useErrorMessage()
  const { baseURL, navigate, paths, Link } = useAuth()
  // redirectTo usually comes from the address bar: anything but a path on
  // this site (or an origin the provider allows) is dropped, so the default
  // applies and a crafted link cannot send the user to another site.
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const { refreshSession } = useSessionActions()
  const password = usePluginClient("password")
  const magiclink = usePluginClient("magiclink")
  const passkey = usePluginClient("passkey")
  const username = usePluginClient("username")
  const { providers } = useOAuthProviders()
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)

  // The default mode, unless its plugin is off and the other one is on.
  const [mode, setMode] = useState<SignInMode>(password === null ? "magiclink" : magiclink === null ? "password" : defaultMode)
  const [formError, setFormError] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<"identifier" | "password", string>>>({})
  const [sentTo, setSentTo] = useState<string | null>(null)

  const target = redirectTo ?? paths.afterSignIn
  const canPasskey = passkey !== null && supportsPasskeys()
  const hasForm = password !== null || magiclink !== null

  /** Shows a failed call: under its field when the code names one, above the form otherwise. */
  function showError(error: AuthError) {
    const field = FIELD_OF_ERROR[error.code]
    if (field === undefined) {
      setFormError(messageFor(error))
    } else {
      setFieldErrors({ [field]: messageFor(error) })
    }
  }

  /** The end of every successful sign-in: refresh the session, then hand off or move on. */
  async function finish(method: SignInSuccess["method"], userId: string, secondFactorRequired: boolean) {
    await refreshSession()
    if (secondFactorRequired) {
      if (onSecondFactor === undefined) navigate(withRedirect(paths.twoFactor, redirectTo))
      else onSecondFactor()
      return
    }
    if (onSuccess === undefined) navigate(target)
    else onSuccess({ method, userId })
  }

  // Passkeys in the identifier field's autofill. Every other way in pauses it
  // first (a browser runs one credential request at a time, so the passkey
  // dialog would fail) and resumes it when that way failed.
  const autofill = usePasskeyAutofill({
    enabled: passkeyAutofill && canPasskey && hasForm && sentTo === null,
    onSignedIn: (result) => finish("passkey", result.user.id, result.secondFactorRequired ?? false),
    onError: showError,
  })

  const passwordSignIn = useMutation({
    mutationFn: async (value: { identifier: string; password: string }) => {
      if (password === null) throw new Error("SignInForm: password plugin missing")
      return password.signIn({ identifier: value.identifier.trim(), password: value.password })
    },
    onSuccess: async ({ data, error }) => {
      if (error !== null) {
        showError(error)
        autofill.resume()
        return
      }
      await finish("password", data.user.id, data.secondFactorRequired)
    },
  })

  const magicLinkSend = useMutation({
    mutationFn: async (identifier: string) => {
      if (magiclink === null) throw new Error("SignInForm: magiclink plugin missing")
      return magiclink.send({ identifier: identifier.trim() })
    },
    onSuccess: ({ error }, identifier) => {
      if (error !== null) {
        showError(error)
        autofill.resume()
        return
      }
      setSentTo(identifier.trim())
    },
  })

  const passkeySignIn = useMutation({
    mutationFn: async (): Promise<{ failure: PasskeyFailure | null; error: AuthError | null; userId: string; secondFactor: boolean }> => {
      if (passkey === null) throw new Error("SignInForm: passkey plugin missing")
      const begin = await passkey.loginBegin()
      if (begin.error !== null) return { failure: null, error: begin.error, userId: "", secondFactor: false }
      const ceremony = await getPasskeyCredential(begin.data.options)
      if (ceremony.credential === null) return { failure: ceremony.failure, error: null, userId: "", secondFactor: false }
      const done = await passkey.loginFinish({ ceremony: begin.data.ceremony, credential: ceremony.credential })
      if (done.error !== null) return { failure: null, error: done.error, userId: "", secondFactor: false }
      return { failure: null, error: null, userId: done.data.user.id, secondFactor: done.data.secondFactorRequired ?? false }
    },
    onSuccess: async (outcome) => {
      if (outcome.error === null && outcome.failure === null) {
        await finish("passkey", outcome.userId, outcome.secondFactor)
        return
      }
      if (outcome.error !== null) showError(outcome.error)
      else if (outcome.failure === "unsupported") setFormError(t.passkeyUnsupported)
      else setFormError(t.passkeyCancelled)
      autofill.resume()
    },
  })

  const autofillFinishing = autofill.status === "finishing"
  const busy = passwordSignIn.isPending || magicLinkSend.isPending || passkeySignIn.isPending || autofillFinishing

  const form = useForm({
    defaultValues: { identifier: "", password: "" },
    // Check on submit, then re-check each field as it is edited. Plain
    // onSubmit validators lose a field's error when focus leaves it, so an
    // empty field stopped saying so after a Tab.
    validationLogic: revalidateLogic(),
    onSubmit: async ({ value }) => {
      setFormError(null)
      setFieldErrors({})
      autofill.pause()
      if (mode === "password") await passwordSignIn.mutateAsync(value)
      else await magicLinkSend.mutateAsync(value.identifier)
    },
    onSubmitInvalid: () => {
      // Move focus to the first field that failed, so a keyboard or screen
      // reader user lands on the message instead of the submit button.
      formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
    },
  })

  function switchMode(next: SignInMode) {
    setMode(next)
    setFormError(null)
    setFieldErrors({})
  }

  if (sentTo !== null) {
    return (
      <Card className={cn("w-full max-w-sm", className, classNames?.root)}>
        <CardHeader className={classNames?.header}>
          <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
            <MailIcon aria-hidden className="size-4 text-muted-foreground" />
            {t.magicLinkSentTitle}
          </CardTitle>
          <CardDescription className={classNames?.description} role="status">
            {format(t.magicLinkSentDescription, { identifier: sentTo })}
          </CardDescription>
        </CardHeader>
        <CardContent className={classNames?.content}>
          <Button
            type="button"
            variant="outline"
            className={cn("w-full", classNames?.toggle)}
            onClick={() => {
              setSentTo(null)
              magicLinkSend.reset()
              autofill.resume()
            }}
          >
            {t.useDifferentEmail}
          </Button>
        </CardContent>
      </Card>
    )
  }

  const identifierLabel = username === null ? t.identifierLabel : t.identifierLabelWithUsername
  const hasAlternatives = providers.length > 0 || canPasskey

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

        {hasAlternatives && (
          <div className={cn("flex flex-col gap-2", classNames?.methods)}>
            {providers.map((p) => (
              <Button
                key={p.id}
                type="button"
                variant="outline"
                className={cn("w-full", classNames?.providerButton)}
                disabled={busy}
                onClick={() => {
                  autofill.pause()
                  window.location.assign(oauthStartURL(baseURL, p.id, { returnTo: target }))
                }}
              >
                <ProviderIcon id={p.id} name={p.name} icons={providerIcons} />
                {format(t.continueWith, { provider: p.name })}
              </Button>
            ))}
            {canPasskey && (
              <Button
                type="button"
                variant="outline"
                className={cn("w-full", classNames?.passkeyButton)}
                disabled={busy}
                aria-busy={passkeySignIn.isPending || autofillFinishing}
                onClick={() => {
                  setFormError(null)
                  autofill.pause()
                  passkeySignIn.mutate()
                }}
              >
                {passkeySignIn.isPending || autofillFinishing ? (
                  <Spinner data-icon="inline-start" />
                ) : (
                  <KeyRoundIcon data-icon="inline-start" aria-hidden />
                )}
                {passkeySignIn.isPending || autofillFinishing ? t.passkeyPending : t.passkey}
              </Button>
            )}
          </div>
        )}

        {hasAlternatives && hasForm && (
          // The label sits on the card, so its knock-out background is the card's, not the page's.
          <FieldSeparator className={cn("*:data-[slot=field-separator-content]:bg-card", classNames?.separator)}>{t.separator}</FieldSeparator>
        )}

        {hasForm && (
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
              <form.Field
                name="identifier"
                validators={{ onDynamic: ({ value }) => (value.trim() === "" ? t.identifierRequired : undefined) }}
              >
                {(field) => {
                  const message = field.state.meta.errors[0] ?? fieldErrors.identifier
                  const invalid = message !== undefined
                  return (
                    <Field data-invalid={invalid} className={classNames?.field}>
                      <FieldLabel htmlFor={`${formId}-identifier`} className={classNames?.label}>
                        {identifierLabel}
                      </FieldLabel>
                      <Input
                        id={`${formId}-identifier`}
                        name="identifier"
                        type={username === null ? "email" : "text"}
                        inputMode={username === null ? "email" : "text"}
                        autoComplete={canPasskey && passkeyAutofill ? "username webauthn" : "username"}
                        autoCapitalize="none"
                        spellCheck={false}
                        autoFocus={autoFocus}
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

              {mode === "password" && (
                <form.Field
                  name="password"
                  validators={{ onDynamic: ({ value }) => (value === "" ? t.passwordRequired : undefined) }}
                >
                  {(field) => {
                    const message = field.state.meta.errors[0] ?? fieldErrors.password
                    const invalid = message !== undefined
                    return (
                      <Field data-invalid={invalid} className={classNames?.field}>
                        <div className="flex items-center justify-between gap-2">
                          <FieldLabel htmlFor={`${formId}-password`} className={classNames?.label}>
                            {t.passwordLabel}
                          </FieldLabel>
                          <Link
                            href={paths.forgotPassword}
                            className={cn(
                              "text-xs text-muted-foreground underline-offset-4 hover:text-foreground hover:underline focus-visible:underline focus-visible:outline-none",
                              classNames?.link,
                            )}
                          >
                            {t.forgotPassword}
                          </Link>
                        </div>
                        <Input
                          id={`${formId}-password`}
                          name="password"
                          type="password"
                          autoComplete="current-password"
                          value={field.state.value}
                          onChange={(e) => field.handleChange(e.target.value)}
                          onBlur={field.handleBlur}
                          aria-invalid={invalid}
                          aria-describedby={invalid ? `${formId}-password-error` : undefined}
                          className={classNames?.input}
                        />
                        {invalid && (
                          <FieldError id={`${formId}-password-error`} className={classNames?.fieldError}>
                            {message}
                          </FieldError>
                        )}
                      </Field>
                    )
                  }}
                </form.Field>
              )}

              <Button type="submit" size="lg" className={cn("w-full", classNames?.submit)} disabled={busy} aria-busy={busy}>
                {(passwordSignIn.isPending || magicLinkSend.isPending) && <Spinner data-icon="inline-start" />}
                {mode === "password"
                  ? passwordSignIn.isPending
                    ? t.submitting
                    : t.submit
                  : magicLinkSend.isPending
                    ? t.magicLinkSubmitting
                    : t.magicLinkSubmit}
              </Button>

              {password !== null && magiclink !== null && (
                <Button
                  type="button"
                  variant="ghost"
                  className={cn("w-full text-muted-foreground", classNames?.toggle)}
                  disabled={busy}
                  onClick={() => switchMode(mode === "password" ? "magiclink" : "password")}
                >
                  {mode === "password" ? t.useMagicLink : t.usePassword}
                </Button>
              )}
            </FieldGroup>
          </form>
        )}
      </CardContent>
      {showSignUp && (
        <CardFooter className={cn("justify-center gap-1 text-[13px] text-muted-foreground", classNames?.footer)}>
          {t.noAccount}
          <Link
            href={withRedirect(paths.signUp, redirectTo)}
            className={cn("font-medium text-foreground underline-offset-4 hover:underline focus-visible:underline focus-visible:outline-none", classNames?.link)}
          >
            {t.signUp}
          </Link>
        </CardFooter>
      )}
    </Card>
  )
}

/** The mark on a provider's button: the app's icon, a built-in brand mark, or the name's initial. */
function ProviderIcon({ id, name, icons }: { id: string; name: string; icons: Readonly<Record<string, ReactNode>> | undefined }) {
  const custom = icons?.[id]
  if (custom !== undefined) return <>{custom}</>
  const builtin = BRAND_MARKS[id]
  if (builtin !== undefined) return builtin
  return (
    <span aria-hidden data-icon="inline-start" className="flex size-3.5 items-center justify-center rounded-sm bg-muted text-[10px] font-semibold uppercase">
      {name.slice(0, 1)}
    </span>
  )
}

/**
 * Monochrome brand marks for the common providers. currentColor keeps them
 * legible in light and dark; brand guidelines allow the single-colour mark.
 */
const BRAND_MARKS: Readonly<Record<string, ReactNode>> = {
  github: (
    <svg aria-hidden data-icon="inline-start" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 .5a11.5 11.5 0 0 0-3.64 22.41c.58.1.79-.25.79-.56v-2c-3.2.7-3.88-1.36-3.88-1.36-.52-1.33-1.28-1.69-1.28-1.69-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.19 1.76 1.19 1.03 1.76 2.69 1.25 3.35.96.1-.75.4-1.25.73-1.54-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.19-3.09-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.17 1.18a11 11 0 0 1 5.77 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.8 1.19 1.83 1.19 3.09 0 4.42-2.69 5.39-5.26 5.68.41.36.78 1.06.78 2.14v3.17c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .5Z" />
    </svg>
  ),
  google: (
    <svg aria-hidden data-icon="inline-start" viewBox="0 0 24 24" fill="currentColor">
      <path d="M21.35 11.1H12v2.98h5.35c-.23 1.45-1.66 4.26-5.35 4.26-3.22 0-5.85-2.67-5.85-5.96S8.78 6.42 12 6.42c1.83 0 3.06.78 3.76 1.45l2.57-2.47C16.68 3.86 14.56 2.9 12 2.9 6.98 2.9 2.9 6.98 2.9 12s4.08 9.1 9.1 9.1c5.25 0 8.74-3.69 8.74-8.89 0-.6-.07-1.05-.15-1.51Z" />
    </svg>
  ),
}
