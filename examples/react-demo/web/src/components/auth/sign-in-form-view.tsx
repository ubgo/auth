import { revalidateLogic, useForm } from "@tanstack/react-form"
import { CircleAlertIcon, KeyRoundIcon, MailIcon } from "lucide-react"
import { useId, useRef, useState, type ReactNode } from "react"

import { AnchorLink, fillText, type ViewHeadingLevel, type ViewLinkComponent } from "@/components/auth/auth-view"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldError, FieldGroup, FieldLabel, FieldSeparator } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// SignInFormView: the sign-in card with no data layer. It renders the
// methods it is told are on, validates its own fields, and hands every
// action to a callback: onSubmit with the typed values, onPasskey,
// onProvider. Which call runs, what failed and whether a magic link went out
// come back in as props. SignInForm (sign-in-form.tsx) is this view wired to
// @ubgo/auth-react; render the view yourself to put the same card on any
// other backend.

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

/** The form's two ways of using the identifier field. */
export type SignInMode = "password" | "magiclink"

/** The fields that can carry their own error message. */
export type SignInField = "identifier" | "password"

/** What the form hands onSubmit: the mode it was in, the identifier trimmed, and the password (empty in magic-link mode). */
export type SignInFormValues = {
  readonly mode: SignInMode
  readonly identifier: string
  readonly password: string
}

/** Which action is running, so the view can show its spinner and disable the rest; null when nothing is. */
export type SignInPending = SignInMode | "passkey" | null

/** An OAuth provider to offer as a button: its id (handed to onProvider) and its display name. */
export type SignInProvider = { readonly id: string; readonly name: string }

/** The sign-in methods to show. A method left false (or out) is not rendered. */
export type SignInMethods = {
  readonly password?: boolean
  readonly magicLink?: boolean
  readonly passkey?: boolean
}

export type SignInFormViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<SignInFormSlot, string>>
  /** Text overrides, merged over SIGN_IN_FORM_TEXT. */
  readonly text?: Partial<SignInFormText>
  /** The level of the title, 1 by default. */
  readonly headingLevel?: ViewHeadingLevel
  /** Which methods to render. Password only when left out. */
  readonly methods?: SignInMethods
  /** The identifier also accepts a username: the label says so and the input is a text field, not an email one. */
  readonly acceptsUsername?: boolean
  /** OAuth providers, one button each. */
  readonly providers?: readonly SignInProvider[]
  /** Icons per provider id, over the built-in GitHub and Google marks; other providers show their initial. */
  readonly providerIcons?: Readonly<Record<string, ReactNode>>
  /** Which form shows first when both password and magic link are on. Password by default. */
  readonly defaultMode?: SignInMode
  /** The running action; every button is disabled while it is not null. */
  readonly pending?: SignInPending
  /** A message above the form, such as a wrong password. */
  readonly formError?: string | null
  /** Messages under a field, by field. */
  readonly fieldErrors?: Partial<Record<SignInField, string>>
  /** Set once a magic link went out: the card says where it went instead of showing the form. */
  readonly sentTo?: string | null
  /** Mark the identifier field for passkey autofill (`autocomplete="username webauthn"`). */
  readonly passkeyAutofill?: boolean
  /** Focus the identifier field on mount. */
  readonly autoFocus?: boolean
  /** The "Forgot password?" link; hidden when left out. */
  readonly forgotPasswordHref?: string
  /** The "No account yet? Sign up" footer link; the footer is hidden when left out. */
  readonly signUpHref?: string
  /** The link component, a plain anchor by default. */
  readonly Link?: ViewLinkComponent
  /** The form passed its own checks. Awaited, so a slow call keeps the form submitting. */
  readonly onSubmit?: (values: SignInFormValues) => void | Promise<void>
  /** The passkey button was pressed. */
  readonly onPasskey?: () => void
  /** A provider's button was pressed. */
  readonly onProvider?: (providerId: string) => void
  /** The person switched between password and magic link; a good moment to clear errors. */
  readonly onModeChange?: (mode: SignInMode) => void
  /** "Use a different email" on the link-sent card. */
  readonly onUseDifferentEmail?: () => void
}

export function SignInFormView({
  className,
  classNames,
  text,
  headingLevel = 1,
  methods = { password: true },
  acceptsUsername = false,
  providers = [],
  providerIcons,
  defaultMode = "password",
  pending = null,
  formError = null,
  fieldErrors = {},
  sentTo = null,
  passkeyAutofill = false,
  autoFocus = false,
  forgotPasswordHref,
  signUpHref,
  Link = AnchorLink,
  onSubmit,
  onPasskey,
  onProvider,
  onModeChange,
  onUseDifferentEmail,
}: SignInFormViewProps) {
  const t: SignInFormText = { ...SIGN_IN_FORM_TEXT, ...text }
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)
  const hasPassword = methods.password === true
  const hasMagicLink = methods.magicLink === true
  const canPasskey = methods.passkey === true
  const hasForm = hasPassword || hasMagicLink

  // The default mode, unless its method is off and the other one is on.
  const [mode, setMode] = useState<SignInMode>(!hasPassword ? "magiclink" : !hasMagicLink ? "password" : defaultMode)
  const busy = pending !== null

  const form = useForm({
    defaultValues: { identifier: "", password: "" },
    // Check on submit, then re-check each field as it is edited. Plain
    // onSubmit validators lose a field's error when focus leaves it, so an
    // empty field stopped saying so after a Tab.
    validationLogic: revalidateLogic(),
    onSubmit: async ({ value }) => {
      await onSubmit?.({ mode, identifier: value.identifier.trim(), password: mode === "password" ? value.password : "" })
    },
    onSubmitInvalid: () => {
      // Move focus to the first field that failed, so a keyboard or screen
      // reader user lands on the message instead of the submit button.
      formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
    },
  })

  function switchMode(next: SignInMode) {
    setMode(next)
    onModeChange?.(next)
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
            {fillText(t.magicLinkSentDescription, { identifier: sentTo })}
          </CardDescription>
        </CardHeader>
        <CardContent className={classNames?.content}>
          <Button type="button" variant="outline" className={cn("w-full", classNames?.toggle)} onClick={() => onUseDifferentEmail?.()}>
            {t.useDifferentEmail}
          </Button>
        </CardContent>
      </Card>
    )
  }

  const identifierLabel = acceptsUsername ? t.identifierLabelWithUsername : t.identifierLabel
  const hasAlternatives = providers.length > 0 || canPasskey
  const passkeyBusy = pending === "passkey"

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
                onClick={() => onProvider?.(p.id)}
              >
                <ProviderIcon id={p.id} name={p.name} icons={providerIcons} />
                {fillText(t.continueWith, { provider: p.name })}
              </Button>
            ))}
            {canPasskey && (
              <Button
                type="button"
                variant="outline"
                className={cn("w-full", classNames?.passkeyButton)}
                disabled={busy}
                aria-busy={passkeyBusy}
                onClick={() => onPasskey?.()}
              >
                {passkeyBusy ? <Spinner data-icon="inline-start" /> : <KeyRoundIcon data-icon="inline-start" aria-hidden />}
                {passkeyBusy ? t.passkeyPending : t.passkey}
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
                        type={acceptsUsername ? "text" : "email"}
                        inputMode={acceptsUsername ? "text" : "email"}
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
                          {forgotPasswordHref !== undefined && (
                            <Link
                              href={forgotPasswordHref}
                              className={cn(
                                "text-xs text-muted-foreground underline-offset-4 hover:text-foreground hover:underline focus-visible:underline focus-visible:outline-none",
                                classNames?.link,
                              )}
                            >
                              {t.forgotPassword}
                            </Link>
                          )}
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
                {(pending === "password" || pending === "magiclink") && <Spinner data-icon="inline-start" />}
                {mode === "password"
                  ? pending === "password"
                    ? t.submitting
                    : t.submit
                  : pending === "magiclink"
                    ? t.magicLinkSubmitting
                    : t.magicLinkSubmit}
              </Button>

              {hasPassword && hasMagicLink && (
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
      {signUpHref !== undefined && (
        <CardFooter className={cn("justify-center gap-1 text-[13px] text-muted-foreground", classNames?.footer)}>
          {t.noAccount}
          <Link
            href={signUpHref}
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
