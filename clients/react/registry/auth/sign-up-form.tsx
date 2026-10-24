import { revalidateLogic, useForm } from "@tanstack/react-form"
import { useMutation } from "@tanstack/react-query"
import type { AuthError } from "@ubgo/auth-client"
import {
  format,
  oauthStartURL,
  useAuth,
  useErrorMessage,
  useLocalization,
  useOAuthProviders,
  usePluginClient,
  useSafeRedirect,
  useSessionActions,
  type AuthComponentProps,
} from "@ubgo/auth-react"
import { CircleAlertIcon, MailCheckIcon } from "lucide-react"
import { Fragment, useId, useRef, useState, type ReactNode } from "react"

import { PasswordStrength, DEFAULT_PASSWORD_MIN_LENGTH } from "@/components/auth/password-strength"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Field, FieldError, FieldGroup, FieldLabel, FieldSeparator } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// SignUpForm: creates an account with a password, in one card. The fields
// follow the client's plugins: the identifier is an email, a phone number or
// either (email, phone), a username field appears with the username plugin,
// and OAuth providers from the server's list sit above the form. A terms
// checkbox appears when the app passes `terms`, and its version is sent as
// the Terms-Version header the terms plugin records at sign-up. When the
// server wants the address verified first, the card turns into a "check your
// email" step with a resend button (or hands off to onVerificationRequired).
//
// Sign-up never says whether an address already has an account: the server
// answers the same and mails the owner instead, so this form has no
// "already taken" message for an email to show.

/** Every string SignUpForm shows, with `{name}` placeholders where a value is filled in. */
export type SignUpFormText = {
  title: string
  description: string
  nameLabel: string
  namePlaceholder: string
  nameRequired: string
  /** Shown beside the name label when nameField is "optional". */
  optional: string
  /** The identifier label for each mix of identifier plugins. */
  emailLabel: string
  phoneLabel: string
  emailOrPhoneLabel: string
  emailPlaceholder: string
  phonePlaceholder: string
  emailOrPhonePlaceholder: string
  identifierRequired: string
  /** A quick shape check before the call; the server has the last word. */
  emailInvalid: string
  usernameLabel: string
  usernamePlaceholder: string
  usernameRequired: string
  passwordLabel: string
  passwordRequired: string
  /** `{min}` is the shortest length the form asks for. */
  passwordTooShort: string
  /** `{terms}` and `{privacy}` become the two links. */
  termsLabel: string
  /** Used when there is no privacy link. `{terms}` becomes the link. */
  termsLabelNoPrivacy: string
  termsLink: string
  privacyLink: string
  termsRequired: string
  submit: string
  submitting: string
  /** `{provider}` is the provider's display name. */
  continueWith: string
  separator: string
  verifyTitle: string
  /** `{identifier}` is the address the link went to. */
  verifyDescription: string
  resend: string
  resending: string
  resent: string
  useDifferentEmail: string
  haveAccount: string
  signIn: string
}

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    signUpForm: SignUpFormText
  }
}

/** The English defaults. Override per app (AuthProvider localization.signUpForm) or per use (localization prop). */
export const SIGN_UP_FORM_TEXT: SignUpFormText = {
  title: "Create your account",
  description: "Welcome. Fill in the details to get started.",
  nameLabel: "Name",
  namePlaceholder: "Ada Lovelace",
  nameRequired: "Enter your name.",
  optional: "Optional",
  emailLabel: "Email",
  phoneLabel: "Phone number",
  emailOrPhoneLabel: "Email or phone number",
  emailPlaceholder: "you@example.com",
  phonePlaceholder: "+1 555 010 0000",
  emailOrPhonePlaceholder: "you@example.com",
  identifierRequired: "Enter your email.",
  emailInvalid: "Enter an email address like you@example.com.",
  usernameLabel: "Username",
  usernamePlaceholder: "ada",
  usernameRequired: "Choose a username.",
  passwordLabel: "Password",
  passwordRequired: "Choose a password.",
  passwordTooShort: "Use {min} or more characters.",
  termsLabel: "I agree to the {terms} and the {privacy}.",
  termsLabelNoPrivacy: "I agree to the {terms}.",
  termsLink: "Terms of Service",
  privacyLink: "Privacy Policy",
  termsRequired: "Accept the terms to create an account.",
  submit: "Create account",
  submitting: "Creating account…",
  continueWith: "Continue with {provider}",
  separator: "or",
  verifyTitle: "Check your email",
  verifyDescription: "We sent a link to {identifier}. Open it to verify your address and finish signing up.",
  resend: "Send the link again",
  resending: "Sending…",
  resent: "Sent. It can take a minute to arrive; check your spam folder too.",
  useDifferentEmail: "Use a different email",
  haveAccount: "Already have an account?",
  signIn: "Sign in",
}

/** The named parts classNames can style. */
export type SignUpFormSlot =
  | "root"
  | "header"
  | "title"
  | "description"
  | "content"
  | "methods"
  | "providerButton"
  | "separator"
  | "form"
  | "field"
  | "label"
  | "input"
  | "fieldError"
  | "formError"
  | "strength"
  | "terms"
  | "checkbox"
  | "submit"
  | "resend"
  | "footer"
  | "link"

/** How the sign-up finished, handed to onSuccess (a session exists) or onVerificationRequired (it does not yet). */
export type SignUpSuccess = {
  readonly userId: string
  /** The identifier as typed (trimmed), for a "check your inbox" screen of the app's own. */
  readonly identifier: string
}

/** The legal links and the version the terms plugin records. */
export type SignUpTerms = {
  /** The version in force, exactly as the server's terms.Current; sent as the Terms-Version header. */
  readonly version: string
  /** The terms page. */
  readonly href: string
  /** The privacy page, linked beside the terms when set. */
  readonly privacyHref?: string
}

/** Whether the name field shows, and whether it must be filled. */
export type SignUpNameField = "required" | "optional" | "hidden"

export type SignUpFormProps = AuthComponentProps<SignUpFormSlot, "signUpForm", SignUpSuccess> & {
  /**
   * Called when the account exists but its address must be verified before
   * the first sign-in; no session was issued. Left out, the card shows a
   * "check your email" step with a resend button.
   */
  readonly onVerificationRequired?: (result: SignUpSuccess) => void
  /** Called when the new session needs a second factor. Left out, the form navigates to paths.twoFactor. */
  readonly onSecondFactor?: () => void
  /** The name field: required (default), optional, or hidden (the account is created with an empty name). */
  readonly nameField?: SignUpNameField
  /**
   * Shows a required "I agree" checkbox and sends `version` with the
   * sign-up. Pass it when the server has the terms plugin; the version must
   * match terms.Current, or the server ignores it.
   */
  readonly terms?: SignUpTerms
  /** The shortest password the strength hint and the check before submit ask for; match the server's password.MinLength. */
  readonly minPasswordLength?: number
  /** Show the "Already have an account? Sign in" footer. On by default. */
  readonly showSignIn?: boolean
  /** Focus the first field on mount, for a page whose only job is signing up. */
  readonly autoFocus?: boolean
  /** Icons per provider id, over the built-in GitHub and Google marks; other providers show their initial. */
  readonly providerIcons?: Readonly<Record<string, ReactNode>>
}

/** The text fields of the form. */
type SignUpField = "name" | "identifier" | "username" | "password"

/** The Terms-Version header the terms plugin reads at sign-up (terms.TermsHeader). */
const TERMS_HEADER = "Terms-Version"

/** A loose shape check: something, an @, something, a dot, something. The server validates for real. */
const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

/** Error codes that belong under one field rather than above the form. auth.identity_taken is resolved in code (see fieldOf). */
const FIELD_OF_ERROR: Readonly<Partial<Record<string, SignUpField>>> = {
  "auth.identifier_invalid": "identifier",
  "email.address_rejected": "identifier",
  "password.too_short": "password",
  "password.too_long": "password",
  "password.weak": "password",
  "password.breached": "password",
  "username.reserved": "username",
}

/** Appends `redirectTo` to a path, so the next step can finish where this one was headed. */
function withRedirect(path: string, redirectTo: string | undefined): string {
  if (redirectTo === undefined) return path
  const joiner = path.includes("?") ? "&" : "?"
  return `${path}${joiner}redirectTo=${encodeURIComponent(redirectTo)}`
}

/**
 * Fills `{name}` placeholders with React nodes, so a translated sentence can
 * put its links in its own word order: "I agree to the {terms}".
 */
function formatNodes(text: string, nodes: Readonly<Record<string, ReactNode>>): ReactNode[] {
  return text.split(/(\{\w+\})/).map((part, i) => {
    const name = /^\{(\w+)\}$/.exec(part)?.[1]
    const node = name === undefined ? undefined : nodes[name]
    return <Fragment key={i}>{node === undefined ? part : node}</Fragment>
  })
}

export function SignUpForm({
  className,
  classNames,
  localization,
  onSuccess,
  redirectTo: requestedRedirectTo,
  headingLevel = 1,
  onVerificationRequired,
  onSecondFactor,
  nameField = "required",
  terms,
  minPasswordLength = DEFAULT_PASSWORD_MIN_LENGTH,
  showSignIn = true,
  autoFocus = false,
  providerIcons,
}: SignUpFormProps) {
  const t = useLocalization("signUpForm", SIGN_UP_FORM_TEXT, localization)
  const messageFor = useErrorMessage()
  const { baseURL, navigate, paths, Link } = useAuth()
  // redirectTo usually comes from the address bar: anything but a path on
  // this site (or an origin the provider allows) is dropped, so the default
  // applies and a crafted link cannot send the user to another site.
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const { refreshSession } = useSessionActions()
  const password = usePluginClient("password")
  const email = usePluginClient("email")
  const phone = usePluginClient("phone")
  const username = usePluginClient("username")
  const { providers } = useOAuthProviders()
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)

  const [formError, setFormError] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<SignUpField, string>>>({})
  const [pending, setPending] = useState<SignUpSuccess | null>(null)

  const target = redirectTo ?? paths.afterSignIn
  // Phone alone asks for a number; email (or neither, the server's default) asks for an email.
  const identifierKind: "email" | "phone" | "either" = phone === null ? "email" : email === null ? "phone" : "either"
  const identifierLabel = identifierKind === "email" ? t.emailLabel : identifierKind === "phone" ? t.phoneLabel : t.emailOrPhoneLabel
  const identifierPlaceholder =
    identifierKind === "email" ? t.emailPlaceholder : identifierKind === "phone" ? t.phonePlaceholder : t.emailOrPhonePlaceholder

  /** The field a server code belongs under, or undefined for the form-level alert. */
  function fieldOf(error: AuthError): SignUpField | undefined {
    // A taken username is the one "taken" answer sign-up gives: an email or
    // phone that is taken still succeeds, so the answer cannot be about it.
    if (error.code === "auth.identity_taken") return username === null ? undefined : "username"
    return FIELD_OF_ERROR[error.code]
  }

  /** Shows a failed call under its field when the code names one, above the form otherwise, then focuses it. */
  function showError(error: AuthError) {
    const field = fieldOf(error)
    if (field === undefined) {
      setFormError(messageFor(error))
      return
    }
    setFieldErrors({ [field]: messageFor(error) })
    // After the re-render that marks the field invalid, move focus there.
    requestAnimationFrame(() => formRef.current?.querySelector<HTMLElement>(`[name="${field}"]`)?.focus())
  }

  const signUp = useMutation({
    mutationFn: async (value: { name: string; identifier: string; username: string; password: string }) => {
      if (password === null) throw new Error("SignUpForm: password plugin missing")
      return password.signUp(
        {
          identifier: value.identifier.trim(),
          password: value.password,
          name: nameField === "hidden" ? "" : value.name.trim(),
          ...(username === null ? {} : { username: value.username.trim() }),
        },
        terms === undefined ? undefined : { headers: { [TERMS_HEADER]: terms.version } },
      )
    },
    onSuccess: async ({ data, error }, value) => {
      if (error !== null) {
        showError(error)
        return
      }
      const result: SignUpSuccess = { userId: data.user.id, identifier: value.identifier.trim() }
      if (data.verificationRequired) {
        if (onVerificationRequired === undefined) setPending(result)
        else onVerificationRequired(result)
        return
      }
      await refreshSession()
      if (data.secondFactorRequired) {
        if (onSecondFactor === undefined) navigate(withRedirect(paths.twoFactor, redirectTo))
        else onSecondFactor()
        return
      }
      if (onSuccess === undefined) navigate(target)
      else onSuccess(result)
    },
  })

  const resend = useMutation({
    mutationFn: async (address: string) => {
      if (email === null) throw new Error("SignUpForm: email plugin missing")
      return email.resend({ email: address })
    },
    onSuccess: ({ error }) => {
      if (error !== null) setFormError(messageFor(error))
    },
  })

  const form = useForm({
    defaultValues: { name: "", identifier: "", username: "", password: "", terms: false },
    // Check on submit, then re-check each field as it is edited: an error
    // stays until it is fixed, and never appears while a field is first typed.
    validationLogic: revalidateLogic(),
    onSubmit: async ({ value }) => {
      setFormError(null)
      setFieldErrors({})
      await signUp.mutateAsync(value)
    },
    onSubmitInvalid: () => {
      // Move focus to the first field that failed, so a keyboard or screen
      // reader user lands on the message instead of the submit button.
      formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
    },
  })

  // Without the password plugin there is nothing to sign up with; OAuth-only
  // apps sign up through SignInForm's provider buttons.
  if (password === null) return null

  if (pending !== null) {
    const canResend = email !== null && EMAIL_SHAPE.test(pending.identifier)
    return (
      <Card className={cn("w-full max-w-sm", className, classNames?.root)}>
        <CardHeader className={classNames?.header}>
          <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
            <MailCheckIcon aria-hidden className="size-4 text-muted-foreground" />
            {t.verifyTitle}
          </CardTitle>
          <CardDescription className={cn("wrap-anywhere", classNames?.description)} role="status">
            {format(t.verifyDescription, { identifier: pending.identifier })}
          </CardDescription>
        </CardHeader>
        <CardContent className={cn("flex flex-col gap-2", classNames?.content)}>
          {formError !== null && (
            <Alert variant="destructive" className={classNames?.formError}>
              <CircleAlertIcon aria-hidden />
              <AlertDescription>{formError}</AlertDescription>
            </Alert>
          )}
          {resend.isSuccess && resend.data.error === null && (
            <p role="status" className="text-xs text-muted-foreground">
              {t.resent}
            </p>
          )}
          {canResend && (
            <Button
              type="button"
              variant="outline"
              className={cn("w-full", classNames?.resend)}
              disabled={resend.isPending}
              aria-busy={resend.isPending}
              onClick={() => {
                setFormError(null)
                resend.mutate(pending.identifier)
              }}
            >
              {resend.isPending && <Spinner data-icon="inline-start" />}
              {resend.isPending ? t.resending : t.resend}
            </Button>
          )}
          <Button
            type="button"
            variant="ghost"
            className="w-full text-muted-foreground"
            onClick={() => {
              setPending(null)
              setFormError(null)
              resend.reset()
              signUp.reset()
            }}
          >
            {t.useDifferentEmail}
          </Button>
        </CardContent>
      </Card>
    )
  }

  const busy = signUp.isPending

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

        {providers.length > 0 && (
          <>
            <div className={cn("flex flex-col gap-2", classNames?.methods)}>
              {providers.map((p) => (
                <Button
                  key={p.id}
                  type="button"
                  variant="outline"
                  className={cn("w-full", classNames?.providerButton)}
                  disabled={busy}
                  onClick={() => window.location.assign(oauthStartURL(baseURL, p.id, { returnTo: target }))}
                >
                  <ProviderIcon id={p.id} name={p.name} icons={providerIcons} />
                  {format(t.continueWith, { provider: p.name })}
                </Button>
              ))}
            </div>
            {/* The label sits on the card, so its knock-out background is the card's, not the page's. */}
            <FieldSeparator className={cn("*:data-[slot=field-separator-content]:bg-card", classNames?.separator)}>{t.separator}</FieldSeparator>
          </>
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
            {nameField !== "hidden" && (
              <form.Field
                name="name"
                validators={{ onDynamic: ({ value }) => (nameField === "required" && value.trim() === "" ? t.nameRequired : undefined) }}
              >
                {(field) => {
                  const message = field.state.meta.errors[0] ?? fieldErrors.name
                  const invalid = message !== undefined
                  return (
                    <Field data-invalid={invalid} className={classNames?.field}>
                      <FieldLabel htmlFor={`${formId}-name`} className={classNames?.label}>
                        {t.nameLabel}
                        {nameField === "optional" && <span className="font-normal text-muted-foreground">{t.optional}</span>}
                      </FieldLabel>
                      <Input
                        id={`${formId}-name`}
                        name="name"
                        autoComplete="name"
                        autoFocus={autoFocus}
                        required={nameField === "required"}
                        placeholder={t.namePlaceholder}
                        value={field.state.value}
                        onChange={(e) => field.handleChange(e.target.value)}
                        onBlur={field.handleBlur}
                        aria-invalid={invalid}
                        aria-describedby={invalid ? `${formId}-name-error` : undefined}
                        className={classNames?.input}
                      />
                      {invalid && (
                        <FieldError id={`${formId}-name-error`} className={classNames?.fieldError}>
                          {message}
                        </FieldError>
                      )}
                    </Field>
                  )
                }}
              </form.Field>
            )}

            <form.Field
              name="identifier"
              validators={{
                onDynamic: ({ value }) => {
                  const v = value.trim()
                  if (v === "") return t.identifierRequired
                  if (identifierKind === "email" && !EMAIL_SHAPE.test(v)) return t.emailInvalid
                  return undefined
                },
              }}
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
                      type={identifierKind === "email" ? "email" : identifierKind === "phone" ? "tel" : "text"}
                      inputMode={identifierKind === "email" ? "email" : identifierKind === "phone" ? "tel" : "text"}
                      autoComplete={identifierKind === "phone" ? "tel" : "email"}
                      autoCapitalize="none"
                      spellCheck={false}
                      autoFocus={autoFocus && nameField === "hidden"}
                      required
                      placeholder={identifierPlaceholder}
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

            {username !== null && (
              <form.Field name="username" validators={{ onDynamic: ({ value }) => (value.trim() === "" ? t.usernameRequired : undefined) }}>
                {(field) => {
                  const message = field.state.meta.errors[0] ?? fieldErrors.username
                  const invalid = message !== undefined
                  return (
                    <Field data-invalid={invalid} className={classNames?.field}>
                      <FieldLabel htmlFor={`${formId}-username`} className={classNames?.label}>
                        {t.usernameLabel}
                      </FieldLabel>
                      <Input
                        id={`${formId}-username`}
                        name="username"
                        autoComplete="username"
                        autoCapitalize="none"
                        spellCheck={false}
                        required
                        placeholder={t.usernamePlaceholder}
                        value={field.state.value}
                        onChange={(e) => field.handleChange(e.target.value)}
                        onBlur={field.handleBlur}
                        aria-invalid={invalid}
                        aria-describedby={invalid ? `${formId}-username-error` : undefined}
                        className={classNames?.input}
                      />
                      {invalid && (
                        <FieldError id={`${formId}-username-error`} className={classNames?.fieldError}>
                          {message}
                        </FieldError>
                      )}
                    </Field>
                  )
                }}
              </form.Field>
            )}

            <form.Field
              name="password"
              validators={{
                onDynamic: ({ value }) =>
                  value === "" ? t.passwordRequired : [...value].length < minPasswordLength ? format(t.passwordTooShort, { min: minPasswordLength }) : undefined,
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
                      required
                      minLength={minPasswordLength}
                      value={field.state.value}
                      onChange={(e) => {
                        field.handleChange(e.target.value)
                        // A server complaint about the old value is stale once the user edits it.
                        if (fieldErrors.password !== undefined) setFieldErrors((prev) => ({ ...prev, password: undefined }))
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

            {terms !== undefined && (
              <form.Field name="terms" validators={{ onDynamic: ({ value }) => (value ? undefined : t.termsRequired) }}>
                {(field) => {
                  const message = field.state.meta.errors[0]
                  const invalid = message !== undefined
                  const linkClass = cn("font-medium text-foreground underline underline-offset-4 hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50 rounded-sm", classNames?.link)
                  const termsLink = (
                    <a href={terms.href} target="_blank" rel="noreferrer" className={linkClass}>
                      {t.termsLink}
                    </a>
                  )
                  const privacyLink =
                    terms.privacyHref === undefined ? null : (
                      <a href={terms.privacyHref} target="_blank" rel="noreferrer" className={linkClass}>
                        {t.privacyLink}
                      </a>
                    )
                  return (
                    <Field orientation="horizontal" data-invalid={invalid} className={cn("items-start", classNames?.terms)}>
                      <Checkbox
                        id={`${formId}-terms`}
                        name="terms"
                        checked={field.state.value}
                        onCheckedChange={(checked) => field.handleChange(checked === true)}
                        aria-invalid={invalid}
                        aria-describedby={invalid ? `${formId}-terms-error` : undefined}
                        className={cn("mt-px", classNames?.checkbox)}
                      />
                      <div className="flex flex-col gap-1">
                        <FieldLabel htmlFor={`${formId}-terms`} className={cn("block font-normal leading-snug text-muted-foreground", classNames?.label)}>
                          {privacyLink === null
                            ? formatNodes(t.termsLabelNoPrivacy, { terms: termsLink })
                            : formatNodes(t.termsLabel, { terms: termsLink, privacy: privacyLink })}
                        </FieldLabel>
                        {invalid && (
                          <FieldError id={`${formId}-terms-error`} className={classNames?.fieldError}>
                            {message}
                          </FieldError>
                        )}
                      </div>
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
      {showSignIn && (
        <CardFooter className={cn("justify-center gap-1 text-[13px] text-muted-foreground", classNames?.footer)}>
          {t.haveAccount}
          <Link
            href={withRedirect(paths.signIn, redirectTo)}
            className={cn("font-medium text-foreground underline-offset-4 hover:underline focus-visible:underline focus-visible:outline-none", classNames?.link)}
          >
            {t.signIn}
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
 * Monochrome brand marks for the common providers, the same as SignInForm's.
 * currentColor keeps them legible in light and dark; brand guidelines allow
 * the single-colour mark.
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
