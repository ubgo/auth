import { revalidateLogic, useForm } from "@tanstack/react-form"
import { CircleAlertIcon, MailCheckIcon } from "lucide-react"
import { Fragment, useEffect, useId, useRef, type ReactNode } from "react"

import { AnchorLink, fillText, type ViewHeadingLevel, type ViewLinkComponent } from "@/components/auth/auth-view"
import { DEFAULT_PASSWORD_MIN_LENGTH, PasswordStrengthView, type PasswordStrengthText } from "@/components/auth/password-strength-view"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Field, FieldError, FieldGroup, FieldLabel, FieldSeparator } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// SignUpFormView: the sign-up card with no data layer. It renders the fields
// it is told to (name, the identifier kind, username, terms), validates them,
// and hands the typed values to onSubmit. Provider buttons, the "check your
// email" step and its resend button report through callbacks; what is
// running and what failed come back in as props. SignUpForm (sign-up-form.tsx)
// is this view wired to @ubgo/auth-react; render the view yourself to put the
// same card on any other backend.

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

/** Which identifier the form asks for: an email, a phone number, or either. */
export type SignUpIdentifierKind = "email" | "phone" | "either"

/** The text fields of the form, the ones that can carry their own error message. */
export type SignUpField = "name" | "identifier" | "username" | "password"

/**
 * What the form hands onSubmit. Text fields are trimmed except the password;
 * name is empty when the name field is hidden, username when there is none;
 * termsAccepted is true whenever terms were shown, since the form refuses
 * otherwise.
 */
export type SignUpFormValues = {
  readonly name: string
  readonly identifier: string
  readonly username: string
  readonly password: string
  readonly termsAccepted: boolean
}

/** An OAuth provider to offer as a button: its id (handed to onProvider) and its display name. */
export type SignUpProvider = { readonly id: string; readonly name: string }

/** The "check your email" step shown once the account exists but its address must be verified. */
export type SignUpVerifyStep = {
  /** The identifier the link went to. */
  readonly identifier: string
  /** Show the resend button; only an email address can be sent the link again. */
  readonly canResend?: boolean
  /** The resend call is running. */
  readonly resendPending?: boolean
  /** The last resend went out. */
  readonly resent?: boolean
}

/**
 * A loose email shape check: something, an @, something, a dot, something.
 * The server validates for real; the form uses it before submit, and the
 * wired form uses it to decide whether an identifier can be sent the link again.
 */
export const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

/** The props of SignUpFormView: what to render, what is running and failed, and the callbacks. */
export type SignUpFormViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<SignUpFormSlot, string>>
  /** Text overrides, merged over SIGN_UP_FORM_TEXT. */
  readonly text?: Partial<SignUpFormText>
  /** Text overrides for the password strength meter, merged over PASSWORD_STRENGTH_TEXT. */
  readonly strengthText?: Partial<PasswordStrengthText>
  /** The level of the title, 1 by default. */
  readonly headingLevel?: ViewHeadingLevel
  /** The name field: required (default), optional, or hidden. */
  readonly nameField?: SignUpNameField
  /** The identifier the form asks for; email by default. */
  readonly identifierKind?: SignUpIdentifierKind
  /** Show the required username field. */
  readonly hasUsername?: boolean
  /** Show the required "I agree" checkbox with these links. */
  readonly terms?: SignUpTerms
  /** The shortest password the strength hint and the check before submit ask for. */
  readonly minPasswordLength?: number
  /** OAuth providers, one button each above the form. */
  readonly providers?: readonly SignUpProvider[]
  /** Icons per provider id, over the built-in GitHub and Google marks; other providers show their initial. */
  readonly providerIcons?: Readonly<Record<string, ReactNode>>
  /** Focus the first field on mount. */
  readonly autoFocus?: boolean
  /** The sign-up call is running: every button is disabled and the submit shows its running label. */
  readonly pending?: boolean
  /** A message above the form (or the verify step), such as a failed resend. */
  readonly formError?: string | null
  /** Messages under a field, by field. A newly set one moves focus to its field. */
  readonly fieldErrors?: Partial<Record<SignUpField, string>>
  /** Set once the account waits for verification: the card shows the "check your email" step instead of the form. */
  readonly verify?: SignUpVerifyStep | null
  /** The "Already have an account? Sign in" footer link; the footer is hidden when left out. */
  readonly signInHref?: string
  /** The link component, a plain anchor by default. The terms links are always plain anchors in a new tab. */
  readonly Link?: ViewLinkComponent
  /** The form passed its own checks. Awaited, so a slow call keeps the form submitting. */
  readonly onSubmit?: (values: SignUpFormValues) => void | Promise<void>
  /** A provider's button was pressed. */
  readonly onProvider?: (providerId: string) => void
  /** The password was edited while it showed a field error: the server's complaint is stale, a good moment to clear it. */
  readonly onPasswordChange?: () => void
  /** The resend button on the verify step. */
  readonly onResend?: () => void
  /** "Use a different email" on the verify step. */
  readonly onUseDifferentEmail?: () => void
}

/** The fieldErrors default, one object so the focus effect does not fire on every render. */
const NO_FIELD_ERRORS: Partial<Record<SignUpField, string>> = {}

/** The order fields appear in, so focus goes to the first one a new error names. */
const FIELD_ORDER: readonly SignUpField[] = ["name", "identifier", "username", "password"]

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

/** The sign-up card, or its "check your email" step, rendered from props alone. */
export function SignUpFormView({
  className,
  classNames,
  text,
  strengthText,
  headingLevel = 1,
  nameField = "required",
  identifierKind = "email",
  hasUsername = false,
  terms,
  minPasswordLength = DEFAULT_PASSWORD_MIN_LENGTH,
  providers = [],
  providerIcons,
  autoFocus = false,
  pending = false,
  formError = null,
  fieldErrors = NO_FIELD_ERRORS,
  verify = null,
  signInHref,
  Link = AnchorLink,
  onSubmit,
  onProvider,
  onPasswordChange,
  onResend,
  onUseDifferentEmail,
}: SignUpFormViewProps) {
  const t: SignUpFormText = { ...SIGN_UP_FORM_TEXT, ...text }
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)
  const shownErrors = useRef<Partial<Record<SignUpField, string>>>(NO_FIELD_ERRORS)

  const identifierLabel = identifierKind === "email" ? t.emailLabel : identifierKind === "phone" ? t.phoneLabel : t.emailOrPhoneLabel
  const identifierPlaceholder =
    identifierKind === "email" ? t.emailPlaceholder : identifierKind === "phone" ? t.phonePlaceholder : t.emailOrPhonePlaceholder

  // A server error that names a field moves focus to that field, once, when it appears.
  useEffect(() => {
    const previous = shownErrors.current
    shownErrors.current = fieldErrors
    const field = FIELD_ORDER.find((f) => fieldErrors[f] !== undefined && fieldErrors[f] !== previous[f])
    if (field !== undefined) formRef.current?.querySelector<HTMLElement>(`[name="${field}"]`)?.focus()
  }, [fieldErrors])

  const form = useForm({
    defaultValues: { name: "", identifier: "", username: "", password: "", terms: false },
    // Check on submit, then re-check each field as it is edited: an error
    // stays until it is fixed, and never appears while a field is first typed.
    validationLogic: revalidateLogic(),
    onSubmit: async ({ value }) => {
      await onSubmit?.({
        name: nameField === "hidden" ? "" : value.name.trim(),
        identifier: value.identifier.trim(),
        username: hasUsername ? value.username.trim() : "",
        password: value.password,
        termsAccepted: value.terms,
      })
    },
    onSubmitInvalid: () => {
      // Move focus to the first field that failed, so a keyboard or screen
      // reader user lands on the message instead of the submit button.
      formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
    },
  })

  if (verify !== null) {
    const resendPending = verify.resendPending === true
    return (
      <Card className={cn("w-full max-w-sm", className, classNames?.root)}>
        <CardHeader className={classNames?.header}>
          <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
            <MailCheckIcon aria-hidden className="size-4 text-muted-foreground" />
            {t.verifyTitle}
          </CardTitle>
          <CardDescription className={cn("wrap-anywhere", classNames?.description)} role="status">
            {fillText(t.verifyDescription, { identifier: verify.identifier })}
          </CardDescription>
        </CardHeader>
        <CardContent className={cn("flex flex-col gap-2", classNames?.content)}>
          {formError !== null && (
            <Alert variant="destructive" className={classNames?.formError}>
              <CircleAlertIcon aria-hidden />
              <AlertDescription>{formError}</AlertDescription>
            </Alert>
          )}
          {verify.resent === true && (
            <p role="status" className="text-xs text-muted-foreground">
              {t.resent}
            </p>
          )}
          {verify.canResend === true && (
            <Button
              type="button"
              variant="outline"
              className={cn("w-full", classNames?.resend)}
              disabled={resendPending}
              aria-busy={resendPending}
              onClick={() => onResend?.()}
            >
              {resendPending && <Spinner data-icon="inline-start" />}
              {resendPending ? t.resending : t.resend}
            </Button>
          )}
          <Button type="button" variant="ghost" className="w-full text-muted-foreground" onClick={() => onUseDifferentEmail?.()}>
            {t.useDifferentEmail}
          </Button>
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
                  onClick={() => onProvider?.(p.id)}
                >
                  <ProviderIcon id={p.id} name={p.name} icons={providerIcons} />
                  {fillText(t.continueWith, { provider: p.name })}
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

            {hasUsername && (
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
      {signInHref !== undefined && (
        <CardFooter className={cn("justify-center gap-1 text-[13px] text-muted-foreground", classNames?.footer)}>
          {t.haveAccount}
          <Link
            href={signInHref}
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
