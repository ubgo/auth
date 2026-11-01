import { useMutation } from "@tanstack/react-query"
import type { AuthError } from "@ubgo/auth-client"
import {
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
import { useState, type ReactNode } from "react"

import { DEFAULT_PASSWORD_MIN_LENGTH, PASSWORD_STRENGTH_TEXT } from "@/components/auth/password-strength"
import {
  EMAIL_SHAPE,
  SIGN_UP_FORM_TEXT,
  SignUpFormView,
  type SignUpField,
  type SignUpFormSlot,
  type SignUpFormText,
  type SignUpFormValues,
  type SignUpIdentifierKind,
  type SignUpNameField,
  type SignUpTerms,
} from "@/components/auth/sign-up-form-view"

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
//
// The card itself is SignUpFormView (sign-up-form-view.tsx): this file only
// wires it to @ubgo/auth-react, the calls, the session and navigation.

export {
  SIGN_UP_FORM_TEXT,
  SignUpFormView,
  type SignUpField,
  type SignUpFormSlot,
  type SignUpFormText,
  type SignUpFormValues,
  type SignUpFormViewProps,
  type SignUpIdentifierKind,
  type SignUpNameField,
  type SignUpProvider,
  type SignUpTerms,
  type SignUpVerifyStep,
} from "@/components/auth/sign-up-form-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    signUpForm: SignUpFormText
  }
}

/** How the sign-up finished, handed to onSuccess (a session exists) or onVerificationRequired (it does not yet). */
export type SignUpSuccess = {
  readonly userId: string
  /** The identifier as typed (trimmed), for a "check your inbox" screen of the app's own. */
  readonly identifier: string
}

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

/** The Terms-Version header the terms plugin reads at sign-up (terms.TermsHeader). */
const TERMS_HEADER = "Terms-Version"

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
  const strengthText = useLocalization("passwordStrength", PASSWORD_STRENGTH_TEXT)
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

  const [formError, setFormError] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<SignUpField, string>>>({})
  const [pending, setPending] = useState<SignUpSuccess | null>(null)

  const target = redirectTo ?? paths.afterSignIn
  // Phone alone asks for a number; email (or neither, the server's default) asks for an email.
  const identifierKind: SignUpIdentifierKind = phone === null ? "email" : email === null ? "phone" : "either"

  /** The field a server code belongs under, or undefined for the form-level alert. */
  function fieldOf(error: AuthError): SignUpField | undefined {
    // A taken username is the one "taken" answer sign-up gives: an email or
    // phone that is taken still succeeds, so the answer cannot be about it.
    if (error.code === "auth.identity_taken") return username === null ? undefined : "username"
    return FIELD_OF_ERROR[error.code]
  }

  /** Shows a failed call under its field when the code names one (the view then focuses it), above the form otherwise. */
  function showError(error: AuthError) {
    const field = fieldOf(error)
    if (field === undefined) {
      setFormError(messageFor(error))
      return
    }
    setFieldErrors({ [field]: messageFor(error) })
  }

  const signUp = useMutation({
    mutationFn: async (value: SignUpFormValues) => {
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

  // Without the password plugin there is nothing to sign up with; OAuth-only
  // apps sign up through SignInForm's provider buttons.
  if (password === null) return null

  return (
    <SignUpFormView
      className={className}
      classNames={classNames}
      text={t}
      strengthText={strengthText}
      headingLevel={headingLevel}
      nameField={nameField}
      identifierKind={identifierKind}
      hasUsername={username !== null}
      terms={terms}
      minPasswordLength={minPasswordLength}
      providers={providers}
      providerIcons={providerIcons}
      autoFocus={autoFocus}
      pending={signUp.isPending}
      formError={formError}
      fieldErrors={fieldErrors}
      verify={
        pending === null
          ? null
          : {
              identifier: pending.identifier,
              canResend: email !== null && EMAIL_SHAPE.test(pending.identifier),
              resendPending: resend.isPending,
              resent: resend.isSuccess && resend.data.error === null,
            }
      }
      signInHref={showSignIn ? withRedirect(paths.signIn, redirectTo) : undefined}
      Link={Link}
      onSubmit={async (values) => {
        setFormError(null)
        setFieldErrors({})
        await signUp.mutateAsync(values)
      }}
      onProvider={(id) => window.location.assign(oauthStartURL(baseURL, id, { returnTo: target }))}
      onPasswordChange={() => setFieldErrors((prev) => ({ ...prev, password: undefined }))}
      onResend={() => {
        if (pending === null) return
        setFormError(null)
        resend.mutate(pending.identifier)
      }}
      onUseDifferentEmail={() => {
        setPending(null)
        setFormError(null)
        resend.reset()
        signUp.reset()
      }}
    />
  )
}
