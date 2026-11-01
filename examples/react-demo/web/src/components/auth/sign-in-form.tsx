import { useMutation } from "@tanstack/react-query"
import type { AuthError } from "@ubgo/auth-client"
import {
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
import { useState, type ReactNode } from "react"

import {
  SIGN_IN_FORM_TEXT,
  SignInFormView,
  type SignInField,
  type SignInFormSlot,
  type SignInFormText,
  type SignInFormValues,
  type SignInMode,
  type SignInPending,
} from "@/components/auth/sign-in-form-view"

// SignInForm: every sign-in method the client has, in one card. Password and
// magic link share the identifier field; OAuth providers come from the
// server's list; the passkey button shows when the plugin is on and the
// browser can run the ceremony, and the same passkeys are offered in the
// identifier field's autofill (conditional mediation) where the browser
// supports it. A sign-in that needs a second factor hands
// off to onSecondFactor (or paths.twoFactor) instead of finishing.
//
// The card itself is SignInFormView (sign-in-form-view.tsx): this file only
// wires it to @ubgo/auth-react, the calls, the session and navigation.

export {
  SIGN_IN_FORM_TEXT,
  SignInFormView,
  type SignInFormSlot,
  type SignInFormText,
  type SignInFormValues,
  type SignInFormViewProps,
  type SignInMode,
} from "@/components/auth/sign-in-form-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    signInForm: SignInFormText
  }
}

/** How the sign-in finished, handed to onSuccess. */
export type SignInSuccess = {
  readonly method: "password" | "passkey"
  readonly userId: string
}

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
const FIELD_OF_ERROR: Readonly<Partial<Record<string, SignInField>>> = {
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

  const [formError, setFormError] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<SignInField, string>>>({})
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

  const pending: SignInPending = passwordSignIn.isPending
    ? "password"
    : magicLinkSend.isPending
      ? "magiclink"
      : passkeySignIn.isPending || autofill.status === "finishing"
        ? "passkey"
        : null

  async function submit(values: SignInFormValues) {
    setFormError(null)
    setFieldErrors({})
    autofill.pause()
    if (values.mode === "password") await passwordSignIn.mutateAsync(values)
    else await magicLinkSend.mutateAsync(values.identifier)
  }

  return (
    <SignInFormView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      methods={{ password: password !== null, magicLink: magiclink !== null, passkey: canPasskey }}
      acceptsUsername={username !== null}
      providers={providers}
      providerIcons={providerIcons}
      defaultMode={defaultMode}
      pending={pending}
      formError={formError}
      fieldErrors={fieldErrors}
      sentTo={sentTo}
      passkeyAutofill={passkeyAutofill}
      autoFocus={autoFocus}
      forgotPasswordHref={paths.forgotPassword}
      signUpHref={showSignUp ? withRedirect(paths.signUp, redirectTo) : undefined}
      Link={Link}
      onSubmit={submit}
      onPasskey={() => {
        setFormError(null)
        autofill.pause()
        passkeySignIn.mutate()
      }}
      onProvider={(id) => {
        autofill.pause()
        window.location.assign(oauthStartURL(baseURL, id, { returnTo: target }))
      }}
      onModeChange={() => {
        setFormError(null)
        setFieldErrors({})
      }}
      onUseDifferentEmail={() => {
        setSentTo(null)
        magicLinkSend.reset()
        autofill.resume()
      }}
    />
  )
}
