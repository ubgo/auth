import { useMutation, useQuery } from "@tanstack/react-query"
import type { AuthError, TwofactorStatus } from "@ubgo/auth-client"
import {
  AUTH_QUERY_ROOT,
  getPasskeyCredential,
  useAuth,
  useErrorMessage,
  useLocalization,
  usePluginClient,
  useSafeRedirect,
  useSessionActions,
  type AnyErrorCode,
  type AuthComponentProps,
} from "@ubgo/auth-react"
import { useState } from "react"

import {
  TWO_FACTOR_CHALLENGE_TEXT,
  TwoFactorChallengeView,
  type TwoFactorChallengePending,
  type TwoFactorChallengeSlot,
  type TwoFactorChallengeText,
  type TwoFactorChallengeValues,
} from "@/components/auth/two-factor-challenge-view"

// TwoFactorChallenge: the step after a sign-in that answered
// secondFactorRequired. The session is pending (it signs nobody in) until
// twofactor.verify accepts a code from the authenticator app, a mailed or
// texted code, or one of the recovery codes; verify then swaps it for a full
// session. It reads twofactor.status to learn which kind of code to ask for
// and whether "trust this device" is on, so it needs no props to match the
// server. A pending session lasts ten minutes; past that it shows a way back
// to the sign-in page instead of a form that can only fail.
//
// The card itself is TwoFactorChallengeView (two-factor-challenge-view.tsx):
// this file only wires it to @ubgo/auth-react, the calls, the session and
// navigation.

export {
  TWO_FACTOR_CHALLENGE_TEXT,
  TwoFactorChallengeView,
  type TwoFactorChallengeMode,
  type TwoFactorChallengePending,
  type TwoFactorChallengeSlot,
  type TwoFactorChallengeText,
  type TwoFactorChallengeValues,
  type TwoFactorChallengeViewProps,
} from "@/components/auth/two-factor-challenge-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    twoFactorChallenge: TwoFactorChallengeText
  }
}

/** How the second step finished, handed to onSuccess. */
export type TwoFactorChallengeSuccess = {
  /** "code" for an authenticator-app or delivered code, "recovery" for a recovery code, "security_key" for a security key. */
  readonly method: "code" | "recovery" | "security_key"
  /** Whether the server was asked to remember this browser. */
  readonly trustedDevice: boolean
}

export type TwoFactorChallengeProps = AuthComponentProps<TwoFactorChallengeSlot, "twoFactorChallenge", TwoFactorChallengeSuccess> & {
  /**
   * The length of the server's codes: 6, or 8 when it was built with
   * twofactor.WithDigits(8). The server does not report it, so it is a prop.
   */
  readonly digits?: 6 | 8
  /** Focus the code field on mount, for a page whose only job is this step. On by default. */
  readonly autoFocus?: boolean
  /** Submit as soon as the last digit is typed or pasted. On by default. */
  readonly autoSubmit?: boolean
  /** Whether "trust this device" starts ticked, when the server offers it. Off by default. */
  readonly defaultTrustDevice?: boolean
  /** Show "Sign in as someone else", which ends the pending session. On by default. */
  readonly showCancel?: boolean
}

/** The query key of the factor's status, under the package root so sign-out clears it. */
const STATUS_QUERY_KEY = [...AUTH_QUERY_ROOT, "twofactor", "status"] as const

/** The method of a security key factor (twofactor.MethodSecurityKey). */
const METHOD_SECURITY_KEY = "security_key"

/** Error codes that belong under the code field rather than above the form. */
const FIELD_ERRORS: ReadonlySet<AnyErrorCode> = new Set<AnyErrorCode>(["twofactor.code_invalid"])

/** Error codes that mean the pending session is gone, so only a new sign-in helps. */
const EXPIRED_ERRORS: ReadonlySet<AnyErrorCode> = new Set<AnyErrorCode>(["auth.signed_out"])

/** Appends `redirectTo` to a path, so the next step can finish where this one was headed. */
function withRedirect(path: string, redirectTo: string | undefined): string {
  if (redirectTo === undefined) return path
  const joiner = path.includes("?") ? "&" : "?"
  return `${path}${joiner}redirectTo=${encodeURIComponent(redirectTo)}`
}

export function TwoFactorChallenge({
  className,
  classNames,
  localization,
  onSuccess,
  redirectTo: requestedRedirectTo,
  digits = 6,
  autoFocus = true,
  autoSubmit = true,
  defaultTrustDevice = false,
  showCancel = true,
  headingLevel = 1,
}: TwoFactorChallengeProps) {
  const t = useLocalization("twoFactorChallenge", TWO_FACTOR_CHALLENGE_TEXT, localization)
  const messageFor = useErrorMessage()
  const { navigate, paths } = useAuth()
  // redirectTo usually comes from the address bar: anything but a path on
  // this site (or an origin the provider allows) is dropped, so the default
  // applies and a crafted link cannot send the user to another site.
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const { refreshSession, signOut } = useSessionActions()
  const twofactor = usePluginClient("twofactor")

  const [formError, setFormError] = useState<string | null>(null)
  const [fieldError, setFieldError] = useState<string | null>(null)
  const [expired, setExpired] = useState(false)
  const [sentCount, setSentCount] = useState(0)

  // Which kind of code to ask for, and whether trusting the device is on.
  // A failed read is data, not a throw: "signed out" means the pending
  // session expired, anything else falls back to the authenticator form.
  const status = useQuery({
    queryKey: STATUS_QUERY_KEY,
    queryFn: async (): Promise<{ status: TwofactorStatus | null; error: AuthError | null }> => {
      if (twofactor === null) throw new Error("TwoFactorChallenge: twofactor plugin missing")
      const { data, error } = await twofactor.status()
      return { status: data, error }
    },
    enabled: twofactor !== null,
    staleTime: 0,
    retry: false,
  })

  const factorMethods = (status.data?.status?.factors ?? []).map((f) => f.method)
  const primaryCode = status.data?.status?.method
  const canTrust = status.data?.status?.trustDevices ?? false
  const statusExpired = status.data?.error !== null && status.data?.error !== undefined && EXPIRED_ERRORS.has(status.data.error.code)

  /** Shows a failed call: under the field for a wrong code (the view clears and refocuses it), the expired card for a lost session, above the form otherwise. */
  function showError(error: AuthError) {
    if (EXPIRED_ERRORS.has(error.code)) setExpired(true)
    else if (FIELD_ERRORS.has(error.code)) setFieldError(messageFor(error))
    else setFormError(messageFor(error))
  }

  const verify = useMutation({
    mutationFn: async (value: TwoFactorChallengeValues) => {
      if (twofactor === null) throw new Error("TwoFactorChallenge: twofactor plugin missing")
      const trust = canTrust && value.trustDevice
      // A picked code factor that is not the primary is named; otherwise the
      // server uses the primary (a recovery code needs no method either).
      const method = value.method !== undefined && value.method !== primaryCode ? { method: value.method } : {}
      return twofactor.verify({ code: value.code, ...method, ...(trust ? { trustDevice: true } : {}) })
    },
    onSuccess: async ({ error }, value) => {
      if (error !== null) {
        showError(error)
        return
      }
      await refreshSession()
      const result: TwoFactorChallengeSuccess = { method: value.mode, trustedDevice: canTrust && value.trustDevice }
      if (onSuccess === undefined) navigate(redirectTo ?? paths.afterSignIn)
      else onSuccess(result)
    },
  })

  /** Answers with a security key: the server's challenge, the browser prompt, then verify with the assertion. */
  const keyVerify = useMutation({
    mutationFn: async (trustDevice: boolean) => {
      if (twofactor === null) throw new Error("TwoFactorChallenge: twofactor plugin missing")
      const challenge = await twofactor.securityKeyChallenge()
      if (challenge.error !== null) return { error: challenge.error, cancelled: false }
      const ceremony = await getPasskeyCredential(challenge.data.options)
      if (ceremony.credential === null) return { error: null, cancelled: true }
      const trust = canTrust && trustDevice
      const { error } = await twofactor.verify({
        code: "",
        method: METHOD_SECURITY_KEY,
        securityKey: { ceremony: challenge.data.ceremony, credential: ceremony.credential },
        ...(trust ? { trustDevice: true } : {}),
      })
      return { error, cancelled: false }
    },
    onMutate: () => {
      setFormError(null)
      setFieldError(null)
    },
    onSuccess: async ({ error, cancelled }, trustDevice) => {
      if (cancelled) {
        setFormError(t.securityKeyCancelled)
        return
      }
      if (error !== null) {
        showError(error)
        return
      }
      await refreshSession()
      const result: TwoFactorChallengeSuccess = { method: "security_key", trustedDevice: canTrust && trustDevice }
      if (onSuccess === undefined) navigate(redirectTo ?? paths.afterSignIn)
      else onSuccess(result)
    },
  })

  const send = useMutation({
    mutationFn: async () => {
      if (twofactor === null) throw new Error("TwoFactorChallenge: twofactor plugin missing")
      return twofactor.send()
    },
    onSuccess: ({ error }) => {
      if (error !== null) {
        showError(error)
        return
      }
      setSentCount((n) => n + 1)
    },
  })

  // No twofactor() in the client: nothing to ask for, so nothing renders (CONTRACT.md rule 2).
  if (twofactor === null) return null

  const pending: TwoFactorChallengePending = verify.isPending ? "verify" : send.isPending ? "send" : keyVerify.isPending ? "securityKey" : null

  return (
    <TwoFactorChallengeView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      digits={digits}
      factorMethods={factorMethods}
      primaryMethod={primaryCode}
      canTrustDevice={canTrust}
      defaultTrustDevice={defaultTrustDevice}
      loading={status.isPending}
      expired={expired || statusExpired}
      pending={pending}
      formError={formError}
      fieldError={fieldError}
      codesSent={sentCount}
      autoFocus={autoFocus}
      autoSubmit={autoSubmit}
      onSubmit={async (values) => {
        setFormError(null)
        setFieldError(null)
        await verify.mutateAsync(values)
      }}
      onSendCode={() => {
        setFormError(null)
        send.mutate()
      }}
      onSecurityKey={(trustDevice) => keyVerify.mutate(trustDevice)}
      onCodeChange={() => setFieldError(null)}
      onModeChange={() => {
        setFormError(null)
        setFieldError(null)
      }}
      onCodeMethodChange={() => setFieldError(null)}
      {...(showCancel ? { onCancel: () => void signOut({ redirectTo: withRedirect(paths.signIn, redirectTo) }) } : {})}
      onSignInAgain={() => navigate(withRedirect(paths.signIn, redirectTo))}
    />
  )
}
