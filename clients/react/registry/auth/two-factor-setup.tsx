import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { AuthError, TwofactorEnrollResult, TwofactorStatus } from "@ubgo/auth-client"
import {
  AUTH_QUERY_ROOT,
  useAuth,
  useErrorMessage,
  useLocalization,
  usePluginClient,
  useSafeRedirect,
  useSessionActions,
  type AnyErrorCode,
  type AuthComponentProps,
  type HeadingLevel,
} from "@ubgo/auth-react"
import { useState } from "react"

import { SecurityKeys } from "@/components/auth/security-keys"
import {
  TWO_FACTOR_SETUP_TEXT,
  TwoFactorSetupView,
  type TwoFactorDialogKind,
  type TwoFactorDialogValues,
  type TwoFactorMethod,
  type TwoFactorSetupField,
  type TwoFactorSetupPending,
  type TwoFactorSetupSlot,
  type TwoFactorSetupText,
} from "@/components/auth/two-factor-setup-view"

// TwoFactorSetup: turns the second factor on and off for the signed-in user,
// in one card that fits a settings page. Off, it starts enrolment
// (twofactor.enroll), shows the QR code and the secret for an authenticator
// app (or, for a factor whose codes are mailed, says a code was sent), and
// confirms the first code (twofactor.confirm), which answers the recovery
// codes; those are shown once, with copy and download, and the user ticks
// that they saved them. On, it makes a new set of recovery codes or turns the
// factor off, each behind a current code. Every one of these needs a recent
// sign-in; when the session is too old the card offers to sign in again
// instead of failing on each click.
//
// The card itself is TwoFactorSetupView (two-factor-setup-view.tsx), with the
// wired SecurityKeys in its security keys slot: this file only wires it to
// @ubgo/auth-react, the calls, the session and navigation.

export {
  TWO_FACTOR_SETUP_TEXT,
  TwoFactorSetupView,
  type TwoFactorDialogKind,
  type TwoFactorDialogValues,
  type TwoFactorEnrollment,
  type TwoFactorMethod,
  type TwoFactorSetupField,
  type TwoFactorSetupPending,
  type TwoFactorSetupSlot,
  type TwoFactorSetupStep,
  type TwoFactorSetupText,
  type TwoFactorSetupViewProps,
} from "@/components/auth/two-factor-setup-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    twoFactorSetup: TwoFactorSetupText
  }
}

/** What changed, handed to onSuccess. */
export type TwoFactorSetupResult = {
  readonly action: "enabled" | "disabled" | "regenerated"
}

export type TwoFactorSetupProps = AuthComponentProps<TwoFactorSetupSlot, "twoFactorSetup", TwoFactorSetupResult> & {
  /**
   * Ask for the current password when turning the factor on or off and when
   * making new codes. Set it when the server uses twofactor.RequirePassword();
   * the server does not report it, so it is a prop.
   */
  readonly requirePassword?: boolean
  /** The code length: 6, or 8 when the server was built with twofactor.WithDigits(8). */
  readonly digits?: 6 | 8
  /** Which kind of factor to enrol. Defaults to the authenticator app when the server offers it. */
  readonly method?: TwoFactorMethod
  /** The downloaded recovery-codes file's name. */
  readonly recoveryCodesFileName?: string
  /**
   * "card" (default) is a standalone card. "embedded" drops the card's
   * border, background, padding and title, for a settings section that
   * already has its own heading.
   */
  readonly variant?: "card" | "embedded"
  /**
   * Called when the server answers auth.fresh_session_required, instead of
   * the card's own "Sign in again" prompt: an account page opens its own
   * re-authentication dialog and, once the user has signed in again, calls
   * `retry`, which reruns the refused action (turn on, confirm, new recovery
   * codes, turn off) with the same inputs.
   */
  readonly onFreshSessionRequired?: (retry: () => Promise<void>) => void
  /**
   * Show the security keys section (SecurityKeys, embedded) under the
   * overview. On by default; it renders nothing when the server does not
   * offer security keys (twofactor.WithSecurityKeys).
   */
  readonly securityKeys?: boolean
}

/** The heading level of a section under the card's title. */
const SUB_LEVEL: Record<HeadingLevel, HeadingLevel> = { 1: 2, 2: 3, 3: 4, 4: 5, 5: 6, 6: 6 }

/** The factor's status, shared with TwoFactorChallenge's key so either refreshes the other. */
const STATUS_QUERY_KEY = [...AUTH_QUERY_ROOT, "twofactor", "status"] as const

/** The error that means the action needs a recent sign-in. */
const FRESH_REQUIRED: AnyErrorCode = "auth.fresh_session_required"

/** Error codes that belong under the code field rather than above the form. */
const CODE_FIELD_ERRORS: ReadonlySet<AnyErrorCode> = new Set<AnyErrorCode>(["twofactor.code_invalid"])

/** Error codes that belong under the password field. */
const PASSWORD_FIELD_ERRORS: ReadonlySet<AnyErrorCode> = new Set<AnyErrorCode>(["password.invalid_credentials"])

/** The card's steps once enrolment starts; "overview" is the on/off card. The view draws each; the password and action stay here for the calls. */
type Step =
  | { readonly kind: "overview" }
  | { readonly kind: "verify"; readonly enrollment: TwofactorEnrollResult; readonly password: string }
  | { readonly kind: "codes"; readonly codes: readonly string[]; readonly action: "enabled" | "regenerated" }

/** Appends `redirectTo` to a path, so the sign-in page can come back here. */
function withRedirect(path: string, redirectTo: string): string {
  const joiner = path.includes("?") ? "&" : "?"
  return `${path}${joiner}redirectTo=${encodeURIComponent(redirectTo)}`
}

export function TwoFactorSetup({
  className,
  classNames,
  localization,
  onSuccess,
  redirectTo: requestedRedirectTo,
  requirePassword = false,
  digits = 6,
  method,
  recoveryCodesFileName = "recovery-codes.txt",
  headingLevel = 1,
  variant = "card",
  onFreshSessionRequired,
  securityKeys = true,
}: TwoFactorSetupProps) {
  const t = useLocalization("twoFactorSetup", TWO_FACTOR_SETUP_TEXT, localization)
  const messageFor = useErrorMessage()
  const { navigate, paths } = useAuth()
  // redirectTo usually comes from the address bar: anything but a path on
  // this site (or an origin the provider allows) is dropped, so the default
  // applies and a crafted link cannot send the user to another site.
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const { signOut } = useSessionActions()
  const queryClient = useQueryClient()
  const twofactor = usePluginClient("twofactor")

  const [step, setStep] = useState<Step>({ kind: "overview" })
  const [formError, setFormError] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<TwoFactorSetupField, string>>>({})
  const [needsFresh, setNeedsFresh] = useState(false)
  const [dialog, setDialog] = useState<TwoFactorDialogKind | null>(null)
  const [dialogFormError, setDialogFormError] = useState<string | null>(null)
  const [dialogFieldErrors, setDialogFieldErrors] = useState<Partial<Record<TwoFactorSetupField, string>>>({})

  const status = useQuery({
    queryKey: STATUS_QUERY_KEY,
    queryFn: async (): Promise<{ status: TwofactorStatus | null; error: AuthError | null }> => {
      if (twofactor === null) throw new Error("TwoFactorSetup: twofactor plugin missing")
      const { data, error } = await twofactor.status()
      return { status: data, error }
    },
    enabled: twofactor !== null,
    staleTime: 30_000,
    retry: false,
  })

  const enabled = status.data?.status?.enabled ?? false
  const methods = status.data?.status?.methods ?? []
  const chosenMethod: TwoFactorMethod = method ?? (methods.length === 0 || methods.includes("totp") ? "totp" : "delivered")

  /** Routes a failed call to the right place; returns nothing so callers can just `return showError(e)`. */
  function showError(error: AuthError, retry: () => Promise<void>) {
    if (error.code === FRESH_REQUIRED) freshRequired(retry)
    else if (CODE_FIELD_ERRORS.has(error.code)) setFieldErrors({ code: messageFor(error) })
    else if (PASSWORD_FIELD_ERRORS.has(error.code) && requirePassword) setFieldErrors({ password: messageFor(error) })
    else setFormError(messageFor(error))
  }

  /** The app's re-authentication when it handles it, the card's own prompt otherwise. */
  function freshRequired(retry: () => Promise<void>) {
    if (onFreshSessionRequired === undefined) setNeedsFresh(true)
    else onFreshSessionRequired(retry)
  }

  function clearErrors() {
    setFormError(null)
    setFieldErrors({})
  }

  /** The end of every change: refresh the status everyone reads, then report or move on. */
  async function finish(action: TwoFactorSetupResult["action"]) {
    await queryClient.invalidateQueries({ queryKey: STATUS_QUERY_KEY })
    setStep({ kind: "overview" })
    if (onSuccess !== undefined) onSuccess({ action })
    else if (redirectTo !== undefined) navigate(redirectTo)
  }

  const enroll = useMutation({
    mutationFn: async (password: string) => {
      if (twofactor === null) throw new Error("TwoFactorSetup: twofactor plugin missing")
      return twofactor.enroll(requirePassword ? { method: chosenMethod, password } : { method: chosenMethod })
    },
    onSuccess: async ({ data, error }, password) => {
      if (error !== null)
        return showError(error, async () => {
          await enroll.mutateAsync(password)
        })
      // A server built with SkipVerificationOnEnable turns the factor on at once and answers the codes.
      if (data.enabled) {
        await queryClient.invalidateQueries({ queryKey: STATUS_QUERY_KEY })
        setStep({ kind: "codes", codes: data.recoveryCodes ?? [], action: "enabled" })
        return
      }
      setStep({ kind: "verify", enrollment: data, password })
    },
  })

  const confirm = useMutation({
    mutationFn: async (code: string) => {
      if (twofactor === null) throw new Error("TwoFactorSetup: twofactor plugin missing")
      return twofactor.confirm({ code })
    },
    onSuccess: async ({ data, error }, code) => {
      if (error !== null) {
        showError(error, async () => {
          await confirm.mutateAsync(code)
        })
        return
      }
      await queryClient.invalidateQueries({ queryKey: STATUS_QUERY_KEY })
      setStep({ kind: "codes", codes: data.codes ?? [], action: "enabled" })
    },
  })

  /** The call behind the code dialog: turn off, or a new set of recovery codes. */
  const dialogAction = useMutation({
    mutationFn: async ({ kind, code, password }: TwoFactorDialogValues & { readonly kind: TwoFactorDialogKind }) => {
      if (twofactor === null) throw new Error("TwoFactorSetup: twofactor plugin missing")
      const input = requirePassword ? { code, password } : { code }
      if (kind === "disable") {
        const { error } = await twofactor.disable(input)
        const none: readonly string[] = []
        return { error, codes: none }
      }
      const { data, error } = await twofactor.recoveryCodes(input)
      return { error, codes: data?.codes ?? [] }
    },
    onSuccess: async ({ error, codes }, value) => {
      if (error === null) {
        setDialog(null)
        if (value.kind === "regenerate") setStep({ kind: "codes", codes, action: "regenerated" })
        else await finish("disabled")
        return
      }
      if (error.code === FRESH_REQUIRED) {
        // Closed while the re-sign-in dialog is up, reopened by the retry so
        // its progress (and any new error) shows where the user left it.
        setDialog(null)
        freshRequired(async () => {
          setDialog(value.kind)
          await dialogAction.mutateAsync(value)
        })
      } else if (CODE_FIELD_ERRORS.has(error.code)) setDialogFieldErrors({ code: messageFor(error) })
      else if (PASSWORD_FIELD_ERRORS.has(error.code) && requirePassword) setDialogFieldErrors({ password: messageFor(error) })
      else setDialogFormError(messageFor(error))
    },
  })

  // No twofactor() in the client: nothing to set up, so nothing renders (CONTRACT.md rule 2).
  if (twofactor === null) return null

  const here = typeof window === "undefined" ? paths.afterSignIn : window.location.pathname + window.location.search
  const pending: TwoFactorSetupPending = enroll.isPending ? "enable" : confirm.isPending ? "confirm" : null

  return (
    <TwoFactorSetupView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      variant={variant}
      loading={status.isPending}
      enabled={enabled}
      primaryMethod={status.data?.status?.method}
      step={step}
      requirePassword={requirePassword}
      digits={digits}
      recoveryCodesFileName={recoveryCodesFileName}
      pending={pending}
      formError={formError}
      fieldErrors={fieldErrors}
      needsFresh={needsFresh}
      securityKeys={
        securityKeys && (
          <SecurityKeys
            variant="embedded"
            headingLevel={SUB_LEVEL[headingLevel]}
            onSuccess={(r) => {
              // A first key turns two-factor on and the last one removed turns it
              // off: the same outcome as the code flow, reported the same way.
              if (r.twoFactorEnabled !== enabled) void finish(r.twoFactorEnabled ? "enabled" : "disabled")
            }}
          />
        )
      }
      dialog={dialog}
      dialogPending={dialogAction.isPending}
      dialogFormError={dialogFormError}
      dialogFieldErrors={dialogFieldErrors}
      onEnable={async ({ password }) => {
        clearErrors()
        await enroll.mutateAsync(password)
      }}
      onConfirm={async (code) => {
        clearErrors()
        await confirm.mutateAsync(code)
      }}
      onCodeChange={() => setFieldErrors({})}
      onResend={() => {
        if (step.kind !== "verify") return
        clearErrors()
        enroll.mutate(step.password)
      }}
      onCancel={() => {
        clearErrors()
        setStep({ kind: "overview" })
      }}
      onDone={() => {
        if (step.kind === "codes") void finish(step.action)
      }}
      onSignInAgain={() => void signOut({ redirectTo: withRedirect(paths.signIn, here) })}
      onDialogChange={(kind) => {
        if (kind !== null) clearErrors()
        setDialogFormError(null)
        setDialogFieldErrors({})
        setDialog(kind)
      }}
      onDialogSubmit={async (kind, values) => {
        setDialogFormError(null)
        setDialogFieldErrors({})
        await dialogAction.mutateAsync({ kind, ...values })
      }}
      onDialogCodeModeChange={() => setDialogFieldErrors({})}
    />
  )
}
