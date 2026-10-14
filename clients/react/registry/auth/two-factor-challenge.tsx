import { useForm } from "@tanstack/react-form"
import { useMutation, useQuery } from "@tanstack/react-query"
import type { AuthError, TwofactorStatus } from "@ubgo/auth-client"
import {
  AUTH_QUERY_ROOT,
  format,
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
import { REGEXP_ONLY_DIGITS } from "input-otp"
import { CircleAlertIcon, ClockIcon, KeyRoundIcon, ShieldCheckIcon } from "lucide-react"
import { useId, useRef, useState } from "react"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { InputOTP, InputOTPGroup, InputOTPSeparator, InputOTPSlot } from "@/components/ui/input-otp"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// TwoFactorChallenge: the step after a sign-in that answered
// secondFactorRequired. The session is pending (it signs nobody in) until
// twofactor.verify accepts a code from the authenticator app, a mailed or
// texted code, or one of the recovery codes; verify then swaps it for a full
// session. It reads twofactor.status to learn which kind of code to ask for
// and whether "trust this device" is on, so it needs no props to match the
// server. A pending session lasts ten minutes; past that it shows a way back
// to the sign-in page instead of a form that can only fail.

/** Every string TwoFactorChallenge shows, with `{name}` placeholders where a value is filled in. */
export type TwoFactorChallengeText = {
  title: string
  /** For an authenticator-app factor. `{digits}` is the code length. */
  description: string
  /** For a factor whose codes are mailed or texted. */
  descriptionDelivered: string
  recoveryDescription: string
  codeLabel: string
  /** `{digits}` is the code length. */
  codeRequired: string
  recoveryLabel: string
  recoveryPlaceholder: string
  recoveryRequired: string
  trustDevice: string
  trustDeviceDescription: string
  submit: string
  submitting: string
  sendCode: string
  sendingCode: string
  resendCode: string
  /** Announced after a code was sent. */
  codeSent: string
  useRecovery: string
  useAuthenticator: string
  useDeliveredCode: string
  /** The description when a security key is the only factor besides recovery codes. */
  descriptionSecurityKey: string
  /** The button that answers with a security key instead of a code. */
  useSecurityKey: string
  usingSecurityKey: string
  /** Shown when the browser prompt for the key was closed or matched nothing. */
  securityKeyCancelled: string
  /** The code-factor picker's label, shown when more than one code factor is on. */
  codeFactorLabel: string
  cancel: string
  expiredTitle: string
  expiredDescription: string
  signInAgain: string
  loading: string
}

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    twoFactorChallenge: TwoFactorChallengeText
  }
}

/** The English defaults. Override per app (AuthProvider localization.twoFactorChallenge) or per use (localization prop). */
export const TWO_FACTOR_CHALLENGE_TEXT: TwoFactorChallengeText = {
  title: "Two-factor authentication",
  description: "Enter the {digits}-digit code from your authenticator app.",
  descriptionDelivered: "Enter the code we sent to your email or phone.",
  recoveryDescription: "Enter one of the recovery codes you saved when you turned on two-factor authentication. Each code works once.",
  codeLabel: "Authentication code",
  codeRequired: "Enter the {digits}-digit code.",
  recoveryLabel: "Recovery code",
  recoveryPlaceholder: "XXXX-XXXX-XXXX-XXXX",
  recoveryRequired: "Enter a recovery code.",
  trustDevice: "Trust this device",
  trustDeviceDescription: "Skip this step when you sign in from this browser.",
  submit: "Verify",
  submitting: "Verifying…",
  sendCode: "Send me a code",
  sendingCode: "Sending…",
  resendCode: "Send a new code",
  codeSent: "A code is on its way. It works for a few minutes.",
  useRecovery: "Use a recovery code",
  useAuthenticator: "Use your authenticator app",
  useDeliveredCode: "Use a code we send you",
  descriptionSecurityKey: "Use your security key to finish signing in.",
  useSecurityKey: "Use a security key",
  usingSecurityKey: "Waiting for your key…",
  securityKeyCancelled: "The security key prompt was closed. Try again, or use a code.",
  codeFactorLabel: "Code from",
  cancel: "Sign in as someone else",
  expiredTitle: "Sign in again",
  expiredDescription: "This sign-in timed out before the second step was finished.",
  signInAgain: "Back to sign in",
  loading: "Loading…",
}

/** The named parts classNames can style. */
export type TwoFactorChallengeSlot =
  | "root"
  | "header"
  | "title"
  | "description"
  | "content"
  | "form"
  | "field"
  | "label"
  | "otp"
  | "otpSlot"
  | "input"
  | "fieldError"
  | "formError"
  | "trustDevice"
  | "submit"
  | "sendCode"
  | "toggle"
  | "footer"
  | "link"

/** How the second step finished, handed to onSuccess. */
export type TwoFactorChallengeSuccess = {
  /** "code" for an authenticator-app or delivered code, "recovery" for a recovery code, "security_key" for a security key. */
  readonly method: "code" | "recovery" | "security_key"
  /** Whether the server was asked to remember this browser. */
  readonly trustedDevice: boolean
}

/** The two ways of answering the challenge. */
export type TwoFactorChallengeMode = "code" | "recovery"

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

/** The method twofactor.status reports for a factor whose codes are mailed or texted. */
const METHOD_DELIVERED = "delivered"

/** The method of a security key factor (twofactor.MethodSecurityKey). */
const METHOD_SECURITY_KEY = "security_key"

/** The methods that answer with a typed code, in the order the picker lists them. */
const CODE_METHODS: readonly string[] = ["totp", METHOD_DELIVERED]

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
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)
  const codeRef = useRef<HTMLInputElement>(null)

  const [mode, setMode] = useState<TwoFactorChallengeMode>("code")
  const [formError, setFormError] = useState<string | null>(null)
  const [fieldError, setFieldError] = useState<string | null>(null)
  const [expired, setExpired] = useState(false)
  const [sentCount, setSentCount] = useState(0)
  // The code factor picked when more than one is on; null follows the primary.
  const [codeMethod, setCodeMethod] = useState<string | null>(null)

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

  const factors = status.data?.status?.factors ?? []
  const hasSecurityKey = factors.some((f) => f.method === METHOD_SECURITY_KEY)
  // Every code factor the user has on, once each, so the picker offers a choice only when there is one.
  const codeFactors = CODE_METHODS.filter((m) => factors.some((f) => f.method === m))
  const primaryCode = status.data?.status?.method
  const activeCode = codeMethod ?? (primaryCode !== undefined && CODE_METHODS.includes(primaryCode) ? primaryCode : codeFactors[0])
  const delivered = activeCode === METHOD_DELIVERED
  const canTrust = status.data?.status?.trustDevices ?? false
  const statusExpired = status.data?.error !== null && status.data?.error !== undefined && EXPIRED_ERRORS.has(status.data.error.code)

  /** Shows a failed call: under the field for a wrong code, the expired card for a lost session, above the form otherwise. */
  function showError(error: AuthError) {
    if (EXPIRED_ERRORS.has(error.code)) {
      setExpired(true)
    } else if (FIELD_ERRORS.has(error.code)) {
      setFieldError(messageFor(error))
      form.setFieldValue("code", "")
      // A wrong code is retyped from the start, so the caret goes back to the first box.
      requestAnimationFrame(() => codeRef.current?.focus())
    } else {
      setFormError(messageFor(error))
    }
  }

  const verify = useMutation({
    mutationFn: async (value: { code: string; trustDevice: boolean }) => {
      if (twofactor === null) throw new Error("TwoFactorChallenge: twofactor plugin missing")
      const trust = canTrust && value.trustDevice
      // A picked code factor that is not the primary is named; otherwise the
      // server uses the primary (a recovery code needs no method either).
      const method = mode === "code" && codeMethod !== null && codeMethod !== primaryCode ? { method: codeMethod } : {}
      return twofactor.verify({ code: value.code.trim(), ...method, ...(trust ? { trustDevice: true } : {}) })
    },
    onSuccess: async ({ error }, value) => {
      if (error !== null) {
        showError(error)
        return
      }
      await refreshSession()
      const result: TwoFactorChallengeSuccess = { method: mode, trustedDevice: canTrust && value.trustDevice }
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
      requestAnimationFrame(() => codeRef.current?.focus())
    },
  })

  const form = useForm({
    defaultValues: { code: "", trustDevice: defaultTrustDevice },
    onSubmit: async ({ value }) => {
      setFormError(null)
      setFieldError(null)
      await verify.mutateAsync(value)
    },
    onSubmitInvalid: () => {
      formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
    },
  })

  function switchMode(next: TwoFactorChallengeMode) {
    setMode(next)
    setFormError(null)
    setFieldError(null)
    form.reset()
    requestAnimationFrame(() => codeRef.current?.focus())
  }

  const rootClass = cn("w-full max-w-sm", className, classNames?.root)

  // No twofactor() in the client: nothing to ask for, so nothing renders (CONTRACT.md rule 2).
  if (twofactor === null) return null

  if (expired || statusExpired) {
    return (
      <Card className={rootClass}>
        <CardHeader className={classNames?.header}>
          <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
            <ClockIcon aria-hidden className="size-4 text-muted-foreground" />
            {t.expiredTitle}
          </CardTitle>
          <CardDescription className={classNames?.description} role="status">
            {t.expiredDescription}
          </CardDescription>
        </CardHeader>
        <CardContent className={classNames?.content}>
          <Button
            size="lg"
            className={cn("w-full", classNames?.submit)}
            onClick={() => navigate(withRedirect(paths.signIn, redirectTo))}
          >
            {t.signInAgain}
          </Button>
        </CardContent>
      </Card>
    )
  }

  const busy = verify.isPending || send.isPending || keyVerify.isPending
  const codeLength = digits
  const half = Math.ceil(codeLength / 2)
  const keyOnly = hasSecurityKey && codeFactors.length === 0
  const description =
    mode === "recovery" ? t.recoveryDescription : keyOnly ? t.descriptionSecurityKey : delivered ? t.descriptionDelivered : format(t.description, { digits: codeLength })

  return (
    <Card className={rootClass}>
      <CardHeader className={classNames?.header}>
        <div aria-hidden className="mb-1 flex size-8 items-center justify-center rounded-lg bg-muted text-muted-foreground">
          <ShieldCheckIcon className="size-4" />
        </div>
        <CardTitle className={classNames?.title} role="heading" aria-level={headingLevel}>
          {t.title}
        </CardTitle>
        {status.isPending ? (
          <Skeleton className="h-4 w-4/5" aria-label={t.loading} />
        ) : (
          <CardDescription className={classNames?.description} id={`${formId}-description`}>
            {description}
          </CardDescription>
        )}
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
          aria-describedby={`${formId}-description`}
          className={classNames?.form}
          onSubmit={(e) => {
            e.preventDefault()
            e.stopPropagation()
            void form.handleSubmit()
          }}
        >
          <FieldGroup>
            {mode === "code" && codeFactors.length > 1 && (
              <div role="radiogroup" aria-label={t.codeFactorLabel} className="flex gap-1">
                {codeFactors.map((m) => (
                  <Button
                    key={m}
                    type="button"
                    role="radio"
                    aria-checked={m === activeCode}
                    variant={m === activeCode ? "secondary" : "ghost"}
                    size="sm"
                    className="flex-1"
                    disabled={busy}
                    onClick={() => {
                      setCodeMethod(m)
                      setFieldError(null)
                      form.setFieldValue("code", "")
                    }}
                  >
                    {m === METHOD_DELIVERED ? t.useDeliveredCode : t.useAuthenticator}
                  </Button>
                ))}
              </div>
            )}
            {mode === "code" && delivered && (
              <div className="flex flex-col gap-1.5">
                <Button
                  type="button"
                  variant="outline"
                  className={cn("w-full", classNames?.sendCode)}
                  disabled={busy}
                  aria-busy={send.isPending}
                  onClick={() => {
                    setFormError(null)
                    send.mutate()
                  }}
                >
                  {send.isPending && <Spinner data-icon="inline-start" />}
                  {send.isPending ? t.sendingCode : sentCount > 0 ? t.resendCode : t.sendCode}
                </Button>
                {/* Polite live region: announces each send, so a screen reader user knows the click worked. */}
                <p role="status" aria-live="polite" className="text-xs text-muted-foreground empty:hidden">
                  {sentCount > 0 ? t.codeSent : ""}
                </p>
              </div>
            )}

            {!(keyOnly && mode === "code") && (
            <form.Field
              name="code"
              validators={{
                onSubmit: ({ value }) => {
                  if (mode === "recovery") return value.trim() === "" ? t.recoveryRequired : undefined
                  return value.length !== codeLength ? format(t.codeRequired, { digits: codeLength }) : undefined
                },
              }}
            >
              {(field) => {
                const message = field.state.meta.errors[0] ?? fieldError ?? undefined
                const invalid = message !== undefined
                const inputId = `${formId}-code`
                const errorId = `${formId}-code-error`
                return (
                  <Field data-invalid={invalid} className={classNames?.field}>
                    <FieldLabel htmlFor={inputId} className={classNames?.label}>
                      {mode === "recovery" ? t.recoveryLabel : t.codeLabel}
                    </FieldLabel>
                    {mode === "code" ? (
                      <InputOTP
                        ref={codeRef}
                        id={inputId}
                        name="code"
                        maxLength={codeLength}
                        pattern={REGEXP_ONLY_DIGITS}
                        inputMode="numeric"
                        autoComplete="one-time-code"
                        autoFocus={autoFocus}
                        disabled={verify.isPending}
                        value={field.state.value}
                        onChange={(next) => {
                          field.handleChange(next)
                          if (fieldError !== null) setFieldError(null)
                        }}
                        onComplete={() => {
                          if (autoSubmit && !verify.isPending) void form.handleSubmit()
                        }}
                        aria-invalid={invalid}
                        aria-describedby={invalid ? errorId : undefined}
                        containerClassName={cn("justify-center", classNames?.otp)}
                      >
                        <InputOTPGroup>
                          {Array.from({ length: half }, (_, i) => (
                            <InputOTPSlot key={i} index={i} aria-invalid={invalid} className={cn("size-10 text-base", classNames?.otpSlot)} />
                          ))}
                        </InputOTPGroup>
                        <InputOTPSeparator className="text-muted-foreground" />
                        <InputOTPGroup>
                          {Array.from({ length: codeLength - half }, (_, i) => (
                            <InputOTPSlot
                              key={half + i}
                              index={half + i}
                              aria-invalid={invalid}
                              className={cn("size-10 text-base", classNames?.otpSlot)}
                            />
                          ))}
                        </InputOTPGroup>
                      </InputOTP>
                    ) : (
                      <Input
                        ref={codeRef}
                        id={inputId}
                        name="code"
                        autoComplete="off"
                        autoCapitalize="characters"
                        spellCheck={false}
                        autoFocus
                        placeholder={t.recoveryPlaceholder}
                        value={field.state.value}
                        onChange={(e) => {
                          field.handleChange(e.target.value)
                          if (fieldError !== null) setFieldError(null)
                        }}
                        onBlur={field.handleBlur}
                        aria-invalid={invalid}
                        aria-describedby={invalid ? errorId : undefined}
                        className={cn("font-mono tracking-wider uppercase placeholder:normal-case placeholder:tracking-normal", classNames?.input)}
                      />
                    )}
                    {invalid && (
                      <FieldError id={errorId} className={cn(mode === "code" && "text-center", classNames?.fieldError)}>
                        {message}
                      </FieldError>
                    )}
                  </Field>
                )
              }}
            </form.Field>
            )}

            {canTrust && (
              <form.Field name="trustDevice">
                {(field) => (
                  <Field orientation="horizontal" className={classNames?.trustDevice}>
                    <Checkbox
                      id={`${formId}-trust`}
                      name="trustDevice"
                      checked={field.state.value}
                      onCheckedChange={(checked) => field.handleChange(checked)}
                      aria-describedby={`${formId}-trust-description`}
                    />
                    <div className="flex flex-col gap-0.5">
                      <FieldLabel htmlFor={`${formId}-trust`} className="font-normal">
                        {t.trustDevice}
                      </FieldLabel>
                      <FieldDescription id={`${formId}-trust-description`} className="text-xs">
                        {t.trustDeviceDescription}
                      </FieldDescription>
                    </div>
                  </Field>
                )}
              </form.Field>
            )}

            {!(keyOnly && mode === "code") && (
            <Button type="submit" size="lg" className={cn("w-full", classNames?.submit)} disabled={busy || status.isPending} aria-busy={verify.isPending}>
              {verify.isPending && <Spinner data-icon="inline-start" />}
              {verify.isPending ? t.submitting : t.submit}
            </Button>
            )}

            {hasSecurityKey && (
              <Button
                type="button"
                variant={keyOnly ? "default" : "outline"}
                size={keyOnly ? "lg" : "default"}
                className={cn("w-full", keyOnly ? classNames?.submit : classNames?.toggle)}
                disabled={busy}
                aria-busy={keyVerify.isPending}
                onClick={() => keyVerify.mutate(form.getFieldValue("trustDevice"))}
              >
                {keyVerify.isPending ? <Spinner data-icon="inline-start" /> : <KeyRoundIcon aria-hidden data-icon="inline-start" />}
                {keyVerify.isPending ? t.usingSecurityKey : t.useSecurityKey}
              </Button>
            )}
            <Button
              type="button"
              variant="ghost"
              className={cn("w-full text-muted-foreground", classNames?.toggle)}
              disabled={busy}
              onClick={() => switchMode(mode === "code" ? "recovery" : "code")}
            >
              {mode === "code" ? t.useRecovery : delivered ? t.useDeliveredCode : t.useAuthenticator}
            </Button>
          </FieldGroup>
        </form>
      </CardContent>
      {showCancel && (
        <CardFooter className={cn("justify-center text-[13px] text-muted-foreground", classNames?.footer)}>
          <button
            type="button"
            className={cn(
              "cursor-pointer rounded-sm underline-offset-4 hover:text-foreground hover:underline focus-visible:underline focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none",
              classNames?.link,
            )}
            onClick={() => void signOut({ redirectTo: withRedirect(paths.signIn, redirectTo) })}
          >
            {t.cancel}
          </button>
        </CardFooter>
      )}
    </Card>
  )
}
