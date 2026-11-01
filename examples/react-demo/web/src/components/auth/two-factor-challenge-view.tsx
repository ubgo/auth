import { useForm } from "@tanstack/react-form"
import { REGEXP_ONLY_DIGITS } from "input-otp"
import { CircleAlertIcon, ClockIcon, KeyRoundIcon, ShieldCheckIcon } from "lucide-react"
import { useEffect, useId, useRef, useState } from "react"

import { fillText, type ViewHeadingLevel } from "@/components/auth/auth-view"
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

// TwoFactorChallengeView: the second-step card with no data layer. It is
// told which factors the person has (an authenticator app, mailed or texted
// codes, a security key), validates the code itself, and hands every action
// to a callback: onSubmit with the typed values, onSendCode, onSecurityKey,
// onCancel, onSignInAgain. Which call runs, what failed, how many codes went
// out and whether the pending session expired come back in as props.
// TwoFactorChallenge (two-factor-challenge.tsx) is this view wired to
// @ubgo/auth-react; render the view yourself to put the same card on any
// other backend.

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

/** The two ways of answering the challenge. */
export type TwoFactorChallengeMode = "code" | "recovery"

/**
 * What the form hands onSubmit. `code` is trimmed. `method` is the code
 * factor picked in the picker, left out when none was picked (the server then
 * uses the primary factor, and a recovery code needs no method).
 */
export type TwoFactorChallengeValues = {
  readonly mode: TwoFactorChallengeMode
  readonly code: string
  readonly trustDevice: boolean
  readonly method?: string
}

/** Which action is running, so the view can show its spinner and disable the rest; null when nothing is. */
export type TwoFactorChallengePending = "verify" | "send" | "securityKey" | null

/** The factor method whose codes are mailed or texted (twofactor's "delivered"). */
const METHOD_DELIVERED = "delivered"

/** The method of a security key factor (twofactor.MethodSecurityKey). */
const METHOD_SECURITY_KEY = "security_key"

/** The methods that answer with a typed code, in the order the picker lists them. */
const CODE_METHODS: readonly string[] = ["totp", METHOD_DELIVERED]

export type TwoFactorChallengeViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<TwoFactorChallengeSlot, string>>
  /** Text overrides, merged over TWO_FACTOR_CHALLENGE_TEXT. */
  readonly text?: Partial<TwoFactorChallengeText>
  /** The level of the title, 1 by default. */
  readonly headingLevel?: ViewHeadingLevel
  /** The length of a code, 6 by default. */
  readonly digits?: 6 | 8
  /** The methods of the factors the person has on ("totp", "delivered", "security_key"); an authenticator app when empty. */
  readonly factorMethods?: readonly string[]
  /** The primary factor's method; the code form follows it until another code factor is picked. */
  readonly primaryMethod?: string
  /** Offer "trust this device". */
  readonly canTrustDevice?: boolean
  /** Whether "trust this device" starts ticked. */
  readonly defaultTrustDevice?: boolean
  /** The factors are still being read: a placeholder replaces the description and Verify waits. */
  readonly loading?: boolean
  /** The pending session is gone: the card offers a new sign-in instead of the form. */
  readonly expired?: boolean
  /** The running action; the buttons are disabled while it is not null. */
  readonly pending?: TwoFactorChallengePending
  /** A message above the form. */
  readonly formError?: string | null
  /** A message under the code field, such as a wrong code. Each new one clears the field and puts the caret back. */
  readonly fieldError?: string | null
  /** How many codes were sent so far: above zero the button offers a new one and the sent notice shows; each new send refocuses the field. */
  readonly codesSent?: number
  /** Focus the code field on mount. On by default. */
  readonly autoFocus?: boolean
  /** Submit as soon as the last digit is typed or pasted. On by default. */
  readonly autoSubmit?: boolean
  /** The form passed its own checks. Awaited, so a slow call keeps the form submitting. */
  readonly onSubmit?: (values: TwoFactorChallengeValues) => void | Promise<void>
  /** "Send me a code" for a mailed or texted factor. */
  readonly onSendCode?: () => void
  /** "Use a security key", with whether "trust this device" is ticked. */
  readonly onSecurityKey?: (trustDevice: boolean) => void
  /** The code was edited; a good moment to clear fieldError. */
  readonly onCodeChange?: () => void
  /** Switched between code and recovery code; a good moment to clear errors. */
  readonly onModeChange?: (mode: TwoFactorChallengeMode) => void
  /** Another code factor was picked; a good moment to clear fieldError. */
  readonly onCodeMethodChange?: (method: string) => void
  /** "Sign in as someone else"; the footer is hidden when left out. */
  readonly onCancel?: () => void
  /** "Back to sign in" on the expired card. */
  readonly onSignInAgain?: () => void
}

export function TwoFactorChallengeView({
  className,
  classNames,
  text,
  headingLevel = 1,
  digits = 6,
  factorMethods = [],
  primaryMethod,
  canTrustDevice = false,
  defaultTrustDevice = false,
  loading = false,
  expired = false,
  pending = null,
  formError = null,
  fieldError = null,
  codesSent = 0,
  autoFocus = true,
  autoSubmit = true,
  onSubmit,
  onSendCode,
  onSecurityKey,
  onCodeChange,
  onModeChange,
  onCodeMethodChange,
  onCancel,
  onSignInAgain,
}: TwoFactorChallengeViewProps) {
  const t: TwoFactorChallengeText = { ...TWO_FACTOR_CHALLENGE_TEXT, ...text }
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)
  const codeRef = useRef<HTMLInputElement>(null)

  const [mode, setMode] = useState<TwoFactorChallengeMode>("code")
  // The code factor picked when more than one is on; null follows the primary.
  const [codeMethod, setCodeMethod] = useState<string | null>(null)

  const hasSecurityKey = factorMethods.includes(METHOD_SECURITY_KEY)
  // Every code factor the person has on, once each, so the picker offers a choice only when there is one.
  const codeFactors = CODE_METHODS.filter((m) => factorMethods.includes(m))
  const activeCode = codeMethod ?? (primaryMethod !== undefined && CODE_METHODS.includes(primaryMethod) ? primaryMethod : codeFactors[0])
  const delivered = activeCode === METHOD_DELIVERED

  const form = useForm({
    defaultValues: { code: "", trustDevice: defaultTrustDevice },
    onSubmit: async ({ value }) => {
      await onSubmit?.({
        mode,
        code: value.code.trim(),
        trustDevice: canTrustDevice && value.trustDevice,
        ...(mode === "code" && codeMethod !== null ? { method: codeMethod } : {}),
      })
    },
    onSubmitInvalid: () => {
      formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
    },
  })

  // A wrong code is retyped from the start: the field empties and the caret goes back to the first box.
  useEffect(() => {
    if (fieldError === null) return
    form.setFieldValue("code", "")
    requestAnimationFrame(() => codeRef.current?.focus())
  }, [fieldError, form])

  // A code just went out: the caret goes to the field it will be typed into.
  useEffect(() => {
    if (codesSent > 0) requestAnimationFrame(() => codeRef.current?.focus())
  }, [codesSent])

  function switchMode(next: TwoFactorChallengeMode) {
    setMode(next)
    form.reset()
    onModeChange?.(next)
    requestAnimationFrame(() => codeRef.current?.focus())
  }

  const rootClass = cn("w-full max-w-sm", className, classNames?.root)

  if (expired) {
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
          <Button size="lg" className={cn("w-full", classNames?.submit)} onClick={() => onSignInAgain?.()}>
            {t.signInAgain}
          </Button>
        </CardContent>
      </Card>
    )
  }

  const busy = pending !== null
  const verifying = pending === "verify"
  const sending = pending === "send"
  const keyPending = pending === "securityKey"
  const codeLength = digits
  const half = Math.ceil(codeLength / 2)
  const keyOnly = hasSecurityKey && codeFactors.length === 0
  const description =
    mode === "recovery" ? t.recoveryDescription : keyOnly ? t.descriptionSecurityKey : delivered ? t.descriptionDelivered : fillText(t.description, { digits: codeLength })

  return (
    <Card className={rootClass}>
      <CardHeader className={classNames?.header}>
        <div aria-hidden className="mb-1 flex size-8 items-center justify-center rounded-lg bg-muted text-muted-foreground">
          <ShieldCheckIcon className="size-4" />
        </div>
        <CardTitle className={classNames?.title} role="heading" aria-level={headingLevel}>
          {t.title}
        </CardTitle>
        {loading ? (
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
                      form.setFieldValue("code", "")
                      onCodeMethodChange?.(m)
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
                  aria-busy={sending}
                  onClick={() => onSendCode?.()}
                >
                  {sending && <Spinner data-icon="inline-start" />}
                  {sending ? t.sendingCode : codesSent > 0 ? t.resendCode : t.sendCode}
                </Button>
                {/* Polite live region: announces each send, so a screen reader user knows the click worked. */}
                <p role="status" aria-live="polite" className="text-xs text-muted-foreground empty:hidden">
                  {codesSent > 0 ? t.codeSent : ""}
                </p>
              </div>
            )}

            {!(keyOnly && mode === "code") && (
            <form.Field
              name="code"
              validators={{
                onSubmit: ({ value }) => {
                  if (mode === "recovery") return value.trim() === "" ? t.recoveryRequired : undefined
                  return value.length !== codeLength ? fillText(t.codeRequired, { digits: codeLength }) : undefined
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
                        disabled={verifying}
                        value={field.state.value}
                        onChange={(next) => {
                          field.handleChange(next)
                          if (fieldError !== null) onCodeChange?.()
                        }}
                        onComplete={() => {
                          if (autoSubmit && !verifying) void form.handleSubmit()
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
                          if (fieldError !== null) onCodeChange?.()
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

            {canTrustDevice && (
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
            <Button type="submit" size="lg" className={cn("w-full", classNames?.submit)} disabled={busy || loading} aria-busy={verifying}>
              {verifying && <Spinner data-icon="inline-start" />}
              {verifying ? t.submitting : t.submit}
            </Button>
            )}

            {hasSecurityKey && (
              <Button
                type="button"
                variant={keyOnly ? "default" : "outline"}
                size={keyOnly ? "lg" : "default"}
                className={cn("w-full", keyOnly ? classNames?.submit : classNames?.toggle)}
                disabled={busy}
                aria-busy={keyPending}
                onClick={() => onSecurityKey?.(canTrustDevice && form.getFieldValue("trustDevice"))}
              >
                {keyPending ? <Spinner data-icon="inline-start" /> : <KeyRoundIcon aria-hidden data-icon="inline-start" />}
                {keyPending ? t.usingSecurityKey : t.useSecurityKey}
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
      {onCancel !== undefined && (
        <CardFooter className={cn("justify-center text-[13px] text-muted-foreground", classNames?.footer)}>
          <button
            type="button"
            className={cn(
              "cursor-pointer rounded-sm underline-offset-4 hover:text-foreground hover:underline focus-visible:underline focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none",
              classNames?.link,
            )}
            onClick={() => onCancel()}
          >
            {t.cancel}
          </button>
        </CardFooter>
      )}
    </Card>
  )
}
