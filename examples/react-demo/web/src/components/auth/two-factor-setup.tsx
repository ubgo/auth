import { useForm } from "@tanstack/react-form"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { AuthError, TwofactorEnrollResult, TwofactorStatus } from "@ubgo/auth-client"
import {
  AUTH_QUERY_ROOT,
  format,
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
import { REGEXP_ONLY_DIGITS } from "input-otp"
import { CheckIcon, CircleAlertIcon, CopyIcon, DownloadIcon, ExternalLinkIcon, KeyRoundIcon, RefreshCwIcon, ShieldCheckIcon, ShieldOffIcon, TriangleAlertIcon } from "lucide-react"
import { useId, useMemo, useRef, useState, type ReactNode } from "react"
import { encode } from "uqr"

import { SecurityKeys } from "@/components/auth/security-keys"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardAction, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { InputOTP, InputOTPGroup, InputOTPSeparator, InputOTPSlot } from "@/components/ui/input-otp"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

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

/** Every string TwoFactorSetup shows, with `{name}` placeholders where a value is filled in. */
export type TwoFactorSetupText = {
  title: string
  descriptionOff: string
  descriptionOn: string
  /** The description when the only second factor is a security key. */
  descriptionOnSecurityKey: string
  statusOn: string
  statusOff: string
  enable: string
  enabling: string
  passwordLabel: string
  passwordRequired: string
  scanStep: string
  scanDescription: string
  /** Read by screen readers in place of the QR image. */
  qrLabel: string
  openInApp: string
  secretLabel: string
  copy: string
  copied: string
  deliveredStep: string
  deliveredDescription: string
  resend: string
  resending: string
  confirmStep: string
  codeLabel: string
  /** `{digits}` is the code length. */
  codeRequired: string
  confirm: string
  confirming: string
  cancel: string
  codesTitle: string
  codesDescription: string
  codesWarningTitle: string
  codesWarning: string
  copyCodes: string
  downloadCodes: string
  /** The first line of the downloaded file. `{date}` is today. */
  codesFileHeader: string
  codesSaved: string
  done: string
  regenerate: string
  regenerateTitle: string
  regenerateDescription: string
  regenerateSubmit: string
  regenerating: string
  disable: string
  disableTitle: string
  disableDescription: string
  disableSubmit: string
  disabling: string
  useRecovery: string
  useCode: string
  recoveryLabel: string
  recoveryRequired: string
  freshTitle: string
  freshDescription: string
  signInAgain: string
  loading: string
}

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    twoFactorSetup: TwoFactorSetupText
  }
}

/** The English defaults. Override per app (AuthProvider localization.twoFactorSetup) or per use (localization prop). */
export const TWO_FACTOR_SETUP_TEXT: TwoFactorSetupText = {
  title: "Two-factor authentication",
  descriptionOff: "Ask for a code from your phone as well as your password when you sign in.",
  descriptionOn: "Signing in asks for a code from your authenticator app as well as your password.",
  descriptionOnSecurityKey: "Signing in asks for your security key as well as your password.",
  statusOn: "On",
  statusOff: "Off",
  enable: "Turn on",
  enabling: "Starting…",
  passwordLabel: "Current password",
  passwordRequired: "Enter your password.",
  scanStep: "Scan the QR code",
  scanDescription: "Use an authenticator app such as 1Password, Google Authenticator or Authy.",
  qrLabel: "QR code for your authenticator app",
  openInApp: "Open in an authenticator app on this device",
  secretLabel: "Or enter this key by hand",
  copy: "Copy",
  copied: "Copied",
  deliveredStep: "Check your inbox",
  deliveredDescription: "We sent a code to your verified email address or phone.",
  resend: "Send a new code",
  resending: "Sending…",
  confirmStep: "Enter the code the app shows",
  codeLabel: "Authentication code",
  codeRequired: "Enter the {digits}-digit code.",
  confirm: "Turn on",
  confirming: "Checking…",
  cancel: "Cancel",
  codesTitle: "Save your recovery codes",
  codesDescription: "If you lose your phone, a recovery code is the only way back into your account.",
  codesWarningTitle: "Shown only once",
  codesWarning: "Each code works once. Keep them somewhere safe, such as a password manager.",
  copyCodes: "Copy all",
  downloadCodes: "Download",
  codesFileHeader: "Recovery codes, made {date}. Each code works once.",
  codesSaved: "I have saved these codes",
  done: "Done",
  regenerate: "New recovery codes",
  regenerateTitle: "Make new recovery codes",
  regenerateDescription: "Your old codes stop working. Enter a code from your authenticator app to continue.",
  regenerateSubmit: "Make new codes",
  regenerating: "Making codes…",
  disable: "Turn off",
  disableTitle: "Turn off two-factor authentication?",
  disableDescription: "Signing in will ask only for your password. Enter a code from your authenticator app to confirm.",
  disableSubmit: "Turn off",
  disabling: "Turning off…",
  useRecovery: "Use a recovery code",
  useCode: "Use an authentication code",
  recoveryLabel: "Recovery code",
  recoveryRequired: "Enter a recovery code.",
  freshTitle: "Confirm it's you",
  freshDescription: "Changing two-factor settings needs a recent sign-in.",
  signInAgain: "Sign in again",
  loading: "Loading…",
}

/** The named parts classNames can style. */
export type TwoFactorSetupSlot =
  | "root"
  | "header"
  | "title"
  | "description"
  | "status"
  | "content"
  | "form"
  | "field"
  | "label"
  | "input"
  | "otp"
  | "fieldError"
  | "formError"
  | "qr"
  | "secret"
  | "codes"
  | "code"
  | "primaryButton"
  | "secondaryButton"
  | "dialog"
  | "footer"

/** What changed, handed to onSuccess. */
export type TwoFactorSetupResult = {
  readonly action: "enabled" | "disabled" | "regenerated"
}

/** The factor kinds the server can enrol: an authenticator app, or codes mailed or texted at each sign-in. */
export type TwoFactorMethod = "totp" | "delivered"

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

/** The method of a security key factor (twofactor.MethodSecurityKey). */
const METHOD_SECURITY_KEY = "security_key"

/** The heading level of a section under the card's title. */
const SUB_LEVEL: Record<HeadingLevel, HeadingLevel> = { 1: 2, 2: 3, 3: 4, 4: 5, 5: 6, 6: 6 }

/** The classes that turn the card into a plain block for variant="embedded". */
const EMBEDDED_CLASS = "gap-3 bg-transparent py-0 ring-0 [--card-spacing:0px] *:data-[slot=card-footer]:bg-transparent *:data-[slot=card-footer]:pt-3"

/** The factor's status, shared with TwoFactorChallenge's key so either refreshes the other. */
const STATUS_QUERY_KEY = [...AUTH_QUERY_ROOT, "twofactor", "status"] as const

/** How long "Copied" shows after a copy, long enough to read, short enough to copy again. */
const COPIED_FEEDBACK_MS = 2000

/** The error that means the action needs a recent sign-in. */
const FRESH_REQUIRED: AnyErrorCode = "auth.fresh_session_required"

/** Error codes that belong under the code field rather than above the form. */
const CODE_FIELD_ERRORS: ReadonlySet<AnyErrorCode> = new Set<AnyErrorCode>(["twofactor.code_invalid"])

/** Error codes that belong under the password field. */
const PASSWORD_FIELD_ERRORS: ReadonlySet<AnyErrorCode> = new Set<AnyErrorCode>(["password.invalid_credentials"])

/** The card's steps once enrolment starts; "overview" is the on/off card. */
type Step =
  | { readonly kind: "overview" }
  | { readonly kind: "verify"; readonly enrollment: TwofactorEnrollResult; readonly password: string }
  | { readonly kind: "codes"; readonly codes: readonly string[]; readonly action: "enabled" | "regenerated" }

/** Appends `redirectTo` to a path, so the sign-in page can come back here. */
function withRedirect(path: string, redirectTo: string): string {
  const joiner = path.includes("?") ? "&" : "?"
  return `${path}${joiner}redirectTo=${encodeURIComponent(redirectTo)}`
}

/** Splits a base32 secret into groups of four, the way authenticator apps print it; a line breaks only between groups. */
function secretGroups(secret: string): readonly string[] {
  return secret.match(/.{1,4}/g) ?? []
}

/** Copies text and reports success; a blocked clipboard (no permission, http) is a false, not a throw. */
async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

/** A "Copy" button that says "Copied" for a moment after it worked. */
function CopyButton({ text, label, copiedLabel, className }: { text: string; label: string; copiedLabel: string; className?: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      className={className}
      onClick={async () => {
        if (!(await copyText(text))) return
        setCopied(true)
        window.setTimeout(() => setCopied(false), COPIED_FEEDBACK_MS)
      }}
    >
      {copied ? <CheckIcon data-icon="inline-start" aria-hidden /> : <CopyIcon data-icon="inline-start" aria-hidden />}
      {/* The label change is announced, so the click is confirmed without sight of the icon. */}
      <span aria-live="polite">{copied ? copiedLabel : label}</span>
    </Button>
  )
}

/**
 * The otpauth URL as a QR code, drawn as one SVG path from the module matrix
 * (no innerHTML). Always dark on white, whatever the theme: scanners expect
 * that contrast and some read an inverted code badly, so this is the one
 * place the component does not follow the theme's colours.
 */
function QRCode({ value, label, className }: { value: string; label: string; className?: string }) {
  const { path, size } = useMemo(() => {
    const qr = encode(value, { ecc: "M", border: 0 })
    let d = ""
    qr.data.forEach((row, y) =>
      row.forEach((dark, x) => {
        if (dark) d += `M${x} ${y}h1v1h-1z`
      }),
    )
    return { path: d, size: qr.size }
  }, [value])
  return (
    <div className={cn("rounded-lg bg-white p-2.5 ring-1 ring-foreground/10", className)}>
      <svg role="img" aria-label={label} viewBox={`0 0 ${size} ${size}`} shapeRendering="crispEdges" className="size-36">
        <path d={path} fill="#000" />
      </svg>
    </div>
  )
}

/** A numbered step heading inside the enrolment card. */
function StepHeading({ n, children }: { n: number; children: ReactNode }) {
  return (
    <div className="flex items-center gap-2 text-[13px] font-medium">
      <span aria-hidden className="flex size-5 shrink-0 items-center justify-center rounded-full bg-muted text-xs tabular-nums text-muted-foreground">
        {n}
      </span>
      {children}
    </div>
  )
}

/** A one-time-code input split in two groups, shared by the confirm step and both dialogs. */
function CodeInput({
  id,
  digits,
  value,
  onChange,
  onComplete,
  invalid,
  describedBy,
  disabled,
  autoFocus,
  className,
}: {
  id: string
  digits: number
  value: string
  onChange: (value: string) => void
  onComplete?: () => void
  invalid: boolean
  describedBy: string | undefined
  disabled: boolean
  autoFocus: boolean
  className: string | undefined
}) {
  const half = Math.ceil(digits / 2)
  return (
    <InputOTP
      id={id}
      name="code"
      maxLength={digits}
      pattern={REGEXP_ONLY_DIGITS}
      inputMode="numeric"
      autoComplete="one-time-code"
      autoFocus={autoFocus}
      disabled={disabled}
      value={value}
      onChange={onChange}
      onComplete={onComplete}
      aria-invalid={invalid}
      aria-describedby={describedBy}
      containerClassName={className}
    >
      <InputOTPGroup>
        {Array.from({ length: half }, (_, i) => (
          <InputOTPSlot key={i} index={i} aria-invalid={invalid} className="size-9 text-sm" />
        ))}
      </InputOTPGroup>
      <InputOTPSeparator className="text-muted-foreground" />
      <InputOTPGroup>
        {Array.from({ length: digits - half }, (_, i) => (
          <InputOTPSlot key={half + i} index={half + i} aria-invalid={invalid} className="size-9 text-sm" />
        ))}
      </InputOTPGroup>
    </InputOTP>
  )
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
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)

  const [step, setStep] = useState<Step>({ kind: "overview" })
  const [formError, setFormError] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<"code" | "password", string>>>({})
  const [needsFresh, setNeedsFresh] = useState(false)
  const [dialog, setDialog] = useState<"disable" | "regenerate" | null>(null)
  const [codesSaved, setCodesSaved] = useState(false)

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
    setCodesSaved(false)
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
        form.setFieldValue("code", "")
        return
      }
      await queryClient.invalidateQueries({ queryKey: STATUS_QUERY_KEY })
      setStep({ kind: "codes", codes: data.codes ?? [], action: "enabled" })
    },
  })

  const form = useForm({
    defaultValues: { code: "", password: "" },
    onSubmit: async ({ value }) => {
      clearErrors()
      if (step.kind === "verify") await confirm.mutateAsync(value.code)
      else await enroll.mutateAsync(value.password)
    },
    onSubmitInvalid: () => {
      formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
    },
  })

  function cancelEnrollment() {
    clearErrors()
    form.reset()
    setStep({ kind: "overview" })
  }

  // No twofactor() in the client: nothing to set up, so nothing renders (CONTRACT.md rule 2).
  if (twofactor === null) return null

  const embedded = variant === "embedded"
  const rootClass = cn("w-full max-w-md", embedded && EMBEDDED_CLASS, className, classNames?.root)
  const here = typeof window === "undefined" ? paths.afterSignIn : window.location.pathname + window.location.search

  const freshAlert = needsFresh && (
    <Alert className={classNames?.formError}>
      <KeyRoundIcon aria-hidden />
      <AlertTitle>{t.freshTitle}</AlertTitle>
      <AlertDescription className="flex flex-col items-start gap-2">
        {t.freshDescription}
        <Button type="button" size="sm" onClick={() => void signOut({ redirectTo: withRedirect(paths.signIn, here) })}>
          {t.signInAgain}
        </Button>
      </AlertDescription>
    </Alert>
  )

  const errorAlert = formError !== null && (
    <Alert variant="destructive" className={classNames?.formError}>
      <CircleAlertIcon aria-hidden />
      <AlertDescription>{formError}</AlertDescription>
    </Alert>
  )

  const header = (
    <CardHeader className={classNames?.header}>
      <CardTitle
        className={cn("flex items-center gap-2", embedded && "sr-only", classNames?.title)}
        role="heading"
        aria-level={headingLevel}
      >
        <ShieldCheckIcon aria-hidden className="size-4 text-muted-foreground" />
        {t.title}
      </CardTitle>
      {status.isPending ? (
        <Skeleton className="h-4 w-3/4" aria-label={t.loading} />
      ) : (
        <CardDescription className={classNames?.description}>{enabled ? (status.data?.status?.method === METHOD_SECURITY_KEY ? t.descriptionOnSecurityKey : t.descriptionOn) : t.descriptionOff}</CardDescription>
      )}
      {!status.isPending && step.kind === "overview" && (
        <CardAction>
          <Badge variant={enabled ? "default" : "secondary"} className={classNames?.status}>
            {enabled ? t.statusOn : t.statusOff}
          </Badge>
        </CardAction>
      )}
    </CardHeader>
  )

  // Recovery codes: shown once, after confirm or a new set.
  if (step.kind === "codes") {
    const text = step.codes.join("\n")
    const download = () => {
      const body = `${format(t.codesFileHeader, { date: new Date().toISOString().slice(0, 10) })}\n\n${text}\n`
      const url = URL.createObjectURL(new Blob([body], { type: "text/plain" }))
      const a = document.createElement("a")
      a.href = url
      a.download = recoveryCodesFileName
      a.click()
      URL.revokeObjectURL(url)
    }
    return (
      <Card className={rootClass}>
        <CardHeader className={classNames?.header}>
          <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
            <ShieldCheckIcon aria-hidden className="size-4 text-muted-foreground" />
            {t.codesTitle}
          </CardTitle>
          <CardDescription className={classNames?.description}>{t.codesDescription}</CardDescription>
        </CardHeader>
        <CardContent className={cn("flex flex-col gap-3.5", classNames?.content)}>
          <Alert>
            <TriangleAlertIcon aria-hidden />
            <AlertTitle>{t.codesWarningTitle}</AlertTitle>
            <AlertDescription>{t.codesWarning}</AlertDescription>
          </Alert>
          {/* Two columns only when the card is wide enough to keep each code on one line. */}
          <div className="@container">
            <ul
              aria-label={t.codesTitle}
              className={cn("grid grid-cols-1 gap-x-4 gap-y-1.5 rounded-lg border bg-muted/40 p-3 font-mono text-[13px] tabular-nums @[22rem]:grid-cols-2", classNames?.codes)}
            >
              {step.codes.map((code) => (
                <li key={code} className={cn("text-center whitespace-nowrap select-all", classNames?.code)}>
                  {code}
                </li>
              ))}
            </ul>
          </div>
          <div className="flex gap-2">
            <CopyButton text={text} label={t.copyCodes} copiedLabel={t.copied} className={cn("flex-1", classNames?.secondaryButton)} />
            <Button type="button" variant="outline" size="sm" className={cn("flex-1", classNames?.secondaryButton)} onClick={download}>
              <DownloadIcon data-icon="inline-start" aria-hidden />
              {t.downloadCodes}
            </Button>
          </div>
          <Field orientation="horizontal">
            <Checkbox id={`${formId}-saved`} checked={codesSaved} onCheckedChange={(checked) => setCodesSaved(checked)} />
            <FieldLabel htmlFor={`${formId}-saved`} className="font-normal">
              {t.codesSaved}
            </FieldLabel>
          </Field>
        </CardContent>
        <CardFooter className={cn("justify-end border-t", classNames?.footer)}>
          <Button type="button" className={classNames?.primaryButton} disabled={!codesSaved} onClick={() => void finish(step.action)}>
            {t.done}
          </Button>
        </CardFooter>
      </Card>
    )
  }

  // Enrolment started: QR code (or "check your inbox") and the first code.
  if (step.kind === "verify") {
    const { enrollment } = step
    const isTotp = enrollment.method !== "delivered"
    const codeError = fieldErrors.code
    return (
      <Card className={rootClass}>
        {header}
        <CardContent className={cn("flex flex-col gap-4", classNames?.content)}>
          {freshAlert}
          {errorAlert}
          {isTotp ? (
            <section className="flex flex-col gap-3">
              <StepHeading n={1}>{t.scanStep}</StepHeading>
              <p className="text-[13px] text-muted-foreground sm:pl-7">{t.scanDescription}</p>
              <div className="flex flex-col items-center gap-3 sm:flex-row sm:items-start sm:pl-7">
                {enrollment.url !== undefined && <QRCode value={enrollment.url} label={t.qrLabel} className={classNames?.qr} />}
                <div className="flex w-full min-w-0 flex-col gap-2">
                  {enrollment.secret !== undefined && (
                    <div className="flex flex-col gap-1.5">
                      <span className="text-xs text-muted-foreground" id={`${formId}-secret-label`}>
                        {t.secretLabel}
                      </span>
                      <code
                        aria-labelledby={`${formId}-secret-label`}
                        className={cn("flex flex-wrap gap-x-[1ch] rounded-md border bg-muted/40 px-2 py-1.5 font-mono text-[13px] select-all", classNames?.secret)}
                      >
                        {secretGroups(enrollment.secret).map((group, i) => (
                          <span key={i} className="whitespace-nowrap">
                            {group}
                          </span>
                        ))}
                      </code>
                      <CopyButton text={enrollment.secret} label={t.copy} copiedLabel={t.copied} className={cn("self-start", classNames?.secondaryButton)} />
                    </div>
                  )}
                  {enrollment.url !== undefined && (
                    <a
                      href={enrollment.url}
                      className="inline-flex items-center gap-1 text-xs text-muted-foreground underline-offset-4 hover:text-foreground hover:underline focus-visible:underline focus-visible:outline-none"
                    >
                      <ExternalLinkIcon aria-hidden className="size-3" />
                      {t.openInApp}
                    </a>
                  )}
                </div>
              </div>
            </section>
          ) : (
            <section className="flex flex-col gap-2">
              <StepHeading n={1}>{t.deliveredStep}</StepHeading>
              <p className="text-[13px] text-muted-foreground sm:pl-7" role="status">
                {t.deliveredDescription}
              </p>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className={cn("self-start sm:ml-7", classNames?.secondaryButton)}
                disabled={enroll.isPending}
                onClick={() => {
                  clearErrors()
                  enroll.mutate(step.password)
                }}
              >
                {enroll.isPending && <Spinner data-icon="inline-start" />}
                {enroll.isPending ? t.resending : t.resend}
              </Button>
            </section>
          )}

          <form
            ref={formRef}
            noValidate
            className={cn("flex flex-col gap-3", classNames?.form)}
            onSubmit={(e) => {
              e.preventDefault()
              e.stopPropagation()
              void form.handleSubmit()
            }}
          >
            <StepHeading n={2}>{t.confirmStep}</StepHeading>
            <form.Field
              name="code"
              validators={{ onSubmit: ({ value }) => (value.length !== digits ? format(t.codeRequired, { digits }) : undefined) }}
            >
              {(field) => {
                const message = field.state.meta.errors[0] ?? codeError
                const invalid = message !== undefined
                return (
                  <Field data-invalid={invalid} className={cn("sm:pl-7", classNames?.field)}>
                    <FieldLabel htmlFor={`${formId}-code`} className={cn("sr-only", classNames?.label)}>
                      {t.codeLabel}
                    </FieldLabel>
                    <CodeInput
                      id={`${formId}-code`}
                      digits={digits}
                      value={field.state.value}
                      onChange={(v) => {
                        field.handleChange(v)
                        if (codeError !== undefined) setFieldErrors({})
                      }}
                      onComplete={() => {
                        if (!confirm.isPending) void form.handleSubmit()
                      }}
                      invalid={invalid}
                      describedBy={invalid ? `${formId}-code-error` : undefined}
                      disabled={confirm.isPending}
                      autoFocus={false}
                      className={classNames?.otp}
                    />
                    {invalid && (
                      <FieldError id={`${formId}-code-error`} className={classNames?.fieldError}>
                        {message}
                      </FieldError>
                    )}
                  </Field>
                )
              }}
            </form.Field>
            <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
              <Button type="button" variant="ghost" className={classNames?.secondaryButton} onClick={cancelEnrollment} disabled={confirm.isPending}>
                {t.cancel}
              </Button>
              <Button type="submit" className={classNames?.primaryButton} disabled={confirm.isPending} aria-busy={confirm.isPending}>
                {confirm.isPending && <Spinner data-icon="inline-start" />}
                {confirm.isPending ? t.confirming : t.confirm}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    )
  }

  // Overview: off (turn on) or on (new codes, turn off).
  return (
    <Card className={rootClass}>
      {header}
      {(needsFresh || formError !== null || !status.isPending) && (
        <CardContent className={cn("flex flex-col gap-3.5", classNames?.content)}>
          {freshAlert}
          {errorAlert}
          {status.isPending ? null : enabled ? (
            <div className="flex flex-col gap-2 sm:flex-row">
              <Button
                type="button"
                variant="outline"
                className={classNames?.secondaryButton}
                onClick={() => {
                  clearErrors()
                  setDialog("regenerate")
                }}
              >
                <RefreshCwIcon data-icon="inline-start" aria-hidden />
                {t.regenerate}
              </Button>
              <Button
                type="button"
                variant="destructive"
                className={classNames?.secondaryButton}
                onClick={() => {
                  clearErrors()
                  setDialog("disable")
                }}
              >
                <ShieldOffIcon data-icon="inline-start" aria-hidden />
                {t.disable}
              </Button>
            </div>
          ) : (
            <form
              ref={formRef}
              noValidate
              className={classNames?.form}
              onSubmit={(e) => {
                e.preventDefault()
                e.stopPropagation()
                void form.handleSubmit()
              }}
            >
              <FieldGroup>
                {requirePassword && (
                  <form.Field name="password" validators={{ onSubmit: ({ value }) => (value === "" ? t.passwordRequired : undefined) }}>
                    {(field) => {
                      const message = field.state.meta.errors[0] ?? fieldErrors.password
                      const invalid = message !== undefined
                      return (
                        <Field data-invalid={invalid} className={classNames?.field}>
                          <FieldLabel htmlFor={`${formId}-password`} className={classNames?.label}>
                            {t.passwordLabel}
                          </FieldLabel>
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
                <Button type="submit" className={cn("self-start", classNames?.primaryButton)} disabled={enroll.isPending} aria-busy={enroll.isPending}>
                  {enroll.isPending && <Spinner data-icon="inline-start" />}
                  {enroll.isPending ? t.enabling : t.enable}
                </Button>
              </FieldGroup>
            </form>
          )}
          {securityKeys && !status.isPending && (
            <SecurityKeys
              variant="embedded"
              headingLevel={SUB_LEVEL[headingLevel]}
              onSuccess={(r) => {
                // A first key turns two-factor on and the last one removed turns it
                // off: the same outcome as the code flow, reported the same way.
                if (r.twoFactorEnabled !== enabled) void finish(r.twoFactorEnabled ? "enabled" : "disabled")
              }}
            />
          )}
        </CardContent>
      )}
      <CodeActionDialog
        kind={dialog}
        onOpenChange={(open) => {
          if (!open) setDialog(null)
        }}
        digits={digits}
        requirePassword={requirePassword}
        t={t}
        className={classNames?.dialog}
        onFresh={(retry) => {
          // Closed while the re-sign-in dialog is up, reopened by the retry so
          // its progress (and any new error) shows where the user left it.
          const kind = dialog
          setDialog(null)
          freshRequired(async () => {
            setDialog(kind)
            await retry()
          })
        }}
        onDone={async (kind, codes) => {
          setDialog(null)
          if (kind === "regenerate") setStep({ kind: "codes", codes, action: "regenerated" })
          else await finish("disabled")
        }}
      />
    </Card>
  )
}

/**
 * The dialog behind "New recovery codes" and "Turn off": both need a current
 * code (or a recovery code) and, under RequirePassword, the password. Its own
 * form, so a wrong code here leaves the card untouched.
 */
function CodeActionDialog({
  kind,
  onOpenChange,
  digits,
  requirePassword,
  t,
  className,
  onFresh,
  onDone,
}: {
  kind: "disable" | "regenerate" | null
  onOpenChange: (open: boolean) => void
  digits: number
  requirePassword: boolean
  t: TwoFactorSetupText
  className: string | undefined
  /** The action needs a fresh sign-in; `retry` reruns it with the same code and password. */
  onFresh: (retry: () => Promise<void>) => void
  onDone: (kind: "disable" | "regenerate", codes: readonly string[]) => Promise<void>
}) {
  const twofactor = usePluginClient("twofactor")
  const messageFor = useErrorMessage()
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)
  const [useRecovery, setUseRecovery] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<"code" | "password", string>>>({})
  // The last kind shown, so the text does not blank out while the dialog animates closed.
  const [shown, setShown] = useState<"disable" | "regenerate">("disable")
  if (kind !== null && kind !== shown) setShown(kind)

  const action = useMutation({
    mutationFn: async (value: { code: string; password: string }) => {
      if (twofactor === null) throw new Error("TwoFactorSetup: twofactor plugin missing")
      const input = requirePassword ? { code: value.code.trim(), password: value.password } : { code: value.code.trim() }
      if (shown === "disable") {
        const { error } = await twofactor.disable(input)
        return { error, codes: [] as readonly string[] }
      }
      const { data, error } = await twofactor.recoveryCodes(input)
      return { error, codes: data?.codes ?? [] }
    },
    onSuccess: async ({ error, codes }, value) => {
      if (error === null) {
        await onDone(shown, codes)
        return
      }
      if (error.code === FRESH_REQUIRED)
        onFresh(async () => {
          await action.mutateAsync(value)
        })
      else if (CODE_FIELD_ERRORS.has(error.code)) {
        setFieldErrors({ code: messageFor(error) })
        form.setFieldValue("code", "")
      } else if (PASSWORD_FIELD_ERRORS.has(error.code) && requirePassword) setFieldErrors({ password: messageFor(error) })
      else setFormError(messageFor(error))
    },
  })

  const form = useForm({
    defaultValues: { code: "", password: "" },
    onSubmit: async ({ value }) => {
      setFormError(null)
      setFieldErrors({})
      await action.mutateAsync(value)
    },
    onSubmitInvalid: () => {
      formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
    },
  })

  const isDisable = shown === "disable"

  return (
    <Dialog
      open={kind !== null}
      onOpenChange={(open) => {
        if (!open) {
          form.reset()
          setUseRecovery(false)
          setFormError(null)
          setFieldErrors({})
        }
        onOpenChange(open)
      }}
    >
      <DialogContent className={className}>
        <DialogHeader>
          <DialogTitle>{isDisable ? t.disableTitle : t.regenerateTitle}</DialogTitle>
          <DialogDescription>{isDisable ? t.disableDescription : t.regenerateDescription}</DialogDescription>
        </DialogHeader>
        <form
          ref={formRef}
          id={formId}
          noValidate
          onSubmit={(e) => {
            e.preventDefault()
            e.stopPropagation()
            void form.handleSubmit()
          }}
        >
          <FieldGroup>
            {formError !== null && (
              <Alert variant="destructive">
                <CircleAlertIcon aria-hidden />
                <AlertDescription>{formError}</AlertDescription>
              </Alert>
            )}
            {requirePassword && (
              <form.Field name="password" validators={{ onSubmit: ({ value }) => (value === "" ? t.passwordRequired : undefined) }}>
                {(field) => {
                  const message = field.state.meta.errors[0] ?? fieldErrors.password
                  const invalid = message !== undefined
                  return (
                    <Field data-invalid={invalid}>
                      <FieldLabel htmlFor={`${formId}-password`}>{t.passwordLabel}</FieldLabel>
                      <Input
                        id={`${formId}-password`}
                        type="password"
                        autoComplete="current-password"
                        value={field.state.value}
                        onChange={(e) => field.handleChange(e.target.value)}
                        aria-invalid={invalid}
                        aria-describedby={invalid ? `${formId}-password-error` : undefined}
                      />
                      {invalid && <FieldError id={`${formId}-password-error`}>{message}</FieldError>}
                    </Field>
                  )
                }}
              </form.Field>
            )}
            <form.Field
              name="code"
              validators={{
                onSubmit: ({ value }) =>
                  useRecovery ? (value.trim() === "" ? t.recoveryRequired : undefined) : value.length !== digits ? format(t.codeRequired, { digits }) : undefined,
              }}
            >
              {(field) => {
                const message = field.state.meta.errors[0] ?? fieldErrors.code
                const invalid = message !== undefined
                const describedBy = invalid ? `${formId}-code-error` : undefined
                return (
                  <Field data-invalid={invalid}>
                    <FieldLabel htmlFor={`${formId}-code`}>{useRecovery ? t.recoveryLabel : t.codeLabel}</FieldLabel>
                    {useRecovery ? (
                      <Input
                        id={`${formId}-code`}
                        autoComplete="off"
                        autoCapitalize="characters"
                        spellCheck={false}
                        autoFocus
                        value={field.state.value}
                        onChange={(e) => field.handleChange(e.target.value)}
                        aria-invalid={invalid}
                        aria-describedby={describedBy}
                        className="font-mono tracking-wider uppercase"
                      />
                    ) : (
                      <CodeInput
                        id={`${formId}-code`}
                        digits={digits}
                        value={field.state.value}
                        onChange={(v) => field.handleChange(v)}
                        invalid={invalid}
                        describedBy={describedBy}
                        disabled={action.isPending}
                        autoFocus={!requirePassword}
                        className={undefined}
                      />
                    )}
                    {invalid && <FieldError id={`${formId}-code-error`}>{message}</FieldError>}
                  </Field>
                )
              }}
            </form.Field>
            <button
              type="button"
              className="w-fit cursor-pointer self-start rounded-sm text-xs text-muted-foreground underline-offset-4 hover:text-foreground hover:underline focus-visible:underline focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
              onClick={() => {
                setUseRecovery((v) => !v)
                form.setFieldValue("code", "")
                setFieldErrors({})
              }}
            >
              {useRecovery ? t.useCode : t.useRecovery}
            </button>
          </FieldGroup>
        </form>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={action.isPending}>
            {t.cancel}
          </Button>
          <Button type="submit" form={formId} variant={isDisable ? "destructive" : "default"} disabled={action.isPending} aria-busy={action.isPending}>
            {action.isPending && <Spinner data-icon="inline-start" />}
            {isDisable ? (action.isPending ? t.disabling : t.disableSubmit) : action.isPending ? t.regenerating : t.regenerateSubmit}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
