import { useForm } from "@tanstack/react-form"
import { REGEXP_ONLY_DIGITS } from "input-otp"
import { CheckIcon, CircleAlertIcon, CopyIcon, DownloadIcon, ExternalLinkIcon, KeyRoundIcon, RefreshCwIcon, ShieldCheckIcon, ShieldOffIcon, TriangleAlertIcon } from "lucide-react"
import { useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react"
import { encode } from "uqr"

import { fillText, type ViewHeadingLevel } from "@/components/auth/auth-view"
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

// TwoFactorSetupView: the two-factor settings card with no data layer. It
// draws whichever step it is given (the on/off overview, the QR code or
// "check your inbox" with the first code, the recovery codes shown once),
// validates its own fields, and hands every action to a callback: onEnable,
// onConfirm, onResend, onCancel, onDone, onSignInAgain, and the code dialog
// behind "New recovery codes" and "Turn off" (onDialogChange,
// onDialogSubmit). Which call runs and what failed come back in as props.
// The security keys section is a slot. TwoFactorSetup (two-factor-setup.tsx)
// is this view wired to @ubgo/auth-react; render the view yourself to put
// the same card on any other backend.

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

/** The factor kinds the server can enrol: an authenticator app, or codes mailed or texted at each sign-in. */
export type TwoFactorMethod = "totp" | "delivered"

/** A started enrolment: its method ("delivered" for mailed codes, anything else is an authenticator app), and for an app the otpauth URL and the secret. */
export type TwoFactorEnrollment = {
  readonly method?: string
  readonly url?: string
  readonly secret?: string
}

/** The step the card draws: the on/off overview, an enrolment waiting for its first code, or recovery codes shown once. */
export type TwoFactorSetupStep =
  | { readonly kind: "overview" }
  | { readonly kind: "verify"; readonly enrollment: TwoFactorEnrollment }
  | { readonly kind: "codes"; readonly codes: readonly string[] }

/** The two actions behind a current code: a new set of recovery codes, or turning the factor off. */
export type TwoFactorDialogKind = "disable" | "regenerate"

/** Which card action is running; null when none is. The dialog has its own dialogPending. */
export type TwoFactorSetupPending = "enable" | "confirm" | null

/** The fields that can carry their own error message, on the card and in the dialog. */
export type TwoFactorSetupField = "code" | "password"

/** What the dialog hands onDialogSubmit: the code (trimmed) and the password (empty unless requirePassword). */
export type TwoFactorDialogValues = { readonly code: string; readonly password: string }

/** The method of a security key factor (twofactor.MethodSecurityKey). */
const METHOD_SECURITY_KEY = "security_key"

/** The enrolment method whose codes are mailed or texted. */
const METHOD_DELIVERED = "delivered"

/** The classes that turn the card into a plain block for variant="embedded". */
const EMBEDDED_CLASS = "gap-3 bg-transparent py-0 ring-0 [--card-spacing:0px] *:data-[slot=card-footer]:bg-transparent *:data-[slot=card-footer]:pt-3"

/** How long "Copied" shows after a copy, long enough to read, short enough to copy again. */
const COPIED_FEEDBACK_MS = 2000

export type TwoFactorSetupViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<TwoFactorSetupSlot, string>>
  /** Text overrides, merged over TWO_FACTOR_SETUP_TEXT. */
  readonly text?: Partial<TwoFactorSetupText>
  /** The level of the title, 1 by default. */
  readonly headingLevel?: ViewHeadingLevel
  /** "card" (default) is a standalone card; "embedded" drops the frame and hides the title, for a section with its own heading. */
  readonly variant?: "card" | "embedded"
  /** The factor's state is still being read: a placeholder replaces the description and no action shows. */
  readonly loading?: boolean
  /** Whether two-factor is on. */
  readonly enabled?: boolean
  /** The primary factor's method; "security_key" changes the "on" description. */
  readonly primaryMethod?: string
  /** The step to draw. The overview when left out. */
  readonly step?: TwoFactorSetupStep
  /** Ask for the current password on turning on and in the dialog. */
  readonly requirePassword?: boolean
  /** The code length, 6 by default. */
  readonly digits?: 6 | 8
  /** The downloaded recovery-codes file's name. */
  readonly recoveryCodesFileName?: string
  /** The running card action. */
  readonly pending?: TwoFactorSetupPending
  /** A message above the card's form. */
  readonly formError?: string | null
  /** Messages under the card's fields, by field. */
  readonly fieldErrors?: Partial<Record<TwoFactorSetupField, string>>
  /** The action needs a recent sign-in: the card shows its "Sign in again" prompt. */
  readonly needsFresh?: boolean
  /** The security keys section under the overview, shown once loaded (TwoFactorSetup puts the wired SecurityKeys here). */
  readonly securityKeys?: ReactNode
  /** Which code dialog is open; null or left out when none is. */
  readonly dialog?: TwoFactorDialogKind | null
  /** The dialog's call is running. */
  readonly dialogPending?: boolean
  /** A message above the dialog's form. */
  readonly dialogFormError?: string | null
  /** Messages under the dialog's fields. Each new code error empties the code field. */
  readonly dialogFieldErrors?: Partial<Record<TwoFactorSetupField, string>>
  /** "Turn on" in the overview passed its checks; `password` is empty unless requirePassword. Awaited. */
  readonly onEnable?: (values: { readonly password: string }) => void | Promise<void>
  /** The first code was entered. Awaited; the field empties afterwards. */
  readonly onConfirm?: (code: string) => void | Promise<void>
  /** The first code was edited while it carried an error; a good moment to clear fieldErrors.code. */
  readonly onCodeChange?: () => void
  /** "Send a new code" for a mailed factor. */
  readonly onResend?: () => void
  /** "Cancel" on the enrolment step. */
  readonly onCancel?: () => void
  /** "Done" after the recovery codes were saved. */
  readonly onDone?: () => void
  /** "Sign in again" in the recent-sign-in prompt. */
  readonly onSignInAgain?: () => void
  /** A dialog should open (a kind) or close (null); a good moment to clear errors. */
  readonly onDialogChange?: (kind: TwoFactorDialogKind | null) => void
  /** The dialog's form passed its checks. Awaited, so a slow call keeps it submitting. */
  readonly onDialogSubmit?: (kind: TwoFactorDialogKind, values: TwoFactorDialogValues) => void | Promise<void>
  /** The dialog switched between an authentication code and a recovery code; a good moment to clear its field error. */
  readonly onDialogCodeModeChange?: (useRecovery: boolean) => void
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

export function TwoFactorSetupView({
  className,
  classNames,
  text,
  headingLevel = 1,
  variant = "card",
  loading = false,
  enabled = false,
  primaryMethod,
  step = { kind: "overview" },
  requirePassword = false,
  digits = 6,
  recoveryCodesFileName = "recovery-codes.txt",
  pending = null,
  formError = null,
  fieldErrors = {},
  needsFresh = false,
  securityKeys,
  dialog = null,
  dialogPending = false,
  dialogFormError = null,
  dialogFieldErrors = {},
  onEnable,
  onConfirm,
  onCodeChange,
  onResend,
  onCancel,
  onDone,
  onSignInAgain,
  onDialogChange,
  onDialogSubmit,
  onDialogCodeModeChange,
}: TwoFactorSetupViewProps) {
  const t: TwoFactorSetupText = { ...TWO_FACTOR_SETUP_TEXT, ...text }
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)
  const enabling = pending === "enable"
  const confirming = pending === "confirm"

  const form = useForm({
    defaultValues: { code: "", password: "" },
    onSubmit: async ({ value }) => {
      if (step.kind === "verify") {
        await onConfirm?.(value.code)
        // A refused code is retyped from the start; an accepted one leaves the step.
        form.setFieldValue("code", "")
      } else {
        await onEnable?.({ password: requirePassword ? value.password : "" })
      }
    },
    onSubmitInvalid: () => {
      formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
    },
  })

  const embedded = variant === "embedded"
  const rootClass = cn("w-full max-w-md", embedded && EMBEDDED_CLASS, className, classNames?.root)

  const freshAlert = needsFresh && (
    <Alert className={classNames?.formError}>
      <KeyRoundIcon aria-hidden />
      <AlertTitle>{t.freshTitle}</AlertTitle>
      <AlertDescription className="flex flex-col items-start gap-2">
        {t.freshDescription}
        <Button type="button" size="sm" onClick={() => onSignInAgain?.()}>
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
      {loading ? (
        <Skeleton className="h-4 w-3/4" aria-label={t.loading} />
      ) : (
        <CardDescription className={classNames?.description}>{enabled ? (primaryMethod === METHOD_SECURITY_KEY ? t.descriptionOnSecurityKey : t.descriptionOn) : t.descriptionOff}</CardDescription>
      )}
      {!loading && step.kind === "overview" && (
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
    return (
      <RecoveryCodesCard
        codes={step.codes}
        t={t}
        className={rootClass}
        classNames={classNames}
        headingLevel={headingLevel}
        fileName={recoveryCodesFileName}
        onDone={onDone}
      />
    )
  }

  // Enrolment started: QR code (or "check your inbox") and the first code.
  if (step.kind === "verify") {
    const { enrollment } = step
    const isTotp = enrollment.method !== METHOD_DELIVERED
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
                disabled={enabling}
                onClick={() => onResend?.()}
              >
                {enabling && <Spinner data-icon="inline-start" />}
                {enabling ? t.resending : t.resend}
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
              validators={{ onSubmit: ({ value }) => (value.length !== digits ? fillText(t.codeRequired, { digits }) : undefined) }}
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
                        if (codeError !== undefined) onCodeChange?.()
                      }}
                      onComplete={() => {
                        if (!confirming) void form.handleSubmit()
                      }}
                      invalid={invalid}
                      describedBy={invalid ? `${formId}-code-error` : undefined}
                      disabled={confirming}
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
              <Button
                type="button"
                variant="ghost"
                className={classNames?.secondaryButton}
                onClick={() => {
                  form.reset()
                  onCancel?.()
                }}
                disabled={confirming}
              >
                {t.cancel}
              </Button>
              <Button type="submit" className={classNames?.primaryButton} disabled={confirming} aria-busy={confirming}>
                {confirming && <Spinner data-icon="inline-start" />}
                {confirming ? t.confirming : t.confirm}
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
      {(needsFresh || formError !== null || !loading) && (
        <CardContent className={cn("flex flex-col gap-3.5", classNames?.content)}>
          {freshAlert}
          {errorAlert}
          {loading ? null : enabled ? (
            <div className="flex flex-col gap-2 sm:flex-row">
              <Button type="button" variant="outline" className={classNames?.secondaryButton} onClick={() => onDialogChange?.("regenerate")}>
                <RefreshCwIcon data-icon="inline-start" aria-hidden />
                {t.regenerate}
              </Button>
              <Button type="button" variant="destructive" className={classNames?.secondaryButton} onClick={() => onDialogChange?.("disable")}>
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
                <Button type="submit" className={cn("self-start", classNames?.primaryButton)} disabled={enabling} aria-busy={enabling}>
                  {enabling && <Spinner data-icon="inline-start" />}
                  {enabling ? t.enabling : t.enable}
                </Button>
              </FieldGroup>
            </form>
          )}
          {!loading && securityKeys}
        </CardContent>
      )}
      <CodeActionDialog
        kind={dialog}
        digits={digits}
        requirePassword={requirePassword}
        t={t}
        className={classNames?.dialog}
        pending={dialogPending}
        formError={dialogFormError}
        fieldErrors={dialogFieldErrors}
        onClose={() => onDialogChange?.(null)}
        onSubmit={onDialogSubmit}
        onCodeModeChange={onDialogCodeModeChange}
      />
    </Card>
  )
}

/** The recovery codes, shown once with copy and download, and a tick that they were saved before Done. */
function RecoveryCodesCard({
  codes,
  t,
  className,
  classNames,
  headingLevel,
  fileName,
  onDone,
}: {
  codes: readonly string[]
  t: TwoFactorSetupText
  className: string
  classNames: Partial<Record<TwoFactorSetupSlot, string>> | undefined
  headingLevel: ViewHeadingLevel
  fileName: string
  onDone: (() => void) | undefined
}) {
  const formId = useId()
  // Local to this card, so the tick is gone the next time codes are shown.
  const [codesSaved, setCodesSaved] = useState(false)
  const text = codes.join("\n")
  const download = () => {
    const body = `${fillText(t.codesFileHeader, { date: new Date().toISOString().slice(0, 10) })}\n\n${text}\n`
    const url = URL.createObjectURL(new Blob([body], { type: "text/plain" }))
    const a = document.createElement("a")
    a.href = url
    a.download = fileName
    a.click()
    URL.revokeObjectURL(url)
  }
  return (
    <Card className={className}>
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
            {codes.map((code) => (
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
        <Button type="button" className={classNames?.primaryButton} disabled={!codesSaved} onClick={() => onDone?.()}>
          {t.done}
        </Button>
      </CardFooter>
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
  digits,
  requirePassword,
  t,
  className,
  pending,
  formError,
  fieldErrors,
  onClose,
  onSubmit,
  onCodeModeChange,
}: {
  kind: TwoFactorDialogKind | null
  digits: number
  requirePassword: boolean
  t: TwoFactorSetupText
  className: string | undefined
  pending: boolean
  formError: string | null
  fieldErrors: Partial<Record<TwoFactorSetupField, string>>
  onClose: () => void
  onSubmit: ((kind: TwoFactorDialogKind, values: TwoFactorDialogValues) => void | Promise<void>) | undefined
  onCodeModeChange: ((useRecovery: boolean) => void) | undefined
}) {
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)
  const [useRecovery, setUseRecovery] = useState(false)
  // The last kind shown, so the text does not blank out while the dialog animates closed.
  const [shown, setShown] = useState<TwoFactorDialogKind>("disable")
  if (kind !== null && kind !== shown) setShown(kind)

  const form = useForm({
    defaultValues: { code: "", password: "" },
    onSubmit: async ({ value }) => {
      await onSubmit?.(shown, { code: value.code.trim(), password: requirePassword ? value.password : "" })
    },
    onSubmitInvalid: () => {
      formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
    },
  })

  // A wrong code is retyped from the start.
  const codeError = fieldErrors.code
  useEffect(() => {
    if (codeError !== undefined) form.setFieldValue("code", "")
  }, [codeError, form])

  /** Closes from the dialog itself (Escape, outside click, Cancel): the form starts clean next time. */
  function close() {
    form.reset()
    setUseRecovery(false)
    onClose()
  }

  const isDisable = shown === "disable"

  return (
    <Dialog
      open={kind !== null}
      onOpenChange={(open) => {
        if (!open) close()
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
                  useRecovery ? (value.trim() === "" ? t.recoveryRequired : undefined) : value.length !== digits ? fillText(t.codeRequired, { digits }) : undefined,
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
                        disabled={pending}
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
                const next = !useRecovery
                setUseRecovery(next)
                form.setFieldValue("code", "")
                onCodeModeChange?.(next)
              }}
            >
              {useRecovery ? t.useCode : t.useRecovery}
            </button>
          </FieldGroup>
        </form>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={close} disabled={pending}>
            {t.cancel}
          </Button>
          <Button type="submit" form={formId} variant={isDisable ? "destructive" : "default"} disabled={pending} aria-busy={pending}>
            {pending && <Spinner data-icon="inline-start" />}
            {isDisable ? (pending ? t.disabling : t.disableSubmit) : pending ? t.regenerating : t.regenerateSubmit}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
