import { CircleAlertIcon, KeyRoundIcon, Trash2Icon } from "lucide-react"
import { useEffect, useId, useState, type FormEvent } from "react"

import { fillText, type ViewHeadingLevel } from "@/components/auth/auth-view"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldError, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// SecurityKeysView: the security keys list with no data layer. It lists the
// keys it is given, takes a name for a new one, and asks for proof (a code,
// or a tap of a key) in a dialog when it is told to; every action goes to a
// callback: onAdd with the name, onRemove with the key, onProofCode,
// onProofKey, onProofCancel, onRecoveryDone. Which call runs, what failed,
// the status line and the first key's recovery codes come back in as props.
// SecurityKeys (security-keys.tsx) is this view wired to @ubgo/auth-react;
// render the view yourself to put the same list on any other backend.

/** Every string SecurityKeys shows. */
export type SecurityKeysText = {
  title: string
  description: string
  empty: string
  /** `{date}` is when the key was added. */
  added: string
  add: string
  adding: string
  nameLabel: string
  namePlaceholder: string
  /** `{name}` is the key's name. */
  removeLabel: string
  proofTitleAdd: string
  proofTitleRemove: string
  proofDescription: string
  codeLabel: string
  codeRequired: string
  useKeyForProof: string
  confirm: string
  cancel: string
  cancelled: string
  alreadyRegistered: string
  unsupported: string
  addedStatus: string
  removedStatus: string
  recoveryTitle: string
  recoveryDescription: string
  recoveryDone: string
}

/** The English defaults. Override per app (AuthProvider localization.securityKeys) or per use (localization prop). */
export const SECURITY_KEYS_TEXT: SecurityKeysText = {
  title: "Security keys",
  description: "A key you tap or touch, or the one built into this device, as your second step at sign-in.",
  empty: "No security keys yet.",
  added: "Added {date}",
  add: "Add a security key",
  adding: "Waiting for your key…",
  nameLabel: "Name",
  namePlaceholder: "YubiKey",
  removeLabel: "Remove {name}",
  proofTitleAdd: "Confirm it's you",
  proofTitleRemove: "Confirm it's you",
  proofDescription: "Enter a code from your authenticator app, a code we sent you, or a recovery code; or tap one of your security keys.",
  codeLabel: "Code",
  codeRequired: "Enter a code.",
  useKeyForProof: "Use a security key instead",
  confirm: "Continue",
  cancel: "Cancel",
  cancelled: "The security key prompt was closed. Try again.",
  alreadyRegistered: "This key is already registered.",
  unsupported: "This browser cannot use security keys.",
  addedStatus: "Security key added.",
  removedStatus: "Security key removed.",
  recoveryTitle: "Save your recovery codes",
  recoveryDescription: "Two-factor authentication is on. Each code signs you in once if you lose your key; this is the only time they are shown.",
  recoveryDone: "I saved them",
}

/** The named parts classNames can style. */
export type SecurityKeysSlot = "root" | "header" | "title" | "description" | "content" | "list" | "key" | "add" | "input" | "formError" | "status" | "dialog"

/** One registered key as the list shows it: its id (handed back to onRemove with the key), its name (the title when empty), and when it was added (an ISO date). */
export type SecurityKeyItem = {
  readonly id?: string
  readonly name?: string
  readonly createdAt: string
}

/** Which call is running, so the view can show its spinner and disable the rest; null when none is. */
export type SecurityKeysPending = "add" | "remove" | null

/** What the proof dialog is asking proof for; null when it is closed. */
export type SecurityKeysProof = "add" | "remove" | null

/** The longest key name the input takes, so a name stays a short label. */
const MAX_NAME_LENGTH = 64

export type SecurityKeysViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<SecurityKeysSlot, string>>
  /** Text overrides, merged over SECURITY_KEYS_TEXT. */
  readonly text?: Partial<SecurityKeysText>
  /** The level of the title, 1 by default. */
  readonly headingLevel?: ViewHeadingLevel
  /** "card" (default) is a standalone card; "embedded" is a titled section with no card, for a card with its own frame. */
  readonly variant?: "card" | "embedded"
  /** The keys are still being read: a placeholder replaces the list and adding waits. */
  readonly loading?: boolean
  /** The registered keys. */
  readonly keys?: readonly SecurityKeyItem[]
  /** The name field's value, for a parent that controls it; the view keeps its own when left out. */
  readonly name?: string
  /** The name field was edited (always called, controlled or not). */
  readonly onNameChange?: (name: string) => void
  /** The running call. */
  readonly pending?: SecurityKeysPending
  /** A message above the list. */
  readonly formError?: string | null
  /** A short polite status line, such as "Security key added." */
  readonly status?: string | null
  /** The first key's recovery codes, shown once until onRecoveryDone; nothing shows while empty. */
  readonly recoveryCodes?: readonly string[]
  /** Opens the proof dialog for adding or removing a key. */
  readonly proof?: SecurityKeysProof
  /** A message under the proof dialog's code, such as a wrong code. */
  readonly proofError?: string | null
  /** The add form was submitted, with the name as typed. */
  readonly onAdd?: (name: string) => void
  /** A key's remove button was pressed. */
  readonly onRemove?: (key: SecurityKeyItem) => void
  /** The proof dialog's code was submitted, trimmed and not empty. Awaited, so a slow call keeps it busy. */
  readonly onProofCode?: (code: string) => void | Promise<void>
  /** "Use a security key instead" in the proof dialog. */
  readonly onProofKey?: () => void
  /** The proof dialog's code was edited; a good moment to clear proofError. */
  readonly onProofCodeChange?: () => void
  /** The proof dialog was closed without proof. */
  readonly onProofCancel?: () => void
  /** "I saved them" under the recovery codes. */
  readonly onRecoveryDone?: () => void
}

/** A key's added date in the reader's locale. */
function formatDate(iso: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(new Date(iso))
}

export function SecurityKeysView({
  className,
  classNames,
  text,
  headingLevel = 1,
  variant = "card",
  loading = false,
  keys = [],
  name: controlledName,
  onNameChange,
  pending = null,
  formError = null,
  status = null,
  recoveryCodes = [],
  proof = null,
  proofError = null,
  onAdd,
  onRemove,
  onProofCode,
  onProofKey,
  onProofCodeChange,
  onProofCancel,
  onRecoveryDone,
}: SecurityKeysViewProps) {
  const t: SecurityKeysText = { ...SECURITY_KEYS_TEXT, ...text }
  const formId = useId()
  const [localName, setLocalName] = useState("")
  const name = controlledName ?? localName
  const busy = pending !== null

  const submitAdd = (e: FormEvent) => {
    e.preventDefault()
    onAdd?.(name)
  }

  const content = (
    <>
        {formError !== null && (
          <Alert variant="destructive" className={classNames?.formError}>
            <CircleAlertIcon aria-hidden />
            <AlertDescription>{formError}</AlertDescription>
          </Alert>
        )}
        <p role="status" className={cn("text-xs text-muted-foreground empty:hidden", classNames?.status)}>
          {status}
        </p>
        {recoveryCodes.length > 0 && (
          <Alert className="flex flex-col gap-2">
            <AlertDescription className="flex flex-col gap-2">
              <span className="font-medium text-foreground">{t.recoveryTitle}</span>
              <span>{t.recoveryDescription}</span>
              <ul className="grid grid-cols-2 gap-1 font-mono text-xs text-foreground">
                {recoveryCodes.map((c) => (
                  <li key={c}>{c}</li>
                ))}
              </ul>
              <Button type="button" size="sm" className="self-start" onClick={() => onRecoveryDone?.()}>
                {t.recoveryDone}
              </Button>
            </AlertDescription>
          </Alert>
        )}
        {loading ? (
          <Skeleton aria-hidden className="h-10 w-full rounded-lg" />
        ) : keys.length === 0 ? (
          <p className="text-[13px] text-muted-foreground">{t.empty}</p>
        ) : (
          <ul className={cn("flex flex-col divide-y rounded-lg border", classNames?.list)}>
            {keys.map((k) => {
              const keyName = k.name === undefined || k.name === "" ? t.title : k.name
              return (
                <li key={k.id ?? keyName} className={cn("flex items-center gap-2 px-2.5 py-1.5", classNames?.key)}>
                  <KeyRoundIcon aria-hidden className="size-3.5 text-muted-foreground" />
                  <div className="flex min-w-0 flex-1 flex-col">
                    <span className="truncate text-[13px] font-medium">{keyName}</span>
                    <span className="text-xs text-muted-foreground">{fillText(t.added, { date: formatDate(k.createdAt) })}</span>
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-sm"
                    aria-label={fillText(t.removeLabel, { name: keyName })}
                    disabled={busy}
                    onClick={() => onRemove?.(k)}
                  >
                    <Trash2Icon aria-hidden />
                  </Button>
                </li>
              )
            })}
          </ul>
        )}
        <form noValidate onSubmit={submitAdd} className={cn("flex items-end gap-2", classNames?.add)}>
          <Field className="flex-1">
            <FieldLabel htmlFor={`${formId}-name`}>{t.nameLabel}</FieldLabel>
            <Input
              id={`${formId}-name`}
              value={name}
              maxLength={MAX_NAME_LENGTH}
              placeholder={t.namePlaceholder}
              autoComplete="off"
              onChange={(e) => {
                setLocalName(e.target.value)
                onNameChange?.(e.target.value)
              }}
              className={classNames?.input}
            />
          </Field>
          <Button type="submit" disabled={pending === "add" || loading} aria-busy={pending === "add"}>
            {pending === "add" ? <Spinner data-icon="inline-start" /> : <KeyRoundIcon aria-hidden data-icon="inline-start" />}
            {pending === "add" ? t.adding : t.add}
          </Button>
        </form>
    </>
  )
  const dialog = (
    <ProofDialog
        open={proof !== null}
        title={proof === "remove" ? t.proofTitleRemove : t.proofTitleAdd}
        t={t}
        className={classNames?.dialog}
        busy={busy}
        error={proofError}
        keyAvailable={keys.length > 0}
        onCancel={() => onProofCancel?.()}
        onCode={onProofCode}
        onKey={onProofKey}
        onCodeChange={onProofCodeChange}
      />
  )

  // Embedded: a titled section for a card that already has its own frame (TwoFactorSetup).
  if (variant === "embedded") {
    return (
      <section aria-labelledby={`${formId}-heading`} className={cn("flex flex-col gap-3 border-t pt-3.5", className, classNames?.root)}>
        <div className="flex flex-col gap-0.5">
          <h3 id={`${formId}-heading`} role="heading" aria-level={headingLevel} className={cn("flex items-center gap-2 text-[13px] font-medium", classNames?.title)}>
            <KeyRoundIcon aria-hidden className="size-3.5 text-muted-foreground" />
            {t.title}
          </h3>
          <p className={cn("text-xs text-muted-foreground", classNames?.description)}>{t.description}</p>
        </div>
        <div className={cn("flex flex-col gap-3", classNames?.content)}>{content}</div>
        {dialog}
      </section>
    )
  }

  return (
    <Card className={cn("w-full max-w-md", className, classNames?.root)}>
      <CardHeader className={classNames?.header}>
        <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
          <KeyRoundIcon aria-hidden className="size-4 text-muted-foreground" />
          {t.title}
        </CardTitle>
        <CardDescription className={classNames?.description}>{t.description}</CardDescription>
      </CardHeader>
      <CardContent className={cn("flex flex-col gap-3", classNames?.content)}>{content}</CardContent>
      {dialog}
    </Card>
  )
}

/** Asks for proof from a factor the person has: a code, or a tap of a security key. */
function ProofDialog({
  open,
  title,
  t,
  className,
  busy,
  error,
  keyAvailable,
  onCancel,
  onCode,
  onKey,
  onCodeChange,
}: {
  open: boolean
  title: string
  t: SecurityKeysText
  className: string | undefined
  busy: boolean
  error: string | null
  keyAvailable: boolean
  onCancel: () => void
  onCode: ((code: string) => void | Promise<void>) | undefined
  onKey: (() => void) | undefined
  onCodeChange: (() => void) | undefined
}) {
  const formId = useId()
  const [code, setCode] = useState("")
  // The view's own check (an empty code); the parent's error (a wrong code) shows when this is clear.
  const [localError, setLocalError] = useState<string | null>(null)

  // Closed (proof given, refused for another reason, or cancelled): the next opening starts clean.
  useEffect(() => {
    if (open) return
    setCode("")
    setLocalError(null)
  }, [open])

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (code.trim() === "") {
      setLocalError(t.codeRequired)
      return
    }
    setLocalError(null)
    void onCode?.(code.trim())
  }
  const message = localError ?? error
  const invalid = message !== null
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (next || busy) return
        onCancel()
      }}
    >
      <DialogContent className={className}>
        <form noValidate onSubmit={submit} className="flex flex-col gap-3">
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            <DialogDescription>{t.proofDescription}</DialogDescription>
          </DialogHeader>
          <Field data-invalid={invalid}>
            <FieldLabel htmlFor={`${formId}-code`}>{t.codeLabel}</FieldLabel>
            <Input
              id={`${formId}-code`}
              value={code}
              autoComplete="one-time-code"
              spellCheck={false}
              onChange={(e) => {
                setLocalError(null)
                setCode(e.target.value)
                onCodeChange?.()
              }}
              aria-invalid={invalid}
              aria-describedby={invalid ? `${formId}-code-error` : undefined}
            />
            {invalid && <FieldError id={`${formId}-code-error`}>{message}</FieldError>}
          </Field>
          {keyAvailable && (
            <Button type="button" variant="outline" disabled={busy} onClick={() => onKey?.()}>
              <KeyRoundIcon aria-hidden data-icon="inline-start" />
              {t.useKeyForProof}
            </Button>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={onCancel}>
              {t.cancel}
            </Button>
            <Button type="submit" disabled={busy} aria-busy={busy}>
              {busy && <Spinner data-icon="inline-start" />}
              {t.confirm}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
