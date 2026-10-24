import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { AuthError, TwofactorFactor, TwofactorFactorProof, TwofactorStatus } from "@ubgo/auth-client"
import {
  AUTH_QUERY_ROOT,
  createPasskeyCredential,
  format,
  getPasskeyCredential,
  useErrorMessage,
  useLocalization,
  usePluginClient,
  useSessionActions,
  type AnyErrorCode,
  type AuthComponentProps,
  type PasskeyFailure,
} from "@ubgo/auth-react"
import { CircleAlertIcon, KeyRoundIcon, Trash2Icon } from "lucide-react"
import { useId, useState, type FormEvent } from "react"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldError, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// SecurityKeys: hardware or platform security keys as a second factor
// (twofactor.WithSecurityKeys). Lists the user's keys, adds one (the
// server's registration options, the browser prompt, then register-finish),
// and removes one. When two-factor is already on, both adding and removing
// need proof from a factor the user has: a code from the authenticator app
// or a mailed code, a recovery code, or a tap of a security key. The first
// key turns two-factor on and returns recovery codes, shown once; when the
// session had the setup-mfa task, that also replaces the session, which the
// component re-reads. It renders nothing when the server does not offer
// security keys (status.methods lacks security_key).

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

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    securityKeys: SecurityKeysText
  }
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

/** What changed, handed to onSuccess. */
export type SecurityKeysResult = { readonly action: "added" | "removed"; readonly twoFactorEnabled: boolean }

export type SecurityKeysProps = AuthComponentProps<SecurityKeysSlot, "securityKeys", SecurityKeysResult> & {
  /**
   * "card" (default) is a standalone card. "embedded" is a titled section
   * with no card, for a card that already has its own frame; TwoFactorSetup
   * renders it that way.
   */
  readonly variant?: "card" | "embedded"
}

/** The factor's status, the key TwoFactorSetup and TwoFactorChallenge read, so a change here refreshes them. */
const STATUS_QUERY_KEY = [...AUTH_QUERY_ROOT, "twofactor", "status"] as const

/** The method of a security key factor (twofactor.MethodSecurityKey). */
const METHOD_SECURITY_KEY = "security_key"

/** Errors that mean the proof was wrong, shown under the code field. */
const PROOF_ERRORS: ReadonlySet<AnyErrorCode> = new Set<AnyErrorCode>(["twofactor.code_invalid", "twofactor.security_key_invalid"])

/** What the proof dialog is for: adding a key (with its name) or removing one. */
type Pending = { readonly kind: "add"; readonly name: string } | { readonly kind: "remove"; readonly key: TwofactorFactor } | null

function formatDate(iso: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(new Date(iso))
}

export function SecurityKeys({ className, classNames, localization, onSuccess, headingLevel = 1, variant = "card" }: SecurityKeysProps) {
  const t = useLocalization("securityKeys", SECURITY_KEYS_TEXT, localization)
  const twofactor = usePluginClient("twofactor")
  const queryClient = useQueryClient()
  const { refreshSession } = useSessionActions()
  const messageFor = useErrorMessage()
  const formId = useId()
  const [name, setName] = useState("")
  const [formError, setFormError] = useState<string | null>(null)
  const [status, setStatus] = useState<string | null>(null)
  const [pending, setPending] = useState<Pending>(null)
  const [recoveryCodes, setRecoveryCodes] = useState<readonly string[]>([])

  const read = useQuery({
    queryKey: STATUS_QUERY_KEY,
    queryFn: async (): Promise<{ status: TwofactorStatus | null; error: AuthError | null }> => {
      if (twofactor === null) return { status: null, error: null }
      const { data, error } = await twofactor.status()
      return { status: data, error }
    },
    enabled: twofactor !== null,
    staleTime: 0,
    retry: false,
  })

  /** The words for a browser ceremony that produced no credential. */
  const failureText = (failure: PasskeyFailure) =>
    failure === "already_registered" ? t.alreadyRegistered : failure === "unsupported" || failure === "invalid_options" ? t.unsupported : t.cancelled

  /** After any change: the status everyone reads, and the session (a first factor ends the setup-mfa task with a new session). */
  const changed = async (result: SecurityKeysResult) => {
    await queryClient.invalidateQueries({ queryKey: STATUS_QUERY_KEY })
    await refreshSession()
    onSuccess?.(result)
  }

  const add = useMutation({
    mutationFn: async ({ keyName, proof }: { keyName: string; proof: TwofactorFactorProof | null }) => {
      if (twofactor === null) return { error: null, failure: "unsupported" as const, codes: [] }
      const begin = await twofactor.securityKeyRegisterBegin({})
      if (begin.error !== null) return { error: begin.error, failure: null, codes: [] }
      const ceremony = await createPasskeyCredential(begin.data.options)
      if (ceremony.credential === null) return { error: null, failure: ceremony.failure, codes: [] }
      const finish = await twofactor.securityKeyRegisterFinish({
        ceremony: begin.data.ceremony,
        credential: ceremony.credential,
        ...(keyName.trim() === "" ? {} : { name: keyName.trim() }),
        ...(proof === null ? {} : { proof }),
      })
      if (finish.error !== null) return { error: finish.error, failure: null, codes: [] }
      return { error: null, failure: null, codes: finish.data.recoveryCodes ?? [] }
    },
    onMutate: () => {
      setFormError(null)
      setStatus(null)
    },
  })

  const remove = useMutation({
    mutationFn: async ({ key, proof }: { key: TwofactorFactor; proof: TwofactorFactorProof }) => {
      if (twofactor === null) return { error: null, enabled: false }
      const { data, error } = await twofactor.removeFactor({ method: METHOD_SECURITY_KEY, ...(key.id === undefined ? {} : { id: key.id }), proof })
      return { error, enabled: data?.enabled ?? false }
    },
    onMutate: () => {
      setFormError(null)
      setStatus(null)
    },
  })

  if (twofactor === null) return null
  const methods = read.data?.status?.methods ?? []
  if (!read.isPending && !methods.includes(METHOD_SECURITY_KEY)) return null
  const enabled = read.data?.status?.enabled ?? false
  const keys = (read.data?.status?.factors ?? []).filter((f) => f.method === METHOD_SECURITY_KEY)

  /** Runs an add with the proof (null when two-factor is off); the proof dialog's errors come back to it. */
  const runAdd = async (keyName: string, proof: TwofactorFactorProof | null): Promise<AuthError | null> => {
    const out = await add.mutateAsync({ keyName, proof })
    if (out.failure !== null) {
      setFormError(failureText(out.failure))
      setPending(null)
      return null
    }
    if (out.error !== null) {
      if (proof !== null && PROOF_ERRORS.has(out.error.code)) return out.error
      setFormError(messageFor(out.error))
      setPending(null)
      return null
    }
    setPending(null)
    setName("")
    setStatus(t.addedStatus)
    // The first key's recovery codes are shown once: the change is reported
    // (and a page may navigate away) only after they are saved.
    if (out.codes.length > 0) setRecoveryCodes(out.codes)
    else await changed({ action: "added", twoFactorEnabled: true })
    return null
  }

  const runRemove = async (key: TwofactorFactor, proof: TwofactorFactorProof): Promise<AuthError | null> => {
    const out = await remove.mutateAsync({ key, proof })
    if (out.error !== null) {
      if (PROOF_ERRORS.has(out.error.code)) return out.error
      setFormError(messageFor(out.error))
      setPending(null)
      return null
    }
    setPending(null)
    setStatus(t.removedStatus)
    await changed({ action: "removed", twoFactorEnabled: out.enabled })
    return null
  }

  const submitAdd = (e: FormEvent) => {
    e.preventDefault()
    if (enabled) setPending({ kind: "add", name })
    else void runAdd(name, null)
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
              <Button
                type="button"
                size="sm"
                className="self-start"
                onClick={() => {
                  setRecoveryCodes([])
                  void changed({ action: "added", twoFactorEnabled: true })
                }}
              >
                {t.recoveryDone}
              </Button>
            </AlertDescription>
          </Alert>
        )}
        {read.isPending ? (
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
                    <span className="text-xs text-muted-foreground">{format(t.added, { date: formatDate(k.createdAt) })}</span>
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-sm"
                    aria-label={format(t.removeLabel, { name: keyName })}
                    disabled={add.isPending || remove.isPending}
                    onClick={() => setPending({ kind: "remove", key: k })}
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
              maxLength={64}
              placeholder={t.namePlaceholder}
              autoComplete="off"
              onChange={(e) => setName(e.target.value)}
              className={classNames?.input}
            />
          </Field>
          <Button type="submit" disabled={add.isPending || read.isPending} aria-busy={add.isPending}>
            {add.isPending ? <Spinner data-icon="inline-start" /> : <KeyRoundIcon aria-hidden data-icon="inline-start" />}
            {add.isPending ? t.adding : t.add}
          </Button>
        </form>
    </>
  )
  const dialog = (
    <ProofDialog
        open={pending !== null}
        title={pending?.kind === "remove" ? t.proofTitleRemove : t.proofTitleAdd}
        t={t}
        className={classNames?.dialog}
        busy={add.isPending || remove.isPending}
        onCancel={() => setPending(null)}
        onProof={(proof) => {
          if (pending === null) return Promise.resolve(null)
          return pending.kind === "add" ? runAdd(pending.name, proof) : runRemove(pending.key, proof)
        }}
        keyAvailable={keys.length > 0}
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

/** Asks for proof from a factor the user has: a code, or a tap of a security key. */
function ProofDialog({
  open,
  title,
  t,
  className,
  busy,
  keyAvailable,
  onCancel,
  onProof,
}: {
  open: boolean
  title: string
  t: SecurityKeysText
  className: string | undefined
  busy: boolean
  keyAvailable: boolean
  onCancel: () => void
  onProof: (proof: TwofactorFactorProof) => Promise<AuthError | null>
}) {
  const twofactor = usePluginClient("twofactor")
  const messageFor = useErrorMessage()
  const formId = useId()
  const [code, setCode] = useState("")
  const [error, setError] = useState<string | null>(null)

  const answer = async (proof: TwofactorFactorProof) => {
    setError(null)
    const failure = await onProof(proof)
    if (failure !== null) setError(messageFor(failure))
    else setCode("")
  }
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (code.trim() === "") {
      setError(t.codeRequired)
      return
    }
    void answer({ code: code.trim() })
  }
  const withKey = async () => {
    if (twofactor === null) return
    setError(null)
    const challenge = await twofactor.securityKeyChallenge()
    if (challenge.error !== null) {
      setError(messageFor(challenge.error))
      return
    }
    const ceremony = await getPasskeyCredential(challenge.data.options)
    if (ceremony.credential === null) {
      setError(t.cancelled)
      return
    }
    await answer({ method: METHOD_SECURITY_KEY, securityKey: { ceremony: challenge.data.ceremony, credential: ceremony.credential } })
  }
  const invalid = error !== null
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (next || busy) return
        setCode("")
        setError(null)
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
                setError(null)
                setCode(e.target.value)
              }}
              aria-invalid={invalid}
              aria-describedby={invalid ? `${formId}-code-error` : undefined}
            />
            {invalid && <FieldError id={`${formId}-code-error`}>{error}</FieldError>}
          </Field>
          {keyAvailable && (
            <Button type="button" variant="outline" disabled={busy} onClick={() => void withKey()}>
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
