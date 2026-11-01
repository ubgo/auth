import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { AuthError, TwofactorFactorProof, TwofactorStatus } from "@ubgo/auth-client"
import {
  AUTH_QUERY_ROOT,
  createPasskeyCredential,
  getPasskeyCredential,
  useErrorMessage,
  useLocalization,
  usePluginClient,
  useSessionActions,
  type AnyErrorCode,
  type AuthComponentProps,
  type PasskeyFailure,
} from "@ubgo/auth-react"
import { useState } from "react"

import {
  SECURITY_KEYS_TEXT,
  SecurityKeysView,
  type SecurityKeyItem,
  type SecurityKeysPending,
  type SecurityKeysSlot,
  type SecurityKeysText,
} from "@/components/auth/security-keys-view"

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
//
// The list itself is SecurityKeysView (security-keys-view.tsx): this file
// only wires it to @ubgo/auth-react, the calls, the browser prompts and the
// session.

export {
  SECURITY_KEYS_TEXT,
  SecurityKeysView,
  type SecurityKeyItem,
  type SecurityKeysPending,
  type SecurityKeysProof,
  type SecurityKeysSlot,
  type SecurityKeysText,
  type SecurityKeysViewProps,
} from "@/components/auth/security-keys-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    securityKeys: SecurityKeysText
  }
}

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
type Pending = { readonly kind: "add"; readonly name: string } | { readonly kind: "remove"; readonly key: SecurityKeyItem } | null

export function SecurityKeys({ className, classNames, localization, onSuccess, headingLevel = 1, variant = "card" }: SecurityKeysProps) {
  const t = useLocalization("securityKeys", SECURITY_KEYS_TEXT, localization)
  const twofactor = usePluginClient("twofactor")
  const queryClient = useQueryClient()
  const { refreshSession } = useSessionActions()
  const messageFor = useErrorMessage()
  const [name, setName] = useState("")
  const [formError, setFormError] = useState<string | null>(null)
  const [status, setStatus] = useState<string | null>(null)
  const [pending, setPending] = useState<Pending>(null)
  const [proofError, setProofError] = useState<string | null>(null)
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

  /** Closes the proof dialog and forgets its error. */
  const closeProof = () => {
    setPending(null)
    setProofError(null)
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
    mutationFn: async ({ key, proof }: { key: SecurityKeyItem; proof: TwofactorFactorProof }) => {
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

  /** Runs an add with the proof (null when two-factor is off); a wrong proof comes back for the dialog to show. */
  const runAdd = async (keyName: string, proof: TwofactorFactorProof | null): Promise<AuthError | null> => {
    const out = await add.mutateAsync({ keyName, proof })
    if (out.failure !== null) {
      setFormError(failureText(out.failure))
      closeProof()
      return null
    }
    if (out.error !== null) {
      if (proof !== null && PROOF_ERRORS.has(out.error.code)) return out.error
      setFormError(messageFor(out.error))
      closeProof()
      return null
    }
    closeProof()
    setName("")
    setStatus(t.addedStatus)
    // The first key's recovery codes are shown once: the change is reported
    // (and a page may navigate away) only after they are saved.
    if (out.codes.length > 0) setRecoveryCodes(out.codes)
    else await changed({ action: "added", twoFactorEnabled: true })
    return null
  }

  const runRemove = async (key: SecurityKeyItem, proof: TwofactorFactorProof): Promise<AuthError | null> => {
    const out = await remove.mutateAsync({ key, proof })
    if (out.error !== null) {
      if (PROOF_ERRORS.has(out.error.code)) return out.error
      setFormError(messageFor(out.error))
      closeProof()
      return null
    }
    closeProof()
    setStatus(t.removedStatus)
    await changed({ action: "removed", twoFactorEnabled: out.enabled })
    return null
  }

  /** Answers the open proof dialog with a proof; a wrong one shows under its code field. */
  const answer = async (proof: TwofactorFactorProof) => {
    if (pending === null) return
    setProofError(null)
    const failure = pending.kind === "add" ? await runAdd(pending.name, proof) : await runRemove(pending.key, proof)
    if (failure !== null) setProofError(messageFor(failure))
  }

  /** Proof by a tap of a registered key: the server's challenge, the browser prompt, then the assertion as the proof. */
  const proveWithKey = async () => {
    setProofError(null)
    const challenge = await twofactor.securityKeyChallenge()
    if (challenge.error !== null) {
      setProofError(messageFor(challenge.error))
      return
    }
    const ceremony = await getPasskeyCredential(challenge.data.options)
    if (ceremony.credential === null) {
      setProofError(t.cancelled)
      return
    }
    await answer({ method: METHOD_SECURITY_KEY, securityKey: { ceremony: challenge.data.ceremony, credential: ceremony.credential } })
  }

  const busy: SecurityKeysPending = add.isPending ? "add" : remove.isPending ? "remove" : null

  return (
    <SecurityKeysView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      variant={variant}
      loading={read.isPending}
      keys={keys}
      name={name}
      onNameChange={setName}
      pending={busy}
      formError={formError}
      status={status}
      recoveryCodes={recoveryCodes}
      proof={pending?.kind ?? null}
      proofError={proofError}
      onAdd={(keyName) => {
        if (enabled) setPending({ kind: "add", name: keyName })
        else void runAdd(keyName, null)
      }}
      onRemove={(key) => setPending({ kind: "remove", key })}
      onProofCode={(code) => answer({ code })}
      onProofKey={() => void proveWithKey()}
      onProofCodeChange={() => setProofError(null)}
      onProofCancel={closeProof}
      onRecoveryDone={() => {
        setRecoveryCodes([])
        void changed({ action: "added", twoFactorEnabled: true })
      }}
    />
  )
}
