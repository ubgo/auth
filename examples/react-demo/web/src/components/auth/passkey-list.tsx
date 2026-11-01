import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { AuthError, PasskeyPasskey } from "@ubgo/auth-client"
import {
  AUTH_QUERY_ROOT,
  createPasskeyCredential,
  format,
  useAuth,
  useErrorMessage,
  useLocalization,
  usePluginClient,
  useSessionActions,
  supportsPasskeys,
  type AnyErrorCode,
  type AuthComponentProps,
} from "@ubgo/auth-react"
import { useState } from "react"

import {
  AddPasskeyView,
  PASSKEY_LIST_TEXT,
  PASSKEY_NAME_MAX_LENGTH,
  PasskeyListView,
  type AddPasskeySlot,
  type PasskeyListPending,
  type PasskeyListSlot,
  type PasskeyListText,
} from "@/components/auth/passkey-list-view"

// PasskeyList and AddPasskey: the signed-in user's passkeys (passkey.list),
// each renamable (passkey.rename) and removable (passkey.remove), and a
// button that registers a new one (register-begin, the browser's WebAuthn
// prompt, register-finish). AddPasskey also stands alone, for an onboarding
// step or a "secure your account" banner. Adding and removing need a recent
// sign-in; when the session is too old the card offers to sign in again. The
// server refuses to remove the last way in (auth.last_sign_in_method), and
// the confirm dialog shows that refusal where the click happened.
//
// The card and the button themselves are PasskeyListView and AddPasskeyView
// (passkey-list-view.tsx): this file only wires them to @ubgo/auth-react,
// the queries, the mutations and the re-sign-in redirect.

export {
  AddPasskeyView,
  PASSKEY_LIST_TEXT,
  PASSKEY_NAME_MAX_LENGTH,
  PasskeyListView,
  type AddPasskeySlot,
  type AddPasskeyViewProps,
  type PasskeyListPending,
  type PasskeyListSlot,
  type PasskeyListText,
  type PasskeyListViewProps,
} from "@/components/auth/passkey-list-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    passkeyList: PasskeyListText
  }
}

/** What PasskeyList hands to onSuccess: the passkey that was added, renamed or removed. */
export type PasskeyListResult = {
  readonly action: "added" | "renamed" | "removed"
  readonly passkey: PasskeyPasskey
}

/** Which authenticators the browser offers: this device's (Touch ID, Windows Hello) or a roaming one (a security key, a phone). */
export type PasskeyAttachment = "platform" | "cross-platform"

export type PasskeyListProps = AuthComponentProps<PasskeyListSlot, "passkeyList", PasskeyListResult> & {
  /** Limit new passkeys to this device's authenticator or to roaming ones. Left out, the browser offers both. */
  readonly authenticatorAttachment?: PasskeyAttachment
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
   * `retry`, which reruns the refused action (add or remove a passkey) with
   * the same inputs. Rename needs no recent sign-in, so it is never refused.
   */
  readonly onFreshSessionRequired?: (retry: () => Promise<void>) => void
}

export type AddPasskeyProps = AuthComponentProps<AddPasskeySlot, "passkeyList", PasskeyPasskey> & {
  /** Limit the passkey to this device's authenticator or to roaming ones. Left out, the browser offers both. */
  readonly authenticatorAttachment?: PasskeyAttachment
  /** The new passkey's name. Left out, "{browser} on {os}" from the user agent. */
  readonly name?: string
  /**
   * Receives a failure instead of the button showing it underneath:
   * `message` is ready to show, `error` is the server's when there was one,
   * and `retry` runs the whole registration again (for a fresh-session
   * refusal, after the user has signed in again).
   */
  readonly onError?: (message: string, error: AuthError | null, retry: () => Promise<void>) => void
  /** The button's variant. Outline by default. */
  readonly variant?: "default" | "outline" | "secondary" | "ghost"
}

/** The passkey list's query key, under the package root so sign-out clears it. */
export const PASSKEY_LIST_QUERY_KEY = [...AUTH_QUERY_ROOT, "passkey", "list"] as const

/** The error that means the action needs a recent sign-in. */
const FRESH_REQUIRED: AnyErrorCode = "auth.fresh_session_required"

/** Appends `redirectTo` to a path, so the sign-in page can come back here. */
function withRedirect(path: string, redirectTo: string): string {
  const joiner = path.includes("?") ? "&" : "?"
  return `${path}${joiner}redirectTo=${encodeURIComponent(redirectTo)}`
}

/** Browser and OS names from the user agent, in the order that avoids the usual false matches (Edge says Chrome, Chrome says Safari). */
const BROWSERS: ReadonlyArray<readonly [RegExp, string]> = [
  [/Edg\//, "Edge"],
  [/OPR\/|Opera/, "Opera"],
  [/Firefox\//, "Firefox"],
  [/Chrome\//, "Chrome"],
  [/Safari\//, "Safari"],
]
const SYSTEMS: ReadonlyArray<readonly [RegExp, string]> = [
  [/iPhone|iPad|iPod/, "iOS"],
  [/Android/, "Android"],
  [/Mac OS X|Macintosh/, "macOS"],
  [/Windows/, "Windows"],
  [/CrOS/, "ChromeOS"],
  [/Linux/, "Linux"],
]

/** A readable default name for a passkey made in this browser. */
function deviceName(t: PasskeyListText): string {
  if (typeof navigator === "undefined") return t.defaultNameUnknown
  const ua = navigator.userAgent
  const browser = BROWSERS.find(([re]) => re.test(ua))?.[1]
  const os = SYSTEMS.find(([re]) => re.test(ua))?.[1]
  if (browser === undefined || os === undefined) return t.defaultNameUnknown
  return format(t.defaultName, { browser, os })
}

/** What useAddPasskey needs: the ceremony's options and where its outcome goes. */
type AddPasskeyOptions = {
  readonly t: PasskeyListText
  readonly authenticatorAttachment: PasskeyAttachment | undefined
  readonly name: string | undefined
  /** A failure, ready to show; `retry` runs the whole registration again. */
  readonly onError: (message: string, error: AuthError | null, retry: () => Promise<void>) => void
  readonly onSuccess: (passkey: PasskeyPasskey) => void
}

/**
 * The registration behind AddPasskey and PasskeyList's add button: begin,
 * the browser's prompt, finish, then a refetch of the list. Every failure
 * goes to onError with its message already chosen.
 */
function useAddPasskey({ t, authenticatorAttachment, name, onError, onSuccess }: AddPasskeyOptions) {
  const messageFor = useErrorMessage()
  const queryClient = useQueryClient()
  const passkey = usePluginClient("passkey")

  function fail(message: string, cause: AuthError | null) {
    onError(message, cause, async () => {
      await add.mutateAsync()
    })
  }

  const add = useMutation({
    mutationFn: async () => {
      if (passkey === null) throw new Error("AddPasskey: the client was created without passkey()")
      const begin = await passkey.registerBegin(authenticatorAttachment === undefined ? {} : { authenticatorAttachment })
      if (begin.error !== null) return { passkey: null, error: begin.error, failure: null }
      const ceremony = await createPasskeyCredential(begin.data.options)
      if (ceremony.credential === null) return { passkey: null, error: null, failure: ceremony.failure }
      const done = await passkey.registerFinish({ ceremony: begin.data.ceremony, credential: ceremony.credential, name: (name ?? deviceName(t)).slice(0, PASSKEY_NAME_MAX_LENGTH) })
      if (done.error !== null) return { passkey: null, error: done.error, failure: null }
      return { passkey: done.data, error: null, failure: null }
    },
    onSuccess: async (outcome) => {
      if (outcome.error !== null) return fail(messageFor(outcome.error), outcome.error)
      if (outcome.failure === "unsupported") return fail(t.addUnsupported, null)
      if (outcome.failure === "already_registered") return fail(t.addAlreadyRegistered, null)
      if (outcome.passkey === null) return fail(t.addCancelled, null)
      await queryClient.invalidateQueries({ queryKey: PASSKEY_LIST_QUERY_KEY })
      onSuccess(outcome.passkey)
    },
  })
  return add
}

/**
 * Registers a new passkey: begin, the browser's prompt, finish. Renders a
 * button; a failure shows under it unless onError takes it.
 */
export function AddPasskey({
  className,
  classNames,
  localization,
  onSuccess,
  authenticatorAttachment,
  name,
  onError,
  variant = "outline",
}: AddPasskeyProps) {
  const t = useLocalization("passkeyList", PASSKEY_LIST_TEXT, localization)
  const passkey = usePluginClient("passkey")
  const [error, setError] = useState<string | null>(null)
  const add = useAddPasskey({
    t,
    authenticatorAttachment,
    name,
    onError: (message, cause, retry) => {
      if (onError === undefined) setError(message)
      else onError(message, cause, retry)
    },
    onSuccess: (p) => onSuccess?.(p),
  })

  if (passkey === null) return null

  return (
    <AddPasskeyView
      className={className}
      classNames={classNames}
      text={t}
      variant={variant}
      supported={supportsPasskeys()}
      pending={add.isPending}
      error={error}
      onAdd={() => {
        setError(null)
        add.mutate()
      }}
    />
  )
}

export function PasskeyList({
  className,
  classNames,
  localization,
  onSuccess,
  authenticatorAttachment,
  headingLevel = 1,
  variant = "card",
  onFreshSessionRequired,
}: PasskeyListProps) {
  const t = useLocalization("passkeyList", PASSKEY_LIST_TEXT, localization)
  const messageFor = useErrorMessage()
  const queryClient = useQueryClient()
  const { paths } = useAuth()
  const { signOut } = useSessionActions()
  const passkey = usePluginClient("passkey")
  const [formError, setFormError] = useState<string | null>(null)
  const [needsFresh, setNeedsFresh] = useState(false)
  const [renaming, setRenaming] = useState<PasskeyPasskey | null>(null)
  const [renameError, setRenameError] = useState<string | null>(null)
  const [removing, setRemoving] = useState<PasskeyPasskey | null>(null)
  const [removeError, setRemoveError] = useState<string | null>(null)

  const list = useQuery({
    queryKey: PASSKEY_LIST_QUERY_KEY,
    queryFn: async (): Promise<readonly PasskeyPasskey[]> => {
      if (passkey === null) throw new Error("PasskeyList: passkey plugin missing")
      const { data, error } = await passkey.list()
      if (error !== null) throw new PasskeyListError(error)
      return data.passkeys ?? []
    },
    enabled: passkey !== null,
    retry: false,
  })

  /** The app's re-authentication when it handles it, the list's own prompt otherwise. */
  function freshRequired(retry: () => Promise<void>) {
    if (onFreshSessionRequired === undefined) setNeedsFresh(true)
    else onFreshSessionRequired(retry)
  }

  const add = useAddPasskey({
    t,
    authenticatorAttachment,
    name: undefined,
    // A failure shows as the fresh-sign-in prompt for an old session, the card's alert otherwise.
    onError: (message, error, retry) => {
      if (error?.code === FRESH_REQUIRED) freshRequired(retry)
      else setFormError(message)
    },
    onSuccess: (p) => {
      setFormError(null)
      onSuccess?.({ action: "added", passkey: p })
    },
  })

  const rename = useMutation({
    mutationFn: async ({ target, name }: { target: PasskeyPasskey; name: string }) => {
      if (passkey === null) throw new Error("PasskeyList: passkey plugin missing")
      return passkey.rename({ id: target.id, name })
    },
    onSuccess: async ({ error: failure }, { target, name }) => {
      if (failure !== null) return setRenameError(messageFor(failure))
      await queryClient.invalidateQueries({ queryKey: PASSKEY_LIST_QUERY_KEY })
      onSuccess?.({ action: "renamed", passkey: { ...target, name } })
      setRenaming(null)
    },
  })

  const remove = useMutation({
    mutationFn: async (target: PasskeyPasskey) => {
      if (passkey === null) throw new Error("PasskeyList: passkey plugin missing")
      return passkey.remove({ id: target.id })
    },
    onSuccess: async ({ error: failure }, target) => {
      if (failure !== null) {
        if (failure.code === FRESH_REQUIRED) {
          // Closed while the re-sign-in dialog is up, reopened by the retry so
          // its progress (and any new error) shows where the user left it.
          setRemoving(null)
          freshRequired(async () => {
            setRemoving(target)
            await remove.mutateAsync(target)
          })
        } else setRemoveError(messageFor(failure))
        return
      }
      await queryClient.invalidateQueries({ queryKey: PASSKEY_LIST_QUERY_KEY })
      onSuccess?.({ action: "removed", passkey: target })
      setRemoving(null)
    },
  })

  // No passkey() in the client: nothing to list, so nothing renders (CONTRACT.md rule 2).
  if (passkey === null) return null

  const here = typeof window === "undefined" ? paths.afterSignIn : window.location.pathname + window.location.search
  const loadError = list.error instanceof PasskeyListError ? list.error.error : null
  const pending: PasskeyListPending = add.isPending ? "add" : rename.isPending ? "rename" : remove.isPending ? "remove" : null

  return (
    <PasskeyListView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      variant={variant}
      passkeys={list.data ?? []}
      loading={list.isPending}
      loadError={loadError === null ? null : messageFor(loadError)}
      supported={supportsPasskeys()}
      pending={pending}
      formError={formError}
      needsFreshSignIn={needsFresh}
      renaming={renaming}
      renameError={renameError}
      removing={removing}
      removeError={removeError}
      onAdd={() => add.mutate()}
      onRetry={() => void list.refetch()}
      onSignInAgain={() => void signOut({ redirectTo: withRedirect(paths.signIn, here) })}
      onRenamingChange={(p) => {
        setRenameError(null)
        setRenaming(p)
      }}
      onRename={async (target, name) => {
        setRenameError(null)
        await rename.mutateAsync({ target, name })
      }}
      onRemovingChange={(p) => {
        setRemoveError(null)
        setRemoving(p)
      }}
      onRemove={(target) => {
        setRemoveError(null)
        remove.mutate(target)
      }}
    />
  )
}

/** A failed list read, thrown so TanStack Query keeps it in `error` with its code. */
class PasskeyListError extends Error {
  readonly error: AuthError
  constructor(error: AuthError) {
    super(error.message)
    this.name = "PasskeyListError"
    this.error = error
  }
}
