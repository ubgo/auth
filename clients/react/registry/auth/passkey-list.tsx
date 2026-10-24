import { useForm } from "@tanstack/react-form"
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
import { CircleAlertIcon, KeyRoundIcon, MoreHorizontalIcon, PencilIcon, PlusIcon, Trash2Icon } from "lucide-react"
import { useId, useRef, useState } from "react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// PasskeyList and AddPasskey: the signed-in user's passkeys (passkey.list),
// each renamable (passkey.rename) and removable (passkey.remove), and a
// button that registers a new one (register-begin, the browser's WebAuthn
// prompt, register-finish). AddPasskey also stands alone, for an onboarding
// step or a "secure your account" banner. Adding and removing need a recent
// sign-in; when the session is too old the card offers to sign in again. The
// server refuses to remove the last way in (auth.last_sign_in_method), and
// the confirm dialog shows that refusal where the click happened.

/** Every string PasskeyList and AddPasskey show, with `{name}` placeholders where a value is filled in. */
export type PasskeyListText = {
  title: string
  description: string
  add: string
  adding: string
  addCancelled: string
  addUnsupported: string
  addAlreadyRegistered: string
  /** `{browser}` and `{os}` from the user agent; the name a new passkey gets until it is renamed. */
  defaultName: string
  defaultNameUnknown: string
  emptyTitle: string
  emptyDescription: string
  unnamed: string
  /** `{date}` is when it was added. */
  added: string
  /** `{when}` is a relative time ("2 days ago"). */
  lastUsed: string
  neverUsed: string
  synced: string
  syncedDescription: string
  actions: string
  rename: string
  renameTitle: string
  renameDescription: string
  nameLabel: string
  nameRequired: string
  save: string
  saving: string
  remove: string
  /** `{name}` is the passkey's name. */
  removeTitle: string
  removeDescription: string
  removeSubmit: string
  removing: string
  cancel: string
  freshTitle: string
  freshDescription: string
  signInAgain: string
  loading: string
  loadFailed: string
  retry: string
}

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    passkeyList: PasskeyListText
  }
}

/** The English defaults. Override per app (AuthProvider localization.passkeyList) or per use (localization prop). */
export const PASSKEY_LIST_TEXT: PasskeyListText = {
  title: "Passkeys",
  description: "Sign in with your fingerprint, face or screen lock instead of a password.",
  add: "Add a passkey",
  adding: "Waiting for your device…",
  addCancelled: "No passkey was added. Try again when you're ready.",
  addUnsupported: "This browser cannot create passkeys.",
  addAlreadyRegistered: "This device already has a passkey for your account.",
  defaultName: "{browser} on {os}",
  defaultNameUnknown: "Passkey",
  emptyTitle: "No passkeys yet",
  emptyDescription: "Add one to sign in faster and without a password on this device.",
  unnamed: "Unnamed passkey",
  added: "Added {date}",
  lastUsed: "Last used {when}",
  neverUsed: "Never used",
  synced: "Synced",
  syncedDescription: "Backed up to your password manager or cloud account, so it works on your other devices.",
  actions: "Actions for {name}",
  rename: "Rename",
  renameTitle: "Rename passkey",
  renameDescription: "A name that says where it lives, such as “Work laptop”.",
  nameLabel: "Name",
  nameRequired: "Enter a name.",
  save: "Save",
  saving: "Saving…",
  remove: "Remove",
  removeTitle: "Remove “{name}”?",
  removeDescription: "You will no longer be able to sign in with it. The passkey stays on your device until you delete it there.",
  removeSubmit: "Remove",
  removing: "Removing…",
  cancel: "Cancel",
  freshTitle: "Confirm it's you",
  freshDescription: "Adding or removing a passkey needs a recent sign-in.",
  signInAgain: "Sign in again",
  loading: "Loading passkeys…",
  loadFailed: "Your passkeys could not be loaded.",
  retry: "Try again",
}

/** The named parts classNames can style. */
export type PasskeyListSlot =
  | "root"
  | "header"
  | "title"
  | "description"
  | "content"
  | "list"
  | "item"
  | "itemIcon"
  | "itemName"
  | "itemMeta"
  | "badge"
  | "actions"
  | "empty"
  | "addButton"
  | "formError"
  | "dialog"

/** The named parts of AddPasskey. */
export type AddPasskeySlot = "root" | "button" | "error"

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

/** The classes that turn the card into a plain block for variant="embedded". */
const EMBEDDED_CLASS = "gap-3 bg-transparent py-0 ring-0 [--card-spacing:0px] *:data-[slot=card-footer]:bg-transparent *:data-[slot=card-footer]:pt-3"

/** The passkey list's query key, under the package root so sign-out clears it. */
export const PASSKEY_LIST_QUERY_KEY = [...AUTH_QUERY_ROOT, "passkey", "list"] as const

/** The error that means the action needs a recent sign-in. */
const FRESH_REQUIRED: AnyErrorCode = "auth.fresh_session_required"

/** Longest name the field accepts; the server cuts longer ones, so the field says so first. */
const MAX_NAME_LENGTH = 64

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

/** The steps of one relative-time unit, largest first, for "2 days ago". */
const RELATIVE_UNITS: ReadonlyArray<readonly [Intl.RelativeTimeFormatUnit, number]> = [
  ["year", 365 * 24 * 3600],
  ["month", 30 * 24 * 3600],
  ["week", 7 * 24 * 3600],
  ["day", 24 * 3600],
  ["hour", 3600],
  ["minute", 60],
]

/** "2 days ago", "just now", in the browser's language. */
function relativeTime(iso: string): string {
  const seconds = (new Date(iso).getTime() - Date.now()) / 1000
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" })
  for (const [unit, size] of RELATIVE_UNITS) {
    if (Math.abs(seconds) >= size) return rtf.format(Math.round(seconds / size), unit)
  }
  return rtf.format(0, "second")
}

/** "Oct 12, 2026", in the browser's language. */
function shortDate(iso: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(new Date(iso))
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
  const messageFor = useErrorMessage()
  const queryClient = useQueryClient()
  const passkey = usePluginClient("passkey")
  const [error, setError] = useState<string | null>(null)

  function fail(message: string, cause: AuthError | null) {
    if (onError === undefined) setError(message)
    else
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
      const done = await passkey.registerFinish({ ceremony: begin.data.ceremony, credential: ceremony.credential, name: (name ?? deviceName(t)).slice(0, MAX_NAME_LENGTH) })
      if (done.error !== null) return { passkey: null, error: done.error, failure: null }
      return { passkey: done.data, error: null, failure: null }
    },
    onSuccess: async (outcome) => {
      if (outcome.error !== null) return fail(messageFor(outcome.error), outcome.error)
      if (outcome.failure === "unsupported") return fail(t.addUnsupported, null)
      if (outcome.failure === "already_registered") return fail(t.addAlreadyRegistered, null)
      if (outcome.passkey === null) return fail(t.addCancelled, null)
      await queryClient.invalidateQueries({ queryKey: PASSKEY_LIST_QUERY_KEY })
      onSuccess?.(outcome.passkey)
    },
  })

  if (passkey === null) return null
  const supported = supportsPasskeys()

  return (
    <div className={cn("flex flex-col gap-1.5", className, classNames?.root)}>
      <Button
        type="button"
        variant={variant}
        className={classNames?.button}
        disabled={add.isPending || !supported}
        aria-busy={add.isPending}
        title={supported ? undefined : t.addUnsupported}
        onClick={() => {
          setError(null)
          add.mutate()
        }}
      >
        {add.isPending ? <Spinner data-icon="inline-start" /> : <PlusIcon data-icon="inline-start" aria-hidden />}
        {add.isPending ? t.adding : t.add}
      </Button>
      {error !== null && (
        <p role="alert" className={cn("text-xs text-destructive", classNames?.error)}>
          {error}
        </p>
      )}
    </div>
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
  const { paths } = useAuth()
  const { signOut } = useSessionActions()
  const passkey = usePluginClient("passkey")
  const [formError, setFormError] = useState<string | null>(null)
  const [needsFresh, setNeedsFresh] = useState(false)
  const [renaming, setRenaming] = useState<PasskeyPasskey | null>(null)
  const [removing, setRemoving] = useState<PasskeyPasskey | null>(null)

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

  /** Shows a failure: the fresh-sign-in prompt for an old session, the card's alert otherwise. */
  function showError(message: string, error: AuthError | null, retry: () => Promise<void>) {
    if (error?.code === FRESH_REQUIRED) freshRequired(retry)
    else setFormError(message)
  }

  /** The app's re-authentication when it handles it, the list's own prompt otherwise. */
  function freshRequired(retry: () => Promise<void>) {
    if (onFreshSessionRequired === undefined) setNeedsFresh(true)
    else onFreshSessionRequired(retry)
  }

  // No passkey() in the client: nothing to list, so nothing renders (CONTRACT.md rule 2).
  if (passkey === null) return null
  const embedded = variant === "embedded"

  const here = typeof window === "undefined" ? paths.afterSignIn : window.location.pathname + window.location.search
  const passkeys = list.data ?? []
  const loadError = list.error instanceof PasskeyListError ? list.error.error : null

  return (
    <Card className={cn("w-full max-w-lg", embedded && EMBEDDED_CLASS, className, classNames?.root)}>
      {!embedded && (
        <CardHeader className={classNames?.header}>
          <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
            <KeyRoundIcon aria-hidden className="size-4 text-muted-foreground" />
            {t.title}
          </CardTitle>
          <CardDescription className={classNames?.description}>{t.description}</CardDescription>
          {passkeys.length > 0 && (
            <CardAction>
              <AddPasskey
                localization={localization}
                authenticatorAttachment={authenticatorAttachment}
                classNames={{ button: classNames?.addButton }}
                onError={showError}
                onSuccess={(p) => {
                  setFormError(null)
                  onSuccess?.({ action: "added", passkey: p })
                }}
              />
            </CardAction>
          )}
        </CardHeader>
      )}
      <CardContent className={cn("flex flex-col gap-3", classNames?.content)}>
        {needsFresh && (
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
        )}
        {formError !== null && (
          <Alert variant="destructive" className={classNames?.formError}>
            <CircleAlertIcon aria-hidden />
            <AlertDescription>{formError}</AlertDescription>
          </Alert>
        )}

        {list.isPending ? (
          <div className="flex flex-col gap-2" aria-busy aria-label={t.loading}>
            {[0, 1].map((i) => (
              <div key={i} className="flex items-center gap-3 rounded-lg border p-2.5">
                <Skeleton className="size-8 rounded-md" />
                <div className="flex flex-1 flex-col gap-1.5">
                  <Skeleton className="h-3.5 w-1/3" />
                  <Skeleton className="h-3 w-1/2" />
                </div>
              </div>
            ))}
          </div>
        ) : loadError !== null ? (
          <Alert variant="destructive">
            <CircleAlertIcon aria-hidden />
            <AlertTitle>{t.loadFailed}</AlertTitle>
            <AlertDescription className="flex flex-col items-start gap-2">
              {messageFor(loadError)}
              <Button type="button" size="sm" variant="outline" onClick={() => void list.refetch()}>
                {t.retry}
              </Button>
            </AlertDescription>
          </Alert>
        ) : passkeys.length === 0 ? (
          <div className={cn("flex flex-col items-center gap-2 rounded-lg border border-dashed px-4 py-6 text-center", classNames?.empty)}>
            <div aria-hidden className="flex size-9 items-center justify-center rounded-lg bg-muted text-muted-foreground">
              <KeyRoundIcon className="size-4" />
            </div>
            <div className="flex flex-col gap-0.5">
              <p className="font-medium">{t.emptyTitle}</p>
              <p className="text-muted-foreground">{t.emptyDescription}</p>
            </div>
            <AddPasskey
              className="mt-1 items-center"
              variant="default"
              localization={localization}
              authenticatorAttachment={authenticatorAttachment}
              classNames={{ button: classNames?.addButton }}
              onError={showError}
              onSuccess={(p) => {
                setFormError(null)
                onSuccess?.({ action: "added", passkey: p })
              }}
            />
          </div>
        ) : (
          <ul aria-label={t.title} className={cn("flex flex-col divide-y rounded-lg border", classNames?.list)}>
            {passkeys.map((p) => {
              const label = p.name === "" ? t.unnamed : p.name
              return (
                <li key={p.id} className={cn("flex items-center gap-3 px-2.5 py-2", classNames?.item)}>
                  <div aria-hidden className={cn("flex size-8 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground", classNames?.itemIcon)}>
                    <KeyRoundIcon className="size-4" />
                  </div>
                  <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <div className="flex min-w-0 items-center gap-1.5">
                      <span className={cn("truncate font-medium", classNames?.itemName)}>{label}</span>
                      {p.backedUp && (
                        <Badge variant="secondary" className={classNames?.badge} title={t.syncedDescription}>
                          {t.synced}
                        </Badge>
                      )}
                    </div>
                    <span className={cn("truncate text-xs text-muted-foreground", classNames?.itemMeta)}>
                      {format(t.added, { date: shortDate(p.createdAt) })}
                      {" · "}
                      {p.lastUsedAt === null ? t.neverUsed : format(t.lastUsed, { when: relativeTime(p.lastUsedAt) })}
                    </span>
                  </div>
                  <DropdownMenu>
                    <DropdownMenuTrigger
                      render={<Button variant="ghost" size="icon-sm" className={classNames?.actions} aria-label={format(t.actions, { name: label })} />}
                    >
                      <MoreHorizontalIcon aria-hidden />
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuGroup>
                        <DropdownMenuItem onClick={() => setRenaming(p)}>
                          <PencilIcon aria-hidden />
                          {t.rename}
                        </DropdownMenuItem>
                      </DropdownMenuGroup>
                      <DropdownMenuSeparator />
                      <DropdownMenuGroup>
                        <DropdownMenuItem variant="destructive" onClick={() => setRemoving(p)}>
                          <Trash2Icon aria-hidden />
                          {t.remove}
                        </DropdownMenuItem>
                      </DropdownMenuGroup>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </li>
              )
            })}
          </ul>
        )}
        {embedded && passkeys.length > 0 && (
          <AddPasskey
            className="items-start"
            localization={localization}
            authenticatorAttachment={authenticatorAttachment}
            classNames={{ button: classNames?.addButton }}
            onError={showError}
            onSuccess={(p) => {
              setFormError(null)
              onSuccess?.({ action: "added", passkey: p })
            }}
          />
        )}
      </CardContent>

      <RenameDialog
        passkey={renaming}
        t={t}
        className={classNames?.dialog}
        onClose={() => setRenaming(null)}
        onRenamed={(p) => onSuccess?.({ action: "renamed", passkey: p })}
      />
      <RemoveDialog
        passkey={removing}
        t={t}
        className={classNames?.dialog}
        onClose={() => setRemoving(null)}
        onFresh={(retry) => {
          // Closed while the re-sign-in dialog is up, reopened by the retry so
          // its progress (and any new error) shows where the user left it.
          const target = removing
          setRemoving(null)
          freshRequired(async () => {
            setRemoving(target)
            await retry()
          })
        }}
        onRemoved={(p) => onSuccess?.({ action: "removed", passkey: p })}
      />
    </Card>
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

/** The rename dialog: one field, prefilled with the current name, saved with passkey.rename. */
function RenameDialog({
  passkey: target,
  t,
  className,
  onClose,
  onRenamed,
}: {
  passkey: PasskeyPasskey | null
  t: PasskeyListText
  className: string | undefined
  onClose: () => void
  onRenamed: (p: PasskeyPasskey) => void
}) {
  // Keep the last target so the dialog's text does not blank out while it animates closed.
  const [shown, setShown] = useState<PasskeyPasskey | null>(null)
  if (target !== null && target !== shown) setShown(target)
  return (
    <Dialog
      open={target !== null}
      onOpenChange={(open) => {
        if (!open) onClose()
      }}
    >
      <DialogContent className={className}>
        <DialogHeader>
          <DialogTitle>{t.renameTitle}</DialogTitle>
          <DialogDescription>{t.renameDescription}</DialogDescription>
        </DialogHeader>
        {/* Keyed by the passkey, so the form starts from its current name each time. */}
        {shown !== null && <RenameForm key={shown.id} passkey={shown} t={t} onClose={onClose} onRenamed={onRenamed} />}
      </DialogContent>
    </Dialog>
  )
}

/** The rename form inside the dialog, with its own TanStack Form state per passkey. */
function RenameForm({
  passkey: current,
  t,
  onClose,
  onRenamed,
}: {
  passkey: PasskeyPasskey
  t: PasskeyListText
  onClose: () => void
  onRenamed: (p: PasskeyPasskey) => void
}) {
  const passkey = usePluginClient("passkey")
  const queryClient = useQueryClient()
  const messageFor = useErrorMessage()
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)
  const [error, setError] = useState<string | null>(null)

  const rename = useMutation({
    mutationFn: async (name: string) => {
      if (passkey === null) throw new Error("PasskeyList: passkey plugin missing")
      return passkey.rename({ id: current.id, name })
    },
    onSuccess: async ({ error: failure }, name) => {
      if (failure !== null) return setError(messageFor(failure))
      await queryClient.invalidateQueries({ queryKey: PASSKEY_LIST_QUERY_KEY })
      onRenamed({ ...current, name })
      onClose()
    },
  })

  const form = useForm({
    defaultValues: { name: current.name },
    onSubmit: async ({ value }) => {
      setError(null)
      await rename.mutateAsync(value.name.trim())
    },
    onSubmitInvalid: () => {
      formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
    },
  })

  return (
    <>
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
          {error !== null && (
            <Alert variant="destructive">
              <CircleAlertIcon aria-hidden />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          <form.Field name="name" validators={{ onSubmit: ({ value }) => (value.trim() === "" ? t.nameRequired : undefined) }}>
            {(field) => {
              const message = field.state.meta.errors[0]
              const invalid = message !== undefined
              return (
                <Field data-invalid={invalid}>
                  <FieldLabel htmlFor={`${formId}-name`}>{t.nameLabel}</FieldLabel>
                  <Input
                    id={`${formId}-name`}
                    autoFocus
                    autoComplete="off"
                    maxLength={MAX_NAME_LENGTH}
                    value={field.state.value}
                    onChange={(e) => field.handleChange(e.target.value)}
                    onFocus={(e) => e.target.select()}
                    aria-invalid={invalid}
                    aria-describedby={invalid ? `${formId}-name-error` : undefined}
                  />
                  {invalid && <FieldError id={`${formId}-name-error`}>{message}</FieldError>}
                </Field>
              )
            }}
          </form.Field>
        </FieldGroup>
      </form>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onClose} disabled={rename.isPending}>
          {t.cancel}
        </Button>
        <Button type="submit" form={formId} disabled={rename.isPending} aria-busy={rename.isPending}>
          {rename.isPending && <Spinner data-icon="inline-start" />}
          {rename.isPending ? t.saving : t.save}
        </Button>
      </DialogFooter>
    </>
  )
}

/** The remove confirmation. A refusal (the last way in) shows inside it, where the click happened. */
function RemoveDialog({
  passkey: target,
  t,
  className,
  onClose,
  onFresh,
  onRemoved,
}: {
  passkey: PasskeyPasskey | null
  t: PasskeyListText
  className: string | undefined
  onClose: () => void
  /** The removal needs a fresh sign-in; `retry` removes the same passkey again. */
  onFresh: (retry: () => Promise<void>) => void
  onRemoved: (p: PasskeyPasskey) => void
}) {
  const passkey = usePluginClient("passkey")
  const queryClient = useQueryClient()
  const messageFor = useErrorMessage()
  const [error, setError] = useState<string | null>(null)
  const [shown, setShown] = useState<PasskeyPasskey | null>(null)
  if (target !== null && target !== shown) setShown(target)

  const remove = useMutation({
    mutationFn: async (id: string) => {
      if (passkey === null) throw new Error("PasskeyList: passkey plugin missing")
      return passkey.remove({ id })
    },
    onSuccess: async ({ error: failure }, id) => {
      if (failure !== null) {
        if (failure.code === FRESH_REQUIRED)
          onFresh(async () => {
            await remove.mutateAsync(id)
          })
        else setError(messageFor(failure))
        return
      }
      await queryClient.invalidateQueries({ queryKey: PASSKEY_LIST_QUERY_KEY })
      if (shown !== null) onRemoved(shown)
      onClose()
    },
  })

  const label = shown === null || shown.name === "" ? t.unnamed : shown.name

  return (
    <AlertDialog
      open={target !== null}
      onOpenChange={(open) => {
        if (!open) {
          setError(null)
          onClose()
        }
      }}
    >
      <AlertDialogContent className={className}>
        <AlertDialogHeader>
          <AlertDialogTitle>{format(t.removeTitle, { name: label })}</AlertDialogTitle>
          <AlertDialogDescription>{t.removeDescription}</AlertDialogDescription>
        </AlertDialogHeader>
        {error !== null && (
          <Alert variant="destructive">
            <CircleAlertIcon aria-hidden />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel disabled={remove.isPending}>{t.cancel}</AlertDialogCancel>
          <Button
            type="button"
            variant="destructive"
            disabled={remove.isPending || shown === null}
            aria-busy={remove.isPending}
            onClick={() => {
              if (shown === null) return
              setError(null)
              remove.mutate(shown.id)
            }}
          >
            {remove.isPending && <Spinner data-icon="inline-start" />}
            {remove.isPending ? t.removing : t.removeSubmit}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
