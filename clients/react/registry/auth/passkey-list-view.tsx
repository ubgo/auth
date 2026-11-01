import { useForm } from "@tanstack/react-form"
import type { PasskeyPasskey } from "@ubgo/auth-client"
import { CircleAlertIcon, KeyRoundIcon, MoreHorizontalIcon, PencilIcon, PlusIcon, Trash2Icon } from "lucide-react"
import { useId, useRef, useState } from "react"

import { fillText, type ViewHeadingLevel } from "@/components/auth/auth-view"
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

// PasskeyListView and AddPasskeyView: the passkey card and its add button
// with no data layer. The list is told its passkeys, whether they are still
// loading or failed to load, which passkey is being renamed or removed and
// what is running, and hands every action to a callback: onAdd, onRename
// with the typed name, onRemove with the passkey, onRetry, onSignInAgain.
// PasskeyList and AddPasskey (passkey-list.tsx) are these views wired to
// @ubgo/auth-react; render the views yourself to put the same card on any
// other backend.

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

/** Longest passkey name the rename field accepts; the server cuts longer ones, so the field says so first. */
export const PASSKEY_NAME_MAX_LENGTH = 64

/** The classes that turn the card into a plain block for variant="embedded". */
const EMBEDDED_CLASS = "gap-3 bg-transparent py-0 ring-0 [--card-spacing:0px] *:data-[slot=card-footer]:bg-transparent *:data-[slot=card-footer]:pt-3"

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

/** The props of AddPasskeyView: whether the browser can run the ceremony, whether one is running, and its failure. */
export type AddPasskeyViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<AddPasskeySlot, string>>
  /** Text overrides, merged over PASSKEY_LIST_TEXT. */
  readonly text?: Partial<PasskeyListText>
  /** The button's variant. Outline by default. */
  readonly variant?: "default" | "outline" | "secondary" | "ghost"
  /** The browser can create passkeys; false disables the button and says why in its title. True by default. */
  readonly supported?: boolean
  /** A registration is running: the button shows a spinner and is disabled. */
  readonly pending?: boolean
  /** A failure to show under the button. */
  readonly error?: string | null
  /** The button was pressed. */
  readonly onAdd?: () => void
}

/** The "Add a passkey" button and its failure line, as plain props; AddPasskey runs the registration behind it. */
export function AddPasskeyView({
  className,
  classNames,
  text,
  variant = "outline",
  supported = true,
  pending = false,
  error = null,
  onAdd,
}: AddPasskeyViewProps) {
  const t: PasskeyListText = { ...PASSKEY_LIST_TEXT, ...text }
  return (
    <div className={cn("flex flex-col gap-1.5", className, classNames?.root)}>
      <Button
        type="button"
        variant={variant}
        className={classNames?.button}
        disabled={pending || !supported}
        aria-busy={pending}
        title={supported ? undefined : t.addUnsupported}
        onClick={() => onAdd?.()}
      >
        {pending ? <Spinner data-icon="inline-start" /> : <PlusIcon data-icon="inline-start" aria-hidden />}
        {pending ? t.adding : t.add}
      </Button>
      {error !== null && (
        <p role="alert" className={cn("text-xs text-destructive", classNames?.error)}>
          {error}
        </p>
      )}
    </div>
  )
}

/** Which passkey action is running, so the view shows its spinner; null when nothing is. */
export type PasskeyListPending = "add" | "rename" | "remove" | null

/** The props of PasskeyListView: the passkeys and their state, the dialogs' targets, and a callback per action. */
export type PasskeyListViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<PasskeyListSlot, string>>
  /** Text overrides, merged over PASSKEY_LIST_TEXT. */
  readonly text?: Partial<PasskeyListText>
  /** The level of the title, 1 by default. */
  readonly headingLevel?: ViewHeadingLevel
  /** "card" (default) is a standalone card; "embedded" drops the card's border, background, padding and title. */
  readonly variant?: "card" | "embedded"
  /** The passkeys to list. */
  readonly passkeys?: readonly PasskeyPasskey[]
  /** The list is still loading: skeleton rows instead of the list. */
  readonly loading?: boolean
  /** The list could not be loaded: this message with a retry button instead of the list. */
  readonly loadError?: string | null
  /** The browser can create passkeys. True by default. */
  readonly supported?: boolean
  /** The running action. */
  readonly pending?: PasskeyListPending
  /** A message above the list, such as a failed registration. */
  readonly formError?: string | null
  /** The last action needs a recent sign-in: the card offers to sign in again. */
  readonly needsFreshSignIn?: boolean
  /** The passkey whose rename dialog is open; null keeps it closed. */
  readonly renaming?: PasskeyPasskey | null
  /** A failed rename, shown in its dialog. */
  readonly renameError?: string | null
  /** The passkey whose remove confirmation is open; null keeps it closed. */
  readonly removing?: PasskeyPasskey | null
  /** A refused removal (such as the last way in), shown in its dialog. */
  readonly removeError?: string | null
  /** "Add a passkey" was pressed. */
  readonly onAdd?: () => void
  /** "Try again" after a failed load. */
  readonly onRetry?: () => void
  /** "Sign in again" on the recent-sign-in prompt. */
  readonly onSignInAgain?: () => void
  /** A passkey's "Rename" was chosen, or the rename dialog closed (null). */
  readonly onRenamingChange?: (passkey: PasskeyPasskey | null) => void
  /** The rename form passed its check: the new name, trimmed. Awaited, so a slow call keeps the form submitting. */
  readonly onRename?: (passkey: PasskeyPasskey, name: string) => void | Promise<void>
  /** A passkey's "Remove" was chosen, or the confirmation closed (null). */
  readonly onRemovingChange?: (passkey: PasskeyPasskey | null) => void
  /** The removal was confirmed. */
  readonly onRemove?: (passkey: PasskeyPasskey) => void
}

/** The passkey card as plain props and callbacks; PasskeyList renders it from passkey.list and its mutations. */
export function PasskeyListView({
  className,
  classNames,
  text,
  headingLevel = 1,
  variant = "card",
  passkeys = [],
  loading = false,
  loadError = null,
  supported = true,
  pending = null,
  formError = null,
  needsFreshSignIn = false,
  renaming = null,
  renameError = null,
  removing = null,
  removeError = null,
  onAdd,
  onRetry,
  onSignInAgain,
  onRenamingChange,
  onRename,
  onRemovingChange,
  onRemove,
}: PasskeyListViewProps) {
  const t: PasskeyListText = { ...PASSKEY_LIST_TEXT, ...text }
  const embedded = variant === "embedded"
  const addProps = { text: t, supported, pending: pending === "add", classNames: { button: classNames?.addButton }, onAdd }

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
              <AddPasskeyView {...addProps} />
            </CardAction>
          )}
        </CardHeader>
      )}
      <CardContent className={cn("flex flex-col gap-3", classNames?.content)}>
        {needsFreshSignIn && (
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
        )}
        {formError !== null && (
          <Alert variant="destructive" className={classNames?.formError}>
            <CircleAlertIcon aria-hidden />
            <AlertDescription>{formError}</AlertDescription>
          </Alert>
        )}

        {loading ? (
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
              {loadError}
              <Button type="button" size="sm" variant="outline" onClick={() => onRetry?.()}>
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
            <AddPasskeyView {...addProps} className="mt-1 items-center" variant="default" />
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
                      {fillText(t.added, { date: shortDate(p.createdAt) })}
                      {" · "}
                      {p.lastUsedAt === null ? t.neverUsed : fillText(t.lastUsed, { when: relativeTime(p.lastUsedAt) })}
                    </span>
                  </div>
                  <DropdownMenu>
                    <DropdownMenuTrigger
                      render={<Button variant="ghost" size="icon-sm" className={classNames?.actions} aria-label={fillText(t.actions, { name: label })} />}
                    >
                      <MoreHorizontalIcon aria-hidden />
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuGroup>
                        <DropdownMenuItem onClick={() => onRenamingChange?.(p)}>
                          <PencilIcon aria-hidden />
                          {t.rename}
                        </DropdownMenuItem>
                      </DropdownMenuGroup>
                      <DropdownMenuSeparator />
                      <DropdownMenuGroup>
                        <DropdownMenuItem variant="destructive" onClick={() => onRemovingChange?.(p)}>
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
        {embedded && passkeys.length > 0 && <AddPasskeyView {...addProps} className="items-start" />}
      </CardContent>

      <RenameDialog
        passkey={renaming}
        t={t}
        className={classNames?.dialog}
        pending={pending === "rename"}
        error={renameError}
        onClose={() => onRenamingChange?.(null)}
        onRename={onRename}
      />
      <RemoveDialog
        passkey={removing}
        t={t}
        className={classNames?.dialog}
        pending={pending === "remove"}
        error={removeError}
        onClose={() => onRemovingChange?.(null)}
        onRemove={onRemove}
      />
    </Card>
  )
}

/** The rename dialog: one field, prefilled with the current name. */
function RenameDialog({
  passkey: target,
  t,
  className,
  pending,
  error,
  onClose,
  onRename,
}: {
  passkey: PasskeyPasskey | null
  t: PasskeyListText
  className: string | undefined
  pending: boolean
  error: string | null
  onClose: () => void
  onRename: ((passkey: PasskeyPasskey, name: string) => void | Promise<void>) | undefined
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
        {shown !== null && (
          <RenameForm key={shown.id} passkey={shown} t={t} pending={pending} error={error} onClose={onClose} onRename={onRename} />
        )}
      </DialogContent>
    </Dialog>
  )
}

/** The rename form inside the dialog, with its own TanStack Form state per passkey. */
function RenameForm({
  passkey: current,
  t,
  pending,
  error,
  onClose,
  onRename,
}: {
  passkey: PasskeyPasskey
  t: PasskeyListText
  pending: boolean
  error: string | null
  onClose: () => void
  onRename: ((passkey: PasskeyPasskey, name: string) => void | Promise<void>) | undefined
}) {
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)

  const form = useForm({
    defaultValues: { name: current.name },
    onSubmit: async ({ value }) => {
      await onRename?.(current, value.name.trim())
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
                    maxLength={PASSKEY_NAME_MAX_LENGTH}
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
        <Button type="button" variant="outline" onClick={onClose} disabled={pending}>
          {t.cancel}
        </Button>
        <Button type="submit" form={formId} disabled={pending} aria-busy={pending}>
          {pending && <Spinner data-icon="inline-start" />}
          {pending ? t.saving : t.save}
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
  pending,
  error,
  onClose,
  onRemove,
}: {
  passkey: PasskeyPasskey | null
  t: PasskeyListText
  className: string | undefined
  pending: boolean
  error: string | null
  onClose: () => void
  onRemove: ((passkey: PasskeyPasskey) => void) | undefined
}) {
  // Keep the last target so the dialog's text does not blank out while it animates closed.
  const [shown, setShown] = useState<PasskeyPasskey | null>(null)
  if (target !== null && target !== shown) setShown(target)
  const label = shown === null || shown.name === "" ? t.unnamed : shown.name

  return (
    <AlertDialog
      open={target !== null}
      onOpenChange={(open) => {
        if (!open) onClose()
      }}
    >
      <AlertDialogContent className={className}>
        <AlertDialogHeader>
          <AlertDialogTitle>{fillText(t.removeTitle, { name: label })}</AlertDialogTitle>
          <AlertDialogDescription>{t.removeDescription}</AlertDialogDescription>
        </AlertDialogHeader>
        {error !== null && (
          <Alert variant="destructive">
            <CircleAlertIcon aria-hidden />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel disabled={pending}>{t.cancel}</AlertDialogCancel>
          <Button
            type="button"
            variant="destructive"
            disabled={pending || shown === null}
            aria-busy={pending}
            onClick={() => {
              if (shown === null) return
              onRemove?.(shown)
            }}
          >
            {pending && <Spinner data-icon="inline-start" />}
            {pending ? t.removing : t.removeSubmit}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
