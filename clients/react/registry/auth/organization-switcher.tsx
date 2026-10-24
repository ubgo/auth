import { revalidateLogic, useForm } from "@tanstack/react-form"
import { useMutation } from "@tanstack/react-query"
import type { AuthError, OrganizationOrg } from "@ubgo/auth-client"
import {
  format,
  useActiveOrganization,
  useAuth,
  useErrorMessage,
  useLocalization,
  useOrganizationActions,
  useOrganizations,
  usePluginClient,
  useSafeRedirect,
  useSession,
  type AuthComponentProps,
} from "@ubgo/auth-react"
import { ChevronsUpDownIcon, CircleAlertIcon, PlusIcon, UserRoundIcon } from "lucide-react"
import { useId, useRef, useState } from "react"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// OrganizationSwitcher: the session's active organization as a menu button.
// The menu lists the user's organizations (and, unless hidden, their
// personal account, which clears the active organization), switches the
// session's active one, and creates a new organization in a dialog. Renders
// nothing when the client has no organization plugin or nobody is signed in.

/** Every string OrganizationSwitcher shows. */
export type OrganizationSwitcherText = {
  /** The trigger's accessible name; `{name}` is the active organization's name, or `personal`. */
  triggerLabel: string
  personal: string
  menuLabel: string
  /** The role shown beside each organization; `{role}` is the user's role in it. */
  role: string
  create: string
  createTitle: string
  createDescription: string
  nameLabel: string
  namePlaceholder: string
  nameRequired: string
  slugLabel: string
  slugDescription: string
  slugRequired: string
  slugInvalid: string
  cancel: string
  submit: string
  submitting: string
}

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    organizationSwitcher: OrganizationSwitcherText
  }
}

/** The English defaults. Override per app (AuthProvider localization.organizationSwitcher) or per use (localization prop). */
export const ORGANIZATION_SWITCHER_TEXT: OrganizationSwitcherText = {
  triggerLabel: "Switch organization, current: {name}",
  personal: "Personal account",
  menuLabel: "Organizations",
  role: "{role}",
  create: "Create organization",
  createTitle: "Create an organization",
  createDescription: "You will be its owner, and it becomes your active organization.",
  nameLabel: "Name",
  namePlaceholder: "Acme Inc.",
  nameRequired: "Enter a name.",
  slugLabel: "Slug",
  slugDescription: "Lowercase letters, digits and dashes; used in links.",
  slugRequired: "Enter a slug.",
  slugInvalid: "Use 2 to 48 lowercase letters, digits and dashes, not starting with a dash.",
  cancel: "Cancel",
  submit: "Create",
  submitting: "Creating…",
}

/** The named parts classNames can style. */
export type OrganizationSwitcherSlot =
  | "root"
  | "trigger"
  | "logo"
  | "name"
  | "content"
  | "label"
  | "item"
  | "role"
  | "create"
  | "error"
  | "dialog"
  | "form"
  | "field"
  | "input"
  | "fieldError"
  | "submit"
  | "skeleton"

export type OrganizationSwitcherProps = AuthComponentProps<OrganizationSwitcherSlot, "organizationSwitcher", OrganizationOrg | null> & {
  /** Leave the personal account (no active organization) out of the menu. Shown by default. */
  readonly hidePersonal?: boolean
  /** Offer "Create organization". On by default; the server may still refuse it (organization.create_forbidden). */
  readonly allowCreate?: boolean
  /** Which side of the trigger the menu aligns to. */
  readonly align?: "start" | "center" | "end"
}

/** The radio value of the personal account, which no organization id can equal (ids are never empty). */
const PERSONAL = ""

/** The server's slug rule (organization.SlugPattern), checked here so a typo is caught before the round trip. */
const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{1,47}$/

/** The longest slug the server accepts. */
const MAX_SLUG_LENGTH = 48

/** A slug suggested from a name: lowercase, runs of anything else become one dash, trimmed to the server's length. */
export function slugFromName(name: string): string {
  return name
    .normalize("NFKD")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+/, "")
    .slice(0, MAX_SLUG_LENGTH)
    .replace(/-+$/, "")
}

/** Error codes that belong under a field of the create form. */
const FIELD_OF_ERROR: Readonly<Partial<Record<string, "name" | "slug">>> = {
  "organization.slug_taken": "slug",
  "organization.bad_slug": "slug",
}

export function OrganizationSwitcher({
  className,
  classNames,
  localization,
  onSuccess,
  redirectTo: requestedRedirectTo,
  hidePersonal = false,
  allowCreate = true,
  align = "start",
}: OrganizationSwitcherProps) {
  const t = useLocalization("organizationSwitcher", ORGANIZATION_SWITCHER_TEXT, localization)
  const messageFor = useErrorMessage()
  const { navigate } = useAuth()
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const plugin = usePluginClient("organization")
  const { user, isPending: sessionPending } = useSession()
  const { organizations, isPending: listPending } = useOrganizations()
  const { organization: active, activeOrganizationId, isPending: activePending } = useActiveOrganization()
  const { setActive } = useOrganizationActions()
  const [error, setError] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const errorId = useId()

  /** After a switch or a create: hand the organization over, or go to redirectTo when one was given. Switching stays on the page otherwise. */
  function done(org: OrganizationOrg | null) {
    if (onSuccess !== undefined) onSuccess(org)
    else if (redirectTo !== undefined) navigate(redirectTo)
  }

  const switchTo = useMutation({
    mutationFn: async (orgId: string): Promise<AuthError | null> =>
      setActive(orgId === PERSONAL ? null : { orgId }),
    onSuccess: (failure, orgId) => {
      if (failure !== null) {
        setError(messageFor(failure))
        return
      }
      done(orgId === PERSONAL ? null : (organizations.find((o) => o.id === orgId) ?? null))
    },
  })

  if (plugin === null || (!sessionPending && user === null)) return null
  if (sessionPending || listPending || activePending) {
    return <Skeleton aria-hidden className={cn("h-7 w-40 rounded-lg", className, classNames?.root, classNames?.skeleton)} />
  }

  const currentName = active?.name ?? t.personal
  const value = activeOrganizationId ?? PERSONAL

  return (
    <div className={cn("inline-flex flex-col gap-1", className, classNames?.root)}>
      <DropdownMenu>
        <DropdownMenuTrigger
          render={
            <Button
              variant="outline"
              className={cn("max-w-64 justify-start gap-2 px-1.5", classNames?.trigger)}
              aria-label={format(t.triggerLabel, { name: currentName })}
              aria-describedby={error === null ? undefined : errorId}
              disabled={switchTo.isPending}
              aria-busy={switchTo.isPending}
            />
          }
        >
          {switchTo.isPending ? <Spinner /> : <OrgMark org={active} className={classNames?.logo} />}
          <span className={cn("min-w-0 flex-1 truncate text-left", classNames?.name)}>{currentName}</span>
          <ChevronsUpDownIcon aria-hidden className="ml-auto text-muted-foreground" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align={align} className={cn("w-60", classNames?.content)}>
          <DropdownMenuGroup>
            <DropdownMenuLabel className={classNames?.label}>{t.menuLabel}</DropdownMenuLabel>
            <DropdownMenuRadioGroup
              value={value}
              onValueChange={(next: string) => {
                if (next === value) return
                setError(null)
                switchTo.mutate(next)
              }}
            >
              {!hidePersonal && (
                <DropdownMenuRadioItem value={PERSONAL} closeOnClick className={classNames?.item}>
                  <OrgMark org={null} />
                  <span className="min-w-0 flex-1 truncate">{t.personal}</span>
                </DropdownMenuRadioItem>
              )}
              {organizations.map((o) => (
                <DropdownMenuRadioItem key={o.id} value={o.id} closeOnClick className={classNames?.item}>
                  <OrgMark org={o} />
                  <span className="min-w-0 flex-1 truncate">{o.name}</span>
                  <span className={cn("text-xs text-muted-foreground capitalize", classNames?.role)}>{format(t.role, { role: o.role })}</span>
                </DropdownMenuRadioItem>
              ))}
            </DropdownMenuRadioGroup>
          </DropdownMenuGroup>
          {allowCreate && (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuGroup>
                <DropdownMenuItem className={classNames?.create} onClick={() => setCreating(true)}>
                  <PlusIcon aria-hidden />
                  {t.create}
                </DropdownMenuItem>
              </DropdownMenuGroup>
            </>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
      {error !== null && (
        <p id={errorId} role="alert" className={cn("text-xs text-destructive", classNames?.error)}>
          {error}
        </p>
      )}
      {allowCreate && (
        <Dialog open={creating} onOpenChange={setCreating}>
          <DialogContent className={classNames?.dialog}>
            <DialogHeader>
              <DialogTitle>{t.createTitle}</DialogTitle>
              <DialogDescription>{t.createDescription}</DialogDescription>
            </DialogHeader>
            {/* Mounted only while open, so each opening starts from an empty form. */}
            {creating && (
              <CreateOrganizationForm
                t={t}
                classNames={classNames}
                onClose={() => setCreating(false)}
                onCreated={(org) => {
                  setCreating(false)
                  done(org)
                }}
              />
            )}
          </DialogContent>
        </Dialog>
      )}
    </div>
  )
}

/** The create form inside the dialog: a name, and a slug suggested from it until the person edits the slug. */
function CreateOrganizationForm({
  t,
  classNames,
  onClose,
  onCreated,
}: {
  t: OrganizationSwitcherText
  classNames: OrganizationSwitcherProps["classNames"]
  onClose: () => void
  onCreated: (org: OrganizationOrg) => void
}) {
  const { create } = useOrganizationActions()
  const messageFor = useErrorMessage()
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [slugError, setSlugError] = useState<string | null>(null)
  // The slug follows the name until the person types in it.
  const [slugEdited, setSlugEdited] = useState(false)

  const submit = useMutation({
    mutationFn: (value: { name: string; slug: string }) => create({ name: value.name.trim(), slug: value.slug.trim() }),
    onSuccess: ({ organization, error }) => {
      if (error !== null) {
        if (FIELD_OF_ERROR[error.code] === "slug") setSlugError(messageFor(error))
        else setFormError(messageFor(error))
        return
      }
      if (organization !== null) onCreated(organization)
    },
  })

  const form = useForm({
    defaultValues: { name: "", slug: "" },
    validationLogic: revalidateLogic(),
    onSubmit: async ({ value }) => {
      setFormError(null)
      setSlugError(null)
      await submit.mutateAsync(value)
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
        className={classNames?.form}
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
          <form.Field name="name" validators={{ onDynamic: ({ value }) => (value.trim() === "" ? t.nameRequired : undefined) }}>
            {(field) => {
              const message = field.state.meta.errors[0]
              const invalid = message !== undefined
              return (
                <Field data-invalid={invalid} className={classNames?.field}>
                  <FieldLabel htmlFor={`${formId}-name`}>{t.nameLabel}</FieldLabel>
                  <Input
                    id={`${formId}-name`}
                    autoFocus
                    autoComplete="organization"
                    placeholder={t.namePlaceholder}
                    value={field.state.value}
                    onChange={(e) => {
                      field.handleChange(e.target.value)
                      if (!slugEdited) form.setFieldValue("slug", slugFromName(e.target.value))
                    }}
                    onBlur={field.handleBlur}
                    aria-invalid={invalid}
                    aria-describedby={invalid ? `${formId}-name-error` : undefined}
                    className={classNames?.input}
                  />
                  {invalid && (
                    <FieldError id={`${formId}-name-error`} className={classNames?.fieldError}>
                      {message}
                    </FieldError>
                  )}
                </Field>
              )
            }}
          </form.Field>
          <form.Field
            name="slug"
            validators={{
              onDynamic: ({ value }) => (value.trim() === "" ? t.slugRequired : SLUG_PATTERN.test(value.trim()) ? undefined : t.slugInvalid),
            }}
          >
            {(field) => {
              const message = field.state.meta.errors[0] ?? slugError ?? undefined
              const invalid = message !== undefined
              return (
                <Field data-invalid={invalid} className={classNames?.field}>
                  <FieldLabel htmlFor={`${formId}-slug`}>{t.slugLabel}</FieldLabel>
                  <Input
                    id={`${formId}-slug`}
                    autoComplete="off"
                    autoCapitalize="none"
                    spellCheck={false}
                    maxLength={MAX_SLUG_LENGTH}
                    value={field.state.value}
                    onChange={(e) => {
                      setSlugEdited(true)
                      setSlugError(null)
                      field.handleChange(e.target.value)
                    }}
                    onBlur={field.handleBlur}
                    aria-invalid={invalid}
                    aria-describedby={invalid ? `${formId}-slug-error` : `${formId}-slug-description`}
                    className={classNames?.input}
                  />
                  {invalid ? (
                    <FieldError id={`${formId}-slug-error`} className={classNames?.fieldError}>
                      {message}
                    </FieldError>
                  ) : (
                    <FieldDescription id={`${formId}-slug-description`}>{t.slugDescription}</FieldDescription>
                  )}
                </Field>
              )
            }}
          </form.Field>
        </FieldGroup>
      </form>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onClose} disabled={submit.isPending}>
          {t.cancel}
        </Button>
        <Button type="submit" form={formId} className={classNames?.submit} disabled={submit.isPending} aria-busy={submit.isPending}>
          {submit.isPending && <Spinner data-icon="inline-start" />}
          {submit.isPending ? t.submitting : t.submit}
        </Button>
      </DialogFooter>
    </>
  )
}

/** An organization's logo, or its initial in a square; the personal account is a person icon. */
export function OrgMark({ org, className }: { org: Pick<OrganizationOrg, "name" | "logo"> | null; className?: string }) {
  const base = "flex size-5 shrink-0 items-center justify-center overflow-hidden rounded-md border border-border bg-muted text-[10px] font-semibold uppercase text-foreground/80"
  if (org === null) {
    return (
      <span aria-hidden className={cn(base, className)}>
        <UserRoundIcon className="size-3" />
      </span>
    )
  }
  if (org.logo !== undefined && org.logo !== null && org.logo !== "") {
    return <img src={org.logo} alt="" className={cn(base, "object-cover", className)} />
  }
  return (
    <span aria-hidden className={cn(base, className)}>
      {org.name.trim().slice(0, 1)}
    </span>
  )
}
