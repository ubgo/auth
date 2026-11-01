import { revalidateLogic, useForm } from "@tanstack/react-form"
import type { OrganizationOrg, OrganizationOrgWithRole } from "@ubgo/auth-client"
import { ChevronsUpDownIcon, CircleAlertIcon, PlusIcon, UserRoundIcon } from "lucide-react"
import { useId, useRef, useState } from "react"

import { fillText } from "@/components/auth/auth-view"
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

// OrganizationSwitcherView: the organization menu button with no data
// layer. It is told the user's organizations, the active one, whether a
// switch or a create is running and what failed, and hands a switch
// (onSwitch) and a new organization (onCreate, with the typed name and slug)
// to callbacks. OrganizationSwitcher (organization-switcher.tsx) is this view
// wired to @ubgo/auth-react; render the view yourself to put the same menu
// on any other backend.

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

/** The radio value of the personal account, which no organization id can equal (ids are never empty). */
const PERSONAL = ""

/** The server's slug rule (organization.SlugPattern), checked here so a typo is caught before the round trip. */
const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{1,47}$/

/** The longest slug the server accepts. */
const MAX_SLUG_LENGTH = 48

/** The combining marks NFKD splits off an accented letter ("é" becomes "e" + U+0301). */
const COMBINING_MARKS = /[\u0300-\u036f]/g

/** A slug suggested from a name: accents dropped, lowercase, runs of anything else become one dash, trimmed to the server's length. */
export function slugFromName(name: string): string {
  return name
    .normalize("NFKD")
    .replace(COMBINING_MARKS, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+/, "")
    .slice(0, MAX_SLUG_LENGTH)
    .replace(/-+$/, "")
}

/** What the create form hands onCreate: the name and the slug, both trimmed. */
export type OrganizationCreateValues = {
  readonly name: string
  readonly slug: string
}

/** The props of OrganizationSwitcherView: the organizations, the menu's state, and a callback per action. */
export type OrganizationSwitcherViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<OrganizationSwitcherSlot, string>>
  /** Text overrides, merged over ORGANIZATION_SWITCHER_TEXT. */
  readonly text?: Partial<OrganizationSwitcherText>
  /** The session or the lists are still loading: a placeholder of the trigger's size. */
  readonly loading?: boolean
  /** The user's organizations with their role in each, one radio item each. */
  readonly organizations?: readonly OrganizationOrgWithRole[]
  /** The active organization, for the trigger's name and logo; null is the personal account. */
  readonly active?: OrganizationOrg | null
  /** The active organization's id, the checked radio item; null is the personal account. Defaults to active's id. */
  readonly activeId?: string | null
  /** Leave the personal account out of the menu. */
  readonly hidePersonal?: boolean
  /** Offer "Create organization" and its dialog. On by default. */
  readonly allowCreate?: boolean
  /** Which side of the trigger the menu aligns to. */
  readonly align?: "start" | "center" | "end"
  /** A switch is running: the trigger shows a spinner and is disabled. */
  readonly switching?: boolean
  /** A failed switch, shown under the trigger. */
  readonly error?: string | null
  /** The create dialog is open. */
  readonly createOpen?: boolean
  /** A create is running. */
  readonly createPending?: boolean
  /** A failed create, shown at the top of the dialog's form. */
  readonly createError?: string | null
  /** A failed create that belongs under the slug field, such as a taken slug. */
  readonly slugError?: string | null
  /** Another organization (an id) or the personal account (null) was picked. */
  readonly onSwitch?: (orgId: string | null) => void
  /** "Create organization" was chosen (true) or the dialog closed (false). */
  readonly onCreateOpenChange?: (open: boolean) => void
  /** The create form passed its checks. Awaited, so a slow call keeps the form submitting. */
  readonly onCreate?: (values: OrganizationCreateValues) => void | Promise<void>
  /** The slug was edited; a good moment to clear slugError. */
  readonly onSlugEdit?: () => void
}

/** The organization menu as plain props and callbacks; OrganizationSwitcher renders it from the session. */
export function OrganizationSwitcherView({
  className,
  classNames,
  text,
  loading = false,
  organizations = [],
  active = null,
  activeId,
  hidePersonal = false,
  allowCreate = true,
  align = "start",
  switching = false,
  error = null,
  createOpen = false,
  createPending = false,
  createError = null,
  slugError = null,
  onSwitch,
  onCreateOpenChange,
  onCreate,
  onSlugEdit,
}: OrganizationSwitcherViewProps) {
  const t: OrganizationSwitcherText = { ...ORGANIZATION_SWITCHER_TEXT, ...text }
  const errorId = useId()

  if (loading) {
    return <Skeleton aria-hidden className={cn("h-7 w-40 rounded-lg", className, classNames?.root, classNames?.skeleton)} />
  }

  const currentName = active?.name ?? t.personal
  const value = (activeId === undefined ? active?.id : activeId) ?? PERSONAL

  return (
    <div className={cn("inline-flex flex-col gap-1", className, classNames?.root)}>
      <DropdownMenu>
        <DropdownMenuTrigger
          render={
            <Button
              variant="outline"
              className={cn("max-w-64 justify-start gap-2 px-1.5", classNames?.trigger)}
              aria-label={fillText(t.triggerLabel, { name: currentName })}
              aria-describedby={error === null ? undefined : errorId}
              disabled={switching}
              aria-busy={switching}
            />
          }
        >
          {switching ? <Spinner /> : <OrgMark org={active} className={classNames?.logo} />}
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
                onSwitch?.(next === PERSONAL ? null : next)
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
                  <span className={cn("text-xs text-muted-foreground capitalize", classNames?.role)}>{fillText(t.role, { role: o.role })}</span>
                </DropdownMenuRadioItem>
              ))}
            </DropdownMenuRadioGroup>
          </DropdownMenuGroup>
          {allowCreate && (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuGroup>
                <DropdownMenuItem className={classNames?.create} onClick={() => onCreateOpenChange?.(true)}>
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
        <Dialog open={createOpen} onOpenChange={(open) => onCreateOpenChange?.(open)}>
          <DialogContent className={classNames?.dialog}>
            <DialogHeader>
              <DialogTitle>{t.createTitle}</DialogTitle>
              <DialogDescription>{t.createDescription}</DialogDescription>
            </DialogHeader>
            {/* Mounted only while open, so each opening starts from an empty form. */}
            {createOpen && (
              <CreateOrganizationForm
                t={t}
                classNames={classNames}
                pending={createPending}
                formError={createError}
                slugError={slugError}
                onClose={() => onCreateOpenChange?.(false)}
                onCreate={onCreate}
                onSlugEdit={onSlugEdit}
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
  pending,
  formError,
  slugError,
  onClose,
  onCreate,
  onSlugEdit,
}: {
  t: OrganizationSwitcherText
  classNames: OrganizationSwitcherViewProps["classNames"]
  pending: boolean
  formError: string | null
  slugError: string | null
  onClose: () => void
  onCreate: ((values: OrganizationCreateValues) => void | Promise<void>) | undefined
  onSlugEdit: (() => void) | undefined
}) {
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)
  // The slug follows the name until the person types in it.
  const [slugEdited, setSlugEdited] = useState(false)

  const form = useForm({
    defaultValues: { name: "", slug: "" },
    validationLogic: revalidateLogic(),
    onSubmit: async ({ value }) => {
      await onCreate?.({ name: value.name.trim(), slug: value.slug.trim() })
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
                      onSlugEdit?.()
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
        <Button type="button" variant="outline" onClick={onClose} disabled={pending}>
          {t.cancel}
        </Button>
        <Button type="submit" form={formId} className={classNames?.submit} disabled={pending} aria-busy={pending}>
          {pending && <Spinner data-icon="inline-start" />}
          {pending ? t.submitting : t.submit}
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
