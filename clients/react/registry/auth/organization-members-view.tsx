import { revalidateLogic, useForm } from "@tanstack/react-form"
import type { OrganizationInvitation, OrganizationMemberView } from "@ubgo/auth-client"
import {
  ChevronDownIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  CircleAlertIcon,
  EllipsisIcon,
  LogOutIcon,
  MailIcon,
  UserMinusIcon,
  UsersRoundIcon,
} from "lucide-react"
import { useId, useRef, useState } from "react"

import { fillText, type ViewHeadingLevel } from "@/components/auth/auth-view"
import { Alert, AlertDescription } from "@/components/ui/alert"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
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
import { Field, FieldError, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// OrganizationMembersView: the members card with no data layer. It is told
// the page of members, the pending invitations, what the caller may do and
// what is running or failed per row, and hands every action to a callback:
// a role change, a removal, leaving, cancelling an invitation, a new page and
// a new invitation (with the typed email and the chosen role).
// OrganizationMembers (organization-members.tsx) is this view wired to
// @ubgo/auth-react; render the view yourself to put the same card on any
// other backend.

/** Every string OrganizationMembers shows. */
export type OrganizationMembersText = {
  title: string
  /** `{organization}` is the organization's name. */
  description: string
  noOrganization: string
  empty: string
  you: string
  unnamed: string
  /** `{date}` is when they joined. */
  joined: string
  /** `{from}`, `{to}` and `{total}` describe the page shown. */
  range: string
  previous: string
  next: string
  inviteHeading: string
  emailLabel: string
  emailPlaceholder: string
  emailRequired: string
  roleLabel: string
  invite: string
  inviting: string
  /** `{email}` is the invited address. */
  invited: string
  pendingHeading: string
  /** `{date}` is when the invitation lapses. */
  expires: string
  cancelInvitation: string
  /** The cancel button's accessible name; `{email}` is the invited address. */
  cancelInvitationLabel: string
  /** The member menu's accessible name; `{name}` is the member's name. */
  memberActions: string
  /** The role choice's heading in the member menu. */
  changeRole: string
  remove: string
  leave: string
  /** `{name}` is the member's name. */
  removeTitle: string
  /** `{name}` is the member's name, `{organization}` the organization's. */
  removeDescription: string
  /** `{organization}` is the organization's name. */
  leaveTitle: string
  leaveDescription: string
  removeConfirm: string
  leaveConfirm: string
  /** The confirmation's way back. */
  keep: string
  /** Announced after a role change; `{name}` is the member, `{role}` the new role. */
  roleChanged: string
}

/** The English defaults. Override per app (AuthProvider localization.organizationMembers) or per use (localization prop). */
export const ORGANIZATION_MEMBERS_TEXT: OrganizationMembersText = {
  title: "Members",
  description: "People in {organization}.",
  noOrganization: "Choose or create an organization to see its members.",
  empty: "No members yet.",
  you: "You",
  unnamed: "Unnamed",
  joined: "Joined {date}",
  range: "{from}–{to} of {total}",
  previous: "Previous page",
  next: "Next page",
  inviteHeading: "Invite someone",
  emailLabel: "Email",
  emailPlaceholder: "name@example.com",
  emailRequired: "Enter an email address.",
  roleLabel: "Role",
  invite: "Invite",
  inviting: "Inviting…",
  invited: "Invitation sent to {email}.",
  pendingHeading: "Pending invitations",
  expires: "Expires {date}",
  cancelInvitation: "Cancel",
  cancelInvitationLabel: "Cancel the invitation to {email}",
  memberActions: "Actions for {name}",
  changeRole: "Role",
  remove: "Remove from organization",
  leave: "Leave organization",
  removeTitle: "Remove {name}?",
  removeDescription: "{name} loses access to {organization} at once. You can invite them again later.",
  leaveTitle: "Leave {organization}?",
  leaveDescription: "You lose access at once, until someone invites you again.",
  removeConfirm: "Remove",
  leaveConfirm: "Leave",
  keep: "Keep",
  roleChanged: "{name} is now {role}.",
}

/** The named parts classNames can style. */
export type OrganizationMembersSlot =
  | "root"
  | "header"
  | "title"
  | "description"
  | "content"
  | "list"
  | "member"
  | "avatar"
  | "memberName"
  | "badge"
  | "pagination"
  | "inviteForm"
  | "input"
  | "roleTrigger"
  | "submit"
  | "fieldError"
  | "formError"
  | "status"
  | "invitations"
  | "invitation"
  | "cancelButton"
  | "memberMenu"
  | "memberError"
  | "confirmDialog"

/** What the invite form hands onInvite: the address, trimmed, and the chosen role. */
export type OrganizationInviteValues = { readonly email: string; readonly role: string }

/** Which call runs on a member row: a role change, or the removal (or leaving, on the caller's own row). */
export type MemberAction = "role" | "remove"

/** The props of OrganizationMembersView: the members and invitations, what the caller may do, per-row state, and a callback per action. */
export type OrganizationMembersViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<OrganizationMembersSlot, string>>
  /** Text overrides, merged over ORGANIZATION_MEMBERS_TEXT. */
  readonly text?: Partial<OrganizationMembersText>
  /** The level of the title, 1 by default. */
  readonly headingLevel?: ViewHeadingLevel
  /** The organization's name, for the description and the confirmations; empty hides the description. */
  readonly organizationName?: string
  /** There is an organization to show. False says to choose or create one. True by default. */
  readonly hasOrganization?: boolean
  /** The members (or, without an organization, the active one) are still loading. */
  readonly loading?: boolean
  /** The members could not be loaded. */
  readonly loadError?: string | null
  /** The signed-in user's id: their row says "You" and offers Leave. */
  readonly currentUserId?: string
  /** This page's members. */
  readonly members?: readonly OrganizationMemberView[]
  /** All members across pages; the pager shows when it exceeds pageSize. */
  readonly total?: number
  /** The page shown, from 1. */
  readonly page?: number
  /** Members per page. */
  readonly pageSize?: number
  /** The open invitations, listed under the members. */
  readonly invitations?: readonly OrganizationInvitation[]
  /** The caller may change roles: the member menu offers memberRoles. */
  readonly canChangeRole?: boolean
  /** The caller may remove other members. */
  readonly canRemove?: boolean
  /** The caller may cancel invitations. */
  readonly canCancel?: boolean
  /** The caller may invite: the invite form shows when inviteRoles is not empty. */
  readonly canInvite?: boolean
  /** The roles a member's menu offers. */
  readonly memberRoles?: readonly string[]
  /** The roles the invite form offers, first one preselected. */
  readonly inviteRoles?: readonly string[]
  /** The running call per member's user id. */
  readonly memberPending?: Readonly<Record<string, MemberAction>>
  /** A failed call's message per member's user id. */
  readonly memberErrors?: Readonly<Record<string, string>>
  /** The role a member was just changed to, per user id, announced in their row. */
  readonly roleChanged?: Readonly<Record<string, string>>
  /** The invitation ids whose cancel is running. */
  readonly cancelling?: Readonly<Record<string, boolean>>
  /** A failed cancel's message per invitation id. */
  readonly invitationErrors?: Readonly<Record<string, string>>
  /** An invitation is being sent. */
  readonly inviting?: boolean
  /** A failed invitation that belongs under the email field. */
  readonly inviteEmailError?: string | null
  /** A failed invitation shown above the invite form. */
  readonly inviteFormError?: string | null
  /** The address an invitation just went to, announced under the form. */
  readonly invitedTo?: string | null
  /** A member's role was picked. */
  readonly onRoleChange?: (member: OrganizationMemberView, role: string) => void
  /** Remove was confirmed for another member. Awaited; the confirmation closes when it settles. */
  readonly onRemove?: (member: OrganizationMemberView) => void | Promise<void>
  /** Leave was confirmed on the caller's own row. Awaited; the confirmation closes when it settles. */
  readonly onLeave?: () => void | Promise<void>
  /** An invitation's Cancel was pressed. */
  readonly onCancelInvitation?: (invitation: OrganizationInvitation) => void
  /** Previous or next page was pressed. */
  readonly onPageChange?: (page: number) => void
  /** The invite form passed its check. Resolve true when the invitation went out, and the field clears. */
  readonly onInvite?: (values: OrganizationInviteValues) => void | boolean | Promise<void | boolean>
  /** The email field was edited; a good moment to clear inviteEmailError. */
  readonly onInviteEmailEdit?: () => void
}

function formatDate(iso: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(new Date(iso))
}

/** The members card as plain props and callbacks; OrganizationMembers renders it from the organization plugin. */
export function OrganizationMembersView({
  className,
  classNames,
  text,
  headingLevel = 1,
  organizationName = "",
  hasOrganization = true,
  loading = false,
  loadError = null,
  currentUserId,
  members = [],
  total = members.length,
  page = 1,
  pageSize = Math.max(1, members.length),
  invitations = [],
  canChangeRole = false,
  canRemove = false,
  canCancel = false,
  canInvite = false,
  memberRoles = [],
  inviteRoles = [],
  memberPending = {},
  memberErrors = {},
  roleChanged = {},
  cancelling = {},
  invitationErrors = {},
  inviting = false,
  inviteEmailError = null,
  inviteFormError = null,
  invitedTo = null,
  onRoleChange,
  onRemove,
  onLeave,
  onCancelInvitation,
  onPageChange,
  onInvite,
  onInviteEmailEdit,
}: OrganizationMembersViewProps) {
  const t: OrganizationMembersText = { ...ORGANIZATION_MEMBERS_TEXT, ...text }
  const pendingHeadingId = useId()
  const name = organizationName
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1
  const to = Math.min(page * pageSize, total)
  const lastPage = Math.max(1, Math.ceil(total / pageSize))

  return (
    <Card className={cn("w-full max-w-xl", className, classNames?.root)}>
      <CardHeader className={classNames?.header}>
        <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
          <UsersRoundIcon aria-hidden className="size-4 text-muted-foreground" />
          {t.title}
        </CardTitle>
        {name !== "" && <CardDescription className={classNames?.description}>{fillText(t.description, { organization: name })}</CardDescription>}
      </CardHeader>
      <CardContent className={cn("flex flex-col gap-4", classNames?.content)}>
        {!hasOrganization ? (
          loading ? (
            <MemberSkeleton />
          ) : (
            <p className="text-[13px] text-muted-foreground">{t.noOrganization}</p>
          )
        ) : (
          <>
            {loadError !== null && (
              <Alert variant="destructive" className={classNames?.formError}>
                <CircleAlertIcon aria-hidden />
                <AlertDescription>{loadError}</AlertDescription>
              </Alert>
            )}
            {loading ? (
              <MemberSkeleton />
            ) : members.length === 0 ? (
              <p className="text-[13px] text-muted-foreground">{t.empty}</p>
            ) : (
              <ul className={cn("flex flex-col divide-y divide-border rounded-lg border border-border", classNames?.list)}>
                {members.map((m) => (
                  <MemberRow
                    key={m.user.id}
                    member={m}
                    organizationName={name}
                    self={m.user.id === currentUserId}
                    roles={canChangeRole ? memberRoles : []}
                    canRemove={canRemove}
                    pending={memberPending[m.user.id] ?? null}
                    error={memberErrors[m.user.id] ?? null}
                    changedTo={roleChanged[m.user.id] ?? null}
                    t={t}
                    classNames={classNames}
                    onRoleChange={onRoleChange}
                    onRemove={onRemove}
                    onLeave={onLeave}
                  />
                ))}
              </ul>
            )}
            {total > pageSize && (
              <nav aria-label={t.title} className={cn("flex items-center justify-end gap-2 text-xs text-muted-foreground tabular-nums", classNames?.pagination)}>
                <span>{fillText(t.range, { from, to, total })}</span>
                <Button type="button" variant="outline" size="icon-sm" aria-label={t.previous} disabled={page <= 1} onClick={() => onPageChange?.(page - 1)}>
                  <ChevronLeftIcon aria-hidden />
                </Button>
                <Button type="button" variant="outline" size="icon-sm" aria-label={t.next} disabled={page >= lastPage} onClick={() => onPageChange?.(page + 1)}>
                  <ChevronRightIcon aria-hidden />
                </Button>
              </nav>
            )}

            {invitations.length > 0 && (
              <section className={cn("flex flex-col gap-1.5", classNames?.invitations)} aria-labelledby={pendingHeadingId}>
                <h3 id={pendingHeadingId} className="text-xs font-medium text-muted-foreground">
                  {t.pendingHeading}
                </h3>
                <ul className="flex flex-col divide-y divide-border rounded-lg border border-border">
                  {invitations.map((i) => (
                    <InvitationRow
                      key={i.id}
                      invitation={i}
                      canCancel={canCancel}
                      pending={cancelling[i.id] === true}
                      error={invitationErrors[i.id] ?? null}
                      t={t}
                      classNames={classNames}
                      onCancel={onCancelInvitation}
                    />
                  ))}
                </ul>
              </section>
            )}

            {canInvite && inviteRoles.length > 0 && (
              <InviteForm
                roles={inviteRoles}
                t={t}
                classNames={classNames}
                pending={inviting}
                emailError={inviteEmailError}
                formError={inviteFormError}
                sentTo={invitedTo}
                onInvite={onInvite}
                onEmailEdit={onInviteEmailEdit}
              />
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}

function MemberSkeleton() {
  return (
    <div aria-hidden className="flex flex-col gap-2">
      <Skeleton className="h-9 w-full rounded-lg" />
      <Skeleton className="h-9 w-full rounded-lg" />
    </div>
  )
}

/** Which confirmation is open on a member row. */
type Confirming = "remove" | "leave" | null

/**
 * One member: avatar, name, "You", their role and when they joined, and a
 * menu with the role choice (`roles`, empty when the caller may not change
 * roles), Remove (when allowed) or, on the caller's own row, Leave.
 */
function MemberRow({
  member,
  organizationName,
  self,
  roles,
  canRemove,
  pending,
  error,
  changedTo,
  t,
  classNames,
  onRoleChange,
  onRemove,
  onLeave,
}: {
  member: OrganizationMemberView
  organizationName: string
  self: boolean
  roles: readonly string[]
  canRemove: boolean
  pending: MemberAction | null
  error: string | null
  changedTo: string | null
  t: OrganizationMembersText
  classNames: OrganizationMembersViewProps["classNames"]
  onRoleChange: OrganizationMembersViewProps["onRoleChange"]
  onRemove: OrganizationMembersViewProps["onRemove"]
  onLeave: OrganizationMembersViewProps["onLeave"]
}) {
  const errorId = useId()
  const [confirming, setConfirming] = useState<Confirming>(null)
  const name = member.user.name.trim()
  const shown = name === "" ? t.unnamed : name

  const canDrop = self || canRemove
  const hasMenu = roles.length > 0 || canDrop
  const busy = pending !== null
  const dropping = pending === "remove"

  async function drop() {
    try {
      await (self ? onLeave?.() : onRemove?.(member))
    } finally {
      setConfirming(null)
    }
  }

  return (
    <li className={cn("flex items-center gap-2.5 px-2.5 py-1.5", classNames?.member)}>
      <Avatar size="sm" className={classNames?.avatar}>
        {member.user.image !== "" && <AvatarImage src={member.user.image} alt="" />}
        <AvatarFallback className="text-[10px] font-medium text-foreground/80">{(name === "" ? "?" : name.slice(0, 1)).toUpperCase()}</AvatarFallback>
      </Avatar>
      <div className="flex min-w-0 flex-1 flex-col">
        <span className={cn("flex items-center gap-1.5 truncate text-[13px] font-medium", classNames?.memberName)}>
          {shown}
          {self && (
            <Badge variant="outline" className={classNames?.badge}>
              {t.you}
            </Badge>
          )}
        </span>
        <span className="text-xs text-muted-foreground">{fillText(t.joined, { date: formatDate(member.joinedAt) })}</span>
        {error !== null && (
          <span id={errorId} role="alert" className={cn("text-xs text-destructive", classNames?.memberError)}>
            {error}
          </span>
        )}
        {changedTo !== null && (
          <span role="status" className={cn("text-xs text-muted-foreground", classNames?.status)}>
            {fillText(t.roleChanged, { name: shown, role: changedTo })}
          </span>
        )}
      </div>
      <Badge variant="secondary" className={cn("capitalize", classNames?.badge)}>
        {member.role}
      </Badge>
      {hasMenu && (
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <Button
                type="button"
                variant="ghost"
                size="icon-sm"
                className={classNames?.memberMenu}
                aria-label={fillText(t.memberActions, { name: shown })}
                aria-describedby={error === null ? undefined : errorId}
                aria-busy={busy}
                disabled={busy}
              />
            }
          >
            {busy ? <Spinner /> : <EllipsisIcon aria-hidden />}
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-52">
            {roles.length > 0 && (
              <DropdownMenuGroup>
                <DropdownMenuLabel>{t.changeRole}</DropdownMenuLabel>
                <DropdownMenuRadioGroup
                  value={member.role}
                  onValueChange={(next: string) => {
                    if (next !== member.role) onRoleChange?.(member, next)
                  }}
                >
                  {roles.map((r) => (
                    <DropdownMenuRadioItem key={r} value={r} closeOnClick className="capitalize">
                      {r}
                    </DropdownMenuRadioItem>
                  ))}
                </DropdownMenuRadioGroup>
              </DropdownMenuGroup>
            )}
            {roles.length > 0 && canDrop && <DropdownMenuSeparator />}
            {canDrop && (
              <DropdownMenuItem variant="destructive" onClick={() => setConfirming(self ? "leave" : "remove")}>
                {self ? <LogOutIcon aria-hidden /> : <UserMinusIcon aria-hidden />}
                {self ? t.leave : t.remove}
              </DropdownMenuItem>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      )}
      <AlertDialog
        open={confirming !== null}
        onOpenChange={(open) => {
          if (!open && !dropping) setConfirming(null)
        }}
      >
        <AlertDialogContent className={classNames?.confirmDialog}>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {confirming === "leave" ? fillText(t.leaveTitle, { organization: organizationName }) : fillText(t.removeTitle, { name: shown })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {confirming === "leave" ? t.leaveDescription : fillText(t.removeDescription, { name: shown, organization: organizationName })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={dropping}>{t.keep}</AlertDialogCancel>
            <AlertDialogAction variant="destructive" disabled={dropping} aria-busy={dropping} onClick={() => void drop()}>
              {dropping && <Spinner data-icon="inline-start" />}
              {confirming === "leave" ? t.leaveConfirm : t.removeConfirm}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </li>
  )
}

/** One pending invitation, with Cancel for those allowed to cancel it. */
function InvitationRow({
  invitation,
  canCancel,
  pending,
  error,
  t,
  classNames,
  onCancel,
}: {
  invitation: OrganizationInvitation
  canCancel: boolean
  pending: boolean
  error: string | null
  t: OrganizationMembersText
  classNames: OrganizationMembersViewProps["classNames"]
  onCancel: OrganizationMembersViewProps["onCancelInvitation"]
}) {
  const errorId = useId()
  const address = invitation.email === "" ? invitation.identifier : invitation.email
  return (
    <li className={cn("flex items-center gap-2.5 px-2.5 py-1.5", classNames?.invitation)}>
      <MailIcon aria-hidden className="size-3.5 shrink-0 text-muted-foreground" />
      <div className="flex min-w-0 flex-1 flex-col">
        <span className="truncate text-[13px]">{address}</span>
        <span className="text-xs text-muted-foreground">{fillText(t.expires, { date: formatDate(invitation.expiresAt) })}</span>
        {error !== null && (
          <span id={errorId} role="alert" className="text-xs text-destructive">
            {error}
          </span>
        )}
      </div>
      <Badge variant="outline" className={cn("capitalize", classNames?.badge)}>
        {invitation.role}
      </Badge>
      {canCancel && (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className={classNames?.cancelButton}
          aria-label={fillText(t.cancelInvitationLabel, { email: address })}
          aria-describedby={error === null ? undefined : errorId}
          disabled={pending}
          aria-busy={pending}
          onClick={() => onCancel?.(invitation)}
        >
          {pending && <Spinner data-icon="inline-start" />}
          {t.cancelInvitation}
        </Button>
      )}
    </li>
  )
}

/** The invite row: an email, a role from `roles`, and Invite. */
function InviteForm({
  roles,
  t,
  classNames,
  pending,
  emailError,
  formError,
  sentTo,
  onInvite,
  onEmailEdit,
}: {
  roles: readonly string[]
  t: OrganizationMembersText
  classNames: OrganizationMembersViewProps["classNames"]
  pending: boolean
  emailError: string | null
  formError: string | null
  sentTo: string | null
  onInvite: OrganizationMembersViewProps["onInvite"]
  onEmailEdit: (() => void) | undefined
}) {
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)
  const [role, setRole] = useState(roles[0] ?? "")

  const form = useForm({
    defaultValues: { email: "" },
    validationLogic: revalidateLogic(),
    onSubmit: async ({ value }) => {
      const sent = await onInvite?.({ email: value.email.trim(), role })
      if (sent === true) form.reset()
    },
    onSubmitInvalid: () => {
      formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
    },
  })

  return (
    <form
      ref={formRef}
      noValidate
      aria-labelledby={`${formId}-heading`}
      className={cn("flex flex-col gap-2", classNames?.inviteForm)}
      onSubmit={(e) => {
        e.preventDefault()
        e.stopPropagation()
        void form.handleSubmit()
      }}
    >
      <h3 id={`${formId}-heading`} className="text-xs font-medium text-muted-foreground">
        {t.inviteHeading}
      </h3>
      {formError !== null && (
        <Alert variant="destructive" className={classNames?.formError}>
          <CircleAlertIcon aria-hidden />
          <AlertDescription>{formError}</AlertDescription>
        </Alert>
      )}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start">
        <form.Field name="email" validators={{ onDynamic: ({ value }) => (value.trim() === "" ? t.emailRequired : undefined) }}>
          {(field) => {
            const message = field.state.meta.errors[0] ?? emailError ?? undefined
            const invalid = message !== undefined
            return (
              <Field data-invalid={invalid} className="flex-1">
                <FieldLabel htmlFor={`${formId}-email`} className="sr-only">
                  {t.emailLabel}
                </FieldLabel>
                <Input
                  id={`${formId}-email`}
                  type="email"
                  inputMode="email"
                  autoComplete="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  placeholder={t.emailPlaceholder}
                  value={field.state.value}
                  onChange={(e) => {
                    onEmailEdit?.()
                    field.handleChange(e.target.value)
                  }}
                  onBlur={field.handleBlur}
                  aria-invalid={invalid}
                  aria-describedby={invalid ? `${formId}-email-error` : undefined}
                  className={classNames?.input}
                />
                {invalid && (
                  <FieldError id={`${formId}-email-error`} className={classNames?.fieldError}>
                    {message}
                  </FieldError>
                )}
              </Field>
            )
          }}
        </form.Field>
        <div className="flex gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger
              render={
                <Button
                  type="button"
                  variant="outline"
                  className={cn("min-w-24 justify-between capitalize", classNames?.roleTrigger)}
                  aria-label={`${t.roleLabel}: ${role}`}
                />
              }
            >
              {role}
              <ChevronDownIcon aria-hidden className="text-muted-foreground" />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-36">
              <DropdownMenuRadioGroup value={role} onValueChange={(next: string) => setRole(next)}>
                {roles.map((r) => (
                  <DropdownMenuRadioItem key={r} value={r} closeOnClick className="capitalize">
                    {r}
                  </DropdownMenuRadioItem>
                ))}
              </DropdownMenuRadioGroup>
            </DropdownMenuContent>
          </DropdownMenu>
          <Button type="submit" className={cn("flex-1 sm:flex-none", classNames?.submit)} disabled={pending} aria-busy={pending}>
            {pending && <Spinner data-icon="inline-start" />}
            {pending ? t.inviting : t.invite}
          </Button>
        </div>
      </div>
      {sentTo !== null && (
        <p role="status" className={cn("text-xs text-muted-foreground", classNames?.status)}>
          {fillText(t.invited, { email: sentTo })}
        </p>
      )}
    </form>
  )
}
