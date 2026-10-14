import { revalidateLogic, useForm } from "@tanstack/react-form"
import { useMutation } from "@tanstack/react-query"
import type { OrganizationInvitation, OrganizationMemberView } from "@ubgo/auth-client"
import {
  format,
  useActiveOrganization,
  useErrorMessage,
  useLocalization,
  useOrganizationActions,
  useOrganizationInvitations,
  useOrganizationMembers,
  useOrganizationPermission,
  usePluginClient,
  useSession,
  type AuthComponentProps,
} from "@ubgo/auth-react"
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

// OrganizationMembers: the members of an organization (the session's active
// one by default), a page at a time, its pending invitations, and an invite
// form, with a menu on each member to change their role, remove them, or
// (on your own row) leave. The invite form, the cancel buttons, the role
// choice and Remove show only to callers the server says may use them
// (organization.has-permission), whatever roles or authorizer the server
// runs; Leave shows to every member, since the server lets anyone but the
// last owner leave. Remove and Leave ask for confirmation first.

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

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    organizationMembers: OrganizationMembersText
  }
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

/** What an invite hands to onSuccess. */
export type OrganizationInviteSuccess = { readonly email: string; readonly role: string }

export type OrganizationMembersProps = AuthComponentProps<OrganizationMembersSlot, "organizationMembers", OrganizationInviteSuccess> & {
  /** The organization to show; the session's active one when left out. */
  readonly orgId?: string
  /** Members per page. */
  readonly pageSize?: number
  /** The roles the invite form offers, first one preselected. The server's own role names (owner, admin, member by default). */
  readonly inviteRoles?: readonly string[]
  /** The roles a member's menu offers to change to. The server refuses what the caller may not grant (only an owner grants owner). */
  readonly memberRoles?: readonly string[]
  /** Called after the caller left the organization, with its id; the app usually navigates away. */
  readonly onLeave?: (orgId: string) => void
}

/** Members per page by default: one screen of compact rows. */
const DEFAULT_PAGE_SIZE = 10

/** The roles offered by default: the plugin's two non-owner roles. */
const DEFAULT_INVITE_ROLES: readonly string[] = ["member", "admin"]

/** The roles a member can be changed to by default: the plugin's three built-in roles. */
const DEFAULT_MEMBER_ROLES: readonly string[] = ["member", "admin", "owner"]

/** The invitation status that is still open (organization.Invitation.status). */
const PENDING = "pending"

/** The permissions the invite form and the cancel buttons need, as the plugin's DefaultStatements name them. */
const CAN_INVITE = { invitation: ["create"] } as const
const CAN_CANCEL = { invitation: ["cancel"] } as const
/** What the role choice and Remove need (organization.set-role, organization.remove-member). */
const CAN_UPDATE_MEMBER = { member: ["update"] } as const
const CAN_REMOVE_MEMBER = { member: ["delete"] } as const

/** Error codes that belong under the email field. */
const EMAIL_ERRORS: ReadonlySet<string> = new Set(["organization.invite_address", "organization.already_member", "organization.already_invited"])

function formatDate(iso: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(new Date(iso))
}

export function OrganizationMembers({
  className,
  classNames,
  localization,
  onSuccess,
  orgId,
  pageSize = DEFAULT_PAGE_SIZE,
  inviteRoles = DEFAULT_INVITE_ROLES,
  memberRoles = DEFAULT_MEMBER_ROLES,
  onLeave,
  headingLevel = 1,
}: OrganizationMembersProps) {
  const t = useLocalization("organizationMembers", ORGANIZATION_MEMBERS_TEXT, localization)
  const plugin = usePluginClient("organization")
  const { user } = useSession()
  const { organization: active, isPending: activePending } = useActiveOrganization()
  const [page, setPage] = useState(1)
  const members = useOrganizationMembers({ ...(orgId === undefined ? {} : { orgId }), page, limit: pageSize })
  const { invitations } = useOrganizationInvitations(orgId)
  const canInvite = useOrganizationPermission(CAN_INVITE, orgId).allowed
  const canCancel = useOrganizationPermission(CAN_CANCEL, orgId).allowed
  const canUpdate = useOrganizationPermission(CAN_UPDATE_MEMBER, orgId).allowed
  const canRemove = useOrganizationPermission(CAN_REMOVE_MEMBER, orgId).allowed
  const messageFor = useErrorMessage()
  const pendingHeadingId = useId()

  if (plugin === null || user === null) return null

  const name = orgId === undefined ? (active?.name ?? "") : (active?.id === orgId ? active.name : "")
  const pending = invitations.filter((i) => i.status === PENDING)
  const from = members.total === 0 ? 0 : (page - 1) * pageSize + 1
  const to = Math.min(page * pageSize, members.total)
  const lastPage = Math.max(1, Math.ceil(members.total / pageSize))

  return (
    <Card className={cn("w-full max-w-xl", className, classNames?.root)}>
      <CardHeader className={classNames?.header}>
        <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
          <UsersRoundIcon aria-hidden className="size-4 text-muted-foreground" />
          {t.title}
        </CardTitle>
        {name !== "" && <CardDescription className={classNames?.description}>{format(t.description, { organization: name })}</CardDescription>}
      </CardHeader>
      <CardContent className={cn("flex flex-col gap-4", classNames?.content)}>
        {members.orgId === null ? (
          activePending ? (
            <MemberSkeleton />
          ) : (
            <p className="text-[13px] text-muted-foreground">{t.noOrganization}</p>
          )
        ) : (
          <>
            {members.error !== null && (
              <Alert variant="destructive" className={classNames?.formError}>
                <CircleAlertIcon aria-hidden />
                <AlertDescription>{messageFor(members.error)}</AlertDescription>
              </Alert>
            )}
            {members.isPending ? (
              <MemberSkeleton />
            ) : members.members.length === 0 ? (
              <p className="text-[13px] text-muted-foreground">{t.empty}</p>
            ) : (
              <ul className={cn("flex flex-col divide-y divide-border rounded-lg border border-border", classNames?.list)}>
                {members.members.map((m) => (
                  <MemberRow
                    key={m.user.id}
                    member={m}
                    orgId={members.orgId ?? ""}
                    organizationName={name}
                    self={m.user.id === user.id}
                    roles={canUpdate ? memberRoles : []}
                    canRemove={canRemove}
                    t={t}
                    classNames={classNames}
                    onLeave={onLeave}
                  />
                ))}
              </ul>
            )}
            {members.total > pageSize && (
              <nav aria-label={t.title} className={cn("flex items-center justify-end gap-2 text-xs text-muted-foreground tabular-nums", classNames?.pagination)}>
                <span>{format(t.range, { from, to, total: members.total })}</span>
                <Button type="button" variant="outline" size="icon-sm" aria-label={t.previous} disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                  <ChevronLeftIcon aria-hidden />
                </Button>
                <Button type="button" variant="outline" size="icon-sm" aria-label={t.next} disabled={page >= lastPage} onClick={() => setPage((p) => p + 1)}>
                  <ChevronRightIcon aria-hidden />
                </Button>
              </nav>
            )}

            {pending.length > 0 && (
              <section className={cn("flex flex-col gap-1.5", classNames?.invitations)} aria-labelledby={pendingHeadingId}>
                <h3 id={pendingHeadingId} className="text-xs font-medium text-muted-foreground">
                  {t.pendingHeading}
                </h3>
                <ul className="flex flex-col divide-y divide-border rounded-lg border border-border">
                  {pending.map((i) => (
                    <InvitationRow key={i.id} invitation={i} canCancel={canCancel} t={t} classNames={classNames} />
                  ))}
                </ul>
              </section>
            )}

            {canInvite && inviteRoles.length > 0 && (
              <InviteForm orgId={members.orgId} roles={inviteRoles} t={t} classNames={classNames} onInvited={onSuccess} />
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
  orgId,
  organizationName,
  self,
  roles,
  canRemove,
  t,
  classNames,
  onLeave,
}: {
  member: OrganizationMemberView
  orgId: string
  organizationName: string
  self: boolean
  roles: readonly string[]
  canRemove: boolean
  t: OrganizationMembersText
  classNames: OrganizationMembersProps["classNames"]
  onLeave: ((orgId: string) => void) | undefined
}) {
  const { removeMember, leave, setRole } = useOrganizationActions()
  const messageFor = useErrorMessage()
  const errorId = useId()
  const [error, setError] = useState<string | null>(null)
  const [changed, setChanged] = useState<string | null>(null)
  const [confirming, setConfirming] = useState<Confirming>(null)
  const name = member.user.name.trim()
  const shown = name === "" ? t.unnamed : name
  const userId = member.user.id

  const changeRole = useMutation({
    mutationFn: (role: string) => setRole({ orgId, userId, role }),
    onMutate: () => {
      setError(null)
      setChanged(null)
    },
    onSuccess: (failure, role) => {
      if (failure === null) setChanged(format(t.roleChanged, { name: shown, role }))
      else setError(messageFor(failure))
    },
  })
  const drop = useMutation({
    mutationFn: () => (self ? leave(orgId) : removeMember({ orgId, userId })),
    onMutate: () => {
      setError(null)
      setChanged(null)
    },
    onSuccess: (failure) => {
      setConfirming(null)
      if (failure !== null) {
        setError(messageFor(failure))
        return
      }
      if (self) onLeave?.(orgId)
    },
  })

  const canDrop = self || canRemove
  const hasMenu = roles.length > 0 || canDrop
  const busy = changeRole.isPending || drop.isPending

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
        <span className="text-xs text-muted-foreground">{format(t.joined, { date: formatDate(member.joinedAt) })}</span>
        {error !== null && (
          <span id={errorId} role="alert" className={cn("text-xs text-destructive", classNames?.memberError)}>
            {error}
          </span>
        )}
        {changed !== null && (
          <span role="status" className={cn("text-xs text-muted-foreground", classNames?.status)}>
            {changed}
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
                aria-label={format(t.memberActions, { name: shown })}
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
                    if (next !== member.role) changeRole.mutate(next)
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
          if (!open && !drop.isPending) setConfirming(null)
        }}
      >
        <AlertDialogContent className={classNames?.confirmDialog}>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {confirming === "leave" ? format(t.leaveTitle, { organization: organizationName }) : format(t.removeTitle, { name: shown })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {confirming === "leave" ? t.leaveDescription : format(t.removeDescription, { name: shown, organization: organizationName })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={drop.isPending}>{t.keep}</AlertDialogCancel>
            <AlertDialogAction variant="destructive" disabled={drop.isPending} aria-busy={drop.isPending} onClick={() => drop.mutate()}>
              {drop.isPending && <Spinner data-icon="inline-start" />}
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
  t,
  classNames,
}: {
  invitation: OrganizationInvitation
  canCancel: boolean
  t: OrganizationMembersText
  classNames: OrganizationMembersProps["classNames"]
}) {
  const { cancelInvitation } = useOrganizationActions()
  const messageFor = useErrorMessage()
  const [error, setError] = useState<string | null>(null)
  const errorId = useId()
  const cancel = useMutation({
    mutationFn: () => cancelInvitation(invitation.id),
    onSuccess: (failure) => setError(failure === null ? null : messageFor(failure)),
  })
  const address = invitation.email === "" ? invitation.identifier : invitation.email
  return (
    <li className={cn("flex items-center gap-2.5 px-2.5 py-1.5", classNames?.invitation)}>
      <MailIcon aria-hidden className="size-3.5 shrink-0 text-muted-foreground" />
      <div className="flex min-w-0 flex-1 flex-col">
        <span className="truncate text-[13px]">{address}</span>
        <span className="text-xs text-muted-foreground">{format(t.expires, { date: formatDate(invitation.expiresAt) })}</span>
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
          aria-label={format(t.cancelInvitationLabel, { email: address })}
          aria-describedby={error === null ? undefined : errorId}
          disabled={cancel.isPending}
          aria-busy={cancel.isPending}
          onClick={() => cancel.mutate()}
        >
          {cancel.isPending && <Spinner data-icon="inline-start" />}
          {t.cancelInvitation}
        </Button>
      )}
    </li>
  )
}

/** The invite row: an email, a role from `roles`, and Invite. */
function InviteForm({
  orgId,
  roles,
  t,
  classNames,
  onInvited,
}: {
  orgId: string
  roles: readonly string[]
  t: OrganizationMembersText
  classNames: OrganizationMembersProps["classNames"]
  onInvited: ((result: OrganizationInviteSuccess) => void) | undefined
}) {
  const { invite } = useOrganizationActions()
  const messageFor = useErrorMessage()
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)
  const [role, setRole] = useState(roles[0] ?? "")
  const [emailError, setEmailError] = useState<string | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [sentTo, setSentTo] = useState<string | null>(null)

  const send = useMutation({
    mutationFn: (email: string) => invite({ orgId, email, role }),
    onSuccess: (failure, email) => {
      if (failure !== null) {
        if (EMAIL_ERRORS.has(failure.code)) setEmailError(messageFor(failure))
        else setFormError(messageFor(failure))
        return
      }
      setSentTo(email)
      form.reset()
      onInvited?.({ email, role })
    },
  })

  const form = useForm({
    defaultValues: { email: "" },
    validationLogic: revalidateLogic(),
    onSubmit: async ({ value }) => {
      setEmailError(null)
      setFormError(null)
      setSentTo(null)
      await send.mutateAsync(value.email.trim())
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
                    setEmailError(null)
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
          <Button type="submit" className={cn("flex-1 sm:flex-none", classNames?.submit)} disabled={send.isPending} aria-busy={send.isPending}>
            {send.isPending && <Spinner data-icon="inline-start" />}
            {send.isPending ? t.inviting : t.invite}
          </Button>
        </div>
      </div>
      {sentTo !== null && (
        <p role="status" className={cn("text-xs text-muted-foreground", classNames?.status)}>
          {format(t.invited, { email: sentTo })}
        </p>
      )}
    </form>
  )
}
