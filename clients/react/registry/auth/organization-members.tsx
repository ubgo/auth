import type { AuthError, OrganizationInvitation, OrganizationMemberView } from "@ubgo/auth-client"
import {
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
import { useState } from "react"

import {
  ORGANIZATION_MEMBERS_TEXT,
  OrganizationMembersView,
  type MemberAction,
  type OrganizationInviteValues,
  type OrganizationMembersSlot,
  type OrganizationMembersText,
} from "@/components/auth/organization-members-view"

// OrganizationMembers: the members of an organization (the session's active
// one by default), a page at a time, its pending invitations, and an invite
// form, with a menu on each member to change their role, remove them, or
// (on your own row) leave. The invite form, the cancel buttons, the role
// choice and Remove show only to callers the server says may use them
// (organization.has-permission), whatever roles or authorizer the server
// runs; Leave shows to every member, since the server lets anyone but the
// last owner leave. Remove and Leave ask for confirmation first.
//
// The card itself is OrganizationMembersView (organization-members-view.tsx):
// this file only wires it to @ubgo/auth-react, the lists, the permission
// checks and the calls.

export {
  ORGANIZATION_MEMBERS_TEXT,
  OrganizationMembersView,
  type MemberAction,
  type OrganizationInviteValues,
  type OrganizationMembersSlot,
  type OrganizationMembersText,
  type OrganizationMembersViewProps,
} from "@/components/auth/organization-members-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    organizationMembers: OrganizationMembersText
  }
}

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

/** A copy of a per-id record with one id set, or removed when the value is undefined. */
function withEntry<V>(record: Readonly<Record<string, V>>, id: string, value: V | undefined): Record<string, V> {
  const next = { ...record }
  if (value === undefined) delete next[id]
  else next[id] = value
  return next
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
  const { removeMember, leave, setRole, cancelInvitation, invite } = useOrganizationActions()
  const messageFor = useErrorMessage()
  const [memberPending, setMemberPending] = useState<Readonly<Record<string, MemberAction>>>({})
  const [memberErrors, setMemberErrors] = useState<Readonly<Record<string, string>>>({})
  const [roleChanged, setRoleChanged] = useState<Readonly<Record<string, string>>>({})
  const [cancelling, setCancelling] = useState<Readonly<Record<string, boolean>>>({})
  const [invitationErrors, setInvitationErrors] = useState<Readonly<Record<string, string>>>({})
  const [inviting, setInviting] = useState(false)
  const [inviteEmailError, setInviteEmailError] = useState<string | null>(null)
  const [inviteFormError, setInviteFormError] = useState<string | null>(null)
  const [invitedTo, setInvitedTo] = useState<string | null>(null)

  if (plugin === null || user === null) return null

  const name = orgId === undefined ? (active?.name ?? "") : (active?.id === orgId ? active.name : "")
  const pending = invitations.filter((i) => i.status === PENDING)
  const memberOrgId = members.orgId ?? ""

  /** Runs one call on a member row, keeping that row's spinner, error and role-change note. */
  async function onMember(member: OrganizationMemberView, action: MemberAction, call: () => Promise<AuthError | null>, newRole?: string) {
    const id = member.user.id
    setMemberErrors((e) => withEntry(e, id, undefined))
    setRoleChanged((c) => withEntry(c, id, undefined))
    setMemberPending((p) => withEntry(p, id, action))
    try {
      const failure = await call()
      if (failure !== null) {
        setMemberErrors((e) => withEntry(e, id, messageFor(failure)))
        return
      }
      if (newRole !== undefined) setRoleChanged((c) => withEntry(c, id, newRole))
      else if (member.user.id === user?.id) onLeave?.(memberOrgId)
    } finally {
      setMemberPending((p) => withEntry(p, id, undefined))
    }
  }

  async function onCancel(invitation: OrganizationInvitation) {
    setCancelling((c) => withEntry(c, invitation.id, true))
    try {
      const failure = await cancelInvitation(invitation.id)
      setInvitationErrors((e) => withEntry(e, invitation.id, failure === null ? undefined : messageFor(failure)))
    } finally {
      setCancelling((c) => withEntry(c, invitation.id, undefined))
    }
  }

  async function onInvite({ email, role }: OrganizationInviteValues): Promise<boolean> {
    setInviteEmailError(null)
    setInviteFormError(null)
    setInvitedTo(null)
    setInviting(true)
    try {
      const failure = await invite({ orgId: memberOrgId, email, role })
      if (failure !== null) {
        if (EMAIL_ERRORS.has(failure.code)) setInviteEmailError(messageFor(failure))
        else setInviteFormError(messageFor(failure))
        return false
      }
      setInvitedTo(email)
      onSuccess?.({ email, role })
      return true
    } finally {
      setInviting(false)
    }
  }

  const self = members.members.find((m) => m.user.id === user.id)

  return (
    <OrganizationMembersView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      organizationName={name}
      hasOrganization={members.orgId !== null}
      loading={members.orgId === null ? activePending : members.isPending}
      loadError={members.error === null ? null : messageFor(members.error)}
      currentUserId={user.id}
      members={members.members}
      total={members.total}
      page={page}
      pageSize={pageSize}
      invitations={pending}
      canChangeRole={canUpdate}
      canRemove={canRemove}
      canCancel={canCancel}
      canInvite={canInvite}
      memberRoles={memberRoles}
      inviteRoles={inviteRoles}
      memberPending={memberPending}
      memberErrors={memberErrors}
      roleChanged={roleChanged}
      cancelling={cancelling}
      invitationErrors={invitationErrors}
      inviting={inviting}
      inviteEmailError={inviteEmailError}
      inviteFormError={inviteFormError}
      invitedTo={invitedTo}
      onRoleChange={(m, role) => void onMember(m, "role", () => setRole({ orgId: memberOrgId, userId: m.user.id, role }), role)}
      onRemove={(m) => onMember(m, "remove", () => removeMember({ orgId: memberOrgId, userId: m.user.id }))}
      onLeave={self === undefined ? undefined : () => onMember(self, "remove", () => leave(memberOrgId))}
      onCancelInvitation={(i) => void onCancel(i)}
      onPageChange={setPage}
      onInvite={onInvite}
      onInviteEmailEdit={() => setInviteEmailError(null)}
    />
  )
}
