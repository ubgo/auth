import type { OrganizationInvite, OrganizationOrg } from "@ubgo/auth-client"
import {
  useAuth,
  useErrorMessage,
  useLocalization,
  useOrganizationActions,
  usePluginClient,
  useReceivedInvitations,
  useSafeRedirect,
  useSession,
  type AuthComponentProps,
} from "@ubgo/auth-react"
import { useState } from "react"

import {
  ORGANIZATION_INVITATIONS_TEXT,
  OrganizationInvitationsView,
  type InvitationAction,
  type OrganizationInvitationsSlot,
  type OrganizationInvitationsText,
} from "@/components/auth/organization-invitations-view"

// OrganizationInvitations: the invitations waiting for the signed-in user,
// each with Accept and Decline; the page an invitation mail links to
// (/invitations by default on the server). The server lists only invitations
// addressed to the user's verified identifiers, so this page needs no token.
//
// The card itself is OrganizationInvitationsView
// (organization-invitations-view.tsx): this file only wires it to
// @ubgo/auth-react, the list, the accept and decline calls and navigation.

export {
  ORGANIZATION_INVITATIONS_TEXT,
  OrganizationInvitationsView,
  type InvitationAction,
  type OrganizationInvitationsSlot,
  type OrganizationInvitationsText,
  type OrganizationInvitationsViewProps,
} from "@/components/auth/organization-invitations-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    organizationInvitations: OrganizationInvitationsText
  }
}

export type OrganizationInvitationsProps = AuthComponentProps<OrganizationInvitationsSlot, "organizationInvitations", OrganizationOrg>

/** A copy of a per-id record without one id. */
function without<V>(record: Readonly<Record<string, V>>, id: string): Record<string, V> {
  const next = { ...record }
  delete next[id]
  return next
}

export function OrganizationInvitations({
  className,
  classNames,
  localization,
  onSuccess,
  redirectTo: requestedRedirectTo,
  headingLevel = 1,
}: OrganizationInvitationsProps) {
  const { navigate } = useAuth()
  // Only a path on this site (or an allowed origin) is followed.
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const t = useLocalization("organizationInvitations", ORGANIZATION_INVITATIONS_TEXT, localization)
  const messageFor = useErrorMessage()
  const plugin = usePluginClient("organization")
  const { user } = useSession()
  const { invitations, isPending, error } = useReceivedInvitations()
  const { acceptInvitation, rejectInvitation } = useOrganizationActions()
  const [joined, setJoined] = useState<string | null>(null)
  const [pending, setPending] = useState<Readonly<Record<string, InvitationAction>>>({})
  const [errors, setErrors] = useState<Readonly<Record<string, string>>>({})

  if (plugin === null || user === null) return null

  /** Runs one answer for one invitation, keeping that row's spinner and message. */
  async function answer(invite: OrganizationInvite, action: InvitationAction) {
    setPending((p) => ({ ...p, [invite.id]: action }))
    try {
      if (action === "accept") {
        const { organization, error: failure } = await acceptInvitation(invite.id)
        if (failure !== null) setErrors((e) => ({ ...e, [invite.id]: messageFor(failure) }))
        else if (organization !== null) {
          setJoined(organization.name)
          // Joining is a step the app usually follows into the
          // organization; without onSuccess or redirectTo it stays here.
          if (onSuccess !== undefined) onSuccess(organization)
          else if (redirectTo !== undefined) navigate(redirectTo)
        }
      } else {
        const failure = await rejectInvitation(invite.id)
        setErrors((e) => (failure === null ? without(e, invite.id) : { ...e, [invite.id]: messageFor(failure) }))
      }
    } finally {
      setPending((p) => without(p, invite.id))
    }
  }

  return (
    <OrganizationInvitationsView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      invitations={invitations}
      loading={isPending}
      loadError={error === null ? null : messageFor(error)}
      joined={joined}
      pending={pending}
      errors={errors}
      onAccept={(i) => void answer(i, "accept")}
      onDecline={(i) => void answer(i, "decline")}
    />
  )
}
