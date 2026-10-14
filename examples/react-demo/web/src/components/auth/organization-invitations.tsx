import { useMutation } from "@tanstack/react-query"
import type { OrganizationInvite, OrganizationOrg } from "@ubgo/auth-client"
import {
  format,
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
import { CircleAlertIcon, MailOpenIcon } from "lucide-react"
import { useId, useState } from "react"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// OrganizationInvitations: the invitations waiting for the signed-in user,
// each with Accept and Decline; the page an invitation mail links to
// (/invitations by default on the server). The server lists only invitations
// addressed to the user's verified identifiers, so this page needs no token.

/** Every string OrganizationInvitations shows. */
export type OrganizationInvitationsText = {
  title: string
  description: string
  empty: string
  /** `{role}` is the role the invitation grants. */
  role: string
  /** `{date}` is when the invitation lapses. */
  expires: string
  accept: string
  accepting: string
  decline: string
  declining: string
  /** The buttons' accessible names; `{organization}` is the organization's name. */
  acceptLabel: string
  declineLabel: string
  /** `{organization}` is the organization just joined. */
  joined: string
}

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    organizationInvitations: OrganizationInvitationsText
  }
}

/** The English defaults. Override per app (AuthProvider localization.organizationInvitations) or per use (localization prop). */
export const ORGANIZATION_INVITATIONS_TEXT: OrganizationInvitationsText = {
  title: "Invitations",
  description: "Organizations that invited you.",
  empty: "No invitations waiting for you.",
  role: "{role}",
  expires: "Expires {date}",
  accept: "Accept",
  accepting: "Joining…",
  decline: "Decline",
  declining: "Declining…",
  acceptLabel: "Accept the invitation to {organization}",
  declineLabel: "Decline the invitation to {organization}",
  joined: "You joined {organization}.",
}

/** The named parts classNames can style. */
export type OrganizationInvitationsSlot =
  | "root"
  | "header"
  | "title"
  | "description"
  | "content"
  | "list"
  | "invitation"
  | "badge"
  | "accept"
  | "decline"
  | "error"
  | "status"

export type OrganizationInvitationsProps = AuthComponentProps<OrganizationInvitationsSlot, "organizationInvitations", OrganizationOrg>

function formatDate(iso: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(new Date(iso))
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
  const [joined, setJoined] = useState<string | null>(null)

  if (plugin === null || user === null) return null

  return (
    <Card className={cn("w-full max-w-md", className, classNames?.root)}>
      <CardHeader className={classNames?.header}>
        <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
          <MailOpenIcon aria-hidden className="size-4 text-muted-foreground" />
          {t.title}
        </CardTitle>
        <CardDescription className={classNames?.description}>{t.description}</CardDescription>
      </CardHeader>
      <CardContent className={cn("flex flex-col gap-3", classNames?.content)}>
        {joined !== null && (
          <p role="status" className={cn("text-[13px] text-muted-foreground", classNames?.status)}>
            {format(t.joined, { organization: joined })}
          </p>
        )}
        {error !== null && (
          <Alert variant="destructive" className={classNames?.error}>
            <CircleAlertIcon aria-hidden />
            <AlertDescription>{messageFor(error)}</AlertDescription>
          </Alert>
        )}
        {isPending ? (
          <Skeleton aria-hidden className="h-12 w-full rounded-lg" />
        ) : invitations.length === 0 ? (
          <p className="text-[13px] text-muted-foreground">{t.empty}</p>
        ) : (
          <ul className={cn("flex flex-col divide-y divide-border rounded-lg border border-border", classNames?.list)}>
            {invitations.map((i) => (
              <InvitationRow
                key={i.id}
                invite={i}
                t={t}
                classNames={classNames}
                onJoined={(org) => {
                  setJoined(org.name)
                  // Joining is a step the app usually follows into the
                  // organization; without onSuccess or redirectTo it stays here.
                  if (onSuccess !== undefined) onSuccess(org)
                  else if (redirectTo !== undefined) navigate(redirectTo)
                }}
              />
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

/** One invitation: the organization, the role, the expiry, Accept and Decline. */
function InvitationRow({
  invite,
  t,
  classNames,
  onJoined,
}: {
  invite: OrganizationInvite
  t: OrganizationInvitationsText
  classNames: OrganizationInvitationsProps["classNames"]
  onJoined: (org: OrganizationOrg) => void
}) {
  const { acceptInvitation, rejectInvitation } = useOrganizationActions()
  const messageFor = useErrorMessage()
  const [error, setError] = useState<string | null>(null)
  const errorId = useId()
  const accept = useMutation({
    mutationFn: () => acceptInvitation(invite.id),
    onSuccess: ({ organization, error: failure }) => {
      if (failure !== null) setError(messageFor(failure))
      else if (organization !== null) onJoined(organization)
    },
  })
  const reject = useMutation({
    mutationFn: () => rejectInvitation(invite.id),
    onSuccess: (failure) => setError(failure === null ? null : messageFor(failure)),
  })
  const busy = accept.isPending || reject.isPending
  return (
    <li className={cn("flex flex-col gap-2 px-2.5 py-2 sm:flex-row sm:items-center", classNames?.invitation)}>
      <div className="flex min-w-0 flex-1 flex-col">
        <span className="flex items-center gap-1.5 truncate text-[13px] font-medium">
          {invite.orgName}
          <Badge variant="secondary" className={cn("capitalize", classNames?.badge)}>
            {format(t.role, { role: invite.role })}
          </Badge>
        </span>
        <span className="text-xs text-muted-foreground">{format(t.expires, { date: formatDate(invite.expiresAt) })}</span>
        {error !== null && (
          <span id={errorId} role="alert" className="text-xs text-destructive">
            {error}
          </span>
        )}
      </div>
      <div className="flex gap-2">
        <Button
          type="button"
          variant="outline"
          className={cn("flex-1 sm:flex-none", classNames?.decline)}
          aria-label={format(t.declineLabel, { organization: invite.orgName })}
          aria-describedby={error === null ? undefined : errorId}
          disabled={busy}
          aria-busy={reject.isPending}
          onClick={() => reject.mutate()}
        >
          {reject.isPending && <Spinner data-icon="inline-start" />}
          {reject.isPending ? t.declining : t.decline}
        </Button>
        <Button
          type="button"
          className={cn("flex-1 sm:flex-none", classNames?.accept)}
          aria-label={format(t.acceptLabel, { organization: invite.orgName })}
          aria-describedby={error === null ? undefined : errorId}
          disabled={busy}
          aria-busy={accept.isPending}
          onClick={() => accept.mutate()}
        >
          {accept.isPending && <Spinner data-icon="inline-start" />}
          {accept.isPending ? t.accepting : t.accept}
        </Button>
      </div>
    </li>
  )
}
