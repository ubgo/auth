import type { OrganizationInvite } from "@ubgo/auth-client"
import { CircleAlertIcon, MailOpenIcon } from "lucide-react"
import { useId } from "react"

import { fillText, type ViewHeadingLevel } from "@/components/auth/auth-view"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// OrganizationInvitationsView: the received-invitations card with no data
// layer. It is told the invitations, which one is being accepted or declined
// and what failed, and hands Accept and Decline to callbacks.
// OrganizationInvitations (organization-invitations.tsx) is this view wired
// to @ubgo/auth-react; render the view yourself to put the same card on any
// other backend.

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

/** The two answers to an invitation, so the view knows which button runs. */
export type InvitationAction = "accept" | "decline"

/** The props of OrganizationInvitationsView: the invitations, per-invitation state, and the two callbacks. */
export type OrganizationInvitationsViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<OrganizationInvitationsSlot, string>>
  /** Text overrides, merged over ORGANIZATION_INVITATIONS_TEXT. */
  readonly text?: Partial<OrganizationInvitationsText>
  /** The level of the title, 1 by default. */
  readonly headingLevel?: ViewHeadingLevel
  /** The invitations waiting for the user. */
  readonly invitations?: readonly OrganizationInvite[]
  /** The list is still loading: a placeholder instead of the list. */
  readonly loading?: boolean
  /** The list could not be loaded. */
  readonly loadError?: string | null
  /** The name of the organization just joined, announced above the list. */
  readonly joined?: string | null
  /** The running answer per invitation id; that row's buttons are disabled. */
  readonly pending?: Readonly<Record<string, InvitationAction>>
  /** A failed answer's message per invitation id, shown in its row. */
  readonly errors?: Readonly<Record<string, string>>
  /** Accept was pressed. */
  readonly onAccept?: (invite: OrganizationInvite) => void
  /** Decline was pressed. */
  readonly onDecline?: (invite: OrganizationInvite) => void
}

function formatDate(iso: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(new Date(iso))
}

/** The received-invitations card as plain props and callbacks; OrganizationInvitations renders it from the server's list. */
export function OrganizationInvitationsView({
  className,
  classNames,
  text,
  headingLevel = 1,
  invitations = [],
  loading = false,
  loadError = null,
  joined = null,
  pending = {},
  errors = {},
  onAccept,
  onDecline,
}: OrganizationInvitationsViewProps) {
  const t: OrganizationInvitationsText = { ...ORGANIZATION_INVITATIONS_TEXT, ...text }
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
            {fillText(t.joined, { organization: joined })}
          </p>
        )}
        {loadError !== null && (
          <Alert variant="destructive" className={classNames?.error}>
            <CircleAlertIcon aria-hidden />
            <AlertDescription>{loadError}</AlertDescription>
          </Alert>
        )}
        {loading ? (
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
                pending={pending[i.id] ?? null}
                error={errors[i.id] ?? null}
                onAccept={onAccept}
                onDecline={onDecline}
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
  pending,
  error,
  onAccept,
  onDecline,
}: {
  invite: OrganizationInvite
  t: OrganizationInvitationsText
  classNames: OrganizationInvitationsViewProps["classNames"]
  pending: InvitationAction | null
  error: string | null
  onAccept: ((invite: OrganizationInvite) => void) | undefined
  onDecline: ((invite: OrganizationInvite) => void) | undefined
}) {
  const errorId = useId()
  const busy = pending !== null
  const accepting = pending === "accept"
  const declining = pending === "decline"
  return (
    <li className={cn("flex flex-col gap-2 px-2.5 py-2 sm:flex-row sm:items-center", classNames?.invitation)}>
      <div className="flex min-w-0 flex-1 flex-col">
        <span className="flex items-center gap-1.5 truncate text-[13px] font-medium">
          {invite.orgName}
          <Badge variant="secondary" className={cn("capitalize", classNames?.badge)}>
            {fillText(t.role, { role: invite.role })}
          </Badge>
        </span>
        <span className="text-xs text-muted-foreground">{fillText(t.expires, { date: formatDate(invite.expiresAt) })}</span>
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
          aria-label={fillText(t.declineLabel, { organization: invite.orgName })}
          aria-describedby={error === null ? undefined : errorId}
          disabled={busy}
          aria-busy={declining}
          onClick={() => onDecline?.(invite)}
        >
          {declining && <Spinner data-icon="inline-start" />}
          {declining ? t.declining : t.decline}
        </Button>
        <Button
          type="button"
          className={cn("flex-1 sm:flex-none", classNames?.accept)}
          aria-label={fillText(t.acceptLabel, { organization: invite.orgName })}
          aria-describedby={error === null ? undefined : errorId}
          disabled={busy}
          aria-busy={accepting}
          onClick={() => onAccept?.(invite)}
        >
          {accepting && <Spinner data-icon="inline-start" />}
          {accepting ? t.accepting : t.accept}
        </Button>
      </div>
    </li>
  )
}
