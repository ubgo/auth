import { useMutation } from "@tanstack/react-query"
import type { AuthError, OrganizationMembershipRequest, OrganizationOrgDomain } from "@ubgo/auth-client"
import {
  DOMAIN_ENROLLMENT_MODES,
  format,
  useErrorMessage,
  useLocalization,
  useMembershipRequests,
  useOrganizationDomainActions,
  useOrganizationDomains,
  useOrganizationPermission,
  usePluginClient,
  useSession,
  type AnyErrorCode,
  type AuthComponentProps,
  type DomainEnrollmentMode,
} from "@ubgo/auth-react"
import { useState } from "react"

import {
  ORGANIZATION_DOMAINS_TEXT,
  OrganizationDomainsView,
  type OrganizationDomainsSlot,
  type OrganizationDomainsText,
} from "@/components/auth/organization-domains-view"

// OrganizationDomains: an organization's verified domains (the session's
// active one by default) and the requests to join they bring in. Admins add
// a domain, publish the TXT record shown until it is verified, check it,
// choose how the domain brings people in (enrollment mode), remove it, and
// approve or reject requests. Every control shows only to callers the
// server lets use it (organization.has-permission: organization:update for
// domains, member:create for requests); members see the list read-only. The
// whole card renders nothing when the server does not serve domains (no
// organization.Domains).
//
// The card itself is OrganizationDomainsView (organization-domains-view.tsx):
// this file only wires it to @ubgo/auth-react, the calls and permissions.

export {
  ORGANIZATION_DOMAIN_MODES,
  ORGANIZATION_DOMAINS_TEXT,
  OrganizationDomainsView,
  type OrganizationDomainMode,
  type OrganizationDomainsSlot,
  type OrganizationDomainsText,
  type OrganizationDomainsViewProps,
} from "@/components/auth/organization-domains-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    organizationDomains: OrganizationDomainsText
  }
}

export type OrganizationDomainsProps = AuthComponentProps<OrganizationDomainsSlot, "organizationDomains", OrganizationOrgDomain> & {
  /** The organization to show; the session's active one when left out. */
  readonly orgId?: string
  /** The enrollment mode a new domain starts with. The server's default (invite by hand) when left out. */
  readonly defaultEnrollmentMode?: DomainEnrollmentMode
}

/** The permission domains need (organization.add-domain, update-domain, remove-domain, verify-domain). */
const CAN_MANAGE = { organization: ["update"] } as const
/** The permission membership requests need. */
const CAN_REQUESTS = { member: ["create"] } as const
/** The request status that is still open. */
const PENDING = "pending"

/** Error codes that belong under the domain field. */
const DOMAIN_ERRORS: ReadonlySet<AnyErrorCode> = new Set<AnyErrorCode>([
  "organization.bad_domain",
  "organization.public_domain",
  "organization.domain_taken",
  "organization.domains_limit",
])

export function OrganizationDomains({
  className,
  classNames,
  localization,
  onSuccess,
  headingLevel = 1,
  orgId,
  defaultEnrollmentMode,
}: OrganizationDomainsProps) {
  const t = useLocalization("organizationDomains", ORGANIZATION_DOMAINS_TEXT, localization)
  const plugin = usePluginClient("organization")
  const { user } = useSession()
  const domains = useOrganizationDomains(orgId)
  const canManage = useOrganizationPermission(CAN_MANAGE, orgId).allowed
  const canRequests = useOrganizationPermission(CAN_REQUESTS, orgId).allowed
  const requests = useMembershipRequests(orgId, canRequests && domains.available)
  const actions = useOrganizationDomainActions()
  const messageFor = useErrorMessage()
  const [failure, setFailure] = useState<string | null>(null)
  const [status, setStatus] = useState<string | null>(null)
  // Removals run per domain, each with its own pending flag and error, so
  // one slow removal never blocks another row.
  const [removingIds, setRemovingIds] = useState<readonly string[]>([])
  const [removeErrors, setRemoveErrors] = useState<Readonly<Partial<Record<string, string>>>>({})
  const [addFieldError, setAddFieldError] = useState<string | null>(null)
  const [addFormError, setAddFormError] = useState<string | null>(null)

  const act = useMutation({
    mutationFn: (job: { run: () => Promise<AuthError | null>; done: string }) => job.run(),
    onMutate: () => {
      setFailure(null)
      setStatus(null)
    },
    onSuccess: (error, job) => {
      if (error === null) setStatus(job.done === "" ? null : job.done)
      else setFailure(messageFor(error))
    },
  })

  const remove = useMutation({
    mutationFn: (domain: OrganizationOrgDomain) => actions.removeDomain(domain.id),
    onMutate: (domain) => setRemovingIds((ids) => [...ids, domain.id]),
    onSuccess: (error, domain) => setRemoveErrors((prev) => ({ ...prev, [domain.id]: error === null ? undefined : messageFor(error) })),
    onSettled: (_data, _error, domain) => setRemovingIds((ids) => ids.filter((id) => id !== domain.id)),
  })

  const add = useMutation({
    mutationFn: (domain: string) => {
      if (domains.orgId === null) throw new Error("OrganizationDomains: no organization")
      return actions.addDomain({ orgId: domains.orgId, domain, ...(defaultEnrollmentMode === undefined ? {} : { enrollmentMode: defaultEnrollmentMode }) })
    },
    onSuccess: ({ domain, error }) => {
      if (domain !== null) {
        setStatus(null)
        onSuccess?.(domain)
        return
      }
      if (error === null) return
      if (DOMAIN_ERRORS.has(error.code)) setAddFieldError(messageFor(error))
      else setAddFormError(messageFor(error))
    },
  })

  if (plugin === null || user === null || !domains.available) return null

  const pending: readonly OrganizationMembershipRequest[] = requests.requests.filter((r) => r.status === PENDING)

  return (
    <OrganizationDomainsView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      noOrganization={domains.orgId === null}
      loading={domains.isPending}
      loadError={domains.error === null ? null : messageFor(domains.error)}
      domains={domains.domains}
      requests={pending}
      canManage={canManage}
      canRequests={canRequests}
      enrollmentModes={DOMAIN_ENROLLMENT_MODES}
      busy={act.isPending}
      actionError={failure}
      status={status}
      removingIds={removingIds}
      removeErrors={removeErrors}
      adding={add.isPending}
      addFieldError={addFieldError}
      addFormError={addFormError}
      onVerify={(d) => act.mutate({ run: () => actions.verifyDomain(d.id), done: format(t.verifiedNow, { domain: d.domain }) })}
      onModeChange={(d, mode: DomainEnrollmentMode) => act.mutate({ run: () => actions.updateDomain(d.id, { enrollmentMode: mode }), done: "" })}
      onRemove={async (d) => {
        await remove.mutateAsync(d)
      }}
      onApprove={(r) => act.mutate({ run: () => actions.approveRequest(r.id), done: "" })}
      onReject={(r) => act.mutate({ run: () => actions.rejectRequest(r.id), done: "" })}
      onAdd={async (domain) => {
        setAddFieldError(null)
        setAddFormError(null)
        const result = await add.mutateAsync(domain)
        return result.domain !== null
      }}
      onAddInput={() => setAddFieldError(null)}
    />
  )
}
