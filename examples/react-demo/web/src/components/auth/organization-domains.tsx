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
import { ChevronDownIcon, CircleAlertIcon, GlobeIcon, Trash2Icon } from "lucide-react"
import { useId, useState, type FormEvent } from "react"

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
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Field, FieldError, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// OrganizationDomains: an organization's verified domains (the session's
// active one by default) and the requests to join they bring in. Admins add
// a domain, publish the TXT record shown until it is verified, check it,
// choose how the domain brings people in (enrollment mode), remove it, and
// approve or reject requests. Every control shows only to callers the
// server lets use it (organization.has-permission: organization:update for
// domains, member:create for requests); members see the list read-only. The
// whole card renders nothing when the server does not serve domains (no
// organization.Domains).

/** Every string OrganizationDomains shows. */
export type OrganizationDomainsText = {
  title: string
  description: string
  noOrganization: string
  empty: string
  verified: string
  unverified: string
  /** `{name}` and `{value}` are the TXT record to publish. */
  record: string
  verify: string
  remove: string
  /** `{domain}` is the domain. */
  removeTitle: string
  removeDescription: string
  removeConfirm: string
  keep: string
  modeLabel: string
  modes: Record<DomainEnrollmentMode, string>
  addHeading: string
  domainLabel: string
  domainPlaceholder: string
  domainRequired: string
  add: string
  /** `{domain}` is the domain. */
  verifiedNow: string
  requestsHeading: string
  /** `{domain}` is the domain the request came through. */
  requestVia: string
  approve: string
  reject: string
  /** `{name}` is the requester. */
  approveLabel: string
  /** `{name}` is the requester. */
  rejectLabel: string
}

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    organizationDomains: OrganizationDomainsText
  }
}

/** The English defaults. Override per app (AuthProvider localization.organizationDomains) or per use (localization prop). */
export const ORGANIZATION_DOMAINS_TEXT: OrganizationDomainsText = {
  title: "Domains",
  description: "People with a verified address at a verified domain can be invited, offered to join, or let in automatically.",
  noOrganization: "Choose or create an organization to manage its domains.",
  empty: "No domains yet.",
  verified: "Verified",
  unverified: "Unverified",
  record: "Add a TXT record {name} with the value {value}, then verify.",
  verify: "Verify",
  remove: "Remove",
  removeTitle: "Remove {domain}?",
  removeDescription: "Nobody joins through it any more. People who already joined stay members.",
  removeConfirm: "Remove",
  keep: "Keep",
  modeLabel: "Enrollment",
  modes: {
    manual_invitation: "Invite by hand",
    automatic_invitation: "Send an invitation",
    automatic_suggestion: "Suggest joining",
    automatic_join: "Join automatically",
  },
  addHeading: "Add a domain",
  domainLabel: "Domain",
  domainPlaceholder: "example.com",
  domainRequired: "Enter a domain.",
  add: "Add",
  verifiedNow: "{domain} is verified.",
  requestsHeading: "Requests to join",
  requestVia: "Through {domain}",
  approve: "Approve",
  reject: "Reject",
  approveLabel: "Approve {name}'s request",
  rejectLabel: "Reject {name}'s request",
}

/** The named parts classNames can style. */
export type OrganizationDomainsSlot =
  | "root"
  | "header"
  | "title"
  | "description"
  | "content"
  | "list"
  | "domain"
  | "badge"
  | "record"
  | "modeTrigger"
  | "addForm"
  | "input"
  | "submit"
  | "fieldError"
  | "formError"
  | "status"
  | "requests"
  | "request"
  | "confirmDialog"

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
  const requestsHeadingId = useId()
  const [failure, setFailure] = useState<string | null>(null)
  const [status, setStatus] = useState<string | null>(null)

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

  if (plugin === null || user === null || !domains.available) return null

  const pending = requests.requests.filter((r) => r.status === PENDING)

  return (
    <Card className={cn("w-full max-w-xl", className, classNames?.root)}>
      <CardHeader className={classNames?.header}>
        <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
          <GlobeIcon aria-hidden className="size-4 text-muted-foreground" />
          {t.title}
        </CardTitle>
        <CardDescription className={classNames?.description}>{t.description}</CardDescription>
      </CardHeader>
      <CardContent className={cn("flex flex-col gap-4", classNames?.content)}>
        {domains.orgId === null ? (
          <p className="text-[13px] text-muted-foreground">{t.noOrganization}</p>
        ) : (
          <>
            {domains.error !== null && (
              <Alert variant="destructive" className={classNames?.formError}>
                <CircleAlertIcon aria-hidden />
                <AlertDescription>{messageFor(domains.error)}</AlertDescription>
              </Alert>
            )}
            {failure !== null && (
              <Alert variant="destructive" className={classNames?.formError}>
                <CircleAlertIcon aria-hidden />
                <AlertDescription>{failure}</AlertDescription>
              </Alert>
            )}
            <p role="status" className={cn("text-xs text-muted-foreground empty:hidden", classNames?.status)}>
              {status}
            </p>
            {domains.isPending ? (
              <Skeleton aria-hidden className="h-12 w-full rounded-lg" />
            ) : domains.domains.length === 0 ? (
              <p className="text-[13px] text-muted-foreground">{t.empty}</p>
            ) : (
              <ul className={cn("flex flex-col divide-y rounded-lg border", classNames?.list)}>
                {domains.domains.map((d) => (
                  <DomainRow
                    key={d.id}
                    domain={d}
                    canManage={canManage}
                    busy={act.isPending}
                    t={t}
                    classNames={classNames}
                    onVerify={() => act.mutate({ run: () => actions.verifyDomain(d.id), done: format(t.verifiedNow, { domain: d.domain }) })}
                    onMode={(mode) => act.mutate({ run: () => actions.updateDomain(d.id, { enrollmentMode: mode }), done: "" })}
                    onRemove={() => actions.removeDomain(d.id)}
                  />
                ))}
              </ul>
            )}

            {canRequests && pending.length > 0 && (
              <section aria-labelledby={requestsHeadingId} className={cn("flex flex-col gap-1.5", classNames?.requests)}>
                <h3 id={requestsHeadingId} className="text-xs font-medium text-muted-foreground">
                  {t.requestsHeading}
                </h3>
                <ul className="flex flex-col divide-y rounded-lg border">
                  {pending.map((r) => (
                    <RequestRow
                      key={r.id}
                      request={r}
                      busy={act.isPending}
                      t={t}
                      className={classNames?.request}
                      onApprove={() => act.mutate({ run: () => actions.approveRequest(r.id), done: "" })}
                      onReject={() => act.mutate({ run: () => actions.rejectRequest(r.id), done: "" })}
                    />
                  ))}
                </ul>
              </section>
            )}

            {canManage && (
              <AddDomainForm
                orgId={domains.orgId}
                defaultMode={defaultEnrollmentMode}
                t={t}
                classNames={classNames}
                onAdded={(d) => {
                  setStatus(null)
                  onSuccess?.(d)
                }}
              />
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}

/** One domain: its name, verified or the TXT record to publish, its enrollment mode, and (for admins) Verify and Remove. */
function DomainRow({
  domain,
  canManage,
  busy,
  t,
  classNames,
  onVerify,
  onMode,
  onRemove,
}: {
  domain: OrganizationOrgDomain
  canManage: boolean
  busy: boolean
  t: OrganizationDomainsText
  classNames: OrganizationDomainsProps["classNames"]
  onVerify: () => void
  onMode: (mode: DomainEnrollmentMode) => void
  onRemove: () => Promise<AuthError | null>
}) {
  const messageFor = useErrorMessage()
  const [confirming, setConfirming] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const remove = useMutation({
    mutationFn: onRemove,
    onSuccess: (failure) => {
      setConfirming(false)
      setError(failure === null ? null : messageFor(failure))
    },
  })
  const mode = DOMAIN_ENROLLMENT_MODES.find((m) => m === domain.enrollmentMode)
  return (
    <li className={cn("flex flex-col gap-1 px-2.5 py-1.5", classNames?.domain)}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="min-w-0 flex-1 basis-full truncate text-[13px] font-medium sm:basis-auto">{domain.domain}</span>
        <Badge variant={domain.verified ? "secondary" : "outline"} className={classNames?.badge}>
          {domain.verified ? t.verified : t.unverified}
        </Badge>
        {canManage ? (
          <DropdownMenu>
            <DropdownMenuTrigger
              render={
                <Button type="button" variant="outline" size="sm" className={cn("justify-between", classNames?.modeTrigger)} disabled={busy} aria-label={`${t.modeLabel}: ${mode === undefined ? domain.enrollmentMode : t.modes[mode]}`} />
              }
            >
              {mode === undefined ? domain.enrollmentMode : t.modes[mode]}
              <ChevronDownIcon aria-hidden className="text-muted-foreground" />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              <DropdownMenuGroup>
                <DropdownMenuLabel>{t.modeLabel}</DropdownMenuLabel>
                <DropdownMenuRadioGroup
                  value={domain.enrollmentMode}
                  onValueChange={(next: string) => {
                    const picked = DOMAIN_ENROLLMENT_MODES.find((m) => m === next)
                    if (picked !== undefined && picked !== domain.enrollmentMode) onMode(picked)
                  }}
                >
                  {DOMAIN_ENROLLMENT_MODES.map((m) => (
                    <DropdownMenuRadioItem key={m} value={m} closeOnClick>
                      {t.modes[m]}
                    </DropdownMenuRadioItem>
                  ))}
                </DropdownMenuRadioGroup>
              </DropdownMenuGroup>
            </DropdownMenuContent>
          </DropdownMenu>
        ) : (
          <span className="text-xs text-muted-foreground">{mode === undefined ? domain.enrollmentMode : t.modes[mode]}</span>
        )}
        {canManage && !domain.verified && (
          <Button type="button" variant="outline" size="sm" disabled={busy} onClick={onVerify}>
            {t.verify}
          </Button>
        )}
        {canManage && (
          <Button type="button" variant="ghost" size="icon-sm" aria-label={`${t.remove} ${domain.domain}`} disabled={busy || remove.isPending} onClick={() => setConfirming(true)}>
            <Trash2Icon aria-hidden />
          </Button>
        )}
      </div>
      {!domain.verified && (
        <p className={cn("text-xs break-all text-muted-foreground", classNames?.record)}>
          {format(t.record, { name: domain.recordName, value: domain.recordValue })}
        </p>
      )}
      {error !== null && (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      )}
      <AlertDialog
        open={confirming}
        onOpenChange={(open) => {
          if (!open && !remove.isPending) setConfirming(false)
        }}
      >
        <AlertDialogContent className={classNames?.confirmDialog}>
          <AlertDialogHeader>
            <AlertDialogTitle>{format(t.removeTitle, { domain: domain.domain })}</AlertDialogTitle>
            <AlertDialogDescription>{t.removeDescription}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={remove.isPending}>{t.keep}</AlertDialogCancel>
            <AlertDialogAction variant="destructive" disabled={remove.isPending} aria-busy={remove.isPending} onClick={() => remove.mutate()}>
              {remove.isPending && <Spinner data-icon="inline-start" />}
              {t.removeConfirm}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </li>
  )
}

/** One open request to join: who, through which domain, Approve and Reject. */
function RequestRow({
  request,
  busy,
  t,
  className,
  onApprove,
  onReject,
}: {
  request: OrganizationMembershipRequest
  busy: boolean
  t: OrganizationDomainsText
  className: string | undefined
  onApprove: () => void
  onReject: () => void
}) {
  const name = request.user.name.trim() === "" ? request.user.id : request.user.name
  return (
    <li className={cn("flex items-center gap-2 px-2.5 py-1.5", className)}>
      <div className="flex min-w-0 flex-1 flex-col">
        <span className="truncate text-[13px] font-medium">{name}</span>
        <span className="text-xs text-muted-foreground">{format(t.requestVia, { domain: request.domain })}</span>
      </div>
      <Button type="button" size="sm" disabled={busy} aria-label={format(t.approveLabel, { name })} onClick={onApprove}>
        {t.approve}
      </Button>
      <Button type="button" variant="ghost" size="sm" disabled={busy} aria-label={format(t.rejectLabel, { name })} onClick={onReject}>
        {t.reject}
      </Button>
    </li>
  )
}

/** The add row: a domain and Add; the new domain starts unverified with its TXT record. */
function AddDomainForm({
  orgId,
  defaultMode,
  t,
  classNames,
  onAdded,
}: {
  orgId: string
  defaultMode: DomainEnrollmentMode | undefined
  t: OrganizationDomainsText
  classNames: OrganizationDomainsProps["classNames"]
  onAdded: (domain: OrganizationOrgDomain) => void
}) {
  const { addDomain } = useOrganizationDomainActions()
  const messageFor = useErrorMessage()
  const formId = useId()
  const [value, setValue] = useState("")
  const [fieldError, setFieldError] = useState<string | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const add = useMutation({
    mutationFn: (domain: string) => addDomain({ orgId, domain, ...(defaultMode === undefined ? {} : { enrollmentMode: defaultMode }) }),
    onSuccess: ({ domain, error }) => {
      if (domain !== null) {
        setValue("")
        onAdded(domain)
        return
      }
      if (error === null) return
      if (DOMAIN_ERRORS.has(error.code)) setFieldError(messageFor(error))
      else setFormError(messageFor(error))
    },
  })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    setFieldError(null)
    setFormError(null)
    if (value.trim() === "") {
      setFieldError(t.domainRequired)
      return
    }
    add.mutate(value)
  }
  const invalid = fieldError !== null
  return (
    <form noValidate onSubmit={submit} aria-labelledby={`${formId}-heading`} className={cn("flex flex-col gap-2", classNames?.addForm)}>
      <h3 id={`${formId}-heading`} className="text-xs font-medium text-muted-foreground">
        {t.addHeading}
      </h3>
      {formError !== null && (
        <Alert variant="destructive" className={classNames?.formError}>
          <CircleAlertIcon aria-hidden />
          <AlertDescription>{formError}</AlertDescription>
        </Alert>
      )}
      <div className="flex items-start gap-2">
        <Field data-invalid={invalid} className="flex-1">
          <FieldLabel htmlFor={`${formId}-domain`} className="sr-only">
            {t.domainLabel}
          </FieldLabel>
          <Input
            id={`${formId}-domain`}
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            placeholder={t.domainPlaceholder}
            value={value}
            onChange={(e) => {
              setFieldError(null)
              setValue(e.target.value)
            }}
            aria-invalid={invalid}
            aria-describedby={invalid ? `${formId}-domain-error` : undefined}
            className={classNames?.input}
          />
          {invalid && (
            <FieldError id={`${formId}-domain-error`} className={classNames?.fieldError}>
              {fieldError}
            </FieldError>
          )}
        </Field>
        <Button type="submit" className={classNames?.submit} disabled={add.isPending} aria-busy={add.isPending}>
          {add.isPending && <Spinner data-icon="inline-start" />}
          {t.add}
        </Button>
      </div>
    </form>
  )
}
