import type { OrganizationMembershipRequest, OrganizationOrgDomain } from "@ubgo/auth-client"
import { ChevronDownIcon, CircleAlertIcon, GlobeIcon, Trash2Icon } from "lucide-react"
import { useId, useState, type FormEvent } from "react"

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

// OrganizationDomainsView: an organization's domains card with no data
// layer. It lists the domains and open requests it is given, shows the
// controls the caller says are allowed, owns only local UI state (the add
// field's text, which remove dialog is open) and hands every action to a
// callback. What runs, what failed and the status line come in as props.
// OrganizationDomains (organization-domains.tsx) is this view wired to
// @ubgo/auth-react.

/**
 * The enrollment modes the view can label, the same closed set as
 * DOMAIN_ENROLLMENT_MODES in @ubgo/auth-react, repeated so the view needs
 * nothing from that package. The wired component passes its own list to
 * `enrollmentModes`, so a mode added there fails its type check here.
 */
export const ORGANIZATION_DOMAIN_MODES = ["manual_invitation", "automatic_invitation", "automatic_suggestion", "automatic_join"] as const

/** One of ORGANIZATION_DOMAIN_MODES: how a verified domain brings people in. */
export type OrganizationDomainMode = (typeof ORGANIZATION_DOMAIN_MODES)[number]

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
  modes: Record<OrganizationDomainMode, string>
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

/** The card's props: the data to list, what the caller may do, the running and failed state, and one callback per action. */
export type OrganizationDomainsViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<OrganizationDomainsSlot, string>>
  /** Text overrides, merged over ORGANIZATION_DOMAINS_TEXT. */
  readonly text?: Partial<OrganizationDomainsText>
  /** The level of the title, 1 by default. */
  readonly headingLevel?: ViewHeadingLevel
  /** No organization is chosen: the card says so instead of listing anything. */
  readonly noOrganization?: boolean
  /** The domains are still loading: a placeholder shows instead of the list. */
  readonly loading?: boolean
  /** An already-translated message for a failed load of the domains. */
  readonly loadError?: string | null
  /** The organization's domains. */
  readonly domains?: readonly OrganizationOrgDomain[]
  /** The open requests to join; shown only when canRequests is true and the list is not empty. */
  readonly requests?: readonly OrganizationMembershipRequest[]
  /** The caller may add, verify, re-mode and remove domains. Read-only when false. */
  readonly canManage?: boolean
  /** The caller may approve and reject requests. */
  readonly canRequests?: boolean
  /** The modes the mode menu offers, ORGANIZATION_DOMAIN_MODES by default. */
  readonly enrollmentModes?: readonly OrganizationDomainMode[]
  /** A verify, mode change, approve or reject is running: those controls are disabled. */
  readonly busy?: boolean
  /** An already-translated message for a failed verify, mode change, approve or reject. */
  readonly actionError?: string | null
  /** A line for the status region, such as "example.com is verified."; nothing when null. */
  readonly status?: string | null
  /** Domain ids whose removal is running. */
  readonly removingIds?: readonly string[]
  /** Already-translated messages for failed removals, by domain id. */
  readonly removeErrors?: Readonly<Partial<Record<string, string>>>
  /** Adding a domain is running. */
  readonly adding?: boolean
  /** An already-translated message under the domain field, such as a taken domain. */
  readonly addFieldError?: string | null
  /** An already-translated message above the add field. */
  readonly addFormError?: string | null
  /** Verify was pressed on an unverified domain. */
  readonly onVerify?: (domain: OrganizationOrgDomain) => void
  /** Another enrollment mode was picked for a domain. */
  readonly onModeChange?: (domain: OrganizationOrgDomain, mode: OrganizationDomainMode) => void
  /** Removal was confirmed in the dialog. Awaited; the dialog closes once it settles. */
  readonly onRemove?: (domain: OrganizationOrgDomain) => void | Promise<void>
  /** Approve was pressed on a request. */
  readonly onApprove?: (request: OrganizationMembershipRequest) => void
  /** Reject was pressed on a request. */
  readonly onReject?: (request: OrganizationMembershipRequest) => void
  /**
   * Add was pressed with a non-empty domain (as typed). Awaited; resolving
   * true means the domain was added, and the field is cleared.
   */
  readonly onAdd?: (domain: string) => boolean | void | Promise<boolean | void>
  /** The domain field was edited; a good moment to clear addFieldError. */
  readonly onAddInput?: () => void
}

export function OrganizationDomainsView({
  className,
  classNames,
  text,
  headingLevel = 1,
  noOrganization = false,
  loading = false,
  loadError = null,
  domains = [],
  requests = [],
  canManage = false,
  canRequests = false,
  enrollmentModes = ORGANIZATION_DOMAIN_MODES,
  busy = false,
  actionError = null,
  status = null,
  removingIds = [],
  removeErrors = {},
  adding = false,
  addFieldError = null,
  addFormError = null,
  onVerify,
  onModeChange,
  onRemove,
  onApprove,
  onReject,
  onAdd,
  onAddInput,
}: OrganizationDomainsViewProps) {
  const t: OrganizationDomainsText = { ...ORGANIZATION_DOMAINS_TEXT, ...text }
  const requestsHeadingId = useId()

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
        {noOrganization ? (
          <p className="text-[13px] text-muted-foreground">{t.noOrganization}</p>
        ) : (
          <>
            {loadError !== null && (
              <Alert variant="destructive" className={classNames?.formError}>
                <CircleAlertIcon aria-hidden />
                <AlertDescription>{loadError}</AlertDescription>
              </Alert>
            )}
            {actionError !== null && (
              <Alert variant="destructive" className={classNames?.formError}>
                <CircleAlertIcon aria-hidden />
                <AlertDescription>{actionError}</AlertDescription>
              </Alert>
            )}
            <p role="status" className={cn("text-xs text-muted-foreground empty:hidden", classNames?.status)}>
              {status}
            </p>
            {loading ? (
              <Skeleton aria-hidden className="h-12 w-full rounded-lg" />
            ) : domains.length === 0 ? (
              <p className="text-[13px] text-muted-foreground">{t.empty}</p>
            ) : (
              <ul className={cn("flex flex-col divide-y rounded-lg border", classNames?.list)}>
                {domains.map((d) => (
                  <DomainRow
                    key={d.id}
                    domain={d}
                    canManage={canManage}
                    busy={busy}
                    removing={removingIds.includes(d.id)}
                    error={removeErrors[d.id]}
                    modes={enrollmentModes}
                    t={t}
                    classNames={classNames}
                    onVerify={() => onVerify?.(d)}
                    onMode={(mode) => onModeChange?.(d, mode)}
                    onRemove={() => onRemove?.(d)}
                  />
                ))}
              </ul>
            )}

            {canRequests && requests.length > 0 && (
              <section aria-labelledby={requestsHeadingId} className={cn("flex flex-col gap-1.5", classNames?.requests)}>
                <h3 id={requestsHeadingId} className="text-xs font-medium text-muted-foreground">
                  {t.requestsHeading}
                </h3>
                <ul className="flex flex-col divide-y rounded-lg border">
                  {requests.map((r) => (
                    <RequestRow
                      key={r.id}
                      request={r}
                      busy={busy}
                      t={t}
                      className={classNames?.request}
                      onApprove={() => onApprove?.(r)}
                      onReject={() => onReject?.(r)}
                    />
                  ))}
                </ul>
              </section>
            )}

            {canManage && (
              <AddDomainForm t={t} classNames={classNames} adding={adding} fieldError={addFieldError} formError={addFormError} onAdd={onAdd} onInput={onAddInput} />
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}

/** The label of a domain's mode: the text for a known mode, the raw value for one this view does not know. */
function modeName(t: OrganizationDomainsText, modes: readonly OrganizationDomainMode[], value: string): string {
  const mode = modes.find((m) => m === value)
  return mode === undefined ? value : t.modes[mode]
}

/** One domain: its name, verified or the TXT record to publish, its enrollment mode, and (for admins) Verify and Remove. */
function DomainRow({
  domain,
  canManage,
  busy,
  removing,
  error,
  modes,
  t,
  classNames,
  onVerify,
  onMode,
  onRemove,
}: {
  domain: OrganizationOrgDomain
  canManage: boolean
  busy: boolean
  removing: boolean
  error: string | undefined
  modes: readonly OrganizationDomainMode[]
  t: OrganizationDomainsText
  classNames: OrganizationDomainsViewProps["classNames"]
  onVerify: () => void
  onMode: (mode: OrganizationDomainMode) => void
  onRemove: () => void | Promise<void>
}) {
  const [confirming, setConfirming] = useState(false)
  const label = modeName(t, modes, domain.enrollmentMode)
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
                <Button type="button" variant="outline" size="sm" className={cn("justify-between", classNames?.modeTrigger)} disabled={busy} aria-label={`${t.modeLabel}: ${label}`} />
              }
            >
              {label}
              <ChevronDownIcon aria-hidden className="text-muted-foreground" />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              <DropdownMenuGroup>
                <DropdownMenuLabel>{t.modeLabel}</DropdownMenuLabel>
                <DropdownMenuRadioGroup
                  value={domain.enrollmentMode}
                  onValueChange={(next: string) => {
                    const picked = modes.find((m) => m === next)
                    if (picked !== undefined && picked !== domain.enrollmentMode) onMode(picked)
                  }}
                >
                  {modes.map((m) => (
                    <DropdownMenuRadioItem key={m} value={m} closeOnClick>
                      {t.modes[m]}
                    </DropdownMenuRadioItem>
                  ))}
                </DropdownMenuRadioGroup>
              </DropdownMenuGroup>
            </DropdownMenuContent>
          </DropdownMenu>
        ) : (
          <span className="text-xs text-muted-foreground">{label}</span>
        )}
        {canManage && !domain.verified && (
          <Button type="button" variant="outline" size="sm" disabled={busy} onClick={onVerify}>
            {t.verify}
          </Button>
        )}
        {canManage && (
          <Button type="button" variant="ghost" size="icon-sm" aria-label={`${t.remove} ${domain.domain}`} disabled={busy || removing} onClick={() => setConfirming(true)}>
            <Trash2Icon aria-hidden />
          </Button>
        )}
      </div>
      {!domain.verified && (
        <p className={cn("text-xs break-all text-muted-foreground", classNames?.record)}>
          {fillText(t.record, { name: domain.recordName, value: domain.recordValue })}
        </p>
      )}
      {error !== undefined && (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      )}
      <AlertDialog
        open={confirming}
        onOpenChange={(open) => {
          if (!open && !removing) setConfirming(false)
        }}
      >
        <AlertDialogContent className={classNames?.confirmDialog}>
          <AlertDialogHeader>
            <AlertDialogTitle>{fillText(t.removeTitle, { domain: domain.domain })}</AlertDialogTitle>
            <AlertDialogDescription>{t.removeDescription}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={removing}>{t.keep}</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={removing}
              aria-busy={removing}
              onClick={async () => {
                await onRemove()
                setConfirming(false)
              }}
            >
              {removing && <Spinner data-icon="inline-start" />}
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
        <span className="text-xs text-muted-foreground">{fillText(t.requestVia, { domain: request.domain })}</span>
      </div>
      <Button type="button" size="sm" disabled={busy} aria-label={fillText(t.approveLabel, { name })} onClick={onApprove}>
        {t.approve}
      </Button>
      <Button type="button" variant="ghost" size="sm" disabled={busy} aria-label={fillText(t.rejectLabel, { name })} onClick={onReject}>
        {t.reject}
      </Button>
    </li>
  )
}

/** The add row: a domain and Add; it refuses an empty field itself and clears once onAdd reports the domain added. */
function AddDomainForm({
  t,
  classNames,
  adding,
  fieldError,
  formError,
  onAdd,
  onInput,
}: {
  t: OrganizationDomainsText
  classNames: OrganizationDomainsViewProps["classNames"]
  adding: boolean
  fieldError: string | null
  formError: string | null
  onAdd: OrganizationDomainsViewProps["onAdd"]
  onInput: (() => void) | undefined
}) {
  const formId = useId()
  const [value, setValue] = useState("")
  const [requiredError, setRequiredError] = useState(false)
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (value.trim() === "") {
      setRequiredError(true)
      return
    }
    setRequiredError(false)
    const added = await onAdd?.(value)
    if (added === true) setValue("")
  }
  const message = requiredError ? t.domainRequired : fieldError
  const invalid = message !== null
  return (
    <form noValidate onSubmit={(e) => void submit(e)} aria-labelledby={`${formId}-heading`} className={cn("flex flex-col gap-2", classNames?.addForm)}>
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
              setRequiredError(false)
              onInput?.()
              setValue(e.target.value)
            }}
            aria-invalid={invalid}
            aria-describedby={invalid ? `${formId}-domain-error` : undefined}
            className={classNames?.input}
          />
          {invalid && (
            <FieldError id={`${formId}-domain-error`} className={classNames?.fieldError}>
              {message}
            </FieldError>
          )}
        </Field>
        <Button type="submit" className={classNames?.submit} disabled={adding} aria-busy={adding}>
          {adding && <Spinner data-icon="inline-start" />}
          {t.add}
        </Button>
      </div>
    </form>
  )
}
