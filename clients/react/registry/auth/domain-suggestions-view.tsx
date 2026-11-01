import type { OrganizationDomainSuggestion } from "@ubgo/auth-client"
import { BuildingIcon } from "lucide-react"

import { fillText, type ViewHeadingLevel } from "@/components/auth/auth-view"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// DomainSuggestionsView: the "organizations you can join" card with no data
// layer. It lists the suggestions it is given, one Request to join button
// each, and hands a press to onRequest. Which requests are running and which
// failed come back in as props keyed by domain id. Like the wired card it
// renders nothing once loaded with nothing to suggest. DomainSuggestions
// (domain-suggestions.tsx) is this view wired to @ubgo/auth-react.

/** Every string DomainSuggestions shows. */
export type DomainSuggestionsText = {
  title: string
  description: string
  /** `{domain}` is the domain that matched. */
  matched: string
  request: string
  requesting: string
  requested: string
  /** `{organization}` is the organization's name. */
  requestLabel: string
}

/** The English defaults. Override per app (AuthProvider localization.domainSuggestions) or per use (localization prop). */
export const DOMAIN_SUGGESTIONS_TEXT: DomainSuggestionsText = {
  title: "Organizations you can join",
  description: "Your verified address matches these organizations' domains.",
  matched: "Matches {domain}",
  request: "Request to join",
  requesting: "Sending…",
  requested: "Requested",
  requestLabel: "Request to join {organization}",
}

/** The named parts classNames can style. */
export type DomainSuggestionsSlot = "root" | "header" | "title" | "description" | "content" | "list" | "suggestion" | "badge" | "button" | "error"

/** The card's props: the suggestions, which requests run or failed (by domain id), and the request callback. */
export type DomainSuggestionsViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<DomainSuggestionsSlot, string>>
  /** Text overrides, merged over DOMAIN_SUGGESTIONS_TEXT. */
  readonly text?: Partial<DomainSuggestionsText>
  /** The level of the title, 1 by default. */
  readonly headingLevel?: ViewHeadingLevel
  /** The organizations to offer. */
  readonly suggestions?: readonly OrganizationDomainSuggestion[]
  /** The list is still loading: a placeholder shows instead of rows. */
  readonly loading?: boolean
  /** Domain ids whose request is running; their buttons are disabled and show the running label. */
  readonly requestingIds?: readonly string[]
  /** Already-translated messages for failed requests, by domain id. */
  readonly errors?: Readonly<Partial<Record<string, string>>>
  /** A suggestion's Request to join was pressed. */
  readonly onRequest?: (suggestion: OrganizationDomainSuggestion) => void
}

export function DomainSuggestionsView({
  className,
  classNames,
  text,
  headingLevel = 1,
  suggestions = [],
  loading = false,
  requestingIds = [],
  errors = {},
  onRequest,
}: DomainSuggestionsViewProps) {
  const t: DomainSuggestionsText = { ...DOMAIN_SUGGESTIONS_TEXT, ...text }
  if (!loading && suggestions.length === 0) return null

  return (
    <Card className={cn("w-full max-w-md", className, classNames?.root)}>
      <CardHeader className={classNames?.header}>
        <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
          <BuildingIcon aria-hidden className="size-4 text-muted-foreground" />
          {t.title}
        </CardTitle>
        <CardDescription className={classNames?.description}>{t.description}</CardDescription>
      </CardHeader>
      <CardContent className={classNames?.content}>
        {loading ? (
          <Skeleton aria-hidden className="h-10 w-full rounded-lg" />
        ) : (
          <ul className={cn("flex flex-col divide-y rounded-lg border", classNames?.list)}>
            {suggestions.map((s) => {
              const busy = requestingIds.includes(s.domainId)
              const error = errors[s.domainId]
              return (
                <li key={s.domainId} className={cn("flex items-center gap-2 px-2.5 py-1.5", classNames?.suggestion)}>
                  <div className="flex min-w-0 flex-1 flex-col">
                    <span className="truncate text-[13px] font-medium">{s.orgName}</span>
                    <span className="text-xs text-muted-foreground">{fillText(t.matched, { domain: s.domain })}</span>
                    {error !== undefined && (
                      <span role="alert" className={cn("text-xs text-destructive", classNames?.error)}>
                        {error}
                      </span>
                    )}
                  </div>
                  {s.requested ? (
                    <Badge variant="secondary" className={classNames?.badge}>
                      {t.requested}
                    </Badge>
                  ) : (
                    <Button
                      type="button"
                      size="sm"
                      className={classNames?.button}
                      disabled={busy}
                      aria-busy={busy}
                      aria-label={fillText(t.requestLabel, { organization: s.orgName })}
                      onClick={() => onRequest?.(s)}
                    >
                      {busy && <Spinner data-icon="inline-start" />}
                      {busy ? t.requesting : t.request}
                    </Button>
                  )}
                </li>
              )
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}
