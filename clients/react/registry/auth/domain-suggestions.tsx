import { useMutation } from "@tanstack/react-query"
import type { OrganizationDomainSuggestion } from "@ubgo/auth-client"
import {
  format,
  useDomainSuggestions,
  useErrorMessage,
  useLocalization,
  useOrganizationDomainActions,
  usePluginClient,
  useSession,
  type AuthComponentProps,
} from "@ubgo/auth-react"
import { BuildingIcon } from "lucide-react"
import { useState } from "react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// DomainSuggestions: the organizations the signed-in user could join because
// one of their verified addresses is at a domain the organization verified
// and set to "suggest joining" (organization.domain-suggestions). Each has
// Request to join, which an admin of that organization then approves; a
// request already sent shows as Requested. It renders nothing when there is
// nothing to suggest or the server does not serve domains, so it can sit on
// a home or onboarding page unconditionally.

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

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    domainSuggestions: DomainSuggestionsText
  }
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

export type DomainSuggestionsProps = AuthComponentProps<DomainSuggestionsSlot, "domainSuggestions", OrganizationDomainSuggestion>

export function DomainSuggestions({ className, classNames, localization, onSuccess, headingLevel = 1 }: DomainSuggestionsProps) {
  const t = useLocalization("domainSuggestions", DOMAIN_SUGGESTIONS_TEXT, localization)
  const plugin = usePluginClient("organization")
  const { user } = useSession()
  const { suggestions, available, isPending } = useDomainSuggestions()

  if (plugin === null || user === null || !available) return null
  if (!isPending && suggestions.length === 0) return null

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
        {isPending ? (
          <Skeleton aria-hidden className="h-10 w-full rounded-lg" />
        ) : (
          <ul className={cn("flex flex-col divide-y rounded-lg border", classNames?.list)}>
            {suggestions.map((s) => (
              <SuggestionRow key={s.domainId} suggestion={s} t={t} classNames={classNames} onRequested={onSuccess} />
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

function SuggestionRow({
  suggestion,
  t,
  classNames,
  onRequested,
}: {
  suggestion: OrganizationDomainSuggestion
  t: DomainSuggestionsText
  classNames: DomainSuggestionsProps["classNames"]
  onRequested: ((s: OrganizationDomainSuggestion) => void) | undefined
}) {
  const { requestToJoin } = useOrganizationDomainActions()
  const messageFor = useErrorMessage()
  const [error, setError] = useState<string | null>(null)
  const ask = useMutation({
    mutationFn: () => requestToJoin(suggestion.domainId),
    onMutate: () => setError(null),
    onSuccess: (failure) => {
      if (failure === null) onRequested?.(suggestion)
      else setError(messageFor(failure))
    },
  })
  return (
    <li className={cn("flex items-center gap-2 px-2.5 py-1.5", classNames?.suggestion)}>
      <div className="flex min-w-0 flex-1 flex-col">
        <span className="truncate text-[13px] font-medium">{suggestion.orgName}</span>
        <span className="text-xs text-muted-foreground">{format(t.matched, { domain: suggestion.domain })}</span>
        {error !== null && (
          <span role="alert" className={cn("text-xs text-destructive", classNames?.error)}>
            {error}
          </span>
        )}
      </div>
      {suggestion.requested ? (
        <Badge variant="secondary" className={classNames?.badge}>
          {t.requested}
        </Badge>
      ) : (
        <Button
          type="button"
          size="sm"
          className={classNames?.button}
          disabled={ask.isPending}
          aria-busy={ask.isPending}
          aria-label={format(t.requestLabel, { organization: suggestion.orgName })}
          onClick={() => ask.mutate()}
        >
          {ask.isPending && <Spinner data-icon="inline-start" />}
          {ask.isPending ? t.requesting : t.request}
        </Button>
      )}
    </li>
  )
}
