import { useMutation } from "@tanstack/react-query"
import type { OrganizationDomainSuggestion } from "@ubgo/auth-client"
import {
  useDomainSuggestions,
  useErrorMessage,
  useLocalization,
  useOrganizationDomainActions,
  usePluginClient,
  useSession,
  type AuthComponentProps,
} from "@ubgo/auth-react"
import { useState } from "react"

import { DOMAIN_SUGGESTIONS_TEXT, DomainSuggestionsView, type DomainSuggestionsSlot, type DomainSuggestionsText } from "@/components/auth/domain-suggestions-view"

// DomainSuggestions: the organizations the signed-in user could join because
// one of their verified addresses is at a domain the organization verified
// and set to "suggest joining" (organization.domain-suggestions). Each has
// Request to join, which an admin of that organization then approves; a
// request already sent shows as Requested. It renders nothing when there is
// nothing to suggest or the server does not serve domains, so it can sit on
// a home or onboarding page unconditionally.
//
// The card itself is DomainSuggestionsView (domain-suggestions-view.tsx):
// this file only wires it to @ubgo/auth-react and the request call.

export {
  DOMAIN_SUGGESTIONS_TEXT,
  DomainSuggestionsView,
  type DomainSuggestionsSlot,
  type DomainSuggestionsText,
  type DomainSuggestionsViewProps,
} from "@/components/auth/domain-suggestions-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    domainSuggestions: DomainSuggestionsText
  }
}

export type DomainSuggestionsProps = AuthComponentProps<DomainSuggestionsSlot, "domainSuggestions", OrganizationDomainSuggestion>

export function DomainSuggestions({ className, classNames, localization, onSuccess, headingLevel = 1 }: DomainSuggestionsProps) {
  const t = useLocalization("domainSuggestions", DOMAIN_SUGGESTIONS_TEXT, localization)
  const plugin = usePluginClient("organization")
  const { user } = useSession()
  const { suggestions, available, isPending } = useDomainSuggestions()
  const { requestToJoin } = useOrganizationDomainActions()
  const messageFor = useErrorMessage()
  // Each row's request runs on its own: one mutation, its running and failed
  // rows tracked by domain id so a slow request never blocks another row.
  const [requestingIds, setRequestingIds] = useState<readonly string[]>([])
  const [errors, setErrors] = useState<Readonly<Partial<Record<string, string>>>>({})

  const ask = useMutation({
    mutationFn: (suggestion: OrganizationDomainSuggestion) => requestToJoin(suggestion.domainId),
    onMutate: (suggestion) => {
      setRequestingIds((ids) => [...ids, suggestion.domainId])
      setErrors((prev) => ({ ...prev, [suggestion.domainId]: undefined }))
    },
    onSuccess: (failure, suggestion) => {
      if (failure === null) onSuccess?.(suggestion)
      else setErrors((prev) => ({ ...prev, [suggestion.domainId]: messageFor(failure) }))
    },
    onSettled: (_data, _error, suggestion) => setRequestingIds((ids) => ids.filter((id) => id !== suggestion.domainId)),
  })

  if (plugin === null || user === null || !available) return null
  if (!isPending && suggestions.length === 0) return null

  return (
    <DomainSuggestionsView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      suggestions={suggestions}
      loading={isPending}
      requestingIds={requestingIds}
      errors={errors}
      onRequest={(s) => ask.mutate(s)}
    />
  )
}
