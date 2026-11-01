import { useMutation } from "@tanstack/react-query"
import type { AuthError, OrganizationOrg } from "@ubgo/auth-client"
import {
  useActiveOrganization,
  useAuth,
  useErrorMessage,
  useLocalization,
  useOrganizationActions,
  useOrganizations,
  usePluginClient,
  useSafeRedirect,
  useSession,
  type AuthComponentProps,
} from "@ubgo/auth-react"
import { useState } from "react"

import {
  ORGANIZATION_SWITCHER_TEXT,
  OrganizationSwitcherView,
  type OrganizationCreateValues,
  type OrganizationSwitcherSlot,
  type OrganizationSwitcherText,
} from "@/components/auth/organization-switcher-view"

// OrganizationSwitcher: the session's active organization as a menu button.
// The menu lists the user's organizations (and, unless hidden, their
// personal account, which clears the active organization), switches the
// session's active one, and creates a new organization in a dialog. Renders
// nothing when the client has no organization plugin or nobody is signed in.
//
// The menu itself is OrganizationSwitcherView (organization-switcher-view.tsx):
// this file only wires it to @ubgo/auth-react, the session, the switch and
// create calls and navigation.

export {
  ORGANIZATION_SWITCHER_TEXT,
  OrgMark,
  OrganizationSwitcherView,
  slugFromName,
  type OrganizationCreateValues,
  type OrganizationSwitcherSlot,
  type OrganizationSwitcherText,
  type OrganizationSwitcherViewProps,
} from "@/components/auth/organization-switcher-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    organizationSwitcher: OrganizationSwitcherText
  }
}

export type OrganizationSwitcherProps = AuthComponentProps<OrganizationSwitcherSlot, "organizationSwitcher", OrganizationOrg | null> & {
  /** Leave the personal account (no active organization) out of the menu. Shown by default. */
  readonly hidePersonal?: boolean
  /** Offer "Create organization". On by default; the server may still refuse it (organization.create_forbidden). */
  readonly allowCreate?: boolean
  /** Which side of the trigger the menu aligns to. */
  readonly align?: "start" | "center" | "end"
}

/** Error codes that belong under a field of the create form. */
const FIELD_OF_ERROR: Readonly<Partial<Record<string, "name" | "slug">>> = {
  "organization.slug_taken": "slug",
  "organization.bad_slug": "slug",
}

export function OrganizationSwitcher({
  className,
  classNames,
  localization,
  onSuccess,
  redirectTo: requestedRedirectTo,
  hidePersonal = false,
  allowCreate = true,
  align = "start",
}: OrganizationSwitcherProps) {
  const t = useLocalization("organizationSwitcher", ORGANIZATION_SWITCHER_TEXT, localization)
  const messageFor = useErrorMessage()
  const { navigate } = useAuth()
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const plugin = usePluginClient("organization")
  const { user, isPending: sessionPending } = useSession()
  const { organizations, isPending: listPending } = useOrganizations()
  const { organization: active, activeOrganizationId, isPending: activePending } = useActiveOrganization()
  const { setActive, create } = useOrganizationActions()
  const [error, setError] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [createError, setCreateError] = useState<string | null>(null)
  const [slugError, setSlugError] = useState<string | null>(null)

  /** After a switch or a create: hand the organization over, or go to redirectTo when one was given. Switching stays on the page otherwise. */
  function done(org: OrganizationOrg | null) {
    if (onSuccess !== undefined) onSuccess(org)
    else if (redirectTo !== undefined) navigate(redirectTo)
  }

  const switchTo = useMutation({
    mutationFn: async (orgId: string | null): Promise<AuthError | null> => setActive(orgId === null ? null : { orgId }),
    onSuccess: (failure, orgId) => {
      if (failure !== null) {
        setError(messageFor(failure))
        return
      }
      done(orgId === null ? null : (organizations.find((o) => o.id === orgId) ?? null))
    },
  })

  const submit = useMutation({
    mutationFn: (value: OrganizationCreateValues) => create({ name: value.name, slug: value.slug }),
    onSuccess: ({ organization, error: failure }) => {
      if (failure !== null) {
        if (FIELD_OF_ERROR[failure.code] === "slug") setSlugError(messageFor(failure))
        else setCreateError(messageFor(failure))
        return
      }
      if (organization !== null) {
        setCreating(false)
        done(organization)
      }
    },
  })

  if (plugin === null || (!sessionPending && user === null)) return null

  return (
    <OrganizationSwitcherView
      className={className}
      classNames={classNames}
      text={t}
      loading={sessionPending || listPending || activePending}
      organizations={organizations}
      active={active}
      activeId={activeOrganizationId}
      hidePersonal={hidePersonal}
      allowCreate={allowCreate}
      align={align}
      switching={switchTo.isPending}
      error={error}
      createOpen={creating}
      createPending={submit.isPending}
      createError={createError}
      slugError={slugError}
      onSwitch={(orgId) => {
        setError(null)
        switchTo.mutate(orgId)
      }}
      onCreateOpenChange={(open) => {
        // Each opening starts clean, like the form it mounts.
        setCreateError(null)
        setSlugError(null)
        setCreating(open)
      }}
      onCreate={async (values) => {
        setCreateError(null)
        setSlugError(null)
        await submit.mutateAsync(values)
      }}
      onSlugEdit={() => setSlugError(null)}
    />
  )
}
