import { useMutation } from "@tanstack/react-query"
import {
  useAdminActions,
  useAuth,
  useErrorMessage,
  useImpersonation,
  useLocalization,
  useSafeRedirect,
  useSession,
  type AuthComponentProps,
} from "@ubgo/auth-react"
import { useState } from "react"

import {
  IMPERSONATION_BANNER_TEXT,
  ImpersonationBannerView,
  type ImpersonationBannerSlot,
  type ImpersonationBannerText,
} from "@/components/auth/impersonation-banner-view"

// ImpersonationBanner: a strip that says an admin is acting as this user,
// with the way back (admin.stop-impersonating). It renders nothing unless
// the current session is an impersonation, so an app mounts it once in its
// layout. After stopping, the admin's own session is back (restored) or the
// browser is signed out, and the banner navigates to redirectTo, else to the
// admin's user list when restored and paths.signIn when not.
//
// The strip itself is ImpersonationBannerView (impersonation-banner-view.tsx):
// this file only wires it to @ubgo/auth-react, the call and navigation.

export {
  IMPERSONATION_BANNER_TEXT,
  ImpersonationBannerView,
  type ImpersonationBannerSlot,
  type ImpersonationBannerText,
  type ImpersonationBannerViewProps,
} from "@/components/auth/impersonation-banner-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    impersonationBanner: ImpersonationBannerText
  }
}

/** What stopping hands to onSuccess: whether the admin's own session came back. */
export type ImpersonationStopResult = { readonly restored: boolean }

export type ImpersonationBannerProps = AuthComponentProps<ImpersonationBannerSlot, "impersonationBanner", ImpersonationStopResult> & {
  /** Where a restored admin goes when there is no onSuccess and no redirectTo. `/admin/users` by default. */
  readonly adminHref?: string
}

export function ImpersonationBanner({
  className,
  classNames,
  localization,
  onSuccess,
  redirectTo: requestedRedirectTo,
  adminHref = "/admin/users",
}: ImpersonationBannerProps) {
  const t = useLocalization("impersonationBanner", IMPERSONATION_BANNER_TEXT, localization)
  const { impersonating } = useImpersonation()
  const { user } = useSession()
  const { stopImpersonating } = useAdminActions()
  const { navigate, paths } = useAuth()
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const messageFor = useErrorMessage()
  const [error, setError] = useState<string | null>(null)

  const stop = useMutation({
    mutationFn: () => stopImpersonating(),
    onMutate: () => setError(null),
    onSuccess: ({ restored, error: failure }) => {
      if (failure !== null) {
        setError(messageFor(failure))
        return
      }
      if (onSuccess !== undefined) onSuccess({ restored })
      else navigate(redirectTo ?? (restored ? adminHref : paths.signIn))
    },
  })

  if (!impersonating || user === null) return null
  const name = user.name.trim() === "" ? user.id : user.name

  return (
    <ImpersonationBannerView
      className={className}
      classNames={classNames}
      text={t}
      name={name}
      pending={stop.isPending}
      error={error}
      onStop={() => stop.mutate()}
    />
  )
}
