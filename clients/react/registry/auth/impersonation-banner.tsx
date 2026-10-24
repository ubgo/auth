import { useMutation } from "@tanstack/react-query"
import {
  format,
  useAdminActions,
  useAuth,
  useErrorMessage,
  useImpersonation,
  useLocalization,
  useSafeRedirect,
  useSession,
  type AuthComponentProps,
} from "@ubgo/auth-react"
import { VenetianMaskIcon } from "lucide-react"
import { useState } from "react"

import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// ImpersonationBanner: a strip that says an admin is acting as this user,
// with the way back (admin.stop-impersonating). It renders nothing unless
// the current session is an impersonation, so an app mounts it once in its
// layout. After stopping, the admin's own session is back (restored) or the
// browser is signed out, and the banner navigates to redirectTo, else to the
// admin's user list when restored and paths.signIn when not.

/** Every string ImpersonationBanner shows. */
export type ImpersonationBannerText = {
  /** `{name}` is the user being impersonated. */
  message: string
  stop: string
  stopping: string
}

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    impersonationBanner: ImpersonationBannerText
  }
}

/** The English defaults. Override per app (AuthProvider localization.impersonationBanner) or per use (localization prop). */
export const IMPERSONATION_BANNER_TEXT: ImpersonationBannerText = {
  message: "You are acting as {name}. Everything you do is recorded as an admin action.",
  stop: "Stop impersonating",
  stopping: "Stopping…",
}

/** The named parts classNames can style. */
export type ImpersonationBannerSlot = "root" | "message" | "button" | "error"

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
    <div
      role="region"
      aria-label={t.stop}
      className={cn(
        "flex flex-wrap items-center gap-2 border-b bg-secondary px-3 py-1.5 text-[13px] text-secondary-foreground",
        className,
        classNames?.root,
      )}
    >
      <VenetianMaskIcon aria-hidden className="size-3.5 shrink-0" />
      <span className={cn("min-w-0 flex-1", classNames?.message)}>{format(t.message, { name })}</span>
      {error !== null && (
        <span role="alert" className={cn("text-xs text-destructive", classNames?.error)}>
          {error}
        </span>
      )}
      <Button type="button" variant="outline" size="sm" className={classNames?.button} disabled={stop.isPending} aria-busy={stop.isPending} onClick={() => stop.mutate()}>
        {stop.isPending && <Spinner data-icon="inline-start" />}
        {stop.isPending ? t.stopping : t.stop}
      </Button>
    </div>
  )
}
