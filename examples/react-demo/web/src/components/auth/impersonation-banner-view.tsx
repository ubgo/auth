import { VenetianMaskIcon } from "lucide-react"

import { fillText } from "@/components/auth/auth-view"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// ImpersonationBannerView: the "you are acting as" strip with no data layer.
// It always renders: whether the session is an impersonation is the caller's
// question. The name, whether stopping runs and what failed come in as props;
// the Stop button calls onStop. ImpersonationBanner (impersonation-banner.tsx)
// is this view wired to @ubgo/auth-react.

/** Every string ImpersonationBanner shows. */
export type ImpersonationBannerText = {
  /** `{name}` is the user being impersonated. */
  message: string
  stop: string
  stopping: string
}

/** The English defaults. Override per app (AuthProvider localization.impersonationBanner) or per use (localization prop). */
export const IMPERSONATION_BANNER_TEXT: ImpersonationBannerText = {
  message: "You are acting as {name}. Everything you do is recorded as an admin action.",
  stop: "Stop impersonating",
  stopping: "Stopping…",
}

/** The named parts classNames can style. */
export type ImpersonationBannerSlot = "root" | "message" | "button" | "error"

/** The banner's props: the impersonated user's name, the stop call's state, and the Stop callback. */
export type ImpersonationBannerViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<ImpersonationBannerSlot, string>>
  /** Text overrides, merged over IMPERSONATION_BANNER_TEXT. */
  readonly text?: Partial<ImpersonationBannerText>
  /** The display name of the user being impersonated, filled into `{name}`. */
  readonly name: string
  /** Stopping is running: the button is disabled and shows its running label. */
  readonly pending?: boolean
  /** An already-translated message for a failed stop. */
  readonly error?: string | null
  /** The Stop button was pressed. */
  readonly onStop?: () => void
}

export function ImpersonationBannerView({ className, classNames, text, name, pending = false, error = null, onStop }: ImpersonationBannerViewProps) {
  const t: ImpersonationBannerText = { ...IMPERSONATION_BANNER_TEXT, ...text }
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
      <span className={cn("min-w-0 flex-1", classNames?.message)}>{fillText(t.message, { name })}</span>
      {error !== null && (
        <span role="alert" className={cn("text-xs text-destructive", classNames?.error)}>
          {error}
        </span>
      )}
      <Button type="button" variant="outline" size="sm" className={classNames?.button} disabled={pending} aria-busy={pending} onClick={() => onStop?.()}>
        {pending && <Spinner data-icon="inline-start" />}
        {pending ? t.stopping : t.stop}
      </Button>
    </div>
  )
}
