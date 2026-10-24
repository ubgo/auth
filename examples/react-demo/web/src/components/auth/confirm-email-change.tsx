import { useQuery } from "@tanstack/react-query"
import type { AuthError } from "@ubgo/auth-client"
import {
  AUTH_QUERY_ROOT,
  format,
  useAuth,
  useErrorMessage,
  useLocalization,
  usePluginClient,
  useSafeRedirect,
  useSession,
  useSessionActions,
  type AuthComponentProps,
  type HeadingLevel,
} from "@ubgo/auth-react"
import { CircleAlertIcon, CircleCheckIcon, LinkIcon, ShieldCheckIcon } from "lucide-react"
import { useState, type ReactNode } from "react"

import { EMAIL_LIST_QUERY_KEY } from "@/components/auth/user-button"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// ConfirmEmailChange: the page an email-change mail opens. "confirm" (the
// link sent to the new address) makes it the account's address; "undo" (the
// link sent to the old address after a change) puts the old one back and
// signs out every session, for the case where someone else made the change.
// The token comes from ?token= and is posted exactly once, never on a GET.

/** Every string ConfirmEmailChange shows, with `{name}` placeholders where a value is filled in. */
export type ConfirmEmailChangeText = {
  workingTitle: string
  workingDescription: string
  confirmedTitle: string
  /** `{email}` is the new address. */
  confirmedDescription: string
  undoneTitle: string
  undoneDescription: string
  invalidTitle: string
  invalidDescription: string
  missingTitle: string
  missingDescription: string
  continue: string
  signIn: string
  account: string
  retry: string
}

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    confirmEmailChange: ConfirmEmailChangeText
  }
}

/** The English defaults. Override per app (AuthProvider localization.confirmEmailChange) or per use (localization prop). */
export const CONFIRM_EMAIL_CHANGE_TEXT: ConfirmEmailChangeText = {
  workingTitle: "Updating your email",
  workingDescription: "One moment…",
  confirmedTitle: "Email changed",
  confirmedDescription: "Your account now uses {email}.",
  undoneTitle: "Change undone",
  undoneDescription: "Your previous email address is back, and every session was signed out. Sign in, then change your password.",
  invalidTitle: "This link has expired",
  invalidDescription: "Email-change links work once and expire after a while. Start the change again from your account.",
  missingTitle: "No link to open",
  missingDescription: "Open this page from the link in your email.",
  continue: "Continue",
  signIn: "Sign in",
  account: "Back to your account",
  retry: "Try again",
}

/** The named parts classNames can style. */
export type ConfirmEmailChangeSlot = "root" | "header" | "title" | "description" | "content" | "formError" | "action"

/** What the link did, handed to onSuccess. */
export type ConfirmEmailChangeSuccess = { readonly action: "confirm"; readonly email: string } | { readonly action: "undo" }

export type ConfirmEmailChangeProps = AuthComponentProps<ConfirmEmailChangeSlot, "confirmEmailChange", ConfirmEmailChangeSuccess> & {
  /** Which link this page serves: the confirmation sent to the new address (default), or the undo sent to the old one. */
  readonly action?: "confirm" | "undo"
  /** The token from the link. Left out, it is read from the page's address (?token=). */
  readonly token?: string
}

/** The `token` query parameter of the page's address, or "" during server rendering or when it is absent. */
function tokenFromLocation(): string {
  if (typeof window === "undefined") return ""
  return new URLSearchParams(window.location.search).get("token") ?? ""
}

/** What the one call came to. */
type Outcome = { readonly ok: true; readonly email: string } | { readonly ok: false; readonly error: AuthError }

export function ConfirmEmailChange({
  className,
  classNames,
  localization,
  onSuccess,
  redirectTo: requestedRedirectTo,
  action = "confirm",
  token: tokenProp,
  headingLevel = 1,
}: ConfirmEmailChangeProps) {
  const t = useLocalization("confirmEmailChange", CONFIRM_EMAIL_CHANGE_TEXT, localization)
  const messageFor = useErrorMessage()
  const { paths, Link, queryClient } = useAuth()
  // redirectTo usually comes from the address bar: anything but a path on
  // this site (or an origin the provider allows) is dropped, so the default
  // applies and a crafted link cannot send the user to another site.
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const { session } = useSession()
  const { refreshSession } = useSessionActions()
  const email = usePluginClient("email")
  const [token] = useState(() => tokenProp ?? tokenFromLocation())

  // One POST per token: a query keyed on it survives React's double mount
  // and re-renders without a second call, and never refetches by itself.
  const call = useQuery(
    {
      queryKey: [...AUTH_QUERY_ROOT, "email-change", action, token],
      enabled: email !== null && token !== "",
      staleTime: Infinity,
      gcTime: Infinity,
      retry: false,
      refetchOnWindowFocus: false,
      refetchOnReconnect: false,
      queryFn: async (): Promise<Outcome> => {
        if (email === null) throw new Error("ConfirmEmailChange: email plugin missing")
        if (action === "undo") {
          const { error } = await email.undoChange({ token })
          if (error !== null) return { ok: false, error }
          // Undo signs out every session, this one included.
          await refreshSession()
          onSuccess?.({ action: "undo" })
          return { ok: true, email: "" }
        }
        const { data, error } = await email.confirmChange({ token })
        if (error !== null) return { ok: false, error }
        await queryClient.invalidateQueries({ queryKey: EMAIL_LIST_QUERY_KEY })
        onSuccess?.({ action: "confirm", email: data.email })
        return { ok: true, email: data.email }
      },
    },
    queryClient,
  )

  if (email === null) return null

  const root = cn("w-full max-w-sm", className, classNames?.root)
  const actionClass = cn(buttonVariants({ size: "lg" }), "w-full", classNames?.action)
  const outcome = call.data

  if (token === "") {
    return (
      <StateCard headingLevel={headingLevel} root={root} classNames={classNames} icon={<LinkIcon aria-hidden className="size-4 text-muted-foreground" />} title={t.missingTitle} description={t.missingDescription}>
        <Link href={session === null ? paths.signIn : paths.account} className={actionClass}>
          {session === null ? t.signIn : t.account}
        </Link>
      </StateCard>
    )
  }

  if (outcome === undefined && call.error === null) {
    return (
      <Card className={root} aria-busy>
        <CardHeader className={classNames?.header}>
          <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
            <Spinner aria-hidden className="text-muted-foreground" />
            {t.workingTitle}
          </CardTitle>
          <CardDescription className={classNames?.description} role="status">
            {t.workingDescription}
          </CardDescription>
        </CardHeader>
      </Card>
    )
  }

  if (outcome?.ok === true) {
    const undone = action === "undo"
    const target = redirectTo ?? (undone || session === null ? paths.signIn : paths.account)
    return (
      <StateCard headingLevel={headingLevel}
        root={root}
        classNames={classNames}
        icon={undone ? <ShieldCheckIcon aria-hidden className="size-4 text-muted-foreground" /> : <CircleCheckIcon aria-hidden className="size-4 text-muted-foreground" />}
        title={undone ? t.undoneTitle : t.confirmedTitle}
        description={undone ? t.undoneDescription : format(t.confirmedDescription, { email: outcome.email })}
        status
      >
        <Link href={target} className={actionClass}>
          {undone || session === null ? t.signIn : t.continue}
        </Link>
      </StateCard>
    )
  }

  const failure = outcome?.ok === false ? outcome.error : null
  if (failure?.code === "auth.token_invalid") {
    return (
      <StateCard headingLevel={headingLevel} root={root} classNames={classNames} icon={<LinkIcon aria-hidden className="size-4 text-muted-foreground" />} title={t.invalidTitle} description={t.invalidDescription}>
        <Link href={session === null ? paths.signIn : paths.account} className={actionClass}>
          {session === null ? t.signIn : t.account}
        </Link>
      </StateCard>
    )
  }

  // The network or a server fault: the token was not spent, so it can be retried.
  return (
    <Card className={root}>
      <CardHeader className={classNames?.header}>
        <CardTitle className={classNames?.title} role="heading" aria-level={headingLevel}>
          {t.workingTitle}
        </CardTitle>
      </CardHeader>
      <CardContent className={cn("flex flex-col gap-3.5", classNames?.content)}>
        {failure !== null && (
          <Alert variant="destructive" className={classNames?.formError}>
            <CircleAlertIcon aria-hidden />
            <AlertDescription>{messageFor(failure)}</AlertDescription>
          </Alert>
        )}
        <Button type="button" size="lg" className={cn("w-full", classNames?.action)} disabled={call.isFetching} onClick={() => void call.refetch()}>
          {call.isFetching && <Spinner data-icon="inline-start" />}
          {t.retry}
        </Button>
      </CardContent>
    </Card>
  )
}

function StateCard({
  root,
  classNames,
  icon,
  title,
  description,
  status = false,
  headingLevel,
  children,
}: {
  headingLevel: HeadingLevel
  root: string
  classNames: ConfirmEmailChangeProps["classNames"]
  icon: ReactNode
  title: string
  description: string
  status?: boolean
  children: ReactNode
}) {
  return (
    <Card className={root}>
      <CardHeader className={classNames?.header}>
        <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
          {icon}
          {title}
        </CardTitle>
        <CardDescription className={classNames?.description} role={status ? "status" : undefined}>
          {description}
        </CardDescription>
      </CardHeader>
      <CardContent className={classNames?.content}>{children}</CardContent>
    </Card>
  )
}
