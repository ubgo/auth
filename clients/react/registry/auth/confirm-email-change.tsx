import { useQuery } from "@tanstack/react-query"
import type { AuthError } from "@ubgo/auth-client"
import {
  AUTH_QUERY_ROOT,
  useAuth,
  useErrorMessage,
  useLocalization,
  usePluginClient,
  useSafeRedirect,
  useSession,
  useSessionActions,
  type AuthComponentProps,
} from "@ubgo/auth-react"
import { useState } from "react"

import {
  CONFIRM_EMAIL_CHANGE_TEXT,
  ConfirmEmailChangeView,
  type ConfirmEmailChangeSlot,
  type ConfirmEmailChangeStatus,
  type ConfirmEmailChangeText,
} from "@/components/auth/confirm-email-change-view"
import { EMAIL_LIST_QUERY_KEY } from "@/components/auth/user-button"

// ConfirmEmailChange: the page an email-change mail opens. "confirm" (the
// link sent to the new address) makes it the account's address; "undo" (the
// link sent to the old address after a change) puts the old one back and
// signs out every session, for the case where someone else made the change.
// The token comes from ?token= and is posted exactly once, never on a GET.
//
// The card itself is ConfirmEmailChangeView (confirm-email-change-view.tsx):
// this file only wires it to @ubgo/auth-react, the token, the call, the
// session and the email list it refreshes.

export {
  CONFIRM_EMAIL_CHANGE_TEXT,
  ConfirmEmailChangeView,
  type ConfirmEmailChangeSlot,
  type ConfirmEmailChangeStatus,
  type ConfirmEmailChangeText,
  type ConfirmEmailChangeViewProps,
} from "@/components/auth/confirm-email-change-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    confirmEmailChange: ConfirmEmailChangeText
  }
}

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

  const outcome = call.data
  const failure = outcome?.ok === false ? outcome.error : null
  const signedIn = session !== null
  const status: ConfirmEmailChangeStatus =
    token === ""
      ? "missing"
      : outcome === undefined && call.error === null
        ? "working"
        : outcome?.ok === true
          ? action === "undo"
            ? "undone"
            : "confirmed"
          : failure?.code === "auth.token_invalid"
            ? "invalid"
            : "failed"
  // After a change: redirectTo, else sign-in (undo signed everyone out, or nobody was in) or the account page.
  const actionHref =
    status === "confirmed" || status === "undone"
      ? (redirectTo ?? (status === "undone" || !signedIn ? paths.signIn : paths.account))
      : signedIn
        ? paths.account
        : paths.signIn

  return (
    <ConfirmEmailChangeView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      status={status}
      email={outcome?.ok === true ? outcome.email : ""}
      signedIn={signedIn}
      actionHref={actionHref}
      formError={failure === null ? null : messageFor(failure)}
      pending={call.isFetching}
      Link={Link}
      onRetry={() => void call.refetch()}
    />
  )
}
