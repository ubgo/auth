import { useQuery } from "@tanstack/react-query"
import {
  AUTH_QUERY_ROOT,
  useAuth,
  useLocalization,
  usePluginClient,
  useSafeRedirect,
  useSession,
  useSessionActions,
  type AuthComponentProps,
} from "@ubgo/auth-react"
import { useState, type ReactNode } from "react"

import {
  USER_BUTTON_TEXT,
  UserButtonView,
  type UserButtonSignedOut,
  type UserButtonSlot,
  type UserButtonText,
} from "@/components/auth/user-button-view"

// UserButton: the signed-in user's avatar, opening a menu with their name and
// primary email, a link to the account page and sign-out. Signed out it is a
// "Sign in" button (or nothing), and while the first session read is in
// flight it is a placeholder of the same size, so the header never jumps.
//
// The menu itself is UserButtonView (user-button-view.tsx): this file only
// wires it to @ubgo/auth-react, the session, the email read and navigation.

export {
  USER_BUTTON_TEXT,
  UserAvatar,
  UserButtonView,
  initialsOf,
  type UserButtonSignedOut,
  type UserButtonSlot,
  type UserButtonText,
  type UserButtonViewProps,
} from "@/components/auth/user-button-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    userButton: UserButtonText
  }
}

export type UserButtonProps = AuthComponentProps<UserButtonSlot, "userButton", void> & {
  /** Show the user's name beside the avatar (from the sm breakpoint up). Off by default: the avatar alone. */
  readonly showName?: boolean
  /** Signed out: a "Sign in" button linking to paths.signIn (default), or nothing. */
  readonly signedOut?: UserButtonSignedOut
  /** Where "Manage account" goes. Defaults to paths.account; null removes the item. */
  readonly accountHref?: string | null
  /** The app's own menu items, rendered between "Manage account" and "Sign out" (DropdownMenuItem elements). */
  readonly menuItems?: ReactNode
  /** Which side of the trigger the menu aligns to. "end" suits a header's right edge. */
  readonly align?: "start" | "center" | "end"
}

/** The key of the email-address list, shared with AccountSettings so a change there updates the menu. */
export const EMAIL_LIST_QUERY_KEY = [...AUTH_QUERY_ROOT, "email-list"] as const

/** The email list rarely changes within a page's life; AccountSettings invalidates it after a change. */
const EMAIL_LIST_STALE_MS = 5 * 60_000

/**
 * The user's primary email, when the email plugin is on. The session carries
 * only id, name and image, so the address is one more read, cached and shared
 * with the account page's email section.
 */
export function usePrimaryEmail(): { email: string | null; verified: boolean; isPending: boolean } {
  const { queryClient } = useAuth()
  const emailClient = usePluginClient("email")
  const { session } = useSession()
  const query = useQuery(
    {
      queryKey: EMAIL_LIST_QUERY_KEY,
      queryFn: async () => {
        if (emailClient === null) return []
        const { data, error } = await emailClient.list()
        // A failed read leaves the menu without an address; the account page
        // reads the same entry and shows the error there.
        if (error !== null) throw new Error(error.message)
        return data.addresses ?? []
      },
      enabled: emailClient !== null && session !== null,
      staleTime: EMAIL_LIST_STALE_MS,
    },
    queryClient,
  )
  const primary = query.data?.find((a) => a.primary) ?? query.data?.[0]
  return { email: primary?.email ?? null, verified: primary?.verified ?? false, isPending: query.isPending && emailClient !== null }
}

export function UserButton({
  className,
  classNames,
  localization,
  onSuccess,
  redirectTo: requestedRedirectTo,
  showName = false,
  signedOut = "sign-in",
  accountHref,
  menuItems,
  align = "end",
}: UserButtonProps) {
  const t = useLocalization("userButton", USER_BUTTON_TEXT, localization)
  const { navigate, paths, Link } = useAuth()
  // redirectTo usually comes from the address bar: anything but a path on
  // this site (or an origin the provider allows) is dropped, so the default
  // applies and a crafted link cannot send the user to another site.
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const { user, isPending } = useSession()
  const { signOut } = useSessionActions()
  const { email } = usePrimaryEmail()
  const [signingOut, setSigningOut] = useState(false)
  const account = accountHref === undefined ? paths.account : accountHref

  async function onSignOut() {
    setSigningOut(true)
    // Without onSuccess, signOut navigates to redirectTo or paths.afterSignOut.
    const error = await signOut({ redirectTo: onSuccess === undefined ? redirectTo : null })
    setSigningOut(false)
    if (error === null) onSuccess?.()
  }

  return (
    <UserButtonView
      className={className}
      classNames={classNames}
      text={t}
      loading={isPending}
      user={user}
      email={email}
      showName={showName}
      signInHref={signedOut === "sign-in" ? paths.signIn : undefined}
      Link={Link}
      menuItems={menuItems}
      align={align}
      pending={signingOut}
      onAccount={account === null ? undefined : () => navigate(account)}
      onSignOut={() => void onSignOut()}
    />
  )
}
