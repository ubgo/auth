import { useQuery } from "@tanstack/react-query"
import type { AuthUserView } from "@ubgo/auth-client"
import {
  AUTH_QUERY_ROOT,
  format,
  useAuth,
  useLocalization,
  usePluginClient,
  useSafeRedirect,
  useSession,
  useSessionActions,
  type AuthComponentProps,
} from "@ubgo/auth-react"
import { LogOutIcon, UserRoundIcon, UserRoundCogIcon } from "lucide-react"
import { useState, type ReactNode } from "react"

import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// UserButton: the signed-in user's avatar, opening a menu with their name and
// primary email, a link to the account page and sign-out. Signed out it is a
// "Sign in" button (or nothing), and while the first session read is in
// flight it is a placeholder of the same size, so the header never jumps.

/** Every string UserButton shows. */
export type UserButtonText = {
  /** The trigger's accessible name; `{name}` is the user's name. */
  triggerLabel: string
  account: string
  signOut: string
  signingOut: string
  signIn: string
  /** Shown in the menu when the user has no name yet. */
  unnamed: string
}

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    userButton: UserButtonText
  }
}

/** The English defaults. Override per app (AuthProvider localization.userButton) or per use (localization prop). */
export const USER_BUTTON_TEXT: UserButtonText = {
  triggerLabel: "Account menu for {name}",
  account: "Manage account",
  signOut: "Sign out",
  signingOut: "Signing out…",
  signIn: "Sign in",
  unnamed: "Your account",
}

/** The named parts classNames can style. */
export type UserButtonSlot =
  | "root"
  | "trigger"
  | "avatar"
  | "name"
  | "content"
  | "header"
  | "headerName"
  | "headerEmail"
  | "item"
  | "signOut"
  | "signIn"
  | "skeleton"

/** What UserButton does when nobody is signed in. */
export type UserButtonSignedOut = "sign-in" | "hidden"

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

/** One or two letters for the avatar: the first and last word of the name, else the email's first letter. */
export function initialsOf(name: string, email: string | null): string {
  const words = name.trim().split(/\s+/).filter((w) => w !== "")
  const first = words[0]
  const last = words.length > 1 ? words[words.length - 1] : undefined
  if (first !== undefined) return (first.slice(0, 1) + (last?.slice(0, 1) ?? "")).toUpperCase()
  return email === null ? "" : email.slice(0, 1).toUpperCase()
}

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

  if (isPending) {
    return <Skeleton aria-hidden className={cn("size-7 rounded-full", className, classNames?.root, classNames?.skeleton)} />
  }

  if (user === null) {
    if (signedOut === "hidden") return null
    return (
      <Link
        href={paths.signIn}
        className={cn(
          "inline-flex h-7 items-center rounded-lg border border-border bg-background px-2.5 text-[13px] font-medium outline-none hover:bg-muted focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:border-input dark:bg-input/30 dark:hover:bg-input/50",
          className,
          classNames?.root,
          classNames?.signIn,
        )}
      >
        {t.signIn}
      </Link>
    )
  }

  const displayName = user.name.trim() === "" ? (email ?? t.unnamed) : user.name
  const account = accountHref === undefined ? paths.account : accountHref

  async function onSignOut() {
    setSigningOut(true)
    // Without onSuccess, signOut navigates to redirectTo or paths.afterSignOut.
    const error = await signOut({ redirectTo: onSuccess === undefined ? redirectTo : null })
    setSigningOut(false)
    if (error === null) onSuccess?.()
  }

  return (
    <div className={cn("inline-flex", className, classNames?.root)}>
      <DropdownMenu>
        <DropdownMenuTrigger
          render={
            <Button
              variant="ghost"
              className={cn(
                "h-auto gap-2 rounded-full p-0.5 data-popup-open:bg-muted",
                showName && "sm:rounded-lg sm:pr-2",
                classNames?.trigger,
              )}
              aria-label={format(t.triggerLabel, { name: displayName })}
            />
          }
        >
          <UserAvatar user={user} email={email} className={classNames?.avatar} />
          {showName && <span className={cn("hidden max-w-40 truncate text-[13px] font-medium sm:inline", classNames?.name)}>{displayName}</span>}
        </DropdownMenuTrigger>
        <DropdownMenuContent align={align} className={cn("w-60", classNames?.content)}>
          <div className={cn("flex items-center gap-2 px-1.5 py-1.5", classNames?.header)}>
            <UserAvatar user={user} email={email} size="lg" />
            <div className="flex min-w-0 flex-col">
              <span className={cn("truncate text-[13px] font-medium", classNames?.headerName)}>{displayName}</span>
              {email !== null && email !== displayName && (
                <span className={cn("truncate text-xs text-muted-foreground", classNames?.headerEmail)}>{email}</span>
              )}
            </div>
          </div>
          <DropdownMenuSeparator />
          {(account !== null || menuItems !== undefined) && (
            <>
              <DropdownMenuGroup>
                {account !== null && (
                  <DropdownMenuItem className={classNames?.item} onClick={() => navigate(account)}>
                    <UserRoundCogIcon aria-hidden />
                    {t.account}
                  </DropdownMenuItem>
                )}
                {menuItems}
              </DropdownMenuGroup>
              <DropdownMenuSeparator />
            </>
          )}
          <DropdownMenuGroup>
            <DropdownMenuItem
              className={classNames?.signOut}
              disabled={signingOut}
              closeOnClick={false}
              onClick={() => void onSignOut()}
            >
              {signingOut ? <Spinner /> : <LogOutIcon aria-hidden />}
              {signingOut ? t.signingOut : t.signOut}
            </DropdownMenuItem>
          </DropdownMenuGroup>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  )
}

/** The user's picture, or their initials, or a person icon when there is neither. */
export function UserAvatar({
  user,
  email,
  size = "sm",
  className,
}: {
  user: AuthUserView
  email: string | null
  size?: "sm" | "default" | "lg"
  className?: string
}) {
  const initials = initialsOf(user.name, email)
  return (
    <Avatar size={size} className={className}>
      {user.image !== "" && <AvatarImage src={user.image} alt="" />}
      <AvatarFallback className="font-medium text-foreground/80">
        {initials === "" ? <UserRoundIcon aria-hidden className="size-3.5" /> : initials}
      </AvatarFallback>
    </Avatar>
  )
}
