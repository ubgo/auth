import type { AuthUserView } from "@ubgo/auth-client"
import { LogOutIcon, UserRoundIcon, UserRoundCogIcon } from "lucide-react"
import type { ReactNode } from "react"

import { AnchorLink, fillText, type ViewLinkComponent } from "@/components/auth/auth-view"
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

// UserButtonView: the account menu with no data layer. It is told who is
// signed in (or that the session is still loading), the primary email and
// whether a sign-out is running, and hands "Manage account" and "Sign out"
// to callbacks. UserButton (user-button.tsx) is this view wired to
// @ubgo/auth-react; render the view yourself to put the same menu on any
// other backend. UserAvatar and initialsOf live here too, because they are
// presentational and other views (AccountSettings) draw the same avatar.

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

/** One or two letters for the avatar: the first and last word of the name, else the email's first letter. */
export function initialsOf(name: string, email: string | null): string {
  const words = name.trim().split(/\s+/).filter((w) => w !== "")
  const first = words[0]
  const last = words.length > 1 ? words[words.length - 1] : undefined
  if (first !== undefined) return (first.slice(0, 1) + (last?.slice(0, 1) ?? "")).toUpperCase()
  return email === null ? "" : email.slice(0, 1).toUpperCase()
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

/** The props of UserButtonView: who is signed in, the menu's state, and a callback per action. */
export type UserButtonViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<UserButtonSlot, string>>
  /** Text overrides, merged over USER_BUTTON_TEXT. */
  readonly text?: Partial<UserButtonText>
  /** The first session read is in flight: a placeholder of the avatar's size, so the header never jumps. */
  readonly loading?: boolean
  /** The signed-in user, or null when nobody is. */
  readonly user: AuthUserView | null
  /** The user's primary email, shown under the name; null when unknown. */
  readonly email?: string | null
  /** Show the user's name beside the avatar (from the sm breakpoint up). */
  readonly showName?: boolean
  /** Signed out, a "Sign in" link to this address; signed out with it left out, nothing renders. */
  readonly signInHref?: string
  /** The link component, a plain anchor by default. */
  readonly Link?: ViewLinkComponent
  /** The app's own menu items, rendered between "Manage account" and "Sign out" (DropdownMenuItem elements). */
  readonly menuItems?: ReactNode
  /** Which side of the trigger the menu aligns to. */
  readonly align?: "start" | "center" | "end"
  /** A sign-out is running: its item shows a spinner and is disabled. */
  readonly pending?: boolean
  /** "Manage account" was chosen; the item is hidden when left out. */
  readonly onAccount?: () => void
  /** "Sign out" was chosen. */
  readonly onSignOut?: () => void
}

/** The account menu as plain props and callbacks; UserButton renders it from the session. */
export function UserButtonView({
  className,
  classNames,
  text,
  loading = false,
  user,
  email = null,
  showName = false,
  signInHref,
  Link = AnchorLink,
  menuItems,
  align = "end",
  pending = false,
  onAccount,
  onSignOut,
}: UserButtonViewProps) {
  const t: UserButtonText = { ...USER_BUTTON_TEXT, ...text }

  if (loading) {
    return <Skeleton aria-hidden className={cn("size-7 rounded-full", className, classNames?.root, classNames?.skeleton)} />
  }

  if (user === null) {
    if (signInHref === undefined) return null
    return (
      <Link
        href={signInHref}
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
              aria-label={fillText(t.triggerLabel, { name: displayName })}
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
          {(onAccount !== undefined || menuItems !== undefined) && (
            <>
              <DropdownMenuGroup>
                {onAccount !== undefined && (
                  <DropdownMenuItem className={classNames?.item} onClick={() => onAccount()}>
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
              disabled={pending}
              closeOnClick={false}
              onClick={() => onSignOut?.()}
            >
              {pending ? <Spinner /> : <LogOutIcon aria-hidden />}
              {pending ? t.signingOut : t.signOut}
            </DropdownMenuItem>
          </DropdownMenuGroup>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  )
}
