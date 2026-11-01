import type { AdminUserDetail as AdminUserDetailData, AuthSessionView } from "@ubgo/auth-client"
import {
  BanIcon,
  ChevronDownIcon,
  ChevronLeftIcon,
  CircleAlertIcon,
  EllipsisIcon,
  KeyRoundIcon,
  LogOutIcon,
  MonitorSmartphoneIcon,
  ShieldIcon,
  Trash2Icon,
  UserRoundCheckIcon,
  VenetianMaskIcon,
} from "lucide-react"
import { useId, useState, type FormEvent, type ReactNode } from "react"

import { AnchorLink, fillText, type ViewHeadingLevel, type ViewLinkComponent } from "@/components/auth/auth-view"
import { Alert, AlertDescription } from "@/components/ui/alert"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Field, FieldError, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { cn } from "@/lib/utils"

// AdminUserDetailView: one user as an admin sees them, with no data layer.
// The user, their sessions, second factor and metadata, what the caller may
// do, what runs and what failed all come in as props; every action goes out
// through a callback. Which dialog is open can be held by the caller (dialog
// and onDialogChange), so a dialog closes when its call succeeds, or by the
// view itself. AdminUserDetail (admin-user-detail.tsx) is this view wired to
// @ubgo/auth-react.

/** Every string AdminUserDetail shows. */
export type AdminUserDetailText = {
  back: string
  loading: string
  forbidden: string
  unnamed: string
  admin: string
  banned: string
  you: string
  detailsHeading: string
  created: string
  lastActive: string
  never: string
  sessionCount: string
  roleLabel: string
  /** `{role}` is the role. */
  roleChanged: string
  identitiesHeading: string
  noIdentities: string
  verified: string
  unverified: string
  primary: string
  /** `{reason}` is the ban's reason. */
  bannedWithReason: string
  bannedNoReason: string
  sessionsHeading: string
  noSessions: string
  sessionDevice: string
  sessionIp: string
  sessionLastSeen: string
  impersonated: string
  unknownDevice: string
  revoke: string
  /** `{device}` names the session. */
  revokeLabel: string
  revokeAll: string
  metadataHeading: string
  metadataPublic: string
  metadataEmpty: string
  twoFactorHeading: string
  twoFactorNone: string
  /** `{method}` is the factor's method. */
  twoFactorOn: string
  /** `{method}` is the factor's method. */
  twoFactorPaused: string
  twoFactorPause: string
  twoFactorResume: string
  twoFactorReset: string
  actions: string
  impersonate: string
  ban: string
  unban: string
  setPassword: string
  delete: string
  banTitle: string
  /** `{name}` is the user's name. */
  banDescription: string
  banReasonLabel: string
  banReasonPlaceholder: string
  banDurationLabel: string
  banForever: string
  /** `{hours}` is a whole number of hours. */
  banHours: string
  /** `{days}` is a whole number of days. */
  banDays: string
  banConfirm: string
  passwordTitle: string
  /** `{name}` is the user's name. */
  passwordDescription: string
  passwordLabel: string
  passwordRequired: string
  passwordConfirm: string
  cancel: string
  /** `{name}` is the user's name. */
  deleteTitle: string
  deleteDescription: string
  deleteConfirm: string
  /** `{name}` is the user's name. */
  revokeAllTitle: string
  revokeAllDescription: string
  revokeAllConfirm: string
  /** `{name}` is the user's name. */
  resetTitle: string
  resetDescription: string
  resetConfirm: string
  freshRequired: string
  signInAgain: string
  bannedDone: string
  unbannedDone: string
  revokedDone: string
  revokedAllDone: string
  passwordDone: string
  pausedDone: string
  resumedDone: string
  resetDone: string
}

/** The English defaults. Override per app (AuthProvider localization.adminUserDetail) or per use (localization prop). */
export const ADMIN_USER_DETAIL_TEXT: AdminUserDetailText = {
  back: "All users",
  loading: "Loading the user…",
  forbidden: "You do not have access to this user.",
  unnamed: "Unnamed",
  admin: "Admin",
  banned: "Banned",
  you: "You",
  detailsHeading: "Details",
  created: "Created",
  lastActive: "Last active",
  never: "Never",
  sessionCount: "Sessions",
  roleLabel: "Role",
  roleChanged: "Role set to {role}.",
  identitiesHeading: "Sign-in identifiers",
  noIdentities: "No identifiers.",
  verified: "Verified",
  unverified: "Unverified",
  primary: "Primary",
  bannedWithReason: "Banned: {reason}",
  bannedNoReason: "This user is banned and cannot sign in.",
  sessionsHeading: "Sessions",
  noSessions: "No active sessions.",
  sessionDevice: "Device",
  sessionIp: "IP address",
  sessionLastSeen: "Last seen",
  impersonated: "Admin",
  unknownDevice: "Unknown device",
  revoke: "Revoke",
  revokeLabel: "Revoke the session on {device}",
  revokeAll: "Revoke all sessions",
  metadataHeading: "Metadata",
  metadataPublic: "Public (the app sets it; the user and the session can read it)",
  metadataEmpty: "Empty.",
  twoFactorHeading: "Two-factor authentication",
  twoFactorNone: "Not set up.",
  twoFactorOn: "On ({method}).",
  twoFactorPaused: "Paused ({method}): sign-in does not ask for it.",
  twoFactorPause: "Pause",
  twoFactorResume: "Switch back on",
  twoFactorReset: "Reset",
  actions: "More actions",
  impersonate: "Impersonate",
  ban: "Ban",
  unban: "Unban",
  setPassword: "Set password",
  delete: "Delete user",
  banTitle: "Ban this user?",
  banDescription: "{name} is signed out everywhere and cannot sign in until the ban ends.",
  banReasonLabel: "Reason (shown to them)",
  banReasonPlaceholder: "Optional",
  banDurationLabel: "For",
  banForever: "Until unbanned",
  banHours: "{hours} h",
  banDays: "{days} d",
  banConfirm: "Ban user",
  passwordTitle: "Set a password",
  passwordDescription: "{name} is signed out everywhere and signs in with this password from now on.",
  passwordLabel: "New password",
  passwordRequired: "Enter a password.",
  passwordConfirm: "Set password",
  cancel: "Cancel",
  deleteTitle: "Delete {name}?",
  deleteDescription: "The account and everything that belongs to it is removed for good. This cannot be undone.",
  deleteConfirm: "Delete",
  revokeAllTitle: "Sign {name} out everywhere?",
  revokeAllDescription: "Every session ends at once. They can sign in again.",
  revokeAllConfirm: "Revoke all",
  resetTitle: "Reset {name}'s two-factor authentication?",
  resetDescription: "Their authenticator and recovery codes are removed, so they set it up again.",
  resetConfirm: "Reset",
  freshRequired: "This action needs a recent sign-in.",
  signInAgain: "Sign in again",
  bannedDone: "User banned.",
  unbannedDone: "Ban lifted.",
  revokedDone: "Session revoked.",
  revokedAllDone: "Every session revoked.",
  passwordDone: "Password set.",
  pausedDone: "Two-factor paused.",
  resumedDone: "Two-factor switched back on.",
  resetDone: "Two-factor reset.",
}

/** The named parts classNames can style. */
export type AdminUserDetailSlot =
  | "root"
  | "header"
  | "title"
  | "content"
  | "toolbar"
  | "badge"
  | "section"
  | "sessions"
  | "formError"
  | "status"
  | "dialog"

/** A date and time in the reader's locale. */
function formatDate(iso: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(iso))
}

/** A short device name from a user agent: the browser and the platform, or null when neither is recognised. */
function deviceName(userAgent: string): string | null {
  const browser = /Edg\//.test(userAgent)
    ? "Edge"
    : /Firefox\//.test(userAgent)
      ? "Firefox"
      : /Chrome\//.test(userAgent)
        ? "Chrome"
        : /Safari\//.test(userAgent)
          ? "Safari"
          : null
  const platform = /iPhone|iPad/.test(userAgent)
    ? "iOS"
    : /Android/.test(userAgent)
      ? "Android"
      : /Mac OS X/.test(userAgent)
        ? "macOS"
        : /Windows/.test(userAgent)
          ? "Windows"
          : /Linux/.test(userAgent)
            ? "Linux"
            : null
  if (browser === null && platform === null) return null
  return [browser, platform].filter((p) => p !== null).join(" on ")
}

/** The capabilities the card asks about, each true when the caller may take that action. Missing counts as false. */
export type AdminUserDetailCapability =
  | "ban"
  | "setRole"
  | "impersonate"
  | "deleteUser"
  | "setPassword"
  | "listSessions"
  | "revokeSessions"
  | "getTwoFactor"
  | "disableTwoFactor"
  | "enableTwoFactor"
  | "resetTwoFactor"

/** What the caller may do, by capability; @ubgo/auth-react's AdminCapabilities fits as is. */
export type AdminUserDetailCapabilities = Readonly<Partial<Record<AdminUserDetailCapability, boolean>>>

/** Which dialog is open: the ban form, the password form, or one of the three confirmations; null when none is. */
export type AdminUserDetailDialog = "ban" | "password" | "delete" | "revokeAll" | "resetTwoFactor" | null

/** What the ban form hands onBan: the reason as typed (may be empty) and the length in minutes, 0 for "until unbanned". */
export type AdminUserBanValues = { readonly reason: string; readonly minutes: number }

/** The user's second factor as the card shows it; @ubgo/auth-client's AdminTwoFactorResult fits as is. */
export type AdminUserDetailTwoFactor = { readonly enrolled: boolean; readonly enabled: boolean; readonly method: string }

/** The admin plugin's built-in roles (plugin/admin RoleUser, RoleAdmin). */
const DEFAULT_ROLES: readonly string[] = ["user", "admin"]

/** The role a user holds by the admin flag alone, when the server does not list their roles. */
const ADMIN_ROLE = "admin"
const USER_ROLE = "user"

/** Minutes in an hour and a day, for the ban-length labels. */
const MINUTES_PER_HOUR = 60
const MINUTES_PER_DAY = 1440

/** The ban lengths offered by default: an hour, a day, a week, and until unbanned. */
const DEFAULT_BAN_DURATIONS: readonly number[] = [MINUTES_PER_HOUR, MINUTES_PER_DAY, 7 * MINUTES_PER_DAY, 0]

/** The longest ban reason the form takes. */
const BAN_REASON_MAX_LENGTH = 300

/** The card's props: the user and their data, what the caller may do, what runs and failed, which dialog is open, and a callback per action. */
export type AdminUserDetailViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<AdminUserDetailSlot, string>>
  /** Text overrides, merged over ADMIN_USER_DETAIL_TEXT. */
  readonly text?: Partial<AdminUserDetailText>
  /** The level of the title, 1 by default. */
  readonly headingLevel?: ViewHeadingLevel
  /** The id of the user shown, printed under the name. */
  readonly userId: string
  /** The signed-in admin's id, so their own page says "You" and offers no actions on itself. */
  readonly selfId?: string
  /** The caller may not read this user: the card says so and nothing else. */
  readonly forbidden?: boolean
  /** The user, null until loaded (or when the read failed). */
  readonly detail?: AdminUserDetailData | null
  /** The user is loading: placeholders show. */
  readonly loading?: boolean
  /** An already-translated message for a failed read of the user. */
  readonly loadError?: string | null
  /** What the caller may do. Nothing when left out. */
  readonly can?: AdminUserDetailCapabilities
  /** The user's sessions; the section shows when can.listSessions is true. */
  readonly sessions?: readonly AuthSessionView[]
  /** The sessions are loading. */
  readonly sessionsLoading?: boolean
  /** An already-translated message for a failed read of the sessions. */
  readonly sessionsError?: string | null
  /** The user's second factor; the section is hidden when null. */
  readonly twoFactor?: AdminUserDetailTwoFactor | null
  /** The user's metadata; the section is hidden when null. */
  readonly metadata?: { readonly public: unknown } | null
  /** The roles the role menu offers. The admin plugin's two built-in roles by default. */
  readonly roles?: readonly string[]
  /** The ban lengths offered, in minutes; 0 is "until unbanned". */
  readonly banDurations?: readonly number[]
  /** Where "All users" links to; hidden when left out. */
  readonly backHref?: string
  /** The link component, a plain anchor by default. */
  readonly Link?: ViewLinkComponent
  /** An action is running: every action control is disabled. */
  readonly busy?: boolean
  /** One of the card's own actions (not impersonation) is running: the more-actions button and the dialogs show a spinner. */
  readonly acting?: boolean
  /** Impersonation is starting: its button shows a spinner. */
  readonly impersonating?: boolean
  /** An already-translated message for a failed action. */
  readonly actionError?: string | null
  /** The last action needs a recent sign-in: the card says so and offers Sign in again. */
  readonly needsFreshSession?: boolean
  /** A line for the status region, such as "User banned."; nothing when null. */
  readonly status?: string | null
  /** An already-translated message under the password field, such as a weak password. */
  readonly passwordError?: string | null
  /** The open dialog. Left out, the view keeps it itself. */
  readonly dialog?: AdminUserDetailDialog
  /** A dialog opened or closed. */
  readonly onDialogChange?: (dialog: AdminUserDetailDialog) => void
  /** Impersonate was pressed. */
  readonly onImpersonate?: () => void
  /** Unban was pressed. */
  readonly onUnban?: () => void
  /** The ban form was submitted. */
  readonly onBan?: (values: AdminUserBanValues) => void
  /** The password form was submitted with a non-empty password. Awaited, so the field keeps its value while it runs. */
  readonly onSetPassword?: (password: string) => void | Promise<void>
  /** The password field was edited; a good moment to clear passwordError. */
  readonly onPasswordInput?: () => void
  /** Another role was picked. */
  readonly onSetRole?: (role: string) => void
  /** Revoke was pressed on a session. */
  readonly onRevokeSession?: (session: AuthSessionView) => void
  /** Revoking every session was confirmed. */
  readonly onRevokeAll?: () => void
  /** Deleting the user was confirmed. */
  readonly onDelete?: () => void
  /** Pause was pressed on the second factor. */
  readonly onPauseTwoFactor?: () => void
  /** Switch back on was pressed on the second factor. */
  readonly onResumeTwoFactor?: () => void
  /** Resetting the second factor was confirmed. */
  readonly onResetTwoFactor?: () => void
  /** Sign in again was pressed on the recent-sign-in notice. */
  readonly onSignInAgain?: () => void
}

export function AdminUserDetailView({
  className,
  classNames,
  text,
  headingLevel = 1,
  userId,
  selfId,
  forbidden = false,
  detail = null,
  loading = false,
  loadError = null,
  can = {},
  sessions = [],
  sessionsLoading = false,
  sessionsError = null,
  twoFactor = null,
  metadata = null,
  roles = DEFAULT_ROLES,
  banDurations = DEFAULT_BAN_DURATIONS,
  backHref,
  Link = AnchorLink,
  busy = false,
  acting = false,
  impersonating = false,
  actionError = null,
  needsFreshSession = false,
  status = null,
  passwordError = null,
  dialog: controlledDialog,
  onDialogChange,
  onImpersonate,
  onUnban,
  onBan,
  onSetPassword,
  onPasswordInput,
  onSetRole,
  onRevokeSession,
  onRevokeAll,
  onDelete,
  onPauseTwoFactor,
  onResumeTwoFactor,
  onResetTwoFactor,
  onSignInAgain,
}: AdminUserDetailViewProps) {
  const t: AdminUserDetailText = { ...ADMIN_USER_DETAIL_TEXT, ...text }
  const statusId = useId()
  const [ownDialog, setOwnDialog] = useState<AdminUserDetailDialog>(null)
  const dialog = controlledDialog === undefined ? ownDialog : controlledDialog
  const setDialog = (next: AdminUserDetailDialog) => {
    if (controlledDialog === undefined) setOwnDialog(next)
    onDialogChange?.(next)
  }

  if (forbidden) {
    return (
      <Card className={cn("w-full max-w-3xl", className, classNames?.root)}>
        <CardContent>
          <p className="text-[13px] text-muted-foreground">{t.forbidden}</p>
        </CardContent>
      </Card>
    )
  }

  const name = detail?.user.name.trim() ?? ""
  const shown = name === "" ? t.unnamed : name
  const self = detail !== null && detail.user.id === selfId
  // The roles the server reports; several are shown joined, and the menu sets one.
  const role = detail === null ? USER_ROLE : (detail.user.roles ?? []).join(", ") || (detail.user.admin ? ADMIN_ROLE : USER_ROLE)
  const confirming = dialog === "delete" || dialog === "revokeAll" || dialog === "resetTwoFactor" ? dialog : null

  return (
    <Card className={cn("w-full max-w-3xl", className, classNames?.root)} aria-busy={loading}>
      <CardHeader className={cn("gap-2", classNames?.header)}>
        {backHref !== undefined && (
          <Link href={backHref} className="flex w-fit items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
            <ChevronLeftIcon aria-hidden className="size-3.5" />
            {t.back}
          </Link>
        )}
        <div className="flex flex-wrap items-center gap-2.5">
          <Avatar>
            <AvatarFallback className="text-xs font-medium text-foreground/80">{(name === "" ? "?" : name.slice(0, 1)).toUpperCase()}</AvatarFallback>
          </Avatar>
          <div className="flex min-w-40 flex-1 flex-col">
            <CardTitle className={cn("flex flex-wrap items-center gap-1.5", classNames?.title)} role="heading" aria-level={headingLevel}>
              {detail === null ? <Skeleton className="h-4 w-40" /> : shown}
              {self && (
                <Badge variant="outline" className={classNames?.badge}>
                  {t.you}
                </Badge>
              )}
              {detail?.user.admin === true && (
                <Badge variant="secondary" className={classNames?.badge}>
                  <ShieldIcon aria-hidden data-icon="inline-start" />
                  {t.admin}
                </Badge>
              )}
              {detail?.user.banned === true && (
                <Badge variant="destructive" className={classNames?.badge}>
                  {t.banned}
                </Badge>
              )}
            </CardTitle>
            <span className="truncate text-xs text-muted-foreground">
              {detail !== null && detail.user.email !== "" && <span className="mr-2">{detail.user.email}</span>}
              <span className="font-mono text-[11px]">{userId}</span>
            </span>
          </div>
          {detail !== null && !self && (
            <div className={cn("flex w-full items-center gap-1.5 sm:w-auto", classNames?.toolbar)}>
              {can.impersonate === true && !detail.user.admin && !detail.user.banned && (
                <Button type="button" variant="outline" disabled={busy} aria-busy={impersonating} onClick={() => onImpersonate?.()}>
                  {impersonating ? <Spinner data-icon="inline-start" /> : <VenetianMaskIcon aria-hidden data-icon="inline-start" />}
                  {t.impersonate}
                </Button>
              )}
              {can.ban === true &&
                !detail.user.admin &&
                (detail.user.banned ? (
                  <Button type="button" variant="outline" disabled={busy} onClick={() => onUnban?.()}>
                    <UserRoundCheckIcon aria-hidden data-icon="inline-start" />
                    {t.unban}
                  </Button>
                ) : (
                  <Button type="button" variant="destructive" disabled={busy} onClick={() => setDialog("ban")}>
                    <BanIcon aria-hidden data-icon="inline-start" />
                    {t.ban}
                  </Button>
                ))}
              {(can.setPassword === true || can.revokeSessions === true || can.deleteUser === true) && (
                <DropdownMenu>
                  <DropdownMenuTrigger render={<Button type="button" variant="ghost" size="icon" aria-label={t.actions} disabled={busy} />}>
                    {acting ? <Spinner /> : <EllipsisIcon aria-hidden />}
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="w-48">
                    {can.setPassword === true && !detail.user.admin && (
                      <DropdownMenuItem onClick={() => setDialog("password")}>
                        <KeyRoundIcon aria-hidden />
                        {t.setPassword}
                      </DropdownMenuItem>
                    )}
                    {can.revokeSessions === true && (
                      <DropdownMenuItem onClick={() => setDialog("revokeAll")}>
                        <LogOutIcon aria-hidden />
                        {t.revokeAll}
                      </DropdownMenuItem>
                    )}
                    {can.deleteUser === true && !detail.user.admin && (
                      <>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem variant="destructive" onClick={() => setDialog("delete")}>
                          <Trash2Icon aria-hidden />
                          {t.delete}
                        </DropdownMenuItem>
                      </>
                    )}
                  </DropdownMenuContent>
                </DropdownMenu>
              )}
            </div>
          )}
        </div>
      </CardHeader>

      <CardContent className={cn("flex flex-col gap-4", classNames?.content)}>
        {loadError !== null && (
          <Alert variant="destructive" className={classNames?.formError}>
            <CircleAlertIcon aria-hidden />
            <AlertDescription>{loadError}</AlertDescription>
          </Alert>
        )}
        {actionError !== null && (
          <Alert variant="destructive" className={classNames?.formError}>
            <CircleAlertIcon aria-hidden />
            <AlertDescription>{actionError}</AlertDescription>
          </Alert>
        )}
        {needsFreshSession && (
          <Alert variant="destructive" className={classNames?.formError}>
            <CircleAlertIcon aria-hidden />
            <AlertDescription className="flex flex-wrap items-center gap-2">
              {t.freshRequired}
              <Button type="button" variant="outline" size="sm" onClick={() => onSignInAgain?.()}>
                {t.signInAgain}
              </Button>
            </AlertDescription>
          </Alert>
        )}
        <p id={statusId} role="status" className={cn("text-xs text-muted-foreground empty:hidden", classNames?.status)}>
          {status}
        </p>

        {detail === null ? (
          loading && (
            <div aria-hidden className="flex flex-col gap-2">
              <span className="sr-only">{t.loading}</span>
              <Skeleton className="h-16 w-full rounded-lg" />
              <Skeleton className="h-24 w-full rounded-lg" />
            </div>
          )
        ) : (
          <>
            {detail.user.banned && (
              <Alert variant="destructive">
                <BanIcon aria-hidden />
                <AlertDescription>{detail.banReason === "" ? t.bannedNoReason : fillText(t.bannedWithReason, { reason: detail.banReason })}</AlertDescription>
              </Alert>
            )}
            <div className="grid gap-4 md:grid-cols-2">
              <Section title={t.detailsHeading} className={classNames?.section}>
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[13px]">
                  <dt className="text-muted-foreground">{t.created}</dt>
                  <dd>{formatDate(detail.user.createdAt)}</dd>
                  <dt className="text-muted-foreground">{t.lastActive}</dt>
                  <dd>{detail.user.lastActiveAt === null ? t.never : formatDate(detail.user.lastActiveAt)}</dd>
                  <dt className="text-muted-foreground">{t.sessionCount}</dt>
                  <dd className="tabular-nums">{detail.sessions}</dd>
                  <dt className="self-center text-muted-foreground">{t.roleLabel}</dt>
                  <dd>
                    {can.setRole === true && !self ? (
                      <RoleMenu value={role} roles={roles} label={t.roleLabel} disabled={busy} onChange={(next) => onSetRole?.(next)} />
                    ) : (
                      <span className="capitalize">{role}</span>
                    )}
                  </dd>
                </dl>
              </Section>
              <Section title={t.identitiesHeading} className={classNames?.section}>
                <Identities detail={detail} t={t} />
              </Section>
            </div>

            {twoFactor !== null && (
              <Section title={t.twoFactorHeading} className={classNames?.section}>
                <div className="flex flex-wrap items-center gap-2 text-[13px]">
                  <span className="flex-1">
                    {!twoFactor.enrolled ? t.twoFactorNone : fillText(twoFactor.enabled ? t.twoFactorOn : t.twoFactorPaused, { method: twoFactor.method })}
                  </span>
                  {twoFactor.enrolled && !self && (
                    <>
                      {twoFactor.enabled
                        ? can.disableTwoFactor === true &&
                          !detail.user.admin && (
                            <Button type="button" variant="outline" size="sm" disabled={busy} onClick={() => onPauseTwoFactor?.()}>
                              {t.twoFactorPause}
                            </Button>
                          )
                        : can.enableTwoFactor === true && (
                            <Button type="button" variant="outline" size="sm" disabled={busy} onClick={() => onResumeTwoFactor?.()}>
                              {t.twoFactorResume}
                            </Button>
                          )}
                      {can.resetTwoFactor === true && !detail.user.admin && (
                        <Button type="button" variant="destructive" size="sm" disabled={busy} onClick={() => setDialog("resetTwoFactor")}>
                          {t.twoFactorReset}
                        </Button>
                      )}
                    </>
                  )}
                </div>
              </Section>
            )}

            {metadata !== null && (
              <Section title={t.metadataHeading} className={classNames?.section}>
                <MetadataDocument label={t.metadataPublic} value={metadata.public} empty={t.metadataEmpty} />
              </Section>
            )}

            {can.listSessions === true && (
              <Section
                title={t.sessionsHeading}
                className={cn(classNames?.section, classNames?.sessions)}
                action={
                  can.revokeSessions === true &&
                  sessions.length > 0 && (
                    <Button type="button" variant="ghost" size="sm" disabled={busy} onClick={() => setDialog("revokeAll")}>
                      {t.revokeAll}
                    </Button>
                  )
                }
              >
                <SessionsTable
                  sessions={sessions}
                  isPending={sessionsLoading}
                  canRevoke={can.revokeSessions === true}
                  busy={busy}
                  t={t}
                  onRevoke={(s) => onRevokeSession?.(s)}
                />
                {sessionsError !== null && <p className="text-xs text-destructive">{sessionsError}</p>}
              </Section>
            )}
          </>
        )}
      </CardContent>

      <BanDialog
        open={dialog === "ban"}
        name={shown}
        durations={banDurations}
        pending={acting}
        t={t}
        className={classNames?.dialog}
        onOpenChange={(open) => setDialog(open ? "ban" : null)}
        onBan={(reason, minutes) => onBan?.({ reason, minutes })}
      />
      <PasswordDialog
        open={dialog === "password"}
        name={shown}
        pending={acting}
        serverError={passwordError}
        t={t}
        className={classNames?.dialog}
        onOpenChange={(open) => setDialog(open ? "password" : null)}
        onSubmit={async (password) => {
          await onSetPassword?.(password)
        }}
        onInput={() => onPasswordInput?.()}
      />
      <AlertDialog
        open={confirming !== null}
        onOpenChange={(open) => {
          if (!open && !acting) setDialog(null)
        }}
      >
        <AlertDialogContent className={classNames?.dialog}>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {fillText(confirming === "delete" ? t.deleteTitle : confirming === "revokeAll" ? t.revokeAllTitle : t.resetTitle, { name: shown })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {confirming === "delete" ? t.deleteDescription : confirming === "revokeAll" ? t.revokeAllDescription : t.resetDescription}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={acting}>{t.cancel}</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={acting}
              aria-busy={acting}
              onClick={() => {
                if (confirming === "delete") onDelete?.()
                else if (confirming === "revokeAll") onRevokeAll?.()
                else if (confirming === "resetTwoFactor") onResetTwoFactor?.()
              }}
            >
              {acting && <Spinner data-icon="inline-start" />}
              {confirming === "delete" ? t.deleteConfirm : confirming === "revokeAll" ? t.revokeAllConfirm : t.resetConfirm}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  )
}

/** A titled block of the card, with an optional action beside the title. */
function Section({ title, className, action, children }: { title: string; className: string | undefined; action?: ReactNode; children: ReactNode }) {
  const headingId = useId()
  return (
    <section aria-labelledby={headingId} className={cn("flex flex-col gap-1.5", className)}>
      <div className="flex min-h-6 items-center justify-between gap-2">
        <h3 id={headingId} className="text-xs font-medium text-muted-foreground">
          {title}
        </h3>
        {action}
      </div>
      {children}
    </section>
  )
}

/** One metadata document as indented JSON, or a muted "empty" for an empty object. */
function MetadataDocument({ label, value, empty }: { label: string; value: unknown; empty: string }) {
  const isEmpty = value === null || value === undefined || (typeof value === "object" && Object.keys(value).length === 0)
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs text-muted-foreground">{label}</span>
      {isEmpty ? (
        <p className="text-[13px] text-muted-foreground">{empty}</p>
      ) : (
        <pre className="max-h-48 overflow-auto rounded-lg border bg-muted/40 px-2.5 py-1.5 font-mono text-xs">{JSON.stringify(value, null, 2)}</pre>
      )}
    </div>
  )
}

/** The user's sign-in identifiers, each with its primary and verified badges. */
function Identities({ detail, t }: { detail: AdminUserDetailData; t: AdminUserDetailText }) {
  const identities = detail.identities ?? []
  if (identities.length === 0) return <p className="text-[13px] text-muted-foreground">{t.noIdentities}</p>
  return (
    <ul className="flex flex-col divide-y rounded-lg border">
      {identities.map((i) => (
        <li key={`${i.kind}:${i.value}`} className="flex flex-wrap items-center gap-x-2 gap-y-1 px-2.5 py-1.5 text-[13px]">
          <span className="w-12 shrink-0 text-xs text-muted-foreground capitalize">{i.kind}</span>
          <span className="min-w-0 flex-1 truncate" title={i.value}>
            {i.value}
          </span>
          {i.primary && <Badge variant="outline">{t.primary}</Badge>}
          <Badge variant={i.verified ? "secondary" : "outline"}>{i.verified ? t.verified : t.unverified}</Badge>
        </li>
      ))}
    </ul>
  )
}

/** The role menu: the current role on the trigger, the offered roles as a radio list. */
function RoleMenu({
  value,
  roles,
  label,
  disabled,
  onChange,
}: {
  value: string
  roles: readonly string[]
  label: string
  disabled: boolean
  onChange: (role: string) => void
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={<Button type="button" variant="outline" size="sm" className="min-w-20 justify-between capitalize" aria-label={`${label}: ${value}`} disabled={disabled} />}
      >
        {value}
        <ChevronDownIcon aria-hidden className="text-muted-foreground" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-36">
        <DropdownMenuGroup>
          <DropdownMenuLabel>{label}</DropdownMenuLabel>
          <DropdownMenuRadioGroup
            value={value}
            onValueChange={(next: string) => {
              if (next !== value) onChange(next)
            }}
          >
            {roles.map((r) => (
              <DropdownMenuRadioItem key={r} value={r} closeOnClick className="capitalize">
                {r}
              </DropdownMenuRadioItem>
            ))}
          </DropdownMenuRadioGroup>
        </DropdownMenuGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

/** The user's sessions, one row each with the device, address, last seen and (when allowed) Revoke. */
function SessionsTable({
  sessions,
  isPending,
  canRevoke,
  busy,
  t,
  onRevoke,
}: {
  sessions: readonly AuthSessionView[]
  isPending: boolean
  canRevoke: boolean
  busy: boolean
  t: AdminUserDetailText
  onRevoke: (session: AuthSessionView) => void
}) {
  if (isPending) return <Skeleton aria-hidden className="h-16 w-full rounded-lg" />
  if (sessions.length === 0) return <p className="text-[13px] text-muted-foreground">{t.noSessions}</p>
  return (
    <div className="rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead>{t.sessionDevice}</TableHead>
            <TableHead className="hidden sm:table-cell">{t.sessionIp}</TableHead>
            <TableHead>{t.sessionLastSeen}</TableHead>
            {canRevoke && (
              <TableHead className="w-16">
                <span className="sr-only">{t.revoke}</span>
              </TableHead>
            )}
          </TableRow>
        </TableHeader>
        <TableBody>
          {sessions.map((s) => {
            const device = deviceName(s.userAgent) ?? t.unknownDevice
            return (
              <TableRow key={s.id}>
                <TableCell>
                  <span className="flex items-center gap-1.5">
                    <MonitorSmartphoneIcon aria-hidden className="size-3.5 text-muted-foreground" />
                    {device}
                    {s.impersonated && <Badge variant="outline">{t.impersonated}</Badge>}
                  </span>
                </TableCell>
                <TableCell className="hidden font-mono text-xs text-muted-foreground sm:table-cell">{s.ip === "" ? "—" : s.ip}</TableCell>
                <TableCell className="text-muted-foreground">{formatDate(s.lastSeenAt)}</TableCell>
                {canRevoke && (
                  <TableCell className="text-right">
                    <Button type="button" variant="ghost" size="sm" disabled={busy} aria-label={fillText(t.revokeLabel, { device })} onClick={() => onRevoke(s)}>
                      {t.revoke}
                    </Button>
                  </TableCell>
                )}
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
    </div>
  )
}

/** The ban form: an optional reason and a length. */
function BanDialog({
  open,
  name,
  durations,
  pending,
  t,
  className,
  onOpenChange,
  onBan,
}: {
  open: boolean
  name: string
  durations: readonly number[]
  pending: boolean
  t: AdminUserDetailText
  className: string | undefined
  onOpenChange: (open: boolean) => void
  onBan: (reason: string, minutes: number) => void
}) {
  const formId = useId()
  const [reason, setReason] = useState("")
  const [minutes, setMinutes] = useState(durations[durations.length - 1] ?? 0)
  const durationText = (m: number) =>
    m <= 0
      ? t.banForever
      : m % MINUTES_PER_DAY === 0
        ? fillText(t.banDays, { days: m / MINUTES_PER_DAY })
        : fillText(t.banHours, { hours: Math.max(1, Math.round(m / MINUTES_PER_HOUR)) })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    onBan(reason, minutes)
  }
  return (
    <Dialog open={open} onOpenChange={(next) => !pending && onOpenChange(next)}>
      <DialogContent className={className}>
        <form noValidate onSubmit={submit} className="flex flex-col gap-3">
          <DialogHeader>
            <DialogTitle>{t.banTitle}</DialogTitle>
            <DialogDescription>{fillText(t.banDescription, { name })}</DialogDescription>
          </DialogHeader>
          <Field>
            <FieldLabel htmlFor={`${formId}-reason`}>{t.banReasonLabel}</FieldLabel>
            <Input id={`${formId}-reason`} value={reason} placeholder={t.banReasonPlaceholder} maxLength={BAN_REASON_MAX_LENGTH} onChange={(e) => setReason(e.target.value)} />
          </Field>
          <fieldset className="flex flex-col gap-1.5">
            <legend className="mb-1.5 text-[13px] font-medium">{t.banDurationLabel}</legend>
            <div role="radiogroup" aria-label={t.banDurationLabel} className="flex flex-wrap gap-1">
              {durations.map((m) => (
                <Button key={m} type="button" role="radio" aria-checked={m === minutes} variant={m === minutes ? "secondary" : "outline"} size="sm" onClick={() => setMinutes(m)}>
                  {durationText(m)}
                </Button>
              ))}
            </div>
          </fieldset>
          <DialogFooter>
            <Button type="button" variant="outline" disabled={pending} onClick={() => onOpenChange(false)}>
              {t.cancel}
            </Button>
            <Button type="submit" variant="destructive" disabled={pending} aria-busy={pending}>
              {pending && <Spinner data-icon="inline-start" />}
              {t.banConfirm}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/**
 * The set-password form: one password field, its errors under it. It
 * refuses an empty field itself; a server's message about the password comes
 * in as serverError. The field empties whenever the dialog closes.
 */
function PasswordDialog({
  open,
  name,
  pending,
  serverError,
  t,
  className,
  onOpenChange,
  onSubmit,
  onInput,
}: {
  open: boolean
  name: string
  pending: boolean
  serverError: string | null
  t: AdminUserDetailText
  className: string | undefined
  onOpenChange: (open: boolean) => void
  onSubmit: (password: string) => Promise<void>
  onInput: () => void
}) {
  const formId = useId()
  const [password, setPassword] = useState("")
  const [requiredError, setRequiredError] = useState(false)
  // Empty the field each time the dialog closes, whoever closed it: the
  // caller closes it after a successful call. Adjusting state during render
  // (not in an effect) is React's pattern for state that follows a prop.
  const [wasOpen, setWasOpen] = useState(open)
  if (open !== wasOpen) {
    setWasOpen(open)
    if (!open) {
      setPassword("")
      setRequiredError(false)
    }
  }
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (password === "") {
      setRequiredError(true)
      return
    }
    setRequiredError(false)
    await onSubmit(password)
  }
  const error = requiredError ? t.passwordRequired : serverError
  const invalid = error !== null
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (pending) return
        onOpenChange(next)
      }}
    >
      <DialogContent className={className}>
        <form noValidate onSubmit={(e) => void submit(e)} className="flex flex-col gap-3">
          <DialogHeader>
            <DialogTitle>{t.passwordTitle}</DialogTitle>
            <DialogDescription>{fillText(t.passwordDescription, { name })}</DialogDescription>
          </DialogHeader>
          <Field data-invalid={invalid}>
            <FieldLabel htmlFor={`${formId}-password`}>{t.passwordLabel}</FieldLabel>
            <Input
              id={`${formId}-password`}
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => {
                setRequiredError(false)
                onInput()
                setPassword(e.target.value)
              }}
              aria-invalid={invalid}
              aria-describedby={invalid ? `${formId}-password-error` : undefined}
            />
            {invalid && <FieldError id={`${formId}-password-error`}>{error}</FieldError>}
          </Field>
          <DialogFooter>
            <Button type="button" variant="outline" disabled={pending} onClick={() => onOpenChange(false)}>
              {t.cancel}
            </Button>
            <Button type="submit" disabled={pending} aria-busy={pending}>
              {pending && <Spinner data-icon="inline-start" />}
              {t.passwordConfirm}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
