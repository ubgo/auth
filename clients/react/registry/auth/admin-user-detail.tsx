import { useMutation } from "@tanstack/react-query"
import type { AdminImpersonateResult, AdminUserDetail as AdminUserDetailData, AuthError, AuthSessionView } from "@ubgo/auth-client"
import {
  format,
  useAdminActions,
  useAdminPermissions,
  useAdminTwoFactor,
  useAdminUser,
  useAdminUserMetadata,
  useAdminUserSessions,
  useAuth,
  useErrorMessage,
  useLocalization,
  usePluginClient,
  useSafeRedirect,
  useSession,
  useSessionActions,
  type AnyErrorCode,
  type AuthComponentProps,
} from "@ubgo/auth-react"
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

// AdminUserDetail: one user as an admin sees them, with every admin action
// on them. Their identities, ban and role; their sessions, each revocable,
// or all at once; their second factor (pause, switch back on, reset); and
// ban or unban, set a password, act as them (impersonate), and delete them
// after a confirmation. Each action shows only to callers the server lets
// take it (admin.has-permission, whatever roles or authorizer it runs); the
// server checks again on every call. The changing actions need a recent
// sign-in: onFreshSessionRequired hands that to the app, else the card
// offers to sign in again.

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

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    adminUserDetail: AdminUserDetailText
  }
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

export type AdminUserDetailProps = AuthComponentProps<AdminUserDetailSlot, "adminUserDetail", AdminImpersonateResult> & {
  /** The user to show. */
  readonly userId: string
  /** Where "All users" links to and where a deleted user's page goes. `/admin/users` by default; null hides the link. */
  readonly backHref?: string | null
  /** The roles the role menu offers, as the server names them. The admin plugin's two built-in roles by default. */
  readonly roles?: readonly string[]
  /** The ban lengths offered, in minutes; 0 is "until unbanned". */
  readonly banDurations?: readonly number[]
  /** Called after the user was deleted, instead of going to backHref. */
  readonly onDeleted?: (userId: string) => void
  /**
   * Called when an action needs a recent sign-in, with a retry that reruns
   * it; the app confirms who the admin is (a re-authentication dialog) and
   * calls retry. Without it the card offers to sign in again.
   */
  readonly onFreshSessionRequired?: (retry: () => Promise<void>) => void
}

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

/** The error that means the action needs a recent sign-in. */
const FRESH_REQUIRED: AnyErrorCode = "auth.fresh_session_required"

/** Error codes that belong under the password field. */
const PASSWORD_ERRORS: ReadonlySet<AnyErrorCode> = new Set<AnyErrorCode>(["password.too_short", "password.too_long", "password.breached", "password.weak", "password.reused"])

/** Which confirmation is open. */
type Confirming = "delete" | "revokeAll" | "resetTwoFactor" | null

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

/** One action the card runs: the call, the message on success, and what to do next. */
type Job = {
  readonly run: () => Promise<AuthError | null>
  readonly done: string
  /** Runs after success, after the message is set (close a dialog, navigate). */
  readonly then?: () => void
  /** Codes a dialog shows under its own field, so the card does not show them a second time. */
  readonly fieldErrors?: ReadonlySet<AnyErrorCode>
}

export function AdminUserDetail({
  className,
  classNames,
  localization,
  onSuccess,
  redirectTo: requestedRedirectTo,
  headingLevel = 1,
  userId,
  backHref = "/admin/users",
  roles = DEFAULT_ROLES,
  banDurations = DEFAULT_BAN_DURATIONS,
  onDeleted,
  onFreshSessionRequired,
}: AdminUserDetailProps) {
  const t = useLocalization("adminUserDetail", ADMIN_USER_DETAIL_TEXT, localization)
  const plugin = usePluginClient("admin")
  const { user: me } = useSession()
  const { signOut } = useSessionActions()
  const { navigate, paths, Link } = useAuth()
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const messageFor = useErrorMessage()
  const { can, isPending: permissionsPending } = useAdminPermissions()
  const { detail, isPending, error: readError } = useAdminUser(can.getUser ? userId : "")
  const sessions = useAdminUserSessions(userId, can.listSessions)
  const twoFactor = useAdminTwoFactor(userId, can.getTwoFactor)
  const metadata = useAdminUserMetadata(userId, can.getUser)
  const actions = useAdminActions()
  const statusId = useId()

  const [failure, setFailure] = useState<string | null>(null)
  const [needsFresh, setNeedsFresh] = useState(false)
  const [status, setStatus] = useState<string | null>(null)
  const [confirming, setConfirming] = useState<Confirming>(null)
  const [banOpen, setBanOpen] = useState(false)
  const [passwordOpen, setPasswordOpen] = useState(false)

  const act = useMutation({
    mutationFn: (job: Job) => job.run(),
    onMutate: () => {
      setFailure(null)
      setNeedsFresh(false)
      setStatus(null)
    },
    onSuccess: (error, job) => {
      if (error === null) {
        setStatus(job.done)
        job.then?.()
        return
      }
      if (error.code === FRESH_REQUIRED) {
        if (onFreshSessionRequired === undefined) setNeedsFresh(true)
        else
          onFreshSessionRequired(async () => {
            await act.mutateAsync(job)
          })
        return
      }
      if (job.fieldErrors?.has(error.code) !== true) setFailure(messageFor(error))
    },
  })

  const impersonate = useMutation({
    mutationFn: () => actions.impersonate(userId),
    onMutate: () => {
      setFailure(null)
      setNeedsFresh(false)
      setStatus(null)
    },
    onSuccess: ({ result, error }) => {
      if (result !== null) {
        if (onSuccess !== undefined) onSuccess(result)
        else navigate(redirectTo ?? paths.afterSignIn)
        return
      }
      if (error === null) return
      if (error.code === FRESH_REQUIRED && onFreshSessionRequired !== undefined) {
        onFreshSessionRequired(async () => {
          await impersonate.mutateAsync()
        })
      } else if (error.code === FRESH_REQUIRED) setNeedsFresh(true)
      else setFailure(messageFor(error))
    },
  })

  if (plugin === null || me === null) return null

  if (!permissionsPending && !can.getUser) {
    return (
      <Card className={cn("w-full max-w-3xl", className, classNames?.root)}>
        <CardContent>
          <p className="text-[13px] text-muted-foreground">{t.forbidden}</p>
        </CardContent>
      </Card>
    )
  }

  const busy = act.isPending || impersonate.isPending
  const run = (job: Job) => act.mutate(job)
  const name = detail?.user.name.trim() ?? ""
  const shown = name === "" ? t.unnamed : name
  const self = detail?.user.id === me.id
  // The roles the server reports; several are shown joined, and the menu sets one.
  const role = detail === null ? USER_ROLE : (detail.user.roles ?? []).join(", ") || (detail.user.admin ? ADMIN_ROLE : USER_ROLE)
  const afterDelete = () => {
    if (onDeleted !== undefined) onDeleted(userId)
    else if (backHref !== null) navigate(backHref)
  }
  const signInAgain = () => {
    const here = typeof window === "undefined" ? "" : window.location.pathname + window.location.search
    void signOut({ redirectTo: here === "" ? paths.signIn : `${paths.signIn}?redirectTo=${encodeURIComponent(here)}` })
  }

  return (
    <Card className={cn("w-full max-w-3xl", className, classNames?.root)} aria-busy={isPending}>
      <CardHeader className={cn("gap-2", classNames?.header)}>
        {backHref !== null && (
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
              {can.impersonate && !detail.user.admin && !detail.user.banned && (
                <Button type="button" variant="outline" disabled={busy} aria-busy={impersonate.isPending} onClick={() => impersonate.mutate()}>
                  {impersonate.isPending ? <Spinner data-icon="inline-start" /> : <VenetianMaskIcon aria-hidden data-icon="inline-start" />}
                  {t.impersonate}
                </Button>
              )}
              {can.ban &&
                !detail.user.admin &&
                (detail.user.banned ? (
                  <Button type="button" variant="outline" disabled={busy} onClick={() => run({ run: () => actions.unban(userId), done: t.unbannedDone })}>
                    <UserRoundCheckIcon aria-hidden data-icon="inline-start" />
                    {t.unban}
                  </Button>
                ) : (
                  <Button type="button" variant="destructive" disabled={busy} onClick={() => setBanOpen(true)}>
                    <BanIcon aria-hidden data-icon="inline-start" />
                    {t.ban}
                  </Button>
                ))}
              {(can.setPassword || can.revokeSessions || can.deleteUser) && (
                <DropdownMenu>
                  <DropdownMenuTrigger render={<Button type="button" variant="ghost" size="icon" aria-label={t.actions} disabled={busy} />}>
                    {act.isPending ? <Spinner /> : <EllipsisIcon aria-hidden />}
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="w-48">
                    {can.setPassword && !detail.user.admin && (
                      <DropdownMenuItem onClick={() => setPasswordOpen(true)}>
                        <KeyRoundIcon aria-hidden />
                        {t.setPassword}
                      </DropdownMenuItem>
                    )}
                    {can.revokeSessions && (
                      <DropdownMenuItem onClick={() => setConfirming("revokeAll")}>
                        <LogOutIcon aria-hidden />
                        {t.revokeAll}
                      </DropdownMenuItem>
                    )}
                    {can.deleteUser && !detail.user.admin && (
                      <>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem variant="destructive" onClick={() => setConfirming("delete")}>
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
        {readError !== null && (
          <Alert variant="destructive" className={classNames?.formError}>
            <CircleAlertIcon aria-hidden />
            <AlertDescription>{messageFor(readError)}</AlertDescription>
          </Alert>
        )}
        {failure !== null && (
          <Alert variant="destructive" className={classNames?.formError}>
            <CircleAlertIcon aria-hidden />
            <AlertDescription>{failure}</AlertDescription>
          </Alert>
        )}
        {needsFresh && (
          <Alert variant="destructive" className={classNames?.formError}>
            <CircleAlertIcon aria-hidden />
            <AlertDescription className="flex flex-wrap items-center gap-2">
              {t.freshRequired}
              <Button type="button" variant="outline" size="sm" onClick={signInAgain}>
                {t.signInAgain}
              </Button>
            </AlertDescription>
          </Alert>
        )}
        <p id={statusId} role="status" className={cn("text-xs text-muted-foreground empty:hidden", classNames?.status)}>
          {status}
        </p>

        {detail === null ? (
          isPending && (
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
                <AlertDescription>{detail.banReason === "" ? t.bannedNoReason : format(t.bannedWithReason, { reason: detail.banReason })}</AlertDescription>
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
                    {can.setRole && !self ? (
                      <RoleMenu
                        value={role}
                        roles={roles}
                        label={t.roleLabel}
                        disabled={busy}
                        onChange={(next) => run({ run: () => actions.setRole(userId, [next]), done: format(t.roleChanged, { role: next }) })}
                      />
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

            {can.getTwoFactor && twoFactor.available && twoFactor.twoFactor !== null && (
              <Section title={t.twoFactorHeading} className={classNames?.section}>
                <div className="flex flex-wrap items-center gap-2 text-[13px]">
                  <span className="flex-1">
                    {!twoFactor.twoFactor.enrolled
                      ? t.twoFactorNone
                      : format(twoFactor.twoFactor.enabled ? t.twoFactorOn : t.twoFactorPaused, { method: twoFactor.twoFactor.method })}
                  </span>
                  {twoFactor.twoFactor.enrolled && !self && (
                    <>
                      {twoFactor.twoFactor.enabled
                        ? can.disableTwoFactor &&
                          !detail.user.admin && (
                            <Button type="button" variant="outline" size="sm" disabled={busy} onClick={() => run({ run: () => actions.disableTwoFactor(userId), done: t.pausedDone })}>
                              {t.twoFactorPause}
                            </Button>
                          )
                        : can.enableTwoFactor && (
                            <Button type="button" variant="outline" size="sm" disabled={busy} onClick={() => run({ run: () => actions.enableTwoFactor(userId), done: t.resumedDone })}>
                              {t.twoFactorResume}
                            </Button>
                          )}
                      {can.resetTwoFactor && !detail.user.admin && (
                        <Button type="button" variant="destructive" size="sm" disabled={busy} onClick={() => setConfirming("resetTwoFactor")}>
                          {t.twoFactorReset}
                        </Button>
                      )}
                    </>
                  )}
                </div>
              </Section>
            )}

            {metadata.available && metadata.metadata !== null && (
              <Section title={t.metadataHeading} className={classNames?.section}>
                <MetadataDocument label={t.metadataPublic} value={metadata.metadata.public} empty={t.metadataEmpty} />
              </Section>
            )}

            {can.listSessions && (
              <Section
                title={t.sessionsHeading}
                className={cn(classNames?.section, classNames?.sessions)}
                action={
                  can.revokeSessions &&
                  sessions.sessions.length > 0 && (
                    <Button type="button" variant="ghost" size="sm" disabled={busy} onClick={() => setConfirming("revokeAll")}>
                      {t.revokeAll}
                    </Button>
                  )
                }
              >
                <SessionsTable
                  sessions={sessions.sessions}
                  isPending={sessions.isPending}
                  canRevoke={can.revokeSessions}
                  busy={busy}
                  t={t}
                  onRevoke={(s) => run({ run: () => actions.revokeSession(userId, s.id), done: t.revokedDone })}
                />
                {sessions.error !== null && <p className="text-xs text-destructive">{messageFor(sessions.error)}</p>}
              </Section>
            )}
          </>
        )}
      </CardContent>

      <BanDialog
        open={banOpen}
        name={shown}
        durations={banDurations}
        pending={act.isPending}
        t={t}
        className={classNames?.dialog}
        onOpenChange={setBanOpen}
        onBan={(reason, minutes) =>
          run({ run: () => actions.ban({ userId, reason, minutes }), done: t.bannedDone, then: () => setBanOpen(false) })
        }
      />
      <PasswordDialog
        open={passwordOpen}
        name={shown}
        pending={act.isPending}
        t={t}
        className={classNames?.dialog}
        onOpenChange={setPasswordOpen}
        onSubmit={(password) => act.mutateAsync({ run: () => actions.setPassword(userId, password), done: t.passwordDone, fieldErrors: PASSWORD_ERRORS })}
        onDone={() => setPasswordOpen(false)}
      />
      <AlertDialog
        open={confirming !== null}
        onOpenChange={(open) => {
          if (!open && !act.isPending) setConfirming(null)
        }}
      >
        <AlertDialogContent className={classNames?.dialog}>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {format(confirming === "delete" ? t.deleteTitle : confirming === "revokeAll" ? t.revokeAllTitle : t.resetTitle, { name: shown })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {confirming === "delete" ? t.deleteDescription : confirming === "revokeAll" ? t.revokeAllDescription : t.resetDescription}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={act.isPending}>{t.cancel}</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={act.isPending}
              aria-busy={act.isPending}
              onClick={() => {
                const close = () => setConfirming(null)
                if (confirming === "delete")
                  run({
                    run: () => actions.removeUser(userId),
                    done: "",
                    then: () => {
                      close()
                      afterDelete()
                    },
                  })
                else if (confirming === "revokeAll") run({ run: () => actions.revokeSessions(userId), done: t.revokedAllDone, then: close })
                else if (confirming === "resetTwoFactor") run({ run: () => actions.resetTwoFactor(userId), done: t.resetDone, then: close })
              }}
            >
              {act.isPending && <Spinner data-icon="inline-start" />}
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
                    <Button type="button" variant="ghost" size="sm" disabled={busy} aria-label={format(t.revokeLabel, { device })} onClick={() => onRevoke(s)}>
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
        ? format(t.banDays, { days: m / MINUTES_PER_DAY })
        : format(t.banHours, { hours: Math.max(1, Math.round(m / MINUTES_PER_HOUR)) })
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
            <DialogDescription>{format(t.banDescription, { name })}</DialogDescription>
          </DialogHeader>
          <Field>
            <FieldLabel htmlFor={`${formId}-reason`}>{t.banReasonLabel}</FieldLabel>
            <Input id={`${formId}-reason`} value={reason} placeholder={t.banReasonPlaceholder} maxLength={300} onChange={(e) => setReason(e.target.value)} />
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

/** The set-password form: one password field, its errors under it. */
function PasswordDialog({
  open,
  name,
  pending,
  t,
  className,
  onOpenChange,
  onSubmit,
  onDone,
}: {
  open: boolean
  name: string
  pending: boolean
  t: AdminUserDetailText
  className: string | undefined
  onOpenChange: (open: boolean) => void
  onSubmit: (password: string) => Promise<AuthError | null>
  onDone: () => void
}) {
  const formId = useId()
  const messageFor = useErrorMessage()
  const [password, setPassword] = useState("")
  const [error, setError] = useState<string | null>(null)
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (password === "") {
      setError(t.passwordRequired)
      return
    }
    setError(null)
    const failure = await onSubmit(password)
    if (failure === null) {
      setPassword("")
      onDone()
    } else if (PASSWORD_ERRORS.has(failure.code)) setError(messageFor(failure))
    else onDone()
  }
  const invalid = error !== null
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (pending) return
        if (!next) {
          setPassword("")
          setError(null)
        }
        onOpenChange(next)
      }}
    >
      <DialogContent className={className}>
        <form noValidate onSubmit={(e) => void submit(e)} className="flex flex-col gap-3">
          <DialogHeader>
            <DialogTitle>{t.passwordTitle}</DialogTitle>
            <DialogDescription>{format(t.passwordDescription, { name })}</DialogDescription>
          </DialogHeader>
          <Field data-invalid={invalid}>
            <FieldLabel htmlFor={`${formId}-password`}>{t.passwordLabel}</FieldLabel>
            <Input
              id={`${formId}-password`}
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => {
                setError(null)
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
