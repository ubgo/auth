import { useMutation } from "@tanstack/react-query"
import type { AdminImpersonateResult, AuthError } from "@ubgo/auth-client"
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
import { useState } from "react"

import {
  ADMIN_USER_DETAIL_TEXT,
  AdminUserDetailView,
  type AdminUserDetailDialog,
  type AdminUserDetailSlot,
  type AdminUserDetailText,
} from "@/components/auth/admin-user-detail-view"

// AdminUserDetail: one user as an admin sees them, with every admin action
// on them. Their identities, ban and role; their sessions, each revocable,
// or all at once; their second factor (pause, switch back on, reset); and
// ban or unban, set a password, act as them (impersonate), and delete them
// after a confirmation. Each action shows only to callers the server lets
// take it (admin.has-permission, whatever roles or authorizer it runs); the
// server checks again on every call. The changing actions need a recent
// sign-in: onFreshSessionRequired hands that to the app, else the card
// offers to sign in again.
//
// The card itself is AdminUserDetailView (admin-user-detail-view.tsx): this
// file only wires it to @ubgo/auth-react, the calls, permissions and
// navigation.

export {
  ADMIN_USER_DETAIL_TEXT,
  AdminUserDetailView,
  type AdminUserBanValues,
  type AdminUserDetailCapabilities,
  type AdminUserDetailCapability,
  type AdminUserDetailDialog,
  type AdminUserDetailSlot,
  type AdminUserDetailText,
  type AdminUserDetailTwoFactor,
  type AdminUserDetailViewProps,
} from "@/components/auth/admin-user-detail-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    adminUserDetail: AdminUserDetailText
  }
}

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

/** Minutes in an hour and a day, for the default ban lengths. */
const MINUTES_PER_HOUR = 60
const MINUTES_PER_DAY = 1440

/** The ban lengths offered by default: an hour, a day, a week, and until unbanned. */
const DEFAULT_BAN_DURATIONS: readonly number[] = [MINUTES_PER_HOUR, MINUTES_PER_DAY, 7 * MINUTES_PER_DAY, 0]

/** The error that means the action needs a recent sign-in. */
const FRESH_REQUIRED: AnyErrorCode = "auth.fresh_session_required"

/** Error codes that belong under the password field. */
const PASSWORD_ERRORS: ReadonlySet<AnyErrorCode> = new Set<AnyErrorCode>(["password.too_short", "password.too_long", "password.breached", "password.weak", "password.reused"])

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

  const [failure, setFailure] = useState<string | null>(null)
  const [needsFresh, setNeedsFresh] = useState(false)
  const [status, setStatus] = useState<string | null>(null)
  const [dialog, setDialog] = useState<AdminUserDetailDialog>(null)
  const [passwordError, setPasswordError] = useState<string | null>(null)

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

  const run = (job: Job) => act.mutate(job)
  const close = () => setDialog(null)
  const afterDelete = () => {
    if (onDeleted !== undefined) onDeleted(userId)
    else if (backHref !== null) navigate(backHref)
  }
  const signInAgain = () => {
    const here = typeof window === "undefined" ? "" : window.location.pathname + window.location.search
    void signOut({ redirectTo: here === "" ? paths.signIn : `${paths.signIn}?redirectTo=${encodeURIComponent(here)}` })
  }

  return (
    <AdminUserDetailView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      userId={userId}
      selfId={me.id}
      forbidden={!permissionsPending && !can.getUser}
      detail={detail}
      loading={isPending}
      loadError={readError === null ? null : messageFor(readError)}
      can={can}
      sessions={sessions.sessions}
      sessionsLoading={sessions.isPending}
      sessionsError={sessions.error === null ? null : messageFor(sessions.error)}
      twoFactor={can.getTwoFactor && twoFactor.available ? twoFactor.twoFactor : null}
      metadata={metadata.available ? metadata.metadata : null}
      roles={roles}
      banDurations={banDurations}
      backHref={backHref ?? undefined}
      Link={Link}
      busy={act.isPending || impersonate.isPending}
      acting={act.isPending}
      impersonating={impersonate.isPending}
      actionError={failure}
      needsFreshSession={needsFresh}
      status={status}
      passwordError={passwordError}
      dialog={dialog}
      onDialogChange={(next) => {
        setPasswordError(null)
        setDialog(next)
      }}
      onImpersonate={() => impersonate.mutate()}
      onUnban={() => run({ run: () => actions.unban(userId), done: t.unbannedDone })}
      onBan={({ reason, minutes }) => run({ run: () => actions.ban({ userId, reason, minutes }), done: t.bannedDone, then: close })}
      onSetPassword={async (password) => {
        setPasswordError(null)
        const failed = await act.mutateAsync({ run: () => actions.setPassword(userId, password), done: t.passwordDone, then: close, fieldErrors: PASSWORD_ERRORS })
        // A password the server refused stays in the dialog under its field;
        // any other failure closes it and shows on the card.
        if (failed === null) return
        if (PASSWORD_ERRORS.has(failed.code)) setPasswordError(messageFor(failed))
        else close()
      }}
      onPasswordInput={() => setPasswordError(null)}
      onSetRole={(next) => run({ run: () => actions.setRole(userId, [next]), done: format(t.roleChanged, { role: next }) })}
      onRevokeSession={(s) => run({ run: () => actions.revokeSession(userId, s.id), done: t.revokedDone })}
      onRevokeAll={() => run({ run: () => actions.revokeSessions(userId), done: t.revokedAllDone, then: close })}
      onDelete={() =>
        run({
          run: () => actions.removeUser(userId),
          done: "",
          then: () => {
            close()
            afterDelete()
          },
        })
      }
      onPauseTwoFactor={() => run({ run: () => actions.disableTwoFactor(userId), done: t.pausedDone })}
      onResumeTwoFactor={() => run({ run: () => actions.enableTwoFactor(userId), done: t.resumedDone })}
      onResetTwoFactor={() => run({ run: () => actions.resetTwoFactor(userId), done: t.resetDone, then: close })}
      onSignInAgain={signInAgain}
    />
  )
}
