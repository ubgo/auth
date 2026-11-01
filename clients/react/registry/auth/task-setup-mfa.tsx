import {
  SESSION_TASK_SETUP_MFA,
  useAuth,
  useLocalization,
  useSafeRedirect,
  useSessionActions,
  useSessionTasks,
  type AuthComponentProps,
  type HeadingLevel,
} from "@ubgo/auth-react"

import { TASK_SETUP_MFA_TEXT, TaskSetupMfaView, type TaskSetupMfaSlot, type TaskSetupMfaText } from "@/components/auth/task-setup-mfa-view"
import { TwoFactorSetup, type TwoFactorMethod, type TwoFactorSetupResult } from "@/components/auth/two-factor-setup"

// TaskSetupMFA: the page a session lands on when the server requires a
// second factor before it works (twofactor.RequireEnrolment opens the
// setup-mfa session task). It explains why, runs TwoFactorSetup, and once
// the factor is on, the server has replaced the session with an ordinary
// one: the page re-reads the session and goes on. TwoFactorSetup's security
// keys section (when the server offers keys) finishes the task the same way. Signing out is the only
// other way out, because every other page answers auth.session_task_pending.
// Without that task open (an ordinary session) it says there is nothing to
// do and links on.
//
// The card itself is TaskSetupMfaView (task-setup-mfa-view.tsx), with the
// wired TwoFactorSetup in its setup slot: this file only wires it to
// @ubgo/auth-react, the session and navigation.

export {
  TASK_SETUP_MFA_TEXT,
  TaskSetupMfaView,
  type TaskSetupMfaSlot,
  type TaskSetupMfaText,
  type TaskSetupMfaViewProps,
} from "@/components/auth/task-setup-mfa-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    taskSetupMfa: TaskSetupMfaText
  }
}

export type TaskSetupMfaProps = AuthComponentProps<TaskSetupMfaSlot, "taskSetupMfa", TwoFactorSetupResult> & {
  /** Passed to TwoFactorSetup: ask for the password when turning the factor on. */
  readonly requirePassword?: boolean
  /** Passed to TwoFactorSetup: the code length. */
  readonly digits?: 6 | 8
  /** Passed to TwoFactorSetup: which factor to enrol. */
  readonly method?: TwoFactorMethod
}

/** The level below each heading level, for the setup's own title under this card's. */
const NEXT_LEVEL: Record<HeadingLevel, HeadingLevel> = { 1: 2, 2: 3, 3: 4, 4: 5, 5: 6, 6: 6 }

export function TaskSetupMFA({
  className,
  classNames,
  localization,
  onSuccess,
  redirectTo: requestedRedirectTo,
  headingLevel = 1,
  requirePassword,
  digits,
  method,
}: TaskSetupMfaProps) {
  const t = useLocalization("taskSetupMfa", TASK_SETUP_MFA_TEXT, localization)
  const { navigate, paths } = useAuth()
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const { refreshSession, signOut } = useSessionActions()
  const { tasks } = useSessionTasks()
  const open = tasks.includes(SESSION_TASK_SETUP_MFA)

  const done = async (result: TwoFactorSetupResult) => {
    // The server issued a new session without the task; read it before moving on.
    await refreshSession()
    if (onSuccess !== undefined) onSuccess(result)
    else navigate(redirectTo ?? paths.afterSignIn)
  }

  return (
    <TaskSetupMfaView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      open={open}
      setup={
        open && (
          <TwoFactorSetup
            variant="embedded"
            headingLevel={NEXT_LEVEL[headingLevel]}
            className={classNames?.setup}
            onSuccess={(result) => void done(result)}
            {...(requirePassword === undefined ? {} : { requirePassword })}
            {...(digits === undefined ? {} : { digits })}
            {...(method === undefined ? {} : { method })}
          />
        )
      }
      onSignOut={() => void signOut()}
      onContinue={() => navigate(redirectTo ?? paths.afterSignIn)}
    />
  )
}
