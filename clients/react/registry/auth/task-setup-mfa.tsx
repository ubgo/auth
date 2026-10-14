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
import { ShieldCheckIcon } from "lucide-react"

import { TwoFactorSetup, type TwoFactorMethod, type TwoFactorSetupResult } from "@/components/auth/two-factor-setup"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { cn } from "@/lib/utils"

// TaskSetupMFA: the page a session lands on when the server requires a
// second factor before it works (twofactor.RequireEnrolment opens the
// setup-mfa session task). It explains why, runs TwoFactorSetup, and once
// the factor is on, the server has replaced the session with an ordinary
// one: the page re-reads the session and goes on. TwoFactorSetup's security
// keys section (when the server offers keys) finishes the task the same way. Signing out is the only
// other way out, because every other page answers auth.session_task_pending.
// Without that task open (an ordinary session) it says there is nothing to
// do and links on.

/** Every string TaskSetupMFA shows. */
export type TaskSetupMfaText = {
  title: string
  description: string
  notRequired: string
  continue: string
  signOut: string
}

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    taskSetupMfa: TaskSetupMfaText
  }
}

/** The English defaults. Override per app (AuthProvider localization.taskSetupMfa) or per use (localization prop). */
export const TASK_SETUP_MFA_TEXT: TaskSetupMfaText = {
  title: "Set up two-factor authentication",
  description: "Your account needs a second factor before you can continue. Set one up now; it takes a minute.",
  notRequired: "Your account has nothing to set up right now.",
  continue: "Continue",
  signOut: "Sign out instead",
}

/** The named parts classNames can style. */
export type TaskSetupMfaSlot = "root" | "header" | "title" | "description" | "content" | "setup" | "signOut"

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
    <Card className={cn("w-full max-w-md", className, classNames?.root)}>
      <CardHeader className={classNames?.header}>
        <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
          <ShieldCheckIcon aria-hidden className="size-4 text-muted-foreground" />
          {t.title}
        </CardTitle>
        <CardDescription className={classNames?.description}>{open ? t.description : t.notRequired}</CardDescription>
      </CardHeader>
      <CardContent className={cn("flex flex-col gap-3", classNames?.content)}>
        {open ? (
          <>
            <TwoFactorSetup
              variant="embedded"
              headingLevel={NEXT_LEVEL[headingLevel]}
              className={classNames?.setup}
              onSuccess={(result) => void done(result)}
              {...(requirePassword === undefined ? {} : { requirePassword })}
              {...(digits === undefined ? {} : { digits })}
              {...(method === undefined ? {} : { method })}
            />
            <Button type="button" variant="link" size="sm" className={cn("self-start px-0", classNames?.signOut)} onClick={() => void signOut()}>
              {t.signOut}
            </Button>
          </>
        ) : (
          <Button type="button" className="self-start" onClick={() => navigate(redirectTo ?? paths.afterSignIn)}>
            {t.continue}
          </Button>
        )}
      </CardContent>
    </Card>
  )
}
