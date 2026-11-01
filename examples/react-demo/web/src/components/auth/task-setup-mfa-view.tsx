import { ShieldCheckIcon } from "lucide-react"
import type { ReactNode } from "react"

import type { ViewHeadingLevel } from "@/components/auth/auth-view"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { cn } from "@/lib/utils"

// TaskSetupMfaView: the "set up a second factor first" card with no data
// layer. While the task is open it shows the explanation, the setup itself
// (a slot: TaskSetupMFA puts the wired TwoFactorSetup there) and a way to
// sign out; once it is not, it says there is nothing to do and offers to go
// on. TaskSetupMFA (task-setup-mfa.tsx) is this view wired to
// @ubgo/auth-react; render the view yourself, with your own setup form in
// the slot, to put the same card on any other backend.

/** Every string TaskSetupMFA shows. */
export type TaskSetupMfaText = {
  title: string
  description: string
  notRequired: string
  continue: string
  signOut: string
}

/** The English defaults. Override per app (AuthProvider localization.taskSetupMfa) or per use (localization prop). */
export const TASK_SETUP_MFA_TEXT: TaskSetupMfaText = {
  title: "Set up two-factor authentication",
  description: "Your account needs a second factor before you can continue. Set one up now; it takes a minute.",
  notRequired: "Your account has nothing to set up right now.",
  continue: "Continue",
  signOut: "Sign out instead",
}

/** The named parts classNames can style. `setup` is for whatever fills the setup slot; the view itself leaves it to the slot's owner. */
export type TaskSetupMfaSlot = "root" | "header" | "title" | "description" | "content" | "setup" | "signOut"

export type TaskSetupMfaViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<TaskSetupMfaSlot, string>>
  /** Text overrides, merged over TASK_SETUP_MFA_TEXT. */
  readonly text?: Partial<TaskSetupMfaText>
  /** The level of the title, 1 by default. */
  readonly headingLevel?: ViewHeadingLevel
  /** Whether the session still has the setup-mfa task: the setup and sign-out show while it does, a Continue button once it does not. */
  readonly open?: boolean
  /** The setup form, rendered while the task is open. */
  readonly setup?: ReactNode
  /** "Sign out instead", the one other way out while the task is open. */
  readonly onSignOut?: () => void
  /** "Continue", once there is nothing to set up. */
  readonly onContinue?: () => void
}

export function TaskSetupMfaView({ className, classNames, text, headingLevel = 1, open = true, setup, onSignOut, onContinue }: TaskSetupMfaViewProps) {
  const t: TaskSetupMfaText = { ...TASK_SETUP_MFA_TEXT, ...text }
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
            {setup}
            <Button type="button" variant="link" size="sm" className={cn("self-start px-0", classNames?.signOut)} onClick={() => onSignOut?.()}>
              {t.signOut}
            </Button>
          </>
        ) : (
          <Button type="button" className="self-start" onClick={() => onContinue?.()}>
            {t.continue}
          </Button>
        )}
      </CardContent>
    </Card>
  )
}
