import { useLocalization } from "@ubgo/auth-react"

import { PASSWORD_STRENGTH_TEXT, PasswordStrengthView, type PasswordStrengthText, type PasswordStrengthViewProps } from "@/components/auth/password-strength-view"

// PasswordStrength: a four-step meter and a one-line hint under a new
// password field, shared by SignUpForm and ResetPasswordForm. It is a hint,
// not a rule: the server decides (its minimum length, a breach check, its own
// strength policy) and the form shows the server's answer under the field.
//
// The meter itself is PasswordStrengthView (password-strength-view.tsx): this
// file only applies the app's localization to it.

export {
  DEFAULT_PASSWORD_MIN_LENGTH,
  PASSWORD_STRENGTH_TEXT,
  PasswordStrengthView,
  scorePassword,
  type PasswordScore,
  type PasswordStrengthSlot,
  type PasswordStrengthText,
  type PasswordStrengthViewProps,
} from "@/components/auth/password-strength-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    passwordStrength: PasswordStrengthText
  }
}

/** The view's props, with `localization` (merged over the app's AuthProvider text) in place of `text`. */
export type PasswordStrengthProps = Omit<PasswordStrengthViewProps, "text"> & {
  readonly localization?: Partial<PasswordStrengthText>
}

/** PasswordStrengthView with the app's passwordStrength localization applied. */
export function PasswordStrength({ localization, ...props }: PasswordStrengthProps) {
  const t = useLocalization("passwordStrength", PASSWORD_STRENGTH_TEXT, localization)
  return <PasswordStrengthView {...props} text={t} />
}
