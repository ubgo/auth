import { format, useLocalization } from "@ubgo/auth-react"

import { cn } from "@/lib/utils"

// PasswordStrength: a four-step meter and a one-line hint under a new
// password field, shared by SignUpForm and ResetPasswordForm. It is a hint,
// not a rule: the server decides (its minimum length, a breach check, its own
// strength policy) and the form shows the server's answer under the field.
// The score is a short heuristic on length and variety, so the file brings no
// dictionary and no dependency.

/** Every string the meter shows. */
export type PasswordStrengthText = {
  /** `{min}` is the shortest length the form asks for. */
  tooShort: string
  weak: string
  fair: string
  good: string
  strong: string
  /** Shown while the password is shorter than the minimum. `{min}` as above. */
  hintLength: string
  /** Shown while the score is weak or fair. */
  hintLonger: string
}

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    passwordStrength: PasswordStrengthText
  }
}

/** The English defaults. Override per app (AuthProvider localization.passwordStrength) or per use. */
export const PASSWORD_STRENGTH_TEXT: PasswordStrengthText = {
  tooShort: "Too short",
  weak: "Weak",
  fair: "Fair",
  good: "Good",
  strong: "Strong",
  hintLength: "Use {min} or more characters.",
  hintLonger: "Longer is stronger. A few unrelated words work well.",
}

/** 0 is shorter than the minimum; 1 to 4 run from weak to strong. */
export type PasswordScore = 0 | 1 | 2 | 3 | 4

/** NIST SP 800-63B's minimum, the server's default (password.DefaultMinLength). */
export const DEFAULT_PASSWORD_MIN_LENGTH = 8

/** Lengths past which a password earns a point: long, then very long. */
const LONG = 12
const VERY_LONG = 16

/** Passwords every guessing list starts with, lowercased; any of these scores weak at any length. */
const COMMON = new Set(["password", "passw0rd", "12345678", "123456789", "1234567890", "qwertyuiop", "iloveyou", "letmein1", "11111111"])

/** A point total (1 to 4) as its score; the lookup keeps the result in the PasswordScore union without a cast. */
const SCORE_OF_POINTS: Readonly<Record<number, PasswordScore>> = { 1: 1, 2: 2, 3: 3, 4: 4 }

/** How many of lower, upper, digit and other characters the password uses. */
function variety(value: string): number {
  return [/[a-z]/, /[A-Z]/, /\d/, /[^a-zA-Z\d]/].filter((re) => re.test(value)).length
}

/**
 * Scores a password from 0 (under minLength) to 4. Length counts most,
 * variety helps, and a password that is one repeated character or a common
 * one is weak however long it is. Characters are counted as code points, as
 * the server counts them.
 */
export function scorePassword(value: string, minLength: number = DEFAULT_PASSWORD_MIN_LENGTH): PasswordScore {
  const length = [...value].length
  if (length < minLength) return 0
  if (COMMON.has(value.toLowerCase()) || new Set(value).size <= 2) return 1
  const points = 1 + Number(length >= LONG) + Number(length >= VERY_LONG) + Number(variety(value) >= 3)
  return SCORE_OF_POINTS[points] ?? 4
}

/** The label for each score, from the text map. */
function labelOf(score: PasswordScore, t: PasswordStrengthText, minLength: number): string {
  switch (score) {
    case 0:
      return format(t.tooShort, { min: minLength })
    case 1:
      return t.weak
    case 2:
      return t.fair
    case 3:
      return t.good
    case 4:
      return t.strong
  }
}

/** The named parts classNames can style. */
export type PasswordStrengthSlot = "root" | "meter" | "segment" | "label" | "hint"

export type PasswordStrengthProps = {
  /** The password being typed. Nothing renders while it is empty. */
  readonly value: string
  /** The shortest length the form asks for; match the server's password.MinLength. */
  readonly minLength?: number
  /** Show the one-line advice after the label. Turn it off while the field shows an error that says the same. */
  readonly showHint?: boolean
  /** Put on the root, so the input can point aria-describedby at it. */
  readonly id?: string
  readonly className?: string
  readonly classNames?: Partial<Record<PasswordStrengthSlot, string>>
  readonly localization?: Partial<PasswordStrengthText>
}

/** The segments the meter draws, one per score above 0. */
const SEGMENTS = [1, 2, 3, 4] as const

export function PasswordStrength({ value, minLength = DEFAULT_PASSWORD_MIN_LENGTH, showHint = true, id, className, classNames, localization }: PasswordStrengthProps) {
  const t = useLocalization("passwordStrength", PASSWORD_STRENGTH_TEXT, localization)
  if (value === "") return null
  const score = scorePassword(value, minLength)
  const hint = !showHint ? null : score === 0 ? format(t.hintLength, { min: minLength }) : score <= 2 ? t.hintLonger : null
  const label = labelOf(score, t, minLength)
  return (
    <div id={id} data-score={score} className={cn("flex flex-col gap-1", className, classNames?.root)}>
      {/* The meter is decoration; the label beside it says the same thing in words. */}
      <div aria-hidden className={cn("flex gap-1", classNames?.meter)}>
        {SEGMENTS.map((s) => (
          <span
            key={s}
            className={cn(
              "h-1 flex-1 rounded-full bg-muted transition-colors",
              s <= score && (score <= 1 ? "bg-destructive" : "bg-primary"),
              classNames?.segment,
            )}
          />
        ))}
      </div>
      {/* Polite, so a screen reader hears the new strength after typing pauses, not on every key.
          "Too short" is left out while the field shows its own error, which says the same. */}
      {(showHint || score > 0) && (
        <p aria-live="polite" className={cn("text-xs text-muted-foreground", classNames?.label)}>
          <span className={cn("font-medium", score <= 1 ? "text-destructive" : "text-foreground")}>{label}</span>
          {hint !== null && <span className={classNames?.hint}> · {hint}</span>}
        </p>
      )}
    </div>
  )
}
