import { useMutation } from "@tanstack/react-query"
import type { AuthError } from "@ubgo/auth-client"
import { useAuth, useErrorMessage, useLocalization, usePluginClient, useSafeRedirect, type AuthComponentProps } from "@ubgo/auth-react"
import { useState } from "react"

import { DEFAULT_PASSWORD_MIN_LENGTH, PASSWORD_STRENGTH_TEXT } from "@/components/auth/password-strength"
import {
  RESET_PASSWORD_FORM_TEXT,
  ResetPasswordFormView,
  type ResetPasswordField,
  type ResetPasswordFormSlot,
  type ResetPasswordFormText,
} from "@/components/auth/reset-password-form-view"

// ResetPasswordForm: step two of a password reset, on the page the mailed
// link opens. It reads the token from the address bar (?token=), asks for the
// new password twice, and posts both. The link works once: a used, expired or
// missing token turns the card into a "request a new link" step instead of
// leaving a form that can only fail. A reset signs nobody in, so success
// offers the sign-in page.
//
// The card itself is ResetPasswordFormView (reset-password-form-view.tsx):
// this file only wires it to @ubgo/auth-react, the token, the call and
// navigation.

export {
  RESET_PASSWORD_FORM_TEXT,
  ResetPasswordFormView,
  type ResetPasswordField,
  type ResetPasswordFormSlot,
  type ResetPasswordFormText,
  type ResetPasswordFormValues,
  type ResetPasswordFormViewProps,
  type ResetPasswordStatus,
} from "@/components/auth/reset-password-form-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    resetPasswordForm: ResetPasswordFormText
  }
}

/** The reset went through, handed to onSuccess. Nobody is signed in by it. */
export type ResetPasswordSuccess = {
  readonly reset: true
}

export type ResetPasswordFormProps = AuthComponentProps<ResetPasswordFormSlot, "resetPasswordForm", ResetPasswordSuccess> & {
  /**
   * The token from the reset link. Left out, it is read from the page's
   * address (?token=), which is where the server's link puts it.
   */
  readonly token?: string
  /** The shortest password the strength hint and the check before submit ask for; match the server's password.MinLength. */
  readonly minPasswordLength?: number
  /** Ask for the new password twice. On by default. */
  readonly confirmPassword?: boolean
  /** Focus the first field on mount. */
  readonly autoFocus?: boolean
}

/** The `token` query parameter of the page's address, or "" during server rendering or when it is absent. */
function tokenFromLocation(): string {
  if (typeof window === "undefined") return ""
  return new URLSearchParams(window.location.search).get("token") ?? ""
}

/** Codes about the new password, shown under its field. */
const PASSWORD_ERRORS: ReadonlySet<string> = new Set(["password.too_short", "password.too_long", "password.weak", "password.breached", "password.reused"])

export function ResetPasswordForm({
  className,
  classNames,
  localization,
  onSuccess,
  redirectTo: requestedRedirectTo,
  headingLevel = 1,
  token: tokenProp,
  minPasswordLength = DEFAULT_PASSWORD_MIN_LENGTH,
  confirmPassword = true,
  autoFocus = false,
}: ResetPasswordFormProps) {
  const t = useLocalization("resetPasswordForm", RESET_PASSWORD_FORM_TEXT, localization)
  const strengthText = useLocalization("passwordStrength", PASSWORD_STRENGTH_TEXT)
  const messageFor = useErrorMessage()
  const { navigate, paths, Link } = useAuth()
  // redirectTo usually comes from the address bar: anything but a path on
  // this site (or an origin the provider allows) is dropped, so the default
  // applies and a crafted link cannot send the user to another site.
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const password = usePluginClient("password")
  // Read once: the address does not change under the form, and a router
  // that strips the query after mount must not blank the token mid-typing.
  const [token] = useState(() => tokenProp ?? tokenFromLocation())

  const [formError, setFormError] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<ResetPasswordField, string>>>({})
  const [state, setState] = useState<"form" | "done" | "invalid">(token === "" ? "invalid" : "form")

  /** Shows a failed call: an used or expired token as its own step, a password complaint under the field (the view focuses it), anything else above the form. */
  function showError(error: AuthError) {
    if (error.code === "auth.token_invalid") setState("invalid")
    else if (PASSWORD_ERRORS.has(error.code)) setFieldErrors({ password: messageFor(error) })
    else setFormError(messageFor(error))
  }

  const reset = useMutation({
    mutationFn: async (newPassword: string) => {
      if (password === null) throw new Error("ResetPasswordForm: password plugin missing")
      return password.reset({ token, password: newPassword })
    },
    onSuccess: ({ error }) => {
      if (error !== null) {
        showError(error)
        return
      }
      if (onSuccess !== undefined) onSuccess({ reset: true })
      else if (redirectTo !== undefined) navigate(redirectTo)
      else setState("done")
    },
  })

  if (password === null) return null

  return (
    <ResetPasswordFormView
      className={className}
      classNames={classNames}
      text={t}
      strengthText={strengthText}
      headingLevel={headingLevel}
      status={state === "invalid" && token === "" ? "missing" : state}
      minPasswordLength={minPasswordLength}
      confirmPassword={confirmPassword}
      autoFocus={autoFocus}
      pending={reset.isPending}
      formError={formError}
      fieldErrors={fieldErrors}
      signInHref={paths.signIn}
      forgotPasswordHref={paths.forgotPassword}
      Link={Link}
      onSubmit={async (values) => {
        setFormError(null)
        setFieldErrors({})
        await reset.mutateAsync(values.password)
      }}
      onPasswordChange={() => setFieldErrors({})}
    />
  )
}
