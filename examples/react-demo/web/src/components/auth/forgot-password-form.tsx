import { useMutation } from "@tanstack/react-query"
import { useAuth, useErrorMessage, useLocalization, usePluginClient, useSafeRedirect, type AuthComponentProps } from "@ubgo/auth-react"
import { useState } from "react"

import {
  FORGOT_PASSWORD_FORM_TEXT,
  ForgotPasswordFormView,
  type ForgotPasswordField,
  type ForgotPasswordFormSlot,
  type ForgotPasswordFormText,
} from "@/components/auth/forgot-password-form-view"

// ForgotPasswordForm: step one of a password reset. It asks for the email
// (or username, with the username plugin) and asks the server to mail a
// reset link to the account's verified recovery address. The server answers
// the same whether or not the account exists, so the "check your email" step
// that follows says "if an account exists" and never confirms one.
//
// The card itself is ForgotPasswordFormView (forgot-password-form-view.tsx):
// this file only wires it to @ubgo/auth-react, the call and navigation.

export {
  FORGOT_PASSWORD_FORM_TEXT,
  ForgotPasswordFormView,
  type ForgotPasswordField,
  type ForgotPasswordFormSlot,
  type ForgotPasswordFormText,
  type ForgotPasswordFormValues,
  type ForgotPasswordFormViewProps,
} from "@/components/auth/forgot-password-form-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    forgotPasswordForm: ForgotPasswordFormText
  }
}

/** What was asked for, handed to onSuccess. The server never says whether the account exists. */
export type ForgotPasswordSuccess = {
  readonly identifier: string
}

export type ForgotPasswordFormProps = AuthComponentProps<ForgotPasswordFormSlot, "forgotPasswordForm", ForgotPasswordSuccess> & {
  /**
   * The page the reset link opens, when it is not the server's default
   * (/reset-password on the app's base URL). The server accepts only a page
   * it trusts and answers password.redirect_invalid otherwise.
   */
  readonly resetPageURL?: string
  /** A starting value for the field, such as the address typed on the sign-in page. */
  readonly defaultIdentifier?: string
  /** Show the "Back to sign in" footer. On by default. */
  readonly showSignIn?: boolean
  /** Focus the field on mount, for a page whose only job is this. */
  readonly autoFocus?: boolean
}

/** Error codes that belong under the field rather than above the form. */
const FIELD_ERRORS: ReadonlySet<string> = new Set(["auth.identifier_invalid"])

export function ForgotPasswordForm({
  className,
  classNames,
  localization,
  onSuccess,
  redirectTo: requestedRedirectTo,
  headingLevel = 1,
  resetPageURL,
  defaultIdentifier = "",
  showSignIn = true,
  autoFocus = false,
}: ForgotPasswordFormProps) {
  const t = useLocalization("forgotPasswordForm", FORGOT_PASSWORD_FORM_TEXT, localization)
  const messageFor = useErrorMessage()
  const { navigate, paths, Link } = useAuth()
  // redirectTo usually comes from the address bar: anything but a path on
  // this site (or an origin the provider allows) is dropped, so the default
  // applies and a crafted link cannot send the user to another site.
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const password = usePluginClient("password")
  const username = usePluginClient("username")

  const [formError, setFormError] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<ForgotPasswordField, string>>>({})
  const [sentTo, setSentTo] = useState<string | null>(null)

  const forgot = useMutation({
    mutationFn: async (identifier: string) => {
      if (password === null) throw new Error("ForgotPasswordForm: password plugin missing")
      return password.forgot({ identifier, ...(resetPageURL === undefined ? {} : { redirectTo: resetPageURL }) })
    },
    onSuccess: ({ error }, identifier) => {
      if (error !== null) {
        if (FIELD_ERRORS.has(error.code)) setFieldErrors({ identifier: messageFor(error) })
        else setFormError(messageFor(error))
        return
      }
      if (onSuccess !== undefined) onSuccess({ identifier })
      else if (redirectTo !== undefined) navigate(redirectTo)
      else setSentTo(identifier)
    },
  })

  // Without the password plugin there is no password to reset.
  if (password === null) return null

  return (
    <ForgotPasswordFormView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      acceptsUsername={username !== null}
      defaultIdentifier={defaultIdentifier}
      autoFocus={autoFocus}
      pending={forgot.isPending}
      formError={formError}
      fieldErrors={fieldErrors}
      sentTo={sentTo}
      signInHref={showSignIn ? paths.signIn : undefined}
      Link={Link}
      onSubmit={async ({ identifier }) => {
        setFormError(null)
        setFieldErrors({})
        await forgot.mutateAsync(identifier)
      }}
      onSendAgain={() => {
        if (sentTo === null) return
        setFormError(null)
        forgot.mutate(sentTo)
      }}
      onUseDifferentEmail={() => {
        setSentTo(null)
        setFormError(null)
        forgot.reset()
      }}
    />
  )
}
