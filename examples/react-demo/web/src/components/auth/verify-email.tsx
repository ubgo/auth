import { revalidateLogic, useForm } from "@tanstack/react-form"
import { useMutation, useQuery } from "@tanstack/react-query"
import type { AuthError } from "@ubgo/auth-client"
import {
  AUTH_QUERY_ROOT,
  format,
  useAuth,
  useErrorMessage,
  useLocalization,
  usePluginClient,
  useSafeRedirect,
  useSession,
  useSessionActions,
  type AuthComponentProps,
} from "@ubgo/auth-react"
import { CircleAlertIcon, CircleCheckIcon, LinkIcon, MailIcon } from "lucide-react"
import { useId, useRef, useState } from "react"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// VerifyEmail: the page the verification link opens. It reads the token from
// the address bar (?token=) and posts it once; a link is never spent by a GET,
// so mail scanners that preview links cannot use it up. The answer decides
// the card: verified (and, when the server signs people in on verify, a
// refreshed session), or expired, which offers to mail a new link. Opened
// without a token, the card is just the "send me a new link" form.

/** Every string VerifyEmail shows, with `{name}` placeholders where a value is filled in. */
export type VerifyEmailText = {
  verifyingTitle: string
  verifyingDescription: string
  successTitle: string
  /** `{email}` is the verified address. */
  successDescription: string
  continue: string
  signIn: string
  invalidTitle: string
  invalidDescription: string
  /** The card opened without a token. */
  resendTitle: string
  resendDescription: string
  emailLabel: string
  emailPlaceholder: string
  emailRequired: string
  resend: string
  resending: string
  resentTitle: string
  /** `{email}` is the address typed. */
  resentDescription: string
  retry: string
  backToSignIn: string
}

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    verifyEmail: VerifyEmailText
  }
}

/** The English defaults. Override per app (AuthProvider localization.verifyEmail) or per use (localization prop). */
export const VERIFY_EMAIL_TEXT: VerifyEmailText = {
  verifyingTitle: "Verifying your email",
  verifyingDescription: "One moment…",
  successTitle: "Email verified",
  successDescription: "{email} is verified. Thank you.",
  continue: "Continue",
  signIn: "Sign in",
  invalidTitle: "This link has expired",
  invalidDescription: "Verification links work once and expire after a while. Enter your email and we will send a new one.",
  resendTitle: "Verify your email",
  resendDescription: "Enter your email and we will send you a new verification link.",
  emailLabel: "Email",
  emailPlaceholder: "you@example.com",
  emailRequired: "Enter your email.",
  resend: "Send a new link",
  resending: "Sending…",
  resentTitle: "Check your email",
  resentDescription: "If {email} is waiting to be verified, a new link is on its way.",
  retry: "Try again",
  backToSignIn: "Back to sign in",
}

/** The named parts classNames can style. */
export type VerifyEmailSlot =
  | "root"
  | "header"
  | "title"
  | "description"
  | "content"
  | "form"
  | "field"
  | "label"
  | "input"
  | "fieldError"
  | "formError"
  | "submit"
  | "action"
  | "footer"
  | "link"

/** The verified address, and whether the server signed the user in with it. Handed to onSuccess. */
export type VerifyEmailSuccess = {
  readonly email: string
  readonly signedIn: boolean
}

export type VerifyEmailProps = AuthComponentProps<VerifyEmailSlot, "verifyEmail", VerifyEmailSuccess> & {
  /** The token from the verification link. Left out, it is read from the page's address (?token=). */
  readonly token?: string
  /**
   * Called when verifying signed the user in and the session needs a second
   * factor. Left out, the page navigates to paths.twoFactor.
   */
  readonly onSecondFactor?: () => void
  /** Show the "Back to sign in" footer on the resend form. On by default. */
  readonly showSignIn?: boolean
}

/** The `token` query parameter of the page's address, or "" during server rendering or when it is absent. */
function tokenFromLocation(): string {
  if (typeof window === "undefined") return ""
  return new URLSearchParams(window.location.search).get("token") ?? ""
}

/** Appends `redirectTo` to a path, so the next step can finish where this one was headed. */
function withRedirect(path: string, redirectTo: string | undefined): string {
  if (redirectTo === undefined) return path
  const joiner = path.includes("?") ? "&" : "?"
  return `${path}${joiner}redirectTo=${encodeURIComponent(redirectTo)}`
}

/** What the one verify call came to. */
type VerifyOutcome = { readonly ok: true; readonly email: string; readonly signedIn: boolean } | { readonly ok: false; readonly error: AuthError }

export function VerifyEmail({
  className,
  classNames,
  localization,
  onSuccess,
  redirectTo: requestedRedirectTo,
  headingLevel = 1,
  token: tokenProp,
  onSecondFactor,
  showSignIn = true,
}: VerifyEmailProps) {
  const t = useLocalization("verifyEmail", VERIFY_EMAIL_TEXT, localization)
  const messageFor = useErrorMessage()
  const { navigate, paths, Link } = useAuth()
  // redirectTo usually comes from the address bar: anything but a path on
  // this site (or an origin the provider allows) is dropped, so the default
  // applies and a crafted link cannot send the user to another site.
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const { refreshSession } = useSessionActions()
  // Verifying in the browser that just signed up finds a session already there.
  const { user } = useSession()
  const email = usePluginClient("email")
  const formId = useId()
  const formRef = useRef<HTMLFormElement>(null)
  const [token] = useState(() => tokenProp ?? tokenFromLocation())
  const [resentTo, setResentTo] = useState<string | null>(null)
  const [resendError, setResendError] = useState<string | null>(null)

  // The token is spent by exactly one POST. A query (not an effect) keyed on
  // the token gives that for free: React's double mount in development, a
  // re-render and a remount all share the one cached answer, and nothing
  // refetches it on focus or reconnect.
  const verify = useQuery({
    queryKey: [...AUTH_QUERY_ROOT, "email-verify", token],
    enabled: email !== null && token !== "",
    staleTime: Infinity,
    gcTime: Infinity,
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    queryFn: async (): Promise<VerifyOutcome> => {
      if (email === null) throw new Error("VerifyEmail: email plugin missing")
      const { data, error } = await email.verify({ token })
      if (error !== null) return { ok: false, error }
      const signedIn = data.signedIn === true
      if (signedIn) await refreshSession()
      const result: VerifyEmailSuccess = { email: data.email, signedIn }
      if (data.secondFactorRequired === true) {
        if (onSecondFactor === undefined) navigate(withRedirect(paths.twoFactor, redirectTo))
        else onSecondFactor()
      } else if (onSuccess !== undefined) onSuccess(result)
      else if (redirectTo !== undefined && signedIn) navigate(redirectTo)
      return { ok: true, email: data.email, signedIn }
    },
  })

  const resend = useMutation({
    mutationFn: async (address: string) => {
      if (email === null) throw new Error("VerifyEmail: email plugin missing")
      return email.resend({ email: address })
    },
    onSuccess: ({ error }, address) => {
      if (error !== null) setResendError(messageFor(error))
      else setResentTo(address)
    },
  })

  const form = useForm({
    defaultValues: { email: "" },
    // Check on submit, then re-check each field as it is edited: an error
    // stays until it is fixed, and never appears while a field is first typed.
    validationLogic: revalidateLogic(),
    onSubmit: async ({ value }) => {
      setResendError(null)
      await resend.mutateAsync(value.email.trim())
    },
    onSubmitInvalid: () => {
      formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
    },
  })

  if (email === null) return null

  const root = cn("w-full max-w-sm", className, classNames?.root)
  const outcome = verify.data
  const actionClass = cn(buttonVariants({ size: "lg" }), "w-full", classNames?.action)

  // Waiting for the one call.
  if (token !== "" && outcome === undefined && verify.error === null) {
    return (
      <Card className={root} aria-busy>
        <CardHeader className={classNames?.header}>
          <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
            <Spinner aria-hidden className="text-muted-foreground" />
            {t.verifyingTitle}
          </CardTitle>
          <CardDescription className={cn("wrap-anywhere", classNames?.description)} role="status">
            {t.verifyingDescription}
          </CardDescription>
        </CardHeader>
      </Card>
    )
  }

  if (outcome?.ok === true) {
    const signedIn = outcome.signedIn || user !== null
    return (
      <Card className={root}>
        <CardHeader className={classNames?.header}>
          <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
            <CircleCheckIcon aria-hidden className="size-4 text-muted-foreground" />
            {t.successTitle}
          </CardTitle>
          <CardDescription className={cn("wrap-anywhere", classNames?.description)} role="status">
            {format(t.successDescription, { email: outcome.email })}
          </CardDescription>
        </CardHeader>
        <CardContent className={classNames?.content}>
          <Link href={signedIn ? (redirectTo ?? paths.afterSignIn) : withRedirect(paths.signIn, redirectTo)} className={actionClass}>
            {signedIn ? t.continue : t.signIn}
          </Link>
        </CardContent>
      </Card>
    )
  }

  // An answer other than an expired link (the network, a server fault) can be retried: the token was not spent.
  const failure = outcome?.ok === false ? outcome.error : null
  if (verify.error !== null || (failure !== null && failure.code !== "auth.token_invalid")) {
    return (
      <Card className={root}>
        <CardHeader className={classNames?.header}>
          <CardTitle className={classNames?.title} role="heading" aria-level={headingLevel}>
            {t.verifyingTitle}
          </CardTitle>
        </CardHeader>
        <CardContent className={cn("flex flex-col gap-3.5", classNames?.content)}>
          {failure !== null && (
            <Alert variant="destructive" className={classNames?.formError}>
              <CircleAlertIcon aria-hidden />
              <AlertDescription>{messageFor(failure)}</AlertDescription>
            </Alert>
          )}
          <Button type="button" size="lg" className={cn("w-full", classNames?.action)} disabled={verify.isFetching} onClick={() => void verify.refetch()}>
            {verify.isFetching && <Spinner data-icon="inline-start" />}
            {t.retry}
          </Button>
        </CardContent>
      </Card>
    )
  }

  const footer = showSignIn && (
    <CardFooter className={cn("justify-center text-[13px]", classNames?.footer)}>
      <Link
        href={paths.signIn}
        className={cn("text-muted-foreground underline-offset-4 hover:text-foreground hover:underline focus-visible:underline focus-visible:outline-none", classNames?.link)}
      >
        {t.backToSignIn}
      </Link>
    </CardFooter>
  )

  if (resentTo !== null) {
    return (
      <Card className={root}>
        <CardHeader className={classNames?.header}>
          <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
            <MailIcon aria-hidden className="size-4 text-muted-foreground" />
            {t.resentTitle}
          </CardTitle>
          <CardDescription className={cn("wrap-anywhere", classNames?.description)} role="status">
            {format(t.resentDescription, { email: resentTo })}
          </CardDescription>
        </CardHeader>
        {footer}
      </Card>
    )
  }

  // No token, or an expired one: the resend form.
  const expired = failure !== null
  const busy = resend.isPending
  return (
    <Card className={root}>
      <CardHeader className={classNames?.header}>
        <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
          {expired && <LinkIcon aria-hidden className="size-4 text-muted-foreground" />}
          {expired ? t.invalidTitle : t.resendTitle}
        </CardTitle>
        <CardDescription className={classNames?.description}>{expired ? t.invalidDescription : t.resendDescription}</CardDescription>
      </CardHeader>
      <CardContent className={cn("flex flex-col gap-3.5", classNames?.content)}>
        {resendError !== null && (
          <Alert variant="destructive" className={classNames?.formError}>
            <CircleAlertIcon aria-hidden />
            <AlertDescription>{resendError}</AlertDescription>
          </Alert>
        )}
        <form
          ref={formRef}
          id={formId}
          noValidate
          className={classNames?.form}
          onSubmit={(e) => {
            e.preventDefault()
            e.stopPropagation()
            void form.handleSubmit()
          }}
        >
          <FieldGroup>
            <form.Field name="email" validators={{ onDynamic: ({ value }) => (value.trim() === "" ? t.emailRequired : undefined) }}>
              {(field) => {
                const message = field.state.meta.errors[0]
                const invalid = message !== undefined
                return (
                  <Field data-invalid={invalid} className={classNames?.field}>
                    <FieldLabel htmlFor={`${formId}-email`} className={classNames?.label}>
                      {t.emailLabel}
                    </FieldLabel>
                    <Input
                      id={`${formId}-email`}
                      name="email"
                      type="email"
                      inputMode="email"
                      autoComplete="email"
                      autoCapitalize="none"
                      spellCheck={false}
                      required
                      placeholder={t.emailPlaceholder}
                      value={field.state.value}
                      onChange={(e) => field.handleChange(e.target.value)}
                      onBlur={field.handleBlur}
                      aria-invalid={invalid}
                      aria-describedby={invalid ? `${formId}-email-error` : undefined}
                      className={classNames?.input}
                    />
                    {invalid && (
                      <FieldError id={`${formId}-email-error`} className={classNames?.fieldError}>
                        {message}
                      </FieldError>
                    )}
                  </Field>
                )
              }}
            </form.Field>
            <Button type="submit" size="lg" className={cn("w-full", classNames?.submit)} disabled={busy} aria-busy={busy}>
              {busy && <Spinner data-icon="inline-start" />}
              {busy ? t.resending : t.resend}
            </Button>
          </FieldGroup>
        </form>
      </CardContent>
      {footer}
    </Card>
  )
}
