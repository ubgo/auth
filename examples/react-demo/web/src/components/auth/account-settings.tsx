import { useForm } from "@tanstack/react-form"
import { useMutation, useQuery } from "@tanstack/react-query"
import { isAuthErrorCode, type AuthError, type AuthReauthentication, type AuthSessionResult, type AuthSessionView, type AuthUserView, type OauthAccount } from "@ubgo/auth-client"
import {
  AUTH_QUERY_ROOT,
  SESSION_QUERY_KEY,
  format,
  getPasskeyCredential,
  oauthStartURL,
  supportsPasskeys,
  useAuth,
  useErrorMessage,
  useLocalization,
  useOAuthProviders,
  usePluginClient,
  useSafeRedirect,
  useSession,
  useSessionActions,
  type AuthComponentProps,
  type HeadingLevel,
  type SlotClassNames,
} from "@ubgo/auth-react"
import {
  CheckIcon,
  CircleAlertIcon,
  KeyRoundIcon,
  LinkIcon,
  MailCheckIcon,
  MonitorIcon,
  ShieldAlertIcon,
  SmartphoneIcon,
  UploadIcon,
} from "lucide-react"
import { Fragment, useEffect, useId, useRef, useState, type ReactNode } from "react"

import { PasskeyList } from "@/components/auth/passkey-list"
import { TwoFactorSetup } from "@/components/auth/two-factor-setup"
import { EMAIL_LIST_QUERY_KEY, UserAvatar, usePrimaryEmail } from "@/components/auth/user-button"
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
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldContent, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

// AccountSettings: the signed-in user's account page, made of sections that
// are also exported on their own (ProfileSection, EmailSection,
// PasswordSection, SessionsSection, LinkedAccountsSection, SecuritySection,
// DeleteAccountSection). Each section renders only when the client has its
// plugin. Operations that need a recent sign-in (change the password, the
// email, unlink, delete) ask for the password or a passkey in a dialog when
// the server answers auth.fresh_session_required, then retry by themselves.

/** Every string the account sections show, with `{name}` placeholders where a value is filled in. */
export type AccountSettingsText = {
  /** A BCP 47 tag for dates and relative times; "" uses the browser's language. */
  locale: string
  title: string
  description: string

  profileTitle: string
  profileDescription: string
  nameLabel: string
  namePlaceholder: string
  nameTooLong: string
  imageLabel: string
  imageDescription: string
  imagePlaceholder: string
  imageInvalid: string
  imageUpload: string
  imageUploading: string
  save: string
  saving: string
  saved: string

  emailTitle: string
  emailDescription: string
  emailVerified: string
  emailUnverified: string
  emailPrimary: string
  emailResend: string
  emailResending: string
  /** `{email}` is the address the verification link went to. */
  emailResent: string
  newEmailLabel: string
  newEmailPlaceholder: string
  newEmailRequired: string
  newEmailSame: string
  emailChange: string
  emailChanging: string
  emailChangeSentTitle: string
  /** `{email}` is the new address. */
  emailChangeSentLink: string
  /** `{email}` is the new address. */
  emailChangeSentCode: string
  emailCodeLabel: string
  emailCodeRequired: string
  emailConfirm: string
  emailConfirming: string
  /** `{email}` is the new address. */
  emailChanged: string
  emailUseDifferent: string
  emailNone: string

  passwordTitle: string
  passwordDescription: string
  currentPasswordLabel: string
  currentPasswordRequired: string
  newPasswordLabel: string
  newPasswordRequired: string
  newPasswordSame: string
  confirmPasswordLabel: string
  confirmPasswordMismatch: string
  revokeOthersLabel: string
  revokeOthersHint: string
  passwordChange: string
  passwordChanging: string
  passwordChanged: string

  sessionsTitle: string
  sessionsDescription: string
  thisDevice: string
  impersonated: string
  activeNow: string
  /** `{time}` is a relative time ("5 minutes ago"). */
  lastActive: string
  /** `{browser}` and `{os}` are names from the user agent. */
  deviceName: string
  unknownDevice: string
  unknownIP: string
  revoke: string
  revoking: string
  revokeOthers: string
  revokeTitle: string
  /** `{device}` is the session's device name. */
  revokeDescription: string
  revokeOthersTitle: string
  /** `{count}` is how many sessions end. */
  revokeOthersDescription: string
  noOtherSessions: string

  linkedTitle: string
  linkedDescription: string
  link: string
  linking: string
  unlink: string
  unlinking: string
  /** `{date}` is when the account was linked. */
  linkedOn: string
  notLinked: string
  unlinkTitle: string
  /** `{provider}` is the provider's name, `{email}` the linked account's address. */
  unlinkDescription: string

  deleteTitle: string
  deleteDescription: string
  deleteButton: string
  deleteDialogTitle: string
  deleteDialogDescription: string
  /** `{word}` is deleteConfirmWord. */
  deleteConfirmLabel: string
  deleteConfirmWord: string
  deleteConfirm: string
  deleting: string
  deleteLinkSentTitle: string
  deleteLinkSentDescription: string
  deleteOff: string

  cancel: string
  retry: string
  loadFailed: string

  reauthTitle: string
  reauthDescription: string
  reauthPasswordLabel: string
  reauthPasswordRequired: string
  reauthConfirm: string
  reauthConfirming: string
  reauthPasskey: string
  reauthPasskeyPending: string
  reauthPasskeyCancelled: string
  reauthSignInAgain: string
  reauthSignInDescription: string
  /** Asked when the account has two-factor on, after the password or passkey. */
  reauthCodeDescription: string
  /** The code step when the account's factor is a mailed or texted code, just sent. */
  reauthCodeSentDescription: string
  reauthCodeLabel: string
  reauthCodeRequired: string
  /** The description when the user can also confirm with a linked provider account. */
  reauthProviderDescription: string
  /** The description when a linked provider account is the only way to confirm here. */
  reauthProviderOnlyDescription: string
  /** A linked provider's button; {provider} is its display name. */
  reauthProvider: string
  /** The same button while the browser leaves for the provider. */
  reauthProviderPending: string
  /** Shown on the page after a provider confirmed it is you: the refused change can be made now. */
  reauthConfirmed: string
}

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    accountSettings: AccountSettingsText
  }
}

/** The English defaults. Override per app (AuthProvider localization.accountSettings) or per use (localization prop). */
export const ACCOUNT_SETTINGS_TEXT: AccountSettingsText = {
  locale: "",
  title: "Account",
  description: "Your profile, how you sign in, and where you are signed in.",

  profileTitle: "Profile",
  profileDescription: "How you appear to others.",
  nameLabel: "Name",
  namePlaceholder: "Ada Lovelace",
  nameTooLong: "Use 100 characters or fewer.",
  imageLabel: "Picture",
  imageDescription: "A link to an image, square works best.",
  imagePlaceholder: "https://…",
  imageInvalid: "Enter a link that starts with https://.",
  imageUpload: "Upload",
  imageUploading: "Uploading…",
  save: "Save",
  saving: "Saving…",
  saved: "Saved",

  emailTitle: "Email",
  emailDescription: "Where we send sign-in links, receipts and security notices.",
  emailVerified: "Verified",
  emailUnverified: "Unverified",
  emailPrimary: "Primary",
  emailResend: "Resend verification",
  emailResending: "Sending…",
  emailResent: "A verification link is on its way to {email}.",
  newEmailLabel: "New email",
  newEmailPlaceholder: "you@example.com",
  newEmailRequired: "Enter the new address.",
  newEmailSame: "This is already your address.",
  emailChange: "Change email",
  emailChanging: "Sending…",
  emailChangeSentTitle: "Confirm the new address",
  emailChangeSentLink: "We sent a link to {email}. Your address changes when you open it; until then nothing is different.",
  emailChangeSentCode: "We sent a code to {email}. Enter it to finish the change.",
  emailCodeLabel: "Code",
  emailCodeRequired: "Enter the code from the email.",
  emailConfirm: "Confirm",
  emailConfirming: "Confirming…",
  emailChanged: "Your email is now {email}.",
  emailUseDifferent: "Use a different address",
  emailNone: "No email address on this account.",

  passwordTitle: "Password",
  passwordDescription: "Use a long passphrase you do not use anywhere else.",
  currentPasswordLabel: "Current password",
  currentPasswordRequired: "Enter your current password.",
  newPasswordLabel: "New password",
  newPasswordRequired: "Enter a new password.",
  newPasswordSame: "Choose a password different from the current one.",
  confirmPasswordLabel: "Confirm new password",
  confirmPasswordMismatch: "The passwords do not match.",
  revokeOthersLabel: "Sign out of other devices",
  revokeOthersHint: "Everywhere else you are signed in will need the new password.",
  passwordChange: "Change password",
  passwordChanging: "Changing…",
  passwordChanged: "Password changed",

  sessionsTitle: "Sessions",
  sessionsDescription: "Devices signed in to your account. Sign out of any you do not recognise.",
  thisDevice: "This device",
  impersonated: "Support",
  activeNow: "Active now",
  lastActive: "Last active {time}",
  deviceName: "{browser} on {os}",
  unknownDevice: "Unknown device",
  unknownIP: "Unknown location",
  revoke: "Sign out",
  revoking: "Signing out…",
  revokeOthers: "Sign out of all other sessions",
  revokeTitle: "Sign out this session?",
  revokeDescription: "{device} will be signed out at its next request.",
  revokeOthersTitle: "Sign out of other sessions?",
  revokeOthersDescription: "{count} other sessions will be signed out. This device stays signed in.",
  noOtherSessions: "You are signed in only on this device.",

  linkedTitle: "Connected accounts",
  linkedDescription: "Sign in with these providers as well as your other methods.",
  link: "Connect",
  linking: "Redirecting…",
  unlink: "Disconnect",
  unlinking: "Disconnecting…",
  linkedOn: "Connected {date}",
  notLinked: "Not connected",
  unlinkTitle: "Disconnect this account?",
  unlinkDescription: "You will no longer be able to sign in with {provider} ({email}).",

  deleteTitle: "Delete account",
  deleteDescription: "Permanently delete your account and everything in it. This cannot be undone.",
  deleteButton: "Delete account",
  deleteDialogTitle: "Delete your account?",
  deleteDialogDescription: "Your profile, sign-in methods and sessions are deleted for good, and you are signed out everywhere.",
  deleteConfirmLabel: "Type {word} to confirm",
  deleteConfirmWord: "delete",
  deleteConfirm: "Delete my account",
  deleting: "Deleting…",
  deleteLinkSentTitle: "Check your email",
  deleteLinkSentDescription: "We sent a link to confirm the deletion. Your account stays until you open it.",
  deleteOff: "Deleting an account is not available here. Contact support.",

  cancel: "Cancel",
  retry: "Try again",
  loadFailed: "This could not be loaded.",

  reauthTitle: "Confirm it's you",
  reauthDescription: "This change needs a recent sign-in. Enter your password to continue.",
  reauthPasswordLabel: "Password",
  reauthPasswordRequired: "Enter your password.",
  reauthConfirm: "Continue",
  reauthConfirming: "Checking…",
  reauthPasskey: "Use a passkey instead",
  reauthPasskeyPending: "Waiting for your passkey…",
  reauthPasskeyCancelled: "No passkey was used. Try again, or use your password.",
  reauthSignInAgain: "Sign in again",
  reauthSignInDescription: "This change needs a recent sign-in. Sign in again, then come back to finish it.",
  reauthCodeDescription: "Enter the code from your authenticator app, or a recovery code.",
  reauthCodeSentDescription: "We sent you a code. Enter it, or a recovery code.",
  reauthCodeLabel: "Authentication code",
  reauthCodeRequired: "Enter the code.",
  reauthProviderDescription: "This change needs a recent sign-in. Enter your password, or continue with an account you linked.",
  reauthProviderOnlyDescription: "This change needs a recent sign-in. Continue with an account you linked to confirm it's you.",
  reauthProvider: "Continue with {provider}",
  reauthProviderPending: "Opening {provider}…",
  reauthConfirmed: "You confirmed it's you. Make the change again to finish it.",
}

/** The named parts classNames can style. "root" is AccountSettings' wrapper, or a section's card when one is used on its own. */
export type AccountSettingsSlot =
  | "root"
  | "header"
  | "title"
  | "description"
  | "section"
  | "sectionHeader"
  | "sectionTitle"
  | "sectionDescription"
  | "sectionContent"
  | "sectionFooter"
  | "field"
  | "label"
  | "input"
  | "fieldError"
  | "formError"
  | "status"
  | "submit"
  | "list"
  | "row"
  | "rowTitle"
  | "rowMeta"
  | "badge"
  | "action"
  | "dangerAction"
  | "dialog"

/** The sections AccountSettings can show, in its default order. */
export const ACCOUNT_SECTIONS = ["profile", "email", "password", "security", "sessions", "linkedAccounts", "delete"] as const

/** One section's name. */
export type AccountSection = (typeof ACCOUNT_SECTIONS)[number]

/** What changed, handed to a section's onSuccess (and AccountSettings' onSuccess with the section's name). */
export type AccountChange =
  | { readonly section: "profile"; readonly user: AuthUserView }
  | { readonly section: "email"; readonly email: string; readonly pending: boolean }
  | { readonly section: "password"; readonly revokedOthers: boolean }
  | { readonly section: "sessions"; readonly revoked: readonly string[] }
  | { readonly section: "linkedAccounts"; readonly provider: string; readonly linked: false }
  | { readonly section: "delete"; readonly deleted: boolean; readonly confirmationSent: boolean }

/** The props every section takes: the shared contract, with its own success shape. */
export type AccountSectionProps<C extends AccountChange["section"]> = AuthComponentProps<
  AccountSettingsSlot,
  "accountSettings",
  Extract<AccountChange, { section: C }>
>

/** The code the server answers when an operation needs a more recent sign-in. */
const FRESH_SESSION_REQUIRED = "auth.fresh_session_required"

/**
 * A section's heading level when used on its own: a section sits under a
 * page's h1, so h2. AccountSettings sets it to one below its own heading.
 */
const SECTION_HEADING_LEVEL: HeadingLevel = 2

/** One heading level below `level`, never past h6. */
function below(level: HeadingLevel): HeadingLevel {
  return level >= 6 ? 6 : ((level + 1) as HeadingLevel)
}

/** The longest name the profile form accepts before asking; the server keeps its own limit. */
const MAX_NAME_LENGTH = 100

/** How long a list read here counts as fresh: a settings page is looked at, not polled. */
const LIST_STALE_MS = 30_000

/** The query keys of the lists the sections read, under the package's root so signOut clears them. */
export const SESSIONS_QUERY_KEY = [...AUTH_QUERY_ROOT, "sessions"] as const
export const OAUTH_ACCOUNTS_QUERY_KEY = [...AUTH_QUERY_ROOT, "oauth-accounts"] as const

/**
 * The query the oauth plugin adds to the page it returns to after a
 * re-authentication with a provider (oauth.ParamReauth, oauth.ParamReauthTicket
 * in plugin/oauth): "fresh", or "second_factor" with the ticket the code step
 * takes. REAUTH_FAILED is this kit's own marker on the errorTo address, so a
 * refused callback, which adds ?error=<code>, is told apart from a failed link flow.
 */
const REAUTH_PARAM = "reauth"
const REAUTH_TICKET_PARAM = "reauthTicket"
const REAUTH_ERROR_PARAM = "error"
const REAUTH_FRESH = "fresh"
const REAUTH_SECOND_FACTOR = "second_factor"
const REAUTH_FAILED = "failed"

export type AccountSettingsProps = AuthComponentProps<AccountSettingsSlot, "accountSettings", AccountChange> & {
  /** Which sections to show, in this order. Every section also hides itself when its plugin is off. */
  readonly sections?: readonly AccountSection[]
  /** Hide the page heading, for an app that draws its own. */
  readonly hideHeader?: boolean
  /** Passed to EmailSection: how the server confirms a new address (email.VerifyByCode means "code"). */
  readonly confirmEmailChangeBy?: "link" | "code"
  /** Passed to ProfileSection: uploads a picture and resolves to its URL, which shows an Upload button. */
  readonly onUploadImage?: (file: File) => Promise<string>
  /** Extra sections of the app's own, rendered before "Delete account". */
  readonly children?: ReactNode
}

/** Drops "root" from the slots handed to sections, so the page's root class does not land on every card. */
function sectionSlots(classNames: SlotClassNames<AccountSettingsSlot> | undefined): SlotClassNames<AccountSettingsSlot> | undefined {
  if (classNames === undefined) return undefined
  const { root: _root, ...rest } = classNames
  return rest
}

export function AccountSettings({
  className,
  classNames,
  localization,
  onSuccess,
  redirectTo,
  sections = ACCOUNT_SECTIONS,
  hideHeader = false,
  headingLevel = 1,
  confirmEmailChangeBy,
  onUploadImage,
  children,
}: AccountSettingsProps) {
  const t = useLocalization("accountSettings", ACCOUNT_SETTINGS_TEXT, localization)
  const { user, isPending } = useSession()
  const messageFor = useErrorMessage()
  const slots = sectionSlots(classNames)
  // Back from a provider re-authentication the dialog started (the page reloaded, so the
  // refused action's closure is gone): say so, or finish the code step it still needs.
  const [returned, dismissReturn] = useReauthReturn()
  const [confirmed, setConfirmed] = useState(false)
  // Sections sit one level under the page heading, or at its level when it is hidden.
  const sectionLevel = hideHeader ? headingLevel : below(headingLevel)
  const shared = { classNames: slots, localization, onSuccess, headingLevel: sectionLevel }

  const rendered = sections.map((name) => {
    switch (name) {
      case "profile":
        return <ProfileSection key={name} {...shared} onUploadImage={onUploadImage} />
      case "email":
        return <EmailSection key={name} {...shared} confirmChangeBy={confirmEmailChangeBy} />
      case "password":
        return <PasswordSection key={name} {...shared} />
      case "security":
        return <SecuritySection key={name} localization={localization} classNames={slots} headingLevel={sectionLevel} twoFactorClassName={slots?.section} passkeysClassName={slots?.section} />
      case "sessions":
        return <SessionsSection key={name} {...shared} />
      case "linkedAccounts":
        return <LinkedAccountsSection key={name} {...shared} />
      case "delete":
        return (
          <Fragment key={name}>
            {children}
            <DeleteAccountSection {...shared} redirectTo={redirectTo} />
          </Fragment>
        )
    }
  })

  return (
    <div className={cn("flex w-full max-w-2xl flex-col gap-4", className, classNames?.root)}>
      {!hideHeader && (
        <div className={cn("flex flex-col gap-0.5 pb-1", classNames?.header)}>
          <div role="heading" aria-level={headingLevel} className={cn("font-heading text-lg font-semibold tracking-tight", classNames?.title)}>
            {t.title}
          </div>
          <p className={cn("text-[13px] text-muted-foreground", classNames?.description)}>{t.description}</p>
        </div>
      )}
      {(confirmed || returned?.status === "fresh") && <StatusAlert message={t.reauthConfirmed} className={classNames?.status} />}
      {returned?.status === "failed" && <FormErrorAlert message={messageFor({ code: returned.code, rawCode: returned.code, message: "", status: 0 })} className={classNames?.formError} />}
      {returned?.status === "second_factor" && user !== null && (
        <ReauthDialog
          t={t}
          classNames={slots}
          open
          ticket={returned.ticket}
          onOpenChange={(open) => !open && dismissReturn()}
          onDone={() => {
            dismissReturn()
            setConfirmed(true)
          }}
        />
      )}
      {isPending ? <SectionSkeleton /> : user === null ? null : rendered}
      {!sections.includes("delete") && children}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Profile

export type ProfileSectionProps = AccountSectionProps<"profile"> & {
  /** Uploads a picture and resolves to its URL. Given, the picture field gets an Upload button. */
  readonly onUploadImage?: (file: File) => Promise<string>
}

/** Name and picture, saved with the core's profile call. */
export function ProfileSection({ className, classNames, localization, onSuccess, onUploadImage, headingLevel = SECTION_HEADING_LEVEL }: ProfileSectionProps) {
  const t = useLocalization("accountSettings", ACCOUNT_SETTINGS_TEXT, localization)
  const { user } = useSession()
  const { email } = usePrimaryEmail()
  if (user === null) return null
  // Keyed by user, so the form's starting values follow an account switch.
  return (
    <ProfileForm
      key={user.id}
      user={user}
      email={email}
      t={t}
      className={className}
      classNames={classNames}
      onSuccess={onSuccess}
      onUploadImage={onUploadImage}
      headingLevel={headingLevel}
    />
  )
}

function ProfileForm({
  user,
  email,
  t,
  className,
  classNames,
  onSuccess,
  onUploadImage,
  headingLevel = SECTION_HEADING_LEVEL,
}: Omit<ProfileSectionProps, "localization"> & { user: AuthUserView; email: string | null; t: AccountSettingsText }) {
  const { client, queryClient } = useAuth()
  const messageFor = useErrorMessage()
  const id = useId()
  const formRef = useRef<HTMLFormElement>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  const save = useMutation({
    mutationFn: (value: { name: string; image: string }) => client.profile({ name: value.name.trim(), image: value.image.trim() }),
    onSuccess: ({ data, error }) => {
      if (error !== null) {
        setFormError(messageFor(error))
        return
      }
      // The answer is the new user view: put it in the session entry so the
      // header's avatar changes without another read.
      queryClient.setQueryData<AuthSessionResult | null>(SESSION_QUERY_KEY, (old) => (old == null ? old : { ...old, user: data }))
      form.reset({ name: data.name, image: data.image })
      setSaved(true)
      onSuccess?.({ section: "profile", user: data })
    },
  })

  const upload = useMutation({
    mutationFn: async (file: File) => {
      if (onUploadImage === undefined) throw new Error("ProfileSection: onUploadImage missing")
      return onUploadImage(file)
    },
    onSuccess: (url) => form.setFieldValue("image", url),
    onError: (error) => setFormError(error instanceof Error ? error.message : String(error)),
  })

  const form = useForm({
    defaultValues: { name: user.name, image: user.image },
    onSubmit: async ({ value }) => {
      setFormError(null)
      setSaved(false)
      await save.mutateAsync(value)
    },
    onSubmitInvalid: () => formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus(),
  })

  return (
    <SettingsCard
      level={headingLevel}
      title={t.profileTitle}
      description={t.profileDescription}
      className={className}
      classNames={classNames}
      footer={
        <form.Subscribe selector={(s) => s.values.name !== user.name || s.values.image !== user.image}>
          {(dirty) => (
            <>
              <SavedStatus show={saved && !dirty} label={t.saved} className={classNames?.status} />
              <Button
                type="submit"
                form={id}
                className={cn("ml-auto", classNames?.submit)}
                disabled={!dirty || save.isPending || upload.isPending}
                aria-busy={save.isPending}
              >
                {save.isPending && <Spinner data-icon="inline-start" />}
                {save.isPending ? t.saving : t.save}
              </Button>
            </>
          )}
        </form.Subscribe>
      }
    >
      <form
        ref={formRef}
        id={id}
        noValidate
        onSubmit={(e) => {
          e.preventDefault()
          e.stopPropagation()
          void form.handleSubmit()
        }}
        onChange={() => setSaved(false)}
      >
        <FieldGroup className="gap-4">
          <FormErrorAlert message={formError} className={classNames?.formError} />
          <form.Field
            name="name"
            validators={{ onSubmit: ({ value }) => (value.trim().length > MAX_NAME_LENGTH ? t.nameTooLong : undefined) }}
          >
            {(field) => (
              <TextField
                id={`${id}-name`}
                label={t.nameLabel}
                value={field.state.value}
                onChange={field.handleChange}
                onBlur={field.handleBlur}
                error={field.state.meta.errors[0]}
                autoComplete="name"
                placeholder={t.namePlaceholder}
                classNames={classNames}
              />
            )}
          </form.Field>
          <form.Field
            name="image"
            validators={{ onSubmit: ({ value }) => (value.trim() === "" || /^https?:\/\//i.test(value.trim()) ? undefined : t.imageInvalid) }}
          >
            {(field) => {
              const message = field.state.meta.errors[0]
              const invalid = message !== undefined
              return (
                <Field data-invalid={invalid} className={classNames?.field}>
                  <FieldLabel htmlFor={`${id}-image`} className={classNames?.label}>
                    {t.imageLabel}
                  </FieldLabel>
                  <div className="flex items-center gap-2.5">
                    <UserAvatar user={{ ...user, name: user.name, image: field.state.value.trim() }} email={email} size="lg" />
                    <Input
                      id={`${id}-image`}
                      type="url"
                      inputMode="url"
                      autoComplete="photo"
                      spellCheck={false}
                      placeholder={t.imagePlaceholder}
                      value={field.state.value}
                      onChange={(e) => field.handleChange(e.target.value)}
                      onBlur={field.handleBlur}
                      aria-invalid={invalid}
                      aria-describedby={invalid ? `${id}-image-error` : `${id}-image-help`}
                      className={cn("min-w-0 flex-1", classNames?.input)}
                    />
                    {onUploadImage !== undefined && (
                      <>
                        <input
                          ref={fileRef}
                          type="file"
                          accept="image/*"
                          className="sr-only"
                          tabIndex={-1}
                          aria-hidden
                          onChange={(e) => {
                            const file = e.target.files?.[0]
                            if (file !== undefined) upload.mutate(file)
                            e.target.value = ""
                          }}
                        />
                        <Button type="button" variant="outline" disabled={upload.isPending} aria-busy={upload.isPending} onClick={() => fileRef.current?.click()}>
                          {upload.isPending ? <Spinner data-icon="inline-start" /> : <UploadIcon data-icon="inline-start" aria-hidden />}
                          {upload.isPending ? t.imageUploading : t.imageUpload}
                        </Button>
                      </>
                    )}
                  </div>
                  {invalid ? (
                    <FieldError id={`${id}-image-error`} className={classNames?.fieldError}>
                      {message}
                    </FieldError>
                  ) : (
                    <FieldDescription id={`${id}-image-help`}>{t.imageDescription}</FieldDescription>
                  )}
                </Field>
              )
            }}
          </form.Field>
        </FieldGroup>
      </form>
    </SettingsCard>
  )
}

// ---------------------------------------------------------------------------
// Email

export type EmailSectionProps = AccountSectionProps<"email"> & {
  /**
   * How the server confirms a new address: a link mailed to it (the default),
   * or a code typed here (the server runs email.VerifyByCode).
   */
  readonly confirmChangeBy?: "link" | "code"
}

/** The primary address with its verification state, and the change-email flow. */
export function EmailSection({ className, classNames, localization, onSuccess, confirmChangeBy = "link", headingLevel = SECTION_HEADING_LEVEL }: EmailSectionProps) {
  const t = useLocalization("accountSettings", ACCOUNT_SETTINGS_TEXT, localization)
  const emailClient = usePluginClient("email")
  const { session } = useSession()
  const { queryClient } = useAuth()
  const messageFor = useErrorMessage()
  const reauth = useReauth(t, classNames)
  const id = useId()
  const formRef = useRef<HTMLFormElement>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [status, setStatus] = useState<string | null>(null)
  const [pendingEmail, setPendingEmail] = useState<string | null>(null)

  const list = useQuery(
    {
      queryKey: EMAIL_LIST_QUERY_KEY,
      queryFn: async () => {
        if (emailClient === null) return []
        const { data, error } = await emailClient.list()
        if (error !== null) throw new AuthCallError(error)
        return data.addresses ?? []
      },
      enabled: emailClient !== null && session !== null,
      staleTime: LIST_STALE_MS,
    },
    queryClient,
  )
  const addresses = list.data ?? []
  const primary = addresses.find((a) => a.primary) ?? addresses[0]

  const resend = useMutation({
    mutationFn: (address: string) => {
      if (emailClient === null) throw new Error("EmailSection: email plugin missing")
      return emailClient.resend({ email: address })
    },
    onSuccess: ({ error }, address) => {
      if (error !== null) setFormError(messageFor(error))
      else setStatus(format(t.emailResent, { email: address }))
    },
  })

  const change = useMutation({
    mutationFn: (address: string) => {
      if (emailClient === null) throw new Error("EmailSection: email plugin missing")
      return emailClient.change({ email: address })
    },
    onSuccess: ({ error }, address) => {
      if (error?.code === FRESH_SESSION_REQUIRED) {
        reauth.request(() => change.mutate(address))
        return
      }
      if (error !== null) {
        setFormError(messageFor(error))
        return
      }
      setPendingEmail(address)
      onSuccess?.({ section: "email", email: address, pending: true })
    },
  })

  const confirm = useMutation({
    mutationFn: (value: { email: string; code: string }) => {
      if (emailClient === null) throw new Error("EmailSection: email plugin missing")
      return emailClient.confirmChangeCode({ email: value.email, code: value.code.trim() })
    },
    onSuccess: async ({ data, error }) => {
      if (error !== null) {
        setFormError(messageFor(error))
        return
      }
      await queryClient.invalidateQueries({ queryKey: EMAIL_LIST_QUERY_KEY })
      setPendingEmail(null)
      setStatus(format(t.emailChanged, { email: data.email }))
      onSuccess?.({ section: "email", email: data.email, pending: false })
    },
  })

  const form = useForm({
    defaultValues: { email: "", code: "" },
    onSubmit: async ({ value }) => {
      setFormError(null)
      setStatus(null)
      if (pendingEmail === null) await change.mutateAsync(value.email.trim())
      else await confirm.mutateAsync({ email: pendingEmail, code: value.code })
    },
    onSubmitInvalid: () => formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus(),
  })

  if (emailClient === null || session === null) return null

  const busy = change.isPending || confirm.isPending
  const codeStep = pendingEmail !== null && confirmChangeBy === "code"

  return (
    <SettingsCard
      level={headingLevel}
      title={t.emailTitle}
      description={t.emailDescription}
      className={className}
      classNames={classNames}
      footer={
        pendingEmail !== null && !codeStep ? (
          <Button
            type="button"
            variant="outline"
            className={cn("ml-auto", classNames?.action)}
            onClick={() => {
              setPendingEmail(null)
              form.reset()
            }}
          >
            {t.emailUseDifferent}
          </Button>
        ) : (
          <>
            {codeStep && (
              <Button type="button" variant="ghost" className={classNames?.action} onClick={() => setPendingEmail(null)}>
                {t.emailUseDifferent}
              </Button>
            )}
            <Button type="submit" form={id} className={cn("ml-auto", classNames?.submit)} disabled={busy} aria-busy={busy}>
              {busy && <Spinner data-icon="inline-start" />}
              {codeStep ? (confirm.isPending ? t.emailConfirming : t.emailConfirm) : change.isPending ? t.emailChanging : t.emailChange}
            </Button>
          </>
        )
      }
    >
      <div className="flex flex-col gap-4">
        <FormErrorAlert message={formError} className={classNames?.formError} />
        {status !== null && <StatusAlert message={status} className={classNames?.status} />}

        {list.isPending ? (
          <Skeleton className="h-9 w-full rounded-lg" />
        ) : list.isError ? (
          <LoadError t={t} onRetry={() => void list.refetch()} />
        ) : primary === undefined ? (
          <p className="text-[13px] text-muted-foreground">{t.emailNone}</p>
        ) : (
          <ul className={cn("flex flex-col divide-y rounded-lg border", classNames?.list)}>
            {addresses.map((a) => (
              <li key={a.email} className={cn("flex flex-wrap items-center gap-x-2 gap-y-1 px-3 py-2", classNames?.row)}>
                <span className={cn("min-w-0 text-[13px] font-medium [overflow-wrap:anywhere]", classNames?.rowTitle)}>{a.email}</span>
                {a.primary && addresses.length > 1 && (
                  <Badge variant="secondary" className={classNames?.badge}>
                    {t.emailPrimary}
                  </Badge>
                )}
                <Badge variant={a.verified ? "secondary" : "outline"} className={cn(!a.verified && "text-amber-700 dark:text-amber-400", classNames?.badge)}>
                  {a.verified && <CheckIcon data-icon="inline-start" aria-hidden />}
                  {a.verified ? t.emailVerified : t.emailUnverified}
                </Badge>
                {!a.verified && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className={cn("ml-auto", classNames?.action)}
                    disabled={resend.isPending}
                    aria-busy={resend.isPending}
                    onClick={() => {
                      setFormError(null)
                      setStatus(null)
                      resend.mutate(a.email)
                    }}
                  >
                    {resend.isPending && <Spinner data-icon="inline-start" />}
                    {resend.isPending ? t.emailResending : t.emailResend}
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}

        {pendingEmail !== null && (
          <Alert className={classNames?.status} role="status">
            <MailCheckIcon aria-hidden />
            <AlertDescription>
              <span className="font-medium text-foreground">{t.emailChangeSentTitle}. </span>
              {format(codeStep ? t.emailChangeSentCode : t.emailChangeSentLink, { email: pendingEmail })}
            </AlertDescription>
          </Alert>
        )}

        {(pendingEmail === null || codeStep) && (
          <form
            ref={formRef}
            id={id}
            noValidate
            onSubmit={(e) => {
              e.preventDefault()
              e.stopPropagation()
              void form.handleSubmit()
            }}
          >
            {codeStep ? (
              <form.Field name="code" validators={{ onSubmit: ({ value }) => (value.trim() === "" ? t.emailCodeRequired : undefined) }}>
                {(field) => (
                  <TextField
                    id={`${id}-code`}
                    label={t.emailCodeLabel}
                    value={field.state.value}
                    onChange={field.handleChange}
                    onBlur={field.handleBlur}
                    error={field.state.meta.errors[0]}
                    autoComplete="one-time-code"
                    inputMode="numeric"
                    autoFocus
                    classNames={classNames}
                  />
                )}
              </form.Field>
            ) : (
              <form.Field
                name="email"
                validators={{
                  onSubmit: ({ value }) =>
                    value.trim() === ""
                      ? t.newEmailRequired
                      : addresses.some((a) => a.email.toLowerCase() === value.trim().toLowerCase())
                        ? t.newEmailSame
                        : undefined,
                }}
              >
                {(field) => (
                  <TextField
                    id={`${id}-email`}
                    label={t.newEmailLabel}
                    type="email"
                    inputMode="email"
                    autoComplete="email"
                    placeholder={t.newEmailPlaceholder}
                    value={field.state.value}
                    onChange={field.handleChange}
                    onBlur={field.handleBlur}
                    error={field.state.meta.errors[0]}
                    classNames={classNames}
                  />
                )}
              </form.Field>
            )}
          </form>
        )}
      </div>
      {reauth.element}
    </SettingsCard>
  )
}

// ---------------------------------------------------------------------------
// Password

export type PasswordSectionProps = AccountSectionProps<"password"> & {
  /** Whether "Sign out of other devices" starts ticked. On by default: a changed password usually means a worry. */
  readonly revokeOthersDefault?: boolean
}

/** The password form's fields; `next` because `new` is the wire name only. */
type PasswordFormValue = { current: string; next: string; confirm: string; revokeOthers: boolean }

/** Error codes that belong under one of the password fields. */
const PASSWORD_FIELD_OF_ERROR: Readonly<Partial<Record<string, "current" | "next">>> = {
  "password.invalid_credentials": "current",
  "password.too_short": "next",
  "password.too_long": "next",
  "password.weak": "next",
  "password.breached": "next",
  "password.reused": "next",
}

/** Change the password, optionally signing out every other session. */
export function PasswordSection({ className, classNames, localization, onSuccess, revokeOthersDefault = true, headingLevel = SECTION_HEADING_LEVEL }: PasswordSectionProps) {
  const t = useLocalization("accountSettings", ACCOUNT_SETTINGS_TEXT, localization)
  const passwordClient = usePluginClient("password")
  const { session } = useSession()
  const { queryClient } = useAuth()
  const messageFor = useErrorMessage()
  const reauth = useReauth(t, classNames)
  const id = useId()
  const formRef = useRef<HTMLFormElement>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<"current" | "next", string>>>({})
  const [saved, setSaved] = useState(false)

  const defaultValues: PasswordFormValue = { current: "", next: "", confirm: "", revokeOthers: revokeOthersDefault }

  const change = useMutation({
    mutationFn: (value: PasswordFormValue) => {
      if (passwordClient === null) throw new Error("PasswordSection: password plugin missing")
      return passwordClient.change({ current: value.current, new: value.next, revokeOtherSessions: value.revokeOthers })
    },
    onSuccess: async ({ error }, value) => {
      if (error?.code === FRESH_SESSION_REQUIRED) {
        reauth.request(() => change.mutate(value))
        return
      }
      if (error !== null) {
        const field = PASSWORD_FIELD_OF_ERROR[error.code]
        if (field === undefined) setFormError(messageFor(error))
        else setFieldErrors({ [field]: messageFor(error) })
        formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
        return
      }
      form.reset()
      setSaved(true)
      await queryClient.invalidateQueries({ queryKey: SESSIONS_QUERY_KEY })
      onSuccess?.({ section: "password", revokedOthers: value.revokeOthers })
    },
  })

  const form = useForm({
    defaultValues,
    onSubmit: async ({ value }) => {
      setFormError(null)
      setFieldErrors({})
      setSaved(false)
      await change.mutateAsync(value)
    },
    onSubmitInvalid: () => formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus(),
  })

  if (passwordClient === null || session === null) return null

  return (
    <SettingsCard
      level={headingLevel}
      title={t.passwordTitle}
      description={t.passwordDescription}
      className={className}
      classNames={classNames}
      footer={
        <>
          <SavedStatus show={saved} label={t.passwordChanged} className={classNames?.status} />
          <Button type="submit" form={id} className={cn("ml-auto", classNames?.submit)} disabled={change.isPending} aria-busy={change.isPending}>
            {change.isPending && <Spinner data-icon="inline-start" />}
            {change.isPending ? t.passwordChanging : t.passwordChange}
          </Button>
        </>
      }
    >
      <form
        ref={formRef}
        id={id}
        noValidate
        onSubmit={(e) => {
          e.preventDefault()
          e.stopPropagation()
          void form.handleSubmit()
        }}
        onChange={() => setSaved(false)}
      >
        <FieldGroup className="gap-4">
          <FormErrorAlert message={formError} className={classNames?.formError} />
          <form.Field name="current" validators={{ onSubmit: ({ value }) => (value === "" ? t.currentPasswordRequired : undefined) }}>
            {(field) => (
              <TextField
                id={`${id}-current`}
                label={t.currentPasswordLabel}
                type="password"
                autoComplete="current-password"
                value={field.state.value}
                onChange={field.handleChange}
                onBlur={field.handleBlur}
                error={field.state.meta.errors[0] ?? fieldErrors.current}
                classNames={classNames}
              />
            )}
          </form.Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <form.Field
              name="next"
              validators={{
                onSubmit: ({ value, fieldApi }) =>
                  value === "" ? t.newPasswordRequired : value === fieldApi.form.getFieldValue("current") ? t.newPasswordSame : undefined,
              }}
            >
              {(field) => (
                <TextField
                  id={`${id}-next`}
                  label={t.newPasswordLabel}
                  type="password"
                  autoComplete="new-password"
                  value={field.state.value}
                  onChange={field.handleChange}
                  onBlur={field.handleBlur}
                  error={field.state.meta.errors[0] ?? fieldErrors.next}
                  classNames={classNames}
                />
              )}
            </form.Field>
            <form.Field
              name="confirm"
              validators={{
                onSubmit: ({ value, fieldApi }) => (value !== fieldApi.form.getFieldValue("next") ? t.confirmPasswordMismatch : undefined),
              }}
            >
              {(field) => (
                <TextField
                  id={`${id}-confirm`}
                  label={t.confirmPasswordLabel}
                  type="password"
                  autoComplete="new-password"
                  value={field.state.value}
                  onChange={field.handleChange}
                  onBlur={field.handleBlur}
                  error={field.state.meta.errors[0]}
                  classNames={classNames}
                />
              )}
            </form.Field>
          </div>
          <form.Field name="revokeOthers">
            {(field) => (
              <Field orientation="horizontal" className={classNames?.field}>
                <Checkbox
                  id={`${id}-revoke`}
                  checked={field.state.value}
                  onCheckedChange={(checked) => field.handleChange(checked === true)}
                  aria-describedby={`${id}-revoke-help`}
                />
                <FieldContent>
                  <FieldLabel htmlFor={`${id}-revoke`} className={cn("font-normal", classNames?.label)}>
                    {t.revokeOthersLabel}
                  </FieldLabel>
                  <FieldDescription id={`${id}-revoke-help`}>{t.revokeOthersHint}</FieldDescription>
                </FieldContent>
              </Field>
            )}
          </form.Field>
        </FieldGroup>
      </form>
      {reauth.element}
    </SettingsCard>
  )
}

// ---------------------------------------------------------------------------
// Sessions

export type SessionsSectionProps = AccountSectionProps<"sessions">

/** Every session of the user, the current one marked, each revocable, plus "sign out of all others". */
export function SessionsSection({ className, classNames, localization, onSuccess, headingLevel = SECTION_HEADING_LEVEL }: SessionsSectionProps) {
  const t = useLocalization("accountSettings", ACCOUNT_SETTINGS_TEXT, localization)
  const { client, queryClient } = useAuth()
  const { session } = useSession()
  const messageFor = useErrorMessage()
  const [formError, setFormError] = useState<string | null>(null)
  const [confirming, setConfirming] = useState<{ kind: "one"; session: AuthSessionView } | { kind: "others" } | null>(null)

  const list = useQuery(
    {
      queryKey: SESSIONS_QUERY_KEY,
      queryFn: async () => {
        const { data, error } = await client.sessions()
        if (error !== null) throw new AuthCallError(error)
        // The current session first, then the most recently active.
        return [...(data.sessions ?? [])].sort((a, b) => Number(b.current) - Number(a.current) || Date.parse(b.lastSeenAt) - Date.parse(a.lastSeenAt))
      },
      enabled: session !== null,
      staleTime: LIST_STALE_MS,
    },
    queryClient,
  )

  const revoke = useMutation({
    mutationFn: async (ids: readonly string[]) => {
      // One call per session: the core has no "all but this one" route, and
      // signOutAll would end this session too.
      const results = await Promise.all(ids.map((id) => client.sessionsRevoke({ id })))
      return { ids, error: results.find((r) => r.error !== null)?.error ?? null }
    },
    onSuccess: async ({ ids, error }) => {
      await queryClient.invalidateQueries({ queryKey: SESSIONS_QUERY_KEY })
      setConfirming(null)
      if (error !== null) {
        setFormError(messageFor(error))
        return
      }
      onSuccess?.({ section: "sessions", revoked: ids })
    },
  })

  if (session === null) return null
  const sessions = list.data ?? []
  const others = sessions.filter((s) => !s.current)
  const locale = t.locale === "" ? undefined : t.locale

  return (
    <SettingsCard
      level={headingLevel}
      title={t.sessionsTitle}
      description={t.sessionsDescription}
      className={className}
      classNames={classNames}
      footer={
        others.length > 0 ? (
          <Button
            type="button"
            variant="outline"
            className={cn("ml-auto", classNames?.action)}
            disabled={revoke.isPending}
            onClick={() => {
              setFormError(null)
              setConfirming({ kind: "others" })
            }}
          >
            {t.revokeOthers}
          </Button>
        ) : list.isSuccess ? (
          <p className="text-[13px] text-muted-foreground">{t.noOtherSessions}</p>
        ) : null
      }
    >
      <div className="flex flex-col gap-3">
        <FormErrorAlert message={formError} className={classNames?.formError} />
        {list.isPending ? (
          <div className="flex flex-col gap-2">
            <Skeleton className="h-12 w-full rounded-lg" />
            <Skeleton className="h-12 w-full rounded-lg" />
          </div>
        ) : list.isError ? (
          <LoadError t={t} onRetry={() => void list.refetch()} />
        ) : (
          <ul className={cn("flex flex-col divide-y rounded-lg border", classNames?.list)} aria-label={t.sessionsTitle}>
            {sessions.map((s) => {
              const device = describeAgent(s.userAgent)
              const name = deviceLabel(s.userAgent, t)
              const DeviceIcon = device?.mobile === true ? SmartphoneIcon : MonitorIcon
              return (
                <li key={s.id} className={cn("flex items-center gap-3 px-3 py-2.5", classNames?.row)}>
                  <span aria-hidden className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground">
                    <DeviceIcon className="size-4" />
                  </span>
                  <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className={cn("text-[13px] font-medium [overflow-wrap:anywhere]", classNames?.rowTitle)}>{name}</span>
                      {s.current && (
                        <Badge variant="secondary" className={classNames?.badge}>
                          {t.thisDevice}
                        </Badge>
                      )}
                      {s.impersonated && (
                        <Badge variant="outline" className={classNames?.badge}>
                          {t.impersonated}
                        </Badge>
                      )}
                    </div>
                    <span className={cn("text-xs text-muted-foreground [overflow-wrap:anywhere]", classNames?.rowMeta)}>
                      {s.ip === "" ? t.unknownIP : s.ip}
                      <span aria-hidden> · </span>
                      {s.current ? t.activeNow : format(t.lastActive, { time: relativeTime(s.lastSeenAt, locale) })}
                    </span>
                  </div>
                  {!s.current && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className={cn("shrink-0", classNames?.action)}
                      disabled={revoke.isPending}
                      aria-label={`${t.revoke}: ${name}`}
                      onClick={() => {
                        setFormError(null)
                        setConfirming({ kind: "one", session: s })
                      }}
                    >
                      {t.revoke}
                    </Button>
                  )}
                </li>
              )
            })}
          </ul>
        )}
      </div>
      <ConfirmDialog
        open={confirming !== null}
        onOpenChange={(open) => !open && !revoke.isPending && setConfirming(null)}
        title={confirming?.kind === "others" ? t.revokeOthersTitle : t.revokeTitle}
        description={
          confirming?.kind === "others"
            ? format(t.revokeOthersDescription, { count: others.length })
            : confirming?.kind === "one"
              ? format(t.revokeDescription, { device: deviceLabel(confirming.session.userAgent, t) })
              : ""
        }
        confirmLabel={revoke.isPending ? t.revoking : t.revoke}
        cancelLabel={t.cancel}
        pending={revoke.isPending}
        onConfirm={() => {
          if (confirming === null) return
          revoke.mutate(confirming.kind === "others" ? others.map((s) => s.id) : [confirming.session.id])
        }}
        className={classNames?.dialog}
      />
    </SettingsCard>
  )
}

// ---------------------------------------------------------------------------
// Linked accounts

export type LinkedAccountsSectionProps = AccountSectionProps<"linkedAccounts"> & {
  /** Icons per provider id, over the built-in GitHub and Google marks; other providers show their initial. */
  readonly providerIcons?: Readonly<Record<string, ReactNode>>
}

/** Every configured OAuth provider: linked accounts with Disconnect, the rest with Connect. */
export function LinkedAccountsSection({ className, classNames, localization, onSuccess, providerIcons, headingLevel = SECTION_HEADING_LEVEL }: LinkedAccountsSectionProps) {
  const t = useLocalization("accountSettings", ACCOUNT_SETTINGS_TEXT, localization)
  const oauth = usePluginClient("oauth")
  const { baseURL, queryClient } = useAuth()
  const { session } = useSession()
  const { providers, isPending: providersPending } = useOAuthProviders()
  const messageFor = useErrorMessage()
  const reauth = useReauth(t, classNames)
  // A link flow that failed at the provider or the callback comes back here
  // (errorTo) with ?error=<code>; its message is shown once.
  const [formError, setFormError] = useState<string | null>(() => {
    const code = returnedErrorCode()
    return code === null ? null : messageFor({ code, rawCode: code, message: "", status: 0 })
  })
  const [confirming, setConfirming] = useState<OauthAccount | null>(null)
  const [redirecting, setRedirecting] = useState<string | null>(null)

  const list = useLinkedAccounts(true)

  const unlink = useMutation({
    mutationFn: (account: OauthAccount) => {
      if (oauth === null) throw new Error("LinkedAccountsSection: oauth plugin missing")
      return oauth.unlink({ provider: account.provider, accountId: account.id })
    },
    onSuccess: async ({ error }, account) => {
      setConfirming(null)
      if (error?.code === FRESH_SESSION_REQUIRED) {
        reauth.request(() => unlink.mutate(account))
        return
      }
      if (error !== null) {
        setFormError(messageFor(error))
        return
      }
      await queryClient.invalidateQueries({ queryKey: OAUTH_ACCOUNTS_QUERY_KEY })
      onSuccess?.({ section: "linkedAccounts", provider: account.provider, linked: false })
    },
  })

  if (oauth === null || session === null) return null
  if (!providersPending && providers.length === 0) return null

  const accounts = list.data ?? []
  const locale = t.locale === "" ? undefined : t.locale
  const nameOf = (provider: string) => providers.find((p) => p.id === provider)?.name ?? provider

  /** Linking is the start route with link=true, a page navigation that comes back here. */
  function startLink(provider: string) {
    setRedirecting(provider)
    const here = window.location.pathname + window.location.search
    window.location.assign(oauthStartURL(baseURL, provider, { returnTo: here, errorTo: here, link: true }))
  }

  return (
    <SettingsCard level={headingLevel} title={t.linkedTitle} description={t.linkedDescription} className={className} classNames={classNames}>
      <div className="flex flex-col gap-3">
        <FormErrorAlert message={formError} className={classNames?.formError} />
        {list.isPending || providersPending ? (
          <div className="flex flex-col gap-2">
            <Skeleton className="h-12 w-full rounded-lg" />
            <Skeleton className="h-12 w-full rounded-lg" />
          </div>
        ) : list.isError ? (
          <LoadError t={t} onRetry={() => void list.refetch()} />
        ) : (
          <ul className={cn("flex flex-col divide-y rounded-lg border", classNames?.list)} aria-label={t.linkedTitle}>
            {providers.map((p) => {
              const linked = accounts.filter((a) => a.provider === p.id)
              const rows: Array<OauthAccount | null> = linked.length === 0 ? [null] : linked
              return rows.map((account) => (
                <li key={account?.id ?? p.id} className={cn("flex items-center gap-3 px-3 py-2.5", classNames?.row)}>
                  <span aria-hidden className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-muted text-foreground [&_svg]:size-4">
                    <ProviderMark id={p.id} name={p.name} icons={providerIcons} />
                  </span>
                  <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <span className={cn("text-[13px] font-medium [overflow-wrap:anywhere]", classNames?.rowTitle)}>{p.name}</span>
                    <span className={cn("text-xs text-muted-foreground [overflow-wrap:anywhere]", classNames?.rowMeta)}>
                      {account === null ? (
                        t.notLinked
                      ) : (
                        <>
                          {account.email !== "" && (
                            <>
                              {account.email}
                              <span aria-hidden> · </span>
                            </>
                          )}
                          {format(t.linkedOn, { date: shortDate(account.createdAt, locale) })}
                        </>
                      )}
                    </span>
                  </div>
                  {account === null ? (
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className={cn("shrink-0", classNames?.action)}
                      disabled={redirecting !== null}
                      aria-busy={redirecting === p.id}
                      aria-label={`${t.link}: ${p.name}`}
                      onClick={() => startLink(p.id)}
                    >
                      {redirecting === p.id ? <Spinner data-icon="inline-start" /> : <LinkIcon data-icon="inline-start" aria-hidden />}
                      {redirecting === p.id ? t.linking : t.link}
                    </Button>
                  ) : (
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className={cn("shrink-0", classNames?.action)}
                      disabled={unlink.isPending}
                      aria-label={`${t.unlink}: ${p.name}${account.email === "" ? "" : ` (${account.email})`}`}
                      onClick={() => {
                        setFormError(null)
                        setConfirming(account)
                      }}
                    >
                      {t.unlink}
                    </Button>
                  )}
                </li>
              ))
            })}
          </ul>
        )}
      </div>
      <ConfirmDialog
        open={confirming !== null}
        onOpenChange={(open) => !open && !unlink.isPending && setConfirming(null)}
        title={t.unlinkTitle}
        description={confirming === null ? "" : format(t.unlinkDescription, { provider: nameOf(confirming.provider), email: confirming.email })}
        confirmLabel={unlink.isPending ? t.unlinking : t.unlink}
        cancelLabel={t.cancel}
        pending={unlink.isPending}
        onConfirm={() => confirming !== null && unlink.mutate(confirming)}
        className={classNames?.dialog}
      />
      {reauth.element}
    </SettingsCard>
  )
}

// ---------------------------------------------------------------------------
// Security

export type SecuritySectionProps = {
  readonly className?: string
  /** The heading level of the two cards. h2 by default. */
  readonly headingLevel?: HeadingLevel
  /** Text for the re-authentication dialog the two cards share with the other sections. */
  readonly localization?: Partial<AccountSettingsText>
  /** Slots of that dialog (dialog, field, label, input, fieldError, formError, submit). */
  readonly classNames?: SlotClassNames<AccountSettingsSlot>
  /** Classes for the TwoFactorSetup card (its own slots are on its own props). */
  readonly twoFactorClassName?: string
  /** Classes for the PasskeyList card. */
  readonly passkeysClassName?: string
  /** Replaces the section's content, for an app with its own second-factor UI. */
  readonly children?: ReactNode
}

/**
 * Second factors and passkeys: the TwoFactorSetup and PasskeyList cards, each
 * shown when its plugin is on. They are cards of their own with their own
 * headings, so this section adds no frame around them, only the column.
 */
export function SecuritySection({
  className,
  headingLevel = SECTION_HEADING_LEVEL,
  localization,
  classNames,
  twoFactorClassName,
  passkeysClassName,
  children,
}: SecuritySectionProps) {
  const t = useLocalization("accountSettings", ACCOUNT_SETTINGS_TEXT, localization)
  const reauth = useReauth(t, classNames)
  // The cards hand a fresh-session refusal over with a retry that reruns the
  // refused action with its inputs, so after the re-sign-in it finishes by
  // itself, as in the other sections.
  const freshRequired = (retry: () => Promise<void>) =>
    reauth.request(() => {
      void retry()
    })
  const twofactor = usePluginClient("twofactor")
  const passkey = usePluginClient("passkey")
  const { session } = useSession()
  if (session === null || (children === undefined && twofactor === null && passkey === null)) return null
  return (
    <div className={cn("flex flex-col gap-4", className)}>
      {children ?? (
        <>
          {twofactor !== null && <TwoFactorSetup headingLevel={headingLevel} onFreshSessionRequired={freshRequired} className={cn("max-w-none", twoFactorClassName)} />}
          {passkey !== null && <PasskeyList headingLevel={headingLevel} onFreshSessionRequired={freshRequired} className={cn("max-w-none", passkeysClassName)} />}
        </>
      )}
      {reauth.element}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Delete account

export type DeleteAccountSectionProps = AccountSectionProps<"delete">

/** Deletes the account after a typed confirmation; with ConfirmByLink on the server, mails a link instead. */
export function DeleteAccountSection({ className, classNames, localization, onSuccess, redirectTo: requestedRedirectTo, headingLevel = SECTION_HEADING_LEVEL }: DeleteAccountSectionProps) {
  const t = useLocalization("accountSettings", ACCOUNT_SETTINGS_TEXT, localization)
  const { client } = useAuth()
  // redirectTo usually comes from the address bar: anything but a path on
  // this site (or an origin the provider allows) is dropped, so the default
  // applies and a crafted link cannot send the user to another site.
  const redirectTo = useSafeRedirect(requestedRedirectTo)
  const { session } = useSession()
  const { signOut } = useSessionActions()
  const messageFor = useErrorMessage()
  const reauth = useReauth(t, classNames)
  const id = useId()
  const [open, setOpen] = useState(false)
  const [typed, setTyped] = useState("")
  const [formError, setFormError] = useState<string | null>(null)
  const [linkSent, setLinkSent] = useState(false)

  const remove = useMutation({
    mutationFn: () => client.accountDelete(),
    onSuccess: async ({ data, error }) => {
      if (error?.code === FRESH_SESSION_REQUIRED) {
        setOpen(false)
        reauth.request(() => {
          setOpen(true)
          remove.mutate()
        })
        return
      }
      if (error !== null) {
        setFormError(error.code === "auth.unknown_operation" ? t.deleteOff : messageFor(error))
        return
      }
      if (!data.deleted) {
        setOpen(false)
        setLinkSent(data.confirmationSent)
        onSuccess?.({ section: "delete", deleted: false, confirmationSent: data.confirmationSent })
        return
      }
      // The session died with the account: signOut answers signed_out, which
      // it treats as done, and forgets every cached auth entry.
      await signOut({ redirectTo: onSuccess === undefined ? (redirectTo ?? undefined) : null })
      onSuccess?.({ section: "delete", deleted: true, confirmationSent: false })
    },
  })

  if (session === null) return null
  const word = t.deleteConfirmWord
  const matches = typed.trim().toLowerCase() === word.toLowerCase()

  return (
    <Card className={cn("border-destructive/30 ring-destructive/20", className, classNames?.section, classNames?.root)}>
      <CardHeader className={classNames?.sectionHeader}>
        <CardTitle className={classNames?.sectionTitle} role="heading" aria-level={headingLevel}>
          {t.deleteTitle}
        </CardTitle>
        <CardDescription className={classNames?.sectionDescription}>{t.deleteDescription}</CardDescription>
      </CardHeader>
      {linkSent && (
        <CardContent className={classNames?.sectionContent}>
          <StatusAlert message={`${t.deleteLinkSentTitle}. ${t.deleteLinkSentDescription}`} className={classNames?.status} />
        </CardContent>
      )}
      <CardFooter className={cn("border-destructive/20 bg-destructive/5", classNames?.sectionFooter)}>
        <Button
          type="button"
          variant="destructive"
          className={cn("ml-auto", classNames?.dangerAction)}
          onClick={() => {
            setTyped("")
            setFormError(null)
            setOpen(true)
          }}
        >
          {t.deleteButton}
        </Button>
      </CardFooter>
      <Dialog open={open} onOpenChange={(next) => !remove.isPending && setOpen(next)}>
        <DialogContent className={classNames?.dialog} showCloseButton={!remove.isPending}>
          <form
            noValidate
            className="contents"
            onSubmit={(e) => {
              e.preventDefault()
              if (matches && !remove.isPending) {
                setFormError(null)
                remove.mutate()
              }
            }}
          >
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <ShieldAlertIcon aria-hidden className="size-4 text-destructive" />
                {t.deleteDialogTitle}
              </DialogTitle>
              <DialogDescription>{t.deleteDialogDescription}</DialogDescription>
            </DialogHeader>
            <FormErrorAlert message={formError} className={classNames?.formError} />
            <Field className={classNames?.field}>
              <FieldLabel htmlFor={`${id}-confirm`} className={classNames?.label}>
                {format(t.deleteConfirmLabel, { word })}
              </FieldLabel>
              <Input
                id={`${id}-confirm`}
                autoComplete="off"
                autoCapitalize="none"
                spellCheck={false}
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                className={classNames?.input}
                autoFocus
              />
            </Field>
            <DialogFooter>
              <Button type="button" variant="outline" disabled={remove.isPending} onClick={() => setOpen(false)}>
                {t.cancel}
              </Button>
              <Button
                type="submit"
                variant="destructive"
                className={cn("bg-destructive text-white hover:bg-destructive/90 dark:bg-destructive/80", classNames?.dangerAction)}
                disabled={!matches || remove.isPending}
                aria-busy={remove.isPending}
              >
                {remove.isPending && <Spinner data-icon="inline-start" />}
                {remove.isPending ? t.deleting : t.deleteConfirm}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      {reauth.element}
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Re-authentication

/**
 * What useReauth returns: `request(retry)` opens the dialog and runs `retry`
 * once the user has signed in again; `element` must be rendered by the caller.
 */
export type Reauth = { readonly request: (retry: () => void) => void; readonly element: ReactNode }

/**
 * Re-authentication on demand. An operation that answered
 * auth.fresh_session_required calls request(retry); the dialog confirms the
 * password or a passkey (then the second-factor code when the account has
 * one), which makes the current session fresh again without replacing it,
 * and runs retry. A user with a linked provider account can continue with
 * it instead: that is a page navigation, so the page comes back with
 * ?reauth=… and retry cannot run; AccountSettings (or useReauthReturn on any
 * other page) then says the change can be made now. Without the password,
 * passkey and oauth plugins, or on a server that cannot refresh sessions, it
 * offers the sign-in page, which brings the user back here.
 */
export function useReauth(t: AccountSettingsText, classNames?: SlotClassNames<AccountSettingsSlot>): Reauth {
  const [retry, setRetry] = useState<(() => void) | null>(null)
  const element = (
    <ReauthDialog
      t={t}
      classNames={classNames}
      open={retry !== null}
      onOpenChange={(open) => !open && setRetry(null)}
      onDone={() => {
        const run = retry
        setRetry(null)
        run?.()
      }}
    />
  )
  // A function in state must be wrapped, or React calls it as an updater.
  return { request: (fn) => setRetry(() => fn), element }
}

/** Props of ReauthDialog, for a component outside AccountSettings that guards its own operations. */
export type ReauthDialogProps = {
  readonly t: AccountSettingsText
  readonly classNames?: SlotClassNames<AccountSettingsSlot>
  readonly open: boolean
  readonly onOpenChange: (open: boolean) => void
  /** Called after the new sign-in, with the session already refreshed. */
  readonly onDone: () => void
  /**
   * Opens the dialog at the code step with this ticket: a provider
   * re-authentication came back with ?reauth=second_factor (useReauthReturn).
   */
  readonly ticket?: string
}

export function ReauthDialog({ t, classNames, open, onOpenChange, onDone, ticket: returnedTicket }: ReauthDialogProps) {
  const { navigate, paths } = useAuth()
  const messageFor = useErrorMessage()
  const passwordClient = usePluginClient("password")
  const passkey = usePluginClient("passkey")
  const twofactor = usePluginClient("twofactor")
  const oauth = usePluginClient("oauth")
  const { providers } = useOAuthProviders()
  const { email } = usePrimaryEmail()
  const id = useId()
  const [password, setPassword] = useState("")
  const [code, setCode] = useState("")
  // The ticket the password or passkey step answers when the account has a
  // second factor; while it is set, the dialog asks for the code.
  const [ticket, setTicket] = useState<string | null>(returnedTicket ?? null)
  // The provider the browser is leaving for, so its button keeps saying so.
  const [leavingFor, setLeavingFor] = useState<string | null>(null)
  // Whether the code was mailed or texted just now (a delivered factor), which changes the hint.
  const [codeSent, setCodeSent] = useState(false)
  // The server cannot refresh this session (auth.reauthentication_unsupported):
  // the dialog falls back to signing in again on the sign-in page.
  const [unsupported, setUnsupported] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [invalid, setInvalid] = useState(false)

  const codeStep = ticket !== null
  const canPassword = passwordClient !== null && !unsupported
  const canPasskey = passkey !== null && supportsPasskeys() && !unsupported
  // The user's linked providers, in the server's order, one button each.
  const linked = useLinkedAccounts(open && !unsupported)
  const linkedProviders = providers.filter((p) => (linked.data ?? []).some((a) => a.provider === p.id))
  const canProvider = linkedProviders.length > 0 && !unsupported
  // Read when the dialog navigates, never during render: the server has no
  // window, so reading it here would break server rendering of the page.
  const here = () => window.location.pathname + window.location.search

  function reset() {
    setPassword("")
    setCode("")
    setTicket(null)
    setCodeSent(false)
    setUnsupported(false)
    setError(null)
    setInvalid(false)
  }

  /**
   * Closes the dialog at any step. Re-authentication only refreshes the
   * current session, and a step left half-way changes nothing, so the user
   * stays signed in on the same session.
   */
  function close() {
    reset()
    onOpenChange(false)
  }

  /** The session is fresh again: hand back so the refused action reruns. */
  function complete() {
    reset()
    onDone()
  }

  /** A failed step: under the field for a wrong password or code, the fallback for a server that cannot refresh sessions, the alert otherwise. */
  function fail(failure: AuthError, field: boolean) {
    setError(messageFor(failure))
    if (failure.code === "auth.reauthentication_unsupported") {
      setUnsupported(true)
      setTicket(null)
      setInvalid(false)
      return
    }
    if (failure.code === "auth.reauthentication_ticket_invalid") {
      // The ticket expired or was used: back to the password or passkey.
      setTicket(null)
      setCode("")
      setInvalid(false)
      return
    }
    setInvalid(field)
  }

  /** After the password or passkey: fresh means done; a second factor means the code step with the ticket. */
  async function answered(result: AuthReauthentication) {
    if (result.fresh) return complete()
    if (!result.secondFactorRequired || result.ticket === undefined || twofactor === null) {
      // A second factor this client cannot answer here: finish on the sign-in page.
      setUnsupported(true)
      setError(t.reauthSignInDescription)
      return
    }
    setError(null)
    setInvalid(false)
    setTicket(result.ticket)
    await sendCodeIfDelivered()
  }

  /** A mailed or texted factor needs its code sent; an authenticator app has one already. */
  async function sendCodeIfDelivered() {
    if (twofactor === null) return
    const status = await twofactor.status()
    if (status.error === null && status.data.method !== undefined && status.data.method !== "" && status.data.method !== "totp") {
      const sent = await twofactor.send()
      setCodeSent(sent.error === null)
    }
  }

  // Opened at the code step by a provider re-authentication that came back
  // needing it: send the code once, as the password step would have.
  const sentForReturn = useRef(false)
  useEffect(() => {
    if (returnedTicket === undefined || sentForReturn.current) return
    sentForReturn.current = true
    void sendCodeIfDelivered()
  })

  /**
   * Continue with a linked provider: the server binds the flow to this
   * session and answers the provider URL; the page leaves for it and comes
   * back with ?reauth=… (useReauthReturn), or ?reauth=failed&error=<code>.
   */
  const viaProvider = useMutation({
    mutationFn: (provider: string) => {
      if (oauth === null) throw new Error("ReauthDialog: oauth plugin missing")
      return oauth.reauthenticate({ provider, returnTo: reauthReturnTo(null), errorTo: reauthReturnTo(REAUTH_FAILED) })
    },
    onSuccess: ({ data, error: failed }, provider) => {
      if (failed !== null) return fail(failed, false)
      setLeavingFor(provider)
      window.location.assign(data.url)
    },
  })

  const viaPassword = useMutation({
    mutationFn: () => {
      if (passwordClient === null) throw new Error("ReauthDialog: password plugin missing")
      return passwordClient.reauthenticate({ password })
    },
    onSuccess: async ({ data, error: failed }) => {
      if (failed !== null) return fail(failed, failed.code === "password.invalid_credentials")
      await answered(data)
    },
  })

  const viaPasskey = useMutation({
    mutationFn: async (): Promise<{ result: AuthReauthentication | null; error: AuthError | null; cancelled: boolean }> => {
      if (passkey === null) throw new Error("ReauthDialog: passkey plugin missing")
      const begin = await passkey.reauthenticateBegin({})
      if (begin.error !== null) return { result: null, error: begin.error, cancelled: false }
      const ceremony = await getPasskeyCredential(begin.data.options)
      if (ceremony.credential === null) return { result: null, error: null, cancelled: true }
      const done = await passkey.reauthenticateFinish({ ceremony: begin.data.ceremony, credential: ceremony.credential })
      if (done.error !== null) return { result: null, error: done.error, cancelled: false }
      return { result: done.data, error: null, cancelled: false }
    },
    onSuccess: async (outcome) => {
      if (outcome.error !== null) fail(outcome.error, false)
      else if (outcome.cancelled || outcome.result === null) setError(t.reauthPasskeyCancelled)
      else await answered(outcome.result)
    },
  })

  const viaCode = useMutation({
    mutationFn: () => {
      if (twofactor === null || ticket === null) throw new Error("ReauthDialog: no second-factor step")
      return twofactor.reauthenticate({ code: code.trim(), ticket })
    },
    onSuccess: ({ data, error: failed }) => {
      if (failed !== null) return fail(failed, failed.code === "twofactor.code_invalid")
      if (data.fresh) complete()
      else fail({ code: "auth.reauthentication_ticket_invalid", rawCode: "", message: "", status: 0 }, false)
    },
  })

  const busy = viaPassword.isPending || viaPasskey.isPending || viaCode.isPending || viaProvider.isPending || leavingFor !== null
  const fieldId = codeStep ? `${id}-code` : `${id}-password`

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (busy) return
        if (!next) close()
        else onOpenChange(next)
      }}
    >
      <DialogContent className={classNames?.dialog} showCloseButton={!busy}>
        <form
          noValidate
          className="contents"
          onSubmit={(e) => {
            e.preventDefault()
            if (busy) return
            if (!canPassword && !codeStep) {
              // No password here, or a server that cannot refresh sessions: sign in again and come back.
              navigate(`${paths.signIn}${paths.signIn.includes("?") ? "&" : "?"}redirectTo=${encodeURIComponent(here())}`)
              return
            }
            if ((codeStep ? code.trim() : password) === "") {
              setError(null)
              setInvalid(true)
              document.getElementById(fieldId)?.focus()
              return
            }
            setError(null)
            setInvalid(false)
            if (codeStep) viaCode.mutate()
            else viaPassword.mutate()
          }}
        >
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <KeyRoundIcon aria-hidden className="size-4 text-muted-foreground" />
              {t.reauthTitle}
            </DialogTitle>
            <DialogDescription>
              {codeStep
                ? codeSent
                  ? t.reauthCodeSentDescription
                  : t.reauthCodeDescription
                : canPassword
                  ? canProvider
                    ? t.reauthProviderDescription
                    : t.reauthDescription
                  : canProvider
                    ? t.reauthProviderOnlyDescription
                    : t.reauthSignInDescription}
            </DialogDescription>
          </DialogHeader>
          {error !== null && !invalid && !(unsupported && error === t.reauthSignInDescription) && (
            <FormErrorAlert message={error} className={classNames?.formError} />
          )}
          {(canPassword || codeStep) && (
            <Field data-invalid={invalid} className={classNames?.field}>
              <FieldLabel htmlFor={fieldId} className={classNames?.label}>
                {codeStep ? t.reauthCodeLabel : t.reauthPasswordLabel}
              </FieldLabel>
              {codeStep ? (
                <Input
                  // A new element, so focus moves to it when the step changes.
                  key="code"
                  id={fieldId}
                  autoComplete="one-time-code"
                  autoCapitalize="none"
                  spellCheck={false}
                  autoFocus
                  value={code}
                  onChange={(e) => {
                    setCode(e.target.value)
                    setInvalid(false)
                  }}
                  aria-invalid={invalid}
                  aria-describedby={invalid ? `${fieldId}-error` : undefined}
                  className={classNames?.input}
                />
              ) : (
                <>
                  {/* The username lets a password manager fill the right account. */}
                  <input type="email" name="username" autoComplete="username" value={email ?? ""} readOnly hidden />
                  <Input
                    key="password"
                    id={fieldId}
                    type="password"
                    autoComplete="current-password"
                    autoFocus
                    value={password}
                    onChange={(e) => {
                      setPassword(e.target.value)
                      setInvalid(false)
                    }}
                    aria-invalid={invalid}
                    aria-describedby={invalid ? `${fieldId}-error` : undefined}
                    className={classNames?.input}
                  />
                </>
              )}
              {invalid && (
                <FieldError id={`${fieldId}-error`} className={classNames?.fieldError}>
                  {error ?? (codeStep ? t.reauthCodeRequired : t.reauthPasswordRequired)}
                </FieldError>
              )}
            </Field>
          )}
          {canProvider && !codeStep && (
            <div className="flex flex-col gap-2">
              {linkedProviders.map((p) => {
                const pending = leavingFor === p.id || (viaProvider.isPending && viaProvider.variables === p.id)
                return (
                  <Button
                    key={p.id}
                    type="button"
                    variant="outline"
                    disabled={busy}
                    aria-busy={pending}
                    onClick={() => {
                      setError(null)
                      setInvalid(false)
                      viaProvider.mutate(p.id)
                    }}
                  >
                    {pending && <Spinner data-icon="inline-start" />}
                    {format(pending ? t.reauthProviderPending : t.reauthProvider, { provider: p.name })}
                  </Button>
                )
              })}
            </div>
          )}
          <DialogFooter className="sm:justify-between">
            {canPasskey && !codeStep ? (
              <Button
                type="button"
                variant="ghost"
                disabled={busy}
                onClick={() => {
                  setError(null)
                  setInvalid(false)
                  viaPasskey.mutate()
                }}
              >
                {viaPasskey.isPending ? <Spinner data-icon="inline-start" /> : <KeyRoundIcon data-icon="inline-start" aria-hidden />}
                {viaPasskey.isPending ? t.reauthPasskeyPending : t.reauthPasskey}
              </Button>
            ) : (
              <span />
            )}
            <div className="flex flex-col-reverse gap-2 sm:flex-row">
              <Button type="button" variant="outline" disabled={busy} onClick={close}>
                {t.cancel}
              </Button>
              <Button type="submit" disabled={busy} aria-busy={viaPassword.isPending || viaCode.isPending} className={classNames?.submit}>
                {(viaPassword.isPending || viaCode.isPending) && <Spinner data-icon="inline-start" />}
                {canPassword || codeStep ? (viaPassword.isPending || viaCode.isPending ? t.reauthConfirming : t.reauthConfirm) : t.reauthSignInAgain}
              </Button>
            </div>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Shared parts

/** A failed list read, carried through TanStack Query's error channel with its AuthError. */
class AuthCallError extends Error {
  readonly error: AuthError
  constructor(error: AuthError) {
    super(error.message)
    this.name = "AuthCallError"
    this.error = error
  }
}

/** One section's card: title, description, content and an optional footer of actions. */
function SettingsCard({
  title,
  description,
  level,
  footer,
  className,
  classNames,
  children,
}: {
  title: string
  description: string
  level: HeadingLevel
  footer?: ReactNode
  className?: string
  classNames?: SlotClassNames<AccountSettingsSlot>
  children: ReactNode
}) {
  const headingId = useId()
  return (
    <Card role="region" aria-labelledby={headingId} className={cn("w-full", className, classNames?.section, classNames?.root)}>
      <CardHeader className={classNames?.sectionHeader}>
        <CardTitle id={headingId} className={classNames?.sectionTitle} role="heading" aria-level={level}>
          {title}
        </CardTitle>
        <CardDescription className={classNames?.sectionDescription}>{description}</CardDescription>
      </CardHeader>
      <CardContent className={classNames?.sectionContent}>{children}</CardContent>
      {footer !== undefined && footer !== null && (
        <CardFooter className={cn("min-h-12 gap-2 py-2.5", classNames?.sectionFooter)}>{footer}</CardFooter>
      )}
    </Card>
  )
}

/** A labelled text input with its error, wired for screen readers the same way everywhere. */
function TextField({
  id,
  label,
  value,
  onChange,
  onBlur,
  error,
  classNames,
  type = "text",
  ...input
}: {
  id: string
  label: string
  value: string
  onChange: (value: string) => void
  onBlur: () => void
  error: string | undefined
  classNames?: SlotClassNames<AccountSettingsSlot>
  type?: string
  autoComplete?: string
  placeholder?: string
  inputMode?: "text" | "email" | "numeric" | "url"
  autoFocus?: boolean
}) {
  const invalid = error !== undefined
  return (
    <Field data-invalid={invalid} className={classNames?.field}>
      <FieldLabel htmlFor={id} className={classNames?.label}>
        {label}
      </FieldLabel>
      <Input
        id={id}
        type={type}
        spellCheck={false}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onBlur={onBlur}
        aria-invalid={invalid}
        aria-describedby={invalid ? `${id}-error` : undefined}
        className={classNames?.input}
        {...input}
      />
      {invalid && (
        <FieldError id={`${id}-error`} className={classNames?.fieldError}>
          {error}
        </FieldError>
      )}
    </Field>
  )
}

function FormErrorAlert({ message, className }: { message: string | null; className?: string }) {
  if (message === null) return null
  return (
    <Alert variant="destructive" className={className}>
      <CircleAlertIcon aria-hidden />
      <AlertDescription>{message}</AlertDescription>
    </Alert>
  )
}

function StatusAlert({ message, className }: { message: string; className?: string }) {
  return (
    <Alert role="status" className={className}>
      <CheckIcon aria-hidden />
      <AlertDescription>{message}</AlertDescription>
    </Alert>
  )
}

/** "Saved" next to a form's button. The live region is always mounted, so the change is announced. */
function SavedStatus({ show, label, className }: { show: boolean; label: string; className?: string }) {
  return (
    <span role="status" className={cn("flex items-center gap-1 text-[13px] text-muted-foreground", className)}>
      {show && (
        <>
          <CheckIcon aria-hidden className="size-3.5 text-emerald-600 dark:text-emerald-400" />
          {label}
        </>
      )}
    </span>
  )
}

function LoadError({ t, onRetry }: { t: AccountSettingsText; onRetry: () => void }) {
  return (
    <Alert variant="destructive">
      <CircleAlertIcon aria-hidden />
      <AlertDescription className="flex flex-wrap items-center justify-between gap-2">
        {t.loadFailed}
        <Button type="button" variant="outline" size="sm" onClick={onRetry}>
          {t.retry}
        </Button>
      </AlertDescription>
    </Alert>
  )
}

function SectionSkeleton() {
  return (
    <div className="flex flex-col gap-4" aria-hidden>
      <Skeleton className="h-44 w-full rounded-xl" />
      <Skeleton className="h-32 w-full rounded-xl" />
    </div>
  )
}

/** A confirmation step in place of window.confirm: an alert dialog, focus-trapped, Escape cancels, the action shows its progress. */
function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  cancelLabel,
  pending,
  onConfirm,
  className,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description: string
  confirmLabel: string
  cancelLabel: string
  pending: boolean
  onConfirm: () => void
  className?: string
}) {
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent className={className}>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={pending}>{cancelLabel}</AlertDialogCancel>
          <AlertDialogAction variant="destructive" disabled={pending} aria-busy={pending} onClick={onConfirm}>
            {pending && <Spinner data-icon="inline-start" />}
            {confirmLabel}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

/** A browser and an OS read from a user agent, or null when neither is recognised. */
export function describeAgent(userAgent: string): { browser: string; os: string; mobile: boolean } | null {
  const ua = userAgent
  const browser = /Edg(e|A|iOS)?\//.test(ua)
    ? "Edge"
    : /OPR\/|Opera/.test(ua)
      ? "Opera"
      : /Firefox\/|FxiOS\//.test(ua)
        ? "Firefox"
        : /Chrome\/|CriOS\//.test(ua)
          ? "Chrome"
          : /Safari\//.test(ua)
            ? "Safari"
            : null
  const os = /iPhone|iPad|iPod/.test(ua)
    ? "iOS"
    : /Android/.test(ua)
      ? "Android"
      : /CrOS/.test(ua)
        ? "ChromeOS"
        : /Mac OS X|Macintosh/.test(ua)
          ? "macOS"
          : /Windows/.test(ua)
            ? "Windows"
            : /Linux/.test(ua)
              ? "Linux"
              : null
  if (browser === null && os === null) return null
  return { browser: browser ?? "Browser", os: os ?? "Unknown OS", mobile: /Mobi|iPhone|Android/.test(ua) }
}

/**
 * The error code a failed OAuth link flow put in the address (?error=), when
 * it is one the client knows. A refused re-authentication's error belongs to
 * useReauthReturn, so it is not shown twice.
 */
function returnedErrorCode(): AuthError["code"] | null {
  if (typeof window === "undefined") return null
  const query = new URLSearchParams(window.location.search)
  if (query.has(REAUTH_PARAM)) return null
  const code = query.get(REAUTH_ERROR_PARAM)
  return code !== null && isAuthErrorCode(code) ? code : null
}

/**
 * Where a provider re-authentication comes back to: this page, without any
 * marker a previous return left, plus `reauth=<marker>` for the errorTo
 * address. Read when the button is pressed, never during render.
 */
function reauthReturnTo(marker: string | null): string {
  const query = new URLSearchParams(window.location.search)
  for (const name of [REAUTH_PARAM, REAUTH_TICKET_PARAM, REAUTH_ERROR_PARAM]) query.delete(name)
  if (marker !== null) query.set(REAUTH_PARAM, marker)
  const qs = query.toString()
  return window.location.pathname + (qs === "" ? "" : `?${qs}`) + window.location.hash
}

/** What a page learns when a provider re-authentication brings it back. */
export type ReauthReturn =
  | { readonly status: "fresh" }
  | { readonly status: "second_factor"; readonly ticket: string }
  | { readonly status: "failed"; readonly code: AuthError["code"] }

/**
 * Reads, once after mount, what a provider re-authentication left in the
 * address (?reauth=…), and removes it so a reload or a shared link does not
 * repeat it. "fresh": the session is fresh, the refused change can be made
 * again; "second_factor": open ReauthDialog with the ticket for the code
 * step; "failed": the code the callback refused with. null when the page was
 * not reached that way. The second value forgets it (closing the message).
 * After mount, because the server render has no address to read.
 */
export function useReauthReturn(): readonly [ReauthReturn | null, () => void] {
  const [returned, setReturned] = useState<ReauthReturn | null>(null)
  useEffect(() => {
    const url = new URL(window.location.href)
    const status = url.searchParams.get(REAUTH_PARAM)
    if (status === null) return
    const ticket = url.searchParams.get(REAUTH_TICKET_PARAM)
    const code = url.searchParams.get(REAUTH_ERROR_PARAM)
    for (const name of [REAUTH_PARAM, REAUTH_TICKET_PARAM, REAUTH_ERROR_PARAM]) url.searchParams.delete(name)
    window.history.replaceState(window.history.state, "", url.pathname + url.search + url.hash)
    if (status === REAUTH_FRESH) setReturned({ status: "fresh" })
    else if (status === REAUTH_SECOND_FACTOR && ticket !== null && ticket !== "") setReturned({ status: "second_factor", ticket })
    else if (status === REAUTH_FAILED) setReturned({ status: "failed", code: code !== null && isAuthErrorCode(code) ? code : "auth.internal" })
  }, [])
  return [returned, () => setReturned(null)] as const
}

/** The signed-in user's linked provider accounts, one cache entry for the linked-accounts list and the re-authentication dialog. */
function useLinkedAccounts(enabled: boolean) {
  const oauth = usePluginClient("oauth")
  const { queryClient } = useAuth()
  const { session } = useSession()
  return useQuery(
    {
      queryKey: OAUTH_ACCOUNTS_QUERY_KEY,
      queryFn: async () => {
        if (oauth === null) return []
        const { data, error } = await oauth.accounts()
        if (error !== null) throw new AuthCallError(error)
        return data.accounts ?? []
      },
      enabled: enabled && oauth !== null && session !== null,
      staleTime: LIST_STALE_MS,
    },
    queryClient,
  )
}

/** "Chrome on macOS", or the unknown-device text. */
function deviceLabel(userAgent: string, t: AccountSettingsText): string {
  const device = describeAgent(userAgent)
  return device === null ? t.unknownDevice : format(t.deviceName, { browser: device.browser, os: device.os })
}

/** "5 minutes ago", in the given locale. */
function relativeTime(iso: string, locale: string | undefined): string {
  const seconds = (Date.parse(iso) - Date.now()) / 1000
  if (Number.isNaN(seconds)) return ""
  const rtf = new Intl.RelativeTimeFormat(locale, { numeric: "auto" })
  const steps: ReadonlyArray<[Intl.RelativeTimeFormatUnit, number]> = [
    ["second", 60],
    ["minute", 60],
    ["hour", 24],
    ["day", 30],
    ["month", 12],
  ]
  let value = seconds
  for (const [unit, size] of steps) {
    if (Math.abs(value) < size) return rtf.format(Math.round(value), unit)
    value /= size
  }
  return rtf.format(Math.round(value), "year")
}

/** "12 Oct 2026", in the given locale. */
function shortDate(iso: string, locale: string | undefined): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return ""
  return new Intl.DateTimeFormat(locale, { dateStyle: "medium" }).format(date)
}

/** A provider's mark: the app's icon, a built-in brand mark, or the name's initial. */
function ProviderMark({ id, name, icons }: { id: string; name: string; icons: Readonly<Record<string, ReactNode>> | undefined }) {
  const custom = icons?.[id]
  if (custom !== undefined) return <>{custom}</>
  const builtin = BRAND_MARKS[id]
  if (builtin !== undefined) return builtin
  return <span className="text-[13px] font-semibold uppercase">{name.slice(0, 1)}</span>
}

/** The same monochrome marks SignInForm draws, so both pages show a provider alike. */
const BRAND_MARKS: Readonly<Record<string, ReactNode>> = {
  github: (
    <svg aria-hidden viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 .5a11.5 11.5 0 0 0-3.64 22.41c.58.1.79-.25.79-.56v-2c-3.2.7-3.88-1.36-3.88-1.36-.52-1.33-1.28-1.69-1.28-1.69-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.19 1.76 1.19 1.03 1.76 2.69 1.25 3.35.96.1-.75.4-1.25.73-1.54-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.19-3.09-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.17 1.18a11 11 0 0 1 5.77 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.8 1.19 1.83 1.19 3.09 0 4.42-2.69 5.39-5.26 5.68.41.36.78 1.06.78 2.14v3.17c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .5Z" />
    </svg>
  ),
  google: (
    <svg aria-hidden viewBox="0 0 24 24" fill="currentColor">
      <path d="M21.35 11.1H12v2.98h5.35c-.23 1.45-1.66 4.26-5.35 4.26-3.22 0-5.85-2.67-5.85-5.96S8.78 6.42 12 6.42c1.83 0 3.06.78 3.76 1.45l2.57-2.47C16.68 3.86 14.56 2.9 12 2.9 6.98 2.9 2.9 6.98 2.9 12s4.08 9.1 9.1 9.1c5.25 0 8.74-3.69 8.74-8.89 0-.6-.07-1.05-.15-1.51Z" />
    </svg>
  ),
}
