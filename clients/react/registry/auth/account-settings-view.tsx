import { useForm } from "@tanstack/react-form"
import type { AuthSessionView, AuthUserView, EmailAddress, OauthAccount } from "@ubgo/auth-client"
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
import { useEffect, useId, useRef, useState, type ReactNode } from "react"

import { fillText, type ViewHeadingLevel } from "@/components/auth/auth-view"
import { UserAvatar } from "@/components/auth/user-button-view"
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

// The account page's views with no data layer: AccountSettingsView (the
// page's frame), one view per section (ProfileSectionView, EmailSectionView,
// PasswordSectionView, SessionsSectionView, LinkedAccountsSectionView,
// SecuritySectionView, DeleteAccountSectionView) and ReauthDialogView. Each
// takes its data, which call runs, what failed and its text as props, keeps
// only local form and dialog state, and hands every action to a callback.
// The wired components in account-settings.tsx render these with
// @ubgo/auth-react's calls; render them yourself to put the same page on any
// other backend. A part that is itself a wired component (TwoFactorSetup,
// PasskeyList, the re-authentication dialog) comes in as a ReactNode slot.

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

/** classNames for the account views: a class per named part. */
export type AccountSettingsClassNames = Partial<Record<AccountSettingsSlot, string>>

/**
 * A section's heading level when used on its own: a section sits under a
 * page's h1, so h2. AccountSettings sets it to one below its own heading.
 */
export const ACCOUNT_SECTION_HEADING_LEVEL: ViewHeadingLevel = 2

/** The longest name the profile form accepts before asking; the server keeps its own limit. */
const MAX_NAME_LENGTH = 100

/** Where a list a section shows stands: still loading, failed (the view offers a retry), or loaded. */
export type AccountListStatus = "pending" | "error" | "success"

/** The props every section view shares: styling, text overrides and the title's level. */
export type AccountSectionViewProps = {
  /** Classes for the section's card, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: AccountSettingsClassNames
  /** Text overrides, merged over ACCOUNT_SETTINGS_TEXT. */
  readonly text?: Partial<AccountSettingsText>
  /** The level of the section's title, h2 by default. */
  readonly headingLevel?: ViewHeadingLevel
}

/** The text with the overrides merged over the English defaults. */
function textOf(text: Partial<AccountSettingsText> | undefined): AccountSettingsText {
  return { ...ACCOUNT_SETTINGS_TEXT, ...text }
}

/** The locale for dates and relative times, or the browser's when the text leaves it empty. */
function localeOf(t: AccountSettingsText): string | undefined {
  return t.locale === "" ? undefined : t.locale
}

// ---------------------------------------------------------------------------
// The page

/** The props of AccountSettingsView: the page's frame around the sections it is handed. */
export type AccountSettingsViewProps = {
  /** Classes for the page's wrapper, merged after the defaults. */
  readonly className?: string
  /** Classes per named part; "root" is the wrapper. */
  readonly classNames?: AccountSettingsClassNames
  /** Text overrides, merged over ACCOUNT_SETTINGS_TEXT. */
  readonly text?: Partial<AccountSettingsText>
  /** The level of the page heading, 1 by default. */
  readonly headingLevel?: ViewHeadingLevel
  /** Hide the page heading, for an app that draws its own. */
  readonly hideHeader?: boolean
  /** The account is still loading: a skeleton stands in for the sections. */
  readonly loading?: boolean
  /** Say the user confirmed it is them and the refused change can be made again. */
  readonly confirmed?: boolean
  /** A message above the sections, such as a refused provider re-authentication. */
  readonly formError?: string | null
  /** A dialog the page owns, such as the re-authentication code step after a provider came back. */
  readonly dialog?: ReactNode
  /** The sections, in order; hidden while loading. */
  readonly children?: ReactNode
  /** Rendered after the sections even while loading, such as the app's own extra sections. */
  readonly trailing?: ReactNode
}

/** The account page's frame: heading, page-level messages and the sections, with no data layer. */
export function AccountSettingsView({
  className,
  classNames,
  text,
  headingLevel = 1,
  hideHeader = false,
  loading = false,
  confirmed = false,
  formError = null,
  dialog,
  children,
  trailing,
}: AccountSettingsViewProps) {
  const t = textOf(text)
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
      {confirmed && <StatusAlert message={t.reauthConfirmed} className={classNames?.status} />}
      <FormErrorAlert message={formError} className={classNames?.formError} />
      {dialog}
      {loading ? <SectionSkeleton /> : children}
      {trailing}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Profile

/** What the profile form hands onSubmit, both trimmed. */
export type ProfileValues = { readonly name: string; readonly image: string }

/** The props of ProfileSectionView. Key it by the user's id so its starting values follow an account switch. */
export type ProfileSectionViewProps = AccountSectionViewProps & {
  /** The user whose name and picture the form starts from. */
  readonly user: AuthUserView
  /** The primary address, for the avatar's initial when there is no name. */
  readonly email?: string | null
  /** The save call is running. */
  readonly saving?: boolean
  /** An upload is running. */
  readonly uploading?: boolean
  /** A message above the form. */
  readonly formError?: string | null
  /** Show "Saved" beside the button until the form is edited again. */
  readonly saved?: boolean
  /** The form passed its checks. Awaited; resolving to the saved values resets the form to them. */
  readonly onSubmit?: (values: ProfileValues) => void | ProfileValues | null | Promise<void | ProfileValues | null>
  /** The form was edited; a good moment to hide "Saved". */
  readonly onEdit?: () => void
  /** Uploads a picked file. Given, the picture field gets an Upload button; a URL it resolves to fills the field. */
  readonly onUpload?: (file: File) => void | string | null | Promise<void | string | null>
}

/** Name and picture, with no data layer. */
export function ProfileSectionView({
  className,
  classNames,
  text,
  headingLevel = ACCOUNT_SECTION_HEADING_LEVEL,
  user,
  email = null,
  saving = false,
  uploading = false,
  formError = null,
  saved = false,
  onSubmit,
  onEdit,
  onUpload,
}: ProfileSectionViewProps) {
  const t = textOf(text)
  const id = useId()
  const formRef = useRef<HTMLFormElement>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const form = useForm({
    defaultValues: { name: user.name, image: user.image },
    onSubmit: async ({ value }) => {
      const done = await onSubmit?.({ name: value.name.trim(), image: value.image.trim() })
      if (done !== undefined && done !== null) form.reset({ name: done.name, image: done.image })
    },
    onSubmitInvalid: () => formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus(),
  })

  async function upload(file: File) {
    const url = await onUpload?.(file)
    if (typeof url === "string") form.setFieldValue("image", url)
  }

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
                disabled={!dirty || saving || uploading}
                aria-busy={saving}
              >
                {saving && <Spinner data-icon="inline-start" />}
                {saving ? t.saving : t.save}
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
        onChange={() => onEdit?.()}
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
                    {onUpload !== undefined && (
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
                            if (file !== undefined) void upload(file)
                            e.target.value = ""
                          }}
                        />
                        <Button type="button" variant="outline" disabled={uploading} aria-busy={uploading} onClick={() => fileRef.current?.click()}>
                          {uploading ? <Spinner data-icon="inline-start" /> : <UploadIcon data-icon="inline-start" aria-hidden />}
                          {uploading ? t.imageUploading : t.imageUpload}
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

/** Which email call the form is running, or null. */
export type EmailSectionPending = "change" | "confirm" | null

/** The props of EmailSectionView. */
export type EmailSectionViewProps = AccountSectionViewProps & {
  /** The account's addresses, the primary one marked. */
  readonly addresses?: readonly EmailAddress[]
  /** Where reading the addresses stands. */
  readonly listStatus?: AccountListStatus
  /** The form's running call. */
  readonly pending?: EmailSectionPending
  /** A verification resend is running. */
  readonly resending?: boolean
  /** A message above the list. */
  readonly formError?: string | null
  /** A success message above the list, already filled in. */
  readonly status?: string | null
  /** The new address a change was started for; set, the card says where the confirmation went. */
  readonly pendingEmail?: string | null
  /** How the server confirms a new address: a link mailed to it, or a code typed here. */
  readonly confirmChangeBy?: "link" | "code"
  /** The re-authentication dialog, rendered inside the card. */
  readonly reauth?: ReactNode
  /** Start a change to this address (trimmed). Awaited. */
  readonly onChange?: (email: string) => void | Promise<void>
  /** Finish a change with the code from the email (trimmed). Awaited. */
  readonly onConfirm?: (values: { readonly email: string; readonly code: string }) => void | Promise<void>
  /** Send the verification link to this address again. */
  readonly onResend?: (email: string) => void
  /** "Use a different address": drop the started change. */
  readonly onUseDifferent?: () => void
  /** Read the addresses again after a failure. */
  readonly onRetry?: () => void
}

/** The addresses with their verification state, and the change-email form, with no data layer. */
export function EmailSectionView({
  className,
  classNames,
  text,
  headingLevel = ACCOUNT_SECTION_HEADING_LEVEL,
  addresses = [],
  listStatus = "success",
  pending = null,
  resending = false,
  formError = null,
  status = null,
  pendingEmail = null,
  confirmChangeBy = "link",
  reauth,
  onChange,
  onConfirm,
  onResend,
  onUseDifferent,
  onRetry,
}: EmailSectionViewProps) {
  const t = textOf(text)
  const id = useId()
  const formRef = useRef<HTMLFormElement>(null)
  const primary = addresses.find((a) => a.primary) ?? addresses[0]

  const form = useForm({
    defaultValues: { email: "", code: "" },
    onSubmit: async ({ value }) => {
      if (pendingEmail === null) await onChange?.(value.email.trim())
      else await onConfirm?.({ email: pendingEmail, code: value.code.trim() })
    },
    onSubmitInvalid: () => formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus(),
  })

  const busy = pending !== null
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
              onUseDifferent?.()
              form.reset()
            }}
          >
            {t.emailUseDifferent}
          </Button>
        ) : (
          <>
            {codeStep && (
              <Button type="button" variant="ghost" className={classNames?.action} onClick={() => onUseDifferent?.()}>
                {t.emailUseDifferent}
              </Button>
            )}
            <Button type="submit" form={id} className={cn("ml-auto", classNames?.submit)} disabled={busy} aria-busy={busy}>
              {busy && <Spinner data-icon="inline-start" />}
              {codeStep ? (pending === "confirm" ? t.emailConfirming : t.emailConfirm) : pending === "change" ? t.emailChanging : t.emailChange}
            </Button>
          </>
        )
      }
    >
      <div className="flex flex-col gap-4">
        <FormErrorAlert message={formError} className={classNames?.formError} />
        {status !== null && <StatusAlert message={status} className={classNames?.status} />}

        {listStatus === "pending" ? (
          <Skeleton className="h-9 w-full rounded-lg" />
        ) : listStatus === "error" ? (
          <LoadError t={t} onRetry={() => onRetry?.()} />
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
                    disabled={resending}
                    aria-busy={resending}
                    onClick={() => onResend?.(a.email)}
                  >
                    {resending && <Spinner data-icon="inline-start" />}
                    {resending ? t.emailResending : t.emailResend}
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
              {fillText(codeStep ? t.emailChangeSentCode : t.emailChangeSentLink, { email: pendingEmail })}
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
      {reauth}
    </SettingsCard>
  )
}

// ---------------------------------------------------------------------------
// Password

/** The password form's fields; `next` because `new` is the wire name only. */
export type PasswordFormValues = {
  readonly current: string
  readonly next: string
  readonly confirm: string
  readonly revokeOthers: boolean
}

/** The password fields a server error can be shown under. */
export type PasswordField = "current" | "next"

/** A stable empty error map, so a default does not look like a new error on every render. */
const NO_PASSWORD_ERRORS: Readonly<Partial<Record<PasswordField, string>>> = {}

/** The props of PasswordSectionView. */
export type PasswordSectionViewProps = AccountSectionViewProps & {
  /** Whether "Sign out of other devices" starts ticked. On by default: a changed password usually means a worry. */
  readonly revokeOthersDefault?: boolean
  /** The change call is running. */
  readonly pending?: boolean
  /** A message above the form. */
  readonly formError?: string | null
  /** Messages under a field, by field; focus moves to the first one when they change. */
  readonly fieldErrors?: Readonly<Partial<Record<PasswordField, string>>>
  /** The password was changed: the form clears and "Password changed" shows until it is edited again. */
  readonly saved?: boolean
  /** The re-authentication dialog, rendered inside the card. */
  readonly reauth?: ReactNode
  /** The form passed its checks. Awaited. */
  readonly onSubmit?: (values: PasswordFormValues) => void | Promise<void>
  /** The form was edited; a good moment to hide "Password changed". */
  readonly onEdit?: () => void
}

/** The change-password form, with no data layer. */
export function PasswordSectionView({
  className,
  classNames,
  text,
  headingLevel = ACCOUNT_SECTION_HEADING_LEVEL,
  revokeOthersDefault = true,
  pending = false,
  formError = null,
  fieldErrors = NO_PASSWORD_ERRORS,
  saved = false,
  reauth,
  onSubmit,
  onEdit,
}: PasswordSectionViewProps) {
  const t = textOf(text)
  const id = useId()
  const formRef = useRef<HTMLFormElement>(null)

  const defaultValues: PasswordFormValues = { current: "", next: "", confirm: "", revokeOthers: revokeOthersDefault }

  const form = useForm({
    defaultValues,
    onSubmit: async ({ value }) => {
      await onSubmit?.(value)
    },
    onSubmitInvalid: () => formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus(),
  })

  // A changed password clears the form, whichever way the change finished
  // (the form's own submit or a retry after re-authentication).
  useEffect(() => {
    if (saved) form.reset()
  }, [saved, form])

  // A server error under a field moves focus there, as a failed check does.
  useEffect(() => {
    if (Object.keys(fieldErrors).length > 0) formRef.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus()
  }, [fieldErrors])

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
          <Button type="submit" form={id} className={cn("ml-auto", classNames?.submit)} disabled={pending} aria-busy={pending}>
            {pending && <Spinner data-icon="inline-start" />}
            {pending ? t.passwordChanging : t.passwordChange}
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
        onChange={() => onEdit?.()}
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
      {reauth}
    </SettingsCard>
  )
}

// ---------------------------------------------------------------------------
// Sessions

/** The props of SessionsSectionView. */
export type SessionsSectionViewProps = AccountSectionViewProps & {
  /** The user's sessions, in the order to show them (the current one first reads best). */
  readonly sessions?: readonly AuthSessionView[]
  /** Where reading the sessions stands. */
  readonly listStatus?: AccountListStatus
  /** A sign-out is running: the buttons are disabled and the dialog shows its progress. */
  readonly revoking?: boolean
  /** A message above the list. */
  readonly formError?: string | null
  /** Sign these sessions out, after the user confirmed in the dialog. Awaited; the dialog closes when it settles. */
  readonly onRevoke?: (ids: readonly string[]) => void | Promise<void>
  /** A sign-out was started; a good moment to clear an old message. */
  readonly onClearError?: () => void
  /** Read the sessions again after a failure. */
  readonly onRetry?: () => void
}

/** What the sign-out dialog asks about: one session, or every other one. */
type RevokeTarget = { readonly kind: "one"; readonly session: AuthSessionView } | { readonly kind: "others" }

/** Every session of the user, each revocable, plus "sign out of all others", with no data layer. */
export function SessionsSectionView({
  className,
  classNames,
  text,
  headingLevel = ACCOUNT_SECTION_HEADING_LEVEL,
  sessions = [],
  listStatus = "success",
  revoking = false,
  formError = null,
  onRevoke,
  onClearError,
  onRetry,
}: SessionsSectionViewProps) {
  const t = textOf(text)
  const [confirming, setConfirming] = useState<RevokeTarget | null>(null)
  const others = sessions.filter((s) => !s.current)
  const locale = localeOf(t)

  async function revoke(target: RevokeTarget) {
    await onRevoke?.(target.kind === "others" ? others.map((s) => s.id) : [target.session.id])
    setConfirming(null)
  }

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
            disabled={revoking}
            onClick={() => {
              onClearError?.()
              setConfirming({ kind: "others" })
            }}
          >
            {t.revokeOthers}
          </Button>
        ) : listStatus === "success" ? (
          <p className="text-[13px] text-muted-foreground">{t.noOtherSessions}</p>
        ) : null
      }
    >
      <div className="flex flex-col gap-3">
        <FormErrorAlert message={formError} className={classNames?.formError} />
        {listStatus === "pending" ? (
          <div className="flex flex-col gap-2">
            <Skeleton className="h-12 w-full rounded-lg" />
            <Skeleton className="h-12 w-full rounded-lg" />
          </div>
        ) : listStatus === "error" ? (
          <LoadError t={t} onRetry={() => onRetry?.()} />
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
                      {s.current ? t.activeNow : fillText(t.lastActive, { time: relativeTime(s.lastSeenAt, locale) })}
                    </span>
                  </div>
                  {!s.current && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className={cn("shrink-0", classNames?.action)}
                      disabled={revoking}
                      aria-label={`${t.revoke}: ${name}`}
                      onClick={() => {
                        onClearError?.()
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
        onOpenChange={(open) => !open && !revoking && setConfirming(null)}
        title={confirming?.kind === "others" ? t.revokeOthersTitle : t.revokeTitle}
        description={
          confirming?.kind === "others"
            ? fillText(t.revokeOthersDescription, { count: others.length })
            : confirming?.kind === "one"
              ? fillText(t.revokeDescription, { device: deviceLabel(confirming.session.userAgent, t) })
              : ""
        }
        confirmLabel={revoking ? t.revoking : t.revoke}
        cancelLabel={t.cancel}
        pending={revoking}
        onConfirm={() => {
          if (confirming !== null) void revoke(confirming)
        }}
        className={classNames?.dialog}
      />
    </SettingsCard>
  )
}

// ---------------------------------------------------------------------------
// Linked accounts

/** An OAuth provider the server offers: its id and its display name. */
export type AccountProvider = { readonly id: string; readonly name: string }

/** The props of LinkedAccountsSectionView. */
export type LinkedAccountsSectionViewProps = AccountSectionViewProps & {
  /** Every configured provider, one row each (or one per linked account of it). */
  readonly providers?: readonly AccountProvider[]
  /** The user's linked accounts. */
  readonly accounts?: readonly OauthAccount[]
  /** Where reading the providers and accounts stands. */
  readonly listStatus?: AccountListStatus
  /** The provider the browser is leaving for to link, or null. */
  readonly redirecting?: string | null
  /** An unlink is running. */
  readonly unlinking?: boolean
  /** A message above the list. */
  readonly formError?: string | null
  /** Icons per provider id, over the built-in GitHub and Google marks; other providers show their initial. */
  readonly providerIcons?: Readonly<Record<string, ReactNode>>
  /** The re-authentication dialog, rendered inside the card. */
  readonly reauth?: ReactNode
  /** Connect was pressed for this provider. */
  readonly onLink?: (provider: string) => void
  /** Disconnect this account, after the user confirmed in the dialog. Awaited; the dialog closes when it settles. */
  readonly onUnlink?: (account: OauthAccount) => void | Promise<void>
  /** A disconnect was started; a good moment to clear an old message. */
  readonly onClearError?: () => void
  /** Read the accounts again after a failure. */
  readonly onRetry?: () => void
}

/** Every configured OAuth provider, linked accounts with Disconnect and the rest with Connect, with no data layer. */
export function LinkedAccountsSectionView({
  className,
  classNames,
  text,
  headingLevel = ACCOUNT_SECTION_HEADING_LEVEL,
  providers = [],
  accounts = [],
  listStatus = "success",
  redirecting = null,
  unlinking = false,
  formError = null,
  providerIcons,
  reauth,
  onLink,
  onUnlink,
  onClearError,
  onRetry,
}: LinkedAccountsSectionViewProps) {
  const t = textOf(text)
  const [confirming, setConfirming] = useState<OauthAccount | null>(null)
  const locale = localeOf(t)
  const nameOf = (provider: string) => providers.find((p) => p.id === provider)?.name ?? provider

  async function unlink(account: OauthAccount) {
    await onUnlink?.(account)
    setConfirming(null)
  }

  return (
    <SettingsCard level={headingLevel} title={t.linkedTitle} description={t.linkedDescription} className={className} classNames={classNames}>
      <div className="flex flex-col gap-3">
        <FormErrorAlert message={formError} className={classNames?.formError} />
        {listStatus === "pending" ? (
          <div className="flex flex-col gap-2">
            <Skeleton className="h-12 w-full rounded-lg" />
            <Skeleton className="h-12 w-full rounded-lg" />
          </div>
        ) : listStatus === "error" ? (
          <LoadError t={t} onRetry={() => onRetry?.()} />
        ) : (
          <ul className={cn("flex flex-col divide-y rounded-lg border", classNames?.list)} aria-label={t.linkedTitle}>
            {providers.map((p) => {
              const linked = accounts.filter((a) => a.provider === p.id)
              const rows: ReadonlyArray<OauthAccount | null> = linked.length === 0 ? [null] : linked
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
                          {fillText(t.linkedOn, { date: shortDate(account.createdAt, locale) })}
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
                      onClick={() => onLink?.(p.id)}
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
                      disabled={unlinking}
                      aria-label={`${t.unlink}: ${p.name}${account.email === "" ? "" : ` (${account.email})`}`}
                      onClick={() => {
                        onClearError?.()
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
        onOpenChange={(open) => !open && !unlinking && setConfirming(null)}
        title={t.unlinkTitle}
        description={confirming === null ? "" : fillText(t.unlinkDescription, { provider: nameOf(confirming.provider), email: confirming.email })}
        confirmLabel={unlinking ? t.unlinking : t.unlink}
        cancelLabel={t.cancel}
        pending={unlinking}
        onConfirm={() => {
          if (confirming !== null) void unlink(confirming)
        }}
        className={classNames?.dialog}
      />
      {reauth}
    </SettingsCard>
  )
}

// ---------------------------------------------------------------------------
// Security

/** The props of SecuritySectionView: the cards it stacks, each a slot. */
export type SecuritySectionViewProps = {
  readonly className?: string
  /** The second-factor card (TwoFactorSetup in the wired section). */
  readonly twoFactor?: ReactNode
  /** The passkeys card (PasskeyList in the wired section). */
  readonly passkeys?: ReactNode
  /** The re-authentication dialog the cards share. */
  readonly reauth?: ReactNode
  /** Replaces the two cards, for an app with its own second-factor UI. */
  readonly children?: ReactNode
}

/** The column the security cards stand in; the cards bring their own frames and headings. */
export function SecuritySectionView({ className, twoFactor, passkeys, reauth, children }: SecuritySectionViewProps) {
  return (
    <div className={cn("flex flex-col gap-4", className)}>
      {children ?? (
        <>
          {twoFactor}
          {passkeys}
        </>
      )}
      {reauth}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Delete account

/** The props of DeleteAccountSectionView. */
export type DeleteAccountSectionViewProps = AccountSectionViewProps & {
  /** Whether the confirmation dialog is open. */
  readonly open?: boolean
  /** The dialog asks to open or close; refused while the deletion runs. */
  readonly onOpenChange?: (open: boolean) => void
  /** The deletion is running. */
  readonly pending?: boolean
  /** A message in the dialog. */
  readonly formError?: string | null
  /** The server mailed a confirmation link instead of deleting. */
  readonly linkSent?: boolean
  /** The confirmation word was typed and the delete button pressed. */
  readonly onDelete?: () => void
  /** The dialog was opened from the button; a good moment to clear an old message. */
  readonly onClearError?: () => void
  /** The re-authentication dialog, rendered inside the card. */
  readonly reauth?: ReactNode
}

/** The delete-account card and its typed-confirmation dialog, with no data layer. */
export function DeleteAccountSectionView({
  className,
  classNames,
  text,
  headingLevel = ACCOUNT_SECTION_HEADING_LEVEL,
  open = false,
  onOpenChange,
  pending = false,
  formError = null,
  linkSent = false,
  onDelete,
  onClearError,
  reauth,
}: DeleteAccountSectionViewProps) {
  const t = textOf(text)
  const id = useId()
  const [typed, setTyped] = useState("")
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
            onClearError?.()
            onOpenChange?.(true)
          }}
        >
          {t.deleteButton}
        </Button>
      </CardFooter>
      <Dialog open={open} onOpenChange={(next) => !pending && onOpenChange?.(next)}>
        <DialogContent className={classNames?.dialog} showCloseButton={!pending}>
          <form
            noValidate
            className="contents"
            onSubmit={(e) => {
              e.preventDefault()
              if (matches && !pending) onDelete?.()
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
                {fillText(t.deleteConfirmLabel, { word })}
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
              <Button type="button" variant="outline" disabled={pending} onClick={() => onOpenChange?.(false)}>
                {t.cancel}
              </Button>
              <Button
                type="submit"
                variant="destructive"
                className={cn("bg-destructive text-white hover:bg-destructive/90 dark:bg-destructive/80", classNames?.dangerAction)}
                disabled={!matches || pending}
                aria-busy={pending}
              >
                {pending && <Spinner data-icon="inline-start" />}
                {pending ? t.deleting : t.deleteConfirm}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      {reauth}
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Re-authentication

/** Which re-authentication call runs: the password, the second-factor code, the passkey, or null. */
export type ReauthPending = "password" | "code" | "passkey" | null

/** The props of ReauthDialogView: the dialog's step and state come in, every action goes out. */
export type ReauthDialogViewProps = {
  /** Classes per named part (dialog, field, label, input, fieldError, formError, submit). */
  readonly classNames?: AccountSettingsClassNames
  /** Text overrides, merged over ACCOUNT_SETTINGS_TEXT. */
  readonly text?: Partial<AccountSettingsText>
  readonly open: boolean
  /** The dialog asks to close (Escape, outside press, the close button); ignored by the view while busy. */
  readonly onOpenChange?: (open: boolean) => void
  /** "password" asks for the password; "code" for the second-factor code. */
  readonly step?: "password" | "code"
  /** The password can be used here; off, the dialog offers the sign-in page instead. */
  readonly canPassword?: boolean
  /** The passkey button shows. */
  readonly canPasskey?: boolean
  /** Linked provider accounts to confirm with, one button each. */
  readonly providers?: readonly AccountProvider[]
  /** The code was mailed or texted just now, which changes the hint. */
  readonly codeSent?: boolean
  /** The running call. */
  readonly pending?: ReauthPending
  /** The provider the browser is leaving for, or whose call runs; its button says so. */
  readonly providerPending?: string | null
  /** A message above the field. */
  readonly formError?: string | null
  /** A message under the field; set, the field is marked invalid. */
  readonly fieldError?: string | null
  /** The address for the hidden username field, so a password manager fills the right account. */
  readonly email?: string | null
  readonly password?: string
  readonly code?: string
  readonly onPasswordChange?: (password: string) => void
  readonly onCodeChange?: (code: string) => void
  /** Continue was pressed with the field filled in. */
  readonly onConfirm?: () => void
  /** Continue was pressed with the field empty. */
  readonly onEmpty?: () => void
  /** "Sign in again" was pressed (no password here). */
  readonly onSignInAgain?: () => void
  readonly onPasskey?: () => void
  readonly onProvider?: (provider: string) => void
  /** Cancel was pressed. */
  readonly onCancel?: () => void
}

/** The "Confirm it's you" dialog, with no data layer. */
export function ReauthDialogView({
  classNames,
  text,
  open,
  onOpenChange,
  step = "password",
  canPassword = true,
  canPasskey = false,
  providers = [],
  codeSent = false,
  pending = null,
  providerPending = null,
  formError = null,
  fieldError = null,
  email = null,
  password = "",
  code = "",
  onPasswordChange,
  onCodeChange,
  onConfirm,
  onEmpty,
  onSignInAgain,
  onPasskey,
  onProvider,
  onCancel,
}: ReauthDialogViewProps) {
  const t = textOf(text)
  const id = useId()
  const codeStep = step === "code"
  const canProvider = providers.length > 0
  const busy = pending !== null || providerPending !== null
  const confirming = pending === "password" || pending === "code"
  const invalid = fieldError !== null
  const fieldId = codeStep ? `${id}-code` : `${id}-password`

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (busy) return
        onOpenChange?.(next)
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
              onSignInAgain?.()
              return
            }
            if ((codeStep ? code.trim() : password) === "") {
              onEmpty?.()
              document.getElementById(fieldId)?.focus()
              return
            }
            onConfirm?.()
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
          <FormErrorAlert message={formError} className={classNames?.formError} />
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
                  onChange={(e) => onCodeChange?.(e.target.value)}
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
                    onChange={(e) => onPasswordChange?.(e.target.value)}
                    aria-invalid={invalid}
                    aria-describedby={invalid ? `${fieldId}-error` : undefined}
                    className={classNames?.input}
                  />
                </>
              )}
              {invalid && (
                <FieldError id={`${fieldId}-error`} className={classNames?.fieldError}>
                  {fieldError}
                </FieldError>
              )}
            </Field>
          )}
          {canProvider && !codeStep && (
            <div className="flex flex-col gap-2">
              {providers.map((p) => {
                const leaving = providerPending === p.id
                return (
                  <Button key={p.id} type="button" variant="outline" disabled={busy} aria-busy={leaving} onClick={() => onProvider?.(p.id)}>
                    {leaving && <Spinner data-icon="inline-start" />}
                    {fillText(leaving ? t.reauthProviderPending : t.reauthProvider, { provider: p.name })}
                  </Button>
                )
              })}
            </div>
          )}
          <DialogFooter className="sm:justify-between">
            {canPasskey && !codeStep ? (
              <Button type="button" variant="ghost" disabled={busy} onClick={() => onPasskey?.()}>
                {pending === "passkey" ? <Spinner data-icon="inline-start" /> : <KeyRoundIcon data-icon="inline-start" aria-hidden />}
                {pending === "passkey" ? t.reauthPasskeyPending : t.reauthPasskey}
              </Button>
            ) : (
              <span />
            )}
            <div className="flex flex-col-reverse gap-2 sm:flex-row">
              <Button type="button" variant="outline" disabled={busy} onClick={() => onCancel?.()}>
                {t.cancel}
              </Button>
              <Button type="submit" disabled={busy} aria-busy={confirming} className={classNames?.submit}>
                {confirming && <Spinner data-icon="inline-start" />}
                {canPassword || codeStep ? (confirming ? t.reauthConfirming : t.reauthConfirm) : t.reauthSignInAgain}
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
  level: ViewHeadingLevel
  footer?: ReactNode
  className?: string
  classNames?: AccountSettingsClassNames
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
  classNames?: AccountSettingsClassNames
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

/** A failed call's message as a destructive alert; nothing when there is none. */
function FormErrorAlert({ message, className }: { message: string | null; className?: string }) {
  if (message === null) return null
  return (
    <Alert variant="destructive" className={className}>
      <CircleAlertIcon aria-hidden />
      <AlertDescription>{message}</AlertDescription>
    </Alert>
  )
}

/** A success message as a status alert. */
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

/** A failed list read, with a retry. */
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

/** The sections' stand-in while the account loads. */
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

/** "Chrome on macOS", or the unknown-device text. */
function deviceLabel(userAgent: string, t: AccountSettingsText): string {
  const device = describeAgent(userAgent)
  return device === null ? t.unknownDevice : fillText(t.deviceName, { browser: device.browser, os: device.os })
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
