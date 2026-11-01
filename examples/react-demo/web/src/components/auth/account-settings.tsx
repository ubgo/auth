import { useMutation, useQuery } from "@tanstack/react-query"
import { isAuthErrorCode, type AuthError, type AuthReauthentication, type AuthSessionResult, type AuthUserView, type OauthAccount } from "@ubgo/auth-client"
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
import { Fragment, useEffect, useRef, useState, type ReactNode } from "react"

import {
  ACCOUNT_SECTIONS,
  ACCOUNT_SECTION_HEADING_LEVEL,
  ACCOUNT_SETTINGS_TEXT,
  AccountSettingsView,
  DeleteAccountSectionView,
  EmailSectionView,
  LinkedAccountsSectionView,
  PasswordSectionView,
  ProfileSectionView,
  ReauthDialogView,
  SecuritySectionView,
  SessionsSectionView,
  type AccountListStatus,
  type AccountSection,
  type AccountSettingsSlot,
  type AccountSettingsText,
  type EmailSectionPending,
  type PasswordField,
  type PasswordFormValues,
  type ProfileValues,
  type ReauthPending,
} from "@/components/auth/account-settings-view"
import { PasskeyList } from "@/components/auth/passkey-list"
import { TwoFactorSetup } from "@/components/auth/two-factor-setup"
import { EMAIL_LIST_QUERY_KEY, usePrimaryEmail } from "@/components/auth/user-button"
import { cn } from "@/lib/utils"

// AccountSettings: the signed-in user's account page, made of sections that
// are also exported on their own (ProfileSection, EmailSection,
// PasswordSection, SessionsSection, LinkedAccountsSection, SecuritySection,
// DeleteAccountSection). Each section renders only when the client has its
// plugin. Operations that need a recent sign-in (change the password, the
// email, unlink, delete) ask for the password or a passkey in a dialog when
// the server answers auth.fresh_session_required, then retry by themselves.
//
// What each section draws is its view in account-settings-view.tsx
// (ProfileSectionView, ..., ReauthDialogView, AccountSettingsView): this file
// only wires them to @ubgo/auth-react, the calls, the cached lists and
// navigation.

export {
  ACCOUNT_SECTIONS,
  ACCOUNT_SETTINGS_TEXT,
  AccountSettingsView,
  DeleteAccountSectionView,
  EmailSectionView,
  LinkedAccountsSectionView,
  PasswordSectionView,
  ProfileSectionView,
  ReauthDialogView,
  SecuritySectionView,
  SessionsSectionView,
  describeAgent,
  type AccountSection,
  type AccountSettingsSlot,
  type AccountSettingsText,
} from "@/components/auth/account-settings-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    accountSettings: AccountSettingsText
  }
}

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

/** A section's heading level when used on its own (h2); the view holds the value. */
const SECTION_HEADING_LEVEL: HeadingLevel = ACCOUNT_SECTION_HEADING_LEVEL

/** One heading level below `level`, never past h6. */
function below(level: HeadingLevel): HeadingLevel {
  return level >= 6 ? 6 : ((level + 1) as HeadingLevel)
}

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

/** Where a TanStack query stands, in the views' terms. */
function listStatusOf(query: { readonly isPending: boolean; readonly isError: boolean }): AccountListStatus {
  return query.isPending ? "pending" : query.isError ? "error" : "success"
}

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
    <AccountSettingsView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      hideHeader={hideHeader}
      loading={isPending}
      confirmed={confirmed || returned?.status === "fresh"}
      formError={returned?.status === "failed" ? messageFor({ code: returned.code, rawCode: returned.code, message: "", status: 0 }) : null}
      dialog={
        returned?.status === "second_factor" && user !== null ? (
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
        ) : null
      }
      trailing={!sections.includes("delete") && children}
    >
      {user === null ? null : rendered}
    </AccountSettingsView>
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
  const [formError, setFormError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  const save = useMutation({
    mutationFn: (value: ProfileValues) => client.profile({ name: value.name.trim(), image: value.image.trim() }),
    onSuccess: ({ data, error }) => {
      if (error !== null) {
        setFormError(messageFor(error))
        return
      }
      // The answer is the new user view: put it in the session entry so the
      // header's avatar changes without another read.
      queryClient.setQueryData<AuthSessionResult | null>(SESSION_QUERY_KEY, (old) => (old == null ? old : { ...old, user: data }))
      setSaved(true)
      onSuccess?.({ section: "profile", user: data })
    },
  })

  const upload = useMutation({
    mutationFn: async (file: File) => {
      if (onUploadImage === undefined) throw new Error("ProfileSection: onUploadImage missing")
      return onUploadImage(file)
    },
    onError: (error) => setFormError(error instanceof Error ? error.message : String(error)),
  })

  return (
    <ProfileSectionView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      user={user}
      email={email}
      saving={save.isPending}
      uploading={upload.isPending}
      formError={formError}
      saved={saved}
      onEdit={() => setSaved(false)}
      onSubmit={async (value) => {
        setFormError(null)
        setSaved(false)
        // The saved user view resets the form, so the fields show what the server kept.
        const { data } = await save.mutateAsync(value)
        return data === null ? null : { name: data.name, image: data.image }
      }}
      onUpload={
        onUploadImage === undefined
          ? undefined
          : // A failed upload is shown by onError above; the field keeps its value.
            (file) => upload.mutateAsync(file).catch(() => null)
      }
    />
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

  if (emailClient === null || session === null) return null

  const pending: EmailSectionPending = change.isPending ? "change" : confirm.isPending ? "confirm" : null

  return (
    <EmailSectionView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      addresses={list.data ?? []}
      listStatus={listStatusOf(list)}
      pending={pending}
      resending={resend.isPending}
      formError={formError}
      status={status}
      pendingEmail={pendingEmail}
      confirmChangeBy={confirmChangeBy}
      reauth={reauth.element}
      onChange={async (address) => {
        setFormError(null)
        setStatus(null)
        await change.mutateAsync(address)
      }}
      onConfirm={async (value) => {
        setFormError(null)
        setStatus(null)
        await confirm.mutateAsync({ email: value.email, code: value.code })
      }}
      onResend={(address) => {
        setFormError(null)
        setStatus(null)
        resend.mutate(address)
      }}
      onUseDifferent={() => setPendingEmail(null)}
      onRetry={() => void list.refetch()}
    />
  )
}

// ---------------------------------------------------------------------------
// Password

export type PasswordSectionProps = AccountSectionProps<"password"> & {
  /** Whether "Sign out of other devices" starts ticked. On by default: a changed password usually means a worry. */
  readonly revokeOthersDefault?: boolean
}

/** Error codes that belong under one of the password fields. */
const PASSWORD_FIELD_OF_ERROR: Readonly<Partial<Record<string, PasswordField>>> = {
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
  const [formError, setFormError] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<PasswordField, string>>>({})
  const [saved, setSaved] = useState(false)

  const change = useMutation({
    mutationFn: (value: PasswordFormValues) => {
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
        return
      }
      // saved clears the view's form, however the change finished.
      setSaved(true)
      await queryClient.invalidateQueries({ queryKey: SESSIONS_QUERY_KEY })
      onSuccess?.({ section: "password", revokedOthers: value.revokeOthers })
    },
  })

  if (passwordClient === null || session === null) return null

  return (
    <PasswordSectionView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      revokeOthersDefault={revokeOthersDefault}
      pending={change.isPending}
      formError={formError}
      fieldErrors={fieldErrors}
      saved={saved}
      reauth={reauth.element}
      onEdit={() => setSaved(false)}
      onSubmit={async (value) => {
        setFormError(null)
        setFieldErrors({})
        setSaved(false)
        await change.mutateAsync(value)
      }}
    />
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
      if (error !== null) {
        setFormError(messageFor(error))
        return
      }
      onSuccess?.({ section: "sessions", revoked: ids })
    },
  })

  if (session === null) return null

  return (
    <SessionsSectionView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      sessions={list.data ?? []}
      listStatus={listStatusOf(list)}
      revoking={revoke.isPending}
      formError={formError}
      onClearError={() => setFormError(null)}
      onRevoke={async (ids) => {
        // The view closes its dialog once this settles; a thrown call has no message of its own.
        await revoke.mutateAsync(ids).catch(() => undefined)
      }}
      onRetry={() => void list.refetch()}
    />
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
  const [redirecting, setRedirecting] = useState<string | null>(null)

  const list = useLinkedAccounts(true)

  const unlink = useMutation({
    mutationFn: (account: OauthAccount) => {
      if (oauth === null) throw new Error("LinkedAccountsSection: oauth plugin missing")
      return oauth.unlink({ provider: account.provider, accountId: account.id })
    },
    onSuccess: async ({ error }, account) => {
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

  /** Linking is the start route with link=true, a page navigation that comes back here. */
  function startLink(provider: string) {
    setRedirecting(provider)
    const here = window.location.pathname + window.location.search
    window.location.assign(oauthStartURL(baseURL, provider, { returnTo: here, errorTo: here, link: true }))
  }

  return (
    <LinkedAccountsSectionView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      providers={providers}
      accounts={list.data ?? []}
      listStatus={providersPending ? "pending" : listStatusOf(list)}
      redirecting={redirecting}
      unlinking={unlink.isPending}
      formError={formError}
      providerIcons={providerIcons}
      reauth={reauth.element}
      onLink={startLink}
      onUnlink={async (account) => {
        // The view closes its dialog once this settles; a thrown call has no message of its own.
        await unlink.mutateAsync(account).catch(() => undefined)
      }}
      onClearError={() => setFormError(null)}
      onRetry={() => void list.refetch()}
    />
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
    <SecuritySectionView
      className={className}
      twoFactor={twofactor !== null && <TwoFactorSetup headingLevel={headingLevel} onFreshSessionRequired={freshRequired} className={cn("max-w-none", twoFactorClassName)} />}
      passkeys={passkey !== null && <PasskeyList headingLevel={headingLevel} onFreshSessionRequired={freshRequired} className={cn("max-w-none", passkeysClassName)} />}
      reauth={reauth.element}
    >
      {children}
    </SecuritySectionView>
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
  const [open, setOpen] = useState(false)
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

  return (
    <DeleteAccountSectionView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      open={open}
      onOpenChange={setOpen}
      pending={remove.isPending}
      formError={formError}
      linkSent={linkSent}
      reauth={reauth.element}
      onClearError={() => setFormError(null)}
      onDelete={() => {
        setFormError(null)
        remove.mutate()
      }}
    />
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
  const linkedProviders = unsupported ? [] : providers.filter((p) => (linked.data ?? []).some((a) => a.provider === p.id))
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

  const pending: ReauthPending = viaPassword.isPending ? "password" : viaCode.isPending ? "code" : viaPasskey.isPending ? "passkey" : null
  const providerPending = leavingFor ?? (viaProvider.isPending ? (viaProvider.variables ?? null) : null)

  return (
    <ReauthDialogView
      classNames={classNames}
      text={t}
      open={open}
      onOpenChange={(next) => {
        if (!next) close()
        else onOpenChange(next)
      }}
      step={codeStep ? "code" : "password"}
      canPassword={canPassword}
      canPasskey={canPasskey}
      providers={linkedProviders}
      codeSent={codeSent}
      pending={pending}
      providerPending={providerPending}
      // The sign-in fallback's own description already says what the alert would.
      formError={error !== null && !invalid && !(unsupported && error === t.reauthSignInDescription) ? error : null}
      fieldError={invalid ? (error ?? (codeStep ? t.reauthCodeRequired : t.reauthPasswordRequired)) : null}
      email={email}
      password={password}
      code={code}
      onPasswordChange={(value) => {
        setPassword(value)
        setInvalid(false)
      }}
      onCodeChange={(value) => {
        setCode(value)
        setInvalid(false)
      }}
      onSignInAgain={() => {
        // No password here, or a server that cannot refresh sessions: sign in again and come back.
        navigate(`${paths.signIn}${paths.signIn.includes("?") ? "&" : "?"}redirectTo=${encodeURIComponent(here())}`)
      }}
      onEmpty={() => {
        setError(null)
        setInvalid(true)
      }}
      onConfirm={() => {
        setError(null)
        setInvalid(false)
        if (codeStep) viaCode.mutate()
        else viaPassword.mutate()
      }}
      onPasskey={() => {
        setError(null)
        setInvalid(false)
        viaPasskey.mutate()
      }}
      onProvider={(provider) => {
        setError(null)
        setInvalid(false)
        viaProvider.mutate(provider)
      }}
      onCancel={close}
    />
  )
}

// ---------------------------------------------------------------------------
// Data-layer helpers

/** A failed list read, carried through TanStack Query's error channel with its AuthError. */
class AuthCallError extends Error {
  readonly error: AuthError
  constructor(error: AuthError) {
    super(error.message)
    this.name = "AuthCallError"
    this.error = error
  }
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
