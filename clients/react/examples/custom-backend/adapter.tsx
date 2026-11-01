// Way (c) of docs/client/custom-backend.md: no HTTP translation at all. An
// object with the client's method names, written over another identity SDK,
// is handed to <AuthProvider client={…}>, and the wired components call it
// as if it were createAuthClient's. Every method answers `{ data, error }`
// and never throws; the codes the components branch on are the library's
// (password.invalid_credentials, auth.signed_out). The compiler checks the
// object against AnyAuthClient and KnownPlugins, so a missing method or a
// wrong shape fails `tsc`. test/custom-backend.test.tsx signs in through it.

import type { AuthDone, AuthError, AuthResult, AuthSessionResult, PasswordSignInResult } from "@ubgo/auth-client"
import { AuthProvider, type AnyAuthClient, type KnownPlugins } from "@ubgo/auth-react"
import { useState } from "react"

import { SignInForm } from "@/components/auth/sign-in-form"

/** Another vendor's identity SDK, as an app already has it: throws on failure, has its own user shape. */
export interface IdentitySdk {
  signIn(email: string, password: string): Promise<{ readonly uid: string; readonly displayName: string }>
  currentUser(): { readonly uid: string; readonly displayName: string } | null
  signOut(): Promise<void>
}

/** The error an IdentitySdk throws, with its own code. */
export class IdentitySdkError extends Error {
  constructor(readonly code: "wrong-password" | "user-not-found" | "network") {
    super(code)
  }
}

/** A failed result with one of the library's codes, the shape every adapter method answers on failure. */
function fail(code: AuthError["code"], message: string, status: number): { readonly data: null; readonly error: AuthError } {
  return { data: null, error: { code, rawCode: code, message, status } }
}

/**
 * The answer of an operation the SDK has no equivalent for. The raw code
 * says which; the components show the client's friendly message for
 * client.unknown_code.
 */
async function unsupported(op: string): Promise<{ readonly data: null; readonly error: AuthError }> {
  return { data: null, error: { code: "client.unknown_code", rawCode: `adapter.unsupported.${op}`, message: `${op} is not available.`, status: 501 } }
}

/** What the adapter must have for SignInForm: the core methods, plus the password plugin's namespace. */
// ds:def id=signinadapter-khybttxg owner=@khanakia stability=stable
export type SignInAdapter = AnyAuthClient & { readonly password: KnownPlugins["password"] }

/** Maps an SDK user to the library's session answer. */
function sessionOf(user: { readonly uid: string; readonly displayName: string }): AuthSessionResult {
  return { user: { id: user.uid, name: user.displayName, image: "" }, expiresAt: new Date(Date.now() + 3_600_000).toISOString() }
}

/** The core methods over the SDK. session() and signOut() are what the provider and every sign-in use; the rest belong to account pages. */
// ds:def id=sdkcore-f93225u3 owner=@khanakia stability=stable
export function sdkCore(sdk: IdentitySdk): AnyAuthClient {
  const session = async (): Promise<AuthResult<AuthSessionResult>> => {
    const user = sdk.currentUser()
    return user === null ? fail("auth.signed_out", "Sign in to continue.", 401) : { data: sessionOf(user), error: null }
  }
  const signOut = async (): Promise<AuthResult<AuthDone>> => {
    await sdk.signOut()
    return { data: { ok: true }, error: null }
  }
  return {
    session,
    sessionRefresh: session,
    signOut,
    signOutAll: signOut,
    accountDelete: () => unsupported("accountDelete"),
    accountDeleteConfirm: () => unsupported("accountDeleteConfirm"),
    deviceSessions: () => unsupported("deviceSessions"),
    deviceSessionsRevoke: () => unsupported("deviceSessionsRevoke"),
    deviceSessionsSwitch: () => unsupported("deviceSessionsSwitch"),
    profile: () => unsupported("profile"),
    sessions: () => unsupported("sessions"),
    sessionsRevoke: () => unsupported("sessionsRevoke"),
  }
}

/** The password plugin's namespace over the SDK. Its presence is what makes SignInForm show the password form. */
// ds:def id=sdkpassword-4ca8yqjn owner=@khanakia stability=stable
export function sdkPassword(sdk: IdentitySdk): KnownPlugins["password"] {
  return {
    async signIn(input): Promise<AuthResult<PasswordSignInResult>> {
      try {
        const user = await sdk.signIn(input.identifier, input.password)
        return { data: { user: { id: user.uid, name: user.displayName, image: "" }, verificationRequired: false, secondFactorRequired: false }, error: null }
      } catch (cause) {
        if (cause instanceof IdentitySdkError && cause.code === "network") return fail("client.network_error", "The request did not reach the server.", 0)
        // Wrong password and unknown account answer alike, so the form does not tell which emails have accounts.
        return fail("password.invalid_credentials", "Wrong email or password.", 401)
      }
    },
    signUp: () => unsupported("password.signUp"),
    change: () => unsupported("password.change"),
    forgot: () => unsupported("password.forgot"),
    reauthenticate: () => unsupported("password.reauthenticate"),
    reset: () => unsupported("password.reset"),
    verify: () => unsupported("password.verify"),
  }
}

/** The adapter: the core and the password namespace, the client's shape with each method answering `{ data, error }`. */
// ds:def id=sdkadapter-9pazz82r owner=@khanakia stability=stable
export function sdkAdapter(sdk: IdentitySdk): SignInAdapter {
  return { ...sdkCore(sdk), password: sdkPassword(sdk) }
}

/** The page: the wired SignInForm, unchanged, over the adapter. */
// ds:def id=sdksigninpage-ezyjqyy9 owner=@khanakia stability=stable
export function SdkSignInPage({ sdk, onSignedIn }: { readonly sdk: IdentitySdk; readonly onSignedIn: (userId: string) => void }) {
  const [client] = useState(() => sdkAdapter(sdk))
  return (
    <AuthProvider client={client}>
      <SignInForm showSignUp={false} onSuccess={(result) => onSignedIn(result.userId)} />
    </AuthProvider>
  )
}
