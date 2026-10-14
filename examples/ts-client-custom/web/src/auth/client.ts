// Generated from the operation list of github.com/ubgo/auth (authhttp.TypeScriptClient). Do not edit.

import type { AnyPlugin, AuthClient, ClientOptions, EmptyInput, Fill, Op, Plugin } from "./runtime.ts";
import { createClient } from "./runtime.ts";

/** The JSON of Go type auth.Done. */
export interface AuthDone {
  ok: boolean;
}

/** The JSON of Go type auth.ProfileRequest. */
export interface AuthProfileRequest {
  name?: string | null;
  image?: string | null;
  fields?: { [key: string]: unknown } | null;
}

/** The JSON of Go type auth.Reauthentication. */
export interface AuthReauthentication {
  fresh: boolean;
  freshUntil?: string | null;
  secondFactorRequired: boolean;
  ticket?: string;
}

/** The JSON of Go type auth.RevokeSessionRequest. */
export interface AuthRevokeSessionRequest {
  id: string;
}

/** The JSON of Go type auth.SessionResult. */
export interface AuthSessionResult {
  user: AuthUserView;
  expiresAt: string;
  extras?: unknown;
  needsRefresh?: boolean;
  tasks?: string[] | null;
}

/** The JSON of Go type auth.SessionView. */
export interface AuthSessionView {
  id: string;
  current: boolean;
  impersonated: boolean;
  ip: string;
  userAgent: string;
  createdAt: string;
  lastSeenAt: string;
}

/** The JSON of Go type auth.SessionsResult. */
export interface AuthSessionsResult {
  sessions: AuthSessionView[] | null;
}

/** The JSON of Go type auth.UserView. */
export interface AuthUserView {
  id: string;
  name: string;
  image: string;
}

/** The JSON of Go type email.Address. */
export interface EmailAddress {
  email: string;
  verified: boolean;
  primary: boolean;
}

/** The JSON of Go type email.AddressRequest. */
export interface EmailAddressRequest {
  email: string;
  metadata?: { [key: string]: string } | null;
}

/** The JSON of Go type email.ListResult. */
export interface EmailListResult {
  addresses: EmailAddress[] | null;
}

/** The JSON of Go type email.TokenRequest. */
export interface EmailTokenRequest {
  token: string;
}

/** The JSON of Go type email.VerifyResult. */
export interface EmailVerifyResult {
  email: string;
  signedIn?: boolean;
  secondFactorRequired?: boolean;
}

/** The JSON of Go type nickname.Result. */
export interface NicknameResult {
  nickname: string | null;
}

/** The JSON of Go type nickname.SetRequest. */
export interface NicknameSetRequest {
  nickname: string;
}

/** The JSON of Go type password.ChangeRequest. */
export interface PasswordChangeRequest {
  current: string;
  new: string;
  revokeOtherSessions?: boolean | null;
}

/** The JSON of Go type password.ForgotRequest. */
export interface PasswordForgotRequest {
  identifier: string;
  redirectTo?: string;
}

/** The JSON of Go type password.ForgotResult. */
export interface PasswordForgotResult {
  status: string;
}

/** The JSON of Go type password.ReauthenticateRequest. */
export interface PasswordReauthenticateRequest {
  password: string;
}

/** The JSON of Go type password.ResetRequest. */
export interface PasswordResetRequest {
  token: string;
  password: string;
}

/** The JSON of Go type password.SignInRequest. */
export interface PasswordSignInRequest {
  identifier: string;
  password: string;
  remember?: boolean | null;
}

/** The JSON of Go type password.SignInResult. */
export interface PasswordSignInResult {
  user: AuthUserView;
  verificationRequired: boolean;
  secondFactorRequired: boolean;
}

/** The JSON of Go type password.SignUpRequest. */
export interface PasswordSignUpRequest {
  identifier: string;
  password: string;
  name?: string;
  image?: string;
  remember?: boolean | null;
  username?: string;
  displayUsername?: string;
  fields?: { [key: string]: unknown } | null;
}

/** The JSON of Go type password.VerifyRequest. */
export interface PasswordVerifyRequest {
  password: string;
}

/** The operations of the core (sessions, profile, account); its methods sit on the client's root. */
export type CoreOps = {
  /** `POST /profile` (core.profile), requires signed_in. */
  readonly profile: Op<AuthProfileRequest, AuthUserView>;
  /** `GET /session` (core.session), requires signed_in. */
  readonly session: Op<EmptyInput, AuthSessionResult>;
  /** `GET /sessions` (core.sessions), requires signed_in. */
  readonly sessions: Op<EmptyInput, AuthSessionsResult>;
  /** `POST /sessions/revoke` (core.sessions-revoke), requires signed_in. */
  readonly sessionsRevoke: Op<AuthRevokeSessionRequest, AuthDone>;
  /** `POST /sign-out` (core.sign-out), requires signed_in. */
  readonly signOut: Op<EmptyInput, AuthDone>;
  /** `POST /sign-out-all` (core.sign-out-all), requires signed_in. */
  readonly signOutAll: Op<EmptyInput, AuthDone>;
};

/** The core's operation table, which every client has. */
export const coreOps: CoreOps = {
  profile: { id: "core.profile", method: "POST", path: "/profile" },
  session: { id: "core.session", method: "GET", path: "/session" },
  sessions: { id: "core.sessions", method: "GET", path: "/sessions" },
  sessionsRevoke: { id: "core.sessions-revoke", method: "POST", path: "/sessions/revoke" },
  signOut: { id: "core.sign-out", method: "POST", path: "/sign-out", endsSession: true },
  signOutAll: { id: "core.sign-out-all", method: "POST", path: "/sign-out-all", endsSession: true },
};

/**
 * Builds a client: the core's methods on the root, and one namespace per plugin in `options.plugins`.
 * A plugin left out has no namespace, so calling it is a compile error. E is the session extras'
 * type, inferred from `options.sessionExtras`.
 */
export function createAuthClient<const P extends readonly AnyPlugin[] = [], E = unknown>(options: ClientOptions<P, E>): AuthClient<CoreOps, P, E> {
  return createClient(coreOps, options);
}

/** The operations of the email plugin. */
export type EmailOps = {
  /** `POST /email/add` (email.add), requires signed_in. */
  readonly add: Op<EmailAddressRequest, AuthDone>;
  /** `POST /email/change` (email.change), requires fresh_sign_in. */
  readonly change: Op<EmailAddressRequest, AuthDone>;
  /** `POST /email/confirm-change` (email.confirm-change), requires public. */
  readonly confirmChange: Op<EmailTokenRequest, EmailVerifyResult>;
  /** `GET /email/list` (email.list), requires signed_in. */
  readonly list: Op<EmptyInput, EmailListResult>;
  /** `POST /email/make-primary` (email.make-primary), requires fresh_sign_in. */
  readonly makePrimary: Op<EmailAddressRequest, AuthDone>;
  /** `POST /email/remove` (email.remove), requires fresh_sign_in. */
  readonly remove: Op<EmailAddressRequest, AuthDone>;
  /** `POST /email/resend` (email.resend), requires public. */
  readonly resend: Op<EmailAddressRequest, AuthDone>;
  /** `POST /email/undo-change` (email.undo-change), requires public. */
  readonly undoChange: Op<EmailTokenRequest, AuthDone>;
  /** `POST /email/verify` (email.verify), requires public. */
  readonly verify: Op<EmailTokenRequest, EmailVerifyResult>;
};

/** Enables the email plugin's methods as `client.email`. */
export function email(): Plugin<"email", EmailOps> {
  return { name: "email", ops: {
    add: { id: "email.add", method: "POST", path: "/email/add" },
    change: { id: "email.change", method: "POST", path: "/email/change" },
    confirmChange: { id: "email.confirm-change", method: "POST", path: "/email/confirm-change" },
    list: { id: "email.list", method: "GET", path: "/email/list" },
    makePrimary: { id: "email.make-primary", method: "POST", path: "/email/make-primary" },
    remove: { id: "email.remove", method: "POST", path: "/email/remove" },
    resend: { id: "email.resend", method: "POST", path: "/email/resend" },
    undoChange: { id: "email.undo-change", method: "POST", path: "/email/undo-change" },
    verify: { id: "email.verify", method: "POST", path: "/email/verify" },
  } };
}

/** The operations of the nickname plugin. */
export type NicknameOps = {
  /** `GET /nickname/get` (nickname.get), requires signed_in. */
  readonly get: Op<EmptyInput, NicknameResult>;
  /** `POST /nickname/set` (nickname.set), requires signed_in. */
  readonly set: Op<NicknameSetRequest, NicknameResult>;
};

/** Enables the nickname plugin's methods as `client.nickname`. */
export function nickname(): Plugin<"nickname", NicknameOps> {
  return { name: "nickname", ops: {
    get: { id: "nickname.get", method: "GET", path: "/nickname/get" },
    set: { id: "nickname.set", method: "POST", path: "/nickname/set" },
  } };
}

/** The operations of the password plugin. */
export type PasswordOps = {
  /** `POST /password/change` (password.change), requires fresh_sign_in. */
  readonly change: Op<PasswordChangeRequest, AuthDone>;
  /** `POST /password/forgot` (password.forgot), requires public. */
  readonly forgot: Op<PasswordForgotRequest, PasswordForgotResult>;
  /** `POST /password/reauthenticate` (password.reauthenticate), requires signed_in. */
  readonly reauthenticate: Op<PasswordReauthenticateRequest, AuthReauthentication>;
  /** `POST /password/reset` (password.reset), requires public. */
  readonly reset: Op<PasswordResetRequest, AuthDone>;
  /** `POST /password/sign-in` (password.sign-in), requires public. */
  readonly signIn: Op<PasswordSignInRequest, PasswordSignInResult>;
  /** `POST /password/sign-up` (password.sign-up), requires public. */
  readonly signUp: Op<PasswordSignUpRequest, PasswordSignInResult>;
  /** `POST /password/verify` (password.verify), requires signed_in. */
  readonly verify: Op<PasswordVerifyRequest, AuthDone>;
};

/** Enables the password plugin's methods as `client.password`. */
export function password(): Plugin<"password", PasswordOps> {
  return { name: "password", ops: {
    change: { id: "password.change", method: "POST", path: "/password/change" },
    forgot: { id: "password.forgot", method: "POST", path: "/password/forgot" },
    reauthenticate: { id: "password.reauthenticate", method: "POST", path: "/password/reauthenticate" },
    reset: { id: "password.reset", method: "POST", path: "/password/reset" },
    signIn: { id: "password.sign-in", method: "POST", path: "/password/sign-in", signIn: true },
    signUp: { id: "password.sign-up", method: "POST", path: "/password/sign-up" },
    verify: { id: "password.verify", method: "POST", path: "/password/verify" },
  } };
}
