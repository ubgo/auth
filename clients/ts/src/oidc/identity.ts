// Who signed in: claims, the verified Identity, the app's User, and the
// UserMapper hook between them.

import type { Provider } from "./provider.ts";
import type { Secret } from "./secret.ts";

/** Any value JSON can carry: what a claim holds before the app reads it. */
export type JsonValue = string | number | boolean | null | readonly JsonValue[] | { readonly [key: string]: JsonValue };

/**
 * The members of a verified ID token (or a userinfo answer), as the server
 * sent them, so no number, nested object or array is reshaped before the app
 * reads it. `claimString`, `claimBool` and `claimStrings` cover the common
 * cases; anything else is a narrowing of the `JsonValue`.
 */
export type Claims = { readonly [name: string]: JsonValue };

/** Returns claim `name` when it is a string, else `undefined`. */
export function claimString(claims: Claims, name: string): string | undefined {
  const v = claims[name];
  return typeof v === "string" ? v : undefined;
}

/**
 * Returns claim `name` when it is a boolean, else `undefined`. The string
 * `"true"` is not a boolean here: a caller that must accept that spelling
 * (`email_verified` at some servers) reads both, as `defaultUser` does.
 */
export function claimBool(claims: Claims, name: string): boolean | undefined {
  const v = claims[name];
  return typeof v === "boolean" ? v : undefined;
}

/**
 * Returns claim `name` as a list of strings, else `undefined`. A single
 * string is a list of one, because groups and roles claims are sent both
 * ways; a list holding anything but strings is `undefined`, not filtered.
 */
export function claimStrings(claims: Claims, name: string): readonly string[] | undefined {
  const v = claims[name];
  if (typeof v === "string") return [v];
  if (Array.isArray(v) && v.every((item): item is string => typeof item === "string")) return v;
  return undefined;
}

/**
 * Standard claim names the package reads (OpenID Connect Core 5.1, Front- and
 * Back-Channel Logout). Wire names, kept verbatim.
 */
export const Claim = {
  subject: "sub",
  issuer: "iss",
  email: "email",
  emailVerified: "email_verified",
  name: "name",
  sessionId: "sid",
} as const;

/** One of the `Claim` names. */
export type Claim = (typeof Claim)[keyof typeof Claim];

/**
 * Who the login server says signed in: the verified ID token, read once. Only
 * the package builds one, after every floor passed (signature under an
 * allowed algorithm, iss, aud, exp, azp, the nonce at sign-in, the same iss
 * and sub at refresh), so a `UserMapper` can trust every field.
 */
export interface Identity {
  /** With `subject`, names the person at the login server; keys back-channel logout. */
  readonly issuer: string;
  readonly subject: string;
  /** Empty when the token carries no email. */
  readonly email: string;
  /** True only for the boolean `true` or the string `"true"`. */
  readonly emailVerified: boolean;
  /** Empty when the token carries no name. */
  readonly name: string;
  /** The ID token's `sid` (the login server's session), which a logout token may name; absent when the server sends none. */
  readonly providerSessionId?: string;
  /** Every member of the ID token, the ones above included. */
  readonly claims: Claims;
}

/**
 * The signed-in person as the app sees it: what `requireSession` hands the
 * app on every request it lets through. `defaultUser` fills it from the
 * `Identity`; a `UserMapper` replaces or enriches it.
 *
 * It is stored in the session, so under the default cookie store its size is
 * the cookie's: a mapper that does not need `claims` may leave them out.
 * `issuer` and `subject` must equal the Identity's: a mapper that changes
 * them is refused (fail closed), because back-channel logout finds sessions
 * by them.
 */
export interface User {
  /** The app's id for the person: `subject` by default, the app's own row id after linking. */
  readonly id: string;
  readonly issuer: string;
  readonly subject: string;
  readonly email: string;
  readonly emailVerified: boolean;
  readonly name: string;
  /** App roles, typically derived from a groups claim by the mapper; empty by default. */
  readonly roles: readonly string[];
  /** The ID token's claims, or fewer (or none) to keep the cookie small. */
  readonly claims?: Claims;
}

/**
 * The `User` stored when no `mapUser` is set: every field copied from the
 * Identity, `id` set to the subject, no roles. A mapper usually starts from
 * it (`{ ...defaultUser(identity), roles }`) and changes what it needs.
 */
export function defaultUser(identity: Identity): User {
  return {
    id: identity.subject,
    issuer: identity.issuer,
    subject: identity.subject,
    email: identity.email,
    emailVerified: identity.emailVerified,
    name: identity.name,
    roles: [],
    claims: identity.claims,
  };
}

/** Why a `UserMapper` is called. */
export const MapReason = {
  /** A sign-in's callback: the first time this session sees the Identity. A mapper that creates the app's user does it here. */
  signIn: "sign_in",
  /** A re-check that brought a new ID token, so roles from claims stay current. `previous` is set. */
  refresh: "refresh",
} as const;

/** One of the `MapReason` values. */
export type MapReason = (typeof MapReason)[keyof typeof MapReason];

/** Every `MapReason`. */
export const MAP_REASONS: readonly MapReason[] = Object.values(MapReason);

/**
 * What a `UserMapper` decides from. An object, so fields can be added without
 * breaking mappers. Discriminated on `reason`: `previous` exists exactly on a
 * refresh.
 */
export type MapUserInput =
  | (MapUserCommon & { readonly reason: typeof MapReason.signIn })
  | (MapUserCommon & { readonly reason: typeof MapReason.refresh; readonly previous: User });

/** The fields every `MapUserInput` carries. */
export interface MapUserCommon {
  readonly identity: Identity;
  /** The session's current access token, for a mapper that calls userinfo or an API of the login server. */
  readonly accessToken?: Secret;
  /** Calls the login server with this client's credentials. */
  readonly provider: Provider;
  /** The request being served (the callback, or the request that triggered the re-check), for the app's own context. */
  readonly request: Request;
}

/**
 * Turns a verified `Identity` into the app's `User`: link or create the app's
 * own user, derive roles from claims, refuse an unverified email. It is the
 * "on login" hook.
 *
 * Throwing `new OidcClientError(OidcErrorCode.accessDenied)` refuses with the
 * no-access response; any other throw refuses as a failure. Either way no
 * session is written (sign-in) or the session ends (refresh): a mapper error
 * never lets anyone in.
 */
export type UserMapper = (input: MapUserInput) => User | Promise<User>;
