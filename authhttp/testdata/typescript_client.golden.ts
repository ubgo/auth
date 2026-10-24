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

/** The JSON of Go type authhttp_test.tsConsent. */
export interface AuthhttpTestTsConsent {
  oauth_query: string;
  accept: boolean;
}

/** The JSON of Go type authhttp_test.tsEmpty. */
export type AuthhttpTestTsEmpty = EmptyInput;

/** The JSON of Go type authhttp_test.tsItem. */
export interface AuthhttpTestTsItem {
  id: string;
  createdAt: string;
  tags: string[] | null;
  labels?: { [key: string]: number } | null;
  parent: AuthhttpTestTsItem | null;
  extra?: unknown;
  any: unknown;
  grid: number[];
  pick: (string | null)[] | null;
  inline: { N: number; };
  key: string;
  "odd-name": string;
}

/** The JSON of Go type authhttp_test.tsListRequest. */
export interface AuthhttpTestTsListRequest {
  query?: string;
  page?: string;
  limit?: number;
  strict: boolean;
}

/** The JSON of Go type authhttp_test.tsPage. */
export interface AuthhttpTestTsPage {
  items: AuthhttpTestTsItem[] | null;
  total: number;
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

/** The operations of the tsp plugin. */
export type TspOps = {
  /** `POST /tsp/consent` (tsp.consent), requires signed_in. */
  readonly consent: Op<Fill<AuthhttpTestTsConsent | null, "oauth_query">, AuthhttpTestTsEmpty>;
  /** `GET /tsp/items` (tsp.list-items), requires signed_in. */
  readonly listItems: Op<AuthhttpTestTsListRequest, AuthhttpTestTsPage>;
  /** `POST /tsp/save` (tsp.save_item), requires fresh_sign_in. */
  readonly saveItem: Op<AuthhttpTestTsItem, AuthhttpTestTsItem | null>;
  /** `POST /tsp/sign-in` (tsp.sign-in), requires public. */
  readonly signIn: Op<AuthhttpTestTsEmpty, AuthhttpTestTsEmpty>;
  /** `POST /tsp/touch` (tsp.touch), requires public. */
  readonly touch: Op<AuthhttpTestTsEmpty, AuthhttpTestTsEmpty>;
  /** `POST /tsp/verify` (tsp.verify), requires pending_second_factor. */
  readonly verify: Op<AuthhttpTestTsEmpty, AuthhttpTestTsEmpty>;
};

/** Enables the tsp plugin's methods as `client.tsp`. */
export function tsp(): Plugin<"tsp", TspOps> {
  return { name: "tsp", ops: {
    consent: { id: "tsp.consent", method: "POST", path: "/tsp/consent", fill: { oauth_query: "oauthQuery" } },
    listItems: { id: "tsp.list-items", method: "GET", path: "/tsp/items" },
    saveItem: { id: "tsp.save_item", method: "POST", path: "/tsp/save" },
    signIn: { id: "tsp.sign-in", method: "POST", path: "/tsp/sign-in", signIn: true },
    touch: { id: "tsp.touch", method: "POST", path: "/tsp/touch" },
    verify: { id: "tsp.verify", method: "POST", path: "/tsp/verify" },
  } };
}
