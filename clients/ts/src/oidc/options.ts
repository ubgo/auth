// Everything createOidcClient takes: what has no safe default, and every
// policy with ours as the default.

import type { Authorizer } from "./authorize.ts";
import type { CookieOptions } from "./cookie.ts";
import type { UserMapper } from "./identity.ts";
import type { Logger } from "./log.ts";
import type { Observer } from "./observe.ts";
import type { ClientAuth, ProviderMetadata } from "./provider.ts";
import type { Rechecker } from "./recheck.ts";
import type { Responder } from "./respond.ts";
import type { Paths, ReturnPolicy, SameSitePath } from "./routes.ts";
import type { Sealer } from "./seal.ts";
import type { Secret } from "./secret.ts";
import type { Lifetimes, SessionStore } from "./session.ts";

/** Always requested, whatever `scopes` says: without it there is no ID token and nothing to verify. */
export const SCOPE_OPENID = "openid";

/**
 * Requested unless `scopes` replaces them. `offline_access` asks for the
 * refresh token `recheckByRefresh` needs (Google ignores it and wants
 * `authParams: { access_type: "offline", prompt: "consent" }` instead).
 */
export const DEFAULT_SCOPES = [SCOPE_OPENID, "email", "profile", "offline_access"] as const;

/**
 * The authorization-request parameters the flow sets itself. `authParams`
 * may not name one (the type forbids it, and start-up refuses it in any
 * letter case), so no option can drop PKCE, the state or the nonce, or send
 * the code elsewhere.
 */
export const RESERVED_AUTH_PARAMS = [
  "response_type",
  "client_id",
  "redirect_uri",
  "scope",
  "state",
  "code_challenge",
  "code_challenge_method",
  "nonce",
  "response_mode",
  "request",
  "request_uri",
] as const;

/** One of `RESERVED_AUTH_PARAMS`. */
export type ReservedAuthParam = (typeof RESERVED_AUTH_PARAMS)[number];

/**
 * Extra authorization-request parameters: `prompt`, `login_hint`,
 * `acr_values`, `hd`, Google's `access_type`. A reserved name is a compile
 * error.
 */
export type AuthParams = Readonly<Record<string, string>> & { readonly [K in ReservedAuthParam]?: never };

/** One request to the login server is abandoned after this long. */
export const DEFAULT_HTTP_TIMEOUT_MS = 10 * 1000;

/**
 * What every client needs and has no safe default, plus every policy with a
 * default. All URLs are https, or http on a loopback host for development.
 */
export interface OidcClientBaseOptions {
  /** The login server's issuer URL, exactly as its ID tokens' `iss` and its discovery document say (a trailing slash aside). May have a path (Keycloak realms). */
  readonly issuer: string;
  /** This app's client id at the login server; every ID token must name it in `aud` (and in `azp`, when present). */
  readonly clientId: string;
  /**
   * The app's public origin, scheme and host only (`"https://admin.example.com"`),
   * as the browser sees it behind any proxy. Never read from the request's
   * Host header, which a client controls. The redirect URI is
   * `appUrl + paths.callback`; the back-channel logout URI to register is
   * `appUrl + paths.backchannel`.
   */
  readonly appUrl: string;

  /** Where sessions are kept. Default `cookieStore()` (stateless). A store with `revokeSessions` enables back-channel logout. */
  readonly store?: SessionStore;
  /** The "on login" hook: Identity to the app's User, at sign-in and at each refresh with a new ID token. Default `defaultUser`. */
  readonly mapUser?: UserMapper;
  /** The app's own rule on every let-through request. Default none: the login server alone decides. */
  readonly authorize?: Authorizer;
  /** How the login server is asked again. Default `recheckByRefresh()`. */
  readonly rechecker?: Rechecker;
  /**
   * How long the login server's last "yes" stands, in milliseconds: the
   * longest a person removed at the server can still use the app.
   * `RECHECK_EVERY_REQUEST` (0) asks on every request. Default
   * `DEFAULT_RECHECK_INTERVAL_MS` (1 minute).
   */
  readonly recheckIntervalMs?: number;
  /**
   * How long the last "yes" stands while the login server cannot be reached,
   * in milliseconds from `Session.checkedAt`. `NO_OUTAGE_GRACE` (0) refuses
   * at once. Default `DEFAULT_OUTAGE_GRACE_MS` (5 minutes). Never extends a
   * session past its lifetimes.
   */
  readonly outageGraceMs?: number;
  /** Idle and absolute session lifetimes. Default 7 days idle, 30 days absolute. */
  readonly lifetimes?: Lifetimes;
  /** Answers refused requests. Default `defaultResponder()`. */
  readonly responder?: Responder;
  /** Where sign-in lands. Default `returnToRequested()`; its answer is still held to the same-site floor. */
  readonly returnPolicy?: ReturnPolicy;
  /** The session cookie's name, domain and SameSite. Default `__Host-oidc_session`, host-only, Lax. */
  readonly cookie?: CookieOptions;
  /** Where the four routes are served. Default `pathsUnder(DEFAULT_ROUTE_PREFIX)`. */
  readonly paths?: Paths;
  /**
   * Where the browser lands after sign-out: sent as `post_logout_redirect_uri`
   * (`appUrl + path`, which must be registered at the server), or redirected
   * to directly when the server has no end-session endpoint. Default `/`.
   */
  readonly postLogoutPath?: SameSitePath;
  /** Replaces the requested scopes; `openid` is added when absent. Default `DEFAULT_SCOPES`. */
  readonly scopes?: readonly string[];
  /** Extra authorization-request parameters; reserved names are refused. */
  readonly authParams?: AuthParams;
  /**
   * Sends every request to the login server: a proxy, mTLS, a test stub.
   * Called with `redirect: "manual"` always, and a redirect answer is a
   * failure, because an endpoint answering with a redirect could send the
   * client's credentials elsewhere. Default the global `fetch`.
   */
  readonly fetch?: typeof fetch;
  /** Abandons one request to the login server after this long. Default `DEFAULT_HTTP_TIMEOUT_MS`. */
  readonly httpTimeoutMs?: number;
  /** Default `console`. */
  readonly logger?: Logger;
  /** Epoch milliseconds, for tests of lifetimes, re-checks and grace; also the clock ID token expiry is checked against. Default `Date.now`. */
  readonly now?: () => number;
  /** Used instead of fetching the discovery document, and held to the same checks. */
  readonly discovery?: ProviderMetadata;
  /** Told about logins, re-checks, refusals and logouts. */
  readonly observe?: Observer;
}

/**
 * How the client authenticates at the token endpoint: exactly one of a
 * secret (client_secret_basic) or a `ClientAuth`. A union, so leaving both
 * out, or giving both, is a compile error; an empty secret is refused at
 * start-up, never read as "public" (that is `publicClient`).
 */
export type ClientCredentials =
  | { readonly clientSecret: Secret; readonly clientAuth?: never }
  | { readonly clientAuth: ClientAuth; readonly clientSecret?: never };

/**
 * How cookies are sealed: exactly one of a session secret (with the previous
 * ones still opening older cookies, see `secretSealer`) or a `Sealer`. Two
 * sources of the key would leave it unclear which opens yesterday's cookies,
 * so both is a compile error.
 */
export type SessionSealing =
  | {
      /** At least `MIN_SECRET_BYTES`, random, secret, the same on every instance. */
      readonly sessionSecret: Secret;
      readonly previousSessionSecrets?: readonly Secret[];
      readonly sealer?: never;
    }
  | { readonly sealer: Sealer; readonly sessionSecret?: never; readonly previousSessionSecrets?: never };

/** Everything `createOidcClient` takes. */
export type OidcClientOptions = OidcClientBaseOptions & ClientCredentials & SessionSealing;
