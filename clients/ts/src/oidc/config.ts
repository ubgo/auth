// Package-private: turns `OidcClientOptions` into the resolved values the
// client runs on, checking every rule at once. The types already forbid most
// mistakes; this file checks them again for callers outside the type system
// (plain JavaScript, values read from configuration), and adds the rules no
// type can express (https, secret length, distinct paths). Nothing here is
// re-exported from index.ts.

import type { Authorizer } from "./authorize.ts";
import { checkMetadata } from "./connection.ts";
import { DEFAULT_COOKIE_NAME, FLOW_COOKIE_SUFFIX, HOST_PREFIX, SAME_SITE_VALUES, SECURE_PREFIX, SameSite, isCookieName, type CookieScope } from "./cookie.ts";
import { OidcClientError, OidcErrorCode } from "./errors.ts";
import { LOGOUT_MODES, LogoutMode, logoutAlways, type LogoutPolicy, type RefreshFailedHook, type SessionEndHook, type SessionStartHook } from "./hooks.ts";
import { defaultUser, type UserMapper } from "./identity.ts";
import type { Logger } from "./log.ts";
import type { Observer } from "./observe.ts";
import {
  DEFAULT_CLOCK_SKEW_MS,
  DEFAULT_FLOW_LIFETIME_MS,
  DEFAULT_HTTP_TIMEOUT_MS,
  DEFAULT_SCOPES,
  DEFAULT_SLIDE_INTERVAL_MS,
  MAX_CLOCK_SKEW_MS,
  RESERVED_AUTH_PARAMS,
  SCOPE_OPENID,
  type OidcClientOptions,
} from "./options.ts";
import { isTrustedUrl } from "./origin.ts";
import { clientSecretBasic, type ClientAuth, type ProviderMetadata } from "./provider.ts";
import { DEFAULT_OUTAGE_GRACE_MS, DEFAULT_RECHECK_INTERVAL_MS, isBackchannelOnly, recheckByRefresh, type Rechecker } from "./recheck.ts";
import { defaultResponder, type Responder } from "./respond.ts";
import { DEFAULT_ROUTE_PREFIX, isSameSitePath, pathsUnder, returnToRequested, type Paths, type ReturnPolicy, type SameSitePath } from "./routes.ts";
import { secretSealer, type Sealer } from "./seal.ts";
import { DEFAULT_ABSOLUTE_LIFETIME_MS, DEFAULT_IDLE_LIFETIME_MS, NO_LIMIT, cookieStore, type SessionStore } from "./session.ts";

/** Every option after defaults, checked. */
export interface Resolved {
  readonly issuer: string;
  readonly clientId: string;
  /** The app's origin, no trailing slash. */
  readonly appOrigin: string;
  readonly clientAuth: ClientAuth;
  readonly sealer: Sealer;
  readonly store: SessionStore;
  readonly mapUser: UserMapper;
  readonly authorize: Authorizer | undefined;
  readonly rechecker: Rechecker;
  readonly recheckIntervalMs: number;
  readonly outageGraceMs: number;
  /** `NO_LIMIT` (Infinity) when the bound is off. */
  readonly idleMs: number;
  /** `NO_LIMIT` (Infinity) when the bound is off. */
  readonly absoluteMs: number;
  /** `NO_LIMIT` (Infinity): never slide. */
  readonly slideIntervalMs: number;
  readonly clockSkewMs: number;
  readonly flowLifetimeMs: number;
  /** Never throws: wraps the app's policy, reading a throw or an unknown answer as `atServer`. */
  readonly logoutPolicy: LogoutPolicy;
  readonly onSessionStart: SessionStartHook | undefined;
  readonly onSessionEnd: SessionEndHook | undefined;
  readonly onRefreshFailed: RefreshFailedHook | undefined;
  readonly responder: Responder;
  readonly returnPolicy: ReturnPolicy;
  readonly sessionCookie: CookieScope;
  /** Always host-only and Lax, named after the session cookie. */
  readonly flowCookie: CookieScope;
  readonly paths: Paths;
  readonly postLogoutPath: SameSitePath;
  readonly scopes: readonly string[];
  readonly authParams: ReadonlyArray<readonly [string, string]>;
  readonly fetch: typeof fetch;
  readonly httpTimeoutMs: number;
  readonly logger: Logger;
  readonly now: () => number;
  readonly discovery: ProviderMetadata | undefined;
  readonly observe: Observer | undefined;
}

/** Whether `v` is a function; hooks given as anything else are refused at start-up, not on the first request. */
function isFunction(v: unknown): v is (...args: never[]) => unknown {
  return typeof v === "function";
}

/** Whether `v` is a usable non-negative duration in milliseconds. */
function isDuration(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v) && v >= 0;
}

/** Whether `v` is a non-negative duration or `NO_LIMIT`. */
function isDurationOrNoLimit(v: unknown): v is number {
  return isDuration(v) || v === NO_LIMIT;
}

/** Whether `v` is a positive duration or `NO_LIMIT`: what a lifetime may be. */
function isLifetime(v: unknown): v is number {
  return isDurationOrNoLimit(v) && v > 0;
}

/** A scope token holds no space or control character (RFC 6749 section 3.3). */
const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

/** Where the app's origin may carry nothing but `/` after the host. */
const ROOT_PATH = "/";

/**
 * Resolves and checks `o`. Throws one `invalidConfig` naming every problem
 * found, so a misconfigured app fails at start-up with the whole list.
 */
export function resolveOptions(o: OidcClientOptions): Resolved {
  const problems: string[] = [];
  const need = (ok: boolean, problem: string): void => {
    if (!ok) problems.push(problem);
  };

  // What has no default.
  const issuer = typeof o.issuer === "string" ? o.issuer : "";
  need(isTrustedUrl(issuer), "issuer must be an https URL (or http on a loopback host)");
  const clientId = typeof o.clientId === "string" ? o.clientId : "";
  need(clientId !== "", "clientId is required");
  const appUrl = typeof o.appUrl === "string" ? o.appUrl : "";
  let appOrigin = "";
  if (isTrustedUrl(appUrl)) {
    const u = new URL(appUrl);
    need((u.pathname === ROOT_PATH || u.pathname === "") && u.search === "", "appUrl must be an origin only (scheme and host), with no path or query");
    appOrigin = u.origin;
  } else {
    problems.push("appUrl must be an https URL (or http on a loopback host)");
  }

  // Client credentials: exactly one of clientSecret and clientAuth.
  let clientAuth: ClientAuth | undefined;
  const hasSecret = o.clientSecret !== undefined;
  const hasAuth = o.clientAuth !== undefined;
  if (hasSecret === hasAuth) {
    problems.push("give exactly one of clientSecret and clientAuth (publicClient for a client without a secret)");
  } else if (o.clientSecret !== undefined) {
    if (typeof o.clientSecret.isEmpty !== "function" || o.clientSecret.isEmpty()) problems.push("clientSecret must be a non-empty secret(); use clientAuth: publicClient(clientId) for a public client");
    else clientAuth = clientSecretBasic(clientId, o.clientSecret);
  } else if (o.clientAuth !== undefined) {
    if (isFunction(o.clientAuth)) clientAuth = o.clientAuth;
    else problems.push("clientAuth must be a function");
  }

  // Sealing: exactly one of sessionSecret and sealer.
  let sealer: Sealer | undefined;
  const hasSessionSecret = o.sessionSecret !== undefined;
  const hasSealer = o.sealer !== undefined;
  if (hasSessionSecret === hasSealer) {
    problems.push("give exactly one of sessionSecret and sealer");
  } else if (o.sessionSecret !== undefined) {
    try {
      sealer = secretSealer({ current: o.sessionSecret, previous: o.previousSessionSecrets ?? [] });
    } catch (err) {
      problems.push(`sessionSecret: ${err instanceof Error ? err.message : String(err)}`);
    }
  } else if (o.sealer !== undefined) {
    if (isFunction(o.sealer.seal) && isFunction(o.sealer.open)) sealer = o.sealer;
    else problems.push("sealer must have seal and open methods");
  }

  // Hooks.
  const store = o.store ?? cookieStore();
  need(isFunction(store.save) && isFunction(store.load) && isFunction(store.delete), "store must have save, load and delete methods");
  need(store.revokeSessions === undefined || isFunction(store.revokeSessions), "store.revokeSessions must be a method when present");
  const mapUser: UserMapper = o.mapUser ?? (({ identity }) => defaultUser(identity));
  need(isFunction(mapUser), "mapUser must be a function");
  need(o.authorize === undefined || isFunction(o.authorize), "authorize must be a function");
  const rechecker = o.rechecker ?? recheckByRefresh();
  need(isFunction(rechecker), "rechecker must be a function");
  need(!isBackchannelOnly(rechecker) || store.revokeSessions !== undefined, "recheckBackchannelOnly needs a store with revokeSessions: with a stateless cookie nothing could ever end the session");
  need(o.logoutPolicy === undefined || isFunction(o.logoutPolicy), "logoutPolicy must be a function");
  need(o.onSessionStart === undefined || isFunction(o.onSessionStart), "onSessionStart must be a function");
  need(o.onSessionEnd === undefined || isFunction(o.onSessionEnd), "onSessionEnd must be a function");
  need(o.onRefreshFailed === undefined || isFunction(o.onRefreshFailed), "onRefreshFailed must be a function");
  const responder = o.responder ?? defaultResponder();
  need(isFunction(responder), "responder must be a function");
  const returnPolicy = o.returnPolicy ?? returnToRequested();
  need(isFunction(returnPolicy), "returnPolicy must be a function");
  need(o.observe === undefined || isFunction(o.observe), "observe must be a function");
  need(o.now === undefined || isFunction(o.now), "now must be a function");
  const logger = o.logger ?? console;
  need(isFunction(logger.debug) && isFunction(logger.info) && isFunction(logger.warn) && isFunction(logger.error), "logger must have debug, info, warn and error");

  // Durations. NO_LIMIT (Infinity) is accepted where a bound may be off.
  const recheckIntervalMs = o.recheckIntervalMs ?? DEFAULT_RECHECK_INTERVAL_MS;
  need(isDurationOrNoLimit(recheckIntervalMs), "recheckIntervalMs must be a non-negative number of milliseconds, or NO_LIMIT");
  const outageGraceMs = o.outageGraceMs ?? DEFAULT_OUTAGE_GRACE_MS;
  need(isDurationOrNoLimit(outageGraceMs), "outageGraceMs must be a non-negative number of milliseconds, or NO_LIMIT");
  const httpTimeoutMs = o.httpTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
  need(isDuration(httpTimeoutMs) && httpTimeoutMs > 0, "httpTimeoutMs must be a positive number of milliseconds");
  const idleMs = o.lifetimes?.idleMs ?? DEFAULT_IDLE_LIFETIME_MS;
  const absoluteMs = o.lifetimes?.absoluteMs ?? DEFAULT_ABSOLUTE_LIFETIME_MS;
  need(isLifetime(idleMs) && isLifetime(absoluteMs), "lifetimes must be positive numbers of milliseconds, or NO_LIMIT to turn a bound off (0 is not NO_LIMIT)");
  need(idleMs === NO_LIMIT || absoluteMs === NO_LIMIT || idleMs <= absoluteMs, "lifetimes.idleMs must not exceed lifetimes.absoluteMs");
  const slideIntervalMs = o.slideIntervalMs ?? DEFAULT_SLIDE_INTERVAL_MS;
  need(isDurationOrNoLimit(slideIntervalMs), "slideIntervalMs must be a non-negative number of milliseconds, or NO_LIMIT");
  need(idleMs === NO_LIMIT || !(slideIntervalMs >= idleMs), "slideIntervalMs must be shorter than lifetimes.idleMs, or an active session would expire");
  const clockSkewMs = o.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;
  need(isDuration(clockSkewMs) && clockSkewMs <= MAX_CLOCK_SKEW_MS, `clockSkewMs must be between 0 and ${MAX_CLOCK_SKEW_MS} milliseconds`);
  const flowLifetimeMs = o.flowLifetimeMs ?? DEFAULT_FLOW_LIFETIME_MS;
  need(isDuration(flowLifetimeMs) && flowLifetimeMs > 0, "flowLifetimeMs must be a positive, finite number of milliseconds");

  need(
    !(o.lifetimes?.idleMs === NO_LIMIT && o.lifetimes?.absoluteMs === NO_LIMIT && recheckIntervalMs === NO_LIMIT && store.revokeSessions === undefined),
    "lifetimes without any limit, a re-check that never runs and a store without revokeSessions: nothing could ever end a session",
  );

  // Cookie.
  const cookieName = o.cookie?.name ?? DEFAULT_COOKIE_NAME;
  const domain = o.cookie?.domain;
  const sameSite = o.cookie?.sameSite ?? SameSite.lax;
  need(isCookieName(cookieName), `cookie name ${JSON.stringify(cookieName)} is not a valid cookie name`);
  need(SAME_SITE_VALUES.includes(sameSite), `cookie sameSite must be one of ${SAME_SITE_VALUES.join(", ")}`);
  if (domain === undefined) need(cookieName.startsWith(HOST_PREFIX), `cookie name must start with ${HOST_PREFIX} (a host-only cookie)`);
  else need(cookieName.startsWith(SECURE_PREFIX) && /^[A-Za-z0-9.-]+$/.test(domain) && domain !== "", `a cookie with domain must be named ${SECURE_PREFIX}… and the domain a host name`);
  const browserSession = o.cookie?.browserSession ?? false;
  need(typeof browserSession === "boolean", "cookie.browserSession must be a boolean");
  const sessionCookie: CookieScope = { name: cookieName, sameSite, ...(domain === undefined ? {} : { domain }), ...(browserSession === true ? { browserSession } : {}) };
  // Host-only and Lax always: the login server's redirect back is cross-site,
  // which Strict would strip the cookie from; host-only, since the callback
  // is on this host. Its prefix stays valid without Domain either way.
  const flowCookie: CookieScope = { name: `${cookieName}${FLOW_COOKIE_SUFFIX}`, sameSite: SameSite.lax };

  // Routes.
  const paths = o.paths ?? pathsUnder(DEFAULT_ROUTE_PREFIX);
  const routeList = [paths.login, paths.callback, paths.logout, paths.backchannel];
  need(routeList.every((p) => typeof p === "string" && isSameSitePath(p)), "paths must all be same-site paths (/x, not //x, no backslash)");
  need(new Set(routeList).size === routeList.length, "paths must be four distinct paths");
  const postLogoutPath = o.postLogoutPath ?? "/";
  need(isSameSitePath(postLogoutPath), "postLogoutPath must be a same-site path");

  // Authorization request.
  const requested = o.scopes ?? DEFAULT_SCOPES;
  need(requested.every((s) => typeof s === "string" && SCOPE_TOKEN.test(s)), "scopes must be scope tokens (no spaces)");
  const scopes = requested.includes(SCOPE_OPENID) ? [...requested] : [SCOPE_OPENID, ...requested];
  const authParams = Object.entries(o.authParams ?? {}).filter((e): e is [string, string] => e[1] !== undefined);
  for (const [k, v] of authParams) {
    need(!RESERVED_AUTH_PARAMS.some((r) => r === k.toLowerCase()), `authParams may not set ${JSON.stringify(k)}: the flow sets it`);
    need(typeof v === "string", `authParams.${k} must be a string`);
  }

  // Plumbing.
  const fetchFn = o.fetch ?? (typeof globalThis.fetch === "function" ? globalThis.fetch.bind(globalThis) : undefined);
  need(isFunction(fetchFn), "this runtime has no global fetch: pass the fetch option");
  if (o.discovery !== undefined) {
    for (const p of checkMetadata(o.discovery, issuer)) problems.push(`discovery: ${p}`);
  }

  if (problems.length > 0 || clientAuth === undefined || sealer === undefined || fetchFn === undefined) {
    throw new OidcClientError(OidcErrorCode.invalidConfig, `createOidcClient: ${problems.join("; ")}`);
  }
  return {
    issuer,
    clientId,
    appOrigin,
    clientAuth,
    sealer,
    store,
    mapUser,
    authorize: o.authorize,
    rechecker,
    recheckIntervalMs,
    outageGraceMs,
    idleMs,
    absoluteMs,
    slideIntervalMs,
    clockSkewMs,
    flowLifetimeMs,
    logoutPolicy: safeLogoutPolicy(o.logoutPolicy ?? logoutAlways(LogoutMode.atServer), logger),
    onSessionStart: o.onSessionStart,
    onSessionEnd: o.onSessionEnd,
    onRefreshFailed: o.onRefreshFailed,
    responder,
    returnPolicy,
    sessionCookie,
    flowCookie,
    paths,
    postLogoutPath,
    scopes,
    authParams,
    fetch: fetchFn,
    httpTimeoutMs,
    logger,
    now: o.now ?? Date.now,
    discovery: o.discovery,
    observe: o.observe,
  };
}

/**
 * `policy`, made safe for the logout route: a throw (logged) or an answer
 * that is not a `LogoutMode` signs out at the server, the more complete
 * sign-out.
 */
function safeLogoutPolicy(policy: LogoutPolicy, logger: Logger): LogoutPolicy {
  return async (input) => {
    try {
      const mode: unknown = await policy(input);
      return LOGOUT_MODES.find((m) => m === mode) ?? LogoutMode.atServer;
    } catch (err) {
      logger.warn("oidc: logoutPolicy threw; signing out at the server", { error: err instanceof Error ? err.message : String(err) });
      return LogoutMode.atServer;
    }
  };
}
