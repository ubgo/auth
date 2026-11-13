// The relying party: the four routes, the session gate, and the factory.

import { fromUtf8, randomToken, utf8 } from "./bytes.ts";
import { resolveOptions } from "./config.ts";
import { PKCE_METHOD_S256, createConnection, isOutage } from "./connection.ts";
import { HEADER_SET_COOKIE, SameSite, deleteChunked, isCookieValue, readCookies, serializeCookie } from "./cookie.ts";
import { LoadKind, createEngine, describe, type PendingRefusal } from "./engine.ts";
import { OidcClientError, OidcErrorCode, isOidcError } from "./errors.ts";
import { FLOW_TTL_MS, addFlow, codeChallenge, decodeFlows, encodeFlows, newFlow, takeFlow, type Flow } from "./flow.ts";
import { MapReason, type User } from "./identity.ts";
import { EventKind } from "./observe.ts";
import type { OidcClientOptions } from "./options.ts";
import { TokenTypeHint, type Provider } from "./provider.ts";
import { HttpStatus, Header, MEDIA_TYPE_HTML_UTF8, MEDIA_TYPE_JSON, NO_STORE, RefusalKind, RefusalReason, defaultResponder, type Refusal } from "./respond.ts";
import { PARAM_RETURN_TO, sameSiteOrRoot, type Paths, type SameSitePath } from "./routes.ts";
import { ReplayCache } from "./replay.ts";
import type { Session } from "./session.ts";

/**
 * `requireSession`'s answer, discriminated on `allowed`.
 *
 * Allowed: the person, and the cookies the request changed (a slid idle
 * window, rotated tokens after a re-check). Those must reach the browser, so
 * the app passes its response through `commit`, or appends `setCookies`
 * itself when its framework sets headers another way. Dropping them is safe
 * (the next request re-checks again) but costs a refresh per request.
 *
 * Refused: the `Refusal` and the `Response` the responder wrote for it, with
 * any cookie deletion already on it. Return it as is.
 */
export type SessionGate =
  | {
      readonly allowed: true;
      readonly user: User;
      /** `Set-Cookie` header values to send with the app's response; empty when nothing changed. */
      readonly setCookies: readonly string[];
      /** Returns `response` with `setCookies` appended (copying it when its headers are immutable, as a fetched response's are). */
      commit(response: Response): Response;
    }
  | {
      readonly allowed: false;
      readonly refusal: Refusal;
      readonly response: Response;
    };

/**
 * `optionalSession`'s answer, discriminated on `signedIn`: the person when
 * `requireSession` would have let the request through, otherwise nobody.
 * Either way `setCookies` holds what the request changed (a rotated token,
 * a slid window, or the deletion of a session that just ended), which must
 * reach the browser through `commit`.
 */
export type OptionalSession =
  | {
      readonly signedIn: true;
      readonly user: User;
      readonly setCookies: readonly string[];
      commit(response: Response): Response;
    }
  | {
      readonly signedIn: false;
      readonly setCookies: readonly string[];
      commit(response: Response): Response;
    };

/** An app handler that runs only for a signed-in, fresh, authorized person. */
export type ProtectedHandler = (request: Request, user: User) => Response | Promise<Response>;

/**
 * The relying party for one client at one login server. Built on the Fetch
 * API's `Request` and `Response`, so it runs wherever they are the server's
 * currency: TanStack Start server routes and middleware, Node 20+ behind any
 * Fetch adapter, Bun, Deno, workers. It holds no module-level state; an app
 * may run several (two login servers, two clients) under different paths and
 * cookie names.
 */
export interface OidcClient {
  /** The routes it serves, after defaults: the one truth for redirects and the registered URIs. */
  readonly paths: Paths;
  /** Calls the login server as this client: the escape hatch for the app's own introspection or userinfo calls. */
  readonly provider: Provider;

  /**
   * Serves the four routes: GET `login`, GET `callback`, POST `logout`, POST
   * `backchannel` (another method on those paths is 405). Resolves
   * `undefined` for any other path, so the app falls through to its own
   * routing: `return (await oidc.handle(request)) ?? app(request)`.
   */
  handle(request: Request): Promise<Response | undefined>;
  /**
   * Starts a sign-in: writes the sealed flow cookie (state, nonce, PKCE
   * verifier, return path) and redirects to the authorization endpoint. The
   * `return_to` query parameter goes through the `ReturnPolicy`.
   */
  login(request: Request): Promise<Response>;
  /**
   * Completes a sign-in: state equal to the flow cookie's (constant time), iss
   * when sent (RFC 9207), the code exchanged with the PKCE verifier, the ID
   * token verified, `mapUser` run, the session saved, the browser sent to the
   * return path. Every failure is a refusal (`failed` or `no_access`) and no
   * session is written.
   */
  callback(request: Request): Promise<Response>;
  /**
   * Signs out: revokes the session's refresh token at the revocation
   * endpoint (best effort: a failure is logged and observed as
   * `revoke_failed`, never blocks sign-out), deletes the session, then sends
   * the browser to the end-session endpoint with the ID token as
   * `id_token_hint`, or straight to
   * `postLogoutPath` when the server has none. POST only, and only from this
   * origin (Origin or Sec-Fetch-Site), so another site cannot sign people out.
   */
  logout(request: Request): Promise<Response>;
  /**
   * Receives a Back-Channel Logout token: POSTed `logout_token` signed by the
   * issuer under an allowed algorithm, with iss, aud equal to the client id,
   * iat at most two minutes old, exp, the back-channel event, a jti, sub or
   * sid, and no nonce. Each jti is accepted once per process (a replay is
   * 400). Ends the matching sessions through `store.revokeSessions` and
   * answers 200; a token that does not verify is 400, keys that cannot be
   * read 503, a store without `revokeSessions` 501.
   */
  backchannel(request: Request): Promise<Response>;

  /**
   * Lets a request through only with a live, fresh, authorized session. In
   * order: load the session (none: login required), apply the lifetimes (past
   * either: login required), re-check when the last "yes" is older than the
   * recheck interval (single-flight per session; deny: login required;
   * unreachable: the outage grace, then unavailable), run `mapUser` on a new
   * Identity, run `authorize`, allow. Every refusal goes to the responder. It
   * never throws for a refusal or a hook failure; it rejects only for a bug.
   */
  requireSession(request: Request): Promise<SessionGate>;
  /**
   * The same steps as `requireSession` (load, lifetimes, re-check with its
   * single-flight and outage grace, `mapUser` on a new Identity,
   * `authorize`), for a public page that shows "signed in as" when someone
   * is: it never refuses and never calls the responder. The user is present
   * exactly when `requireSession` would have allowed the request; a session
   * the login server refused is still ended (its deletion is in
   * `setCookies`). Observers see refusals of an existing session, not the
   * absence of one, so anonymous traffic is not reported as refusals.
   */
  optionalSession(request: Request): Promise<OptionalSession>;
  /**
   * Wraps a handler with `requireSession` and `commit`: the refusal response
   * when refused, the handler's response with the session cookies when
   * allowed. The short form for Fetch-style servers.
   */
  protect(handler: ProtectedHandler): (request: Request) => Promise<Response>;
}

/**
 * Checks the options and returns a client. Synchronous and makes no network
 * call: the discovery document is fetched on first use, so the app starts
 * while the login server is down. Every mistake it can find is thrown
 * together as one `OidcClientError` with code `invalidConfig`, naming each
 * field, at start-up rather than on the first request.
 */
export function createOidcClient(options: OidcClientOptions): OidcClient {
  const cfg = resolveOptions(options);
  const connection = createConnection({
    issuer: cfg.issuer,
    clientId: cfg.clientId,
    clientAuth: cfg.clientAuth,
    redirectUri: cfg.appOrigin + cfg.paths.callback,
    fetch: cfg.fetch,
    timeoutMs: cfg.httpTimeoutMs,
    now: cfg.now,
    ...(cfg.discovery === undefined ? {} : { discovery: cfg.discovery }),
  });
  // The public face of the connection: the code exchange and logout-token
  // calls stay with the routes.
  const provider: Provider = {
    metadata: () => connection.metadata(),
    refresh: (input) => connection.refresh(input),
    introspect: (input) => connection.introspect(input),
    userInfo: (input) => connection.userInfo(input),
  };
  const engine = createEngine(cfg, provider);
  const replay = new ReplayCache();
  const fallbackResponder = defaultResponder();

  /** Answers `p` through the app's responder (the default one if it throws or returns no Response), with `setCookies` on it, and reports it. */
  async function refuse(p: PendingRefusal, request: Request, setCookies: readonly string[], session?: Session): Promise<{ refusal: Refusal; response: Response }> {
    const refusal = engine.refusal(p, request);
    engine.emit({
      kind: EventKind.refuse,
      at: cfg.now(),
      reason: p.reason,
      ...(p.cause === undefined ? {} : { cause: p.cause }),
      ...(session === undefined ? {} : { sessionId: session.id, subject: session.user.subject }),
    });
    const fields = { kind: p.kind, reason: p.reason, ...(p.cause === undefined ? {} : { error: describe(p.cause) }) };
    if (p.kind === RefusalKind.failed) cfg.logger.error("oidc: request failed", fields);
    else cfg.logger.debug("oidc: request refused", fields);
    let response: Response;
    try {
      const r: unknown = await cfg.responder(refusal, request);
      response = r instanceof Response ? r : await fallbackResponder(refusal, request);
    } catch (err) {
      cfg.logger.error("oidc: responder threw; answered with the default responder", { error: describe(err) });
      response = await fallbackResponder(refusal, request);
    }
    return { refusal, response: withCookies(response, setCookies) };
  }

  /** The pending flows in a sealed flow cookie (expired ones dropped); throws the sealer's error, `sealedCorrupt` for one that does not open. */
  async function openFlows(sealed: string | undefined, now: number): Promise<readonly Flow[]> {
    if (sealed === undefined) return [];
    return decodeFlows(fromUtf8(await cfg.sealer.open(sealed, cfg.flowCookie.name)), now);
  }

  /** The `Set-Cookie` value holding `flows`, living until the newest expires; a deletion when none is left. */
  async function sealFlows(flows: readonly Flow[], now: number): Promise<string> {
    const newest = flows.at(-1);
    if (newest === undefined) return serializeCookie(cfg.flowCookie, cfg.flowCookie.name, "", 0);
    const sealed = await cfg.sealer.seal(utf8(encodeFlows(flows)), cfg.flowCookie.name);
    if (!isCookieValue(sealed)) throw new OidcClientError(OidcErrorCode.invalidConfig, "sealer output is not cookie-safe text");
    return serializeCookie(cfg.flowCookie, cfg.flowCookie.name, sealed, (newest.startedAt + FLOW_TTL_MS - now) / 1000);
  }

  async function login(request: Request): Promise<Response> {
    if (request.method !== Method.get) return methodNotAllowed(Method.get);
    const requested = new URL(request.url).searchParams.get(PARAM_RETURN_TO) ?? "";
    let returnTo: SameSitePath;
    try {
      const chosen: unknown = cfg.returnPolicy({ requested, request });
      returnTo = sameSiteOrRoot(typeof chosen === "string" ? chosen : "");
    } catch (err) {
      return (await refuse({ kind: RefusalKind.failed, reason: RefusalReason.hookFailed, cause: err }, request, [])).response;
    }
    let endpoint: string;
    try {
      endpoint = (await connection.metadata()).authorizationEndpoint;
    } catch (err) {
      return (await refuse(outageOrFailure(err, RefusalReason.storeFailed), request, [])).response;
    }
    const now = cfg.now();
    const flow = newFlow(returnTo, now);
    let flowCookie: string;
    try {
      // A sign-in already in flight in another tab stays: up to
      // MAX_PENDING_FLOWS can finish. A flow cookie that does not open is
      // started afresh.
      const pending = await openFlows(readCookies(request).get(cfg.flowCookie.name), now).catch((): readonly Flow[] => []);
      flowCookie = await sealFlows(addFlow(pending, flow), now);
    } catch (err) {
      return (await refuse({ kind: RefusalKind.failed, reason: RefusalReason.storeFailed, cause: err }, request, [])).response;
    }
    const target = new URL(endpoint);
    // The app's extra parameters first, then the flow's own over them; the
    // reserved names were refused at start-up, so nothing is overwritten.
    for (const [k, v] of cfg.authParams) target.searchParams.set(k, v);
    const flowParams: ReadonlyArray<readonly [string, string]> = [
      [AuthParam.responseType, RESPONSE_TYPE_CODE],
      [AuthParam.clientId, cfg.clientId],
      [AuthParam.redirectUri, cfg.appOrigin + cfg.paths.callback],
      [AuthParam.scope, cfg.scopes.join(" ")],
      [AuthParam.state, flow.state],
      [AuthParam.nonce, flow.nonce],
      [AuthParam.codeChallenge, await codeChallenge(flow.verifier)],
      [AuthParam.codeChallengeMethod, PKCE_METHOD_S256],
    ];
    for (const [k, v] of flowParams) target.searchParams.set(k, v);
    return redirect(HttpStatus.found, target.toString(), [flowCookie]);
  }

  async function callback(request: Request): Promise<Response> {
    if (request.method !== Method.get) return methodNotAllowed(Method.get);
    const cookies = readCookies(request);
    const params = new URL(request.url).searchParams;
    const now = cfg.now();
    const bad = (why: string, cause?: unknown, setCookies: readonly string[] = []): Promise<Response> =>
      refuse({ kind: RefusalKind.failed, reason: RefusalReason.badCallback, cause: new OidcClientError(OidcErrorCode.invalidToken, why, cause === undefined ? undefined : { cause }) }, request, setCookies).then((r) => r.response);
    const sealedFlow = cookies.get(cfg.flowCookie.name);
    if (sealedFlow === undefined) return bad("no sign-in in progress (flow cookie missing)");
    let pending: readonly Flow[];
    try {
      pending = await openFlows(sealedFlow, now);
    } catch (err) {
      const clear = [serializeCookie(cfg.flowCookie, cfg.flowCookie.name, "", 0)];
      if (isOidcError(err, OidcErrorCode.sealedCorrupt)) return bad("flow cookie does not open", err, clear);
      return (await refuse({ kind: RefusalKind.failed, reason: RefusalReason.storeFailed, cause: err }, request, clear)).response;
    }
    // Expired flows were dropped on opening; a state matching none of the
    // rest is refused and the others are left for their own tabs.
    const { flow, rest } = takeFlow(pending, params.get(AuthParam.state) ?? "");
    if (flow === undefined) return bad("state matches no sign-in in progress in this browser (or it took too long)");
    // The taken flow is single-use: every answer from here rewrites the
    // flow cookie without it.
    let flowCookie: string;
    try {
      flowCookie = await sealFlows(rest, now);
    } catch (err) {
      return (await refuse({ kind: RefusalKind.failed, reason: RefusalReason.storeFailed, cause: err }, request, [serializeCookie(cfg.flowCookie, cfg.flowCookie.name, "", 0)])).response;
    }
    const fail = async (p: PendingRefusal): Promise<Response> => (await refuse(p, request, [flowCookie])).response;
    const error = params.get(AuthParam.error);
    if (error !== null) {
      if (error === ERROR_ACCESS_DENIED) return fail({ kind: RefusalKind.noAccess, reason: RefusalReason.providerDenied });
      return bad(`login server answered error ${JSON.stringify(error)}`, undefined, [flowCookie]);
    }
    let issuer: string;
    let issRequired: boolean;
    try {
      const m = await connection.metadata();
      issuer = m.issuer;
      issRequired = m.authorizationResponseIssParameterSupported === true;
    } catch (err) {
      return fail(outageOrFailure(err, RefusalReason.badCallback));
    }
    // RFC 9207: an iss sent must be the issuer (mix-up defence), and one the
    // server promised must be sent.
    const iss = params.get(AuthParam.iss);
    if ((iss !== null || issRequired) && iss !== issuer) return bad("iss is not the issuer", undefined, [flowCookie]);
    const code = params.get(AuthParam.code) ?? "";
    if (code === "") return bad("no code", undefined, [flowCookie]);
    let exchanged;
    try {
      exchanged = await connection.exchangeCode(code, flow.verifier, flow.nonce);
    } catch (err) {
      if (isOutage(err)) return fail({ kind: RefusalKind.unavailable, reason: RefusalReason.serverDown, cause: err });
      return bad("code exchange or ID token refused", err, [flowCookie]);
    }
    const { identity, tokens } = exchanged;
    let user: unknown;
    try {
      user = await cfg.mapUser({ reason: MapReason.signIn, identity, provider, request, ...(tokens.accessToken === undefined ? {} : { accessToken: tokens.accessToken }) });
    } catch (err) {
      if (isOidcError(err, OidcErrorCode.accessDenied)) return fail({ kind: RefusalKind.noAccess, reason: RefusalReason.notAuthorized, cause: err });
      return fail({ kind: RefusalKind.failed, reason: RefusalReason.hookFailed, cause: err });
    }
    if (!engine.isUserFor(user, identity)) {
      return fail({ kind: RefusalKind.failed, reason: RefusalReason.hookFailed, cause: new Error("mapUser returned no User, or one with another issuer or subject") });
    }
    // A new id on every sign-in (no session fixation); a session the browser
    // already held is ended, not inherited.
    const previous = await engine.load(request, cookies);
    if (previous.kind === LoadKind.session) await engine.end(previous.session, request);
    const session: Session = {
      id: randomToken(),
      user,
      ...(identity.providerSessionId === undefined ? {} : { providerSessionId: identity.providerSessionId }),
      tokens,
      createdAt: now,
      lastSeenAt: now,
      checkedAt: now,
      expiresAt: engine.expiresAt(now, now),
    };
    let setCookies: readonly string[];
    try {
      setCookies = await engine.write(session, request, cookies);
    } catch (err) {
      return fail({ kind: RefusalKind.failed, reason: RefusalReason.storeFailed, cause: err });
    }
    engine.emit({ kind: EventKind.login, at: now, sessionId: session.id, subject: user.subject });
    const all = [...setCookies, flowCookie];
    // Under Strict the browser holds back the new cookie on a redirect chain
    // that began cross-site (at the login server), so the landing is a
    // same-site page that navigates on.
    if (cfg.sessionCookie.sameSite === SameSite.strict) return landingPage(flow.returnTo, all);
    return redirect(HttpStatus.seeOther, flow.returnTo, all);
  }

  async function logout(request: Request): Promise<Response> {
    if (request.method !== Method.post) return methodNotAllowed(Method.post);
    if (!isSameOrigin(request, cfg.appOrigin)) {
      return (await refuse({ kind: RefusalKind.failed, reason: RefusalReason.crossSite }, request, [])).response;
    }
    const cookies = readCookies(request);
    const loaded = await engine.load(request, cookies);
    const session = loaded.kind === LoadKind.session ? loaded.session : undefined;
    if (session !== undefined) {
      await revokeAtLogout(session);
      await engine.end(session, request);
      engine.emit({ kind: EventKind.logout, at: cfg.now(), sessionId: session.id, subject: session.user.subject });
    }
    const clear = deleteChunked(cfg.sessionCookie, cookies);
    const back = cfg.appOrigin + cfg.postLogoutPath;
    let endSession: string | undefined;
    try {
      endSession = (await connection.metadata()).endSessionEndpoint;
    } catch (err) {
      // The app's session is over either way; the login server's stays.
      cfg.logger.warn("oidc: discovery failed at sign-out; ending the app's session only", { error: describe(err) });
    }
    if (endSession === undefined) return redirect(HttpStatus.seeOther, cfg.postLogoutPath, clear);
    const target = new URL(endSession);
    const hint = session?.tokens.idToken;
    if (hint !== undefined) target.searchParams.set(LogoutParam.idTokenHint, hint.reveal());
    target.searchParams.set(LogoutParam.postLogoutRedirectUri, back);
    target.searchParams.set(LogoutParam.clientId, cfg.clientId);
    return redirect(HttpStatus.seeOther, target.toString(), clear);
  }

  /**
   * Revokes the session's refresh token at sign-out, before the end-session
   * redirect. Without it a stateless cookie store deletes nothing on the
   * server, and a provider keeps an offline_access refresh token past the
   * end of its own session, so a copy of the cookie saved before sign-out
   * would keep refreshing. Best effort: a failure (or a server with no
   * revocation endpoint) is logged and observed, and sign-out goes on.
   */
  async function revokeAtLogout(session: Session): Promise<void> {
    const token = session.tokens.refreshToken;
    if (token === undefined) return;
    const failed = (cause: unknown, message: string): void => {
      cfg.logger.warn(message, { sessionId: session.id, error: describe(cause) });
      engine.emit({ kind: EventKind.revokeFailed, at: cfg.now(), sessionId: session.id, subject: session.user.subject, cause });
    };
    try {
      if (!(await connection.revoke(token, TokenTypeHint.refreshToken))) {
        failed(new Error("no revocation endpoint"), "oidc: the login server has no revocation endpoint; a saved copy of the cookie can refresh until its refresh token expires");
      }
    } catch (err) {
      failed(err, "oidc: refresh token revocation failed at sign-out; signing out anyway");
    }
  }

  async function backchannel(request: Request): Promise<Response> {
    if (request.method !== Method.post) return methodNotAllowed(Method.post);
    const store = cfg.store;
    if (store.revokeSessions === undefined) {
      return json(HttpStatus.notImplemented, { error: OidcErrorCode.backchannelUnsupported });
    }
    let token: string | null;
    try {
      token = new URLSearchParams(await request.text()).get(PARAM_LOGOUT_TOKEN);
    } catch {
      token = null;
    }
    if (token === null || token === "") return json(HttpStatus.badRequest, { error: ERROR_INVALID_REQUEST });
    let verified;
    try {
      verified = await connection.logoutToken(token);
    } catch (err) {
      cfg.logger.warn("oidc: logout token refused", { error: describe(err) });
      // Keys that could not be read are 503, so the server's log tells an
      // outage apart; any token that does not verify is 400 (section 2.8).
      return isOutage(err) ? json(HttpStatus.serviceUnavailable, { error: ERROR_TEMPORARILY_UNAVAILABLE }) : json(HttpStatus.badRequest, { error: ERROR_INVALID_REQUEST });
    }
    const target = verified.target;
    if (!replay.remember(verified.jti, verified.rememberUntil, cfg.now())) {
      cfg.logger.warn("oidc: logout token replayed (jti already used)");
      return json(HttpStatus.badRequest, { error: ERROR_INVALID_REQUEST });
    }
    let count: number;
    try {
      count = await store.revokeSessions(target, { request, now: cfg.now() });
    } catch (err) {
      replay.forget(verified.jti);
      cfg.logger.error("oidc: store.revokeSessions failed", { error: describe(err) });
      return json(HttpStatus.internalServerError, { error: ERROR_SERVER });
    }
    engine.emit({ kind: EventKind.backchannelLogout, at: cfg.now(), count, ...(target.subject === undefined ? {} : { subject: target.subject }) });
    return new Response(null, { status: HttpStatus.ok, headers: { [Header.cacheControl]: NO_STORE } });
  }

  const routes: ReadonlyArray<readonly [string, (request: Request) => Promise<Response>]> = [
    [cfg.paths.login, login],
    [cfg.paths.callback, callback],
    [cfg.paths.logout, logout],
    [cfg.paths.backchannel, backchannel],
  ];

  async function requireSession(request: Request): Promise<SessionGate> {
    const e = await engine.evaluate(request, readCookies(request));
    if (e.ok) return { allowed: true, user: e.session.user, setCookies: e.setCookies, commit: (r) => withCookies(r, e.setCookies) };
    const { refusal, response } = await refuse(e.refusal, request, e.setCookies, e.session);
    return { allowed: false, refusal, response };
  }

  async function optionalSession(request: Request): Promise<OptionalSession> {
    const e = await engine.evaluate(request, readCookies(request));
    const commit = (r: Response): Response => withCookies(r, e.setCookies);
    if (e.ok) return { signedIn: true, user: e.session.user, setCookies: e.setCookies, commit };
    if (e.session !== undefined || e.refusal.reason !== RefusalReason.noSession) {
      engine.emit({
        kind: EventKind.refuse,
        at: cfg.now(),
        reason: e.refusal.reason,
        ...(e.refusal.cause === undefined ? {} : { cause: e.refusal.cause }),
        ...(e.session === undefined ? {} : { sessionId: e.session.id, subject: e.session.user.subject }),
      });
      if (e.refusal.kind === RefusalKind.failed) cfg.logger.error("oidc: optional session failed", { reason: e.refusal.reason, error: describe(e.refusal.cause) });
    }
    return { signedIn: false, setCookies: e.setCookies, commit };
  }

  return {
    paths: cfg.paths,
    provider,
    async handle(request) {
      const path = new URL(request.url).pathname;
      const route = routes.find(([p]) => p === path);
      return route === undefined ? undefined : route[1](request);
    },
    login,
    callback,
    logout,
    backchannel,
    requireSession,
    optionalSession,
    protect(handler) {
      return async (request) => {
        const gate = await requireSession(request);
        if (!gate.allowed) return gate.response;
        return gate.commit(await handler(request, gate.user));
      };
    },
  };
}

/** Request methods the routes accept. */
const Method = { get: "GET", post: "POST" } as const;

/** Authorization request and response parameters (RFC 6749, RFC 7636, OpenID Connect Core, RFC 9207). Wire names, kept verbatim. */
const AuthParam = {
  responseType: "response_type",
  clientId: "client_id",
  redirectUri: "redirect_uri",
  scope: "scope",
  state: "state",
  nonce: "nonce",
  codeChallenge: "code_challenge",
  codeChallengeMethod: "code_challenge_method",
  code: "code",
  error: "error",
  iss: "iss",
} as const;

/** The authorization code flow's response type, the only one used. */
const RESPONSE_TYPE_CODE = "code";

/** The authorization error that means the person (or the server's policy) said no (RFC 6749 section 4.1.2.1). */
const ERROR_ACCESS_DENIED = "access_denied";

/** RP-Initiated Logout parameters. Wire names, kept verbatim. */
const LogoutParam = { idTokenHint: "id_token_hint", postLogoutRedirectUri: "post_logout_redirect_uri", clientId: "client_id" } as const;

/** The back-channel request's form member (Back-Channel Logout section 2.5). */
const PARAM_LOGOUT_TOKEN = "logout_token";

/** Error codes the back-channel route answers with (section 2.8 uses OAuth's). */
const ERROR_INVALID_REQUEST = "invalid_request";
const ERROR_TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";
const ERROR_SERVER = "server_error";

/** Headers the logout origin check reads. */
const HEADER_ORIGIN = "Origin";
const HEADER_SEC_FETCH_SITE = "Sec-Fetch-Site";

/** The Sec-Fetch-Site value of a request from the app's own origin. */
const SEC_FETCH_SAME_ORIGIN = "same-origin";

/**
 * Whether `request` came from `appOrigin`: its Origin header equals it, or,
 * with no Origin, Sec-Fetch-Site says same-origin. A request with neither
 * is refused: every browser that can run the app sends one of them on a
 * POST, and a sign-out another site can trigger is a nuisance attack.
 */
function isSameOrigin(request: Request, appOrigin: string): boolean {
  const origin = request.headers.get(HEADER_ORIGIN);
  if (origin !== null) return origin === appOrigin;
  return request.headers.get(HEADER_SEC_FETCH_SITE) === SEC_FETCH_SAME_ORIGIN;
}

/** An outage as `unavailable`; anything else as `failed` with `reason`. */
function outageOrFailure(err: unknown, reason: RefusalReason): PendingRefusal {
  return isOutage(err) ? { kind: RefusalKind.unavailable, reason: RefusalReason.serverDown, cause: err } : { kind: RefusalKind.failed, reason, cause: err };
}

/**
 * `response` with `cookies` appended as `Set-Cookie`. The response is
 * copied first: a fetched or `Response.redirect` response has immutable
 * headers, and the caller's object is not changed.
 */
function withCookies(response: Response, cookies: readonly string[]): Response {
  if (cookies.length === 0) return response;
  const out = new Response(response.body, { status: response.status, statusText: response.statusText, headers: new Headers(response.headers) });
  for (const c of cookies) out.headers.append(HEADER_SET_COOKIE, c);
  return out;
}

/** A redirect with `cookies`, never cached. */
function redirect(status: number, location: string, cookies: readonly string[]): Response {
  return withCookies(new Response(null, { status, headers: { [Header.location]: location, [Header.cacheControl]: NO_STORE } }), cookies);
}

/** A JSON answer, never cached. */
function json(status: number, body: Readonly<Record<string, string>>): Response {
  return new Response(JSON.stringify(body), { status, headers: { [Header.contentType]: MEDIA_TYPE_JSON, [Header.cacheControl]: NO_STORE } });
}

/** 405 naming the one method the route takes. */
function methodNotAllowed(allowed: string): Response {
  return new Response(null, { status: HttpStatus.methodNotAllowed, headers: { [Header.allow]: allowed, [Header.cacheControl]: NO_STORE } });
}

/** The characters HTML gives meaning to, and their escapes. */
const HTML_ESCAPES: Readonly<Record<string, string>> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

/** `s` safe inside an HTML attribute or text. */
function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => HTML_ESCAPES[c] ?? c);
}

/** The same-site landing page for a Strict cookie: navigates to `to` at once, with a link when meta refresh is disabled. */
function landingPage(to: SameSitePath, cookies: readonly string[]): Response {
  const href = escapeHtml(to);
  const body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=${href}"><title>Signing in</title></head><body><a href="${href}">Continue</a></body></html>`;
  return withCookies(new Response(body, { status: HttpStatus.ok, headers: { [Header.contentType]: MEDIA_TYPE_HTML_UTF8, [Header.cacheControl]: NO_STORE } }), cookies);
}
