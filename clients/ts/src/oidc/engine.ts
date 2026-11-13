// Package-private: the session engine behind `requireSession`,
// `optionalSession` and the routes. It loads a session from its cookie,
// applies the lifetimes, re-checks a stale session with the login server
// (single-flight per session state in this process), applies the outage
// grace and the app's authorizer, and writes the cookies that changed.
// Every outcome is a value, never a throw: a refusal carries its kind,
// reason and cause, and the cookies the browser must still receive.
// Nothing here is re-exported from index.ts.

import { Decision } from "./authorize.ts";
import { fromUtf8, utf8 } from "./bytes.ts";
import type { Resolved } from "./config.ts";
import { isOutage } from "./connection.ts";
import { deleteChunked, isCookieValue, readChunked, writeChunked } from "./cookie.ts";
import { OidcClientError, OidcErrorCode, isOidcError } from "./errors.ts";
import { MapReason, type Identity, type User } from "./identity.ts";
import { genuineRefreshed } from "./internal.ts";
import { EventKind, type OidcEvent } from "./observe.ts";
import type { Provider } from "./provider.ts";
import type { RecheckResult } from "./recheck.ts";
import { RefusalKind, RefusalReason, type Refusal } from "./respond.ts";
import { PARAM_RETURN_TO, isSameSitePath } from "./routes.ts";
import type { Session, StoreContext } from "./session.ts";

/**
 * The idle window slides at most this often: a busy session does not
 * rewrite its cookie (or its row) on every request. A value, not a policy.
 */
export const SLIDE_GRANULARITY_MS = 60 * 1000;

/**
 * How long a finished re-check's outcome is reused for a request that
 * arrives with the same session state (the same id, checkedAt and refresh
 * token). A browser sends requests it started before the new cookie arrived
 * with the old one; answering them from the outcome, instead of redeeming
 * the old refresh token again, keeps the login server from reading that as
 * token reuse and ending the whole session. In-process only; across
 * instances the provider's refresh-reuse interval covers the same race, and
 * this matches the interval the login-server guide recommends.
 */
export const RECHECK_REUSE_MS = 10 * 1000;

/** A refusal before its login URL is filled in. */
export interface PendingRefusal {
  readonly kind: RefusalKind;
  readonly reason: RefusalReason;
  readonly cause?: unknown;
}

/**
 * What the engine decided for one request. Both arms carry `setCookies`:
 * a refused request may still have rotated tokens (an authorizer said no
 * after a successful re-check), and losing them would make the next request
 * redeem a spent refresh token.
 */
export type Evaluation =
  | { readonly ok: true; readonly session: Session; readonly setCookies: readonly string[] }
  | { readonly ok: false; readonly refusal: PendingRefusal; readonly setCookies: readonly string[]; /** The session the refusal is about; absent when none loaded. */ readonly session?: Session };

/** A loaded session cookie: none (absent, does not open, no live session), a session, or a failure of the sealer or store. */
export type Loaded =
  | { readonly kind: typeof LoadKind.none; readonly cookiePresent: boolean }
  | { readonly kind: typeof LoadKind.session; readonly session: Session }
  | { readonly kind: typeof LoadKind.failed; readonly cause: unknown };

/** The arms of `Loaded`. */
export const LoadKind = { none: "none", session: "session", failed: "failed" } as const;

/** The outcome of one re-check, shared by every request of the same session state. */
type RecheckOutcome =
  | { readonly kind: typeof OutcomeKind.allowed; readonly session: Session; readonly sealed: string }
  | { readonly kind: typeof OutcomeKind.refused; readonly refusal: PendingRefusal; readonly ended: boolean }
  | { readonly kind: typeof OutcomeKind.grace }
  | { readonly kind: typeof OutcomeKind.down; readonly cause: unknown };

/** The arms of `RecheckOutcome`. */
const OutcomeKind = { allowed: "allowed", refused: "refused", grace: "grace", down: "down" } as const;

/** The engine's calls, for the client's routes and gates. */
export interface Engine {
  evaluate(request: Request, cookies: ReadonlyMap<string, string>): Promise<Evaluation>;
  load(request: Request, cookies: ReadonlyMap<string, string>): Promise<Loaded>;
  /** Saves and seals `session` and returns its `Set-Cookie` values; throws `sessionTooLarge` or the store's or sealer's error. */
  write(session: Session, request: Request, cookies: ReadonlyMap<string, string>): Promise<readonly string[]>;
  /** Deletes `session` from the store; a failure is logged, never thrown (the cookie is cleared regardless). */
  end(session: Session, request: Request): Promise<void>;
  /** The earlier of the idle and absolute ends. */
  expiresAt(lastSeenAt: number, createdAt: number): number;
  /** The refusal with its login URL, for the responder. */
  refusal(p: PendingRefusal, request: Request): Refusal;
  /** Calls the observer; a throw from it is logged and swallowed. */
  emit(event: OidcEvent): void;
  /** Whether `user` is a well-formed `User` for `identity`: the shape a hook must return, and the same issuer and subject. */
  isUserFor(user: unknown, identity: Identity): user is User;
}

/** Builds the engine for one client. Holds the in-flight re-check map, so two clients never share one. */
export function createEngine(cfg: Resolved, provider: Provider): Engine {
  const inflight = new Map<string, { readonly outcome: Promise<RecheckOutcome>; settledAt: number | undefined }>();
  const ctx = (request: Request): StoreContext => ({ request, now: cfg.now() });
  const name = cfg.sessionCookie.name;

  function emit(event: OidcEvent): void {
    if (cfg.observe === undefined) return;
    try {
      cfg.observe(event);
    } catch (err) {
      cfg.logger.warn("oidc: observer threw; ignored", { error: describe(err) });
    }
  }

  function expiresAt(lastSeenAt: number, createdAt: number): number {
    return Math.min(lastSeenAt + cfg.idleMs, createdAt + cfg.absoluteMs);
  }

  function refusal(p: PendingRefusal, request: Request): Refusal {
    const cause = p.cause === undefined ? {} : { cause: p.cause };
    if (p.kind === RefusalKind.loginRequired) return { kind: p.kind, reason: p.reason, loginUrl: loginUrlFor(request), ...cause };
    return { kind: p.kind, reason: p.reason, ...cause };
  }

  /** The login route with this request's path and query as `return_to`, when they form a same-site path. */
  function loginUrlFor(request: Request): string {
    const u = new URL(request.url);
    const back = u.pathname + u.search;
    return isSameSitePath(back) ? `${cfg.paths.login}?${new URLSearchParams({ [PARAM_RETURN_TO]: back }).toString()}` : cfg.paths.login;
  }

  async function load(request: Request, cookies: ReadonlyMap<string, string>): Promise<Loaded> {
    const sealed = readChunked(cookies, name);
    if (sealed === undefined) return { kind: LoadKind.none, cookiePresent: false };
    let value: string;
    try {
      value = fromUtf8(await cfg.sealer.open(sealed, name));
    } catch (err) {
      // Tampered, another cookie's, or a key no longer held: not signed in.
      // Anything else is the key service failing, which is not a "no".
      if (isOidcError(err, OidcErrorCode.sealedCorrupt)) return { kind: LoadKind.none, cookiePresent: true };
      return { kind: LoadKind.failed, cause: err };
    }
    let session: Session | undefined;
    try {
      session = await cfg.store.load(value, ctx(request));
    } catch (err) {
      if (isOidcError(err, OidcErrorCode.sealedCorrupt)) return { kind: LoadKind.none, cookiePresent: true };
      return { kind: LoadKind.failed, cause: err };
    }
    return session === undefined ? { kind: LoadKind.none, cookiePresent: true } : { kind: LoadKind.session, session };
  }

  /** Saves `session` and seals the store's cookie value, checking it is cookie-safe and fits the chunks. */
  async function saveAndSeal(session: Session, request: Request): Promise<string> {
    const value = await cfg.store.save(session, ctx(request));
    if (typeof value !== "string") throw new OidcClientError(OidcErrorCode.invalidConfig, "store.save must resolve to a string");
    const sealed = await cfg.sealer.seal(utf8(value), name);
    if (typeof sealed !== "string" || !isCookieValue(sealed)) throw new OidcClientError(OidcErrorCode.invalidConfig, "sealer output is not cookie-safe text");
    if (writeChunked(cfg.sessionCookie, sealed, 0, new Map()) === undefined) {
      throw new OidcClientError(OidcErrorCode.sessionTooLarge, `sealed session is ${sealed.length} characters; keep fewer claims in mapUser or use a server-side store`);
    }
    return sealed;
  }

  /** The `Set-Cookie` values for `sealed` on this request, deleting chunks it no longer needs. */
  function cookiesFor(sealed: string, session: Session, cookies: ReadonlyMap<string, string>): readonly string[] {
    const maxAge = (session.expiresAt - cfg.now()) / 1000;
    return writeChunked(cfg.sessionCookie, sealed, maxAge, cookies) ?? deleteChunked(cfg.sessionCookie, cookies);
  }

  async function write(session: Session, request: Request, cookies: ReadonlyMap<string, string>): Promise<readonly string[]> {
    return cookiesFor(await saveAndSeal(session, request), session, cookies);
  }

  async function end(session: Session, request: Request): Promise<void> {
    try {
      await cfg.store.delete(session, ctx(request));
    } catch (err) {
      cfg.logger.error("oidc: store.delete failed; the cookie is cleared regardless", { sessionId: session.id, error: describe(err) });
    }
  }

  function isUserFor(user: unknown, identity: Identity): user is User {
    if (typeof user !== "object" || user === null) return false;
    const u: Partial<Record<keyof User, unknown>> = user;
    return (
      typeof u.id === "string" &&
      u.id !== "" &&
      u.issuer === identity.issuer &&
      u.subject === identity.subject &&
      typeof u.email === "string" &&
      typeof u.emailVerified === "boolean" &&
      typeof u.name === "string" &&
      Array.isArray(u.roles) &&
      u.roles.every((r) => typeof r === "string") &&
      (u.claims === undefined || (typeof u.claims === "object" && u.claims !== null))
    );
  }

  /**
   * One re-check of `s`: the rechecker, then (on a new Identity) the user
   * mapper, then the save. Fails closed at every step: only an explicit
   * allow, with a genuine `Refreshed` when there is one, keeps the session.
   */
  async function recheck(s: Session, request: Request): Promise<RecheckOutcome> {
    const now = cfg.now();
    const ended = async (refusal: PendingRefusal): Promise<RecheckOutcome> => {
      await end(s, request);
      return { kind: OutcomeKind.refused, refusal, ended: true };
    };
    let result: RecheckResult;
    try {
      result = await cfg.rechecker({ session: s, provider, request, now });
    } catch (err) {
      if (isOutage(err)) {
        if (now - s.checkedAt < cfg.outageGraceMs) {
          emit({ kind: EventKind.grace, at: now, sessionId: s.id, subject: s.user.subject, cause: err });
          cfg.logger.warn("oidc: login server unreachable; using the last yes within the outage grace", { sessionId: s.id, error: describe(err) });
          return { kind: OutcomeKind.grace };
        }
        return { kind: OutcomeKind.down, cause: err };
      }
      return ended({ kind: RefusalKind.loginRequired, reason: RefusalReason.serverRefused, cause: err });
    }
    // Anything but an explicit allow (a deny, undefined from a sloppy
    // rechecker, a misspelt decision) ends the session.
    if (typeof result !== "object" || result === null || result.decision !== Decision.allow) {
      if (s.tokens.refreshToken === undefined) cfg.logger.info("oidc: session has no refresh token to re-check with; ask for offline_access", { sessionId: s.id });
      return ended({ kind: RefusalKind.loginRequired, reason: RefusalReason.serverRefused });
    }
    const refreshed = result.refreshed;
    if (refreshed !== undefined && !genuineRefreshed.has(refreshed)) {
      return ended({ kind: RefusalKind.failed, reason: RefusalReason.hookFailed, cause: new Error("rechecker returned a Refreshed that Provider.refresh did not make") });
    }
    let user = s.user;
    let providerSessionId = s.providerSessionId;
    let tokens = s.tokens;
    if (refreshed !== undefined) {
      const idToken = refreshed.tokens.idToken ?? s.tokens.idToken;
      const scope = refreshed.tokens.scope ?? s.tokens.scope;
      tokens = { ...refreshed.tokens, ...(idToken === undefined ? {} : { idToken }), ...(scope === undefined ? {} : { scope }) };
      const identity = refreshed.identity;
      if (identity !== undefined) {
        if (identity.issuer !== s.user.issuer || identity.subject !== s.user.subject) {
          return ended({ kind: RefusalKind.loginRequired, reason: RefusalReason.serverRefused, cause: new Error("refreshed ID token names another person") });
        }
        let mapped: unknown;
        try {
          mapped = await cfg.mapUser({
            reason: MapReason.refresh,
            identity,
            previous: s.user,
            provider,
            request,
            ...(tokens.accessToken === undefined ? {} : { accessToken: tokens.accessToken }),
          });
        } catch (err) {
          if (isOidcError(err, OidcErrorCode.accessDenied)) return ended({ kind: RefusalKind.noAccess, reason: RefusalReason.notAuthorized, cause: err });
          return ended({ kind: RefusalKind.failed, reason: RefusalReason.hookFailed, cause: err });
        }
        if (!isUserFor(mapped, identity)) {
          return ended({ kind: RefusalKind.failed, reason: RefusalReason.hookFailed, cause: new Error("mapUser returned no User, or one with another issuer or subject") });
        }
        user = mapped;
        providerSessionId = identity.providerSessionId ?? s.providerSessionId;
      }
    }
    const next: Session = {
      id: s.id,
      user,
      ...(providerSessionId === undefined ? {} : { providerSessionId }),
      tokens,
      createdAt: s.createdAt,
      lastSeenAt: now,
      checkedAt: now,
      expiresAt: expiresAt(now, s.createdAt),
    };
    let sealed: string;
    try {
      sealed = await saveAndSeal(next, request);
    } catch (err) {
      return { kind: OutcomeKind.refused, refusal: { kind: RefusalKind.failed, reason: RefusalReason.storeFailed, cause: err }, ended: false };
    }
    emit({ kind: EventKind.refresh, at: now, sessionId: s.id, subject: user.subject });
    return { kind: OutcomeKind.allowed, session: next, sealed };
  }

  /**
   * `recheck`, shared: requests carrying the same session state while one
   * is in flight, or within `RECHECK_REUSE_MS` after it settled, get its
   * outcome. The key is the state, not only the id, so an older saved copy
   * of the cookie (another refresh token, another checkedAt) never borrows
   * the current copy's "yes".
   */
  function sharedRecheck(s: Session, request: Request): Promise<RecheckOutcome> {
    const now = cfg.now();
    for (const [k, v] of inflight) if (v.settledAt !== undefined && now - v.settledAt >= RECHECK_REUSE_MS) inflight.delete(k);
    const key = `${s.id}\u0000${s.checkedAt}\u0000${s.tokens.refreshToken?.reveal() ?? ""}`;
    const existing = inflight.get(key);
    if (existing !== undefined) return existing.outcome;
    const entry: { outcome: Promise<RecheckOutcome>; settledAt: number | undefined } = { outcome: recheck(s, request), settledAt: undefined };
    inflight.set(key, entry);
    // A grace or down outcome is not reused: the next request should try
    // the server again rather than wait out the window.
    entry.outcome.then(
      (o) => (o.kind === OutcomeKind.allowed || o.kind === OutcomeKind.refused ? (entry.settledAt = cfg.now()) : inflight.delete(key)),
      () => inflight.delete(key),
    );
    return entry.outcome;
  }

  async function evaluate(request: Request, cookies: ReadonlyMap<string, string>): Promise<Evaluation> {
    const loaded = await load(request, cookies);
    if (loaded.kind === LoadKind.none) {
      return { ok: false, refusal: { kind: RefusalKind.loginRequired, reason: RefusalReason.noSession }, setCookies: loaded.cookiePresent ? deleteChunked(cfg.sessionCookie, cookies) : [] };
    }
    if (loaded.kind === LoadKind.failed) {
      cfg.logger.error("oidc: session could not be loaded", { error: describe(loaded.cause) });
      return { ok: false, refusal: { kind: RefusalKind.failed, reason: RefusalReason.storeFailed, cause: loaded.cause }, setCookies: [] };
    }
    const s = loaded.session;
    const now = cfg.now();
    const clear = deleteChunked(cfg.sessionCookie, cookies);
    if (now >= s.createdAt + cfg.absoluteMs || now < s.createdAt) {
      await end(s, request);
      return { ok: false, refusal: { kind: RefusalKind.loginRequired, reason: RefusalReason.absoluteExpired }, setCookies: clear, session: s };
    }
    if (now >= s.lastSeenAt + cfg.idleMs) {
      await end(s, request);
      return { ok: false, refusal: { kind: RefusalKind.loginRequired, reason: RefusalReason.idleExpired }, setCookies: clear, session: s };
    }

    let current = s;
    let setCookies: readonly string[] = [];
    // A checkedAt in the future (a clock moved back) is stale, not fresh forever.
    if (now < s.checkedAt || now - s.checkedAt >= cfg.recheckIntervalMs) {
      const outcome = await sharedRecheck(s, request);
      switch (outcome.kind) {
        case OutcomeKind.allowed:
          current = outcome.session;
          setCookies = cookiesFor(outcome.sealed, outcome.session, cookies);
          break;
        case OutcomeKind.refused:
          return { ok: false, refusal: outcome.refusal, setCookies: outcome.ended ? clear : [], session: s };
        case OutcomeKind.down:
          // The session is kept: the person is back the moment the server is.
          return { ok: false, refusal: { kind: RefusalKind.unavailable, reason: RefusalReason.serverDown, cause: outcome.cause }, setCookies: [], session: s };
        case OutcomeKind.grace:
          break;
        default:
          return unreachable(outcome);
      }
    } else if (now - s.lastSeenAt >= SLIDE_GRANULARITY_MS) {
      const slid: Session = { ...s, lastSeenAt: now, expiresAt: expiresAt(now, s.createdAt) };
      try {
        setCookies = await write(slid, request, cookies);
        current = slid;
      } catch (err) {
        // Sliding is a convenience; the session is still valid without it.
        cfg.logger.warn("oidc: could not slide the idle window", { sessionId: s.id, error: describe(err) });
      }
    }

    if (cfg.authorize !== undefined) {
      let decision: unknown;
      try {
        decision = await cfg.authorize({ user: current.user, request });
      } catch (err) {
        const denied = isOidcError(err, OidcErrorCode.accessDenied);
        return {
          ok: false,
          refusal: { kind: denied ? RefusalKind.noAccess : RefusalKind.failed, reason: denied ? RefusalReason.notAuthorized : RefusalReason.hookFailed, cause: err },
          setCookies,
          session: s,
        };
      }
      if (decision !== Decision.allow) return { ok: false, refusal: { kind: RefusalKind.noAccess, reason: RefusalReason.notAuthorized }, setCookies, session: s };
    }
    return { ok: true, session: current, setCookies };
  }

  return { evaluate, load, write, end, expiresAt, refusal, emit, isUserFor };
}

/** A compile error when a union arm is added and not handled. */
function unreachable(value: never): never {
  throw new Error(`unhandled outcome ${JSON.stringify(value)}`);
}

/** An error's message for a log field: never the error object itself, whose own fields might hold a request. */
export function describe(err: unknown): string {
  if (err instanceof Error) return err.cause instanceof Error ? `${err.message}: ${err.cause.message}` : err.message;
  return String(err);
}
