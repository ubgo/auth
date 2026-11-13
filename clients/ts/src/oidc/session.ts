// Sessions: what one signed-in browser holds, how long it lives, and where
// it is kept.

import { OidcClientError, OidcErrorCode } from "./errors.ts";
import type { Claims, User } from "./identity.ts";
import { bool, isJsonObject, num, obj, parseJsonObject, str, strList, type JsonObject } from "./json.ts";
import { secret, type Secret } from "./secret.ts";

/**
 * What the login server's token endpoint returned, kept so the session can be
 * re-checked (`refreshToken`), the person signed out at the server (`idToken`
 * as `id_token_hint`) and the server's APIs called (`accessToken`).
 */
export interface Tokens {
  readonly accessToken?: Secret;
  /** Absent when the server granted none; `recheckByRefresh` then refuses at the first re-check. */
  readonly refreshToken?: Secret;
  readonly idToken?: Secret;
  /** When the access token stops (epoch milliseconds), from `expires_in`; absent when the server sent none. */
  readonly accessExpiresAt?: number;
  /** The granted scope, space separated, as the server sent it. */
  readonly scope?: string;
}

/**
 * One signed-in browser: who, the tokens, and the three times the model runs
 * on. Every time is epoch milliseconds from the configured clock. The package
 * writes every field; a `SessionStore` keeps it and returns it unchanged.
 */
export interface Session {
  /**
   * Random (256 bits), set at sign-in, stable for the session's life: a
   * server-side store's key, and the single-flight key that lets one refresh
   * serve every concurrent request of the session in this process.
   */
  readonly id: string;
  readonly user: User;
  /** The ID token's `sid`, which a back-channel logout token may name instead of the subject. */
  readonly providerSessionId?: string;
  readonly tokens: Tokens;
  /** Sign-in time; the absolute lifetime counts from it. */
  readonly createdAt: number;
  /**
   * The last request that moved the idle window; the idle lifetime counts from
   * it. Advanced at most once a minute, so a busy session does not rewrite its
   * cookie or row on every request.
   */
  readonly lastSeenAt: number;
  /** The last time the login server said yes. Fresh while within the recheck interval of it; the outage grace counts from it. */
  readonly checkedAt: number;
  /**
   * The earlier of `lastSeenAt + idle` and `createdAt + absolute`, written
   * before every save, so a store sets its TTL from it without knowing the
   * lifetimes.
   */
  readonly expiresAt: number;
}

/**
 * What a `SessionStore` call may read besides the session: the request being
 * served, so an app's own session system can find its context (and, through
 * `request.signal`, stop when the client goes away).
 */
export interface StoreContext {
  readonly request: Request;
  /**
   * The client's clock for this call (epoch milliseconds, the `now` option),
   * so a store that drops expired sessions compares `Session.expiresAt`
   * against the same clock that wrote it, also under a test clock.
   */
  readonly now: number;
}

/**
 * Keeps sessions. The package owns the session cookie: it seals whatever
 * string `save` returns under the cookie name, sets the cookie with the
 * cookie options, and hands the opened string back to `load`. So a store
 * never touches HTTP, cookies or keys, and every store gets the same cookie
 * floors.
 *
 * Two models fit. A stateless store returns the whole session as the cookie
 * value (the default, `cookieStore`). A server-side store (Redis, SQL, the
 * app's own session system) keeps the session and returns its `id`. Only a
 * server-side store can end a session the browser still holds a cookie for,
 * which back-channel logout and `recheckBackchannelOnly` need: it adds the
 * optional `revokeSessions`.
 */
export interface SessionStore {
  /** Keeps `session` until `session.expiresAt` and returns the cookie value. Called at sign-in and whenever a field changed. */
  save(session: Session, ctx: StoreContext): Promise<string>;
  /**
   * The session `cookieValue` names, or `undefined` when none is live (deleted,
   * expired, revoked): "not signed in", never a failure. A throw is a failure
   * and refuses the request.
   */
  load(cookieValue: string, ctx: StoreContext): Promise<Session | undefined>;
  /** Ends `session` (sign-out, expiry, a refused re-check). Deleting one that is already gone is not an error. */
  delete(session: Session, ctx: StoreContext): Promise<void>;
  /**
   * The optional upgrade: end every session `target` matches without their
   * cookie, and return how many it ended (zero is not an error). Apply
   * `logoutTargetMatches`, so every store follows one rule. Without it the
   * back-channel route answers 501 and `recheckBackchannelOnly` is refused
   * at start-up.
   */
  revokeSessions?(target: LogoutTarget, ctx: StoreContext): Promise<number>;
}

/**
 * The sessions a back-channel logout token ends: those of `subject` at
 * `issuer`, narrowed to the login server's session `providerSessionId` when
 * the token names one. A union, so "neither subject nor sid" cannot be built.
 */
export type LogoutTarget =
  | { readonly issuer: string; readonly subject: string; readonly providerSessionId?: string }
  | { readonly issuer: string; readonly subject?: string; readonly providerSessionId: string };

/**
 * Whether `session` is one `target` names: same issuer, and the same subject
 * and provider session for each of the two the target sets. The rule every
 * `revokeSessions` applies, exported so a custom store's query and
 * `memoryStore` cannot drift. Empty strings never match, so a malformed
 * target ends nothing.
 */
export function logoutTargetMatches(target: LogoutTarget, session: Session): boolean {
  const subject = target.subject ?? "";
  const sid = target.providerSessionId ?? "";
  if (target.issuer === "" || session.user.issuer !== target.issuer || (subject === "" && sid === "")) return false;
  if (subject !== "" && session.user.subject !== subject) return false;
  return sid === "" || session.providerSessionId === sid;
}

/**
 * The default `SessionStore`: stateless, the whole session encoded into the
 * cookie (sealed by the client, split over a few cookies when it exceeds
 * one), nothing kept on the server. It survives restarts and needs no
 * database, but cannot end a session the browser still holds, so it has no
 * `revokeSessions`: the recheck interval is what bounds a removed person's
 * access.
 */
export function cookieStore(): SessionStore {
  return {
    save: async (session) => encodeSession(session),
    // A value that does not decode throws sealedCorrupt, which the client
    // reads as "no session"; expiry is the client's check, not the store's.
    load: async (cookieValue) => decodeSession(cookieValue),
    // Nothing is kept, so nothing to end: the client deletes the cookie.
    delete: async () => undefined,
  };
}

/** A store that also implements the back-channel upgrade, as `memoryStore` returns. */
export type RevokingSessionStore = SessionStore & Required<Pick<SessionStore, "revokeSessions">>;

/**
 * A server-side store in this process's memory: the cookie carries only the
 * session id. It supports back-channel logout and suits tests and a single
 * long-lived instance; sessions are lost on restart and not shared between
 * instances or serverless invocations, for which a Redis or SQL store
 * implements the same interface. Expired sessions are dropped as they are
 * read and swept periodically, so memory does not grow without bound.
 */
export function memoryStore(): RevokingSessionStore {
  const sessions = new Map<string, Session>();
  let lastSweep = Number.NEGATIVE_INFINITY;
  // Drops every expired session, at most once per MEMORY_SWEEP_INTERVAL_MS
  // and only when called: no timer, so the store never keeps a process (or a
  // test runner) alive and needs no stop method.
  const sweep = (now: number): void => {
    if (now - lastSweep < MEMORY_SWEEP_INTERVAL_MS) return;
    lastSweep = now;
    for (const [id, s] of sessions) if (s.expiresAt <= now) sessions.delete(id);
  };
  return {
    async save(session, ctx) {
      sweep(ctx.now);
      sessions.set(session.id, session);
      return session.id;
    },
    async load(cookieValue, ctx) {
      sweep(ctx.now);
      const s = sessions.get(cookieValue);
      if (s === undefined) return undefined;
      if (s.expiresAt <= ctx.now) {
        sessions.delete(cookieValue);
        return undefined;
      }
      return s;
    },
    async delete(session) {
      sessions.delete(session.id);
    },
    async revokeSessions(target) {
      let n = 0;
      for (const [id, s] of sessions) {
        if (logoutTargetMatches(target, s)) {
          sessions.delete(id);
          n++;
        }
      }
      return n;
    },
  };
}

/** How often `memoryStore` walks its map for expired sessions: often enough to bound memory, rarely enough to cost nothing per request. */
const MEMORY_SWEEP_INTERVAL_MS = 60 * 1000;

/**
 * Serialises a session for a server-side store, revealing its tokens on
 * purpose (`JSON.stringify` alone would write `[redacted]`). The output holds
 * live credentials: keep it only where the session belongs, never in a log.
 */
export function encodeSession(session: Session): string {
  const t = session.tokens;
  const record: SessionRecord = {
    [Field.version]: SESSION_FORMAT_V1,
    [Field.id]: session.id,
    [Field.user]: userRecord(session.user),
    ...(session.providerSessionId === undefined ? {} : { [Field.providerSessionId]: session.providerSessionId }),
    [Field.tokens]: {
      ...(t.accessToken === undefined ? {} : { [TokenField.accessToken]: t.accessToken.reveal() }),
      ...(t.refreshToken === undefined ? {} : { [TokenField.refreshToken]: t.refreshToken.reveal() }),
      ...(t.idToken === undefined ? {} : { [TokenField.idToken]: t.idToken.reveal() }),
      ...(t.accessExpiresAt === undefined ? {} : { [TokenField.accessExpiresAt]: t.accessExpiresAt }),
      ...(t.scope === undefined ? {} : { [TokenField.scope]: t.scope }),
    },
    [Field.createdAt]: session.createdAt,
    [Field.lastSeenAt]: session.lastSeenAt,
    [Field.checkedAt]: session.checkedAt,
    [Field.expiresAt]: session.expiresAt,
  };
  return JSON.stringify(record);
}

/**
 * Parses what `encodeSession` wrote, checking every field's type and
 * re-wrapping the tokens as `Secret`. Anything malformed throws
 * `OidcErrorCode.sealedCorrupt`, which reads as "no session": a store row
 * damaged or written by another version never becomes a half-filled session.
 */
export function decodeSession(text: string): Session {
  const o = parseJsonObject(text);
  if (o === undefined || num(o, Field.version) !== SESSION_FORMAT_V1) return corrupt("not a session record of this version");
  const id = str(o, Field.id);
  const userObj = obj(o, Field.user);
  const tokensObj = obj(o, Field.tokens);
  const createdAt = num(o, Field.createdAt);
  const lastSeenAt = num(o, Field.lastSeenAt);
  const checkedAt = num(o, Field.checkedAt);
  const expiresAt = num(o, Field.expiresAt);
  if (id === undefined || id === "" || userObj === undefined || tokensObj === undefined) return corrupt("session record misses a field");
  if (createdAt === undefined || lastSeenAt === undefined || checkedAt === undefined || expiresAt === undefined) return corrupt("session record misses a time");
  const providerSessionId = optionalString(o, Field.providerSessionId);
  return {
    id,
    user: decodeUser(userObj),
    ...(providerSessionId === undefined ? {} : { providerSessionId }),
    tokens: decodeTokens(tokensObj),
    createdAt,
    lastSeenAt,
    checkedAt,
    expiresAt,
  };
}

/**
 * The member names of an encoded session, written out in full so a row in a
 * store reads without this file at hand. Changing one is a format change:
 * bump `SESSION_FORMAT_V1`'s successor, never rename in place.
 */
const Field = {
  version: "v",
  id: "id",
  user: "user",
  providerSessionId: "provider_session_id",
  tokens: "tokens",
  createdAt: "created_at",
  lastSeenAt: "last_seen_at",
  checkedAt: "checked_at",
  expiresAt: "expires_at",
} as const;

/** The member names under `tokens`. */
const TokenField = {
  accessToken: "access_token",
  refreshToken: "refresh_token",
  idToken: "id_token",
  accessExpiresAt: "access_expires_at",
  scope: "scope",
} as const;

/** The member names under `user`. */
const UserField = {
  id: "id",
  issuer: "issuer",
  subject: "subject",
  email: "email",
  emailVerified: "email_verified",
  name: "name",
  roles: "roles",
  claims: "claims",
} as const;

/** The encoding's version; a record with another is refused, never guessed at. */
const SESSION_FORMAT_V1 = 1;

/** An encoded session: a JSON object. */
type SessionRecord = JsonObject;

/** `user` as an encoded record. */
function userRecord(u: User): JsonObject {
  return {
    [UserField.id]: u.id,
    [UserField.issuer]: u.issuer,
    [UserField.subject]: u.subject,
    [UserField.email]: u.email,
    [UserField.emailVerified]: u.emailVerified,
    [UserField.name]: u.name,
    [UserField.roles]: [...u.roles],
    ...(u.claims === undefined ? {} : { [UserField.claims]: u.claims }),
  };
}

/** The `User` in an encoded record; every field typed or the whole record is corrupt. */
function decodeUser(o: JsonObject): User {
  const id = str(o, UserField.id);
  const issuer = str(o, UserField.issuer);
  const subject = str(o, UserField.subject);
  const email = str(o, UserField.email);
  const emailVerified = bool(o, UserField.emailVerified);
  const name = str(o, UserField.name);
  const roles = strList(o, UserField.roles);
  if (id === undefined || issuer === undefined || subject === undefined || email === undefined || emailVerified === undefined || name === undefined || roles === undefined) {
    return corrupt("session user misses a field");
  }
  let claims: Claims | undefined;
  if (UserField.claims in o) {
    const c = o[UserField.claims];
    if (!isJsonObject(c)) return corrupt("session claims are not an object");
    claims = c;
  }
  return { id, issuer, subject, email, emailVerified, name, roles, ...(claims === undefined ? {} : { claims }) };
}

/** The `Tokens` in an encoded record, re-wrapped as `Secret`. */
function decodeTokens(o: JsonObject): Tokens {
  const accessToken = optionalString(o, TokenField.accessToken);
  const refreshToken = optionalString(o, TokenField.refreshToken);
  const idToken = optionalString(o, TokenField.idToken);
  const scope = optionalString(o, TokenField.scope);
  let accessExpiresAt: number | undefined;
  if (TokenField.accessExpiresAt in o) {
    accessExpiresAt = num(o, TokenField.accessExpiresAt);
    if (accessExpiresAt === undefined) return corrupt("session access expiry is not a number");
  }
  return {
    ...(accessToken === undefined ? {} : { accessToken: secret(accessToken) }),
    ...(refreshToken === undefined ? {} : { refreshToken: secret(refreshToken) }),
    ...(idToken === undefined ? {} : { idToken: secret(idToken) }),
    ...(accessExpiresAt === undefined ? {} : { accessExpiresAt }),
    ...(scope === undefined ? {} : { scope }),
  };
}

/** Member `name` when absent (`undefined`) or a string; any other type makes the record corrupt. */
function optionalString(o: JsonObject, name: string): string | undefined {
  if (!(name in o)) return undefined;
  const v = str(o, name);
  return v ?? corrupt(`session ${name} is not a string`);
}

/** Throws the one error every malformed record raises. */
function corrupt(why: string): never {
  throw new OidcClientError(OidcErrorCode.sealedCorrupt, why);
}

/**
 * Bounds a session whatever the login server says, in milliseconds. `idleMs`
 * ends a session nobody used for that long (sliding: every active minute
 * moves it); `absoluteMs` ends it that long after sign-in, used or not. An
 * absent field takes its default; `createOidcClient` refuses a value that is
 * not positive, or idle above absolute.
 */
export interface Lifetimes {
  readonly idleMs?: number;
  readonly absoluteMs?: number;
}

/** Closing the browser on Monday and coming back on Wednesday keeps the person signed in. */
export const DEFAULT_IDLE_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;

/** Nobody stays signed in past a month without passing the login server again. */
export const DEFAULT_ABSOLUTE_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;
