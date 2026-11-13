// Re-checks: how, and how often, the login server is asked again.

import { Decision } from "./authorize.ts";
import { OidcErrorCode, isOidcError } from "./errors.ts";
import { TokenTypeHint, type Provider, type Refreshed } from "./provider.ts";
import type { Session } from "./session.ts";

/** One re-check of a session whose last "yes" is older than the recheck interval. */
export interface RecheckInput {
  readonly session: Session;
  readonly provider: Provider;
  /** The request that found the session stale. Under single-flight, the first of the concurrent requests. */
  readonly request: Request;
  /** The client's clock (epoch milliseconds, the `now` option), for a rechecker that compares token expiry. */
  readonly now: number;
}

/**
 * A `Rechecker`'s answer. Discriminated on `decision`: only an allow may
 * carry new tokens, and they arrive only as a `Refreshed`, which only
 * `Provider.refresh` makes; the `UserMapper` sees a new Identity in it as a
 * refresh.
 */
export type RecheckResult =
  | { readonly decision: typeof Decision.allow; readonly refreshed?: Refreshed }
  | { readonly decision: typeof Decision.deny };

/**
 * Asks the login server whether a session still stands. The client calls it
 * at most once per recheck interval per session, and at most once at a time
 * per session in this process: concurrent requests of one session await the
 * same promise (single-flight), so two tabs never spend one refresh token
 * twice from here. Other processes are the provider's refresh-reuse grace's
 * concern.
 *
 * It fails closed: only `{ decision: "allow" }` keeps the session. Deny ends
 * it and the person signs in again (the login server then decides). A throw
 * of `OidcErrorCode.providerUnavailable` keeps the last "yes" for the outage
 * grace; any other throw ends the session as deny does.
 */
export type Rechecker = (input: RecheckInput) => Promise<RecheckResult>;

/**
 * The default `Rechecker`: redeem the session's refresh token. A server that
 * re-asks its access rule on every refresh (ubgo/auth's provider does)
 * refuses a removed person within one recheck interval. A session without a
 * refresh token (ask for `offline_access`, or Google's `access_type=offline`
 * through `authParams`) is refused at its first re-check, and the log says
 * why.
 */
export function recheckByRefresh(): Rechecker {
  return async ({ session, provider }) => {
    const refreshToken = session.tokens.refreshToken;
    if (refreshToken === undefined) return DENY; // The client logs why: no refresh token was granted.
    return refusedAsDeny(async () => ({
      decision: Decision.allow,
      refreshed: await provider.refresh({ refreshToken, subject: session.user.subject }),
    }));
  };
}

/**
 * Asks the introspection endpoint about the session's refresh token (its
 * access token when it has none) and allows while it is active and, when
 * the answer names a subject, names the session's. Nothing is rotated.
 * Whether a removed person shows as inactive depends on the server revoking
 * their tokens (ubgo/auth's operator revoke does).
 */
export function recheckByIntrospection(): Rechecker {
  return async ({ session, provider }) => {
    const { refreshToken, accessToken } = session.tokens;
    const token = refreshToken ?? accessToken;
    if (token === undefined) return DENY;
    const hint = refreshToken === undefined ? TokenTypeHint.accessToken : TokenTypeHint.refreshToken;
    return refusedAsDeny(async () => {
      const answer = await provider.introspect({ token, hint });
      const sameSubject = answer.subject === undefined || answer.subject === session.user.subject;
      return answer.active && sameSubject ? ALLOW : DENY;
    });
  };
}

/**
 * Calls the userinfo endpoint with the session's access token and allows on
 * a 200 for the same subject. An access token that is missing or expired
 * (by `Tokens.accessExpiresAt`) is refreshed first, and the refreshed tokens
 * are kept. For a server whose userinfo, not its token endpoint, applies the
 * access rule.
 */
export function recheckByUserInfo(): Rechecker {
  return async ({ session, provider, now }) => {
    const { accessToken, accessExpiresAt, refreshToken } = session.tokens;
    const expired = accessToken === undefined || (accessExpiresAt !== undefined && accessExpiresAt <= now);
    return refusedAsDeny(async (): Promise<RecheckResult> => {
      let token = accessToken;
      let refreshed: Refreshed | undefined;
      if (expired) {
        if (refreshToken === undefined) return DENY;
        refreshed = await provider.refresh({ refreshToken, subject: session.user.subject });
        token = refreshed.tokens.accessToken;
      }
      if (token === undefined) return DENY;
      await provider.userInfo({ accessToken: token, subject: session.user.subject });
      return refreshed === undefined ? ALLOW : { decision: Decision.allow, refreshed };
    });
  };
}

/** The plain answers, shared so no rechecker spells them out. */
const ALLOW: RecheckResult = { decision: Decision.allow };
const DENY: RecheckResult = { decision: Decision.deny };

/**
 * Runs `ask`, reading the server's "no" (`providerRefused`) and a token that
 * fails a floor (`invalidToken`) as deny. Every other throw passes through:
 * `providerUnavailable` so the client applies the outage grace, anything
 * else so the client refuses and logs it as a failure.
 */
async function refusedAsDeny(ask: () => Promise<RecheckResult>): Promise<RecheckResult> {
  try {
    return await ask();
  } catch (err) {
    if (isOidcError(err, OidcErrorCode.providerRefused) || isOidcError(err, OidcErrorCode.invalidToken)) return DENY;
    throw err;
  }
}

/**
 * Never calls the login server: the session stands until the server's
 * back-channel logout token ends it (or a lifetime does). `createOidcClient`
 * refuses it unless the store has `revokeSessions`, because with a stateless
 * cookie nothing could ever end the session. Back-channel delivery is best
 * effort with no retry in the specification, so prefer a periodic re-check
 * where removal must be certain.
 */
export function recheckBackchannelOnly(): Rechecker {
  return backchannelOnly;
}

/**
 * The `recheckBackchannelOnly` rechecker. One shared function, so
 * `createOidcClient` recognises it by identity and checks the store.
 */
const backchannelOnly: Rechecker = async () => ({ decision: Decision.allow });

/** Whether `r` is `recheckBackchannelOnly()`; package-internal, used by `createOidcClient`. */
export function isBackchannelOnly(r: Rechecker): boolean {
  return r === backchannelOnly;
}

/**
 * How long the login server's last "yes" stands: a person removed at the
 * server is refused by the app within this long, even with a saved cookie.
 */
export const DEFAULT_RECHECK_INTERVAL_MS = 60 * 1000;

/** Given as `recheckIntervalMs`, asks the login server on every request: strict, one round trip per request. */
export const RECHECK_EVERY_REQUEST = 0;

/**
 * How long the last "yes" still stands while the login server cannot be
 * reached, counted from `Session.checkedAt`. After it, requests are answered
 * "unavailable" and the session is kept, so the person is back the moment the
 * server answers.
 */
export const DEFAULT_OUTAGE_GRACE_MS = 5 * 60 * 1000;

/** Given as `outageGraceMs`, refuses as soon as the login server cannot be reached. */
export const NO_OUTAGE_GRACE = 0;
