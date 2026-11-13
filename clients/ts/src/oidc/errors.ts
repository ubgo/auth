/**
 * Error codes a caller may branch on. Every other failure is wrapped with
 * its cause for the log and answered as a refusal: the package never turns
 * an unexpected error into a "yes".
 *
 * A closed set: `OidcErrorCode` is the union of the values, and
 * `OIDC_ERROR_CODES` the list to iterate.
 */
export const OidcErrorCode = {
  /**
   * `createOidcClient` found options that cannot be used safely: a missing
   * field, an http issuer or app URL on a non-loopback host, conflicting
   * options, a cookie name the browser would reject, a reserved
   * authorization parameter. The message names the field. Thrown at start-up,
   * never per request.
   */
  invalidConfig: "invalid_config",
  /**
   * Thrown (or wrapped as `cause`) by a `UserMapper` or `Authorizer` to say
   * "this person may not use the app": answered with the no-access response.
   * Any other thrown error refuses too, but as a failure, so an outage of the
   * app's own user database is not shown as a permanent "no".
   */
  accessDenied: "access_denied",
  /**
   * No answer from the login server: a network error, a timeout, a 5xx, an
   * unreadable body. Only this code starts the outage grace; a `Rechecker`
   * that fails for any other reason refuses at once. A custom `Rechecker`
   * throws it when, and only when, the server could not be asked.
   */
  providerUnavailable: "provider_unavailable",
  /**
   * The login server answered "no": `invalid_grant` on a refresh, 401 from
   * userinfo, a token endpoint that refuses the client. It ends the session
   * and never starts the outage grace.
   */
  providerRefused: "provider_refused",
  /**
   * The back-channel route was called but the `SessionStore` has no
   * `revokeSessions`, so the login server's log shows why its logout token
   * did nothing. The default cookie store is such a store; `memoryStore` is not.
   */
  backchannelUnsupported: "backchannel_unsupported",
  /**
   * A session whose sealed form does not fit the cookie store's limit. Sign-in
   * is refused rather than writing a cookie the browser would drop silently;
   * a `UserMapper` that keeps fewer claims, or a server-side store, fixes it.
   */
  sessionTooLarge: "session_too_large",
  /**
   * What a `Sealer`'s `open` throws for a value that does not open: tampered,
   * sealed under another cookie name, or under a key no longer held. It reads
   * as "no session"; any other error from `open` is a failure to reach the
   * key service.
   */
  sealedCorrupt: "sealed_corrupt",
  /**
   * A token from the login server failed a floor: not a compact JWS, an
   * algorithm outside `ID_TOKEN_ALGORITHMS`, a signature no current key
   * verifies, or a wrong iss, aud, azp, exp, nonce or sub. A sign-in is
   * refused, a re-check ends the session; it never starts the outage grace.
   */
  invalidToken: "invalid_token",
} as const;

/** One of the `OidcErrorCode` values. */
export type OidcErrorCode = (typeof OidcErrorCode)[keyof typeof OidcErrorCode];

/** Every `OidcErrorCode`, for iteration (tests, metrics labels). */
export const OIDC_ERROR_CODES: readonly OidcErrorCode[] = Object.values(OidcErrorCode);

/**
 * The one error type the package throws on purpose, and the one a hook throws
 * to steer a refusal (`accessDenied`) or the outage grace
 * (`providerUnavailable`). A class, unlike the rest of the API, because
 * `instanceof`, `cause` and the stack trace are what JavaScript gives errors.
 *
 * The message may name internals (an endpoint, a store failure); a `Responder`
 * must never show it, and the default one does not.
 */
export class OidcClientError extends Error {
  /** Which closed-set failure this is; branch on it, never on the message. */
  readonly code: OidcErrorCode;

  constructor(code: OidcErrorCode, message?: string, options?: { readonly cause?: unknown }) {
    super(message ?? code, options);
    this.name = "OidcClientError";
    this.code = code;
  }
}

/**
 * Reports whether `err` is an `OidcClientError` with `code`, also when it
 * arrives as the `cause` of another error (a hook that wraps the package's
 * error in its own). Follows the cause chain to a fixed depth, so a cyclic
 * chain cannot loop.
 */
export function isOidcError(err: unknown, code: OidcErrorCode): boolean {
  let current: unknown = err;
  for (let depth = 0; depth < MAX_CAUSE_DEPTH && current instanceof Error; depth++) {
    if (current instanceof OidcClientError && current.code === code) return true;
    current = current.cause;
  }
  return false;
}

/** How far `isOidcError` follows `cause`: deep enough for any real wrapping. */
const MAX_CAUSE_DEPTH = 8;
