// Package-private: the claim rules of ID tokens (OpenID Connect Core 3.1.3.7)
// and Back-Channel Logout tokens (OpenID Connect Back-Channel Logout 1.0
// section 2.6), on top of the signature check in jose.ts. Every rule is a
// floor: no option reaches this file. Nothing here is re-exported.

import { constantTimeEqual } from "./bytes.ts";
import { Claim, type Identity } from "./identity.ts";
import { decodeJws, invalidToken, type KeySet } from "./jose.ts";
import { num, obj, str, strList, type JsonObject } from "./json.ts";
import type { LogoutTarget } from "./session.ts";

/**
 * The clock skew allowed on exp, nbf and iat: 30 seconds, the value
 * ubgo/auth's own verifier uses. Fixed, not an option.
 */
export const CLOCK_LEEWAY_MS = 30 * 1000;

/** Registered claim names the rules read besides `Claim`'s. Wire names, kept verbatim. */
const Registered = {
  audience: "aud",
  authorizedParty: "azp",
  expires: "exp",
  issuedAt: "iat",
  notBefore: "nbf",
  nonce: "nonce",
  events: "events",
  tokenId: "jti",
} as const;

/**
 * The oldest logout token accepted, by `iat`: ubgo/auth's provider gives its
 * logout tokens two minutes, and an older one is a replay or a delivery so
 * late that acting on it surprises more than it protects. The Go client's
 * value.
 */
export const LOGOUT_TOKEN_MAX_AGE_MS = 2 * 60 * 1000;

/** A verified logout token: whom to sign out, and its `jti` with how long to remember it against replay (epoch milliseconds). */
export interface VerifiedLogoutToken {
  readonly target: LogoutTarget;
  readonly jti: string;
  readonly rememberUntil: number;
}

/** The `events` member a logout token must carry (Back-Channel Logout section 2.4). */
export const BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

/**
 * The `typ` a logout token is sent with (section 2.4 recommends explicit
 * typing; ubgo/auth's provider sends it). An ID token with this `typ` is
 * refused, so a logout token cannot be presented as an ID token.
 */
const LOGOUT_TOKEN_TYPE = "logout+jwt";

/** The media-type spelling of the same `typ` (RFC 7515 section 4.1.9 allows the `application/` prefix). */
const LOGOUT_TOKEN_MEDIA_TYPE = `application/${LOGOUT_TOKEN_TYPE}`;

/** What every token of this login server is checked against. */
export interface TokenContext {
  /** The discovered issuer, compared exactly (OpenID Connect Core 3.1.3.7 step 2). */
  readonly issuer: string;
  readonly clientId: string;
  readonly keys: KeySet;
  /** Epoch milliseconds now. */
  readonly now: number;
}

/** What an ID token is checked against besides the context. */
export interface IdTokenExpectations {
  /** At sign-in: the flow's nonce, compared in constant time. Absent at refresh, which carries none to compare. */
  readonly nonce?: string;
  /** At refresh: the session's subject, which the new token must name. */
  readonly subject?: string;
}

/** Whether `typ` names a logout token, in any letter case. */
function isLogoutType(typ: string | undefined): boolean {
  const t = typ?.toLowerCase();
  return t === LOGOUT_TOKEN_TYPE || t === LOGOUT_TOKEN_MEDIA_TYPE;
}

/**
 * Verifies an ID token and reads its Identity: an allowed algorithm and a
 * current key's signature, then iss exactly, aud naming the client (azp
 * required when there are several audiences and equal to the client when
 * present), exp and nbf with the leeway, iat present, sub non-empty, and the
 * nonce or subject the caller expects. Throws `invalidToken` on any failure.
 */
export async function verifyIdToken(token: string, ctx: TokenContext, expect: IdTokenExpectations): Promise<Identity> {
  const jws = decodeJws(token);
  if (isLogoutType(jws.typ)) invalidToken("a logout token is not an ID token");
  await ctx.keys.verify(jws);
  const c = jws.payload;
  checkCommon(c, ctx);
  const exp = num(c, Registered.expires);
  if (exp === undefined || exp * 1000 + CLOCK_LEEWAY_MS <= ctx.now) invalidToken("ID token has expired or has no exp");
  const nbf = num(c, Registered.notBefore);
  if (nbf !== undefined && nbf * 1000 - CLOCK_LEEWAY_MS > ctx.now) invalidToken("ID token is not valid yet");
  const subject = str(c, Claim.subject) ?? "";
  if (subject === "") invalidToken("ID token has no sub");
  if (expect.subject !== undefined && subject !== expect.subject) invalidToken("ID token names another subject");
  if (expect.nonce !== undefined && !constantTimeEqual(str(c, Registered.nonce) ?? "", expect.nonce)) invalidToken("ID token nonce does not match");
  const verified = c[Claim.emailVerified];
  const sid = str(c, Claim.sessionId);
  return {
    issuer: ctx.issuer,
    subject,
    email: str(c, Claim.email) ?? "",
    emailVerified: verified === true || verified === "true",
    name: str(c, Claim.name) ?? "",
    ...(sid === undefined || sid === "" ? {} : { providerSessionId: sid }),
    claims: c,
  };
}

/**
 * Verifies a Back-Channel Logout token and reads whom it logs out, the rules
 * of section 2.6 as ubgo/auth's provider issues them (plugin/oauthprovider
 * backchannel.go: typ `logout+jwt`, iss, sub, aud, iat, exp two minutes out,
 * jti, an optional sid and the logout event): an allowed algorithm and a
 * current key's signature; `typ`, when present, a logout type; iss exactly;
 * aud naming the client; iat present and at most `LOGOUT_TOKEN_MAX_AGE_MS`
 * old; exp present and not past (with the leeway); `events` holding the
 * logout event as an object; a `jti` (the caller refuses a second use);
 * sub or sid; and no nonce, so an ID token can never pass as one. Throws
 * `invalidToken`.
 */
export async function verifyLogoutToken(token: string, ctx: TokenContext): Promise<VerifiedLogoutToken> {
  const jws = decodeJws(token);
  if (jws.typ !== undefined && !isLogoutType(jws.typ)) invalidToken(`logout token typ ${JSON.stringify(jws.typ)} is not ${LOGOUT_TOKEN_TYPE}`);
  await ctx.keys.verify(jws);
  const c = jws.payload;
  checkCommon(c, ctx);
  const exp = num(c, Registered.expires);
  if (exp === undefined || exp * 1000 + CLOCK_LEEWAY_MS <= ctx.now) invalidToken("logout token has expired or has no exp");
  const iat = num(c, Registered.issuedAt) ?? 0; // present: checkCommon refused a token without it
  if (ctx.now - iat * 1000 > LOGOUT_TOKEN_MAX_AGE_MS + CLOCK_LEEWAY_MS) invalidToken("logout token was issued too long ago");
  const events = obj(c, Registered.events);
  if (events === undefined || obj(events, BACKCHANNEL_LOGOUT_EVENT) === undefined) invalidToken("logout token has no back-channel logout event");
  if (Registered.nonce in c) invalidToken("logout token carries a nonce");
  const jti = str(c, Registered.tokenId) ?? "";
  if (jti === "") invalidToken("logout token has no jti");
  const subject = str(c, Claim.subject) ?? "";
  const sid = str(c, Claim.sessionId) ?? "";
  // Remembered for as long as the token could still be accepted.
  const rememberUntil = Math.max(iat * 1000 + LOGOUT_TOKEN_MAX_AGE_MS, exp * 1000) + CLOCK_LEEWAY_MS;
  if (subject !== "") return { target: { issuer: ctx.issuer, subject, ...(sid === "" ? {} : { providerSessionId: sid }) }, jti, rememberUntil };
  if (sid !== "") return { target: { issuer: ctx.issuer, providerSessionId: sid }, jti, rememberUntil };
  return invalidToken("logout token names neither sub nor sid");
}

/** The rules ID and logout tokens share: iss, aud, azp, iat. */
function checkCommon(c: JsonObject, ctx: TokenContext): void {
  if (str(c, Claim.issuer) !== ctx.issuer) invalidToken("token iss is not the issuer");
  const aud = audience(c);
  if (!aud.includes(ctx.clientId)) invalidToken("token aud does not name this client");
  const azp = str(c, Registered.authorizedParty);
  if (Registered.authorizedParty in c && azp !== ctx.clientId) invalidToken("token azp is not this client");
  if (aud.length > 1 && azp === undefined) invalidToken("token has several audiences and no azp");
  const iat = num(c, Registered.issuedAt);
  if (iat === undefined || iat * 1000 - CLOCK_LEEWAY_MS > ctx.now) invalidToken("token iat is missing or in the future");
}

/** `aud` as a list: a single string is a list of one (RFC 7519 section 4.1.3); anything else is empty, so it names nobody. */
function audience(c: JsonObject): readonly string[] {
  const one = str(c, Registered.audience);
  if (one !== undefined) return [one];
  return strList(c, Registered.audience) ?? [];
}
