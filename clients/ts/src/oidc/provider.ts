// Talking to the login server as this client: discovery, client
// authentication, and the token, introspection and userinfo endpoints.

import type { Claims, Identity } from "./identity.ts";
import type { refreshedBrand } from "./internal.ts";
import type { Secret } from "./secret.ts";
import type { Tokens } from "./session.ts";

/**
 * The part of the login server's discovery document (OpenID Connect
 * Discovery 1.0, RFC 8414) the package reads, under the document's member
 * names in camelCase. Fetched from `issuer/.well-known/openid-configuration`
 * on first use and cached, or given once with the `discovery` option for a
 * server without discovery or a test.
 *
 * Whichever way it arrives, `issuer` must equal the configured issuer (a
 * trailing slash aside) and every endpoint must be https (http on a loopback
 * host), or sign-in fails: a document naming another issuer is the mix-up
 * attack.
 */
export interface ProviderMetadata {
  readonly issuer: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly jwksUri: string;
  readonly userinfoEndpoint?: string;
  /** RP-Initiated Logout's endpoint; without one, sign-out ends the app's session only. */
  readonly endSessionEndpoint?: string;
  readonly introspectionEndpoint?: string;
  readonly revocationEndpoint?: string;
  /** When listed, must include S256; S256 is sent whether listed or not (some servers support PKCE without saying). */
  readonly codeChallengeMethodsSupported?: readonly string[];
  /** Informational: the accepted algorithms are the package's fixed set (`ID_TOKEN_ALGORITHMS`), whatever the server lists. */
  readonly idTokenSigningAlgValuesSupported?: readonly string[];
  /** RFC 9207: the callback then requires an `iss` parameter equal to the issuer; without it an `iss` sent is still checked. */
  readonly authorizationResponseIssParameterSupported?: boolean;
  readonly backchannelLogoutSupported?: boolean;
  readonly backchannelLogoutSessionSupported?: boolean;
}

/**
 * The ID token signature algorithms accepted: what ubgo/auth's provider,
 * Google, Keycloak and Entra sign with by default. Fixed, not an option:
 * `none` and the HMAC family are never accepted, and a server listing other
 * algorithms does not widen the set. Exported for documentation and tests.
 */
export const ID_TOKEN_ALGORITHMS = ["RS256", "ES256", "EdDSA"] as const;

/** One of `ID_TOKEN_ALGORITHMS`. */
export type IdTokenAlgorithm = (typeof ID_TOKEN_ALGORITHMS)[number];

/**
 * A token, introspection or revocation request about to be sent, for a
 * `ClientAuth` to authenticate. `endpoint` is where it goes (the audience of
 * a private_key_jwt assertion); `form` and `headers` are sent as they are
 * once the `ClientAuth` returns.
 */
export interface ClientAuthRequest {
  readonly endpoint: string;
  readonly form: URLSearchParams;
  readonly headers: Headers;
}

/**
 * Authenticates the client at the login server's endpoints by adding to the
 * form or headers. The default is client_secret_basic with `clientSecret`;
 * the `clientAuth` option sets another: `clientSecretPost`, `publicClient`,
 * or the app's own for private_key_jwt or a KMS-held key. mTLS needs none:
 * it is the `fetch` option's certificate with `publicClient`.
 */
export type ClientAuth = (request: ClientAuthRequest) => void | Promise<void>;

/**
 * client_secret_basic (RFC 6749 2.3.1): id and secret as HTTP Basic, each
 * form-encoded first as the RFC requires. What `clientSecret` alone means.
 */
export function clientSecretBasic(clientId: string, clientSecret: Secret): ClientAuth {
  return ({ headers }) => {
    headers.set(HEADER_AUTHORIZATION, `Basic ${btoa(`${formEncode(clientId)}:${formEncode(clientSecret.reveal())}`)}`);
  };
}

/** client_secret_post: id and secret in the form body, for a server that does not accept Basic. */
export function clientSecretPost(clientId: string, clientSecret: Secret): ClientAuth {
  return ({ form }) => {
    form.set(ClientParam.clientId, clientId);
    form.set(ClientParam.clientSecret, clientSecret.reveal());
  };
}

/**
 * Sends only the client id: a client with no secret, which PKCE alone
 * protects, or one authenticated by mTLS. Explicit, so an empty secret is
 * never mistaken for a public client.
 */
export function publicClient(clientId: string): ClientAuth {
  return ({ form }) => {
    form.set(ClientParam.clientId, clientId);
  };
}

/** The header client_secret_basic writes. */
const HEADER_AUTHORIZATION = "Authorization";

/** The form members client authentication writes (RFC 6749 section 2.3.1). Wire names, kept verbatim. */
const ClientParam = { clientId: "client_id", clientSecret: "client_secret" } as const;

/**
 * `s` in application/x-www-form-urlencoded form, as RFC 6749 section 2.3.1
 * requires of the id and secret before Basic encoding (a secret with `:` or
 * `%` otherwise breaks at servers that decode, as ubgo/auth's does). The
 * result is ASCII, so `btoa` takes it.
 */
function formEncode(s: string): string {
  return new URLSearchParams([["", s]]).toString().slice(1);
}

/** A refresh-token grant for one session. */
export interface RefreshInput {
  readonly refreshToken: Secret;
  /** The session's subject: an ID token in the answer must name it. */
  readonly subject: string;
}

/**
 * A successful refresh: the new tokens and, when the server issued a new ID
 * token, the Identity it verified. Only `Provider.refresh` makes one: the
 * brand key is a module-private symbol, so no object literal type-checks as
 * a `Refreshed`, and the client also checks at run time that the value came
 * from `refresh` (a cast does not get past it). So a `Rechecker` can hand the
 * package new tokens only by actually refreshing them, never with an
 * unverified ID token.
 */
export interface Refreshed {
  readonly [refreshedBrand]: true;
  /** The new tokens; a refresh token the server did not rotate is the previous one, carried over. */
  readonly tokens: Tokens;
  /** The verified Identity of the new ID token; absent when the answer had none. */
  readonly identity?: Identity;
}

/** RFC 7009 `token_type_hint` values. Wire names, kept verbatim. */
export const TokenTypeHint = {
  refreshToken: "refresh_token",
  accessToken: "access_token",
} as const;

/** One of the `TokenTypeHint` values. */
export type TokenTypeHint = (typeof TokenTypeHint)[keyof typeof TokenTypeHint];

/** Every `TokenTypeHint`. */
export const TOKEN_TYPE_HINTS: readonly TokenTypeHint[] = Object.values(TokenTypeHint);

/** An RFC 7662 introspection. */
export interface IntrospectInput {
  readonly token: Secret;
  readonly hint?: TokenTypeHint;
}

/**
 * The introspection endpoint's answer (RFC 7662 2.2). `active: false` is the
 * server's "no", not an error. Times are epoch milliseconds.
 */
export interface Introspection {
  readonly active: boolean;
  readonly subject?: string;
  readonly clientId?: string;
  readonly scope?: string;
  readonly tokenType?: string;
  readonly issuer?: string;
  readonly audience: readonly string[];
  readonly expiresAt?: number;
  readonly issuedAt?: number;
  /** Every member of the answer, the ones above included. */
  readonly claims: Claims;
}

/** A userinfo call for one session. */
export interface UserInfoInput {
  readonly accessToken: Secret;
  /** The answer's `sub` must equal it (OpenID Connect Core 5.3.2), or the answer is refused. */
  readonly subject: string;
}

/**
 * Calls the login server as this client, with its `ClientAuth`, `fetch` and
 * floors. The package's own flows use it, a `Rechecker` and a `UserMapper`
 * receive it, and `OidcClient.provider` returns it for anything else: the one
 * escape hatch.
 *
 * Every method applies the floors itself (an ID token from a refresh is
 * verified and must name the session's iss and sub; no request follows a
 * redirect) and classifies every failure: `OidcErrorCode.providerRefused` for
 * the server's "no", `OidcErrorCode.providerUnavailable` for no answer.
 */
export interface Provider {
  /** The discovery document: fetched on first call, again at most once a minute after a failure. */
  metadata(): Promise<ProviderMetadata>;
  /**
   * Redeems a refresh token. The answer's ID token, when there is one, is
   * verified as at sign-in (except the nonce, which a refresh does not carry)
   * and must name `input.subject`. `invalid_grant` is `providerRefused`.
   */
  refresh(input: RefreshInput): Promise<Refreshed>;
  /** Asks the introspection endpoint; a server without one is `invalidConfig` at the first call. */
  introspect(input: IntrospectInput): Promise<Introspection>;
  /** Calls the userinfo endpoint; 401 is `providerRefused`. */
  userInfo(input: UserInfoInput): Promise<Claims>;
}
