// Package-private: the one connection to the login server. It implements
// the public `Provider` (discovery, refresh, introspection, userinfo) and
// adds what only the client's own routes need (the code exchange and logout
// token verification). Every request goes through `send`, which never
// follows a redirect and classifies every failure as the server's "no"
// (`providerRefused`) or no answer (`providerUnavailable`). Nothing here is
// re-exported from index.ts.

import { OidcClientError, OidcErrorCode, isOidcError } from "./errors.ts";
import type { Claims, Identity } from "./identity.ts";
import { genuineRefreshed, refreshedBrand } from "./internal.ts";
import { KeySet } from "./jose.ts";
import { bool, num, parseJsonObject, str, strList, type JsonObject } from "./json.ts";
import { isTrustedUrl, trimTrailingSlash } from "./origin.ts";
import type {
  ClientAuth,
  IntrospectInput,
  Introspection,
  Provider,
  ProviderMetadata,
  Refreshed,
  RefreshInput,
  TokenTypeHint,
  UserInfoInput,
} from "./provider.ts";
import { secret, type Secret } from "./secret.ts";
import type { Tokens } from "./session.ts";
import { verifyIdToken, verifyLogoutToken, type TokenContext, type VerifiedLogoutToken } from "./tokens.ts";

/** What the connection needs from the client's resolved options. */
export interface ConnectionConfig {
  readonly issuer: string;
  readonly clientId: string;
  readonly clientAuth: ClientAuth;
  /** `appUrl + paths.callback`, sent with the code exchange as RFC 6749 section 4.1.3 requires. */
  readonly redirectUri: string;
  readonly fetch: typeof fetch;
  readonly timeoutMs: number;
  readonly now: () => number;
  /** Given instead of discovery; already checked by `checkMetadata`. */
  readonly discovery?: ProviderMetadata;
}

/** A completed code exchange: the tokens and the verified Identity of the ID token, which a sign-in requires. */
export interface Exchanged {
  readonly tokens: Tokens;
  readonly identity: Identity;
}

/** The public `Provider` plus the calls only the client's routes make. */
export interface Connection extends Provider {
  /** Redeems an authorization code with its PKCE verifier and verifies the ID token against the flow's nonce. */
  exchangeCode(code: string, verifier: string, nonce: string): Promise<Exchanged>;
  /**
   * Revokes `token` at the revocation endpoint (RFC 7009) with the client's
   * authentication. Resolves `false` when the server advertises no
   * revocation endpoint; throws `providerUnavailable` or `providerRefused`
   * when the call fails.
   */
  revoke(token: Secret, hint: TokenTypeHint): Promise<boolean>;
  /** Verifies a back-channel logout token and returns whom it logs out, with its jti. */
  logoutToken(token: string): Promise<VerifiedLogoutToken>;
}

/** The discovery document's path below the issuer (OpenID Connect Discovery 1.0 section 4). */
const DISCOVERY_PATH = "/.well-known/openid-configuration";

/** How long a fetched discovery document is used before it is read again. */
const DISCOVERY_MAX_AGE_MS = 24 * 60 * 60 * 1000;

/** After a failed discovery fetch, the same failure is answered for this long instead of asking a server that is down on every request. */
const DISCOVERY_RETRY_MS = 60 * 1000;

/** Request and response headers and media types the connection uses. */
const Http = {
  accept: "Accept",
  authorization: "Authorization",
  contentType: "Content-Type",
  json: "application/json",
  form: "application/x-www-form-urlencoded",
} as const;

/** Methods, as fetch spells them. */
const Method = { get: "GET", post: "POST" } as const;

/** Token endpoint, introspection and response member names (RFC 6749, RFC 7662, OpenID Connect Discovery). Wire names, kept verbatim. */
const Param = {
  grantType: "grant_type",
  code: "code",
  redirectUri: "redirect_uri",
  codeVerifier: "code_verifier",
  refreshToken: "refresh_token",
  token: "token",
  tokenTypeHint: "token_type_hint",
  accessToken: "access_token",
  idToken: "id_token",
  tokenType: "token_type",
  expiresIn: "expires_in",
  scope: "scope",
  error: "error",
  active: "active",
  subject: "sub",
  clientId: "client_id",
  issuer: "iss",
  audience: "aud",
  expires: "exp",
  issuedAt: "iat",
} as const;

/** The grant types the connection redeems. */
const GrantType = { authorizationCode: "authorization_code", refreshToken: "refresh_token" } as const;

/** The only access-token type accepted: a DPoP-bound token would be useless to this client, so it is refused rather than misused. */
const TOKEN_TYPE_BEARER = "bearer";

/** The PKCE method the flow uses; a server listing methods must list it. */
export const PKCE_METHOD_S256 = "S256";

/** Discovery member names (OpenID Connect Discovery 1.0 section 3, RFC 8414, RFC 9207, Back-Channel Logout section 2.1). Wire names. */
const Meta = {
  issuer: "issuer",
  authorizationEndpoint: "authorization_endpoint",
  tokenEndpoint: "token_endpoint",
  jwksUri: "jwks_uri",
  userinfoEndpoint: "userinfo_endpoint",
  endSessionEndpoint: "end_session_endpoint",
  introspectionEndpoint: "introspection_endpoint",
  revocationEndpoint: "revocation_endpoint",
  codeChallengeMethodsSupported: "code_challenge_methods_supported",
  idTokenSigningAlgValuesSupported: "id_token_signing_alg_values_supported",
  authorizationResponseIssParameterSupported: "authorization_response_iss_parameter_supported",
  backchannelLogoutSupported: "backchannel_logout_supported",
  backchannelLogoutSessionSupported: "backchannel_logout_session_supported",
} as const;

/** HTTP statuses that mean "no answer" rather than "no": try again later. */
const RETRYABLE_STATUSES: readonly number[] = [408, 429];

/** The first 5xx status: every server error is an outage, not a refusal. */
const FIRST_SERVER_ERROR = 500;

/** Throws `providerUnavailable`. */
function unavailable(message: string, cause?: unknown): never {
  throw new OidcClientError(OidcErrorCode.providerUnavailable, message, cause === undefined ? undefined : { cause });
}

/** Throws `providerRefused`. */
function refused(message: string): never {
  throw new OidcClientError(OidcErrorCode.providerRefused, message);
}

/**
 * The problems with `m` as this issuer's metadata, empty when none: the
 * issuer equal to the configured one (a trailing slash aside; another is the
 * mix-up attack), the three required endpoints present, every endpoint
 * trusted (https, or http on loopback), and S256 among the PKCE methods when
 * methods are listed.
 */
export function checkMetadata(m: ProviderMetadata, issuer: string): readonly string[] {
  const problems: string[] = [];
  if (trimTrailingSlash(m.issuer) !== trimTrailingSlash(issuer)) problems.push(`discovery names issuer ${JSON.stringify(m.issuer)}, not ${JSON.stringify(issuer)}`);
  const endpoints: ReadonlyArray<readonly [string, string | undefined]> = [
    [Meta.authorizationEndpoint, m.authorizationEndpoint],
    [Meta.tokenEndpoint, m.tokenEndpoint],
    [Meta.jwksUri, m.jwksUri],
    [Meta.userinfoEndpoint, m.userinfoEndpoint],
    [Meta.endSessionEndpoint, m.endSessionEndpoint],
    [Meta.introspectionEndpoint, m.introspectionEndpoint],
    [Meta.revocationEndpoint, m.revocationEndpoint],
  ];
  endpoints.forEach(([name, url], i) => {
    const required = i < REQUIRED_ENDPOINTS;
    if (url === undefined) {
      if (required) problems.push(`discovery has no ${name}`);
    } else if (!isTrustedUrl(url)) {
      problems.push(`discovery ${name} ${JSON.stringify(url)} is not https (or http on a loopback host)`);
    }
  });
  if (m.codeChallengeMethodsSupported !== undefined && !m.codeChallengeMethodsSupported.includes(PKCE_METHOD_S256)) {
    problems.push(`discovery ${Meta.codeChallengeMethodsSupported} does not list ${PKCE_METHOD_S256}`);
  }
  return problems;
}

/** The first entries of `checkMetadata`'s endpoint list are required: authorization, token, JWKS. */
const REQUIRED_ENDPOINTS = 3;

/** The metadata in a discovery document, or `undefined` when a required member is missing or mistyped. */
function parseMetadata(o: JsonObject): ProviderMetadata | undefined {
  const issuer = str(o, Meta.issuer);
  const authorizationEndpoint = str(o, Meta.authorizationEndpoint);
  const tokenEndpoint = str(o, Meta.tokenEndpoint);
  const jwksUri = str(o, Meta.jwksUri);
  if (issuer === undefined || authorizationEndpoint === undefined || tokenEndpoint === undefined || jwksUri === undefined) return undefined;
  const optional = {
    userinfoEndpoint: str(o, Meta.userinfoEndpoint),
    endSessionEndpoint: str(o, Meta.endSessionEndpoint),
    introspectionEndpoint: str(o, Meta.introspectionEndpoint),
    revocationEndpoint: str(o, Meta.revocationEndpoint),
    codeChallengeMethodsSupported: strList(o, Meta.codeChallengeMethodsSupported),
    idTokenSigningAlgValuesSupported: strList(o, Meta.idTokenSigningAlgValuesSupported),
    authorizationResponseIssParameterSupported: bool(o, Meta.authorizationResponseIssParameterSupported),
    backchannelLogoutSupported: bool(o, Meta.backchannelLogoutSupported),
    backchannelLogoutSessionSupported: bool(o, Meta.backchannelLogoutSessionSupported),
  };
  // Drop absent members, so the result satisfies exactOptionalPropertyTypes.
  const present = Object.fromEntries(Object.entries(optional).filter(([, v]) => v !== undefined));
  return { issuer, authorizationEndpoint, tokenEndpoint, jwksUri, ...present };
}

/** Builds the connection. Makes no request: discovery and keys are fetched on first use. */
export function createConnection(cfg: ConnectionConfig): Connection {
  let metadataCache: { readonly value: ProviderMetadata; readonly at: number } | undefined;
  let metadataFailure: { readonly err: unknown; readonly at: number } | undefined;
  let metadataInflight: Promise<ProviderMetadata> | undefined;

  /**
   * One request to the login server: `redirect: "manual"` always (a redirect
   * answer is an outage, since following it could carry the client's
   * credentials elsewhere), the timeout, and a network failure as
   * `providerUnavailable`.
   */
  async function send(url: string, init: RequestInit): Promise<Response> {
    let res: Response;
    try {
      res = await cfg.fetch(url, { ...init, redirect: "manual", signal: AbortSignal.timeout(cfg.timeoutMs) });
    } catch (cause) {
      return unavailable(`login server request to ${url} failed`, cause);
    }
    if (res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) {
      return unavailable(`login server answered ${url} with a redirect`);
    }
    return res;
  }

  /** The body as a JSON object, or `providerUnavailable` (an unreadable answer is no answer). */
  async function readJson(res: Response, what: string): Promise<JsonObject> {
    let text: string;
    try {
      text = await res.text();
    } catch (cause) {
      return unavailable(`${what}: body could not be read`, cause);
    }
    return parseJsonObject(text) ?? unavailable(`${what}: answer is not a JSON object`);
  }

  /** Classifies a non-2xx answer: retryable and 5xx statuses are an outage, other 4xx the server's "no". */
  async function fail(res: Response, what: string): Promise<never> {
    if (res.status >= FIRST_SERVER_ERROR || RETRYABLE_STATUSES.includes(res.status)) return unavailable(`${what}: status ${res.status}`);
    const body = parseJsonObject(await res.text().catch(() => "")) ?? {};
    return refused(`${what}: status ${res.status}${str(body, Param.error) === undefined ? "" : ` (${str(body, Param.error)})`}`);
  }

  async function fetchMetadata(): Promise<ProviderMetadata> {
    const url = trimTrailingSlash(cfg.issuer) + DISCOVERY_PATH;
    const res = await send(url, { method: Method.get, headers: { [Http.accept]: Http.json } });
    if (!res.ok) return fail(res, "discovery");
    const m = parseMetadata(await readJson(res, "discovery")) ?? unavailable("discovery document misses a required member");
    const problems = checkMetadata(m, cfg.issuer);
    // A document that names another issuer or an untrusted endpoint is a
    // misconfiguration or an attack, never an outage to wait out.
    if (problems.length > 0) throw new OidcClientError(OidcErrorCode.invalidConfig, problems.join("; "));
    return m;
  }

  async function metadata(): Promise<ProviderMetadata> {
    if (cfg.discovery !== undefined) return cfg.discovery;
    const now = cfg.now();
    if (metadataCache !== undefined && now - metadataCache.at < DISCOVERY_MAX_AGE_MS) return metadataCache.value;
    if (metadataFailure !== undefined && now - metadataFailure.at < DISCOVERY_RETRY_MS) {
      if (metadataCache !== undefined) return metadataCache.value;
      throw metadataFailure.err;
    }
    metadataInflight ??= fetchMetadata()
      .then((value) => {
        metadataCache = { value, at: cfg.now() };
        metadataFailure = undefined;
        return value;
      })
      .catch((err: unknown) => {
        metadataFailure = { err, at: cfg.now() };
        // A stale document beats none while the server is down.
        if (metadataCache !== undefined) return metadataCache.value;
        throw err;
      })
      .finally(() => {
        metadataInflight = undefined;
      });
    return metadataInflight;
  }

  const keys = new KeySet(async () => {
    const m = await metadata();
    const res = await send(m.jwksUri, { method: Method.get, headers: { [Http.accept]: Http.json } });
    if (!res.ok) return fail(res, "jwks");
    return readJson(res, "jwks");
  }, cfg.now);

  async function tokenContext(): Promise<TokenContext> {
    return { issuer: (await metadata()).issuer, clientId: cfg.clientId, keys, now: cfg.now() };
  }

  /** POSTs `form` to `endpoint` with client authentication and returns the JSON answer of a 2xx (an empty object when `readBody` is false). */
  async function postForm(endpoint: string, form: URLSearchParams, what: string, readBody = true): Promise<JsonObject> {
    const headers = new Headers({ [Http.contentType]: Http.form, [Http.accept]: Http.json });
    await cfg.clientAuth({ endpoint, form, headers });
    const res = await send(endpoint, { method: Method.post, headers, body: form.toString() });
    if (!res.ok) return fail(res, what);
    return readBody ? readJson(res, what) : {};
  }

  /** The tokens in a token-endpoint answer; a missing access token or a non-Bearer type is unreadable. */
  function readTokens(o: JsonObject, what: string): Tokens {
    const accessToken = str(o, Param.accessToken);
    if (accessToken === undefined || accessToken === "") return unavailable(`${what}: no access_token`);
    const tokenType = str(o, Param.tokenType);
    if (tokenType !== undefined && tokenType.toLowerCase() !== TOKEN_TYPE_BEARER) return refused(`${what}: token_type ${tokenType} is not Bearer`);
    const refreshToken = str(o, Param.refreshToken);
    const idToken = str(o, Param.idToken);
    const expiresIn = num(o, Param.expiresIn);
    const scope = str(o, Param.scope);
    return {
      accessToken: secret(accessToken),
      ...(refreshToken === undefined || refreshToken === "" ? {} : { refreshToken: secret(refreshToken) }),
      ...(idToken === undefined || idToken === "" ? {} : { idToken: secret(idToken) }),
      ...(expiresIn === undefined ? {} : { accessExpiresAt: cfg.now() + expiresIn * 1000 }),
      ...(scope === undefined ? {} : { scope }),
    };
  }

  return {
    metadata,

    async exchangeCode(code, verifier, nonce) {
      const m = await metadata();
      const form = new URLSearchParams({
        [Param.grantType]: GrantType.authorizationCode,
        [Param.code]: code,
        [Param.redirectUri]: cfg.redirectUri,
        [Param.codeVerifier]: verifier,
      });
      const tokens = readTokens(await postForm(m.tokenEndpoint, form, "code exchange"), "code exchange");
      if (tokens.idToken === undefined) throw new OidcClientError(OidcErrorCode.invalidToken, "code exchange returned no id_token");
      const identity = await verifyIdToken(tokens.idToken.reveal(), await tokenContext(), { nonce });
      return { tokens, identity };
    },

    async refresh(input: RefreshInput): Promise<Refreshed> {
      const m = await metadata();
      const form = new URLSearchParams({ [Param.grantType]: GrantType.refreshToken, [Param.refreshToken]: input.refreshToken.reveal() });
      const answer = readTokens(await postForm(m.tokenEndpoint, form, "refresh"), "refresh");
      const tokens: Tokens = answer.refreshToken === undefined ? { ...answer, refreshToken: input.refreshToken } : answer;
      let identity: Identity | undefined;
      if (tokens.idToken !== undefined) identity = await verifyIdToken(tokens.idToken.reveal(), await tokenContext(), { subject: input.subject });
      const out: Refreshed = { [refreshedBrand]: true, tokens, ...(identity === undefined ? {} : { identity }) };
      genuineRefreshed.add(out);
      return Object.freeze(out);
    },

    async introspect(input: IntrospectInput): Promise<Introspection> {
      const m = await metadata();
      if (m.introspectionEndpoint === undefined) throw new OidcClientError(OidcErrorCode.invalidConfig, "the login server has no introspection endpoint");
      const form = new URLSearchParams({ [Param.token]: input.token.reveal() });
      if (input.hint !== undefined) form.set(Param.tokenTypeHint, input.hint);
      const o = await postForm(m.introspectionEndpoint, form, "introspection");
      const active = bool(o, Param.active) ?? unavailable("introspection: answer has no active member");
      const audOne = str(o, Param.audience);
      const exp = num(o, Param.expires);
      const iat = num(o, Param.issuedAt);
      const fields = {
        subject: str(o, Param.subject),
        clientId: str(o, Param.clientId),
        scope: str(o, Param.scope),
        tokenType: str(o, Param.tokenType),
        issuer: str(o, Param.issuer),
        expiresAt: exp === undefined ? undefined : exp * 1000,
        issuedAt: iat === undefined ? undefined : iat * 1000,
      };
      const present = Object.fromEntries(Object.entries(fields).filter(([, v]) => v !== undefined));
      return { active, audience: audOne === undefined ? (strList(o, Param.audience) ?? []) : [audOne], claims: o, ...present };
    },

    async userInfo(input: UserInfoInput): Promise<Claims> {
      const m = await metadata();
      if (m.userinfoEndpoint === undefined) throw new OidcClientError(OidcErrorCode.invalidConfig, "the login server has no userinfo endpoint");
      const res = await send(m.userinfoEndpoint, {
        method: Method.get,
        headers: { [Http.accept]: Http.json, [Http.authorization]: `Bearer ${input.accessToken.reveal()}` },
      });
      if (!res.ok) return fail(res, "userinfo");
      const o = await readJson(res, "userinfo");
      if (str(o, Param.subject) !== input.subject) throw new OidcClientError(OidcErrorCode.invalidToken, "userinfo names another subject");
      return o;
    },

    async revoke(token, hint) {
      const m = await metadata();
      if (m.revocationEndpoint === undefined) return false;
      // RFC 7009 section 2.2: 200 for a revoked or an unknown token alike;
      // the body is not read.
      await postForm(m.revocationEndpoint, new URLSearchParams({ [Param.token]: token.reveal(), [Param.tokenTypeHint]: hint }), "revocation", false);
      return true;
    },

    async logoutToken(token) {
      return verifyLogoutToken(token, await tokenContext());
    },
  };
}

/** Whether `err` means the login server could not be reached: the one failure that starts the outage grace. */
export function isOutage(err: unknown): boolean {
  return isOidcError(err, OidcErrorCode.providerUnavailable);
}
