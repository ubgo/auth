// A stand-in OpenID Connect server for the tests, behind a `fetch` the
// client is given: discovery, JWKS, the token endpoint (authorization code
// with PKCE, refresh with rotation and reuse detection, an access rule a
// test can change), introspection, userinfo and end-session. It behaves as
// ubgo/auth's plugin/oauthprovider does where the client depends on it:
// a refresh re-asks the access rule, a spent refresh token revokes its
// family, logout tokens are typed `logout+jwt`.

/** The algorithms a fake can sign with. */
export type FakeAlg = "RS256" | "ES256" | "EdDSA";

export const ISSUER = "https://login.example.com";
export const CLIENT_ID = "admin";
export const CLIENT_SECRET = "s3cret:with%chars";
export const APP_URL = "https://app.example.com";
export const SUBJECT = "usr_1";

/** WebCrypto parameters per algorithm. */
const KEYGEN: Readonly<Record<FakeAlg, { gen: RsaHashedKeyGenParams | EcKeyGenParams | Algorithm; sign: AlgorithmIdentifier | EcdsaParams }>> = {
  RS256: { gen: { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, sign: "RSASSA-PKCS1-v1_5" },
  ES256: { gen: { name: "ECDSA", namedCurve: "P-256" }, sign: { name: "ECDSA", hash: "SHA-256" } },
  EdDSA: { gen: { name: "Ed25519" }, sign: "Ed25519" },
};

const enc = new TextEncoder();

export function b64url(bytes: Uint8Array | string): string {
  const b = typeof bytes === "string" ? enc.encode(bytes) : bytes;
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A signing key with its public JWK. */
export interface FakeKey {
  readonly alg: FakeAlg;
  readonly kid: string;
  readonly privateKey: CryptoKey;
  readonly jwk: JsonWebKey & { kid: string };
}

/** A fresh key pair for `alg`; `modulusLength` overrides RSA's size for the weak-key test. */
export async function makeKey(alg: FakeAlg, kid: string, modulusLength?: number): Promise<FakeKey> {
  const spec = KEYGEN[alg];
  const gen = modulusLength === undefined || alg !== "RS256" ? spec.gen : { ...spec.gen, modulusLength };
  const pair = await crypto.subtle.generateKey(gen, true, ["sign", "verify"]);
  if (!("privateKey" in pair)) throw new Error("expected a key pair");
  const pub = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const jwk: JsonWebKey & { kid: string } = { kid, use: "sig", alg };
  for (const m of ["kty", "n", "e", "crv", "x", "y"] as const) if (pub[m] !== undefined) jwk[m] = pub[m];
  return { alg, kid, privateKey: pair.privateKey, jwk };
}

/** Signs `payload` under `key` with `header` merged over the defaults (alg, kid, typ JWT). */
export async function signJwt(key: FakeKey, payload: Record<string, unknown>, header: Record<string, unknown> = {}): Promise<string> {
  const h = b64url(JSON.stringify({ alg: key.alg, kid: key.kid, typ: "JWT", ...header }));
  const p = b64url(JSON.stringify(payload));
  const sig = new Uint8Array(await crypto.subtle.sign(KEYGEN[key.alg].sign, key.privateKey, enc.encode(`${h}.${p}`)));
  return `${h}.${p}.${b64url(sig)}`;
}

/** An HS256 token keyed with `secret`: what an attacker who knows a public key or the client secret might try. */
export async function signHs256(secret: string, payload: Record<string, unknown>, kid: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const h = b64url(JSON.stringify({ alg: "HS256", kid, typ: "JWT" }));
  const p = b64url(JSON.stringify(payload));
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(`${h}.${p}`)));
  return `${h}.${p}.${b64url(sig)}`;
}

/** A refresh token's record at the fake. */
interface RefreshRecord {
  readonly sub: string;
  readonly family: string;
  rotated: boolean;
}

/** An issued code's record. */
interface CodeRecord {
  readonly sub: string;
  readonly challenge: string;
  readonly method: string;
  readonly nonce: string;
  readonly redirectUri: string;
  used: boolean;
}

/** Counters a test reads to see what the client asked. */
export interface FakeCalls {
  discovery: number;
  jwks: number;
  token: number;
  refresh: number;
  introspect: number;
  revoke: number;
  userinfo: number;
}

/** The fake server and the knobs a test turns. */
export interface FakeProvider {
  readonly key: FakeKey;
  readonly calls: FakeCalls;
  /** Subjects the access rule allows; removing one refuses its next refresh, introspection and userinfo. */
  readonly allowed: Set<string>;
  /** Families a reuse or a removal revoked. */
  readonly revokedFamilies: Set<string>;
  /** While true every request fails as a network error. */
  down: boolean;
  /** When set, the revocation endpoint answers with this status instead of working. */
  revokeStatus: number | undefined;
  /** When set, the token endpoint answers with this status (a 503, a 302) instead of working. */
  tokenStatus: number | undefined;
  /** Whether a client sending only its id is accepted (a public client). */
  publicClients: boolean;
  /** Whether refresh rotates the refresh token (ubgo/auth does). */
  rotate: boolean;
  /** Whether the token endpoint returns a refresh token at all. */
  grantRefresh: boolean;
  /** Whether refresh answers carry a new ID token. */
  refreshIdToken: boolean;
  /** Mutates every ID token's claims and header before signing, for floor tests. */
  tamper: ((claims: Record<string, unknown>, header: Record<string, unknown>) => void) | undefined;
  /** Extra ID token claims (groups, a large blob). */
  extraClaims: Record<string, unknown>;
  /** When set, refresh answers wait for it: the single-flight tests hold requests in flight with it. */
  refreshGate: Promise<void> | undefined;
  /** Discovery overrides, for discovery-floor tests. */
  discoveryOverrides: Record<string, unknown>;
  /** The keys published at the JWKS endpoint (the signing key by default). */
  published: JsonWebKey[];
  /** The fetch the client is given. */
  readonly fetch: typeof fetch;
  /** Plays the browser at the authorization endpoint: approves `sub` and returns the callback URL the server redirects to. */
  authorize(authorizationUrl: string, sub?: string): string;
  /** A logout token for `claims` merged over valid defaults, typed logout+jwt. */
  logoutToken(claims?: Record<string, unknown>, header?: Record<string, unknown>): Promise<string>;
  /** A valid ID token for the client with `claims` merged over defaults. */
  idToken(claims?: Record<string, unknown>, header?: Record<string, unknown>): Promise<string>;
}

/** Builds a fake server signing with `alg`, on the clock `now`. */
export async function createFakeProvider(now: () => number, alg: FakeAlg = "RS256"): Promise<FakeProvider> {
  const key = await makeKey(alg, "k1");
  const codes = new Map<string, CodeRecord>();
  const refresh = new Map<string, RefreshRecord>();
  const access = new Map<string, string>();
  let counter = 0;
  const next = (p: string): string => `${p}_${++counter}`;
  const seconds = (): number => Math.floor(now() / 1000);

  const fake: FakeProvider = {
    key,
    calls: { discovery: 0, jwks: 0, token: 0, refresh: 0, introspect: 0, revoke: 0, userinfo: 0 },
    allowed: new Set([SUBJECT]),
    revokedFamilies: new Set(),
    down: false,
    tokenStatus: undefined,
    revokeStatus: undefined,
    publicClients: false,
    rotate: true,
    grantRefresh: true,
    refreshIdToken: true,
    tamper: undefined,
    extraClaims: {},
    refreshGate: undefined,
    discoveryOverrides: {},
    published: [key.jwk],
    fetch: async (input, init) => {
      const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
      if (fake.down) throw new TypeError("fetch failed");
      if (init?.redirect !== "manual") return new Response("client must not follow redirects", { status: 500 });
      return route(url, init);
    },
    authorize(authorizationUrl, sub = SUBJECT) {
      const u = new URL(authorizationUrl);
      const q = u.searchParams;
      const code = next("code");
      codes.set(code, {
        sub,
        challenge: q.get("code_challenge") ?? "",
        method: q.get("code_challenge_method") ?? "",
        nonce: q.get("nonce") ?? "",
        redirectUri: q.get("redirect_uri") ?? "",
        used: false,
      });
      const cb = new URL(q.get("redirect_uri") ?? "");
      cb.searchParams.set("code", code);
      cb.searchParams.set("state", q.get("state") ?? "");
      cb.searchParams.set("iss", ISSUER);
      return cb.toString();
    },
    async logoutToken(claims = {}, header = {}) {
      return signJwt(
        key,
        { iss: ISSUER, sub: SUBJECT, aud: [CLIENT_ID], iat: seconds(), nbf: seconds(), exp: seconds() + 120, jti: next("jti"), events: { "http://schemas.openid.net/event/backchannel-logout": {} }, ...claims },
        { typ: "logout+jwt", ...header },
      );
    },
    async idToken(claims = {}, header = {}) {
      return signJwt(key, { ...idClaims(SUBJECT, undefined), ...claims }, header);
    },
  };

  function idClaims(sub: string, nonce: string | undefined): Record<string, unknown> {
    return {
      iss: ISSUER,
      sub,
      aud: CLIENT_ID,
      iat: seconds(),
      exp: seconds() + 300,
      sid: "sid_1",
      email: "ada@example.com",
      email_verified: true,
      name: "Ada",
      ...(nonce === undefined ? {} : { nonce }),
      ...fake.extraClaims,
    };
  }

  async function mintIdToken(sub: string, nonce: string | undefined): Promise<string> {
    const claims = idClaims(sub, nonce);
    const header: Record<string, unknown> = {};
    fake.tamper?.(claims, header);
    return signJwt(key, claims, header);
  }

  function json(status: number, body: unknown): Response {
    return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  }

  function clientOk(init: RequestInit | undefined, form: URLSearchParams): boolean {
    const auth = new Headers(init?.headers).get("Authorization") ?? "";
    const want = `Basic ${btoa(`${encodeURIComponent(CLIENT_ID)}:${encodeURIComponent(CLIENT_SECRET).replace(/%20/g, "+")}`)}`;
    return auth === want || (form.get("client_id") === CLIENT_ID && form.get("client_secret") === CLIENT_SECRET) || (fake.publicClients && form.get("client_id") === CLIENT_ID && !form.has("client_secret"));
  }

  async function issue(sub: string, family: string, nonce: string | undefined, withId: boolean): Promise<Record<string, unknown>> {
    const at = next("at");
    access.set(at, sub);
    const out: Record<string, unknown> = { access_token: at, token_type: "Bearer", expires_in: 300, scope: "openid email profile offline_access" };
    if (fake.grantRefresh) {
      const rt = next("rt");
      refresh.set(rt, { sub, family, rotated: false });
      out["refresh_token"] = rt;
    }
    if (withId) out["id_token"] = await mintIdToken(sub, nonce);
    return out;
  }

  async function route(url: URL, init: RequestInit | undefined): Promise<Response> {
    const path = url.pathname;
    if (path === "/.well-known/openid-configuration") {
      fake.calls.discovery++;
      return json(200, {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/oauth/authorize`,
        token_endpoint: `${ISSUER}/oauth/token`,
        jwks_uri: `${ISSUER}/jwks.json`,
        userinfo_endpoint: `${ISSUER}/oauth/userinfo`,
        end_session_endpoint: `${ISSUER}/oauth/end-session`,
        introspection_endpoint: `${ISSUER}/oauth/introspect`,
        revocation_endpoint: `${ISSUER}/oauth/revoke`,
        code_challenge_methods_supported: ["S256"],
        authorization_response_iss_parameter_supported: true,
        ...fake.discoveryOverrides,
      });
    }
    if (path === "/jwks.json") {
      fake.calls.jwks++;
      return json(200, { keys: fake.published });
    }
    const form = new URLSearchParams(typeof init?.body === "string" ? init.body : "");
    if (path === "/oauth/token") {
      fake.calls.token++;
      if (fake.tokenStatus !== undefined) return new Response("", { status: fake.tokenStatus, headers: { Location: "https://elsewhere.example/" } });
      if (!clientOk(init, form)) return json(401, { error: "invalid_client" });
      const grant = form.get("grant_type");
      if (grant === "authorization_code") {
        const rec = codes.get(form.get("code") ?? "");
        if (rec === undefined || rec.used || rec.redirectUri !== form.get("redirect_uri") || rec.method !== "S256") return json(400, { error: "invalid_grant" });
        rec.used = true;
        const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(form.get("code_verifier") ?? "")));
        if (b64url(digest) !== rec.challenge) return json(400, { error: "invalid_grant" });
        if (!fake.allowed.has(rec.sub)) return json(400, { error: "access_denied" });
        return json(200, await issue(rec.sub, next("fam"), rec.nonce, true));
      }
      if (grant === "refresh_token") {
        fake.calls.refresh++;
        if (fake.refreshGate !== undefined) await fake.refreshGate;
        const token = form.get("refresh_token") ?? "";
        const rec = refresh.get(token);
        if (rec === undefined || fake.revokedFamilies.has(rec.family)) return json(400, { error: "invalid_grant" });
        if (rec.rotated) {
          // Reuse of a spent token: the whole family ends (RFC 9700 4.14.2).
          fake.revokedFamilies.add(rec.family);
          return json(400, { error: "invalid_grant" });
        }
        if (!fake.allowed.has(rec.sub)) {
          fake.revokedFamilies.add(rec.family);
          return json(400, { error: "invalid_grant" });
        }
        if (fake.rotate) {
          rec.rotated = true;
          return json(200, await issue(rec.sub, rec.family, undefined, fake.refreshIdToken));
        }
        const at = next("at");
        access.set(at, rec.sub);
        const out: Record<string, unknown> = { access_token: at, token_type: "Bearer", expires_in: 300 };
        if (fake.refreshIdToken) out["id_token"] = await mintIdToken(rec.sub, undefined);
        return json(200, out);
      }
      return json(400, { error: "unsupported_grant_type" });
    }
    if (path === "/oauth/revoke") {
      // RFC 7009: revoking a refresh token ends its family; an unknown token
      // is still 200. Like ubgo/auth, it outlives the session otherwise
      // (offline_access), which is why the client must revoke at logout.
      fake.calls.revoke++;
      if (fake.revokeStatus !== undefined) return new Response("", { status: fake.revokeStatus });
      if (!clientOk(init, form)) return json(401, { error: "invalid_client" });
      if (form.get("token_type_hint") !== "refresh_token") return json(400, { error: "unexpected hint in this fake" });
      const rec = refresh.get(form.get("token") ?? "");
      if (rec !== undefined) fake.revokedFamilies.add(rec.family);
      return new Response(null, { status: 200 });
    }
    if (path === "/oauth/introspect") {
      fake.calls.introspect++;
      if (!clientOk(init, form)) return json(401, { error: "invalid_client" });
      const rec = refresh.get(form.get("token") ?? "");
      const active = rec !== undefined && !rec.rotated && !fake.revokedFamilies.has(rec.family) && fake.allowed.has(rec.sub);
      return json(200, active ? { active, sub: rec.sub, client_id: CLIENT_ID, aud: CLIENT_ID, exp: seconds() + 300, iat: seconds() } : { active: false });
    }
    if (path === "/oauth/userinfo") {
      fake.calls.userinfo++;
      const bearer = (new Headers(init?.headers).get("Authorization") ?? "").replace(/^Bearer /, "");
      const sub = access.get(bearer);
      if (sub === undefined || !fake.allowed.has(sub)) return json(401, { error: "invalid_token" });
      return json(200, { sub, email: "ada@example.com" });
    }
    return json(404, { error: "not_found" });
  }

  return fake;
}
