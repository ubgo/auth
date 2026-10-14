# Security

This page lists what the library defends against and how, so you know what you get, and what it cannot do for you, so you know what remains yours.

## Before you start

- [Sessions](sessions.md) and [Errors](errors.md) explain the cookie and the uniform error codes this page refers to.
- Auth code is held to a higher bar than other features: a broken checkout produces a ticket in an hour; a timing leak on a login endpoint produces nothing for three years and then a breach. The rules below are each pinned by a test in the repository, and several by a test that reads the library's own source.

## Step 1 — Cross-site requests: the origin check

A browser attaches the session cookie to a cross-site `POST` on its own. The library refuses every mutation that carries a session cookie unless the request's `Origin` (or `Referer`, when `Origin` is missing) is the base URL or a trusted origin, and it refuses a missing `Origin` too: a browser that sends a cookie on a cross-site `POST` sends an `Origin`, so a missing one is not an innocent case worth accommodating. The check runs before any lookup, so a cross-site request learns nothing, not even whether its session is valid. Bearer tokens are not affected: a browser never attaches those on its own.

<!-- ds:block id=core-trustsorigin-pvpqhgyd -->
**Auth.TrustsOrigin** · [`pipeline.go:405-418`](../../pipeline.go#L405-L418)

```go
func (a *Auth) TrustsOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	if _, ok := a.trustedOrigins[origin]; ok {
		return true
	}
	for _, p := range a.originPatterns {
		if p.matches(origin) {
			return true
		}
	}
	return a.originFunc != nil && a.originFunc(origin)
}
```
<!-- /ds:block hash=7419f6 -->

The origin check looks only at calls that carry a session cookie, because those are the ones a browser could be made to send on a victim's behalf. A sign-in has no cookie yet, so a form on another site could sign the victim into an account the attacker controls (login CSRF); the password plugin and `authui` check the origin of their own sign-in forms, and `auth.WithFetchMetadata()` closes the rest (next section).

### Refuse cross-site sign-ins: WithFetchMetadata

Use this for any app whose users sign in from a browser, to stop login CSRF on every route at once, including the sign-in routes of plugins that have no form check of their own. With `auth.WithFetchMetadata()`, a mutation whose request says `Sec-Fetch-Site: cross-site` and whose `Origin` is not trusted is refused the same way, cookie or not. Browsers send that header on every request and no script can change it; a client that sends none (a native app, curl, an old browser) is unaffected, which is why it is opt-in rather than a default an app would not know it relies on. A trusted origin passes either check, so an admin app on another site keeps working.

<!-- ds:block id=opt-withfetchmetadata-5rn7kq8z -->
**WithFetchMetadata** · [`call.go:71`](../../call.go#L71-L71)

```go
func WithFetchMetadata() Option { return func(s *settings) { s.fetchMetadata = true } }
```
<!-- /ds:block hash=449a15 -->

`examples/core-options` turns it on with the other core switches:

<!-- ds:block id=coreoptions-p4ag7zqk -->
**coreOptions** · [`examples/core-options/main.go:142-150`](../../examples/core-options/main.go#L142-L150)

```go
func coreOptions(db *sql.DB) []auth.Option {
	return []auth.Option{
		auth.WithDBAuto(db),
		auth.WithBaseURL(baseURL),
		auth.WithIDs(newUUIDv7),
		auth.WithDisabledOperations(password.EndpointSignUp),
		auth.WithFetchMetadata(),
	}
}
```
<!-- /ds:block hash=a02430 -->

Try it: a sign-in sent the way a hidden form on another site would send it is refused, although it carries no cookie; the same request from the app's own page, and one with no `Sec-Fetch-Site` at all, pass:

```sh
curl -s -i -X POST localhost:8098/auth/password/sign-in -H 'Origin: https://evil.example' -H 'Sec-Fetch-Site: cross-site' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
```

```text
HTTP/1.1 403 Forbidden
{"error":{"code":"auth.origin_not_trusted","message":"This request came from a site that is not trusted."}}
```

Check: `TestFetchMetadata` in `examples/core-options`: 403 and no cookie for `cross-site`, 200 for `same-origin` and for no header, and the same cross-site sign-in succeeding on an `Auth` built without the option.

### Return URLs and the trusted set

Where a flow may send the browser afterwards is a separate question from who may post with a cookie, and `auth.WithLoopbackReturn()` keeps it separate: it lets `TrustsReturnURL` accept `http://127.0.0.1` and `http://[::1]` on any port for a native app that listens on an ephemeral loopback port (RFC 8252 §7.3), while `TrustsOrigin` never accepts a loopback origin it was not given exactly, since any page served from any local port could otherwise make credentialed requests.

The trusted set is the base URL's origin, `auth.WithTrustedOrigins` (exact origins, or a wildcard pattern such as `https://*.example.com` for every subdomain of a domain you own), what an `OriginTruster` plugin adds, and, asked last and only for an origin none of those accepted, the function given to `auth.WithTrustedOriginFunc`, for a set that changes while the process runs. A pattern is strict about where its wildcards sit: `*` and `?` only in labels left of a fixed domain of two labels or more, so `https://*`, `https://*.com` and `https://api.*` are refused at start. A first label that is `*` alone spans any depth of subdomains; inside a label (`https://preview-*.example.com`) `*` and `?` never cross a dot.

<!-- ds:block id=opt-withtrustedoriginfunc-7j7xq3hq -->
**WithTrustedOriginFunc** · [`origins.go:55-62`](../../origins.go#L55-L62)

```go
func WithTrustedOriginFunc(fn OriginFunc) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithTrustedOriginFunc", fn) {
			return
		}
		s.originFunc = fn
	}
}
```
<!-- /ds:block hash=f23f42 -->

A sign-in or sign-up carries no session cookie, so the cookie check does not cover it; the library's own sign-in operations and `authui`'s forms check the origin themselves, which is the only defence against login CSRF (getting a victim signed in to the attacker's account). An app route of its own that signs users in does the same:

<!-- ds:block id=saas-signuphandler-88qakgg4 -->
**signupHandler** · [`examples/saas-workspace/main.go:222-244`](../../examples/saas-workspace/main.go#L222-L244)

```go
func signupHandler(a *auth.Auth, pw *password.Plugin) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.TrustsOrigin(authhttp.RequestOf(r).Client.Origin) {
			authhttp.WriteError(w, auth.ErrOriginNotTrusted)
			return
		}
		var in signupRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&in); err != nil {
			authhttp.WriteError(w, auth.ErrBadRequest)
			return
		}
		out, err := signup(r.Context(), a, pw, in)
		if err != nil {
			var ae *auth.Error
			if !errors.As(err, &ae) {
				log.Printf("signup: %v", err)
			}
			authhttp.WriteError(w, err)
			return
		}
		writeJSON(w, out)
	})
}
```
<!-- /ds:block hash=f7d267 -->

Check: a `POST` with the session cookie and `Origin: https://evil.example` answers `403` with `auth.origin_not_trusted`.

### Escape hatches, and what each one opens

better-auth has three switches that turn a check off, and the library has each as an opt-in, off by default, logged as a warning by `auth.New` (or the plugin's `Init`) at every start while it is on, so a deployment cannot forget it set one:

| Switch | better-auth | What it turns off | What it opens |
| --- | --- | --- | --- |
| [`auth.WithoutCSRFCheck()`](ds:block?id=opt-withoutcsrfcheck-6tw2mz9k) | `advanced.disableCSRFCheck` | The origin check on cookie-authenticated mutations, and `WithFetchMetadata`'s cross-site refusal | Cross-site request forgery: another site posts to the auth routes with the user's cookie (sign-out, revoking sessions, unlinking a provider, creating an API key) |
| [`auth.WithoutOriginCheck()`](ds:block?id=opt-withoutorigincheck-2nf7xq4d) | `advanced.disableOriginCheck` | Return-URL validation: `TrustsReturnURL` accepts any non-empty target without a line break or backslash | An open redirect, and token-bearing links to any host: a reset `redirectTo` or magic-link callback on the attacker's site receives the victim's live token, which is account takeover on one click |
| [`oauth.SkipStateCookieCheck()`](ds:block?id=oauth-skipstatecookiecheck-3wn8kq5d) | `account.skipStateCookieCheck` | The match between the callback's state and the flow cookie (the state is still single use and checked against its stored row) | Login CSRF: the attacker starts a flow, signs in at the provider as themself and sends the victim the callback URL; the victim is signed in to the attacker's account |

None has a production use that a safer switch does not cover: `WithTrustedOrigins` (patterns, custom schemes), `WithTrustedOriginFunc`, `WithLoopbackReturn`, bearer mode, and authhttp's `CookieDomain` or the desktop hand-off for a callback the flow cookie cannot reach. Search the start-up log for `WithoutCSRFCheck is on`, `WithoutOriginCheck is on` and `SkipStateCookieCheck is on` before a release, and for `AllowIDTokenReplay is set`, the library's own switch that lets a captured native ID token be used again until it expires.

## Step 2 — The cookie

`__Host-auth_session`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`. `__Host-` makes the browser refuse the cookie from any other host, port or scheme and forbids a `Domain`; `HttpOnly` keeps it from scripts; `Secure` keeps it off plain HTTP; `Lax` keeps it off cross-site `POST`s while letting a link to your site work. The value is a random token, never anything a client could decode; the database holds its hash, so a backup contains no live session.

<!-- ds:block id=authhttp-cookie-hnq6pz4u -->
**config.cookie** · [`authhttp/authhttp.go:1443-1470`](../../authhttp/authhttp.go#L1443-L1470)

```go
func (cfg config) cookie(name, value string, expiresAt time.Time) *http.Cookie {
	attrs := cfg.attrsOfName(name)
	c := &http.Cookie{
		Name:        name,
		Domain:      cfg.cookieDomain,
		Value:       value,
		Path:        "/",
		HttpOnly:    !attrs.ScriptReadable,
		Secure:      !attrs.Insecure,
		SameSite:    http.SameSiteLaxMode,
		Partitioned: cfg.partitioned && !attrs.Insecure,
	}
	if attrs.Path != "" {
		c.Path = attrs.Path
	}
	if cfg.sameSite == http.SameSiteStrictMode {
		c.SameSite = http.SameSiteStrictMode
	}
	if attrs.CrossSite {
		c.SameSite = http.SameSiteNoneMode
	}
	if expiresAt.IsZero() {
		c.MaxAge = -1
	} else {
		c.Expires = expiresAt
	}
	return c
}
```
<!-- /ds:block hash=0a79ff -->

`authhttp.WeakenCookies` / `authhttp.WeakenCookie` (better-auth's cookie attributes) can turn `HttpOnly`, `Secure`, `SameSite` or `Path=/` off, each an escape hatch that logs [a warning](ds:block?id=authhttp-warncookiesweakened-3nq8wk5x) at every start; `Insecure` also drops the `__Host-` prefix, which a browser accepts only on a secure cookie. `authhttp.CookieDomain` relaxes one of these on purpose, so sibling subdomains can share the session; every subdomain, including one that serves user content, can then read it. Use it only when every subdomain is yours. Nothing else can be relaxed: there is no option for `HttpOnly`, `Secure` or the browser prefix. The options go the other way. `authhttp.SameSiteStrict()` sends every cookie but the flow cookie with `SameSite=Strict`, so a link from a mail or a redirect from another site arrives with no session; the flow cookie stays `Lax` because the OAuth return is exactly such a navigation, and the trade-off is that the first page after an OAuth callback may render signed out, since browsers treat a redirect chain that began at the provider as cross-site. `authhttp.PartitionedCookies()` adds `Partitioned` (CHIPS) for an app embedded in another site's page. `authhttp.CookiePrefix("myapp")` renames the cookies (`__Host-myapp_session` and so on) without touching the `__Host-` or `__Secure-` part.

Check: `curl -si` on sign-in shows exactly those attributes.

## Step 3 — Enumeration: uniform answers and uniform timing

A sign-in answers `password.invalid_credentials` for a wrong password and for an unknown account alike, and hashes a password even when there is no account to compare against, so the response time says no more than the message. A reset request answers the same whether or not the address exists, and the mail goes out after the response, in the background, so the request takes the same time either way. Tokens and codes answer `auth.token_invalid` and `auth.code_invalid` for wrong, used, expired and wrong-purpose alike. Every comparison of a secret is constant-time; a test reads the library's syntax tree and fails on any `==` between a token, a hash or a code.

<!-- ds:block id=core-hashtoken-4dghp6j6 -->
**HashToken** · [`token.go:73-76`](../../token.go#L73-L76)

```go
func HashToken(t Token) []byte {
	sum := sha256.Sum256([]byte(t))
	return sum[:]
}
```
<!-- /ds:block hash=6b8927 -->

Check: time a sign-in with a wrong password for an existing and for a missing account; both take the hash's duration. [`TestPassword_UnknownAccountCostsAHash`](ds:block?id=testpassword-unknownaccountcostsahash-qbmfb3b2&assert=true) does that on SQLite with a real Argon2 cost, and [`TestGuard_PasswordSignInAlwaysHashesOnce`](ds:block?id=testguard-passwordsigninalwayshashesonce-6msnvqty&assert=true) reads the sign-in code's syntax tree so a branch that skips the hash cannot be added. This is a property of every sign-in path rather than something a program calls, so it has no example of its own.

## Step 4 — Tokens, codes and secrets

- Session and verification tokens are 32 random bytes; only their SHA-256 reaches the database. A verification token is spent by the database, not by Go: of two requests with one token exactly one updates the row.
- A provider ID token posted by a native app (`plugin/oauth`'s id-token route and its re-authentication) is accepted once: after it verifies, the plugin claims it until its `exp`, keyed by the hash of its signed part, and the same token again is `401 oauth.id_token_replayed` and a `token.replay` security event. The nonce alone cannot stop a replay, because the client sends it beside the token. The guard is swappable (`oauth.WithIDTokenReplayGuard`) and turned off only by name (`oauth.AllowIDTokenReplay`, logged at start); see [replay protection](../plugins/oauth.md#replay-protection).
- A one-time code is six digits, bound to its subject (the address or number it was sent to) and spent after [five](ds:block?id=defaultcodemaxattempts-qcfgc2jc) wrong guesses, which the rate limits bound further. A code is never looked up by its value alone.
- A password is hashed with Argon2id by `plugin/password`, which refuses short, long and breached passwords (`plugin/password/hibp`, k-anonymity, never the password itself leaving the process).
- Secrets a plugin must read back — a TOTP secret, a provider's refresh token — are sealed with AES-256-GCM, bound to their row, by `auth.Seal`; a sealed value copied onto another row does not open.
- One secret can stand behind every key: `auth.WithSecret` derives the stateless session key, the snapshot cache key and any plugin key that was not passed explicitly with HKDF-SHA256 under a label of its own, so the features share a variable and no key material. The secret is never read by a plugin; `Config.DeriveKey(label)` hands out keys only.
- `auth.Token` prints as `[redacted]` through every formatting path and encodes as `"[redacted]"` in JSON, so a logged request or result never leaks one. The raw value is reachable only through `Reveal`, which a review can grep for. A field that is meant to carry a token over the wire (the token `invite.create` hands its creator, a poll token, the token a client sends back from a link) is an `auth.WireToken` instead: it encodes as its value in JSON and only there, and still prints `[redacted]` everywhere else. `auth.New` refuses an operation whose output carries an `auth.Token` in a field JSON would write, because that field could only ever answer `"[redacted]"`.

<!-- ds:block id=core-seal-6juxhbp8 -->
**Seal** · [`seal.go:28-35`](../../seal.go#L28-L35)

```go
func Seal(key, plain []byte, aad string) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := randomBytes(gcm.NonceSize())
	return base64.RawStdEncoding.EncodeToString(gcm.Seal(nonce, nonce, plain, []byte(aad))), nil
}
```
<!-- /ds:block hash=fb92c9 -->

Check: `grep -rn 'Reveal()'` in your code shows exactly the places that write a token to a client.

## Step 5 — Sessions and factors

- A second factor makes the password alone produce a pending session that signs nobody in; passing the factor issues a new token, so one captured before the step is worthless after it.
- Changing a password, an address or a factor needs a session created or re-authenticated within [ten minutes](ds:block?id=defaultfreshwindow-5mt8jqw7): a stolen laptop with an old session cannot lock the owner out. Re-authentication asks for what sign-in asks for, the second factor included, so a stolen cookie plus a leaked password is not enough.
- A password reset and "sign out everywhere" end every session of the user, in every session mode.
- An admin acting as a user gets a session of at most [an hour](ds:block?id=maximpersonationttl-3f39wbus) that the user's own session list shows, and that cannot change what proves the user is them.
- A banned or suspended user is refused at the next session lookup, because the condition is part of the lookup; with a session cache the delay is the cache TTL, at most [fifteen minutes](ds:block?id=maxsessioncachettl-2sh2x4n6).

Opt-in policies harden sign-in further, all off by default:

- Country allow and deny rules, checked before the credentials so a refusal says nothing about the password, and impossible-travel detection, checked where the session is created, over a GeoIP source you supply ([Geo rules](geo-rules.md)).
- Checks of your own for a suspicious address, a script and a repeat free-trial sign-up, each blocking, logging or challenging, with an explicit fail-open or fail-closed choice when the check is down ([Risk signals](risk-signals.md)).
- A proof-of-work challenge in place of a captcha for a rate or geo rule's challenge action, with no third party in the loop ([pow](../plugins/pow.md)).
- A security event stream that hands every rate-limit excess, credential-stuffing crossing, two-factor lockout and geo refusal to your own log drain or SIEM, without ever blocking a request ([Security events](security-events.md)).
- Warning, and if you ask for it deleting, accounts nobody has used for a long time (a year by default), so a dormant account with a reused password does not stay open forever ([stale](../plugins/stale.md)).
- Rotating the session token on every sliding refresh and revoking the session when a replaced token comes back after a short grace window, so a copied cookie or bearer token is caught and ended rather than silently shared ([Sessions](sessions.md#catch-a-copied-token-withtokenrotation)).
- Session tasks: a signed-in user who must first set up a second factor (or choose an organization, or anything a plugin declares) reaches only the operations that finish it, and every app route treats them as signed out until then ([Session tasks](session-tasks.md)).

## Step 6 — What the app must still do

The library cannot do these for you:

- Serve over HTTPS. The cookie is `Secure`; over plain HTTP no browser sends it, and over HTTP the token travels in clear.
- Keep keys out of the code: the stateless-session key, the snapshot key, the two-factor and OAuth sealing keys, OAuth client secrets. Rotating the stateless key signs everyone out; rotating a sealing key makes every sealed value unreadable (`auth: sealed value does not open; was the key changed?`).
- Set `WithBaseURL` to the real public URL. Without it no origin is trusted and every cookie-authenticated mutation fails; with the wrong one, links in mail point at the wrong site.
- Share rate-limit counters across instances (`WithDBRateStore` or Redis), or an attacker gets every instance's budget.
- Terminate proxies so that the client's address reaches the app, or address-based limits count the proxy.
- Authorize. The library says who the user is and whether the session is fresh; what they may do in your app is yours, including role checks (`plugin/organization` helps) and scope checks for API keys (`authhttp.RequireScope`).
- Check the origin on your own sign-in routes, as in step 1, and never write an auth table yourself: the invariants live in Go, and a direct `UPDATE auth_identity` can create two verified owners of one address.
- Log the internal errors the transport hands you; the client sees `auth.internal` and nothing else.

## Rotating a sealing key

Every key the library takes is 32 bytes (`auth.SealKeySize`). `auth.WithStatelessSessions(new, old)` and `auth.NewSnapshotCache(new, old)` take a ring: the first key seals, every key opens, so a rotation is "add the new key first, deploy, drop the old key once what it sealed has expired", with nobody signed out. A plugin that seals its own values (a TOTP secret, a provider's refresh token) rotates the same way with `auth.NewKeyRing(new, old)`, whose `Open` also reads values sealed by the single-key `auth.Seal`, so nothing needs resealing to start. Keys derived from `auth.WithSecret` rotate the same way: `auth.WithSecret(new, old)` derives the sealing key from the new secret and an opening key from each, under the same fixed labels (`Config.DeriveKeys` is the ring's argument list), so a rotation of the one secret is a rotation of every derived ring at once with nothing resealed.

<!-- ds:block id=core-keyring-6zn8rq2v -->
**KeyRing** · [`keyring.go:24-26`](../../keyring.go#L24-L26)

```go
type KeyRing struct {
	gcms []cipher.AEAD
}
```
<!-- /ds:block hash=ff2013 -->

## Keys in a KMS: the Sealer

An app whose keys must never sit in process memory (Vault transit, AWS KMS, Google Cloud KMS, an HSM) supplies an [`auth.Sealer`](ds:block?id=core-sealer-4kw9vn2t): `Seal(ctx, plain, aad)` returns text for a column and `Open(ctx, sealed, aad)` reverses it, refusing a value sealed under another `aad`. The sealed text is opaque to the library, so a key service that rotates puts its key id inside it (Vault's `vault:v3:…`) and picks the key from it when opening. The default is the key ring itself, adapted by [`auth.RingSealer(ring)`](ds:block?id=core-ringsealer-9qz3xh6p) in the ring's own format, so values sealed before the switch still open.

[`auth.WithSealer(s)`](ds:block?id=opt-withsealer-2mt7rk5c) makes `s` the sealer of every plugin that keeps secrets at rest and was given no key of its own; plugins read it as [`Config.Sealer()`](ds:block?id=core-config-sealer-6hd4pw8n) in `Validate`. Today that is the OAuth plugin's stored provider tokens and the two-factor plugin's TOTP secrets and encrypted recovery codes. A plugin's explicit key still wins, and `oauth.StoreTokensWith(s)` and `twofactor.WithSealer(s)` set one for that plugin alone. A seal error fails the write and an open error is reported, never read as an empty secret. Session tokens and the snapshot cache are not sealed through it: they are opened on every request, where a round trip to a key service is the wrong trade, so they keep their in-memory ring.

[`examples/kms-sealer`](../../examples/kms-sealer) wires a fake key service with Vault transit's shape in place of a real one, and gives two-factor sign-in no key of its own:

<!-- ds:block id=kmssealer-newauth-6pw3xr9k -->
**newAuth** · [`examples/kms-sealer/main.go:98-109`](../../examples/kms-sealer/main.go#L98-L109)

```go
func newAuth(db *sql.DB, s auth.Sealer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSealer(s),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
			password.New(),
			twofactor.New(twofactor.Issuer(appName)),
		),
	)
}
```
<!-- /ds:block hash=f3926b -->

The fake seals under its newest key version, names the version in the text, and binds the value to the `aad` the plugin passes, which a real service takes as its context (Vault) or encryption context (AWS KMS):

<!-- ds:block id=fakekms-seal-sx8hws4z -->
**fakeKMS.Seal** · [`examples/kms-sealer/kms.go:80-94`](../../examples/kms-sealer/kms.go#L80-L94)

```go
func (k *fakeKMS) Seal(_ context.Context, plain []byte, aad string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.down {
		return "", errKMSUnavailable
	}
	k.seals++
	gcm := k.versions[len(k.versions)-1]
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := gcm.Seal(nonce, nonce, plain, []byte(aad))
	return kmsPrefix + strconv.Itoa(len(k.versions)) + ":" + base64.RawURLEncoding.EncodeToString(out), nil
}
```
<!-- /ds:block hash=017ba6 -->

Try it: `go run ./kms-sealer`, sign up, `POST /auth/twofactor/enroll`, then `sqlite3 kms-sealer.db 'select secret_sealed from auth_two_factor'` shows `kms:v1:…` and never the secret the enrolment answered. Confirming with the authenticator's code still works, because the plugin opens the secret through the same service. The [example's README](../../examples/kms-sealer/README.md) has the transcript.

Check: in the example, `TestSecretIsSealedByTheKeyService` proves the row holds neither the secret nor its bytes and sign-in still completes; `TestRotationKeepsOldSecretsOpening` that a rotated service seals `v2` and still opens `v1`; `TestSecretIsBoundToItsRow` that a sealed secret copied into another user's row does not open; `TestOutageFailsTheWrite` that enrolment fails and stores nothing while the service is down.

## What can go wrong

- `auth.origin_not_trusted` from your own front end — the front end's origin is not the base URL; add it with `WithTrustedOrigins`, or serve both from one origin.
- `auth.signed_out` on every request in development over HTTP — browsers exempt `localhost`; another plain-HTTP host name does not get the `Secure` cookie. Use `localhost` or HTTPS.
- A verify link that points at `localhost` in production — `WithBaseURL` was not set from the environment.
- `auth: sealed value does not open; was the key changed?` — a sealing key changed; the sealed values written under the old key are gone.

## Next

- [Rate limits](rate-limits.md): the budgets around sign-in.
- [Errors](errors.md): every code and why the uniform ones are uniform.
