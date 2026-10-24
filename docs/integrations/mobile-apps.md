# Mobile apps: bearer mode end to end

You will have a native app (iOS, Android, a desktop client or a CLI) that signs in against the same routes as the browser, keeps its session as a bearer token in the device's secure storage, stays signed in for a year while browsers get a month, skips the session lookup with a sealed copy it carries, and signs out without an `Origin` header, which a native app never has.

## Before you start

- [net/http](net-http.md) for the routes, cookies and error JSON the app will call; nothing in this guide is specific to a router.
- The example is [`examples/mobile-bearer`](../../examples/mobile-bearer/main.go). `go run ./mobile-bearer` in `examples/` serves it on `http://localhost:8081`; `go test ./mobile-bearer` runs its tests. Set `AUTH_SESSION_KEY` (64 hex characters) to keep the sealing key across restarts; unset, a key is made for this run and the log says so.
- No extra module: bearer mode is part of `authhttp`.

## Step 1 — Ask for the token as a bearer

A browser gets its session as a cookie it never sees. An app cannot keep cookies, so it sends [`Auth-Token-Mode`](ds:block?id=tokenmodeheader-s6xp5wjc)`: `[`bearer`](ds:block?id=tokenmodebearer-3p2r26xe) on the sign-in or sign-up request. The session then arrives in [`Set-Auth-Token`](ds:block?id=settokenheader-j7vbxqvy), its expiry in [`Set-Auth-Token-Expires`](ds:block?id=settokenexpiresheader-rxwtm4ay), and no cookie is set. The token is never in the JSON body, so a page script on a cookie client can never read one out of a response.

```sh
curl -si -X POST localhost:8081/auth/password/sign-up -H 'Auth-Token-Mode: bearer' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
```

```text
HTTP/1.1 200 OK
Set-Auth-Token: m7gVGPn9an0pm4yrgJ_pFeEJ_g8l36DLZDzAxTP7V6o
Set-Auth-Token-Expires: 2026-12-30T05:17:42Z

{"user":{"id":"usr_u52646iiyonxgopmb4ylxi3x","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

No `Set-Cookie` and no `Origin` header: a native app has neither. The expiry is ninety days ahead, the app's idle lifetime (step 4). Headers unrelated to auth are left out of the transcripts here.

Check: the app stores the token in the platform's secure storage (Keychain on iOS, EncryptedSharedPreferences or the Keystore on Android, the OS credential store on desktop), never in a plain file, a log or a crash report, and reads `Set-Auth-Token-Expires` to know when to sign in again.

## Step 2 — Send it back on every request

Every request carries `Authorization: Bearer <token>`. `authhttp` reads it when there is no session cookie (a cookie wins when both are present). The handler is the same one that serves the browser; `/me` here reports which credential the request used.

<!-- ds:block id=mobile-newhandler-c8ht2nfe -->
**newHandler** · [`examples/mobile-bearer/main.go:164-169`](../../examples/mobile-bearer/main.go#L164-L169)

```go
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}
```
<!-- /ds:block hash=9e6587 -->

<!-- ds:block id=mobile-me-k2vd8snw -->
**me** · [`examples/mobile-bearer/main.go:182-187`](../../examples/mobile-bearer/main.go#L182-L187)

```go
func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	s, _ := auth.CurrentSession(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, Credential: auth.RequestCredential(r.Context()), ExpiresAt: s.ExpiresAt}) // a client that hung up cannot be told
}
```
<!-- /ds:block hash=d3d940 -->

```sh
curl -si localhost:8081/me -H 'Authorization: Bearer m7gVGPn9an0pm4yrgJ_pFeEJ_g8l36DLZDzAxTP7V6o'
```

```text
HTTP/1.1 200 OK
Set-Auth-Session-Cache: LKIRjQfl9H4zX4QyDNOzXYBgoBNCN5PxrRWlm7-zekwWB9WnZLf9MwANbUIuBJ7RBSze-pNRA1xBoGR2YKXSrnOPf1kII99q7DQZoPpP2xB9mTFrXVvvw5OnMH0A1I7RK5ezWEfMMVQmYAu71aS7ywEBUxX2VTfVh-dPkfCUHUpvv4ym2hUZsGcDMgyIXSzkoRuDqfrvJVMrj5d3M6g5gQ9s1HLge7BToxaVIt2J1GMopc2S5l3R5ohhFTd5WJjifl1jbQa4O0e-aDraFpRU2c2SzWBPB_trgKAqbGwXip5EyS2WxsD3PmbMZD4MdPicteojDwDQvAsh969hyXWIwK6V1hFHgNL-9-m1a-fPzIhWK8UFwaY15pRXPv8VhwIt6bdK_6LaFzvsoE9h4vUZVvEDbTozRKbaYgtl_N-Lbl9LqXWiYLSD9HQDidE_h9kAVEtbrQGuyAaV0QCGiEg1k2JTPEFbISSMar1qM27Vh8uxMO6pARhtTLgHsr6zKgkk7o4j5495QLabGqwpEvKpsVGvr5mPFylG506VzEv-CJ9RN4IC7As3TuZo68ovrc8VpP8ObeCI_OH_FLJZKMXANeVN8JBXh1cyo3j-N-b0jo3SBmlueN01d7BM4SldiTSpxKrCIJHQqdV212BnA9rrlZVNirocZtzpVaNaJs_Ms0myjV9Ly60HdAEMsEgScr6BAceLe_gs1VvsvYzW805aGaa9zWfceCDmQAjf7PFfEfa2VN9bqezDLm0y_s-Qkpg11wI8iG8o5faQUf6CyJ3M_B5vdoD2VEIp3Xykrr0L_mGUgYcOrbAxRL_ieLtCSevPeKQxVkjppsqTMwH1k9fgSWgZMQ-bFBB3xMsrdllKqiCiSrtweGrzaIg4hYgupFm9olShqRli_LmQUzhX2fIosdVpy8Bkv7y4X_hSPEAGfaUlVMq0BPpceUZlcfGo_ss

{"id":"usr_u52646iiyonxgopmb4ylxi3x","credential":"bearer","expiresAt":"2026-12-30T05:17:42.857457Z"}
```

Check: the same account from a browser gets a cookie and the shorter lifetime (step 4).

## Step 3 — Skip the lookup with the session cache header

With `auth.WithSessionCache(auth.NewSnapshotCache(key), ttl)`, the first request looks the session up and answers with [`Set-Auth-Session-Cache`](../../authhttp/README.md): a sealed copy of the session and user, bound to this token's hash and valid for the TTL (here five minutes; the core caps it at [`MaxSessionCacheTTL`](ds:block?id=maxsessioncachettl-2sh2x4n6), fifteen). The app sends it back in `Auth-Session-Cache`, and those requests cost no session lookup at all. A copy presented with another token is refused: the hash inside is compared in constant time.

The first `/me` above answered `Set-Auth-Session-Cache`, 959 characters here. Sent back, the next request is answered without a lookup and without a new copy; the same copy with another token is refused:

```sh
curl -si localhost:8081/me -H 'Authorization: Bearer m7gVGPn9an0pm4yrgJ_pFeEJ_g8l36DLZDzAxTP7V6o' -H "Auth-Session-Cache: $SNAPSHOT"
curl -si localhost:8081/me -H 'Authorization: Bearer not-the-token' -H "Auth-Session-Cache: $SNAPSHOT"
```

```text
HTTP/1.1 200 OK
{"id":"usr_u52646iiyonxgopmb4ylxi3x","credential":"bearer","expiresAt":"2026-12-30T05:17:42.857457Z"}
HTTP/1.1 401 Unauthorized
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

(`$SNAPSHOT` holds the header value from the previous answer.)

Check: when the copy expires the next request looks the session up again and answers a fresh `Set-Auth-Session-Cache`; the app replaces what it holds whenever the header appears. A sign-out or a revocation elsewhere reaches a device holding a valid copy only when the copy expires, which is why the TTL is short.

## Step 4 — Give apps and browsers different lifetimes

A phone app signs in once and should stay signed in; a browser on a shared machine should not. `auth.WithSessionPolicy(auth.ByCredential(web, app))` chooses the lifetime by how the client presents its token: `CredentialBearer` for the app (a request that asked for bearer delivery counts as one at sign-in, when it has no token yet), `CredentialCookie` for the browser. The choice is stored with the session, so every sliding refresh honours it.

<!-- ds:block id=mobile-lifetimes-a3k9mw2q -->
**webLifetime** · [`examples/mobile-bearer/main.go:89-92`](../../examples/mobile-bearer/main.go#L89-L92)

```go
var (
	webLifetime = auth.SessionLifetime{Idle: 7 * day, Max: 30 * day}
	appLifetime = auth.SessionLifetime{Idle: 90 * day, Max: 365 * day}
)
```
<!-- /ds:block hash=023ca9 -->

<!-- ds:block id=mobile-newauth-7qpx4rvm -->
**newAuth** · [`examples/mobile-bearer/main.go:146-157`](../../examples/mobile-bearer/main.go#L146-L157)

```go
func newAuth(db *sql.DB, m email.Mailer, key []byte) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSessionPolicy(auth.ByCredential(webLifetime, appLifetime)),
		auth.WithSessionCache(auth.NewSnapshotCache(key), cacheTTL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
	)
}
```
<!-- /ds:block hash=bb5831 -->

<!-- ds:block id=core-bycredential-f4r97d2a -->
**ByCredential** · [`lifetime.go:68-75`](../../lifetime.go#L68-L75)

```go
func ByCredential(cookie, bearer SessionLifetime) SessionPolicy {
	return func(_ context.Context, in SessionPolicyInput) SessionLifetime {
		if in.Credential == CredentialBearer {
			return bearer
		}
		return cookie
	}
}
```
<!-- /ds:block hash=5b1881 -->

`Idle` is how long a session may go unused, `Max` the ceiling from creation (capped at [`MaxSessionLifetime`](ds:block?id=maxsessionlifetime-pmz4mcbj), 400 days), and `RefreshAfter` how often the expiry slides; a zero falls back to `auth.SessionConfig`.

```sh
curl -si -c cookies.txt -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b cookies.txt localhost:8081/me
```

```text
HTTP/1.1 200 OK
Set-Cookie: __Host-auth_session=UWueilo6eBQQTCQe4sVox9DfJlJH82u53XR-W5Us3Dw; Path=/; Expires=Thu, 08 Oct 2026 05:17:43 GMT; HttpOnly; Secure; SameSite=Lax

{"id":"usr_u52646iiyonxgopmb4ylxi3x","credential":"cookie","expiresAt":"2026-10-08T05:17:43.26301Z"}
```

Check: `Set-Auth-Token-Expires` is about ninety days ahead for the app; the browser's cookie `Expires` about seven.

## Step 5 — Sign out, and handle a dead token

A bearer mutation needs no `Origin`: the origin check exists for cookies, which a browser attaches to a cross-site request on its own; a bearer header is attached only by code that holds the token. Sign-out answers with no `Set-Cookie` and no header; the app deletes its token and its cached copy. A token that was signed out, expired or revoked from the session list answers 401 `auth.signed_out` on every route, and the app goes back to the sign-in screen.

```sh
curl -si -X POST localhost:8081/auth/sign-out -H 'Authorization: Bearer m7gVGPn9an0pm4yrgJ_pFeEJ_g8l36DLZDzAxTP7V6o'
curl -s localhost:8081/me -H 'Authorization: Bearer m7gVGPn9an0pm4yrgJ_pFeEJ_g8l36DLZDzAxTP7V6o'
```

```text
HTTP/1.1 200 OK
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

A sign-out that does not send the copy is looked up once more before the session ends, but the copy that lookup makes is not sent back: a response that ends the session never answers `Set-Auth-Session-Cache`.

Check: a wrong password answers the same JSON as in a browser, with no token in sight:

```sh
curl -si -X POST localhost:8081/auth/password/sign-in -H 'Auth-Token-Mode: bearer' \
  -d '{"identifier":"alice@example.com","password":"wrong"}'
```

```text
HTTP/1.1 401 Unauthorized
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
```

## Step 6 — End a browser flow inside the app

Some sign-ins cannot stay in the app: an OAuth provider or a magic link opens the system browser, and the browser has to hand the result back. The hand-off is a deep link, a URL in the app's own scheme (`myapp://signed-in`) or its reverse-domain form (`com.example.app:/signed-in`), which the device routes to the app.

The library treats such a URL like any other return address: it must be trusted, and the one rule every `returnTo` goes through is `TrustsReturnURL`:

<!-- ds:block id=core-trustsreturnurl-9tk2mq4w -->
**Auth.TrustsReturnURL** · [`returnurl.go:83-108`](../../returnurl.go#L83-L108)

```go
func (a *Auth) TrustsReturnURL(target string) bool {
	if a.noOriginCheck {
		// WithoutOriginCheck: any destination. A line break or a backslash is
		// still refused: that guards the Location header against injection
		// and URL confusion, which is not a destination policy. See its
		// comment for the risk.
		return target != "" && !strings.ContainsAny(target, "\\\n\r")
	}
	if target == "" || strings.ContainsAny(target, "\\\n\r") {
		return false
	}
	if strings.HasPrefix(target, "/") {
		return !strings.HasPrefix(target, "//")
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" {
		return false
	}
	if _, ok := a.trustedSchemes[strings.ToLower(u.Scheme)]; ok {
		return true
	}
	if a.loopbackReturn && isLoopbackReturn(u) {
		return true
	}
	return u.Host != "" && a.TrustsOrigin(u.Scheme+"://"+u.Host)
}
```
<!-- /ds:block hash=14f065 -->

List the scheme once, at wiring, and the OAuth plugin's `returnTo` may name it:

```go
auth.WithTrustedOrigins("myapp://")
```

Only the scheme is trusted, never a wildcard (`myapp://*` is refused, like every pattern that is not a `*.` subdomain), and a scheme entry with a host or a path is refused by `auth.New`. The return carries nothing secret: any app on the device can register a scheme, so the browser flow ends with the session delivered as the flow asked for it, a bearer token in the response for an app (step 1), and the deep link only tells the app to continue. A start that names an untrusted return is refused before anything is sent to the provider, the same open-redirect defence a web app gets for a path on another site. See [Configuration](../concepts/configuration.md) for the entry's spelling.

## Step 7 — From TypeScript: React Native, Electron and CLIs

An app written in TypeScript does Steps 1, 2 and 5 with the [TypeScript client](../client/README.md) in bearer mode: it sends `Auth-Token-Mode: bearer`, stores every `Set-Auth-Token` it receives in a `TokenStore`, sends `Authorization: Bearer` from it, and clears it when the server answers `Set-Auth-Token` with an empty value (the session ended or the token is dead). The store is the one thing the app writes. In React Native with Expo, over `expo-secure-store` (the Keychain on iOS, the Keystore on Android; type-checked by `task ts:check`, not run):

<!-- ds:block id=bearer-expostore-4qw8kx2m -->
**expoSecureStorage** · [`clients/ts/examples/bearer.ts:47-57`](../../clients/ts/examples/bearer.ts#L47-L57)

```typescript
export function expoSecureStorage(store: {
  getItemAsync(key: string): Promise<string | null>;
  setItemAsync(key: string, value: string): Promise<void>;
  deleteItemAsync(key: string): Promise<void>;
}): SecureStorage {
  return {
    getItem: (key) => store.getItemAsync(key),
    setItem: (key, value) => store.setItemAsync(key, value),
    deleteItem: (key) => store.deleteItemAsync(key),
  };
}
```
<!-- /ds:block hash=23be32 -->

In a CLI, over a file only its owner can read, from [ts-client-bearer](../../examples/ts-client-bearer/), whose Go test runs every command as a new process:

<!-- ds:block id=filetokenstore-az67vtyj -->
**fileTokenStore** · [`examples/ts-client-bearer/web/cli.ts:37-52`](../../examples/ts-client-bearer/web/cli.ts#L37-L52)

```typescript
function fileTokenStore(path: string): TokenStore {
  return {
    get: async () => {
      try {
        return (await readFile(path, "utf8")).trim() || null;
      } catch (err) {
        if (isMissingFile(err)) return null; // no file yet: signed out
        throw err; // unreadable (permissions, a directory): say so, never pretend to be signed out
      }
    },
    set: async (token) => {
      if (token === null) await rm(path, { force: true });
      else await writeFile(path, token, { mode: TOKEN_FILE_MODE });
    },
  };
}
```
<!-- /ds:block hash=d2cb8f -->

The CLI passes it as `tokenStore` beside `tokenMode: "bearer"`, and its own `fetch` names the program in the session list and gives up on a dead server:

<!-- ds:block id=clifetch-2wa5e3a3 -->
**cliFetch** · [`examples/ts-client-bearer/web/cli.ts:65-69`](../../examples/ts-client-bearer/web/cli.ts#L65-L69)

```typescript
const cliFetch: typeof fetch = (input, init) => {
  const headers = new Headers(init?.headers);
  headers.set("User-Agent", USER_AGENT);
  return fetch(input, { ...init, headers, signal: init?.signal ?? AbortSignal.timeout(CALL_TIMEOUT_MS) });
};
```
<!-- /ds:block hash=531f12 -->

Try it: from `examples/`, `PORT=8111 go run ./ts-client-bearer`, then in another terminal with Node 22.18 or later (`export AUTH_URL=http://localhost:8111`), each line a new process:

```sh
node ts-client-bearer/web/cli.ts sign-up ada@example.com "correct horse battery staple" Ada
ls -l .auth-token
node ts-client-bearer/web/cli.ts whoami
node ts-client-bearer/web/cli.ts sign-out
node ts-client-bearer/web/cli.ts whoami
node ts-client-bearer/web/cli.ts sign-in ada@example.com wrong
```

```text
signed up and signed in as Ada; token saved
-rw-------@ 1 khanakia  staff  43 Oct 12 15:11 .auth-token
Ada (token read from .auth-token)
signed out; token file removed
not signed in (auth.signed_out)
The sign-in details are not right. (password.invalid_credentials)
```

Pitfalls with the client:

- The client empties the store whenever the server answers an empty `Set-Auth-Token`: the call ended the session (sign-out, revoking the current session, deleting the account) or the token names no session any more (expired, revoked, `signOutAll` from another device). A pending second-factor token is refused with `auth.signed_out` too but is alive, so it is kept for `twofactor.verify`. Against a server older than that header, `signOut()` and `signOutAll()` still clear the store on `auth.signed_out` ([Bearer mode › Forget the token](../client/bearer-and-mobile.md#forget-the-token-when-the-session-is-gone)).
- With no `tokenStore`, bearer mode keeps the token in memory: the app is signed out every time it restarts.
- A token file or storage entry is a credential: write it owner-only (`0600`), keep it out of backups you do not control and out of logs. The repository's `.gitignore` ignores the CLI example's `.auth-token`.
- The client does not handle the session cache of Step 3: it neither keeps `Set-Auth-Session-Cache` nor sends `Auth-Session-Cache`. An app that wants it reads the header in its own `fetch` option and sends it back in `headers`.

## Options you may want

| Need | Do |
|---|---|
| The app's session should end when the phone is lost | Show the session list (`GET /auth/sessions`) in the web app; `POST /auth/sessions/revoke` ends one by id, and `POST /auth/sign-out-all` ends them all. The app's next request gets 401. |
| Second factor on the app | Sign-in answers `secondFactorRequired: true` and a pending bearer token; `POST /auth/twofactor/verify` with it promotes the session and answers a new `Set-Auth-Token`. See [Two-factor](../plugins/twofactor.md). |
| Refresh tokens | There are none: the session slides on use, up to `Max`, and the new expiry arrives in `Set-Auth-Token-Expires` whenever it moves (the token itself does not change, except in stateless mode, where a new token is issued). |
| Expo development builds (`exp://192.168.1.20:8081`) | `auth.WithTrustedOrigins("exp://")` trusts the whole development scheme as a return address. When a check must be narrower than a scheme, `auth.WithTrustedOriginFunc(func(origin string) bool { return strings.HasPrefix(origin, "exp://192.168.") })` decides any pattern; keep it as narrow as an exact list would be, because the origin check is the login-CSRF defence. |
| A CLI or a script rather than an app | The same headers work; for a long-lived machine credential prefer an [API key](../plugins/apikey.md), which carries scopes and can be revoked without ending a person's sessions. |

## What can go wrong

| You see | Why | Fix |
|---|---|---|
| A cookie arrives and `Set-Auth-Token` is missing | The sign-in request did not send `Auth-Token-Mode: bearer`. | Send the header on every request that may issue a session: sign-in, sign-up, the two-factor step. |
| `auth.signed_out` on every request with a token that worked yesterday | The session was signed out elsewhere, revoked, or passed its lifetime. | Sign in again; show the session list so users see their devices. |
| A copy from `Set-Auth-Session-Cache` makes no difference | It is sent back under the wrong header name, or with a different token. | Send it as `Auth-Session-Cache` with the same `Authorization` token. |
| The app gets the browser's short lifetime | The sign-in request had no `Auth-Token-Mode: bearer`, so the core saw a cookie client. | Same fix as the first row. |
| `auth.origin_not_trusted` on a bearer request | The request also carried a session cookie (a WebView sharing the browser's jar), and the cookie wins. | Clear the WebView's cookies, or do not share them with the native client. |

## Next

- [SPA frontends](spa-frontends.md) for a JavaScript app that must choose between cookies and bearer mode, and the [TypeScript client](../client/bearer-and-mobile.md) that calls the routes in either mode.
- [Sessions](../concepts/sessions.md) for stateless sessions, which keep no row at all and suit an API that serves only apps.
- The `authhttp` [README](../../authhttp/README.md) is the reference for every header.
