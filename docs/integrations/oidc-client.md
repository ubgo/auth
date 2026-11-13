# OIDC client: sign people in to a Go app through a login server

You will have a Go web app that signs people in through an OpenID Connect login server, keeps them signed in for days (closing the browser does not sign them out), and still lets the login server take someone out within a minute, whatever cookie their browser holds. The app needs no user table and no code of its own for the protocol: the [`oidcclient`](../../oidcclient/doc.go) package does the redirects, the checks and the session, with the standard library only.

## The story

Example Co. runs the [SSO login server](sso-server.md) at `login.example.com`. The ops console at `ops.example.com` is open to a short list of people, and Sam, a contractor, is on it.

On Monday Sam opens the ops console, signs in with Google through the login server, and works. He closes the browser. On Wednesday he opens the console again and is still signed in: no redirect, no Google. On Thursday at 15:00 his contract ends; the operator takes him off the ops list and revokes what he holds at the console. At 15:01 every request Sam makes is refused, and so is every request made with a copy of his cookie saved on Wednesday. If he is put back on the list next Monday, one click signs him in again.

Two things make that work. The session is long and lives in a cookie with an expiry, so the browser keeps it. And while Sam is active, the console asks the login server again at most once a minute whether he may still use it; the login server's answer, not the cookie, decides. [How an OIDC login works](../concepts/oidc-login-flow.md#staying-signed-in-and-being-removed) tells the story step by step.

## When to use it

Use it for a server-rendered Go app, or a Go backend that serves a browser, that signs people in through any OpenID Connect server: the ubgo/auth [login server](sso-server.md), Google, Keycloak or Entra.

Pick something else when:

- **You want to see every check written out.** [`examples/sso-client`](../../examples/sso-client/) does the same sign-in by hand with the standard library, as a teaching aid.
- **One internal tool, no login server, an allow rule in the app.** The [login gate](login-gate.md) signs in with Google directly and keeps no session server-side either.
- **The app has its own accounts and sign-in methods.** That is `auth.New` with [`plugin/oauth`](../plugins/oauth.md) for "Sign in with Google" beside the other methods.
- **The app is TypeScript (TanStack Start, Node, Bun, Deno, workers).** Use [`@ubgo/auth-client/oidc`](../../clients/ts/README.md#ubgoauth-clientoidc-server-side-sign-in-through-an-openid-connect-server), the server-side entry of the TypeScript client: the same model, seams and floors, as one options object.

## How it works

- **Session lifetime**: how long a browser stays signed in without seeing the login server, [7 days](ds:block?id=defaultidlelifetime-mjhkz59a) while in use and [30 days](ds:block?id=defaultabsolutelifetime-957evyy7) at most by default. The session is sealed (AES-256-GCM) into a cookie that has an expiry.
- **Re-check interval**: how long the login server's last "yes" stands, [1 minute](ds:block?id=defaultrecheckinterval-vekfr6zh) by default. On the first request after it, the app redeems the session's refresh token. The ubgo/auth login server asks its access rule again on every refresh, so a person taken off the list gets a "no", and the app ends the session on that request.
- **Outage grace**: when the login server cannot be reached (not a "no"), the last "yes" stands for [5 more minutes](ds:block?id=defaultoutagegrace-asgxt3qs), then requests are answered "unavailable" while the session is kept.

The two clocks are independent on purpose: a long session is convenience, the re-check is authority. The request lifecycle, as a sequence diagram, and the reason behind each option are in the package's [DESIGN.md](../../oidcclient/DESIGN.md).

## Before you start

- The example is [`examples/oidc-app`](../../examples/oidc-app/main.go). Its tests run the login server, a stand-in for Google and the app in-process.
- The module: `go get github.com/ubgo/auth/oidcclient`. It depends on the standard library only.
- A login server that grants refresh tokens. The ubgo/auth provider does when the client asks for `offline_access`, which `oidcclient` asks for [by default](ds:block?id=defaultscopes-9z5zg4vd). For Google, see the pitfalls below.
- An `https` address for the app. The session cookie is `Secure` and `__Host-` prefixed, and the ubgo/auth login server accepts only `https` redirect URIs for a web app. In development, put a TLS proxy in front of the app too.
- A session secret of at least 32 random bytes: `openssl rand -base64 32`. Keep it secret and the same on every instance.

## Step 1 — Register the app at the login server

The app's redirect URI is its public URL plus `/auth/callback`; the post-logout URI is where the browser lands after sign-out:

```sh
go run ./sso-server auth oauth-client create --name ops \
  --redirect-uri https://ops.example.com/auth/callback \
  --post-logout-uri https://ops.example.com/ \
  --skip-consent --end-session --secret-file ops.secret
```

Then write who may use it: add an `ops` entry to the login server's allow lists ([Step 1 of the SSO server guide](sso-server.md#step-1--write-down-who-may-use-each-app)). An app without a list lets nobody in.

## Step 2 — Configure the client

`oidcclient.Config` holds only the values with no safe default; everything else is an option. The example reads them from the environment, and the client secret from the file `create` wrote:

<!-- ds:block id=oidcapp-configfromenv-q7m3xk2p -->
**configFromEnv** · [`examples/oidc-app/main.go:65-83`](../../examples/oidc-app/main.go#L65-L83)

```go
func configFromEnv(getenv func(string) string, readFile func(string) ([]byte, error)) (oidcclient.Config, error) {
	secret, err := readFile(cmp.Or(getenv(envClientSecretFile), defaultSecretFile))
	if err != nil {
		return oidcclient.Config{}, fmt.Errorf("client secret: %w", err)
	}
	cfg := oidcclient.Config{
		Issuer:        getenv(envIssuer),
		ClientID:      getenv(envClientID),
		ClientSecret:  oidcclient.Secret(strings.TrimSpace(string(secret))),
		AppURL:        getenv(envAppURL),
		SessionSecret: oidcclient.Secret(getenv(envSessionSecret)),
	}
	for _, env := range []string{envIssuer, envClientID, envAppURL, envSessionSecret} {
		if getenv(env) == "" {
			return oidcclient.Config{}, fmt.Errorf("%w: %s", errMissingEnv, env)
		}
	}
	return cfg, nil
}
```
<!-- /ds:block hash=e8f97b -->

`oidcclient.New(cfg)` checks the configuration and every option at once and returns every mistake together. It makes no network call: the login server's discovery document is fetched on first use, so the app starts while the login server is down.

## Step 3 — Mount the routes and protect the app

`Client.Handler` serves `/auth/login`, `/auth/callback`, `/auth/logout` and `/auth/backchannel`. `Client.Require` wraps everything else:

<!-- ds:block id=oidcapp-newhandler-v4n8wd3k -->
**newHandler** · [`examples/oidc-app/main.go:90-99`](../../examples/oidc-app/main.go#L90-L99)

```go
func newHandler(c *oidcclient.Client) http.Handler {
	app := http.NewServeMux()
	app.HandleFunc("GET "+pathHome+"{$}", home)
	app.HandleFunc("GET "+pathMe, me)

	root := http.NewServeMux()
	root.Handle(oidcclient.DefaultRoutePrefix+"/", c.Handler())
	root.Handle(pathHome, c.Require(app))
	return root
}
```
<!-- /ds:block hash=0686f7 -->

On each request `Require` opens the cookie, applies the lifetimes, re-checks with the login server when the last "yes" is older than the interval, and only then calls the app. Two tabs whose sessions need a re-check at the same moment share one refresh in the process. A refused page is redirected to sign-in, with the path the person asked for as the place to come back to; a refused API call (no `Accept: text/html`) gets `401` with `{"error":"login_required","login_url":"…"}`.

For pages anyone may see that show more to a signed-in person, wrap them with `Client.Optional` instead: it makes the same decision and never refuses.

## Step 4 — Read the person

Behind `Require`, `oidcclient.UserFrom` returns the signed-in person:

<!-- ds:block id=oidcapp-home-c2t9pj5r -->
**home** · [`examples/oidc-app/main.go:117-123`](../../examples/oidc-app/main.go#L117-L123)

```go
func home(w http.ResponseWriter, r *http.Request) {
	u, _ := oidcclient.UserFrom(r.Context()) // always there behind Require
	logout := oidcclient.PathsUnder(oidcclient.DefaultRoutePrefix).Logout
	if err := homePage.Execute(w, homeView{Name: u.Name, Email: u.Email, Logout: logout}); err != nil {
		log.Printf("home: %v", err) // the browser hung up; nothing more to tell it
	}
}
```
<!-- /ds:block hash=19a8bd -->

`User.Subject` is the login server's stable id for the person: key your own rows by it, never by the address. `User.Email`, `EmailVerified` and `Name` come from the ID token, and `User.Claims` holds the rest. To link the person to your own user table, create them on first sign-in, or read roles from a claim, pass `oidcclient.WithUserMapper`; it runs at sign-in and again at each refresh that brings a new ID token, so a role removed at the login server is removed in the app too.

Sign-out is the form on that page: a `POST` to `/auth/logout` from the app's own origin (a link from another site cannot sign anyone out). It ends the app's session and sends the browser to the login server's end-session endpoint, which ends the session there too and comes back to the post-logout URI.

## Step 5 — Take someone out

Two steps, in this order:

1. Remove the person from the app's allow list at the login server (or change whatever your `ClientAccess` rule reads).
2. Revoke what they hold at that app: `go run ./sso-server auth oauth-client revoke-user ops sam@partner.io`, or `op.RevokeUserForClient(ctx, oauthprovider.RevokeUserRequest{ClientID: …, UserID: …})` from your own admin tooling.

Within one re-check interval every request of that person is answered "login required", whichever copy of the cookie it carries. The app sends a browser to the login server, which asks the rule again and shows its no-access page. Step 1 alone already stops the next refresh; the revoke also ends the access tokens the app holds and sends a back-channel logout to an app that registered one.

The order matters: a revoke without the rule change ends the session, but the login server still lets the person in, so their browser is signed straight back in.

Check: [`TestOIDCApp_RemovedUserIsRefusedWithinRecheck`](ds:block?id=testoidcapp-removeduserisrefusedwithinrecheck-h3w8qn5t&assert=true) saves a copy of Sam's cookie, removes him and revokes, sees the copy still let in until the minute is up (the stated bound) and refused after it, and follows his browser to the no-access page. [`TestOIDCApp_RevokeAloneSignsBackIn`](ds:block?id=testoidcapp-revokealonesignsbackin-m6r2xv9d&assert=true) shows the wrong order. [`TestOIDCApp_ClosingTheBrowserKeepsTheSession`](ds:block?id=testoidcapp-closingthebrowserkeepsthesession-p9k4tz2w&assert=true) restarts the browser with only the cookie and opens the app two days later; [`TestOIDCApp_AllowedUserStaysSignedIn`](ds:block?id=testoidcapp-alloweduserstayssignedin-f5j7wc3n&assert=true) re-checks three times in a row without a refusal.

## Change a default

Each policy is one option to `oidcclient.New`; the package's godoc is the reference.

| You want | Option |
|---|---|
| Removal to take effect faster, or fewer calls to the login server | `WithRecheckInterval(d)`; `RecheckEveryRequest` asks on every request |
| To fail closed the moment the login server is down, or a longer grace | `WithOutageGrace(d)`; `NoOutageGrace` refuses at once |
| Other session lifetimes | `WithLifetimes(oidcclient.Lifetimes{Idle: …, Absolute: …})` |
| Sessions on the server (Redis, SQL, your own), back-channel logout, big sessions | `WithSessionStore(store)`; `NewMemoryStore()` for one instance |
| A KMS-held key, or rotating the session secret | `WithSealer(sealer)`, or `Config.PreviousSessionSecrets` |
| Roles, tenants or per-route rules in the app | `WithAuthorizer(fn)`; it fails closed, and an error refuses |
| Re-check by introspection or userinfo instead of refresh | `WithRechecker(oidcclient.RecheckByIntrospection())`, `RecheckByUserInfo()`, `RecheckBackchannelOnly()` |
| Your own pages, a JSON shape for a SPA, translations | `WithResponder(r)`; delegate the rest to `DefaultResponder()` |
| A fixed landing page after sign-in | `WithReturnPolicy(oidcclient.ReturnToFixed("/dashboard"))` |
| A cookie shared with subdomains, or `SameSite=Strict` | `WithCookie(oidcclient.CookieOptions{Name: "__Secure-…", Domain: …})` |
| The routes under another prefix | `WithPaths(oidcclient.PathsUnder("/oidc"))` |
| Metrics or an audit log of logins, refreshes and refusals | `WithObserver(o)` |

PKCE, state, nonce, the ID token's signature and claims, the same-site return path and the cookie's `Secure`, `HttpOnly` and prefix have no option: there is nothing to turn off.

## Try it

```sh
cd examples
go test -v ./oidc-app
```

```text
--- PASS: TestOIDCApp_RemovedUserIsRefusedWithinRecheck (0.08s)
--- PASS: TestOIDCApp_RevokeAloneSignsBackIn (0.06s)
--- PASS: TestOIDCApp_ClosingTheBrowserKeepsTheSession (0.10s)
--- PASS: TestOIDCApp_AllowedUserStaysSignedIn (0.07s)
--- PASS: TestOIDCApp_ConfigFromEnv (0.00s)
PASS
ok  	github.com/ubgo/auth/examples/oidc-app	0.325s
```

To run it against a real login server, follow the [example's README](../../examples/oidc-app/README.md#run-it).

## Pitfalls

| Symptom or trap | Cause | Fix |
|---|---|---|
| Signed out at random when the app runs on several instances, or a browser app refreshes from several tabs | Two requests present the same refresh token. Within one process `oidcclient` shares one refresh and remembers its answer for a few seconds, but it cannot see other processes: there the second presentation looks like a stolen token, and a login server with strict rotation revokes the whole family | On the ubgo/auth login server set `oauthprovider.RefreshReuseInterval` to a few seconds (10 s is a good start); [its default, 0](ds:block?id=oauthprovider-refreshreuseinterval-y84nezrp), is strict. [`TestOAuthProvider_ConcurrentRefreshInsideReuseWindow`](ds:block?id=testoauthprovider-concurrentrefreshinsidewindow-k3v9pd2r&assert=true) and [`TestOAuthProvider_ConcurrentRefreshWithoutWindowRevokesFamily`](ds:block?id=testoauthprovider-concurrentrefreshnowindow-r8m2xq5w&assert=true) show both sides |
| Against Google directly, sign-in fails or the first re-check signs everyone out | Google does not grant refresh tokens through the `offline_access` scope; it gives one only for `access_type=offline`, and a session without one is refused at its first re-check | `WithScopes("openid", "email", "profile")` and `WithAuthParams(map[string]string{"access_type": "offline", "prompt": "consent"})`. Google's refresh only says the account and the grant still exist, so who may use the app is then your `WithAuthorizer` rule |
| A sign-in fails with "session too large" (`ErrSessionTooLarge`) | The cookie store keeps the whole session, tokens included, in at most three cookies; a login server with large tokens or many claims overflows them | Keep the session server-side with `WithSessionStore` (the cookie then carries only its id), or drop claims you do not need in `WithUserMapper` |
| Refreshes fail with "database is locked" on a SQLite login server | SQLite's default deferred transactions let two concurrent refreshes both read, then one fails its write | Open the login server's database with `_txlock=immediate` (and a `busy_timeout`), so the second transaction waits for the first |
| A removed person is let in again at once | The revoke ran but the access rule still lets them in, so "login required" sends them to a login server that signs them straight back in | Change the rule first, then revoke (Step 5) |
| A removed person still gets in for up to a minute | That is the re-check interval: until the last "yes" is that old the app does not ask | `WithRecheckInterval` shorter, or `RecheckEveryRequest` for an app where every request must ask |
| Everyone is refused with "unavailable" during a login server restart | The outage grace ([5 minutes](ds:block?id=defaultoutagegrace-asgxt3qs) from the last "yes") ran out | A longer `WithOutageGrace`, or accept the refusal: sessions are kept and work again the moment the server answers |
| `oidcclient.New` refuses the cookie name | A host-only cookie must start with `__Host-`, a `Domain` cookie with `__Secure-` | Rename it as the error says |
| Sign-out answers 403 | The logout came from another origin, or without `Origin` and `Sec-Fetch-Site` headers | Sign out with a form `POST` on the app's own pages |
| Back-channel logout answers 501 | The default cookie store cannot end a session it does not hold | A server-side store that implements `SessionRevoker`, such as `NewMemoryStore()` |

## Related

- [How an OIDC login works](../concepts/oidc-login-flow.md): every request of one sign-in, and [staying signed in and being removed](../concepts/oidc-login-flow.md#staying-signed-in-and-being-removed).
- [SSO login server](sso-server.md): the login server, its allow lists and client registration.
- [`examples/oidc-app`](../../examples/oidc-app/) and [`examples/sso-server`](../../examples/sso-server/).
- [`oidcclient` DESIGN.md](../../oidcclient/DESIGN.md): the request lifecycle, every seam and the floors.
- [OAuth provider](../plugins/oauthprovider.md): `RefreshReuseInterval`, token lifetimes and the revoke.
