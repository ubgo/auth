# Sign in from an embedded app with a popup

You will let an app that runs inside another site's iframe sign its users in with a provider, even when the browser blocks or partitions third-party cookies. The sign-in runs in a first-party popup on your auth origin, and the popup hands the new session token to the embedded page, which sends it as a bearer token. This is better-auth's `oauth-popup` plugin.

## Before you start

- The [oauth plugin](oauth.md) wired, and `auth.WithSecret` set: the popup's marker cookie is sealed with a key derived from it.
- The module: `go get github.com/ubgo/auth/plugin/oauthproxy` (the package is `oauthproxy/oauthpopup`).
- The reference is the package's [README](../../plugin/oauthproxy/oauthpopup/README.md).
- The runnable program is [`examples/oauth-popup`](../../examples/oauth-popup/): the auth app on `:8081` and a stand-in for the customer's page on `:8082`. Its tests drive the whole popup against a fake OpenID Connect provider.

## Step 1 — Mount the handler and trust the embedding origin

<!-- ds:block id=oauthpopup-example-newauth-f7q2wd9k -->
**newAuth** · [`examples/oauth-popup/main.go:86-96`](../../examples/oauth-popup/main.go#L86-L96)

```go
func newAuth(db *sql.DB, provider oauth.Provider, secret []byte, embedders ...string) (*auth.Auth, *oauthpopup.Plugin, error) {
	pp := oauthpopup.New()
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret),
		auth.WithTrustedOrigins(embedders...),
		auth.WithPlugins(oauth.New(oauth.WithProviders(provider)), pp),
	)
	return a, pp, err
}
```
<!-- /ds:block hash=1e6a5d -->

<!-- ds:block id=oauthpopup-example-newhandler-k3m8zr5v -->
**newHandler** · [`examples/oauth-popup/main.go:104-110`](../../examples/oauth-popup/main.go#L104-L110)

```go
func newHandler(a *auth.Auth, pp *oauthpopup.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", pp.RewriteCallback(authhttp.Handler(a, authhttp.Prefix(authPrefix))))
	mux.Handle(oauthpopup.DefaultMount+"/", http.StripPrefix(oauthpopup.DefaultMount, pp.Handler()))
	mux.Handle("GET /api/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}
```
<!-- /ds:block hash=d201c7 -->

The plugin's own handler:

<!-- ds:block id=oauthpopup-handler-6k9wm3qt -->
**Plugin.Handler** · [`plugin/oauthproxy/oauthpopup/oauthpopup.go:171-187`](../../plugin/oauthproxy/oauthpopup/oauthpopup.go#L171-L187)

```go
func (p *Plugin) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		switch strings.TrimSuffix(r.URL.Path, "/") {
		case "/start":
			p.start(w, r)
		case "/complete":
			p.complete(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}
```
<!-- /ds:block hash=9ad2e7 -->

## Step 2 — Open the popup and listen

The embedded page opens `/auth/oauthpopup/start` with the provider, its own origin and a nonce, and waits for a message of type [`ubgo-auth:oauth-popup`](ds:block?id=oauthpopup-messagetype-3w8kq5nv) from the auth origin carrying that nonce:

<!-- ds:block id=oauthpopup-example-openerpage-n2x7cv4h -->
**openerPage** · [`examples/oauth-popup/main.go:130-150`](../../examples/oauth-popup/main.go#L130-L150)

```go
var openerPage = template.Must(template.New("opener").Parse(`<!doctype html>
<meta charset="utf-8">
<title>Embedded app</title>
<button id="go">Sign in</button>
<pre id="out"></pre>
<script>
const authOrigin = {{.AuthOrigin}};
document.getElementById("go").onclick = () => {
  const nonce = crypto.randomUUID();
  const start = new URL("/auth/oauthpopup/start", authOrigin);
  start.search = new URLSearchParams({provider: {{.Provider}}, popupOrigin: location.origin, popupNonce: nonce});
  window.open(start, "signin", "width=500,height=600");
  window.addEventListener("message", async (e) => {
    if (e.origin !== authOrigin || e.data?.type !== {{.MessageType}} || e.data.nonce !== nonce) return;
    if (e.data.error) { document.getElementById("out").textContent = e.data.error; return; }
    const res = await fetch(new URL("/api/me", authOrigin), {headers: {Authorization: "Bearer " + e.data.token}});
    document.getElementById("out").textContent = await res.text();
  });
};
</script>
`))
```
<!-- /ds:block hash=eddbef -->

A Go page can build the start link with `oauthpopup.StartURL(base, provider, popupOrigin, nonce)`.

The start refuses an opener origin you do not trust (403). The popup has [10 minutes](ds:block?id=oauthpopup-markerttl-5q2xn7wk) to finish.

## Step 3 — What the completion page does

After the provider sign-in, the oauth callback lands on the completion page, which posts `{type, nonce, token, redirectTo, error}` to the opener at the trusted origin and closes. It hands out only a session created after the popup started, and only once, so no page can use it to read an existing session. Its one script is pinned by hash in the Content-Security-Policy:

<!-- ds:block id=oauthpopup-scriptcsphash-8n4vq2xm -->
**ScriptCSPHash** · [`plugin/oauthproxy/oauthpopup/oauthpopup.go:94-97`](../../plugin/oauthproxy/oauthpopup/oauthpopup.go#L94-L97)

```go
var ScriptCSPHash = func() string {
	h := sha256.Sum256([]byte(completionScript))
	return "'sha256-" + base64.StdEncoding.EncodeToString(h[:]) + "'"
}()
```
<!-- /ds:block hash=83e605 -->

### Opt-in: answer the callback with the page

better-auth rewrites the provider callback's redirect into the completion page. [`pp.RewriteCallback(handler)`](ds:block?id=oauthpopup-rewritecallback-p3r2vk6n) does the same when it wraps the handler serving the oauth routes:

```go
mux.Handle("/auth/", pp.RewriteCallback(authhttp.Handler(a, authhttp.Prefix("/auth"))))
```

While a popup marker is present, a callback that would redirect to `/auth/oauthpopup/complete` answers with the completion page itself, built by the same code from the cookies the callback just set: one request fewer, the same checks (the marker is spent, only a session created after it is handed out). Every other response passes through unchanged. Without it the redirect reaches `/complete` with the same result, so it is a convenience, not a security setting.

Check: `TestPopup_HandsTheNewSessionToTheOpener` in the example: the callback answers with the completion page (through `RewriteCallback`), the posted token is the session the callback issued and works as a bearer token on the API, and a second load of `/complete` posts `popup_sign_in_failed`; `TestPopup_RefusesAnUntrustedOpener` gets the 403.

## Try it

The flow needs a real provider and a browser to watch, so the example's tests are the transcript, run against a fake OpenID Connect issuer on `httptest`:

```sh
cd examples && go test -v ./oauth-popup
```

```text
=== RUN   TestPopup_HandsTheNewSessionToTheOpener
--- PASS: TestPopup_HandsTheNewSessionToTheOpener (0.03s)
=== RUN   TestPopup_RefusesAnUntrustedOpener
--- PASS: TestPopup_RefusesAnUntrustedOpener (0.01s)
=== RUN   TestPopup_OpenerPageNamesTheAuthOrigin
--- PASS: TestPopup_OpenerPageNamesTheAuthOrigin (0.00s)
PASS
ok  	github.com/ubgo/auth/examples/oauth-popup	0.696s
```

## From TypeScript

The [typed client](../client/README.md) has the opener built in: `oauthPopup()` adds `client.oauthPopup.signIn`, which opens `start` in a popup, accepts the message only from the auth origin, from that window, with its type and a fresh nonce, keeps the token in the client's `TokenStore` and reads the session back ([Plugins › Hand-written plugins](../client/plugins.md#hand-written-plugins-popup-sign-in-and-the-last-login-hint)). The embedded page calls it from a click:

<!-- ds:block id=tsp-oauthpopup-open-6wk3qn8x -->
**signInWithPopup** · [`clients/ts/examples/plugin-popup.ts:25-37`](../../clients/ts/examples/plugin-popup.ts#L25-L37)

```typescript
export async function signInWithPopup(auth: ReturnType<typeof clientFor>, provider: string): Promise<string> {
  const { data, error } = await auth.oauthPopup.signIn({ provider, timeoutMs: 120_000 });
  if (data) return `Signed in as ${data.session.user.name}`;
  switch (error.code) {
    case "popup.blocked":
      return "Allow popups for this site, then try again.";
    case "popup.closed":
    case "popup.timeout":
      return "The sign-in window closed before you finished.";
    default:
      return `Sign-in failed (${error.rawCode || error.code}).`;
  }
}
```
<!-- /ds:block hash=3f1291 -->

The client is in bearer mode on the auth origin, so no third-party cookie is involved:

<!-- ds:block id=tsp-oauthpopup-client-2mq8wk5x -->
**clientFor** · [`clients/ts/examples/plugin-popup.ts:12-19`](../../clients/ts/examples/plugin-popup.ts#L12-L19)

```typescript
export function clientFor(authOrigin: string) {
  return createAuthClient({
    baseURL: `${authOrigin}/auth`,
    tokenMode: "bearer",
    tokenStore: keyValueTokenStore(localStorage),
    plugins: [password(), oauthPopup()],
  });
}
```
<!-- /ds:block hash=297801 -->

The error codes are a closed union: the client's own (`popup.blocked`, `popup.closed`, `popup.timeout`, `popup.busy`, `popup.unavailable`) and the strings the page posts, in [What can go wrong](#what-can-go-wrong) (`popup_sign_in_failed`, `provider_not_found`, `invalid_callback_url`, an `oauth.…` code). After that, calls through the client resolve to `{ data, error }` as usual.

Try it: `examples/oauth-popup` runs the auth app and a stand-in embedding page, and its tests drive the whole popup (Step 3 has the commands); the blocks above are type-checked by `task ts:check`, and `node clients/ts/test/runtime.ts` checks every gate and failure of `signIn` against a fake window.

Pitfalls:

- **Every call from the embedded page is cross-origin.** The auth app must answer CORS for the embedding origin, allowing the `Authorization` and `Auth-Token-Mode` request headers and exposing `Set-Auth-Token`, or the browser hides the answers; the library sends no CORS headers itself ([Bearer and mobile › Step 4](../client/bearer-and-mobile.md#step-4--a-frontend-on-another-site)).
- **A hand-written opener must check `e.origin`, the source window and the nonce before reading the token**, as `oauthPopup()` does: any window can post a message to the page.
- **Open the popup from a click handler.** Browsers block `window.open` that does not follow a user gesture.
- **Where the token sits is the store's choice.** `keyValueTokenStore(localStorage)` keeps the user signed in across reloads and makes the token readable by any script on the embedding origin; `memoryTokenStore()` keeps it out of storage, so a reload signs the user out.

## What can go wrong

| Message `error` | When | Fix |
|---|---|---|
| `popup_sign_in_failed` | The marker cookie is missing or old (the popup took too long, or the page was reloaded), or no new session exists. | Start again. |
| `invalid_callback_url`, `invalid_new_user_callback_url` | A `callbackURL` or `newUserCallbackURL` is not on a trusted origin. | Trust it, or pass a path. |
| `provider_not_found` | The provider is not configured. | Check the name. |
| `oauth.…` | The sign-in failed after the state check (the exchange, a sign-up rule). | As for the oauth plugin. |

A denial at the provider, before the state check, follows the oauth plugin's `ErrorURL` (or `auth.WithErrorURL`); point it at `/auth/oauthpopup/complete` if popups are your only browser flow, or the popup shows that page instead of posting.

The token is a bearer credential readable by any script on the embedding origin: trust only the origins that embed you, and keep those sessions short.

## Next

- [Sessions](../concepts/sessions.md): bearer tokens and their lifetime.
- [Preview deployments](oauthproxy.md): the other companion in this module.
