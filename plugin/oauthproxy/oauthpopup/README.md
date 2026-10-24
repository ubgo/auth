# oauthpopup

Sign in with a provider in a popup and hand the new session to the page that opened it. It is for an app embedded on another site (an iframe in a customer's page) where the browser partitions or blocks third-party cookies: the popup is a first-party window on the auth origin, the sign-in completes there, and a completion page posts the session token to the opener, which sends it as `Authorization: Bearer` from then on.

It is a package of the `oauthproxy` module (both are opt-in browser-flow companions of `plugin/oauth` with no dependency of their own) and shares nothing with the proxy, so an app imports only the one it uses.

```go
pp := oauthpopup.New()
a, err := auth.New(auth.WithBaseURL("https://auth.example.com"), auth.WithSecret(secret),
	auth.WithTrustedOrigins("https://embed.customer.com"),
	auth.WithPlugins(oauth.New(oauth.WithProviders(oauth.Google(id, s))), pp))

mux.Handle("/auth/", authhttp.Handler(a, authhttp.Prefix("/auth")))
mux.Handle(oauthpopup.DefaultMount+"/", http.StripPrefix(oauthpopup.DefaultMount, pp.Handler()))
```

## Routes

| Route | What it does |
|---|---|
| `GET /auth/oauthpopup/start` | `provider`, `popupOrigin` (must be trusted, else 403), `popupNonce`, `callbackURL`, `newUserCallbackURL` (each must pass `TrustsReturnURL`), `scopes` (comma list), `requestSignUp=true`, `additionalData`; sets the sealed marker cookie `__Host-auth_popup` (10 minutes) and starts the oauth plugin's flow with the completion page as its return and error page |
| `GET /auth/oauthpopup/complete` | Opens and expires the marker, then renders a page that posts `{type: "ubgo-auth:oauth-popup", nonce, token, redirectTo, error}` to the opener at `popupOrigin` and closes |

The completion page hands out only a session created after the marker, so an existing session can never be fished out of the cookie, and only once, because the marker is expired on first use. Its script is fixed and pinned by hash (`ScriptCSPHash`) in `Content-Security-Policy: default-src 'none'; script-src 'sha256-…'; base-uri 'none'`; the per-request data sits in an inert JSON element, escaped by `encoding/json`. The answer is `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.

Error codes the page posts: `popup_sign_in_failed`, `invalid_callback_url`, `invalid_new_user_callback_url`, `provider_not_found`, or the oauth plugin's code (`oauth.provider_failed`, …) for a failure after the state check. A provider-side denial before the state check follows the oauth plugin's `ErrorURL` (or `auth.WithErrorURL`); point it at the completion page if popups are the only browser flow.

`RewriteCallback(next)` is an after hook on the callback: wrapping the handler that serves the oauth routes, it answers a popup sign-in's callback (marker cookie present, redirect to `<mount>/complete` on the same host) with the completion page instead of the redirect, built by `complete` from the request's cookies plus the ones the callback set, so the marker and new-session checks are unchanged. Anything else passes through; responses are buffered only while a marker cookie is present.

## The opener

```js
const nonce = crypto.randomUUID();
const popup = window.open(`https://auth.example.com/auth/oauthpopup/start?provider=google&popupOrigin=${encodeURIComponent(location.origin)}&popupNonce=${nonce}`, "signin", "width=500,height=600");
window.addEventListener("message", (e) => {
  if (e.origin !== "https://auth.example.com" || e.data?.type !== "ubgo-auth:oauth-popup" || e.data.nonce !== nonce) return;
  if (e.data.error) return showError(e.data.error);
  sessionStorage.setItem("auth", e.data.token); // send as Authorization: Bearer
});
```

The opener page must allow popups to keep their opener (`Cross-Origin-Opener-Policy: same-origin-allow-popups` or none), and the auth origin's callback must not send a COOP header that severs it.

## Security

The token is a bearer credential: any script on the opener's origin can read it, which is the purpose and the risk. Trust only the origins that embed you, and keep such sessions short (`auth.WithSessionPolicy`).
