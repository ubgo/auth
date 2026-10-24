# Desktop apps and CLIs: sign in through the system browser

You will have a desktop app, an Electron or Tauri shell, or a command-line tool that never shows a password form of its own: it opens your web app in the system browser, the person signs in there with whatever you offer (password, Google, a passkey, a magic link, a second factor), the browser hands a short-lived token back to the app on a loopback port or on the app's own URL scheme, and the app exchanges it for a bearer session that lives as long as you let it. When the browser cannot come back, the person pastes a code.

## Before you start

- [Mobile apps](mobile-apps.md) for bearer mode, which this guide builds on; [hand-off](../plugins/handoff.md) for the token itself.
- The example is [`examples/desktop-sign-in`](../../examples/desktop-sign-in/): `go run ./desktop-sign-in` is the web app on `localhost:8081`, `go run ./desktop-sign-in -app` the desktop app on a loopback port the OS picks; `go test ./desktop-sign-in` drives both.
- No extra module: the hand-off plugin is in the core module.

## Step 1 — Trust the app's return addresses and close the mint

The app needs two things from the web app: a page that hands a signed-in session over, and permission to be sent to. Both are configuration:

<!-- ds:block id=desktop-newauth-4w7mk2qr -->
**newAuth** · [`examples/desktop-sign-in/main.go:133-147`](../../examples/desktop-sign-in/main.go#L133-L147)

```go
func newAuth(db *sql.DB, m email.Mailer, trusted ...string) (*auth.Auth, *handoff.Plugin, error) {
	hp := handoff.New(handoff.ServerOnly())
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithTrustedOrigins(trusted...),
		auth.WithLoopbackReturn(),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			hp,
		),
	)
	return a, hp, err
}
```
<!-- /ds:block hash=e4a773 -->

[`auth.WithLoopbackReturn()`](ds:block?id=opt-withloopbackreturn-6tn4wq8k) makes `http://127.0.0.1:<any port>/…` and `http://[::1]:<any port>/…` acceptable return addresses, because the app binds an ephemeral port it cannot know in advance (RFC 8252 section 7.3). It changes return-URL validation only: a loopback origin is never trusted for cookie-authenticated mutations, since a page served from any local port could then make credentialed requests, which is the CSRF the origin check exists to refuse; `localhost` by name is never accepted, and only `http`. `auth.WithTrustedOrigins("myapp://")` trusts every URL in the app's own scheme. `handoff.ServerOnly()` closes the plugin's `generate` route to clients: only the web app's own page, after its own checks, mints a token.

Check: `POST /auth/handoff/generate` from a signed-in browser answers 404 `auth.unknown_operation`, and a cookie-authenticated POST with `Origin: http://127.0.0.1:53241` is still refused with `auth.origin_not_trusted`.

## Step 2 — The open-in-app page

The app opens `https://your-app/open-in-app?returnTo=http://127.0.0.1:<port>/callback` in the browser. If the person is not signed in, your usual sign-in page takes over and comes back here; `authhttp.RequireUser` enforces it. The page then confirms with one button and, on the button's POST, mints the token and redirects:

<!-- ds:block id=desktop-openinapp-8n3xv5tp -->
**openInApp** · [`examples/desktop-sign-in/main.go:173-196`](../../examples/desktop-sign-in/main.go#L173-L196)

```go
func openInApp(a *auth.Auth, hp *handoff.Plugin) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		returnTo, challenge := r.FormValue(returnToParam), r.FormValue(challengeParam)
		if returnTo != "" && !a.TrustsReturnURL(returnTo) {
			http.Error(w, "the return address is not trusted", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method != http.MethodPost {
			_ = confirmTemplate.Execute(w, confirmData{ReturnTo: returnTo, Challenge: challenge, User: authhttp.MustUser(r)}) // a client that hung up cannot be told
			return
		}
		res, err := hp.GenerateWith(r.Context(), handoff.GenerateRequest{Challenge: challenge})
		if err != nil {
			authhttp.WriteError(w, err)
			return
		}
		if returnTo == "" {
			_ = pasteTemplate.Execute(w, res) // a client that hung up cannot be told
			return
		}
		http.Redirect(w, r, withToken(returnTo, res.Token), http.StatusFound)
	})
}
```
<!-- /ds:block hash=6cf9cb -->

Three decisions in that handler:

- **`a.TrustsReturnURL` first.** It is the same rule every `returnTo` in the library goes through: a relative path, a trusted origin, or a trusted scheme; `//evil.example` and `https://evil.example` are refused. A token minted for an attacker's address would be a session for the attacker, so the check runs before anything is minted, on the GET and on the POST.
- **The mint is a POST.** A browser sends no `Origin` on a navigation, so a GET could not pass the origin check that protects every cookie-authenticated mutation, and `hp.Generate` runs through the pipeline like the route would. It also means a link in a mail cannot hand a session off: a click does.
- **No `returnTo` shows the token.** The person types it into the app, the fallback for a browser that will not open a loopback address or a scheme (a locked-down kiosk, a remote desktop).

```sh
curl -s -i -b cookies.txt -X POST -H 'Origin: http://localhost:8081' \
  -d 'returnTo=http%3A%2F%2F127.0.0.1%3A53241%2Fcallback' localhost:8081/open-in-app
```

```text
HTTP/1.1 302 Found
Location: http://127.0.0.1:53241/callback?token=9OsDfF24MIreUqcQNGliyGJaBU1WxDL-qFkJiAxCYDA
```

Check: with `returnTo=https://evil.example/cb` the GET answers 400 `the return address is not trusted` and no token exists.

## Step 3 — The app: listen, open, wait

The app side is fifty lines: listen on the loopback interface, make a verifier, open the browser with the page URL, the callback as `returnTo` and the verifier's challenge, wait for the browser to hit the callback, close the listener, then exchange with the verifier:

<!-- ds:block id=desktop-runapp-2c6zq8wd -->
**runApp** · [`examples/desktop-sign-in/app.go:45-83`](../../examples/desktop-sign-in/app.go#L45-L83)

```go
func runApp(ctx context.Context, out io.Writer, hc *http.Client, server, loopback string, wait time.Duration, open browserOpener) error {
	ln, err := net.Listen("tcp", loopback)
	if err != nil {
		return err
	}
	callback := "http://" + ln.Addr().String() + callbackPath
	tokens := make(chan string, 1)
	srv := &http.Server{Handler: callbackHandler(tokens), ReadHeaderTimeout: readHeaderTimeout}
	go func() { _ = srv.Serve(ln) }() // ends with Shutdown below
	// The token has arrived or the wait is over: close the listener now, not
	// when Serve gets round to it, so the port is free for the next run.
	defer func() { _ = srv.Shutdown(context.Background()); _ = ln.Close() }()

	verifier, challenge, err := handoff.NewVerifier()
	if err != nil {
		return err
	}
	if err := open(server + openInAppPath + "?" + url.Values{returnToParam: {callback}, challengeParam: {challenge}}.Encode()); err != nil {
		return err
	}
	var token string
	select {
	case token = <-tokens:
	case <-time.After(wait):
		return errTimeout
	case <-ctx.Done():
		return ctx.Err()
	}
	bearer, user, err := exchange(ctx, hc, server, token, verifier)
	if err != nil {
		return err
	}
	var me meResponse
	if err := call(ctx, hc, server+"/me", bearer, &me); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "signed in as %s (%s), /me answered %s with credential %q\n", user.User.ID, user.User.Name, me.ID, me.Credential)
	return err
}
```
<!-- /ds:block hash=124886 -->

The verifier is the app's PKCE (RFC 7636): [`handoff.NewVerifier`](ds:block?id=handoff-newverifier-6w4jt8kn) draws [32](ds:block?id=handoff-verifierbytes-8q2mt5rw) random bytes, keeps them in the process as the verifier, and sends only their SHA-256 (the challenge, method [`S256`](ds:block?id=handoff-challengemethod-4k7xp2nm)) to the page, which passes it to `hp.GenerateWith`. A token minted with a challenge is exchanged only together with the verifier, so a token that reached a different program, one registered for the same URL scheme, say, cannot be exchanged by it, and a refused attempt leaves the token unspent for the real app. The loopback return has no such second listener, but one flow for both return paths is simpler than two, and RFC 8252 section 8.1 asks every native app to do it.

Two rules for that listener. It binds to the loopback interface only (`127.0.0.1:0` or `[::1]:0`, never `:0`): a listener on every interface would take the token from anyone on the network. And it closes as soon as the callback has arrived or the wait has run out: a person who walked away should not leave a port open, and the next run picks a fresh one. The callback handler answers a page ("you can close this tab") and passes the token on; the first token wins, a refresh changes nothing.

Check: `go run ./desktop-sign-in -app` prints the URL, and the signed-in browser's click ends with `signed in as usr_… credential "bearer"` in the app's terminal.

## Step 4 — Exchange the token for a bearer session

The exchange is one `POST /auth/handoff/verify` with the token and the verifier, `Auth-Token-Mode: bearer` and no cookie, no `Origin`: the app is not a browser. The new session arrives in `Set-Auth-Token`, and every later request carries `Authorization: Bearer`:

<!-- ds:block id=desktop-exchange-6h9rp3fk -->
**exchange** · [`examples/desktop-sign-in/app.go:111-145`](../../examples/desktop-sign-in/app.go#L111-L145)

```go
func exchange(ctx context.Context, hc *http.Client, server, token, verifier string) (string, handoff.VerifyResult, error) {
	// The request body is a plain struct: auth.Token redacts itself when
	// marshalled, which is right for a server and wrong for the client.
	body, err := json.Marshal(struct {
		Token    string `json:"token"`
		Verifier string `json:"verifier,omitempty"`
	}{token, verifier})
	if err != nil {
		return "", handoff.VerifyResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+authPrefix+"/handoff/verify", bytes.NewReader(body))
	if err != nil {
		return "", handoff.VerifyResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(authhttp.TokenModeHeader, authhttp.TokenModeBearer)
	res, err := hc.Do(req)
	if err != nil {
		return "", handoff.VerifyResult{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		return "", handoff.VerifyResult{}, fmt.Errorf("exchange: %s: %s", res.Status, raw)
	}
	var out handoff.VerifyResult
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return "", handoff.VerifyResult{}, err
	}
	bearer := res.Header.Get(authhttp.SetTokenHeader)
	if bearer == "" {
		return "", handoff.VerifyResult{}, errors.New("exchange: no " + authhttp.SetTokenHeader + " in the answer")
	}
	return bearer, out, nil
}
```
<!-- /ds:block hash=52330e -->

The token works once and for three minutes; a second exchange, or one without the verifier, answers `auth.token_invalid`. The session is the app's own (the web session is untouched, and signing out of either leaves the other), it is a full session even for a user with a second factor, because the web session already passed it, and it gets the lifetime your `auth.WithSessionPolicy` gives bearer clients ([mobile apps](mobile-apps.md), step 4). Keep the token in the OS credential store (Keychain, Credential Manager, libsecret), never in a plain file.

Check: `curl localhost:8081/me -H 'Authorization: Bearer <Set-Auth-Token>'` answers `"credential":"bearer"`.

## Step 5 — Loopback, scheme or paste: which return path

| Return path | How | When |
|---|---|---|
| Loopback (`http://127.0.0.1:<port>/callback`, `http://[::1]:<port>/callback`) | The app listens on an ephemeral loopback port; the browser is redirected to it (RFC 8252 section 7.3) | Desktop apps and CLIs. The port is answered by the process that holds it, so the token reaches your app and nothing else. `auth.WithLoopbackReturn()` accepts any port; the app binds the loopback interface only and closes after the callback |
| The app's URL scheme (`myapp://signed-in`) | The OS routes the URL to the app registered for the scheme | Electron and Tauri shells that registered one. Any program on the machine can register the same scheme, so the OS decides who receives the URL: the challenge the app sent makes the token useless to anyone without the verifier, so a caught link signs nobody in. Prefer loopback where you can, and on mobile use universal links or app links, which the OS verifies against your domain |
| Paste | The page shows the token; the person types it | A browser that will not open either, a remote session, a headless machine next to a phone. The app sent no challenge for a token it did not ask for, so it exchanges a pasted token without a verifier |

Whichever path, the browser flow itself is your web app's: Google sign-in, passkeys, magic links and the second factor all happen on the web pages before the open-in-app page is reached, so the app needs no code for any of them. For a provider that offers a native SDK the [oauth plugin's ID-token sign-in](../plugins/oauth.md) is the alternative with no browser at all.

## Options you may want

| Need | Do |
|---|---|
| A longer or shorter window for the browser to come back | `handoff.WithTTL(d)`; three minutes is the default, and the app's own wait should be about the same |
| Mint from your own handler without `ServerOnly` | Leave the option off: the route is then open to any signed-in client, which is right when the app hands off from its own web view |
| The app should know which request a callback answers | Put your own parameter on `returnTo` (`?req=7`); `withToken` keeps the query and adds `token` |
| Sign the app out everywhere | The web app's session list (`GET /auth/sessions`) shows the app's session; `POST /auth/sessions/revoke` ends it, and the app's next request is 401 |

## What can go wrong

| You see | Why | Fix |
|---|---|---|
| `the return address is not trusted` | `auth.WithLoopbackReturn()` is not set, the callback says `localhost` or `https`, or the scheme is not in `auth.WithTrustedOrigins` | Set the option and use the literal `127.0.0.1` or `[::1]` over `http`; a scheme is listed as `myapp://` |
| 403 `auth.origin_not_trusted` on the POST | The POST came without `Origin` (a navigation, a script on another site) | Use the page's form; a browser's form POST carries `Origin` |
| 404 `auth.unknown_operation` on `/auth/handoff/generate` | `ServerOnly` is on | Intended: mint through the page, or drop the option |
| `exchange: 400 … auth.token_invalid` | The token was used, expired, or the web session signed out before the exchange; or the verifier does not match the challenge the page sent (another program's token, or a challenge lost on the way to the POST) | Start again from the app; carry `challenge` through the confirmation form as the example does |
| `handoff.challenge_invalid` on the page's POST | The challenge reached the page damaged (not 43 base64url characters) | Encode the SHA-256 base64url without padding; `handoff.ChallengeOf` does |
| The browser shows the callback page but the app says `no sign-in arrived in time` | The browser reached a different process on that port (a stale listener from an earlier run) | Bind `127.0.0.1:0` so the OS picks a free port, and close the listener when the run ends |
| The callback page never loads | A firewall or the browser blocks loopback; or the app is on another machine | Fall back to paste |

## Next

- [Hand-off](../plugins/handoff.md) for the plugin's own reference and the security notes behind the token.
- [Mobile apps](mobile-apps.md) for bearer lifetimes and the session cache header, which apply to the desktop app's session too.
- [OAuth](../plugins/oauth.md) for ID-token sign-in when a native SDK is available.
