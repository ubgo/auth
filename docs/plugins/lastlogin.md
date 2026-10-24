# Last sign-in method

You will know how each user last signed in — a password, a provider, a magic link, a code, a passkey — and when. A sign-in page can put that method in front ("Continue with Google, as last time"), and a product can see which methods its users actually use.

Use this plugin when you offer more than one way in. It is two columns on `auth_user`, written by a data hook on session creation, which every sign-in method ends with; a method you add later is recorded without knowing this plugin exists.

## Before you start

- An app with two or more sign-in methods wired, as in [your first app](../start/first-app.md) plus [magic links](magiclink.md).
- The example program this guide is built from, with a `main_test.go` that drives the same steps and a `README.md` with the same transcript: [`examples/last-login`](../../examples/last-login/).
- The reference for every option and column is the package's [README](../../plugin/lastlogin/README.md).

## Step 1 — Wire the plugin

The example wires email, passwords, magic links and the record. The plugin value is kept, because `/me` reads through it:

<!-- ds:block id=newauth-8r5kw2nx -->
**newAuth** · [`examples/last-login/main.go:91-104`](../../examples/last-login/main.go#L91-L104)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, *lastlogin.Plugin, error) {
	ll := lastlogin.New()
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			magiclink.New(),
			ll,
		),
	)
	return a, ll, err
}
```
<!-- /ds:block hash=2298c3 -->

`a.Migrate` adds [`last_login_method`](ds:block?id=colmethod-7q2nv8kx) and `last_login_at` to `auth_user` with everything else. There is no route: the hint belongs to your own pages.

Check: `go run ./last-login` prints `listening on http://localhost:8081`.

## Step 2 — Sign in two ways and read the record

The method is the name of the plugin whose operation created the session, and the time is the session's creation time:

<!-- ds:block id=me-4w7nx2kt -->
**me** · [`examples/last-login/main.go:127-138`](../../examples/last-login/main.go#L127-L138)

```go
func me(ll *lastlogin.Plugin) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := authhttp.MustUser(r)
		last, err := ll.Of(r.Context(), u.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, LastMethod: last.LastLoginMethod, LastAt: last.LastLoginAt}) // a client that hung up cannot be told
	}
}
```
<!-- /ds:block hash=bcb37f -->

<!-- ds:block id=meresponse-6k3tv9qp -->
**meResponse** · [`examples/last-login/main.go:117-121`](../../examples/last-login/main.go#L117-L121)

```go
type meResponse struct {
	ID         string     `json:"id"`
	LastMethod string     `json:"lastMethod"`
	LastAt     *time.Time `json:"lastAt"`
}
```
<!-- /ds:block hash=2e6cec -->

```sh
O='Origin: http://localhost:8081'
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"user":{"id":"usr_rfnko74ozlcywipmvo6yuwhp","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_rfnko74ozlcywipmvo6yuwhp","lastMethod":"password","lastAt":"2026-10-02T16:20:43.480739Z"}
```

A magic link goes only to a verified address, so the verify link from the mail is opened first; after the link signs in, the record says so, with the later time:

```sh
curl -s -X POST localhost:8081/auth/email/verify -H "$O" -d '{"token":"8xgMm1FomRJPGRgAfB4mTygngcgiP0ILojVAJD48GDk"}'
curl -s -X POST localhost:8081/auth/magiclink/send -H "$O" -d '{"identifier":"alice@example.com"}'
curl -s -c cookies.txt -X POST localhost:8081/auth/magiclink/sign-in -H "$O" -d '{"token":"wYAhueFCQDkDcHvlIyFoXSu0iHaWdLtiu2bKV0tDn0U"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"email":"alice@example.com"}
{"ok":true}
{"user":{"id":"usr_rfnko74ozlcywipmvo6yuwhp","name":"","image":""},"created":false,"secondFactorRequired":false}
{"id":"usr_rfnko74ozlcywipmvo6yuwhp","lastMethod":"magiclink","lastAt":"2026-10-02T16:20:45.562417Z"}
```

From Go:

<!-- ds:block id=plugin-of-5t8wn3qr -->
**Plugin.Of** · [`plugin/lastlogin/lastlogin.go:357-366`](../../plugin/lastlogin/lastlogin.go#L357-L366)

```go
func (p *Plugin) Of(ctx context.Context, userID string) (LastLoginColumns, error) {
	if p.core == nil {
		return LastLoginColumns{}, auth.ErrOperationNotWired
	}
	var c LastLoginColumns
	if err := p.core.LoadUserColumns(ctx, userID, Bindings(&c)...); err != nil {
		return LastLoginColumns{}, err
	}
	return c, nil
}
```
<!-- /ds:block hash=1023a0 -->

Check: a session made from Go outside any operation (`a.CreateSession`) records nothing, since there is no operation to name; an admin's impersonation records nothing either. A sign-in that ends in a pending second-factor session records its method, and the second step does not overwrite it.

## Options you may want

| Option | Use it when |
|---|---|
| `lastlogin.WithResolver(fn)` | You want the provider ("google") rather than the plugin ("oauth"), or you want some operations (a hand-off exchange, say) to leave the record alone by answering `""`. |
| `lastlogin.WithCookie("", 0)` | Your sign-in page is shown before anyone is signed in and should still put "you last used Google" first. Each sign-in sets `__Host-auth_last_used_login_method` for 30 days; the page reads it server-side with `auth.RequestCookie`, or a script calls `GET /auth/lastlogin/method`, and `POST /auth/lastlogin/clear` forgets it. The cookie is HttpOnly like every cookie the library sets, which is why a script reads it through the route rather than `document.cookie`. Add `lastlogin.WithCookieConsent(fn)` to set it only after the visitor agreed to your cookie banner. |

<!-- ds:block id=resolver-3m9xk2wt -->
**Resolver** · [`plugin/lastlogin/lastlogin.go:64`](../../plugin/lastlogin/lastlogin.go#L64-L64)

```go
type Resolver func(ctx context.Context, op auth.OpInfo, s auth.Session) string
```
<!-- /ds:block hash=65e60e -->

## From TypeScript

By default the plugin adds no route: the method lives in two columns your own `/me` (Step 2) reads, so a frontend gets it from your route, not from the [typed client](../client/README.md). With `lastlogin.WithCookie`, the plugin serves `GET /auth/lastlogin/method` (`{ method }`, from the cookie, before anyone is signed in) and `POST /auth/lastlogin/clear`. The prebuilt `client.ts` has no `lastlogin` factory, because it was generated without that option; generate the client from your app with [`auth client ts`](../client/custom-plugins.md) and `client.lastlogin.method()` and `client.lastlogin.clear()` appear, typed. A sign-in page calls `method()` to put "you last used Google" first, and `clear()` on "not you?". The cookie is HttpOnly, which is why a script reads it through the route rather than `document.cookie`.

## What can go wrong

| Problem | When | Fix |
|---|---|---|
| The record is empty | The user signed in before the plugin was wired, or only through `a.CreateSession` from Go. | Expected; it fills at the next sign-in through an operation. |
| The method reads `handoff` after an app sign-in | The hand-off exchange is an operation and created a session. | Resolve `handoff.EndpointVerify` to `""` with `WithResolver`. |
| A visitor sees which method an address uses | Your sign-in page showed the record before any session existed. | Read it only after sign-in, or use `WithCookie`, which tells only this browser how it last signed in, behind `WithCookieConsent` if your banner asks. |

## Next

- [Hooks](../extending/03-hooks.md): the data hook mechanism this plugin is built on, and `auth.OperationOf` for a hook of your own.
- The package [README](../../plugin/lastlogin/README.md) is the full reference; the Go reference is on [pkg.go.dev](https://pkg.go.dev/github.com/ubgo/auth/plugin/lastlogin).
