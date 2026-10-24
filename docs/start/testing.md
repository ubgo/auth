# Test your app

You will have end-to-end tests of your own app's sign-in, pages and settings that run on a database in memory, read the mail and texts the library sent, move the clock, and need no server, no file and no sleeping. The harness is `github.com/ubgo/auth/authtest`, part of the core module.

## Before you start

- [Your first app](first-app.md): an app whose `auth.New` call takes its outside dependencies (the senders) as parameters, so the test can put recorders there.
- `go get modernc.org/sqlite` in your module: the harness opens SQLite by driver name and imports no driver itself.

## Step 1 — Build the app on the harness

Give the harness the app's own plugin list, built with its recorders in the senders' places. The plugin list is a function of the `Env` because the recorders belong to it:

<!-- ds:block id=apptests-plugins-5kq8wn3r -->
**plugins** · [`examples/app-tests/main.go:89-95`](../../examples/app-tests/main.go#L89-L95)

```go
func plugins(m email.Mailer, s phone.SMSSender) []auth.Plugin {
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
		phone.New(phone.Contact(), phone.WithSMS(s)),
	}
}
```
<!-- /ds:block hash=e6a2d7 -->

<!-- ds:block id=apptests-newenv-3wr7kq9m -->
**newEnv** · [`examples/app-tests/main_test.go:32-39`](../../examples/app-tests/main_test.go#L32-L39)

```go
func newEnv(t *testing.T) *authtest.Env {
	t.Helper()
	return authtest.New(t, authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin {
		ps := plugins(e.Mail, e.SMS)
		ps[1] = password.New(password.Argon2(fastArgon2))
		return ps
	}))
}
```
<!-- /ds:block hash=94ca7a -->

`authtest.New` opens SQLite in memory, wires the plugins over a frozen clock and a memory rate store, migrates, and closes everything when the test ends; a failure in any of that fails the test at once. The `Env` has `Auth`, `DB`, `Clock`, `Mail`, `SMS` and `BaseURL` ([`https://app.example.test`](ds:block?id=authtest-baseurl-7kq3wm2d)).

<!-- ds:block id=authtest-new-4bm7xq9s -->
**New** · [`authtest/authtest.go:159-195`](../../authtest/authtest.go#L159-L195)

```go
func New(t testing.TB, opts ...Option) *Env {
	t.Helper()
	s := settings{driver: SQLiteDriver, baseURL: BaseURL}
	for _, o := range opts {
		o(&s)
	}
	if err := s.optErrs.OptionErr(); err != nil {
		t.Fatalf("authtest.New: %v", err)
	}
	if s.plugins == nil {
		t.Fatal("authtest.New: WithPlugins is required; the library has no sign-in method of its own")
	}
	e := &Env{T: t, Clock: NewClock(), Mail: &Mailbox{}, SMS: &SMSBox{}, BaseURL: s.baseURL, Faults: s.faults}
	e.Mail.env, e.SMS.env = e, e
	if s.db != nil {
		e.DB, e.Dialect = s.db, s.dialect
	} else {
		e.DB, e.Dialect = openSQLite(t, s.driver, s.dsn, s.faults)
	}
	all := append([]auth.Option{
		auth.WithDB(e.DB, e.Dialect), auth.WithBaseURL(e.BaseURL), auth.WithClock(e.Clock.Now),
		// An explicit rate store on the test clock, so a window moves with
		// Advance and the one-process warning does not fire per test.
		auth.WithRateStore(auth.NewMemoryRateStore(e.Clock.Now)),
		auth.WithPlugins(s.plugins(e)...),
	}, s.opts...)
	a, err := auth.New(all...)
	if err != nil {
		t.Fatalf("authtest.New: auth.New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatalf("authtest.New: migrate: %v", err)
	}
	e.Auth = a
	return e
}
```
<!-- /ds:block hash=7b9c65 -->

Check: `go test ./...` passes with nothing installed and leaves no file behind. Two tests in one process are two databases.

## Step 2 — Drive the app over HTTPS

`e.Browser(handler)` serves your handler on a TLS test server with a cookie jar, sends the app's `Origin` on every `POST`, and does not follow redirects. A body with a password is a plain map: `password.Secret` encodes as `"[redacted]"` on purpose. Request types that carry a link or poll token (`auth.WireToken`) can be posted as they are.

<!-- ds:block id=apptests-flow-6px2vn4t -->
**TestSignUpVerifyAndProtectedPage** · [`examples/app-tests/main_test.go:46-72`](../../examples/app-tests/main_test.go#L46-L72)

```go
func TestSignUpVerifyAndProtectedPage(t *testing.T) {
	e := newEnv(t)
	b := e.Browser(newHandler(e.Auth))

	var up password.SignInResult
	b.Post("/auth/password/sign-up", map[string]string{"identifier": alice, "password": passcode, "name": "Alice"}).Expect(http.StatusOK).Decode(&up)
	if b.Cookie(authhttp.CookieName) == nil {
		t.Fatal("sign-up set no session cookie")
	}
	var me meResponse
	b.Get("/me").Expect(http.StatusOK).Decode(&me)
	if me.ID != up.User.ID || me.Name != "Alice" {
		t.Fatalf("/me = %+v", me)
	}

	tok := e.Mail.LastToken(alice)
	b.Post("/auth/email/verify", map[string]string{"token": tok.Reveal()}).Expect(http.StatusOK)

	b.Post("/auth/sign-out", nil).Expect(http.StatusOK)
	if code := b.Get("/me").Expect(http.StatusUnauthorized).ErrorCode(); code != auth.ErrSignedOut.Code {
		t.Fatalf("/me after sign-out: %q", code)
	}
	wrong := b.Post("/auth/password/sign-in", map[string]string{"identifier": alice, "password": "wrong"}).Expect(http.StatusUnauthorized)
	if wrong.ErrorCode() != password.ErrInvalidCredentials.Code {
		t.Fatalf("wrong password: %q", wrong.ErrorCode())
	}
}
```
<!-- /ds:block hash=ac9c47 -->

`Expect(status)` fails the test with the body when the status differs; `Decode(&v)` reads the answer into the library's result type; `ErrorCode()` is the code of an error answer, compared with the sentinel's `.Code` and never with a string you typed.

Check: a wrong password answers `401` with `password.invalid_credentials`, and a `POST` after `b.Origin = "https://evil.example"` answers `403`.

## Step 3 — Read what was sent

`e.Mail` records every mail the email plugin sends and `e.SMS` every text; both wait for the deliveries in flight, which go out after the transaction commits. `LastToken(addr)` pulls the token out of the newest link; `LastCode` the one-time code out of the newest message.

<!-- ds:block id=authtest-lastlink-2qm7xv9r -->
**Mailbox.LastLink** · [`authtest/capture.go:78-88`](../../authtest/capture.go#L78-L88)

```go
func (m *Mailbox) LastLink(addr string) *url.URL {
	m.env.T.Helper()
	list := m.To(addr)
	for i := len(list) - 1; i >= 0; i-- {
		if u := linkWithToken(list[i].Text); u != nil {
			return u
		}
	}
	m.env.T.Fatalf("authtest: no link mailed to %s (%d mails)", addr, len(list))
	return nil
}
```
<!-- /ds:block hash=23b93f -->

<!-- ds:block id=authtest-smslastcode-6yx2wq8h -->
**SMSBox.LastCode** · [`authtest/capture.go:176-186`](../../authtest/capture.go#L176-L186)

```go
func (s *SMSBox) LastCode(number string) string {
	s.env.T.Helper()
	list := s.To(number)
	for i := len(list) - 1; i >= 0; i-- {
		if c := codeIn(list[i]); c != "" {
			return c
		}
	}
	s.env.T.Fatalf("authtest: no code texted to %s (%d texts)", number, len(list))
	return ""
}
```
<!-- /ds:block hash=a6ae49 -->

Check: `e.Mail.Reset()` then one action, then `len(e.Mail.Sent()) == 1`.

## Step 4 — Fixtures, sessions and the clock

A test about a settings page should not start with a sign-up. `e.CreateUser` makes a user with verified identities through the real core API, `e.SignIn` makes a session, and the `Browser` takes it with `SetSession`. The clock expires things without sleeping:

<!-- ds:block id=apptests-fixtures-9hn4tw2k -->
**TestFixturesAndFreshSession** · [`examples/app-tests/main_test.go:80-100`](../../examples/app-tests/main_test.go#L80-L100)

```go
func TestFixturesAndFreshSession(t *testing.T) {
	e := newEnv(t)
	u := e.CreateUser("Ada", authtest.Identity{Kind: email.KindEmail, Value: alice})
	s := e.SignIn(u.ID)
	b := e.Browser(newHandler(e.Auth))
	b.SetSession(s)

	b.Post("/auth/phone/add", map[string]string{"phone": number}).Expect(http.StatusOK)
	code := e.SMS.LastCode(number)
	b.Post("/auth/phone/verify", map[string]string{"phone": number, "code": code}).Expect(http.StatusOK)

	// Removing the number needs a fresh sign-in; after the window it is
	// refused, and signing in again is the answer.
	e.Clock.Advance(auth.DefaultFreshWindow + time.Minute)
	stale := b.Post("/auth/phone/remove", map[string]string{"phone": number}).Expect(http.StatusForbidden)
	if stale.ErrorCode() != auth.ErrFreshSessionRequired.Code {
		t.Fatalf("stale session: %q", stale.ErrorCode())
	}
	b.SetSession(e.SignIn(u.ID))
	b.Post("/auth/phone/remove", map[string]string{"phone": number}).Expect(http.StatusOK)
}
```
<!-- /ds:block hash=cd50bb -->

<!-- ds:block id=authtest-session-9fn3qk7t -->
**Session** · [`authtest/session.go:17-23`](../../authtest/session.go#L17-L23)

```go
type Session struct {
	env *Env
	// Session is the row as the core created it.
	Session auth.Session
	// Token is the raw session token.
	Token auth.Token
}
```
<!-- /ds:block hash=3e1aae -->

Check: after `e.Clock.Advance(auth.DefaultFreshWindow + time.Minute)` a fresh-sign-in route answers `403 auth.fresh_session_required`; after `e.SignIn` again it answers `200`.

## Step 5 — The Go API as a signed-in user

A service, a job or a GraphQL resolver calls the library from Go with a request context. `s.Context(ctx)` is that context for the session, `s.BearerContext` the same as an app without cookies, and `e.Anonymous(ctx)` a signed-out browser; `auth.RequestEffects(ctx)` lists what the call asked the transport to do.

<!-- ds:block id=apptests-context-2zk7mp5q -->
**TestGoAPIWithASessionContext** · [`examples/app-tests/main_test.go:107-128`](../../examples/app-tests/main_test.go#L107-L128)

```go
func TestGoAPIWithASessionContext(t *testing.T) {
	e := newEnv(t)
	u := e.CreateUser("Ada", authtest.Identity{Kind: email.KindEmail, Value: alice})
	s := e.SignIn(u.ID)
	ctx := s.Context(context.Background())
	if res, err := e.Auth.Session(ctx); err != nil || res.User.ID != u.ID {
		t.Fatalf("Session: %+v %v", res, err)
	}
	if err := e.Auth.SignOut(ctx); err != nil {
		t.Fatal(err)
	}
	var cleared bool
	for _, ef := range auth.RequestEffects(ctx) {
		cleared = cleared || ef.Kind == auth.EffectClearSession
	}
	if !cleared {
		t.Fatal("sign-out must ask the transport to clear the cookie")
	}
	if _, err := e.Auth.Session(s.Context(context.Background())); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("after sign-out: %v, want ErrSignedOut", err)
	}
}
```
<!-- /ds:block hash=f80f82 -->

Check: after `e.Auth.SignOut(ctx)` the effects hold an `auth.EffectClearSession`, and the next call with the same token is `auth.signed_out`.

## Another database

`authtest.WithDB(db, dialect)` runs the same tests on a Postgres or MySQL your suite reset itself, so the engine rules (collation, timestamps) are covered too; `authtest.WithSQLite(driver, dsn)` uses another SQLite driver or a file.

## What can go wrong

- `authtest.New: open sqlite: sql: unknown driver "sqlite"` — the test file does not import the driver. Add `_ "modernc.org/sqlite"`.
- `WithPlugins is required` — the harness has no sign-in method of its own; pass the app's plugin list.
- A test passes alone and fails with the suite — two tests share a user name through a package-level `Env`. Build the `Env` inside each test.
- Password tests are slow — pass `password.Argon2(password.Argon2Params{Memory: 64, Time: 1, Threads: 1})` in the test's plugin list; the test checks behaviour, not cost.

## Next

- [Test a plugin](../extending/09-testing-plugins.md): fault injection and the session store contract suite, for a plugin of your own.
- [examples/app-tests](../../examples/app-tests): the program these snippets come from.
