# Test a plugin

You will have tests for a plugin written outside this repository that run against a real database in-process, drive the app over HTTP, control the clock, and prove that every database failure is reported.

## Before you start

- Testing an app rather than a plugin? [Test your app](../start/testing.md) does Steps 1 to 4 of this page in one call with `github.com/ubgo/auth/authtest`; this page shows the pieces by hand because a plugin's tests also need the fault-injecting driver and the store contract suite below.

- A plugin and an app that wires it, built like [examples/plugin-delivery](../../examples/plugin-delivery) or [examples/custom-plugin](../../examples/custom-plugin): the app's `main` calls a `newAuth(...)` function that takes its outside dependencies (the database, the mailer, the clock) as parameters. That one function is what makes the app testable, because the test builds the same `*auth.Auth` with fakes in those places.
- `go get modernc.org/sqlite`: a pure-Go SQLite driver, so the tests need no server and no cgo. The library is also tested on Postgres and MySQL, and the values your plugin stores behave the same on all three because they are normalized in Go and compared byte for byte.

## Step 1 — A fresh SQLite database per test

Open a file in `t.TempDir()`, not `:memory:`, so the connection pool may hold several connections the way a deployment does. The pragmas are the ones the library needs: WAL and a busy timeout. No foreign-key pragma: the library creates no foreign keys.

<!-- ds:block id=opendb-pcxjbzur -->
**openDB** · [`examples/plugin-delivery/main_test.go:212-220`](../../examples/plugin-delivery/main_test.go#L212-L220)

```go
func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
```
<!-- /ds:block hash=181f26 -->

Then build the app through its own `newAuth`, with recorders in place of the senders, and migrate:

<!-- ds:block id=newtestauth-aysyu5qt -->
**newTestAuth** · [`examples/plugin-delivery/main_test.go:194-207`](../../examples/plugin-delivery/main_test.go#L194-L207)

```go
func newTestAuth(t *testing.T, clock *clock) (*auth.Auth, *botbox, *mailbox) {
	t.Helper()
	db := openDB(t)
	box, bot := &mailbox{}, &botbox{}
	a, err := newAuth(db, box, bot, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, bot, box
}
```
<!-- /ds:block hash=d4b766 -->

Check: `go test ./...` runs with nothing installed and leaves no file behind.

## Step 2 — Record what the plugin sends

A `Mailer`, an `SMSSender`, or your own `Sender` is an interface the app implements; the test implements it with a type that records. Delivery runs after the transaction commits, in the background, so before reading the recorder call `a.WaitDeliveries()`, which blocks until every send in flight finished.

<!-- ds:block id=botbox-tt9mpjx6 -->
**botbox** · [`examples/plugin-delivery/main_test.go:277-280`](../../examples/plugin-delivery/main_test.go#L277-L280)

```go
type botbox struct {
	mu   sync.Mutex
	sent map[string][]string
}
```
<!-- /ds:block hash=17c7b2 -->

<!-- ds:block id=botbox-last-e7m6hgct -->
**botbox.last** · [`examples/plugin-delivery/main_test.go:297-307`](../../examples/plugin-delivery/main_test.go#L297-L307)

```go
func (b *botbox) last(t *testing.T, a *auth.Auth, handle string) string {
	t.Helper()
	a.WaitDeliveries()
	b.mu.Lock()
	defer b.mu.Unlock()
	list := b.sent[handle]
	if len(list) == 0 {
		t.Fatalf("no chat message sent to @%s", handle)
	}
	return list[len(list)-1]
}
```
<!-- /ds:block hash=27fa90 -->

For mail, the same shape with a method that finds the token in the mailed link, from [examples/quickstart](../../examples/quickstart):

<!-- ds:block id=mailbox-lasttoken-wm6rku45 -->
**mailbox.lastToken** · [`examples/quickstart/main_test.go:117-134`](../../examples/quickstart/main_test.go#L117-L134)

```go
func (m *mailbox) lastToken(t *testing.T, a *auth.Auth, addr string) string {
	t.Helper()
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To != addr {
			continue
		}
		for _, field := range strings.Fields(m.sent[i].Text) {
			if u, err := url.Parse(field); err == nil && u.Query().Get("token") != "" {
				return u.Query().Get("token")
			}
		}
	}
	t.Fatalf("no link mailed to %s", addr)
	return ""
}
```
<!-- /ds:block hash=cebace -->

Check: a test that reads the recorder without `WaitDeliveries` is flaky, not wrong; if yours passes sometimes, that is the cause.

## Step 3 — Drive the app over HTTPS

An end-to-end test serves the app's real handler on `httptest.NewTLSServer`, with a cookie jar, and sends the `Origin` header a page of the app would. Two details are forced by the library's security rules. The session cookie is `__Host-` and `Secure`, and a cookie jar keeps such a cookie only for an `https` URL, so the test server must be TLS. Every cookie-authenticated `POST` must carry a trusted `Origin`, or it is refused with `403 auth.origin_not_trusted` before anything runs.

<!-- ds:block id=browser-3e7u6w6w -->
**browser** · [`examples/quickstart/main_test.go:140-144`](../../examples/quickstart/main_test.go#L140-L144)

```go
type browser struct {
	srv    *httptest.Server
	client *http.Client
	origin string
}
```
<!-- /ds:block hash=600f1b -->

<!-- ds:block id=newbrowser-6ygtmdm5 -->
**newBrowser** · [`examples/quickstart/main_test.go:150-161`](../../examples/quickstart/main_test.go#L150-L161)

```go
func newBrowser(t *testing.T, h http.Handler) *browser {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.Jar = jar
	return &browser{srv: srv, client: client, origin: baseURL}
}
```
<!-- /ds:block hash=3e9df5 -->

Request bodies that carry a password are plain maps, not the library's request types, because `password.Secret` (an `auth.Token`) encodes as `"[redacted]"` on purpose, so a logged struct never leaks a password; marshalling `password.SignUpRequest` would send the text `[redacted]` as the password. Request types that carry a link or poll token use `auth.WireToken`, which encodes as its value, so those can be posted as they are.

<!-- ds:block id=fields-jh5rwvqb -->
**fields** · [`examples/quickstart/main_test.go:168`](../../examples/quickstart/main_test.go#L168-L168)

```go
type fields map[string]string
```
<!-- /ds:block hash=0f310c -->

<!-- ds:block id=post-tzjd9day -->
**post** · [`examples/quickstart/main_test.go:183-196`](../../examples/quickstart/main_test.go#L183-L196)

```go
func post[Out, In any](t *testing.T, b *browser, path string, in In, status int) Out {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, b.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", b.origin)
	return do[Out](t, b, req, status)
}
```
<!-- /ds:block hash=eb8305 -->

Check: decode answers into the library's own result types (`password.SignInResult`, `email.VerifyResult`, `auth.Done`) and into one `errorAnswer` struct with an `auth.ErrorInfo` field for failures; compare `Error.Code` with the exported error's `.Code`, never with a string you typed.

## Step 4 — Control the clock

Codes, links and sessions expire. `auth.WithClock` replaces the library's clock, so a test moves time instead of sleeping. The app's `newAuth` takes the clock as a parameter and `main` passes `time.Now`. Two rules the clock type follows: it starts at the real time, because the HTTP client judges cookie expiries against the real clock and would drop every cookie from a clock in the past; and it rounds to microseconds, which is what Postgres and MySQL store, so a value read back equals the value written.

<!-- ds:block id=clock-32ewvc3p -->
**clock** · [`examples/plugin-delivery/main_test.go:226-229`](../../examples/plugin-delivery/main_test.go#L226-L229)

```go
type clock struct {
	mu sync.Mutex
	t  time.Time
}
```
<!-- /ds:block hash=bcdda4 -->

<!-- ds:block id=newclock-edpvz5ty -->
**newClock** · [`examples/plugin-delivery/main_test.go:236`](../../examples/plugin-delivery/main_test.go#L236-L236)

```go
func newClock() *clock { return &clock{t: time.Now().UTC().Truncate(time.Microsecond)} }
```
<!-- /ds:block hash=4acc1b -->

<!-- ds:block id=clock-advance-hu7nzsv3 -->
**clock.Advance** · [`examples/plugin-delivery/main_test.go:248-252`](../../examples/plugin-delivery/main_test.go#L248-L252)

```go
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d).Truncate(time.Microsecond)
	c.mu.Unlock()
}
```
<!-- /ds:block hash=04af15 -->

The test that uses it:

<!-- ds:block id=testchat-codeexpires-sjmqyfy9 -->
**TestChat_CodeExpires** · [`examples/plugin-delivery/main_test.go:74-90`](../../examples/plugin-delivery/main_test.go#L74-L90)

```go
func TestChat_CodeExpires(t *testing.T) {
	clock := newClock()
	a, bot, _ := newTestAuth(t, clock)
	b := newBrowser(t, newHandler(a))
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)
	post[auth.Done](t, b, "/auth/chat/add", fields{"handle": testHandle}, http.StatusOK)
	code := bot.lastCode(t, a, storedHandle)

	clock.Advance(chat.DefaultCodeTTL + time.Second)
	late := post[errorAnswer](t, b, "/auth/chat/verify", fields{"handle": testHandle, "code": code}, http.StatusBadRequest)
	if late.Error.Code != auth.ErrCodeInvalid.Code {
		t.Fatalf("expired code = %+v", late.Error)
	}
	if idn := identityOf(t, a, testEmail, chat.KindChat); idn.Verified() {
		t.Fatal("an expired code verified the handle")
	}
}
```
<!-- /ds:block hash=69d13a -->

Check: assert the state after the refusal, not only the refusal; here, that the handle is still unverified.

## Step 5 — Prove the start-up refusals

Everything a plugin's `Validate` refuses, and everything `auth.New` refuses about a kind, a column or an operation, is a wiring error that must fail before the server listens. Test it with `errors.Is` against the exported sentinel:

<!-- ds:block id=testchat-newrefusesapluginwithoutasender-6feusx2u -->
**TestChat_NewRefusesAPluginWithoutASender** · [`examples/plugin-delivery/main_test.go:113-123`](../../examples/plugin-delivery/main_test.go#L113-L123)

```go
func TestChat_NewRefusesAPluginWithoutASender(t *testing.T) {
	db := openDB(t)
	_, err := auth.New(
		auth.WithDB(db, dialect),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.WithMailer(discard{})), password.New(), chat.New(nil, chat.Recover())),
	)
	if !errors.Is(err, chat.ErrNoSender) {
		t.Fatalf("auth.New = %v, want %v", err, chat.ErrNoSender)
	}
}
```
<!-- /ds:block hash=7d423a -->

Check: the test fails when you delete the `Validate` method, and passes again when you put it back. A guard never seen to fail proves nothing.

## Step 6 — Prove every database failure is reported

An operation that swallows a database error reports success for work that did not happen: a handle that was never stored, a code that was never issued. The honest way to reach those branches is to make a real database fail at one exact call, and to do that for every call the operation makes. `authtest.SweepFaults` does this: build each fresh `Env` with `authtest.WithFaults(authtest.NewFaults())`, return it with `e.Faults`, and the sweep fails the test at every call whose failure the operation swallowed (the library's own integration suite runs on it). The example carries its own copy of the driver in `faults_test.go`, shown below, to show the parts.

A `database/sql/driver` connector wraps the SQLite driver and counts calls; armed, the call numbered `at` fails:

<!-- ds:block id=faults-mcqs6jyk -->
**faults** · [`examples/plugin-delivery/faults_test.go:37-42`](../../examples/plugin-delivery/faults_test.go#L37-L42)

```go
type faults struct {
	mu    sync.Mutex
	armed bool
	n, at int
	hit   bool
}
```
<!-- /ds:block hash=c18904 -->

<!-- ds:block id=faults-step-8m4cqp4s -->
**faults.step** · [`examples/plugin-delivery/faults_test.go:59-71`](../../examples/plugin-delivery/faults_test.go#L59-L71)

```go
func (f *faults) step() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.armed {
		return nil
	}
	f.n++
	if f.n == f.at {
		f.hit = true
		return errFault
	}
	return nil
}
```
<!-- /ds:block hash=d1f218 -->

Every method of the connection steps the counter first. `ExecContext` is one of them; `QueryContext`, `PrepareContext`, `BeginTx` and the transaction's `Commit` do the same:

<!-- ds:block id=faultconn-execcontext-8ffryhwv -->
**faultConn.ExecContext** · [`examples/plugin-delivery/faults_test.go:111-116`](../../examples/plugin-delivery/faults_test.go#L111-L116)

```go
func (c *faultConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.f.step(); err != nil {
		return nil, err
	}
	return inner[driver.ExecerContext](c.Conn).ExecContext(ctx, q, args)
}
```
<!-- /ds:block hash=036ca5 -->

The sweep runs the operation once per database call, each time on a fresh database with a different call failing, until a run finishes without reaching the armed call:

<!-- ds:block id=sweepfaults-xx3u9wd8 -->
**sweepFaults** · [`examples/plugin-delivery/faults_test.go:179-201`](../../examples/plugin-delivery/faults_test.go#L179-L201)

```go
func sweepFaults(t *testing.T, setup func(t *testing.T, db *sql.DB) func(ctx context.Context) error) {
	t.Helper()
	for k := 1; k <= maxFaultSteps; k++ {
		db, f := openFaultDB(t)
		op := setup(t, db)
		f.arm(k)
		err := op(context.Background())
		if !f.disarm() {
			if err != nil {
				t.Fatalf("run with no fault reached (step %d) failed: %v", k, err)
			}
			if k == 1 {
				t.Fatal("the operation made no database call; the sweep proves nothing")
			}
			t.Logf("swept %d database calls", k-1)
			return
		}
		if err == nil {
			t.Errorf("fault at database call %d was swallowed: the operation returned no error", k)
		}
	}
	t.Fatalf("no run finished within %d database calls", maxFaultSteps)
}
```
<!-- /ds:block hash=b91b7f -->

And a test hands it the operation, built on the faulting database through the app's own `newAuth`:

<!-- ds:block id=testchat-addsurfaceseverydatabasefailure-nrsqf3wx -->
**TestChat_AddSurfacesEveryDatabaseFailure** · [`examples/plugin-delivery/main_test.go:131-156`](../../examples/plugin-delivery/main_test.go#L131-L156)

```go
func TestChat_AddSurfacesEveryDatabaseFailure(t *testing.T) {
	sweepFaults(t, func(t *testing.T, db *sql.DB) func(context.Context) error {
		bot := &botbox{}
		a, err := newAuth(db, discard{}, bot, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = a.Close() })
		if _, err := a.Migrate(context.Background()); err != nil {
			t.Fatal(err)
		}
		pw, err := auth.PluginOf[*password.Plugin](a)
		if err != nil {
			t.Fatal(err)
		}
		ch, err := auth.PluginOf[*chat.Plugin](a)
		if err != nil {
			t.Fatal(err)
		}
		up, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: testEmail, Password: testPassword})
		if err != nil {
			t.Fatal(err)
		}
		return func(context.Context) error { return ch.Add(signedIn(a, up.Token), testHandle) }
	})
}
```
<!-- /ds:block hash=875787 -->

Check: the log line `swept N database calls` says how many calls the operation makes; a swallowed failure is reported as `fault at database call N was swallowed`. Run it with `-v` once to see N; when N changes without a reason you know, a query was added or lost.

## Step 7 — A session store runs the contract suite

If your plugin or app provides an `auth.SessionStore` ([extend sessions](08-extend-sessions.md)), one call checks it against every rule a store must keep: ordering, another user's id matching nothing, `Touch` only moving an expiry forward, concurrent refreshes, `Sweep`, expired sessions not found. `github.com/ubgo/auth/sessiontest` imports only the standard library and the core, so it is importable from any module.

<!-- ds:block id=testcustomstore-sa7nqfq3 -->
**TestCustomStore** · [`examples/session-strategies/main_test.go:173-177`](../../examples/session-strategies/main_test.go#L173-L177)

```go
func TestCustomStore(t *testing.T) {
	sessiontest.Run(t, func(*testing.T) auth.SessionStore {
		return newLoggingStore(auth.NewMemorySessionStore(), nil)
	})
}
```
<!-- /ds:block hash=a31c74 -->

Check: `open` is called once per case, so a store backed by a shared server must return a store on a fresh key prefix or a cleared keyspace each time.

## Step 8 — An OAuth provider runs the conformance kit

A plugin or app that brings its own sign-in provider (an `oauth.Provider` for a service the OAuth plugin has no constructor for, or an adapter over another OAuth library) proves it the same way: [`oauthtest.Run`](ds:block?id=oauthtest-run-h4kw9qzt) starts a fake authorization server, builds the provider against it once per case, and checks the authorization URL, the profile mapping (subject, email, the verified flag exactly as the server reported it) and that every provider failure is an error. Like `sessiontest`, it imports only the standard library and the core.

<!-- ds:block id=testconformance-oauth2userinfo-z75vqp6t -->
**TestConformance_OAuth2UserInfo** · [`plugin/oauth/oauthtest/providers_test.go:76-81`](../../plugin/oauth/oauthtest/providers_test.go#L76-L81)

```go
func TestConformance_OAuth2UserInfo(t *testing.T) {
	oauthtest.Run(t, func(u string) oauth.Provider {
		return pointAt(&oauth.OAuth2{ID: "corp", ClientID: oauthtest.ClientID, ClientSecret: oauthtest.ClientSecret, Scopes: []string{"openid", "email"},
			FetchProfile: oauth.UserInfoProfile(u+oauthtest.UserInfoPath, "")}, u)
	}, oauthtest.WantScopes("openid", "email"))
}
```
<!-- /ds:block hash=7b7d83 -->

Check: a provider that cannot send a PKCE challenge says so with `oauthtest.NoPKCE()`, and the run then fails if a challenge ever appears, so the declaration cannot go stale; a provider whose API says nothing about verification declares `oauthtest.NeverVerified()` and must never claim a verified address. The [oauthtest README](../../plugin/oauth/oauthtest/README.md) lists every case.

## What the repository checks for you

A plugin added to this repository is covered by two safety nets in `integration/`, with no test written for it, as soon as it is wired into them. Both run under `task check` on SQLite, and the wire contract also runs on Postgres and MySQL under `task test:engines`.

- **The wire contract** (`TestWireContract`, `integration/wirecontract_test.go`) wires every built-in plugin, reads `a.Operations()`, builds each operation's input from its Go type (the zero value with ids from earlier answers, then a plausible value per field kind) and sends it through `authhttp.Handler`: a JSON body for a POST, a query string with every number and bool for a GET. It fails when a request a typed client may send is refused before its input is decoded (`400 auth.bad_request` with no decoded input), when an operation in the list is not routed, when any answer is a 500, and when any JSON answer carries `"[redacted]"` (an `auth.Token` in a response; use `auth.WireToken`). Scripted flows in `wirecontract_flows_test.go` drive the operations that need a mailed token, a code or a pending session, and the test logs which operations no call drove to success. A new plugin joins by being added to the `plugins` list there; a new operation of an existing plugin is probed with no edit.
- **The config edge test** (`TestConfigEdge`, `integration/configedge_test.go`) finds every exported option constructor in the source (a function returning a func type named `…Option`), calls it with the edge values of each parameter (nil, 0, -1, `""`, an empty slice, no variadic argument, a config struct with one field set), applies it to a minimal valid instance and requires that `auth.New` either refuses with an error naming the option or serves a sign-up, a sign-in and a session read without a panic and without a session that dies within a minute. A new option fails the test until its line is in `configedge_registry_test.go`; the failure prints the line. A new option type needs a builder in `edgeBuilders`.

Write the refusal so it names the option: `auth: password: MinLength must be 0 or more, and MaxLength at least 1` passes; `every lifetime is positive` does not. Refusals that predate the test and describe the setting in other words are pinned in `edgeUnnamedRefusals`; that list only shrinks.

## What can go wrong

| Symptom | Cause |
|---|---|
| `403 {"error":{"code":"auth.origin_not_trusted","message":"This request came from a site that is not trusted."}}` on every POST | The request carried the session cookie and no `Origin`, or an `Origin` other than the base URL. Set `Origin` to the app's base URL on every POST. |
| The cookie is set but the next request is signed out | The test server is plain `http`; the `Secure` cookie was dropped by the jar. Use `httptest.NewTLSServer`. |
| Sign-up answers `400 auth.bad_request` or sign-in fails with the right password | The body was built from a library request type; its password (`password.Secret`) encoded as `[redacted]`. Send a map. |
| The recorder is empty right after the request | Delivery is asynchronous. Call `a.WaitDeliveries()` first. |
| Every cookie is treated as expired | The test clock started in the past. Start it at `time.Now()`. |
| `auth: operation called before auth.New registered its plugin` | A plugin method such as `Add` was called on a plugin that was not in `auth.WithPlugins`, or before `auth.New` returned. |
| The sweep says `the operation made no database call; the sweep proves nothing` | The operation was refused before it reached the database (a requirement, a rate limit, a validation error). Fix the setup so the operation runs. |

## Next

- [Ship a plugin](10-ship-a-plugin.md): the module layout and the dependency rule your tests then guard.
- The examples' tests are all built this way: [examples/plugin-delivery](../../examples/plugin-delivery/main_test.go), [examples/custom-plugin](../../examples/custom-plugin/main_test.go), [examples/session-strategies](../../examples/session-strategies/main_test.go).
