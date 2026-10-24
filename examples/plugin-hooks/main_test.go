package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/examples/plugin-hooks/guard"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
)

const (
	aliceEmail   = "alice@example.com"
	testPassword = "correct horse battery staple"
	testPIN      = "2468"
)

// guardOf returns the wired plugin, to read its counters and pause it.
func guardOf(t *testing.T, a *auth.Auth) *guard.Plugin {
	t.Helper()
	g, err := auth.PluginOf[*guard.Plugin](a)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// TestGuard_DataHookVetoesTheSignUp: a blocked domain is refused inside the
// sign-up's transaction, with the plugin's code, and no user row remains.
func TestGuard_DataHookVetoesTheSignUp(t *testing.T) {
	a := newTestAuth(t)
	b := newBrowser(t, newHandler(a))
	e := post[errorAnswer](t, b, "/auth/password/sign-up", fields{"identifier": "eve@" + blockedDomains[0], "password": testPassword}, http.StatusBadRequest)
	if e.Error.Code != guard.ErrDomainBlocked.Code {
		t.Fatalf("sign-up from a blocked domain: %+v, want %s", e.Error, guard.ErrDomainBlocked.Code)
	}
	var users int64
	if err := a.One(context.Background(), a.Select().Columns(sqlb.Bind(sqlb.Count(), &users)).From(auth.TableUser)); err != nil {
		t.Fatal(err)
	}
	if users != 0 {
		t.Fatalf("%d users after a vetoed sign-up, want 0: the veto rolls the user back", users)
	}
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
}

// TestGuard_OperationHooksCountAndPause: AfterTx counts every attempt, a
// wrong password included; AfterCommit counts only sign-ins that committed;
// a paused plugin refuses before the password is even checked.
func TestGuard_OperationHooksCountAndPause(t *testing.T) {
	a := newTestAuth(t)
	g := guardOf(t, a)
	b := newBrowser(t, newHandler(a))
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)

	post[errorAnswer](t, b, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": "wrong"}, http.StatusUnauthorized)
	post[password.SignInResult](t, b, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	if g.Attempts() != 2 || g.SignedIn() != 1 {
		t.Fatalf("attempts %d, signed in %d; want 2 and 1", g.Attempts(), g.SignedIn())
	}

	g.Pause()
	e := post[errorAnswer](t, newBrowser(t, newHandler(a)), "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusServiceUnavailable)
	if e.Error.Code != guard.ErrSignInsPaused.Code {
		t.Fatalf("paused: %+v, want %s", e.Error, guard.ErrSignInsPaused.Code)
	}
	g.Resume()
	if g.Attempts() != 3 {
		t.Fatalf("attempts %d after a refused call, want 3: AfterTx runs for a refusal too", g.Attempts())
	}
}

// TestGuard_PINIsASecondFactor: with a PIN set, sign-in gives a pending
// session that signs nobody in until verify promotes it.
func TestGuard_PINIsASecondFactor(t *testing.T) {
	a := newTestAuth(t)
	b := newBrowser(t, newHandler(a))
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	if e := post[errorAnswer](t, b, "/auth/guard/set-pin", fields{"pin": "12ab"}, http.StatusBadRequest); e.Error.Code != guard.ErrPINInvalid.Code {
		t.Fatalf("bad PIN: %+v, want %s", e.Error, guard.ErrPINInvalid.Code)
	}
	post[auth.Done](t, b, "/auth/guard/set-pin", fields{"pin": testPIN}, http.StatusOK) // the sign-up is seconds old: fresh
	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)

	in := post[password.SignInResult](t, b, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	if !in.SecondFactorRequired {
		t.Fatal("a user with a PIN must get a pending session")
	}
	get[errorAnswer](t, b, "/me", http.StatusUnauthorized) // pending signs nobody in
	if e := post[errorAnswer](t, b, "/auth/guard/verify", fields{"pin": "0000"}, http.StatusBadRequest); e.Error.Code != guard.ErrPINWrong.Code {
		t.Fatalf("wrong PIN: %+v, want %s", e.Error, guard.ErrPINWrong.Code)
	}
	post[auth.Done](t, b, "/auth/guard/verify", fields{"pin": testPIN}, http.StatusOK)
	get[auth.UserView](t, b, "/me", http.StatusOK)
	// The pending session is gone; verify has nothing to promote now.
	post[errorAnswer](t, b, "/auth/guard/verify", fields{"pin": testPIN}, http.StatusUnauthorized)
}

// TestGuard_SessionConditionStopsASuspendedUser: suspending sets a column,
// and the condition in the session lookup refuses the next lookup. The app
// caches sessions for a minute, so the device that suspended still passes
// until it signs out (which drops its cache entry) or the entry expires; a
// new sign-in is refused on its first request.
func TestGuard_SessionConditionStopsASuspendedUser(t *testing.T) {
	a := newTestAuth(t)
	b := newBrowser(t, newHandler(a))
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	get[auth.UserView](t, b, "/me", http.StatusOK)
	post[auth.Done](t, b, "/auth/guard/suspend", none{}, http.StatusOK)
	get[auth.UserView](t, b, "/me", http.StatusOK) // served from the cache, for up to cacheTTL
	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)
	post[password.SignInResult](t, b, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	get[errorAnswer](t, b, "/me", http.StatusUnauthorized)
}

// TestGuard_CustomCacheCountsWhatItSaves: the first request after a sign-in
// misses and is looked up; the next ones hit and cost no lookup.
func TestGuard_CustomCacheCountsWhatItSaves(t *testing.T) {
	a, cache := newTestAuthAndCache(t)
	b := newBrowser(t, newHandler(a))
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	for range 3 {
		get[auth.UserView](t, b, "/me", http.StatusOK)
	}
	if hits, misses := cache.hits.Load(), cache.misses.Load(); hits != 2 || misses != 1 {
		t.Fatalf("hits %d, misses %d; want 2 and 1", hits, misses)
	}
}

// TestGuard_PolicyGivesOneFactorSessionsADay: without a PIN a session lives
// a day; with one it gets the browser's week.
func TestGuard_PolicyGivesOneFactorSessionsADay(t *testing.T) {
	a := newTestAuth(t)
	b := newBrowser(t, newHandler(a))
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	ctx := context.Background()
	idn, err := a.FindIdentity(ctx, email.KindEmail, aliceEmail, false)
	if err != nil {
		t.Fatal(err)
	}
	day := int64(guard.OneFactorLifetime.Idle / time.Second)
	if list, err := a.Sessions(ctx, idn.UserID); err != nil || len(list) != 1 || list[0].IdleSeconds != day {
		t.Fatalf("one-factor session = %+v, %v; want an idle timeout of a day", list, err)
	}
	post[auth.Done](t, b, "/auth/guard/set-pin", fields{"pin": testPIN}, http.StatusOK)
	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)
	post[password.SignInResult](t, b, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	post[auth.Done](t, b, "/auth/guard/verify", fields{"pin": testPIN}, http.StatusOK)
	week := int64(guard.WebLifetime.Idle / time.Second)
	if list, err := a.Sessions(ctx, idn.UserID); err != nil || len(list) != 1 || list[0].IdleSeconds != week {
		t.Fatalf("two-factor session = %+v, %v; want the browser's week", list, err)
	}
}

// TestGuard_NeedsThePluginsItHooks: without the password plugin the hook
// would never run, so auth.New refuses the list.
func TestGuard_NeedsThePluginsItHooks(t *testing.T) {
	_, err := auth.New(
		auth.WithDB(openTestDB(t), sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(discard)), email.SignInWithCode()), guard.New()),
	)
	if !errors.Is(err, auth.ErrMissingDependency) || !strings.Contains(err.Error(), `"password"`) {
		t.Fatalf("auth.New = %v, want ErrMissingDependency naming password", err)
	}
	t.Logf("auth.New: %v", err)
}

// discard drops mail, for a test that never sends any.
func discard(context.Context, email.Mail) error { return nil }

// openTestDB opens a fresh SQLite file for one test.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newTestAuth builds the app's Auth on a fresh SQLite file and migrates it.
func newTestAuth(t *testing.T) *auth.Auth {
	t.Helper()
	a, _ := newTestAuthAndCache(t)
	return a
}

// newTestAuthAndCache is newTestAuth that also returns the app's cache.
func newTestAuthAndCache(t *testing.T) (*auth.Auth, *countingCache) {
	t.Helper()
	a, cache, err := newAuth(openTestDB(t), email.MailerFunc(discard))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, cache
}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would, like a real browser on the app.
type browser struct {
	srv    *httptest.Server
	client *http.Client
	origin string
}

// newBrowser serves h over TLS, because the session cookie is __Host- and
// Secure, and a cookie jar keeps such a cookie only for an https URL.
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

// fields is a JSON request body as a client writes it.
type fields map[string]string

// none is the answer of a call whose body the test does not read.
type none struct{}

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// post sends in as JSON with the browser's Origin, checks the status and
// decodes the answer as Out.
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

// get fetches path, checks the status and decodes the answer as Out.
func get[Out any](t *testing.T, b *browser, path string, status int) Out {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return do[Out](t, b, req, status)
}

// do sends req, checks the status and decodes the answer as Out.
func do[Out any](t *testing.T, b *browser, req *http.Request, status int) Out {
	t.Helper()
	var out Out
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d: %s", req.Method, req.URL.Path, res.StatusCode, status, buf.String())
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: decode %q: %v", req.Method, req.URL.Path, buf.String(), err)
	}
	return out
}
