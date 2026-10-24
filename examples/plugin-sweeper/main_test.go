package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/examples/plugin-sweeper/tickets"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	testTarget   = filesPrefix + "report.txt"
)

// TestTickets_HeaderThenRedirect: minting hands the ticket over in a header
// and keeps it out of the JSON body; redeeming it answers a redirect to the
// target, which serves the page.
func TestTickets_HeaderThenRedirect(t *testing.T) {
	app := newApp(t)
	app.signUp(t)

	res, body := app.do(t, http.MethodPost, authPrefix+"/tickets/mint", `{"target":"`+testTarget+`"}`)
	ticket := res.Header.Get(tickets.HeaderTicket)
	if res.StatusCode != http.StatusOK || ticket == "" {
		t.Fatalf("mint = %d, ticket %q: %s", res.StatusCode, ticket, body)
	}
	if strings.Contains(body, ticket) {
		t.Fatalf("the ticket leaked into the body: %s", body)
	}

	res, _ = app.do(t, http.MethodGet, authPrefix+"/tickets/redeem?ticket="+url.QueryEscape(ticket), "")
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != testTarget {
		t.Fatalf("redeem = %d to %q", res.StatusCode, res.Header.Get("Location"))
	}
	if res, body := app.do(t, http.MethodGet, testTarget, ""); res.StatusCode != http.StatusOK || !strings.Contains(body, "report.txt") {
		t.Fatalf("target = %d %s", res.StatusCode, body)
	}
}

// TestTickets_RefusesAnotherSite: a target that is not a path of this site
// is refused, so a ticket can never become an open redirect, and a failed
// call applies no effect: no ticket header.
func TestTickets_RefusesAnotherSite(t *testing.T) {
	app := newApp(t)
	app.signUp(t)
	for _, target := range []string{"https://evil.example/", "//evil.example/", `/\evil.example`} {
		res, body := app.do(t, http.MethodPost, authPrefix+"/tickets/mint", `{"target":"`+strings.ReplaceAll(target, `\`, `\\`)+`"}`)
		if res.StatusCode != tickets.ErrTargetInvalid.Status || !strings.Contains(body, tickets.ErrTargetInvalid.Code) {
			t.Fatalf("mint %q = %d %s", target, res.StatusCode, body)
		}
		if res.Header.Get(tickets.HeaderTicket) != "" {
			t.Fatalf("a refused mint handed out a ticket")
		}
	}
}

// TestTickets_MintIsLimitedPerUser: the ByFunc rule counts mints per user,
// so the next mint past the limit is refused with the rate-limit code and a
// Retry-After header.
func TestTickets_MintIsLimitedPerUser(t *testing.T) {
	app := newApp(t)
	app.signUp(t)
	for i := 0; i < tickets.MintLimit; i++ {
		if res, body := app.do(t, http.MethodPost, authPrefix+"/tickets/mint", `{"target":"`+testTarget+`"}`); res.StatusCode != http.StatusOK {
			t.Fatalf("mint %d = %d %s", i+1, res.StatusCode, body)
		}
	}
	res, body := app.do(t, http.MethodPost, authPrefix+"/tickets/mint", `{"target":"`+testTarget+`"}`)
	if res.StatusCode != http.StatusTooManyRequests || !strings.Contains(body, auth.ErrRateLimited.Code) || res.Header.Get("Retry-After") == "" {
		t.Fatalf("mint past the limit = %d %s", res.StatusCode, body)
	}
}

// TestTickets_ExpireThenSweep: an expired ticket is refused before any sweep
// runs, Auth.Sweep then deletes it and reports it under the plugin's name,
// and a second sweep finds nothing, so running it twice is harmless.
func TestTickets_ExpireThenSweep(t *testing.T) {
	app := newApp(t)
	app.signUp(t)
	res, _ := app.do(t, http.MethodPost, authPrefix+"/tickets/mint", `{"target":"`+testTarget+`"}`)
	ticket := res.Header.Get(tickets.HeaderTicket)

	// At exactly its expiry a ticket stops opening; Sweep deletes rows that
	// expired strictly before the cutoff, so step one second past it.
	app.clock.advance(tickets.DefaultTTL)
	res, body := app.do(t, http.MethodGet, authPrefix+"/tickets/redeem?ticket="+url.QueryEscape(ticket), "")
	if res.StatusCode != tickets.ErrInvalid.Status || !strings.Contains(body, tickets.ErrInvalid.Code) {
		t.Fatalf("expired redeem = %d %s", res.StatusCode, body)
	}

	app.clock.advance(time.Second)
	ctx := context.Background()
	swept, err := app.a.Sweep(ctx, 0)
	if err != nil || swept[tickets.PluginName] != 1 {
		t.Fatalf("sweep = %v, %v; want 1 under %q", swept, err, tickets.PluginName)
	}
	if again, err := app.a.Sweep(ctx, 0); err != nil || again[tickets.PluginName] != 0 {
		t.Fatalf("second sweep = %v, %v", again, err)
	}
}

// TestTickets_RetentionKeepsRecentlyExpired: Sweep's retention keeps a
// ticket that expired less than that long ago.
func TestTickets_RetentionKeepsRecentlyExpired(t *testing.T) {
	app := newApp(t)
	app.signUp(t)
	app.do(t, http.MethodPost, authPrefix+"/tickets/mint", `{"target":"`+testTarget+`"}`)
	app.clock.advance(tickets.DefaultTTL + time.Minute)

	if swept, err := app.a.Sweep(context.Background(), time.Hour); err != nil || swept[tickets.PluginName] != 0 {
		t.Fatalf("sweep with an hour's retention = %v, %v", swept, err)
	}
}

// TestTickets_GoCallRecordsTheSameEffects: the same operation called from
// Go, with no HTTP anywhere, records the header effect, which the caller
// reads back with auth.RequestEffects.
func TestTickets_GoCallRecordsTheSameEffects(t *testing.T) {
	app := newApp(t)
	userID := app.signUp(t)
	_, tok, err := app.a.CreateSession(context.Background(), userID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := app.a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportGo, Credential: auth.CredentialBearer, Token: tok})

	p, _ := auth.PluginOf[*tickets.Plugin](app.a)
	if _, err := p.Mint(ctx, testTarget); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, ef := range auth.RequestEffects(ctx) {
		found = found || (ef.Kind == auth.EffectHeader && ef.Name == tickets.HeaderTicket && ef.Value != "")
	}
	if !found {
		t.Fatalf("effects = %+v, want the ticket header", auth.RequestEffects(ctx))
	}
}

// app is the example wired on a fresh SQLite file with a clock the test moves.
type app struct {
	a       *auth.Auth
	h       http.Handler
	clock   *clock
	cookies []*http.Cookie
}

// newApp builds the app the way main does, with a test clock.
func newApp(t *testing.T) *app {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	c := &clock{now: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)}
	a, err := newAuth(db, discardMailer{}, c.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &app{a: a, h: newHandler(a), clock: c}
}

// signUp creates the account and keeps its session cookie; it returns the
// user's id.
func (x *app) signUp(t *testing.T) string {
	t.Helper()
	res, body := x.do(t, http.MethodPost, authPrefix+"/password/sign-up", `{"identifier":"`+testEmail+`","password":"`+testPassword+`"}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sign-up = %d %s", res.StatusCode, body)
	}
	var out password.SignInResult
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out.User.ID
}

// do serves one request with the app's Origin and the cookies so far.
func (x *app) do(t *testing.T, method, path, body string) (*http.Response, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = bytes.NewBufferString(body)
	}
	req := httptest.NewRequest(method, baseURL+path, r)
	req.Header.Set("Origin", baseURL)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range x.cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	x.h.ServeHTTP(rec, req)
	res := rec.Result()
	for _, c := range res.Cookies() {
		if c.Name == authhttp.CookieName {
			x.cookies = []*http.Cookie{c}
		}
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, string(b)
}

// clock is a time source the test moves forward.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

// Now is the current test time.
func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// advance moves the clock forward by d.
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// discardMailer drops mail; these tests never open a link.
type discardMailer struct{}

// Send drops m.
func (discardMailer) Send(context.Context, email.Mail) error { return nil }
