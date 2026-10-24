package main

import (
	"context"
	"crypto"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/password"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
)

// beforeMidnight is a moment two minutes before a rotation boundary: periods
// are counted from the Unix epoch, so a 24-hour period ends at 00:00 UTC.
var beforeMidnight = time.Date(2026, 10, 9, 23, 58, 0, 0, time.UTC)

// TestRotation_TheReportServiceFollowsANewKey: a token signed just before
// midnight and one signed just after carry different key ids. The report
// service learned the first key on its first fetch; meeting the second id it
// fetches again, and both tokens verify, because the old key stays published
// for the grace period.
func TestRotation_TheReportServiceFollowsANewKey(t *testing.T) {
	clock := &fakeClock{now: beforeMidnight}
	app := newTestApp(t, testSeed(), testRSAKey(t), clock)
	b := newBrowser(t, newHandler(app.a))
	post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)

	v, remote := newVerifier(b.srv.URL+jwksPath, baseURL, b.srv.Client(), clock.Now)
	reports := newBrowser(t, newReportService(v))

	before := post[jwt.TokenResult](t, b, "/auth/jwt/token", none{}, http.StatusOK)
	got := get[reportResult](t, reports.as(before.Token), "/report", http.StatusOK)
	if got.SessionID == "" {
		t.Fatalf("a session token named no session: %+v", got)
	}

	clock.Advance(4 * time.Minute) // past midnight: a new period, a new key
	after := post[jwt.TokenResult](t, b, "/auth/jwt/token", none{}, http.StatusOK)
	if kidOf(t, before.Token) == kidOf(t, after.Token) {
		t.Fatal("the key did not rotate at the period boundary")
	}
	get[reportResult](t, reports.as(after.Token), "/report", http.StatusOK)
	get[reportResult](t, reports.as(before.Token), "/report", http.StatusOK)
	if err := remote.LastError(); err != nil {
		t.Fatalf("key set fetch: %v", err)
	}
}

// TestRotation_EveryInstanceDerivesTheSameKey: two instances built from one
// seed, on two databases, publish the same signing key, so a token from one
// verifies at a service that fetched the other's key set.
func TestRotation_EveryInstanceDerivesTheSameKey(t *testing.T) {
	clock := &fakeClock{now: beforeMidnight}
	one := newTestApp(t, testSeed(), testRSAKey(t), clock)
	two := newTestApp(t, testSeed(), testRSAKey(t), clock)
	if a, b := one.jw.PublicKeys().Keys[0].KeyID, two.jw.PublicKeys().Keys[0].KeyID; a != b {
		t.Fatalf("instances sign with %s and %s", a, b)
	}
	job, err := mintJobToken(context.Background(), one.jw)
	if err != nil {
		t.Fatal(err)
	}
	other := newBrowser(t, newHandler(two.a))
	v, _ := newVerifier(other.srv.URL+jwksPath, baseURL, other.srv.Client(), clock.Now)
	if _, err := v.Verify(job.Token); err != nil {
		t.Fatalf("a token from one instance at the other's key set: %v", err)
	}
}

// TestJobToken_RS256WithoutASession: the job's token is signed with the RSA
// key, names no session, carries its role, and is refused once it expires.
func TestJobToken_RS256WithoutASession(t *testing.T) {
	clock := &fakeClock{now: beforeMidnight}
	app := newTestApp(t, testSeed(), testRSAKey(t), clock)
	b := newBrowser(t, newHandler(app.a))
	v, _ := newVerifier(b.srv.URL+jwksPath, baseURL, b.srv.Client(), clock.Now)
	reports := newBrowser(t, newReportService(v))

	job, err := mintJobToken(context.Background(), app.jw)
	if err != nil {
		t.Fatal(err)
	}
	if alg := headerOf(t, job.Token).Alg; alg != string(jwt.RS256) {
		t.Fatalf("job token alg = %s", alg)
	}
	got := get[reportResult](t, reports.as(job.Token), "/report", http.StatusOK)
	if got.Subject != jobSubject || got.SessionID != "" || got.Role != roleWorker {
		t.Fatalf("job token at the report service = %+v", got)
	}
	clock.Advance(jobTTL + time.Minute)
	get[reportError](t, reports.as(job.Token), "/report", http.StatusUnauthorized)
}

// TestRotationSeed_FromTheEnvironment: a set seed is used as given, and a
// malformed one is refused rather than replaced.
func TestRotationSeed_FromTheEnvironment(t *testing.T) {
	got, err := rotationSeed(func(string) string { return "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" })
	if err != nil || string(got) != string(testSeed()) {
		t.Fatalf("seed from the environment: %v", err)
	}
	if _, err := rotationSeed(func(string) string { return "short" }); err == nil {
		t.Fatal("a malformed seed was accepted")
	}
}

// testApp is the app's Auth and jwt plugin.
type testApp struct {
	a  *auth.Auth
	jw *jwt.Plugin
}

// newTestApp builds the app on a fresh SQLite file with clock as its time.
func newTestApp(t *testing.T, seed []byte, rsaKey crypto.Signer, clock *fakeClock) testApp {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	jw := newJWT(seed, rsaKey)
	a, err := newAuth(db, jw, auth.WithClock(clock.Now))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return testApp{a: a, jw: jw}
}

// testSeed is the seed whose bytes are 0..31, the value
// TestRotationSeed_FromTheEnvironment passes as base64url.
func testSeed() []byte {
	seed := make([]byte, jwt.RotationSeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

// rsaOnce makes one RSA key for the whole package: generating one takes
// long enough to slow every test down.
var rsaOnce = sync.OnceValues(func() (crypto.Signer, error) { return jwt.GenerateKey(jwt.RS256) })

// testRSAKey is the package's RSA key.
func testRSAKey(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := rsaOnce()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// fakeClock is a clock the test moves by hand.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now returns the clock's time.
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// jwsHeader is the part of a token's header the tests read.
type jwsHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// headerOf decodes a token's header without verifying anything.
func headerOf(t *testing.T, token string) jwsHeader {
	t.Helper()
	head, _, _ := strings.Cut(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		t.Fatal(err)
	}
	var h jwsHeader
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

// kidOf is the id of the key that signed token.
func kidOf(t *testing.T, token string) string {
	t.Helper()
	return headerOf(t, token).Kid
}
