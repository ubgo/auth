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
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/oauth"
)

const (
	testPassword = "correct horse battery staple"
	aliceEmail   = "alice@example.com"
	daveEmail    = "dave@contractor.test"
)

// TestRules_NewPersonGetsAnAccountWithTheirLogin: a person the app has never
// seen gets an account, and the OnResolved hook kept their login handle in
// the app's column. The same person again is the same account.
func TestRules_NewPersonGetsAnAccountWithTheirLogin(t *testing.T) {
	app := newTestApp(t, linkDefault)
	b := app.browser(t)
	b.signInWithProvider(t, "carol")
	got := get[meResponse](t, b, "/me", http.StatusOK)
	if got.Name != "Carol" || got.Login != "carol" {
		t.Fatalf("/me = %+v", got)
	}
	again := app.browser(t)
	again.signInWithProvider(t, "carol")
	if id := get[meResponse](t, again, "/me", http.StatusOK).ID; id != got.ID {
		t.Fatalf("second sign-in reached %s, want %s", id, got.ID)
	}
}

// TestRules_DefaultLinksOnlyWhenBothSidesAreVerified: the provider address
// meets Alice's verified password account. The issuer vouching for it links
// to her account; the same address without email_verified is refused.
func TestRules_DefaultLinksOnlyWhenBothSidesAreVerified(t *testing.T) {
	app := newTestApp(t, linkDefault)
	owner := app.verifiedPasswordAccount(t)

	refused := app.browser(t)
	if e := get[errorAnswer](t, refused, refused.throughProvider(t, "alice-unflagged"), http.StatusConflict); e.Error.Code != oauth.ErrAccountExists.Code {
		t.Fatalf("unflagged address: %+v", e.Error)
	}
	linked := app.browser(t)
	linked.signInWithProvider(t, "alice")
	got := get[meResponse](t, linked, "/me", http.StatusOK)
	if got.ID != owner || got.Login != "alice" {
		t.Fatalf("verified address reached %+v, want the password account %s", got, owner)
	}
}

// TestRules_StrictNeverLinksByEmail: under NoImplicitLinking even a verified
// match is refused; the person signs in with the password and links from
// settings.
func TestRules_StrictNeverLinksByEmail(t *testing.T) {
	app := newTestApp(t, linkStrict)
	app.verifiedPasswordAccount(t)
	b := app.browser(t)
	if e := get[errorAnswer](t, b, b.throughProvider(t, "alice"), http.StatusConflict); e.Error.Code != oauth.ErrAccountExists.Code {
		t.Fatalf("strict linking: %+v", e.Error)
	}
}

// TestRules_TrustedProviderLinksAnUnflaggedAddress: under TrustedProviders
// the corp address counts as verified without email_verified, so it links.
func TestRules_TrustedProviderLinksAnUnflaggedAddress(t *testing.T) {
	app := newTestApp(t, linkTrusted)
	owner := app.verifiedPasswordAccount(t)
	b := app.browser(t)
	b.signInWithProvider(t, "alice-unflagged")
	if got := get[meResponse](t, b, "/me", http.StatusOK); got.ID != owner {
		t.Fatalf("trusted provider reached %s, want %s", got.ID, owner)
	}
}

// TestRules_OtherDomainIsRefusedBeforeAnythingIsWritten: the ValidateProfile
// hook answers the app's own error, and no user exists afterwards.
func TestRules_OtherDomainIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	app := newTestApp(t, linkDefault)
	b := app.browser(t)
	e := get[errorAnswer](t, b, b.throughProvider(t, "dave"), http.StatusForbidden)
	if e.Error.Code != errDomainNotAllowed.Code {
		t.Fatalf("other domain: %+v", e.Error)
	}
	if _, err := app.auth.FindIdentity(context.Background(), email.KindEmail, daveEmail, false); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("a refused sign-up left a user: %v", err)
	}
	if b.hasCookie(authhttp.CookieName) {
		t.Fatal("a refused sign-up set a session cookie")
	}
}

// TestRules_DashboardTileRestartsAFlow: the tile sends the browser to the
// callback with a code and no state. The app drops the code unread and
// answers a fresh flow bound to this browser; the issuer signs the person
// straight through, and the second callback signs in, landing on /.
func TestRules_DashboardTileRestartsAFlow(t *testing.T) {
	app := newTestApp(t, linkDefault)
	b := app.browser(t)

	tile := pathOf(t, b.redirect(t, app.idpURL+"/tile"))
	restart := b.redirect(t, tile)
	if !strings.HasPrefix(restart, app.idpURL+"/authorize?") || !strings.Contains(restart, "state=") {
		t.Fatalf("the tile's callback answered %q, not a new flow at the issuer", restart)
	}
	if b.hasCookie(authhttp.CookieName) {
		t.Fatal("the tile's own code signed someone in")
	}
	callback := pathOf(t, b.redirect(t, restart))
	if loc := b.redirect(t, callback); loc != "/" {
		t.Fatalf("restarted callback redirected to %q, want /", loc)
	}
	if got := get[meResponse](t, b, "/me", http.StatusOK); got.Login != defaultPerson {
		t.Fatalf("/me after the tile = %+v", got)
	}
	if n := app.idp.tileCodesExchanged(); n != 0 {
		t.Fatalf("the tile's code was exchanged %d times", n)
	}
}

// TestRules_UnknownLinkingModeIsRefused: a typo in LINKING stops the
// program instead of quietly running the default.
func TestRules_UnknownLinkingModeIsRefused(t *testing.T) {
	for _, m := range []linkingMode{linkDefault, linkStrict, linkTrusted} {
		if _, err := linkingRules(m); err != nil {
			t.Fatalf("linkingRules(%q): %v", m, err)
		}
	}
	if _, err := linkingRules("trusting"); err == nil {
		t.Fatal("an unknown mode was accepted")
	}
}

// testApp is the app wired as main wires it, with the issuer on httptest.
type testApp struct {
	auth   *auth.Auth
	h      http.Handler
	idp    *issuer
	idpURL string
	box    *mailbox
}

// newTestApp starts the issuer, then builds and migrates the app with the
// linking rule mode, on a fresh SQLite file.
func newTestApp(t *testing.T, mode linkingMode) *testApp {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	u := "http://" + srv.Listener.Addr().String()
	idp := newIssuer(u, callbackURL)
	srv.Config.Handler = idp.handler()
	srv.Start()
	t.Cleanup(srv.Close)

	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	linking, err := linkingRules(mode)
	if err != nil {
		t.Fatal(err)
	}
	box := &mailbox{}
	a, err := newAuth(db, box, newOAuth(u, linking...))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &testApp{auth: a, h: newHandler(a), idp: idp, idpURL: u, box: box}
}

// verifiedPasswordAccount signs Alice up with a password, verifies her
// address from the mailed link, and returns her user id.
func (app *testApp) verifiedPasswordAccount(t *testing.T) string {
	t.Helper()
	b := app.browser(t)
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	post[none](t, b, "/auth/email/verify", fields{"token": app.box.lastToken(t, app.auth, aliceEmail)}, http.StatusOK)
	return get[meResponse](t, b, "/me", http.StatusOK).ID
}

// signInWithProvider runs start, consent and callback for the person the
// login hint names, and checks the callback lands on /me with a session.
func (b *browser) signInWithProvider(t *testing.T, who string) {
	t.Helper()
	if loc := b.redirect(t, b.throughProvider(t, who)); loc != "/me" {
		t.Fatalf("callback redirected to %q, want /me", loc)
	}
	if !b.hasCookie(authhttp.CookieName) {
		t.Fatal("callback set no session cookie")
	}
}

// throughProvider starts a flow for who and follows the issuer's consent,
// returning the app's callback path and query.
func (b *browser) throughProvider(t *testing.T, who string) string {
	t.Helper()
	consent := b.redirect(t, "/auth/oauth/"+providerName+"/start?returnTo=/me&loginHint="+url.QueryEscape(who))
	return pathOf(t, b.redirect(t, consent))
}

// pathOf checks u is the registered callback URL and keeps its path and
// query: it names baseURL, where main would listen, and the test server is
// elsewhere.
func pathOf(t *testing.T, u string) string {
	t.Helper()
	if !strings.HasPrefix(u, callbackURL+"?") {
		t.Fatalf("the issuer sent the browser to %s, not the registered callback", u)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.RequestURI()
}

// mailbox records every mail sent.
type mailbox struct {
	mu   sync.Mutex
	sent []email.Mail
}

// Send records m.
func (m *mailbox) Send(_ context.Context, mail email.Mail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, mail)
	return nil
}

// lastToken returns the token of the newest link mailed to addr, after the
// deliveries that run once a transaction commits.
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

// browser is an HTTPS test server for the app and a client with a cookie
// jar that sends the app's Origin and does not follow redirects, so each
// step of the dance is checked.
type browser struct {
	srv    *httptest.Server
	client *http.Client
}

// browser serves the app over TLS, because the session cookie is __Host-
// and Secure, and a cookie jar keeps such a cookie only for an https URL.
func (app *testApp) browser(t *testing.T) *browser {
	t.Helper()
	srv := httptest.NewTLSServer(app.h)
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &browser{srv: srv, client: client}
}

// fields is a JSON request body as a client writes it.
type fields map[string]string

// none is an answer whose body the test does not read.
type none struct{}

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// redirect gets u (a path on the app, or an absolute URL), checks the answer
// is a 302 and returns its Location.
func (b *browser) redirect(t *testing.T, u string) string {
	t.Helper()
	if strings.HasPrefix(u, "/") {
		u = b.srv.URL + u
	}
	res, err := b.client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("GET %s: status %d, want 302: %s", u, res.StatusCode, buf.String())
	}
	return res.Header.Get("Location")
}

// post sends in as JSON with the app's Origin, checks the status and decodes
// the answer as Out.
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
	req.Header.Set("Origin", baseURL)
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

// hasCookie reports whether the jar holds a non-empty cookie called name.
func (b *browser) hasCookie(name string) bool {
	u, _ := url.Parse(b.srv.URL)
	for _, c := range b.client.Jar.Cookies(u) {
		if c.Name == name && c.Value != "" {
			return true
		}
	}
	return false
}
