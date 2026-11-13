package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"errors"
	"html"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/authui/social"
	"github.com/ubgo/auth/oidcclient"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// The two hosts of the story, both served in-process over TLS with a test
// certificate; nothing leaves the machine. The session cookie is Secure and
// __Host- prefixed, so the app must be https even in a test.
const (
	loginHost  = "login.example.com"
	appHost    = "ops.example.com"
	loginURL   = "https://" + loginHost
	appURL     = "https://" + appHost
	authPrefix = "/auth"
	// appName is the client's name at the login server, which its access
	// list is keyed by.
	appName       = "ops"
	sessionSecret = "the-ops-console-session-secret-32-bytes"
	// person is Sam, a contractor the ops console's list names by address.
	person = "sam@partner.io"
	// acceptHTML makes a request a browser navigation (a refusal redirects
	// to sign-in); acceptJSON an API call (a refusal is 401 JSON).
	acceptHTML = "text/html"
	acceptJSON = "application/json"
	// sinceStart is how far past the recheck interval the clock moves to
	// make the session's last "yes" stale.
	sinceStart = oidcclient.DefaultRecheckInterval + time.Second
)

// testSecret is the login server's auth.WithSecret: a visibly fake 32-byte
// run, built here so it reads as a fixture rather than a key.
var testSecret = strings.Repeat("0123456789abcdef", 2)

// fakeGoogle stands in for Google, as in examples/sso-server: its sign-in
// page sends the browser straight back to the login server's callback with
// a code, and the code is one person with a verified address.
type fakeGoogle struct{ email string }

func (fakeGoogle) Name() string { return "google" }
func (fakeGoogle) AuthCodeURL(state, _, redirectURI string) string {
	return redirectURI + "?" + url.Values{"code": {"c"}, "state": {state}}.Encode()
}
func (g fakeGoogle) Exchange(context.Context, *http.Client, string, string, string) (oauth.Profile, error) {
	return oauth.Profile{Subject: "g-" + g.email, Email: g.email, EmailVerified: true, Name: "Sam"}, nil
}

// clock is the one time both servers read, so a test can move days ahead
// and have the login server's token lifetimes, the ID tokens' iat and exp,
// and the app's session lifetimes and re-check all agree.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

func (c *clock) Advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.now = c.now.Add(d) }

// accessLists is the login server's rule, as examples/sso-server's
// allowLists, behind a lock so a test can take a person off a list while
// the servers read it.
type accessLists struct {
	mu    sync.Mutex
	lists map[string]oauthprovider.AllowList
}

func (a *accessLists) lookup(_ context.Context, c oauthprovider.Client) (oauthprovider.AllowList, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	l, ok := a.lists[c.Name]
	return l, ok
}

// set replaces one app's list: the operator's edit of the configuration.
func (a *accessLists) set(app string, l oauthprovider.AllowList) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lists[app] = l
}

// world is one run of the story: the login server, the ops console, the
// network between them and the browser, and the shared clock.
type world struct {
	t        *testing.T
	clk      *clock
	access   *accessLists
	op       *oauthprovider.Plugin
	clientID string
	net      *http.Transport
	mu       sync.Mutex
	events   []oidcclient.Event // what the app's Observer was told since the last signIn
}

// newWorld starts the login server (wired as examples/sso-server wires it,
// with the stand-in Google signing Sam in) and the ops console, registered
// as a first-party client whose list names Sam.
func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, clk: &clock{now: time.Now()}, access: &accessLists{lists: map[string]oauthprovider.AllowList{appName: {Emails: []string{person}}}}}
	cert, pool := testCertificate(t)
	login := httptest.NewUnstartedServer(nil)
	app := httptest.NewUnstartedServer(nil)
	w.net = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			to := map[string]string{loginHost: login.Listener.Addr().String(), appHost: app.Listener.Addr().String()}[host]
			return (&net.Dialer{}).DialContext(ctx, network, to)
		},
	}

	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "t.db")+"?_txlock=immediate&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(loginURL))
	w.op = oauthprovider.New(jw,
		oauthprovider.Issuer(loginURL),
		oauthprovider.LoginPage(social.DefaultLoginPath),
		oauthprovider.ConsentPage(social.DefaultConsentPath),
		oauthprovider.NoAccessPage(social.DefaultNoAccessPath),
		oauthprovider.ClientAccess(oauthprovider.AllowListAccess(w.access.lookup)),
	)
	a, err := auth.New(auth.WithDB(db, sqlb.SQLiteDialect{}), auth.WithBaseURL(loginURL), auth.WithSecret([]byte(testSecret)), auth.WithClock(w.clk.Now),
		auth.WithPlugins(email.New(email.NoMail()), oauth.New(oauth.WithProviders(fakeGoogle{email: person}), oauth.RequireVerifiedEmail()), jw, w.op))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(); _ = db.Close() }) // a test database; nothing to report on close
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	pages, err := social.New(a, w.op, social.Brand("Example login"))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/.well-known/", w.op.Handler())
	mux.Handle(oauthprovider.DefaultBasePath+"/", w.op.Handler())
	mux.Handle("/", pages.Handler())
	login.Config.Handler = mux
	login.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	login.StartTLS()
	t.Cleanup(login.Close)

	paths := oidcclient.PathsUnder(oidcclient.DefaultRoutePrefix)
	reg, err := w.op.CreateClient(context.Background(), oauthprovider.ClientSpec{SkipConsent: true, EnableEndSession: true, ClientMetadata: oauthprovider.ClientMetadata{
		Name: appName, RedirectURIs: []string{appURL + paths.Callback}, PostLogoutRedirectURIs: []string{appURL + pathHome},
	}})
	if err != nil {
		t.Fatal(err)
	}
	w.clientID = reg.ClientID

	// The program's own configuration path, then the test's plumbing: the
	// in-process network and the shared clock. Every policy is the default.
	env := map[string]string{envIssuer: loginURL, envAppURL: appURL, envClientID: reg.ClientID, envSessionSecret: sessionSecret}
	cfg, err := configFromEnv(func(k string) string { return env[k] }, func(string) ([]byte, error) { return []byte(reg.Secret + "\n"), nil })
	if err != nil {
		t.Fatal(err)
	}
	c, err := oidcclient.New(cfg,
		oidcclient.WithHTTPClient(&http.Client{Transport: w.net}),
		oidcclient.WithClock(w.clk.Now),
		oidcclient.WithObserver(oidcclient.ObserverFunc(func(_ context.Context, e oidcclient.Event) {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.events = append(w.events, e)
		})),
	)
	if err != nil {
		t.Fatal(err)
	}
	app.Config.Handler = newHandler(c)
	app.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	app.StartTLS()
	t.Cleanup(app.Close)
	return w
}

// count returns how many events of kind the app's Observer was told since
// the last signIn, and the reasons of the refusals among them.
func (w *world) count(kind oidcclient.EventKind) (int, []oidcclient.Reason) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, reasons := 0, []oidcclient.Reason{}
	for _, e := range w.events {
		if e.Kind == kind {
			n++
			if e.Reason != "" {
				reasons = append(reasons, e.Reason)
			}
		}
	}
	return n, reasons
}

// browser is Sam's browser: it keeps cookies per host and follows
// redirects, and remembers the session cookies the app's callback set.
type browser struct {
	*http.Client
	jar *cookiejar.Jar
	// fromCallback is every cookie the app's callback answer set.
	fromCallback []*http.Cookie
}

// newBrowser returns a browser whose jar holds cookies, empty when none
// are given (a fresh profile) or holding cookies kept from before.
func (w *world) newBrowser(cookies ...*http.Cookie) *browser {
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(appURL)
	jar.SetCookies(u, cookies)
	b := &browser{jar: jar}
	b.Client = &http.Client{Jar: jar, Transport: w.net, CheckRedirect: func(r *http.Request, _ []*http.Request) error {
		if prev := r.Response; prev != nil && prev.Request.URL.Host == appHost && prev.Request.URL.Path == oidcclient.PathsUnder(oidcclient.DefaultRoutePrefix).Callback {
			b.fromCallback = prev.Cookies()
		}
		return nil
	}}
	return b
}

// open is a browser navigation to the app's path; it returns the page the
// browser ends on, body read.
func (w *world) open(b *browser, path string) (*http.Response, string) {
	w.t.Helper()
	return w.do(b.Client, appURL+path, acceptHTML, nil)
}

// do sends one GET with accept as the Accept header and cookies added by
// hand, and returns the answer with its body read.
func (w *world) do(c *http.Client, u, accept string, cookies []*http.Cookie) (*http.Response, string) {
	w.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("Accept", accept)
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	res, err := c.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close() // fully read; a close error changes nothing
	return res, string(body)
}

// signIn opens the ops console signed out, which ends on the login
// server's sign-in page, clicks "Sign in with Google", and lands back on
// the console's home page signed in.
func (w *world) signIn(b *browser) {
	w.t.Helper()
	res, page := w.open(b, pathHome)
	m := regexp.MustCompile(`href="([^"]*google/start[^"]*)"`).FindStringSubmatch(page)
	if res.Request.URL.Host != loginHost || m == nil {
		w.t.Fatalf("opening the console signed out ended on %s, not the login server's sign-in page:\n%s", res.Request.URL, page)
	}
	res, page = w.do(b.Client, loginURL+html.UnescapeString(m[1]), acceptHTML, nil)
	if res.StatusCode != http.StatusOK || res.Request.URL.String() != appURL+pathHome || !strings.Contains(page, "Signed in as Sam ("+person+")") {
		w.t.Fatalf("sign-in ended on %d %s:\n%s", res.StatusCode, res.Request.URL, page)
	}
	// The signed-out first visit was a refusal (no session); the tests
	// count what happens to the session from here on.
	w.mu.Lock()
	w.events = nil
	w.mu.Unlock()
}

// savedCopy is a copy of every cookie the browser holds for the app, as
// someone copying it out of the browser's storage would take it.
func (w *world) savedCopy(b *browser) []*http.Cookie {
	u, _ := url.Parse(appURL)
	cs := b.jar.Cookies(u)
	if len(cs) == 0 {
		w.t.Fatal("the browser holds no cookie for the app")
	}
	return cs
}

// withCopy calls the app's path with the saved cookies and nothing else:
// no jar (a new cookie the app sets is not kept, so the copy stays the
// copy) and no redirect followed (the first answer is what is checked).
func (w *world) withCopy(saved []*http.Cookie, path, accept string) (*http.Response, string) {
	w.t.Helper()
	c := &http.Client{Transport: w.net, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return w.do(c, appURL+path, accept, saved)
}

// subject is the login server's id for the signed-in person, read from the
// app's /api/me as an operator's tooling would look it up.
func (w *world) subject(b *browser) string {
	w.t.Helper()
	res, body := w.do(b.Client, appURL+pathMe, acceptJSON, nil)
	var me meView
	if res.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &me) != nil || me.Subject == "" {
		w.t.Fatalf("/api/me = %d %s", res.StatusCode, body)
	}
	return me.Subject
}

// The story's key promise. Sam signs in and someone keeps a copy of his
// session cookie. The operator takes him off the ops list and revokes his
// tokens for the console. Within one recheck interval every request
// carrying that copy is answered "login required", and the login server,
// asked again, shows its no-access page. Before the revoke the same copy
// was let in.
//
//ds:def id=testoidcapp-removeduserisrefusedwithinrecheck-h3w8qn5t owner=@khanakia stability=stable
func TestOIDCApp_RemovedUserIsRefusedWithinRecheck(t *testing.T) {
	w := newWorld(t)
	b := w.newBrowser()
	w.signIn(b)
	saved := w.savedCopy(b)
	if res, body := w.withCopy(saved, pathMe, acceptJSON); res.StatusCode != http.StatusOK {
		t.Fatalf("before the revoke the saved copy was refused: %d %s", res.StatusCode, body)
	}

	// The operator's two steps, in the order the revoke's doc gives: change
	// the rule first, so a fresh sign-in is refused too, then revoke.
	w.access.set(appName, oauthprovider.AllowList{})
	got, err := w.op.RevokeUserForClient(context.Background(), oauthprovider.RevokeUserRequest{ClientID: w.clientID, UserID: w.subject(b)})
	if err != nil || got.Tokens == 0 {
		t.Fatalf("RevokeUserForClient = %+v, %v", got, err)
	}

	// The bound, stated honestly: until the last "yes" is a recheck interval
	// old, the app has not asked again and the copy still works.
	if res, _ := w.withCopy(saved, pathMe, acceptJSON); res.StatusCode != http.StatusOK {
		t.Fatalf("inside the recheck interval the copy was refused already: %d (the bound this test pins moved)", res.StatusCode)
	}

	w.clk.Advance(sinceStart)
	res, body := w.withCopy(saved, pathMe, acceptJSON)
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(body, `"error":"`+string(oidcclient.RefusalLoginRequired)+`"`) {
		t.Fatalf("an API call with the saved copy after the interval = %d %s, want 401 login_required", res.StatusCode, body)
	}
	res, _ = w.withCopy(saved, pathHome, acceptHTML)
	if loc := res.Header.Get("Location"); res.StatusCode != http.StatusFound || !strings.HasPrefix(loc, oidcclient.PathsUnder(oidcclient.DefaultRoutePrefix).Login) {
		t.Fatalf("a page with the saved copy = %d Location %q, want a redirect to sign-in", res.StatusCode, loc)
	}
	if _, reasons := w.count(oidcclient.EventRefuse); len(reasons) == 0 || reasons[0] != oidcclient.ReasonServerRefused {
		t.Fatalf("refusal reasons = %v, want %s first", reasons, oidcclient.ReasonServerRefused)
	}

	// Sam's own browser follows the redirect: the app sends him to the login
	// server, which still knows him but asks the rule again and shows its
	// no-access page. The app never gets a code.
	res, page := w.open(b, pathHome)
	if res.StatusCode != http.StatusForbidden || res.Request.URL.Host != loginHost || !strings.Contains(page, appName) {
		t.Fatalf("Sam's browser ended on %d %s, want the login server's no-access page:\n%s", res.StatusCode, res.Request.URL, page)
	}
	if n, _ := w.count(oidcclient.EventRefresh); n != 0 {
		t.Fatalf("%d refreshes succeeded after the revoke", n)
	}
}

// Revoking without changing the rule ends the session the copy holds, but
// not Sam's access: the app's "login required" sends him to the login
// server, which still lets him in, and he is signed in again with one
// click's worth of redirects. This is why the operator changes the rule
// first. The old copy stays dead all the same.
//
//ds:def id=testoidcapp-revokealonesignsbackin-m6r2xv9d owner=@khanakia stability=stable
func TestOIDCApp_RevokeAloneSignsBackIn(t *testing.T) {
	w := newWorld(t)
	b := w.newBrowser()
	w.signIn(b)
	saved := w.savedCopy(b)
	if _, err := w.op.RevokeUserForClient(context.Background(), oauthprovider.RevokeUserRequest{ClientID: w.clientID, UserID: w.subject(b)}); err != nil {
		t.Fatal(err)
	}
	w.clk.Advance(sinceStart)
	if res, body := w.withCopy(saved, pathMe, acceptJSON); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the saved copy after the revoke = %d %s, want 401", res.StatusCode, body)
	}
	res, page := w.open(b, pathHome)
	if res.StatusCode != http.StatusOK || res.Request.URL.String() != appURL+pathHome || !strings.Contains(page, "Signed in as Sam") {
		t.Fatalf("with the rule unchanged Sam's browser ended on %d %s, want signed in again:\n%s", res.StatusCode, res.Request.URL, page)
	}
	if res, _ := w.withCopy(saved, pathMe, acceptJSON); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the old copy works again after the new sign-in: %d", res.StatusCode)
	}
}

// Closing the browser does not sign Sam out. The session cookie the
// callback sets has an expiry (the idle lifetime, 7 days), so a browser
// keeps it across a restart; two days later the console opens without a
// sign-in, after one re-check with the login server.
//
//ds:def id=testoidcapp-closingthebrowserkeepsthesession-p9k4tz2w owner=@khanakia stability=stable
func TestOIDCApp_ClosingTheBrowserKeepsTheSession(t *testing.T) {
	w := newWorld(t)
	b := w.newBrowser()
	w.signIn(b)

	var kept []*http.Cookie
	for _, c := range b.fromCallback {
		if c.Value == "" {
			continue // a deleted cookie, such as the spent sign-in flow cookie
		}
		if c.Name != oidcclient.DefaultCookieName {
			t.Fatalf("the callback set %q, want only %s", c.Name, oidcclient.DefaultCookieName)
		}
		if want := int(oidcclient.DefaultIdleLifetime / time.Second); c.Expires.IsZero() || c.MaxAge < want-60 || c.MaxAge > want {
			t.Fatalf("session cookie Expires %v Max-Age %d: a browser would drop it on close; want about %d seconds", c.Expires, c.MaxAge, want)
		}
		if !c.Secure || !c.HttpOnly {
			t.Fatalf("session cookie Secure=%v HttpOnly=%v", c.Secure, c.HttpOnly)
		}
		kept = append(kept, c)
	}
	if len(kept) == 0 {
		t.Fatal("the callback set no session cookie")
	}

	// The browser restarts: only the cookies with an expiry survive, in a
	// new process. Two days pass.
	w.clk.Advance(48 * time.Hour)
	reopened := w.newBrowser(kept...)
	res, page := w.open(reopened, pathHome)
	if res.StatusCode != http.StatusOK || res.Request.URL.Host != appHost || !strings.Contains(page, "Signed in as Sam") {
		t.Fatalf("two days after a restart the console answered %d %s:\n%s", res.StatusCode, res.Request.URL, page)
	}
	if n, _ := w.count(oidcclient.EventRefresh); n != 1 {
		t.Fatalf("refreshes = %d, want the one re-check of a two-day-old yes", n)
	}
}

// A person still on the list stays signed in across re-checks: each request
// after the interval refreshes once, the rotated tokens are saved into a new
// cookie, and the next re-check presents the new refresh token, so the
// provider's strict rotation never sees a reuse.
//
//ds:def id=testoidcapp-alloweduserstayssignedin-f5j7wc3n owner=@khanakia stability=stable
func TestOIDCApp_AllowedUserStaysSignedIn(t *testing.T) {
	w := newWorld(t)
	b := w.newBrowser()
	w.signIn(b)
	before := w.savedCopy(b)[0].Value
	for i := 1; i <= 3; i++ {
		w.clk.Advance(sinceStart)
		if res, body := w.do(b.Client, appURL+pathMe, acceptJSON, nil); res.StatusCode != http.StatusOK {
			t.Fatalf("re-check %d: /api/me = %d %s", i, res.StatusCode, body)
		}
		if n, _ := w.count(oidcclient.EventRefresh); n != i {
			t.Fatalf("after re-check %d: %d refreshes", i, n)
		}
		now := w.savedCopy(b)[0].Value
		if now == before {
			t.Fatalf("re-check %d did not save the rotated tokens into a new cookie", i)
		}
		before = now
	}
	if n, _ := w.count(oidcclient.EventRefuse); n != 0 {
		t.Fatalf("%d refusals for a person still on the list", n)
	}
}

// configFromEnv names the first missing setting, and reads the client
// secret from its file without the trailing newline an editor leaves.
func TestOIDCApp_ConfigFromEnv(t *testing.T) {
	full := map[string]string{envIssuer: loginURL, envAppURL: appURL, envClientID: "oac_ops", envSessionSecret: sessionSecret}
	secretFile := func(name string) ([]byte, error) {
		if name != defaultSecretFile {
			return nil, fs.ErrNotExist
		}
		return []byte("s3cret\n"), nil
	}
	cfg, err := configFromEnv(func(k string) string { return full[k] }, secretFile)
	if err != nil || cfg.ClientSecret.Reveal() != "s3cret" || cfg.Issuer != loginURL || cfg.AppURL != appURL || cfg.ClientID != "oac_ops" {
		t.Fatalf("configFromEnv = %+v, %v", cfg, err)
	}
	for _, missing := range []string{envIssuer, envClientID, envAppURL, envSessionSecret} {
		env := func(k string) string {
			if k == missing {
				return ""
			}
			return full[k]
		}
		if _, err := configFromEnv(env, secretFile); !errors.Is(err, errMissingEnv) || !strings.Contains(err.Error(), missing) {
			t.Errorf("without %s: %v", missing, err)
		}
	}
	if _, err := configFromEnv(func(k string) string { return full[k] }, func(string) ([]byte, error) { return nil, fs.ErrNotExist }); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("without the secret file: %v", err)
	}
}

// testCertificate is a self-signed certificate for both hosts.
func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, DNSNames: []string{loginHost, appHost},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}
