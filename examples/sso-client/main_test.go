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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/authui/social"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// The two hosts of the story. Both are served in-process over TLS with a
// test certificate; nothing leaves the machine.
const (
	loginHost  = "login.example.com"
	wikiHost   = "wiki.example.com"
	loginURL   = "https://" + loginHost
	wikiURL    = "https://" + wikiHost
	authPrefix = "/auth"
	wikiName   = "wiki"
	testSecret = "0123456789abcdef0123456789abcdef"
	// listed is on the wiki's list (the example.com domain); unlisted is not.
	listed   = "priya@example.com"
	unlisted = "sam@partner.io"
	// traceMax shortens long values in the -v trace.
	traceMax = 72
)

// allowLists is the login server's rule, as in examples/sso-server: the
// wiki is open to the example.com domain.
var allowLists = map[string]oauthprovider.AllowList{wikiName: {Domains: []string{"example.com"}}}

// fakeGoogle stands in for Google: its sign-in page sends the browser
// straight back to the callback with a code, and the code is one person.
type fakeGoogle struct{ email string }

func (fakeGoogle) Name() string { return "google" }
func (fakeGoogle) AuthCodeURL(state, _, redirectURI string) string {
	return redirectURI + "?" + url.Values{"code": {"c"}, "state": {state}}.Encode()
}
func (g fakeGoogle) Exchange(context.Context, *http.Client, string, string, string) (oauth.Profile, error) {
	return oauth.Profile{Subject: "g-" + g.email, Email: g.email, EmailVerified: true, Name: "Priya"}, nil
}

// world is one run of the story: the login server, the wiki, and the
// network between them and the browser.
type world struct {
	t      *testing.T
	op     *oauthprovider.Plugin
	app    *App
	net    *http.Transport
	tokens atomic.Int32 // token endpoint calls
	trace  bool
}

// newWorld starts the login server (wired as examples/sso-server wires it,
// with the stand-in Google signing in as address) and the wiki, registered as
// a first-party client that may end sessions.
func newWorld(t *testing.T, address string) *world {
	t.Helper()
	w := &world{t: t}
	cert, pool := testCertificate(t)
	login := httptest.NewUnstartedServer(nil)
	wiki := httptest.NewUnstartedServer(nil)
	w.net = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			to := map[string]string{loginHost: login.Listener.Addr().String(), wikiHost: wiki.Listener.Addr().String()}[host]
			return (&net.Dialer{}).DialContext(ctx, network, to)
		},
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "t.db"))
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
		oauthprovider.ClientAccess(oauthprovider.AllowListAccess(func(_ context.Context, c oauthprovider.Client) (oauthprovider.AllowList, bool) {
			l, ok := allowLists[c.Name]
			return l, ok
		})),
	)
	a, err := auth.New(auth.WithDB(db, sqlb.SQLiteDialect{}), auth.WithBaseURL(loginURL), auth.WithSecret([]byte(testSecret)),
		auth.WithPlugins(email.New(email.NoMail()), oauth.New(oauth.WithProviders(fakeGoogle{email: address}), oauth.RequireVerifiedEmail()), jw, w.op))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); db.Close() })
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

	reg, err := w.op.CreateClient(context.Background(), oauthprovider.ClientSpec{SkipConsent: true, EnableEndSession: true, ClientMetadata: oauthprovider.ClientMetadata{
		Name: wikiName, RedirectURIs: []string{wikiURL + pathCallback}, PostLogoutRedirectURIs: []string{wikiURL + pathHome},
	}})
	if err != nil {
		t.Fatal(err)
	}
	w.app, err = NewApp(context.Background(), Config{
		Issuer: loginURL, BaseURL: wikiURL, ClientID: reg.ClientID, ClientSecret: reg.Secret,
		SessionSecret: []byte("the-wiki-own-session-secret-32-bytes!"),
		HTTPClient:    &http.Client{Transport: w.recorder("wiki → login")},
	})
	if err != nil {
		t.Fatal(err)
	}
	wiki.Config.Handler = w.app.Handler()
	wiki.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	wiki.StartTLS()
	t.Cleanup(wiki.Close)
	return w
}

// browser is Priya's browser: it keeps cookies per host and follows
// redirects, except that stopAtCallback hands back the login server's
// redirect to the wiki's callback instead of following it.
func (w *world) browser(stopAtCallback bool) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Transport: w.recorder("browser"), CheckRedirect: func(r *http.Request, _ []*http.Request) error {
		if stopAtCallback && r.URL.Host == wikiHost && r.URL.Path == pathCallback {
			return http.ErrUseLastResponse
		}
		return nil
	}}
}

// signIn opens the wiki's sign-in route, which ends on the login server's
// sign-in page, and clicks "Sign in with Google". It returns the last
// answer the browser got.
func (w *world) signIn(b *http.Client) *http.Response {
	w.t.Helper()
	res := w.get(b, wikiURL+pathLogin)
	page, _ := io.ReadAll(res.Body)
	res.Body.Close()
	m := regexp.MustCompile(`href="([^"]*google/start[^"]*)"`).FindSubmatch(page)
	if m == nil {
		w.t.Fatalf("the login server's sign-in page has no Google button:\n%s", page)
	}
	return w.get(b, loginURL+html.UnescapeString(string(m[1])))
}

// get is a browser navigation: it asks for HTML, as a browser does.
func (w *world) get(b *http.Client, u string) *http.Response {
	w.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("Accept", "text/html")
	res, err := b.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	return res
}

// body reads and closes a response body.
func body(res *http.Response) string {
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return string(b)
}

// cookie is the browser's cookie name on host, or "".
func cookie(b *http.Client, host, name string) string {
	for _, c := range b.Jar.Cookies(&url.URL{Scheme: "https", Host: host}) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// atCallback signs in with a browser that stops at the wiki's callback and
// returns the callback URL and the step-1 values from the wiki's cookie.
func (w *world) atCallback() (*http.Client, *url.URL, loginState) {
	w.t.Helper()
	b := w.browser(true)
	res := w.signIn(b)
	res.Body.Close()
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil || res.StatusCode != http.StatusFound || loc.Host != wikiHost {
		w.t.Fatalf("expected a redirect to the wiki, got %d %s", res.StatusCode, loc)
	}
	var st loginState
	if err := open(w.app.cfg.SessionSecret, purposeLogin, cookie(b, wikiHost, cookieLogin), time.Now(), &st); err != nil {
		w.t.Fatal(err)
	}
	return b, loc, st
}

// Priya signs in to the wiki through the login server and Google, the
// wiki's step-1 cookie is gone and its session cookie is set, and signing
// out ends the login server's session too.
//
//ds:def id=testssoclient-signinandout-3s8tq2vb owner=@khanakia stability=stable
func TestSSOClient_SignInAndOut(t *testing.T) {
	w := newWorld(t, listed)
	w.trace = true
	b := w.browser(false)
	res := w.signIn(b)
	page := body(res)
	if res.Request.URL.String() != wikiURL+pathHome || !strings.Contains(page, "Signed in as Priya ("+listed+")") {
		t.Fatalf("ended on %s:\n%s", res.Request.URL, page)
	}
	if cookie(b, wikiHost, cookieLogin) != "" || cookie(b, wikiHost, cookieSession) == "" {
		t.Fatal("after the callback the login cookie must be gone and the session cookie set")
	}
	req, _ := http.NewRequest(http.MethodPost, wikiURL+pathLogout, nil)
	req.Header.Set("Accept", "text/html")
	res, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if page := body(res); res.Request.URL.String() != wikiURL+pathHome || !strings.Contains(page, "not signed in") {
		t.Fatalf("after sign-out ended on %s:\n%s", res.Request.URL, page)
	}
	w.trace = false
	// The login server's session ended too: the next sign-in asks again.
	res = w.get(b, wikiURL+pathLogin)
	if body(res); res.Request.URL.Host != loginHost || res.Request.URL.Path != social.DefaultLoginPath {
		t.Fatalf("after sign-out a new sign-in ended on %s, want the sign-in page", res.Request.URL)
	}
}

// A callback whose state is not the one in the wiki's own cookie is
// refused before the code is ever sent to the token endpoint.
//
//ds:def id=testssoclient-refuseswrongstate-7mk4xw9d owner=@khanakia stability=stable
func TestSSOClient_RefusesWrongState(t *testing.T) {
	w := newWorld(t, listed)
	b, loc, _ := w.atCallback()
	q := loc.Query()
	q.Set("state", "planted-by-an-attacker")
	loc.RawQuery = q.Encode()
	res := w.get(b, loc.String())
	body(res)
	if res.StatusCode != http.StatusBadRequest || cookie(b, wikiHost, cookieSession) != "" || w.tokens.Load() != 0 {
		t.Fatalf("wrong state: %d, session %q, token calls %d", res.StatusCode, cookie(b, wikiHost, cookieSession), w.tokens.Load())
	}
}

// A code is spent by its first exchange: the same code with the right
// verifier and secret is refused the second time.
//
//ds:def id=testssoclient-codeworksonce-q2v7nd4k owner=@khanakia stability=stable
func TestSSOClient_CodeWorksOnce(t *testing.T) {
	w := newWorld(t, listed)
	b, loc, st := w.atCallback()
	if res := w.get(b, loc.String()); !strings.Contains(body(res), "Signed in as") {
		t.Fatal("the first use of the code must sign in")
	}
	_, err := w.app.exchangeCode(context.Background(), loc.Query().Get("code"), st.Verifier)
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("second exchange = %v, want invalid_grant", err)
	}
}

// A code with another verifier than the one whose fingerprint went to
// /oauth2/authorize gets no tokens: a stolen code alone is useless.
//
//ds:def id=testssoclient-refuseswrongverifier-h6c3pz8r owner=@khanakia stability=stable
func TestSSOClient_RefusesWrongVerifier(t *testing.T) {
	w := newWorld(t, listed)
	_, loc, _ := w.atCallback()
	_, err := w.app.exchangeCode(context.Background(), loc.Query().Get("code"), random())
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("exchange with another verifier = %v, want invalid_grant", err)
	}
}

// A person the wiki's list does not name ends on the login server's
// no-access page; the wiki's callback is never reached and no code exists.
//
//ds:def id=testssoclient-unlisteduserseesnoaccess-n8w2kq5t owner=@khanakia stability=stable
func TestSSOClient_UnlistedUserSeesNoAccess(t *testing.T) {
	w := newWorld(t, unlisted)
	w.trace = true
	b := w.browser(false)
	res := w.signIn(b)
	page := body(res)
	if res.StatusCode != http.StatusForbidden || res.Request.URL.Host != loginHost || res.Request.URL.Path != social.DefaultNoAccessPath || !strings.Contains(page, wikiName) {
		t.Fatalf("ended on %d %s:\n%s", res.StatusCode, res.Request.URL, page)
	}
	if cookie(b, wikiHost, cookieSession) != "" || w.tokens.Load() != 0 {
		t.Fatal("an unlisted person must get no code and no wiki session")
	}
}

// An authorize request naming a redirect URI the wiki never registered is
// answered by the login server itself with an error page: the browser is
// not sent there, so no code can leak to an address an attacker picked.
//
//ds:def id=testssoclient-unregisteredredirect-k7t2wq9s owner=@khanakia stability=stable
func TestSSOClient_UnregisteredRedirect(t *testing.T) {
	w := newWorld(t, listed)
	b := w.browser(false)
	q := url.Values{
		"response_type": {responseTypeCode}, "client_id": {w.app.cfg.ClientID}, "redirect_uri": {wikiURL + "/callback/../evil"},
		"scope": {scopeOpenIDEmail}, "state": {random()}, "code_challenge": {challenge(random())}, "code_challenge_method": {challengeMethodS256},
	}
	res := w.get(b, w.app.meta.AuthorizationEndpoint+"?"+q.Encode())
	body(res)
	if res.StatusCode != http.StatusBadRequest || res.Request.URL.Host != loginHost {
		t.Fatalf("unregistered redirect: %d at %s, want 400 on the login server", res.StatusCode, res.Request.URL)
	}
}

// The wiki refuses an ID token that was altered, signed with another key,
// issued for another sign-in (nonce), expired, or unsigned (alg none).
//
//ds:def id=testssoclient-refusesbadidtoken-x4r9mf2j owner=@khanakia stability=stable
func TestSSOClient_RefusesBadIDToken(t *testing.T) {
	w := newWorld(t, listed)
	_, loc, st := w.atCallback()
	ctx := context.Background()
	tok, err := w.app.exchangeCode(ctx, loc.Query().Get("code"), st.Verifier)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := w.app.verifyIDToken(ctx, tok.IDToken, st.Nonce); err != nil || c.Email != listed {
		t.Fatalf("the real token must verify: %+v %v", c, err)
	}
	parts := strings.Split(tok.IDToken, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	altered := strings.Join([]string{parts[0], base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(payload), listed, "boss@example.com", 1))), parts[2]}, ".")
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	forged := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(other, []byte(parts[0]+"."+parts[1])))
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + parts[1] + "."
	late := *w.app
	late.cfg.Now = func() time.Time { return time.Now().Add(24 * time.Hour) }
	cases := map[string]error{
		"altered claims":   func() error { _, err := w.app.verifyIDToken(ctx, altered, st.Nonce); return err }(),
		"another key":      func() error { _, err := w.app.verifyIDToken(ctx, forged, st.Nonce); return err }(),
		"another nonce":    func() error { _, err := w.app.verifyIDToken(ctx, tok.IDToken, random()); return err }(),
		"expired":          func() error { _, err := late.verifyIDToken(ctx, tok.IDToken, st.Nonce); return err }(),
		"alg none":         func() error { _, err := w.app.verifyIDToken(ctx, none, st.Nonce); return err }(),
		"not a JWT at all": func() error { _, err := w.app.verifyIDToken(ctx, "x.y", st.Nonce); return err }(),
	}
	for name, err := range cases {
		if !errors.Is(err, errBadIDToken) {
			t.Errorf("%s: %v, want errBadIDToken", name, err)
		}
	}
}

// recorder wraps the test network: it counts token endpoint calls and,
// while trace is on, logs each request and answer (go test -v shows it).
func (w *world) recorder(who string) http.RoundTripper {
	return roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == oauthprovider.DefaultBasePath+"/token" {
			w.tokens.Add(1)
		}
		var form string
		if r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(strings.NewReader(string(b)))
			form = string(b)
		}
		res, err := w.net.RoundTrip(r)
		if err != nil || !w.trace {
			return res, err
		}
		var out strings.Builder
		fmt.Fprintf(&out, "%s: %s %s\n", who, r.Method, splitURL(r.URL.String()))
		if c := r.Header.Get("Cookie"); c != "" {
			fmt.Fprintf(&out, "    Cookie: %s\n", cookieNames(c))
		}
		if r.Header.Get("Authorization") != "" {
			fmt.Fprintf(&out, "    Authorization: Basic base64(client_id:client_secret)\n")
		}
		if form != "" {
			q, _ := url.ParseQuery(form)
			fmt.Fprintf(&out, "    form:%s\n", params(q))
		}
		fmt.Fprintf(&out, "  ← %s\n", res.Status)
		if l := res.Header.Get("Location"); l != "" {
			fmt.Fprintf(&out, "    Location: %s\n", splitURL(l))
		}
		for _, c := range res.Cookies() {
			fmt.Fprintf(&out, "    Set-Cookie: %s=%s (Max-Age %d)\n", c.Name, short(c.Value), c.MaxAge)
		}
		if strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") {
			b, _ := io.ReadAll(res.Body)
			res.Body = io.NopCloser(strings.NewReader(string(b)))
			fmt.Fprintf(&out, "    body: %s\n", jsonShort(b))
		}
		w.t.Log("\n" + out.String())
		return res, nil
	})
}

// roundTrip adapts a function to http.RoundTripper.
type roundTrip func(*http.Request) (*http.Response, error)

// RoundTrip runs the function.
func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// short cuts every query value and long string to traceMax characters.
func short(s string) string {
	if len(s) <= traceMax {
		return s
	}
	return s[:traceMax] + "…"
}

// splitURL prints a URL's path, then each query parameter on its own line
// with long values shortened.
func splitURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery == "" {
		return raw
	}
	q := u.Query()
	u.RawQuery = ""
	return u.String() + params(q)
}

// params prints form or query values one per line, in key order, with the
// signed-query bookkeeping of the login server's pages left out.
func params(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		if !strings.HasPrefix(k, "ba_") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "\n        %s=%s", k, short(q.Get(k)))
	}
	if len(keys) < len(q) {
		b.WriteString("\n        ba_…  (the login server's signature over the query)")
	}
	return b.String()
}

// jsonShort prints a JSON object with long string values shortened, and
// decodes an id_token so the trace shows its header and claims.
func jsonShort(b []byte) string {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return short(string(b))
	}
	var out strings.Builder
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v, _ := json.Marshal(m[k])
		fmt.Fprintf(&out, "\n        %s: %s", k, short(string(v)))
	}
	if tok, ok := m["id_token"].(string); ok {
		parts := strings.Split(tok, ".")
		h, _ := base64.RawURLEncoding.DecodeString(parts[0])
		p, _ := base64.RawURLEncoding.DecodeString(parts[1])
		fmt.Fprintf(&out, "\n      id_token header: %s\n      id_token claims: %s", h, p)
	}
	return out.String()
}

// cookieNames lists the names of a Cookie header, not the values.
func cookieNames(h string) string {
	var names []string
	for _, kv := range strings.Split(h, "; ") {
		name, _, _ := strings.Cut(kv, "=")
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}

// testCertificate is a self-signed certificate for both hosts, and the
// pool that trusts it.
func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, DNSNames: []string{loginHost, wikiHost},
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
