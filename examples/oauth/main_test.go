package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
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
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	// The fake issuer's client credentials and the one code it hands out.
	testClientID     = "example-client"
	testClientSecret = "example-secret"
	testCode         = "the-code"
	testAccessToken  = "the-access-token"
)

// TestOAuth_NewPersonGetsAnAccount runs the whole redirect dance against a
// fake OpenID Connect issuer configured the way main configures one, from
// OIDC_* variables: start, the provider's consent, the callback, and the
// session it leaves behind.
func TestOAuth_NewPersonGetsAnAccount(t *testing.T) {
	idp := newFakeIssuer(t)
	idp.profile = userInfo{Sub: "idp-1", Email: "carol@example.com", EmailVerified: true, Name: "Carol"}
	a, _ := newTestAuth(t, idp)
	b := newBrowser(t, newHandler(a, providersFromEnv(idp.env)))

	b.signInWithProvider(t, "/me")
	got := get[meResponse](t, b, "/me", http.StatusOK)
	if got.Name != "Carol" || got.ID == "" {
		t.Fatalf("/me = %+v", got)
	}
	if !idp.pkceChecked {
		t.Fatal("the token request carried no PKCE verifier matching the challenge")
	}

	// The same person again is the same account.
	b2 := newBrowser(t, newHandler(a, providersFromEnv(idp.env)))
	b2.signInWithProvider(t, "/me")
	if again := get[meResponse](t, b2, "/me", http.StatusOK); again.ID != got.ID {
		t.Fatalf("second sign-in created user %s, want %s", again.ID, got.ID)
	}
}

// TestOAuth_VerifiedAddressLinksToTheExistingAccount: someone who signed up
// with a password and verified their address, then signs in with a provider
// that vouches for the same address, lands in the same account. An address
// the provider does not vouch for is refused rather than linked.
func TestOAuth_VerifiedAddressLinksToTheExistingAccount(t *testing.T) {
	idp := newFakeIssuer(t)
	a, box := newTestAuth(t, idp)
	h := newHandler(a, providersFromEnv(idp.env))

	pw := newBrowser(t, h)
	post[none](t, pw, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)
	post[none](t, pw, "/auth/email/verify", fields{"token": box.lastToken(t, a, testEmail)}, http.StatusOK)
	owner := get[meResponse](t, pw, "/me", http.StatusOK)

	idp.profile = userInfo{Sub: "idp-2", Email: testEmail, EmailVerified: false, Name: "Mallory"}
	refused := newBrowser(t, h)
	cb := refused.throughProvider(t, "/me")
	if e := get[errorAnswer](t, refused, cb, http.StatusConflict); e.Error.Code != oauth.ErrAccountExists.Code {
		t.Fatalf("unverified provider address: %+v", e.Error)
	}

	idp.profile = userInfo{Sub: "idp-3", Email: testEmail, EmailVerified: true, Name: "Alice"}
	linked := newBrowser(t, h)
	linked.signInWithProvider(t, "/me")
	if got := get[meResponse](t, linked, "/me", http.StatusOK); got.ID != owner.ID {
		t.Fatalf("provider sign-in reached user %s, want the password account %s", got.ID, owner.ID)
	}
}

// TestOAuth_NoProvidersNoStart: with no variables set, no provider is built,
// and the library refuses the configuration instead of serving a sign-in
// page with nothing on it.
func TestOAuth_NoProvidersNoStart(t *testing.T) {
	if got := providersFromEnv(func(string) string { return "" }); len(got) != 0 {
		t.Fatalf("providers from an empty environment = %d", len(got))
	}
	if _, err := newAuth(openTestDB(t), &mailbox{}, nil); err == nil || !strings.Contains(err.Error(), oauth.ErrNoProviders.Error()) {
		t.Fatalf("newAuth with no providers: %v", err)
	}
}

// signInWithProvider runs start, consent and callback, and checks the
// callback lands on returnTo with a session cookie.
func (b *browser) signInWithProvider(t *testing.T, returnTo string) {
	t.Helper()
	cb := b.throughProvider(t, returnTo)
	if loc := b.redirect(t, cb); loc != returnTo {
		t.Fatalf("callback redirected to %q, want %q", loc, returnTo)
	}
	if !b.hasCookie(authhttp.CookieName) {
		t.Fatal("callback set no session cookie")
	}
}

// throughProvider starts a flow and follows the provider's consent redirect,
// returning the app's callback path and query. The callback URL names
// baseURL, where main would be listening; the test server is elsewhere, so
// only its path and query are kept.
func (b *browser) throughProvider(t *testing.T, returnTo string) string {
	t.Helper()
	consent := b.redirect(t, "/auth/oauth/"+oidcProviderName+"/start?returnTo="+url.QueryEscape(returnTo))
	back, err := url.Parse(b.redirect(t, consent))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(back.String(), callbackURL(oidcProviderName)) {
		t.Fatalf("the provider sent the browser to %s, not the registered callback", back)
	}
	return back.RequestURI()
}

// userInfo is the fake issuer's userinfo answer.
type userInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

// discovery is the fake issuer's discovery document.
type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

// tokenAnswer is the fake issuer's token endpoint answer.
type tokenAnswer struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error,omitempty"`
}

// fakeIssuer is an OpenID Connect issuer on httptest: discovery, an
// authorize endpoint that consents at once, a token endpoint that checks the
// client secret and PKCE, and userinfo answering with profile.
type fakeIssuer struct {
	srv *httptest.Server

	mu          sync.Mutex
	profile     userInfo
	challenge   string
	pkceChecked bool
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, discovery{Issuer: f.srv.URL, AuthorizationEndpoint: f.srv.URL + "/authorize", TokenEndpoint: f.srv.URL + "/token", UserinfoEndpoint: f.srv.URL + "/userinfo"})
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		f.challenge = q.Get("code_challenge")
		f.mu.Unlock()
		back := q.Get("redirect_uri") + "?code=" + testCode + "&state=" + url.QueryEscape(q.Get("state"))
		http.Redirect(w, r, back, http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("client_secret") != testClientSecret || r.Form.Get("code") != testCode {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, tokenAnswer{Error: "invalid_grant"})
			return
		}
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		f.mu.Lock()
		f.pkceChecked = base64.RawURLEncoding.EncodeToString(sum[:]) == f.challenge
		ok := f.pkceChecked
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, tokenAnswer{Error: "invalid_grant"})
			return
		}
		writeJSON(w, tokenAnswer{AccessToken: testAccessToken})
	})
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testAccessToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		p := f.profile
		f.mu.Unlock()
		writeJSON(w, p)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// env is the environment main would see with this issuer configured.
func (f *fakeIssuer) env(name string) string {
	return map[string]string{envOIDCIssuer: f.srv.URL, envOIDCID: testClientID, envOIDCSecret: testClientSecret}[name]
}

// writeJSON answers v as JSON for the fake issuer.
func writeJSON[T any](w http.ResponseWriter, v T) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

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

// newTestAuth builds the app's Auth with the fake issuer as its provider,
// migrated, with a mailbox that records mail.
func newTestAuth(t *testing.T, idp *fakeIssuer) (*auth.Auth, *mailbox) {
	t.Helper()
	box := &mailbox{}
	a, err := newAuth(openTestDB(t), box, providersFromEnv(idp.env))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, box
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

// lastToken returns the token of the newest link mailed to addr. Mail goes
// out after the transaction commits, so it waits for deliveries first.
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

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would, and does not follow redirects, so each
// step of the provider dance is checked.
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
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &browser{srv: srv, client: client, origin: baseURL}
}

// fields is a JSON request body as a client writes it. The library's own
// request types are not used to send: their secrets (auth.Token) encode as
// "[redacted]" on purpose, so a logged struct never leaks one.
type fields map[string]string

// none is the request body of a route that takes no input, and the answer
// of a call whose body the test does not read.
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

// hasCookie reports whether the jar holds a cookie called name for the server.
func (b *browser) hasCookie(name string) bool {
	u, _ := url.Parse(b.srv.URL)
	for _, c := range b.client.Jar.Cookies(u) {
		if c.Name == name && c.Value != "" {
			return true
		}
	}
	return false
}
