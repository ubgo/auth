package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/sso"
	"github.com/ubgo/auth/plugin/sso/ssotest"
)

const (
	// testSecret is AUTH_SECRET for the tests: 32 bytes, as auth.WithSecret requires.
	testSecret   = "an example secret of 32 bytes!!!"
	testPassword = "correct horse battery staple"
	// The SAML provider's company and the IdP's entity id.
	samlDomain = "globex.test"
	samlIdP    = "https://idp.globex.test"
)

// samlSP is the SP entity id the admin chooses for the SAML provider.
var samlSP = baseURL + "/sp/globex"

// TestSSO_OIDCSignInByWorkEmail runs the whole OpenID Connect round trip
// against ssotest's fake IdP configured the way main configures one, from
// SSO_* variables: the work email picks the provider, the IdP authenticates,
// the callback signs the person in, and a second sign-in reaches the same
// account.
func TestSSO_OIDCSignInByWorkEmail(t *testing.T) {
	idp := ssotest.NewOIDC(t)
	idp.Person = ssotest.Person{Subject: "okta-ada", Email: "ada@acme.test", EmailVerified: true, Name: "Ada Lovelace"}
	env := map[string]string{envSSOIssuer: idp.Issuer(), envSSOClientID: idp.ClientID, envSSOSecret: idp.ClientSecret, envSSODomain: "acme.test"}
	pr, ok := providerFromEnv(func(k string) string { return env[k] })
	if !ok {
		t.Fatal("providerFromEnv built no provider from a full environment")
	}
	a := newTestAuth(t, []sso.Provider{pr}, sso.WithTrustedOrigins(idp.URL))
	h := newHandler(a)

	first := newBrowser(t, h)
	first.signInOIDC(t, idp, "ada@acme.test")
	got := get[meResponse](t, first, "/me", http.StatusOK)
	if got.Name != "Ada Lovelace" || got.ID == "" {
		t.Fatalf("/me = %+v", got)
	}

	again := newBrowser(t, h)
	again.signInOIDC(t, idp, "ada@acme.test")
	if second := get[meResponse](t, again, "/me", http.StatusOK); second.ID != got.ID {
		t.Fatalf("second sign-in reached user %s, want %s", second.ID, got.ID)
	}
}

// TestSSO_SAMLProviderRegisteredAtRunTime: a signed-in admin registers a
// customer's SAML IdP over HTTP, without a deploy, and that company's people
// then sign in through it: AuthnRequest out, signed assertion posted back to
// the ACS, session in.
func TestSSO_SAMLProviderRegisteredAtRunTime(t *testing.T) {
	idp := ssotest.NewSAMLIdP(t, samlIdP)
	a := newTestAuth(t, nil)
	h := newHandler(a)

	admin := newBrowser(t, h)
	post[none](t, admin, "/auth/password/sign-up", fields{"identifier": "admin@example.com", "password": testPassword}, http.StatusOK)
	reg := post[sso.SanitizedProvider](t, admin, "/auth/sso/register", sso.RegisterRequest{
		ProviderID: "globex", Issuer: samlSP, Domain: samlDomain,
		SAMLConfig: &sso.SAMLConfig{EntryPoint: idp.SSOURL, Cert: idp.CertPEM, WantAssertionsSigned: true,
			IdPMetadata: sso.IdPMetadata{EntityID: idp.EntityID}, SPMetadata: sso.SPMetadata{EntityID: samlSP}},
	}, http.StatusOK)
	if reg.ACSURL != baseURL+"/auth/sso/saml2/sp/acs" {
		t.Fatalf("registration answered ACS URL %q", reg.ACSURL)
	}

	person := newBrowser(t, h)
	start := post[sso.SignInResult](t, person, "/auth/sso/sign-in", fields{"email": "bob@" + samlDomain, "callbackURL": "/me"}, http.StatusOK)
	reqID, acs, relay := ssotest.AuthnRequest(t, start.URL)
	if acs != reg.ACSURL {
		t.Fatalf("AuthnRequest names ACS %q, want %q", acs, reg.ACSURL)
	}
	answer := idp.Response(idp.Valid(acs, samlSP, reqID, "bob@"+samlDomain))
	if loc := person.postForm(t, "/auth/sso/saml2/sp/acs", url.Values{"SAMLResponse": {answer}, "RelayState": {relay}}); loc != "/me" {
		t.Fatalf("ACS redirected to %q, want /me", loc)
	}
	if got := get[meResponse](t, person, "/me", http.StatusOK); got.ID == "" {
		t.Fatalf("/me after SAML = %+v", got)
	}
}

// TestSSO_Refusals: registering a provider needs a signed-in user, an
// address no provider serves is told so, and a configuration missing a
// variable builds no provider rather than a broken one.
func TestSSO_Refusals(t *testing.T) {
	a := newTestAuth(t, nil)
	b := newBrowser(t, newHandler(a))

	e := post[errorAnswer](t, b, "/auth/sso/register", sso.RegisterRequest{ProviderID: "x", Issuer: "https://x.test", Domain: "x.test",
		OIDCConfig: &sso.OIDCConfig{ClientID: "id", ClientSecret: "secret"}}, http.StatusUnauthorized)
	if e.Error.Code != auth.ErrSignedOut.Code {
		t.Fatalf("anonymous register: %+v", e.Error)
	}
	e = post[errorAnswer](t, b, "/auth/sso/sign-in", fields{"email": "eve@nowhere.test"}, http.StatusNotFound)
	if e.Error.Code != sso.ErrProviderNotFound.Code {
		t.Fatalf("unknown domain: %+v", e.Error)
	}
	if _, ok := providerFromEnv(func(k string) string {
		return map[string]string{envSSOIssuer: "https://x.test", envSSOClientID: "id", envSSOSecret: "s"}[k]
	}); ok {
		t.Fatal("a provider was built without SSO_DOMAIN")
	}
}

// signInOIDC starts SSO from addr, plays the person at the IdP and follows
// the callback, which must land on /me with a session cookie.
func (b *browser) signInOIDC(t *testing.T, idp *ssotest.OIDC, addr string) {
	t.Helper()
	start := post[sso.SignInResult](t, b, "/auth/sso/sign-in", fields{"email": addr, "callbackURL": "/me"}, http.StatusOK)
	if !start.Redirect || !strings.HasPrefix(start.URL, idp.URL+"/authorize") {
		t.Fatalf("sign-in answered %+v, want a redirect to the IdP", start)
	}
	q := idp.Authorize(t, start.URL)
	if loc := b.redirect(t, "/auth/sso/callback?"+q.Encode()); loc != "/me" {
		t.Fatalf("callback redirected to %q, want /me", loc)
	}
	if !b.hasCookie(authhttp.CookieName) {
		t.Fatal("callback set no session cookie")
	}
}

// newTestAuth builds the app's Auth on a fresh SQLite file, migrated.
func newTestAuth(t *testing.T, providers []sso.Provider, opts ...sso.Option) *auth.Auth {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, err := newAuth(db, []byte(testSecret), discard{}, providers, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
}

// discard drops mail; no step here sends any that the test reads.
type discard struct{}

func (discard) Send(context.Context, email.Mail) error { return nil }

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would, and does not follow redirects. HTTPS,
// because the session and flow cookies are __Host- and Secure.
type browser struct {
	srv    *httptest.Server
	client *http.Client
}

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
	return &browser{srv: srv, client: client}
}

// fields is a JSON request body as a client writes it.
type fields map[string]string

// none is the answer of a call whose body the test does not read.
type none struct{}

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// redirect gets path, checks the answer is a 302 and returns its Location.
func (b *browser) redirect(t *testing.T, path string) string {
	t.Helper()
	res, err := b.client.Get(b.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	return wantFound(t, res)
}

// postForm posts form as the IdP's auto-submitting page does: a cross-site
// form, so no Origin of this app. It checks for a 302 and returns Location.
func (b *browser) postForm(t *testing.T, path string, form url.Values) string {
	t.Helper()
	res, err := b.client.PostForm(b.srv.URL+path, form)
	if err != nil {
		t.Fatal(err)
	}
	return wantFound(t, res)
}

func wantFound(t *testing.T, res *http.Response) string {
	t.Helper()
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("%s %s: status %d, want 302: %s", res.Request.Method, res.Request.URL.Path, res.StatusCode, buf.String())
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
