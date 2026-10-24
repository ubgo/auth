package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	testName     = "Alice"
	testSecret   = "edge-shared-secret"
	// proxyAddr is the load balancer's connection address, inside proxyNetwork.
	proxyAddr = "10.0.0.5:41000"
	// strangerAddr connects from outside proxyNetwork.
	strangerAddr = "198.51.100.9:52000"
	// clientIP is the visitor's real address, as the proxy or edge reports it.
	clientIP = "203.0.113.7"
	// spoofedIP is what a client writes into a forwarded header itself.
	spoofedIP = "192.0.2.66"
)

// TestBehindProxy_ForwardedFromTheProxy: a sign-up that arrives through the
// load balancer is recorded with the address its Forwarded header names,
// from a plain HTML form body, and the session list shows it.
func TestBehindProxy_ForwardedFromTheProxy(t *testing.T) {
	c := newClient(t, testSecret)
	c.remote = proxyAddr
	c.header.Set(authhttp.HeaderForwarded, "for="+clientIP)

	c.signUpWithForm(t)
	if got := c.sessionIP(t); got != clientIP {
		t.Fatalf("session IP = %q, want %q", got, clientIP)
	}
}

// TestBehindProxy_StrangerCannotChooseItsAddress: the same headers from a
// connection outside the proxy network are ignored, so a client cannot pick
// an address to escape per-IP rate limits.
func TestBehindProxy_StrangerCannotChooseItsAddress(t *testing.T) {
	c := newClient(t, testSecret)
	c.remote = strangerAddr
	c.header.Set(authhttp.HeaderForwarded, "for="+spoofedIP)
	c.header.Set(forwardedForHeader, spoofedIP)

	c.signUpWithForm(t)
	if got, want := c.sessionIP(t), strings.Split(strangerAddr, ":")[0]; got != want {
		t.Fatalf("session IP = %q, want the connection's %q", got, want)
	}
}

// TestBehindProxy_SignedEdgeHeader: ClientIPFunc believes the edge's address
// when its signature checks out, and declines a forged one, which falls back
// to the connection's address.
func TestBehindProxy_SignedEdgeHeader(t *testing.T) {
	signed := newClient(t, testSecret)
	signed.remote = strangerAddr
	signed.header.Set(edgeIPHeader, clientIP)
	signed.header.Set(edgeSignatureHeader, hex.EncodeToString(signIP(testSecret, clientIP)))
	signed.signUpWithForm(t)
	if got := signed.sessionIP(t); got != clientIP {
		t.Fatalf("signed edge IP = %q, want %q", got, clientIP)
	}

	forged := newClient(t, testSecret)
	forged.remote = strangerAddr
	forged.header.Set(edgeIPHeader, spoofedIP)
	forged.header.Set(edgeSignatureHeader, hex.EncodeToString(signIP("guessed", spoofedIP)))
	forged.signUpWithForm(t)
	if got, want := forged.sessionIP(t), strings.Split(strangerAddr, ":")[0]; got != want {
		t.Fatalf("forged edge IP = %q, want the connection's %q", got, want)
	}
}

// TestBehindProxy_ProblemJSONInTheChosenLanguage: an error is an RFC 9457
// body under the library's status, its title in the language the auth_locale
// cookie names rather than the browser's list.
func TestBehindProxy_ProblemJSONInTheChosenLanguage(t *testing.T) {
	c := newClient(t, testSecret)
	c.header.Set("Accept-Language", "de")
	c.cookies = append(c.cookies, &http.Cookie{Name: authhttp.DefaultLocaleCookieName, Value: "fr"})

	res, body := c.do(t, http.MethodGet, "/me", nil, "")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != problemContentType {
		t.Fatalf("Content-Type = %q", ct)
	}
	var p problem
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatal(err)
	}
	if p.Code != auth.ErrSignedOut.Code || p.Status != http.StatusUnauthorized || p.Type != problemTypeBase+auth.ErrSignedOut.Code {
		t.Fatalf("problem = %+v", p)
	}
	if p.Title != "Connectez-vous pour continuer." {
		t.Fatalf("title = %q, want the French message", p.Title)
	}
}

// TestBehindProxy_PlatformRoutes: the health route answers without a
// database read, the OpenAPI document lists the routes, and a trailing slash
// reaches the same operation.
func TestBehindProxy_PlatformRoutes(t *testing.T) {
	c := newClient(t, testSecret)

	res, body := c.do(t, http.MethodGet, authPrefix+authhttp.HealthPath, nil, "")
	if res.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != `{"ok":true}` {
		t.Fatalf("health = %d %s", res.StatusCode, body)
	}

	res, body = c.do(t, http.MethodGet, authPrefix+authhttp.OpenAPIPath, nil, "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("openapi = %d", res.StatusCode)
	}
	var doc struct {
		OpenAPI string                     `json:"openapi"`
		Info    struct{ Title string }     `json:"info"`
		Paths   map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Info.Title != apiTitle || doc.Paths[authPrefix+"/password/sign-up"] == nil {
		t.Fatalf("openapi = %s, title %q, %d paths", doc.OpenAPI, doc.Info.Title, len(doc.Paths))
	}

	c.signUpWithForm(t)
	if res, body := c.do(t, http.MethodPost, authPrefix+"/sign-out/", strings.NewReader("{}"), "application/json"); res.StatusCode != http.StatusOK {
		t.Fatalf("sign-out with a trailing slash = %d %s", res.StatusCode, body)
	}
	if res, _ := c.do(t, http.MethodGet, "/me", nil, ""); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/me after sign-out = %d", res.StatusCode)
	}
}

// client drives the handler directly, so each request can come from a chosen
// connection address the way a request through a proxy does.
type client struct {
	h       http.Handler
	remote  string
	header  http.Header
	cookies []*http.Cookie
}

// newClient builds the app on a fresh SQLite file.
func newClient(t *testing.T, secret string) *client {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, err := newAuth(db, discardMailer{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &client{h: newHandler(a, secret), remote: "127.0.0.1:50000", header: http.Header{}}
}

// do sends one request with the client's address, headers and cookies, and
// keeps the cookies the answer sets.
func (c *client) do(t *testing.T, method, path string, body io.Reader, contentType string) (*http.Response, []byte) {
	t.Helper()
	req := httptest.NewRequest(method, baseURL+path, body)
	req.RemoteAddr = c.remote
	for k, v := range c.header {
		req.Header[k] = v
	}
	req.Header.Set("Origin", baseURL)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for _, ck := range c.cookies {
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	res := rec.Result()
	c.cookies = append(c.cookies, res.Cookies()...)
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, b
}

// signUpWithForm signs up the way a plain HTML form does: a form-encoded
// body, which AcceptForms lets the JSON route take.
func (c *client) signUpWithForm(t *testing.T) {
	t.Helper()
	form := url.Values{"identifier": {testEmail}, "password": {testPassword}, "name": {testName}}
	res, body := c.do(t, http.MethodPost, authPrefix+"/password/sign-up", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("form sign-up = %d %s", res.StatusCode, body)
	}
}

// sessionIP is the address the session list recorded for the current session.
func (c *client) sessionIP(t *testing.T) string {
	t.Helper()
	res, body := c.do(t, http.MethodGet, authPrefix+"/sessions", nil, "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sessions = %d %s", res.StatusCode, body)
	}
	var out auth.SessionsResult
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	for _, s := range out.Sessions {
		if s.Current {
			return s.IP
		}
	}
	t.Fatalf("no current session in %s", body)
	return ""
}

// discardMailer drops mail; these tests never open a link.
type discardMailer struct{}

// Send drops m.
func (discardMailer) Send(context.Context, email.Mail) error { return nil }
