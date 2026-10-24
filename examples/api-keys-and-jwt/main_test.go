package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/password"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	testName     = "Alice"
)

// TestAPIKeys_ScopesDecideWhatAScriptMayDo: a person signs in, mints a
// read-only key and a read-write key, and a script with no cookies uses them
// on the app's API. Each route checks its own scope, a browser session is not
// a key, a key cannot manage the account, and a revoked key stops working.
func TestAPIKeys_ScopesDecideWhatAScriptMayDo(t *testing.T) {
	a := newTestAuth(t, testKey(t))
	b := newBrowser(t, newHandler(a, newOrders()))
	user := post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword, "name": testName}, http.StatusOK).User

	readOnly := post[apikey.CreateResult](t, b, "/auth/apikey/create", apikey.CreateRequest{Name: "dashboard", Scopes: []string{scopeOrdersRead}}, http.StatusOK)
	readWrite := post[apikey.CreateResult](t, b, "/auth/apikey/create", apikey.CreateRequest{Name: "importer", Scopes: []string{scopeOrdersRead, scopeOrdersWrite}}, http.StatusOK)
	if !strings.HasPrefix(readOnly.Secret, apikey.DefaultPrefix) || readOnly.Key.Hint == "" {
		t.Fatalf("created key = %+v", readOnly.Key)
	}
	if e := post[errorAnswer](t, b, "/auth/apikey/create", apikey.CreateRequest{Name: "typo", Scopes: []string{"orders:delete"}}, http.StatusBadRequest); e.Error.Code != apikey.ErrUnknownScope.Code {
		t.Fatalf("an undeclared scope: %+v", e.Error)
	}

	script := b.as(readWrite.Secret)
	if row := post[order](t, script, "/api/orders", newOrderRequest{Item: "coffee beans"}, http.StatusCreated); row.Item != "coffee beans" {
		t.Fatalf("new order = %+v", row)
	}
	list := get[ordersResult](t, b.as(readOnly.Secret), "/api/orders", http.StatusOK)
	if list.UserID != user.ID || len(list.Orders) != 1 {
		t.Fatalf("orders through the read-only key = %+v", list)
	}
	if e := post[errorAnswer](t, b.as(readOnly.Secret), "/api/orders", newOrderRequest{Item: "more"}, http.StatusForbidden); e.Error.Code != authhttp.ErrMissingScope.Code {
		t.Fatalf("writing with a read-only key: %+v", e.Error)
	}

	// The API is for keys: the browser's own session is refused there.
	get[errorAnswer](t, b, "/api/orders", http.StatusForbidden)
	// And a key cannot act on the account, such as minting more keys.
	if e := post[errorAnswer](t, script, "/auth/apikey/create", apikey.CreateRequest{Name: "more", Scopes: []string{scopeOrdersRead}}, http.StatusForbidden); e.Error.Code != auth.ErrAPIKeyRefused.Code {
		t.Fatalf("minting a key with a key: %+v", e.Error)
	}

	post[none](t, b, "/auth/apikey/revoke", fields{"id": readWrite.Key.ID}, http.StatusOK)
	get[errorAnswer](t, script, "/api/orders", http.StatusUnauthorized)
}

// TestJWT_AnotherServiceVerifiesWithThePublishedKeys: the signed-in person
// asks for a JWT; the report service, built only from the published key set,
// accepts it and learns who the caller is, and refuses a token that was
// tampered with or is missing.
func TestJWT_AnotherServiceVerifiesWithThePublishedKeys(t *testing.T) {
	a := newTestAuth(t, testKey(t))
	b := newBrowser(t, newHandler(a, newOrders()))
	user := post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword, "name": testName}, http.StatusOK).User

	tok := post[jwt.TokenResult](t, b, "/auth/jwt/token", none{}, http.StatusOK)
	set := get[jwt.JWKS](t, b, jwksPath, http.StatusOK)
	reports := newBrowser(t, newReportService(jwt.Verifier{Keys: jwt.KeysFromJWKS(set), Issuer: baseURL, Audience: jwtAudience}))

	got := get[reportResult](t, reports.as(tok.Token), "/report", http.StatusOK)
	if got.Subject != user.ID || got.Name != testName || !got.ExpiresAt.Equal(tok.ExpiresAt.Truncate(time.Second)) {
		t.Fatalf("report = %+v, token expires %v", got, tok.ExpiresAt)
	}
	tampered := tamperSignature(tok.Token)
	get[reportError](t, reports.as(tampered), "/report", http.StatusUnauthorized)
	get[reportError](t, reports, "/report", http.StatusUnauthorized)

	// A token needs a session: a signed-out caller gets none.
	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)
	post[errorAnswer](t, b, "/auth/jwt/token", none{}, http.StatusUnauthorized)
}

// TestSigningKey_FromTheEnvironment: a set key is used as given, so every
// instance and every restart signs with it; a malformed one is refused.
func TestSigningKey_FromTheEnvironment(t *testing.T) {
	want := testKey(t)
	got, err := signingKey(func(string) string { return "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" })
	if err != nil || !got.Equal(want) {
		t.Fatalf("key from the environment: %v", err)
	}
	if _, err := signingKey(func(string) string { return "too-short" }); err == nil {
		t.Fatal("a malformed key was accepted")
	}
}

// testKey is the key whose seed is the bytes 0..31, the same value
// TestSigningKey_FromTheEnvironment passes as base64url.
func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// newTestAuth builds the app's Auth on a fresh SQLite file, migrated.
func newTestAuth(t *testing.T, key ed25519.PrivateKey) *auth.Auth {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, err := newAuth(db, email.MailerFunc(discardMail), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
}

// discardMail drops the verification mail sign-up sends; these tests do not
// read it.
func discardMail(context.Context, email.Mail) error { return nil }

// browser is an HTTPS test server and a client. A browser keeps cookies and
// sends the app's Origin; a script made with as sends a bearer token instead
// and has no cookies at all.
type browser struct {
	srv    *httptest.Server
	client *http.Client
	origin string
	bearer string
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

// as returns a script against the same server: no cookie jar, no Origin, and
// token in the Authorization header.
func (b *browser) as(token string) *browser {
	c := *b.client
	c.Jar = nil
	return &browser{srv: b.srv, client: &c, bearer: token}
}

// fields is a JSON request body as a client writes it. The library's request
// types that carry a secret (auth.Token) encode it as "[redacted]" on
// purpose, so those bodies are written as plain maps.
type fields map[string]string

// none is the request body of a route that takes no input, and the answer
// of a call whose body the test does not read.
type none struct{}

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// post sends in as JSON, checks the status and decodes the answer as Out.
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
	if b.origin != "" && req.Method == http.MethodPost {
		req.Header.Set("Origin", b.origin)
	}
	if b.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+b.bearer)
	}
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

// tamperSignature changes the first character of a token's signature. The
// first character carries six whole bits of the signature, so the result is
// always a different signature; changing the last character is not enough,
// because some of its bits are padding.
func tamperSignature(token string) string {
	i := strings.LastIndexByte(token, '.') + 1
	c := byte('A')
	if token[i] == c {
		c = 'B'
	}
	return token[:i] + string(c) + token[i+1:]
}
