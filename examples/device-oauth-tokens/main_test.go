package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth/plugin/deviceauth"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	testName     = "Alice"
)

// userCodeIn finds the user code in what the CLI printed.
var userCodeIn = regexp.MustCompile(`enter the code (\S+)`)

// TestDeviceOAuth_CLIGetsTokens: the registered CLI asks for a code, a
// signed-in browser approves it, and the poll returns access, refresh and
// ID tokens for the approving user; the refresh token refreshes.
func TestDeviceOAuth_CLIGetsTokens(t *testing.T) {
	srv, web, app := newTestServer(t)
	ctx := context.Background()
	reg, err := registerCLI(ctx, app.op)
	if err != nil {
		t.Fatal(err)
	}

	// Discovery advertises the device authorization endpoint.
	var disc map[string]json.RawMessage
	getJSON(t, web, "/.well-known/openid-configuration", &disc)
	if string(disc["device_authorization_endpoint"]) != `"`+baseURL+codePath+`"` {
		t.Fatalf("discovery = %s", disc["device_authorization_endpoint"])
	}

	var out bytes.Buffer
	polls := 0
	c := cli{CodeURL: srv.URL + codePath, TokenURL: srv.URL + "/oauth2/token", ClientID: reg.ClientID, HTTP: cliClient(srv),
		Wait: func(context.Context, time.Duration) error {
			// The CLI's wait before its first poll is where the person
			// approves: the test's browser does it there, so the first poll
			// finds the approval. A poll sooner than the interval would be
			// refused, and this wait does not really wait.
			if polls++; polls == 1 {
				code := userCodeIn.FindStringSubmatch(out.String())
				if code == nil {
					t.Fatalf("no code printed: %s", out.String())
				}
				var v deviceauth.VerifyResult
				getJSON(t, web, authPrefix+"/device/verify?user_code="+url.QueryEscape(code[1]), &v)
				if v.ClientID != reg.ClientID || v.Status != deviceauth.StatusPending {
					t.Errorf("lookup = %+v", v)
				}
				web.post(t, authPrefix+"/device/approve", map[string]string{"userCode": code[1]}, http.StatusOK)
			}
			return nil
		}}
	tok, err := c.login(ctx, &out)
	if err != nil {
		t.Fatalf("login: %v\n%s", err, out.String())
	}
	if polls != 1 || tok.AccessToken == "" || tok.RefreshToken == "" || tok.IDToken == "" || tok.Scope != cliScope {
		t.Fatalf("after %d polls: %+v", polls, tok)
	}
	if !strings.HasPrefix(out.String(), "open "+baseURL+"/device and enter the code ") {
		t.Fatalf("the CLI printed: %s", out.String())
	}

	// The ID token names the CLI as its audience and Alice as its subject.
	var keys jwt.JWKS
	getJSON(t, web, "/oauth2/jwks", &keys)
	idt, err := jwt.Verifier{Keys: jwt.KeysFromJWKS(keys), Issuer: baseURL, Audience: reg.ClientID}.Verify(tok.IDToken)
	if err != nil {
		t.Fatalf("id token: %v", err)
	}
	at, err := app.op.VerifyAccessToken(ctx, tok.AccessToken)
	if err != nil || at.ClientID != reg.ClientID || at.UserID != idt.Subject {
		t.Fatalf("access token = %+v %v", at, err)
	}

	// The refresh token works at the same endpoint.
	res, body := web.form(t, "/oauth2/token", url.Values{"grant_type": {oauthprovider.GrantRefreshToken}, "refresh_token": {tok.RefreshToken}, "client_id": {reg.ClientID}})
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `"access_token"`) {
		t.Fatalf("refresh = %d %s", res.StatusCode, body)
	}
}

// TestDeviceOAuth_CodesAreBoundToTheProvider: a code issued to an OAuth
// client is never redeemed for a session at deviceauth's own /device/token.
func TestDeviceOAuth_CodesAreBoundToTheProvider(t *testing.T) {
	srv, _, app := newTestServer(t)
	reg, err := registerCLI(context.Background(), app.op)
	if err != nil {
		t.Fatal(err)
	}
	dc := &deviceauth.Client{CodeURL: srv.URL + codePath, TokenURL: srv.URL + "/oauth2/token", ClientID: reg.ClientID, HTTP: cliClient(srv)}
	code, err := dc.RequestCode(context.Background(), cliScope)
	if err != nil {
		t.Fatal(err)
	}
	// Before the person decides, the provider answers authorization_pending.
	c := cli{TokenURL: srv.URL + "/oauth2/token", ClientID: reg.ClientID, HTTP: cliClient(srv)}
	if _, pending, err := c.redeem(context.Background(), code.DeviceCode); err != nil || pending != rfcAuthorizationPending {
		t.Fatalf("first poll = %q %v", pending, err)
	}
	// deviceauth's own token route refuses the code: it is bound to the
	// provider's grant.
	raw, err := json.Marshal(deviceauth.TokenRequest{GrantType: deviceauth.GrantType, DeviceCode: code.DeviceCode, ClientID: reg.ClientID})
	if err != nil {
		t.Fatal(err)
	}
	res, err := cliClient(srv).Post(srv.URL+authPrefix+"/device/token", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(buf.String(), deviceauth.ErrInvalidDeviceCode.Code) {
		t.Fatalf("/device/token = %d %s", res.StatusCode, buf.String())
	}
}

// newTestServer serves the app over TLS (the session cookie is __Host- and
// Secure) and returns a signed-in browser for Alice.
func newTestServer(t *testing.T) (*httptest.Server, *browser, app) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ap, err := newAuth(db, logMailer{}, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ap.a.Close() })
	if _, err := ap.a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(newHandler(ap))
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: srv.Client().Transport, Jar: jar}
	web := &browser{srv: srv, client: client}
	web.post(t, authPrefix+"/password/sign-up", map[string]string{"identifier": testEmail, "password": testPassword, "name": testName}, http.StatusOK)
	return srv, web, ap
}

// cliClient is the CLI's HTTP client: it trusts the test server's
// certificate and, unlike the browser, holds no cookies. A cookie on a
// cross-site POST is what the CSRF check refuses.
func cliClient(srv *httptest.Server) *http.Client {
	return &http.Client{Transport: srv.Client().Transport}
}

// browser is a client with a cookie jar that sends the app's Origin.
type browser struct {
	srv    *httptest.Server
	client *http.Client
}

// post sends in as JSON and fails unless the answer has status.
func (b *browser) post(t *testing.T, path string, in map[string]string, status int) {
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
	res, body := b.do(t, req)
	if res.StatusCode != status {
		t.Fatalf("POST %s: %d %s, want %d", path, res.StatusCode, body, status)
	}
}

// form posts a form, as an OAuth client does.
func (b *browser) form(t *testing.T, path string, form url.Values) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, b.srv.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.do(t, req)
}

// getJSON GETs path and decodes a 200 answer into out.
func getJSON[Out any](t *testing.T, b *browser, path string, out *Out) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, body := b.do(t, req)
	if res.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), out) != nil {
		t.Fatalf("GET %s: %d %s", path, res.StatusCode, body)
	}
}

// do sends req and returns the response with its body read, so a caller
// can check any status, including a refusal.
func (b *browser) do(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	return res, buf.String()
}
