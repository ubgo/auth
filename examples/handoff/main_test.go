package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/handoff"
	"github.com/ubgo/auth/plugin/password"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery"
)

// TestHandoff_WebSessionToBearerClient: the browser signs up, mints a token,
// and a second client with no cookies exchanges it for a bearer session that
// reaches /me; the token works once, and both sessions stay independent.
func TestHandoff_WebSessionToBearerClient(t *testing.T) {
	a := newTestAuth(t)
	srv := httptest.NewTLSServer(newHandler(a))
	t.Cleanup(srv.Close)
	web := newBrowser(t, srv)

	up := do[password.SignInResult](t, web, http.MethodPost, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword}, nil, http.StatusOK)
	gen := do[handoff.GenerateResult](t, web, http.MethodPost, "/auth/handoff/generate", fields{}, nil, http.StatusOK)
	if gen.Token == "" || gen.ExpiresAt.IsZero() {
		t.Fatalf("generate = %+v", gen)
	}

	// The "app": a client with no cookie jar, asking for a bearer token.
	app := &browser{srv: srv, client: srv.Client()}
	bearer := map[string]string{authhttp.TokenModeHeader: authhttp.TokenModeBearer}
	res, headers := doRaw(t, app, http.MethodPost, "/auth/handoff/verify", fields{"token": gen.Token}, bearer, http.StatusOK)
	var got handoff.VerifyResult
	if err := json.Unmarshal(res, &got); err != nil || got.User.ID != up.User.ID {
		t.Fatalf("verify = %s %v", res, err)
	}
	token := headers.Get(authhttp.SetTokenHeader)
	if token == "" {
		t.Fatal("a bearer client must receive Set-Auth-Token")
	}
	me := do[meResponse](t, app, http.MethodGet, "/me", nil, map[string]string{"Authorization": "Bearer " + token}, http.StatusOK)
	if me.ID != up.User.ID {
		t.Fatalf("/me as the app = %+v", me)
	}
	spent := do[errorAnswer](t, app, http.MethodPost, "/auth/handoff/verify", fields{"token": gen.Token}, bearer, http.StatusBadRequest)
	if spent.Error.Code != auth.ErrTokenInvalid.Code {
		t.Fatalf("a token used twice = %+v", spent.Error)
	}
	// The web session is untouched by the hand-off, and signing out of it
	// leaves the app's session working.
	do[meResponse](t, web, http.MethodGet, "/me", nil, nil, http.StatusOK)
	do[struct{}](t, web, http.MethodPost, "/auth/sign-out", fields{}, nil, http.StatusOK)
	do[meResponse](t, app, http.MethodGet, "/me", nil, map[string]string{"Authorization": "Bearer " + token}, http.StatusOK)
}

// newTestAuth builds the app's Auth on a fresh SQLite file.
func newTestAuth(t *testing.T) *auth.Auth {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, err := newAuth(db, logMailer{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
}

// browser is a client against the test server; the web one has a cookie jar.
type browser struct {
	srv    *httptest.Server
	client *http.Client
}

// newBrowser is a client with a cookie jar, like a browser on the app. The
// server is TLS because the session cookie is __Host- and Secure.
func newBrowser(t *testing.T, srv *httptest.Server) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.Jar = jar
	return &browser{srv: srv, client: client}
}

// fields is a JSON request body as a client writes it.
type fields map[string]string

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// do sends a request with the app's Origin and extra headers, checks the
// status and decodes the answer as Out.
func do[Out any](t *testing.T, b *browser, method, path string, in fields, headers map[string]string, status int) Out {
	t.Helper()
	raw, _ := doRaw(t, b, method, path, in, headers, status)
	var out Out
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s %s: decode %q: %v", method, path, raw, err)
		}
	}
	return out
}

// doRaw is do without decoding: the body and the response headers.
func doRaw(t *testing.T, b *browser, method, path string, in fields, headers map[string]string, status int) ([]byte, http.Header) {
	t.Helper()
	var body *bytes.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(raw)
	} else {
		body = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, b.srv.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
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
		t.Fatalf("%s %s: status %d, want %d: %s", method, path, res.StatusCode, status, buf.String())
	}
	return buf.Bytes(), res.Header
}
