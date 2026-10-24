package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	// testKeyHex is a fixed 32-byte key, so the test needs no randomness.
	testKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)

// TestSignOutEndsTheTokenAtOnce: with the list, a token copied before the
// sign-out is refused after it, while another session of the same user,
// which did not sign out, keeps working. No session row exists at any point.
func TestSignOutEndsTheTokenAtOnce(t *testing.T) {
	app := newTestApp(t, auth.NewMemorySessionRevocations())
	laptop := app.call(t, http.MethodPost, "/auth/password/sign-up", "", credentials(), http.StatusOK).Header.Get(authhttp.SetTokenHeader)
	phone := app.call(t, http.MethodPost, "/auth/password/sign-in", "", credentials(), http.StatusOK).Header.Get(authhttp.SetTokenHeader)
	if laptop == "" || phone == "" {
		t.Fatal("bearer sign-in returned no token")
	}
	app.call(t, http.MethodGet, "/me", laptop, nil, http.StatusOK)

	app.call(t, http.MethodPost, "/auth/sign-out", laptop, []byte("{}"), http.StatusOK)
	res := app.call(t, http.MethodGet, "/me", laptop, nil, http.StatusUnauthorized)
	var e errorAnswer
	if err := json.NewDecoder(res.Body).Decode(&e); err != nil || e.Error.Code != auth.ErrSignedOut.Code {
		t.Fatalf("revoked token answered %+v %v", e, err)
	}
	app.call(t, http.MethodGet, "/me", phone, nil, http.StatusOK)

	var rows int
	if err := app.db.QueryRow("SELECT count(*) FROM " + auth.TableNameSession).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("auth_session holds %d rows", rows)
	}
}

// TestWithoutTheListATokenOutlivesSignOut pins why the list exists: without
// it, sign-out answers ok but the token it was given still signs in.
func TestWithoutTheListATokenOutlivesSignOut(t *testing.T) {
	app := newTestApp(t, nil)
	tok := app.call(t, http.MethodPost, "/auth/password/sign-up", "", credentials(), http.StatusOK).Header.Get(authhttp.SetTokenHeader)
	app.call(t, http.MethodPost, "/auth/sign-out", tok, []byte("{}"), http.StatusOK)
	app.call(t, http.MethodGet, "/me", tok, nil, http.StatusOK)
}

// TestSessionKey: a set key must be 64 hex characters; unset makes one.
func TestSessionKey(t *testing.T) {
	if k, err := sessionKey(testKeyHex); err != nil || len(k) != auth.SealKeySize {
		t.Fatalf("sessionKey(valid) = %d bytes, %v", len(k), err)
	}
	if _, err := sessionKey("abc"); !errors.Is(err, errBadKey) {
		t.Fatalf("sessionKey(short) = %v", err)
	}
	if k, err := sessionKey(""); err != nil || len(k) != auth.SealKeySize {
		t.Fatalf("sessionKey(unset) = %d bytes, %v", len(k), err)
	}
}

// testApp is the app on httptest, with its database for the row check.
type testApp struct {
	srv *httptest.Server
	db  *sql.DB
}

// newTestApp builds and migrates the app with list (nil for none) on a
// fresh SQLite file.
func newTestApp(t *testing.T, list auth.SessionRevocations) *testApp {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	key, err := sessionKey(testKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	a, err := newAuth(db, sessionOptions(key, list))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newHandler(a))
	t.Cleanup(srv.Close)
	return &testApp{srv: srv, db: db}
}

// credentials is Alice's sign-up and sign-in body.
func credentials() []byte {
	raw, _ := json.Marshal(map[string]string{"identifier": testEmail, "password": testPassword}) // a map of strings always encodes
	return raw
}

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// call sends a bearer-mode request (the token in Authorization when set),
// checks the status and returns the response with its body buffered.
func (app *testApp) call(t *testing.T, method, path, token string, body []byte, status int) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, app.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(authhttp.TokenModeHeader, authhttp.TokenModeBearer)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := app.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d: %s", method, path, res.StatusCode, status, strings.TrimSpace(buf.String()))
	}
	res.Body = readCloser{bytes.NewReader(buf.Bytes())}
	return res
}

// readCloser lets call hand back a body it already read.
type readCloser struct{ *bytes.Reader }

// Close does nothing: the body is in memory.
func (readCloser) Close() error { return nil }
