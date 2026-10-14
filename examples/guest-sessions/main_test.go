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
	"github.com/ubgo/auth/plugin/anonymous"
	"github.com/ubgo/auth/plugin/password"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery"
)

// TestGuestCartMovesToTheAccount: a guest fills a cart, signs up, and the
// cart belongs to the new account while the guest row is gone.
func TestGuestCartMovesToTheAccount(t *testing.T) {
	a, db := newTestAuth(t)
	b := newBrowser(t, newHandler(a))

	if _, status := get(t, b, "/cart"); status != http.StatusUnauthorized {
		t.Fatalf("cart signed out: %d", status)
	}
	guest := post[anonymous.SignInResult](t, b, "/auth/anonymous/sign-in", fields{}, http.StatusOK)
	if guest.User.ID == "" || guest.User.Name != anonymous.DefaultName {
		t.Fatalf("guest = %+v", guest)
	}
	post[cartView](t, b, "/cart", fields{"item": "lamp"}, http.StatusOK)
	view := post[cartView](t, b, "/cart", fields{"item": "chair"}, http.StatusOK)
	if view.UserID != guest.User.ID || len(view.Items) != 2 {
		t.Fatalf("guest cart = %+v", view)
	}
	again := post[errorAnswer](t, b, "/auth/anonymous/sign-in", fields{}, http.StatusConflict)
	if again.Error.Code != anonymous.ErrAlreadyAnonymous.Code {
		t.Fatalf("second guest sign-in = %+v", again.Error)
	}

	up := post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword, "name": "Alice"}, http.StatusOK)
	if up.User.ID == guest.User.ID || up.User.ID == "" {
		t.Fatalf("sign-up = %+v", up)
	}
	moved, status := get(t, b, "/cart")
	if status != http.StatusOK || moved.UserID != up.User.ID || len(moved.Items) != 2 || moved.Items[0] != "lamp" {
		t.Fatalf("cart after sign-up = %+v (%d)", moved, status)
	}
	if _, err := a.User(context.Background(), guest.User.ID); err == nil {
		t.Fatal("the guest row must be deleted once linked")
	}
	var n int
	if err := db.QueryRow("SELECT count(*) FROM app_cart_item WHERE user_id = ?", guest.User.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows left for the guest: %d %v", n, err)
	}
}

// newTestAuth builds the app's Auth and tables on a fresh SQLite file.
func newTestAuth(t *testing.T) (*auth.Auth, *sql.DB) {
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
	if _, err := db.Exec(cartSchema); err != nil {
		t.Fatal(err)
	}
	return a, db
}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would.
type browser struct {
	srv    *httptest.Server
	client *http.Client
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
	return &browser{srv: srv, client: client}
}

// fields is a JSON request body as a client writes it.
type fields map[string]string

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// post sends in as JSON with the browser's Origin, checks the status and
// decodes the answer as Out.
func post[Out any](t *testing.T, b *browser, path string, in fields, status int) Out {
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
		t.Fatalf("POST %s: status %d, want %d: %s", path, res.StatusCode, status, buf.String())
	}
	var out Out
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("POST %s: decode %q: %v", path, buf.String(), err)
	}
	return out
}

// get fetches the cart and returns it with the status; the body is decoded
// only on 200.
func get(t *testing.T, b *browser, path string) (cartView, int) {
	t.Helper()
	res, err := b.client.Get(b.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out cartView
	if res.StatusCode == http.StatusOK {
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
	}
	return out, res.StatusCode
}
