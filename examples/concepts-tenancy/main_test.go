package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

const (
	aliceEmail   = "alice@example.com"
	acmePassword = "correct horse battery staple"
	globexPass   = "a different password at globex"
)

// TestTenancy_OneAddressTwoTenantsTwoUsers: the same address signs up at two
// tenants and gets two users; each tenant's password works only there.
func TestTenancy_OneAddressTwoTenantsTwoUsers(t *testing.T) {
	a := newTestAuth(t)
	acme, globex := newBrowser(t, newHandler(a)), newBrowser(t, newHandler(a))
	up1 := post[password.SignInResult](t, acme, "/t/acme/auth/password/sign-up", fields{"identifier": aliceEmail, "password": acmePassword}, http.StatusOK)
	up2 := post[password.SignInResult](t, globex, "/t/globex/auth/password/sign-up", fields{"identifier": aliceEmail, "password": globexPass}, http.StatusOK)
	if up1.User.ID == up2.User.ID {
		t.Fatal("one address at two tenants must be two users")
	}
	me := get[meResponse](t, acme, "/t/acme/me", http.StatusOK)
	if me.Tenant != "acme" || me.User.ID != up1.User.ID {
		t.Fatalf("/t/acme/me = %+v", me)
	}

	// Globex's password does not open the Acme account.
	e := post[errorAnswer](t, newBrowser(t, newHandler(a)), "/t/acme/auth/password/sign-in", fields{"identifier": aliceEmail, "password": globexPass}, http.StatusUnauthorized)
	if e.Error.Code != password.ErrInvalidCredentials.Code {
		t.Fatalf("cross-tenant sign-in: %+v", e.Error)
	}
	post[password.SignInResult](t, newBrowser(t, newHandler(a)), "/t/acme/auth/password/sign-in", fields{"identifier": aliceEmail, "password": acmePassword}, http.StatusOK)

	// Both identities exist, each with its tenant.
	ctx := context.Background()
	for tenant, id := range map[string]string{"acme": up1.User.ID, "globex": up2.User.ID} {
		idn, err := a.FindIdentity(auth.WithScope(ctx, tenant), email.KindEmail, aliceEmail, false)
		if err != nil || idn.UserID != id || idn.ScopeID == nil || *idn.ScopeID != tenant {
			t.Fatalf("identity at %s = %+v, %v", tenant, idn, err)
		}
	}
}

// TestTenancy_NoTenantIsRefused: a scoped kind with no tenant in the context
// is auth.ErrNoScope, over HTTP and from Go, never a lookup across tenants.
func TestTenancy_NoTenantIsRefused(t *testing.T) {
	a := newTestAuth(t)
	b := newBrowser(t, newHandler(a))
	e := post[errorAnswer](t, b, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": acmePassword}, http.StatusBadRequest)
	if e.Error.Code != auth.ErrNoScope.Code {
		t.Fatalf("sign-up with no tenant: %+v, want %s", e.Error, auth.ErrNoScope.Code)
	}
	if _, err := a.FindIdentity(context.Background(), email.KindEmail, aliceEmail, false); !errors.Is(err, auth.ErrNoScope) {
		t.Fatalf("FindIdentity with no tenant: %v, want ErrNoScope", err)
	}
}

// discard drops mail, for a test that never sends any.
func discard(context.Context, email.Mail) error { return nil }

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

// newTestAuth builds the app's Auth on a fresh SQLite file and migrates it.
func newTestAuth(t *testing.T) *auth.Auth {
	t.Helper()
	a, err := newAuth(openTestDB(t), email.MailerFunc(discard))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would, like a real browser on the app.
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
	return &browser{srv: srv, client: client, origin: baseURL}
}

// fields is a JSON request body as a client writes it.
type fields map[string]string

// none is the answer of a call whose body the test does not read.
type none struct{}

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
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

// do sends req, checks the status and decodes the answer as Out.
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
