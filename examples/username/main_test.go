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
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/username"
)

const (
	address  = "ada@example.com"
	secret   = "correct horse battery staple"
	typed    = "Ada_Lovelace" // as Ada types it; stored as ada_lovelace
	handle   = "ada_lovelace"
	renamed  = "ada"
	reserved = "pricing" // an app route name from reservedHandles
)

// TestUsername_ClaimRenameAndSignIn: a handle is claimed, shown back as typed,
// signs in with the password, and a rename frees the old handle.
func TestUsername_ClaimRenameAndSignIn(t *testing.T) {
	a := newTestAuth(t)
	b := newBrowser(t, newHandler(a))

	post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": address, "password": secret}, http.StatusOK)
	if free := get[username.Availability](t, b, "/auth/username/available?username="+typed, http.StatusOK); !free.Available {
		t.Fatal("a handle nobody has must be available")
	}
	set := post[username.Result](t, b, "/auth/username/set", fields{"username": typed}, http.StatusOK)
	if set.Username != handle {
		t.Fatalf("set = %+v, want the normalized handle", set)
	}
	if me := get[meResponse](t, b, "/me", http.StatusOK); me.Handle != handle || me.Display != typed {
		t.Fatalf("/me = %+v", me)
	}
	if free := get[username.Availability](t, b, "/auth/username/available?username=ADA_LOVELACE", http.StatusOK); free.Available {
		t.Fatal("a taken handle must not be available, whatever its case")
	}

	// The handle signs in with the same password, in any case.
	other := newBrowser(t, newHandler(a))
	in := post[password.SignInResult](t, other, "/auth/password/sign-in", fields{"identifier": "ADA_LOVELACE", "password": secret}, http.StatusOK)
	if me := get[meResponse](t, other, "/me", http.StatusOK); me.ID != in.User.ID || me.Handle != handle {
		t.Fatalf("/me after handle sign-in = %+v", me)
	}

	post[username.Result](t, b, "/auth/username/set", fields{"username": renamed}, http.StatusOK)
	if free := get[username.Availability](t, b, "/auth/username/available?username="+handle, http.StatusOK); !free.Available {
		t.Fatal("the old handle must be free after a rename")
	}
	if me := get[meResponse](t, b, "/me", http.StatusOK); me.Handle != renamed {
		t.Fatalf("/me after rename = %+v", me)
	}
}

// TestUsername_Refusals: reserved and malformed handles are refused and read
// as unavailable, and a handle another user holds is taken.
func TestUsername_Refusals(t *testing.T) {
	a := newTestAuth(t)
	b := newBrowser(t, newHandler(a))
	post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": address, "password": secret}, http.StatusOK)

	if free := get[username.Availability](t, b, "/auth/username/available?username="+reserved, http.StatusOK); free.Available {
		t.Fatal("a reserved handle must not be available")
	}
	if e := post[errorAnswer](t, b, "/auth/username/set", fields{"username": reserved}, http.StatusConflict); e.Error.Code != username.ErrReserved.Code {
		t.Fatalf("reserved = %+v", e.Error)
	}
	if e := post[errorAnswer](t, b, "/auth/username/set", fields{"username": "1ada"}, http.StatusBadRequest); e.Error.Code != auth.ErrIdentifierInvalid.Code {
		t.Fatalf("malformed = %+v", e.Error)
	}
	post[username.Result](t, b, "/auth/username/set", fields{"username": handle}, http.StatusOK)

	bob := newBrowser(t, newHandler(a))
	post[password.SignInResult](t, bob, "/auth/password/sign-up", fields{"identifier": "bob@example.com", "password": secret}, http.StatusOK)
	if e := post[errorAnswer](t, bob, "/auth/username/set", fields{"username": handle}, http.StatusConflict); e.Error.Code != auth.ErrIdentityTaken.Code {
		t.Fatalf("taken = %+v", e.Error)
	}
	if me := get[meResponse](t, bob, "/me", http.StatusOK); me.Handle != "" {
		t.Fatalf("bob got a handle: %+v", me)
	}
}

// newTestAuth builds the app's Auth on a fresh SQLite file; mail is dropped.
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
