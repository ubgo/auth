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
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/examples/plugin-tables/devices"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
)

const (
	aliceEmail   = "alice@example.com"
	testPassword = "correct horse battery staple"
)

// TestDevices_AddListRemove drives the three operations over HTTP: the
// pipeline enforces the session, the plugin enforces its own rules, and the
// rows belong to the user who made them.
func TestDevices_AddListRemove(t *testing.T) {
	a := newTestAuth(t)
	b := newBrowser(t, newHandler(a))

	get[errorAnswer](t, b, "/auth/devices/list", http.StatusUnauthorized) // SignedIn is enforced before the plugin runs
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)

	post[auth.Done](t, b, "/auth/devices/add", fields{"name": "Laptop"}, http.StatusOK)
	post[auth.Done](t, b, "/auth/devices/add", fields{"name": "Phone"}, http.StatusOK)
	if e := post[errorAnswer](t, b, "/auth/devices/add", fields{"name": "Phone"}, http.StatusConflict); e.Error.Code != devices.ErrNameTaken.Code {
		t.Fatalf("duplicate name: %+v, want %s", e.Error, devices.ErrNameTaken.Code)
	}
	if e := post[errorAnswer](t, b, "/auth/devices/add", fields{"name": strings.Repeat("x", devices.MaxNameLength+1)}, http.StatusBadRequest); e.Error.Code != devices.ErrNameInvalid.Code {
		t.Fatalf("long name: %+v, want %s", e.Error, devices.ErrNameInvalid.Code)
	}

	list := get[devices.ListResult](t, b, "/auth/devices/list", http.StatusOK)
	if len(list.Devices) != 2 || list.Devices[0].Name != "Laptop" || list.Devices[1].Name != "Phone" {
		t.Fatalf("list = %+v, want Laptop then Phone", list.Devices)
	}

	// Removing needs a fresh sign-in; this one is seconds old, so it passes.
	post[auth.Done](t, b, "/auth/devices/remove", fields{"id": list.Devices[0].ID}, http.StatusOK)
	if e := post[errorAnswer](t, b, "/auth/devices/remove", fields{"id": list.Devices[0].ID}, http.StatusNotFound); e.Error.Code != devices.ErrNotFound.Code {
		t.Fatalf("remove twice: %+v, want %s", e.Error, devices.ErrNotFound.Code)
	}
	if list := get[devices.ListResult](t, b, "/auth/devices/list", http.StatusOK); len(list.Devices) != 1 || list.Devices[0].Name != "Phone" {
		t.Fatalf("after remove: %+v, want only Phone", list.Devices)
	}

	// Another user's device id matches nothing.
	bob := newBrowser(t, newHandler(a))
	post[none](t, bob, "/auth/password/sign-up", fields{"identifier": "bob@example.com", "password": testPassword}, http.StatusOK)
	post[errorAnswer](t, bob, "/auth/devices/remove", fields{"id": list.Devices[1].ID}, http.StatusNotFound)
	if list := get[devices.ListResult](t, b, "/auth/devices/list", http.StatusOK); len(list.Devices) != 1 {
		t.Fatalf("bob removed alice's device: %+v", list.Devices)
	}
}

// TestDevices_LimitIsEnforcedInTheTransaction: the eleventh device is
// refused with the plugin's own error code.
func TestDevices_LimitIsEnforcedInTheTransaction(t *testing.T) {
	a := newTestAuth(t)
	b := newBrowser(t, newHandler(a))
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	for i := range devices.DefaultMax {
		post[auth.Done](t, b, "/auth/devices/add", fields{"name": "Device " + string(rune('A'+i))}, http.StatusOK)
	}
	if e := post[errorAnswer](t, b, "/auth/devices/add", fields{"name": "One more"}, http.StatusConflict); e.Error.Code != devices.ErrTooMany.Code {
		t.Fatalf("over the limit: %+v, want %s", e.Error, devices.ErrTooMany.Code)
	}
}

// TestDevices_GoAPIRunsTheSamePipeline: the plugin's methods are the same
// operations the routes serve, so a Go caller is limited and checked alike.
func TestDevices_GoAPIRunsTheSamePipeline(t *testing.T) {
	a := newTestAuth(t)
	p, err := auth.PluginOf[*devices.Plugin](a)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Add(context.Background(), "Laptop"); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("Add with no session: %v, want ErrSignedOut", err)
	}
}

// TestDevices_MigrationAndLedger: the plugin's DDL comes out of the one
// schema command with the core's, and the ledger lists it as applied.
func TestDevices_MigrationAndLedger(t *testing.T) {
	a := newTestAuth(t)
	var out, errb bytes.Buffer
	if code := authcli.Main(context.Background(), a, []string{"migrate", "sql"}, &out, &errb); code != authcli.ExitOK {
		t.Fatalf("migrate sql: %d %s", code, errb.String())
	}
	for _, want := range []string{"-- devices 0001_devices", "CREATE TABLE IF NOT EXISTS auth_device", "UNIQUE (user_id, name)"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("schema lacks %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	if code := authcli.Main(context.Background(), a, []string{"migrate", "status"}, &out, &errb); code != authcli.ExitOK {
		t.Fatalf("migrate status: %d %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "applied  devices   0001_devices") {
		t.Fatalf("status lacks the plugin's migration:\n%s", out.String())
	}
}

// TestDevices_BadLimitFailsAtStartUp: Validate turns a wrong option into a
// refused auth.New that names the plugin.
func TestDevices_BadLimitFailsAtStartUp(t *testing.T) {
	_, err := auth.New(
		auth.WithDB(openTestDB(t), sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(discard))), password.New(), devices.New(devices.WithMax(0))),
	)
	if !errors.Is(err, devices.ErrBadMax) || !strings.Contains(err.Error(), `plugin "devices"`) {
		t.Fatalf("auth.New = %v, want ErrBadMax naming the plugin", err)
	}
	t.Logf("auth.New: %v", err)
}

// TestDevices_DeletingTheUserDeletesTheDevices: the plugin lists its table in
// UserTables, so auth.DeleteUser removes the devices with the user; there is
// no foreign key to do it.
func TestDevices_DeletingTheUserDeletesTheDevices(t *testing.T) {
	a := newTestAuth(t)
	b := newBrowser(t, newHandler(a))
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	post[auth.Done](t, b, "/auth/devices/add", fields{"name": "Laptop"}, http.StatusOK)
	ctx := context.Background()
	idn, err := a.FindIdentity(ctx, email.KindEmail, aliceEmail, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.DeleteUser(ctx, idn.UserID); err != nil {
		t.Fatal(err)
	}
	var n int64
	if err := a.One(ctx, a.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(devices.TableDevice)); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d devices survive their user", n)
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
