package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
)

// TestLifecycle_ListRenamePauseRevoke: a person makes a live key and a test
// key in settings, lists them a page at a time, renames and pauses one,
// resumes it, and revokes it. A paused or revoked key is refused exactly like
// an unknown one.
func TestLifecycle_ListRenamePauseRevoke(t *testing.T) {
	app := newTestApp(t, access.MustNew(statements))
	b := app.browser(t)
	signUp(t, b)

	live := post[apikey.CreateResult](t, b, "/auth/apikey/create", apikey.CreateRequest{Config: configLive, Name: "importer", Scopes: []string{scopeOrdersRead}, Metadata: []byte(`{"team":"ops"}`)}, http.StatusOK)
	test := post[apikey.CreateResult](t, b, "/auth/apikey/create", apikey.CreateRequest{Config: configTest, Name: "ci", Scopes: []string{scopeOrdersRead}}, http.StatusOK)
	if !strings.HasPrefix(live.Secret, prefixLive) || !strings.HasPrefix(test.Secret, prefixTest) {
		t.Fatalf("prefixes: live %q, test %q", live.Key.Prefix, test.Key.Prefix)
	}
	if live.Key.Config != configLive || string(live.Key.Metadata) != `{"team":"ops"}` {
		t.Fatalf("live key = %+v", live.Key)
	}
	if e := post[errorAnswer](t, b, "/auth/apikey/create", apikey.CreateRequest{Config: "staging", Name: "typo"}, http.StatusBadRequest); e.Error.Code != apikey.ErrUnknownConfig.Code {
		t.Fatalf("an unknown configuration: %+v", e.Error)
	}

	page := get[apikey.ListResult](t, b, "/auth/apikey/list?limit=1&sortBy=name&sort=asc", http.StatusOK)
	if page.Total != 2 || len(page.Keys) != 1 || page.Keys[0].Name != "ci" {
		t.Fatalf("first page = %+v", page)
	}
	if only := get[apikey.ListResult](t, b, "/auth/apikey/list?configId="+configLive, http.StatusOK); only.Total != 1 || only.Keys[0].ID != live.Key.ID {
		t.Fatalf("live keys = %+v", only)
	}

	script := b.as(live.Secret)
	get[ordersResult](t, script, "/api/orders", http.StatusOK)

	paused := post[apikey.Key](t, b, "/auth/apikey/update", updateBody{ID: live.Key.ID, Name: "importer (paused)", Disabled: true}, http.StatusOK)
	if !paused.Disabled || paused.Name != "importer (paused)" {
		t.Fatalf("paused key = %+v", paused)
	}
	get[errorAnswer](t, script, "/api/orders", http.StatusUnauthorized)
	post[apikey.Key](t, b, "/auth/apikey/update", resumeBody{ID: live.Key.ID, Disabled: false}, http.StatusOK)
	get[ordersResult](t, script, "/api/orders", http.StatusOK)

	post[none](t, b, "/auth/apikey/revoke", fields{"id": live.Key.ID}, http.StatusOK)
	get[errorAnswer](t, script, "/api/orders", http.StatusUnauthorized)
	if e := get[errorAnswer](t, b, "/auth/apikey/get?id="+live.Key.ID, http.StatusNotFound); e.Error.Code != apikey.ErrNotFound.Code {
		t.Fatalf("a revoked key: %+v", e.Error)
	}
}

// TestLifecycle_TestKeysAreThrottled: a test key inherits the test
// configuration's rate limit, so its request past testRateMax in the window
// is 429 with Retry-After.
func TestLifecycle_TestKeysAreThrottled(t *testing.T) {
	app := newTestApp(t, access.MustNew(statements))
	b := app.browser(t)
	signUp(t, b)
	key := post[apikey.CreateResult](t, b, "/auth/apikey/create", apikey.CreateRequest{Config: configTest, Name: "ci", Scopes: []string{scopeOrdersRead}}, http.StatusOK)

	script := b.as(key.Secret)
	for range testRateMax {
		get[ordersResult](t, script, "/api/orders", http.StatusOK)
	}
	res := script.raw(t, "/api/orders")
	if res.StatusCode != http.StatusTooManyRequests || res.Header.Get("Retry-After") == "" {
		t.Fatalf("request past the limit: status %d, Retry-After %q", res.StatusCode, res.Header.Get("Retry-After"))
	}
}

// TestLifecycle_ProvisionedKeyHasAQuota: a key minted from Go with a quota of
// two serves two requests and then answers usage_exceeded until it refills.
func TestLifecycle_ProvisionedKeyHasAQuota(t *testing.T) {
	app := newTestApp(t, access.MustNew(statements))
	b := app.browser(t)
	user := signUp(t, b)
	const quota = 2
	key, err := provisionKey(context.Background(), app.ak, user.ID, quota)
	if err != nil {
		t.Fatal(err)
	}
	script := b.as(key.Secret)
	for range quota {
		get[ordersResult](t, script, "/api/orders", http.StatusOK)
	}
	if e := get[errorAnswer](t, script, "/api/orders", http.StatusTooManyRequests); e.Error.Code != apikey.ErrUsageExceeded.Code {
		t.Fatalf("past the quota: %+v", e.Error)
	}
}

// TestLifecycle_VerifyAKeyFromElsewhere: checkWebhookKey accepts a key with
// the scope and gives its owner; a key without the scope and a revoked key
// are refused with the reason the API would give.
func TestLifecycle_VerifyAKeyFromElsewhere(t *testing.T) {
	app := newTestApp(t, access.MustNew(statements))
	b := app.browser(t)
	user := signUp(t, b)
	ctx := context.Background()
	writer := post[apikey.CreateResult](t, b, "/auth/apikey/create", apikey.CreateRequest{Name: "hooks", Scopes: []string{scopeOrdersWrite}}, http.StatusOK)
	reader := post[apikey.CreateResult](t, b, "/auth/apikey/create", apikey.CreateRequest{Name: "reader", Scopes: []string{scopeOrdersRead}}, http.StatusOK)

	if owner, err := checkWebhookKey(ctx, app.ak, writer.Secret); err != nil || owner != user.ID {
		t.Fatalf("a valid key: owner %q, %v", owner, err)
	}
	if _, err := checkWebhookKey(ctx, app.ak, reader.Secret); !errors.Is(err, apikey.ErrScopeMissing) {
		t.Fatalf("a key without the scope: %v", err)
	}
	post[none](t, b, "/auth/apikey/revoke", fields{"id": writer.Key.ID}, http.StatusOK)
	if _, err := checkWebhookKey(ctx, app.ak, writer.Secret); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("a revoked key: %v", err)
	}
}

// TestLifecycle_PermissionsAndARemovedAction: a provisioned key with the
// refund permission may refund; a key made in settings has no permissions
// and may not. When the app later removes the refund action from its
// statements, the old key is refused until the app sets its permissions
// again from the new vocabulary.
func TestLifecycle_PermissionsAndARemovedAction(t *testing.T) {
	db := openTestDB(t)
	app := newTestAppOn(t, db, access.MustNew(statements))
	b := app.browser(t)
	user := signUp(t, b)
	ctx := context.Background()

	key, err := provisionKey(ctx, app.ak, user.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	post[refundResult](t, b.as(key.Secret), "/api/refunds", none{}, http.StatusOK)
	plain := post[apikey.CreateResult](t, b, "/auth/apikey/create", apikey.CreateRequest{Name: "plain", Scopes: []string{scopeOrdersRead}}, http.StatusOK)
	if e := post[errorAnswer](t, b.as(plain.Secret), "/api/refunds", none{}, http.StatusForbidden); e.Error.Code != apikey.ErrPermissionDenied.Code {
		t.Fatalf("a key without permissions: %+v", e.Error)
	}

	// The next release drops refunds from the vocabulary. The same database
	// still holds the key with "orders: refund".
	shrunk := newTestAppOn(t, db, access.MustNew(access.Statements{resourceOrders: {actionRead}}))
	sb := shrunk.browser(t)
	if e := post[errorAnswer](t, sb.as(key.Secret), "/api/refunds", none{}, http.StatusForbidden); e.Error.Code != apikey.ErrPermissionDenied.Code {
		t.Fatalf("a removed action: %+v", e.Error)
	}
	if err := shrunk.ak.SetPermissions(ctx, key.Key.ID, apikey.Permissions{resourceOrders: {actionRead}}); err != nil {
		t.Fatal(err)
	}
	if err := shrunk.ak.SetPermissions(ctx, key.Key.ID, apikey.Permissions{resourceOrders: {actionRefund}}); !errors.Is(err, apikey.ErrBadPermissions) {
		t.Fatalf("setting an undeclared action: %v", err)
	}
}

// updateBody renames and pauses a key. apikey.UpdateRequest's pointer fields
// are written here as plain values, the way a settings page sends them.
type updateBody struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Disabled bool   `json:"disabled"`
}

// resumeBody resumes a key and leaves its name alone.
type resumeBody struct {
	ID       string `json:"id"`
	Disabled bool   `json:"disabled"`
}

// signUp creates the test user in b's cookie jar and returns them.
func signUp(t *testing.T, b *browser) auth.UserView {
	t.Helper()
	return post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK).User
}

// testApp is the app's Auth and API-key plugin, migrated.
type testApp struct {
	a  *auth.Auth
	ak *apikey.Plugin
}

// browser serves the app's handler to a new browser.
func (app testApp) browser(t *testing.T) *browser {
	t.Helper()
	return newBrowser(t, newHandler(app.a, app.ak))
}

// newTestApp builds the app on a fresh SQLite file.
func newTestApp(t *testing.T, ac *access.AccessControl) testApp {
	t.Helper()
	return newTestAppOn(t, openTestDB(t), ac)
}

// newTestAppOn builds the app on db, so two builds can share one database.
func newTestAppOn(t *testing.T, db *sql.DB, ac *access.AccessControl) testApp {
	t.Helper()
	a, ak, err := newAuth(db, email.MailerFunc(discardMail), ac)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return testApp{a: a, ak: ak}
}

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

// discardMail drops the verification mail sign-up sends; these tests do not
// read it.
func discardMail(context.Context, email.Mail) error { return nil }
