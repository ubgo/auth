package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauthproxy"
)

const (
	productionURL = "https://app.example.com"
	previewURL    = "https://pr-7.preview.example.com"
	// previewOrigins is what production trusts: every preview the host makes.
	previewOrigins = "https://*.preview.example.com"
	proxySecret    = "a-shared-proxy-secret-of-32-bytes!!"
)

// productionCallback is the one redirect URI registered at the provider.
var productionCallback = productionURL + authPrefix + "/" + oauth.PluginName + "/" + providerName + "/callback"

// TestPreview_SignsInThroughProductionsCallback: a preview's sign-in goes to
// the provider with production's callback, production relays the sealed code
// without exchanging it or writing a row, and the preview's own callback
// exchanges it and signs the person in on the preview.
func TestPreview_SignsInThroughProductionsCallback(t *testing.T) {
	idp := newFakeIssuer(t, productionCallback, userInfo{Sub: "idp-1", Email: "dana@example.com", EmailVerified: true, Name: "Dana"})
	prod, prodDB := newTestDeployment(t, idp, productionURL)
	preview, _ := newTestDeployment(t, idp, previewURL)

	b := newBrowser()
	authURL := b.redirect(t, preview, previewURL+"/auth/oauth/"+providerName+"/start?returnTo=/me")
	if got := redirectURIOf(t, authURL); got != productionCallback {
		t.Fatalf("the preview sent the provider redirect_uri %s, want production's", got)
	}
	back := idp.consent(t, authURL)

	relay := b.redirect(t, prod, back)
	if !strings.HasPrefix(relay, previewURL+"/auth/oauth/"+providerName+"/callback?") {
		t.Fatalf("production relayed to %s", relay)
	}
	if idp.exchangeCount() != 0 || countUsers(t, prodDB) != 0 {
		t.Fatal("production exchanged the code or created a user for a preview sign-in")
	}

	if landing := b.redirect(t, preview, relay); landing != "/me" {
		t.Fatalf("the preview callback landed on %s", landing)
	}
	got := b.get(t, preview, previewURL+"/me")
	var who meResponse
	if err := json.Unmarshal([]byte(got.body), &who); got.status != http.StatusOK || err != nil || who.Name != "Dana" {
		t.Fatalf("/me on the preview = %d %s", got.status, got.body)
	}
	if b.jar[authhttp.CookieName] == "" || idp.exchangeCount() != 1 {
		t.Fatal("the preview holds no session, or did not exchange the code itself")
	}
}

// TestPreview_ProductionSignsInDirectly: on production a wrapped provider is
// the provider itself, so its own sign-in is not relayed anywhere.
func TestPreview_ProductionSignsInDirectly(t *testing.T) {
	idp := newFakeIssuer(t, productionCallback, userInfo{Sub: "idp-2", Email: "erin@example.com", EmailVerified: true, Name: "Erin"})
	prod, prodDB := newTestDeployment(t, idp, productionURL)

	b := newBrowser()
	back := idp.consent(t, b.redirect(t, prod, productionURL+"/auth/oauth/"+providerName+"/start?returnTo=/me"))
	if landing := b.redirect(t, prod, back); landing != "/me" {
		t.Fatalf("production's callback landed on %s", landing)
	}
	if countUsers(t, prodDB) != 1 {
		t.Fatal("production's own sign-in created no user")
	}
}

// TestPreview_ProductionRefusesWhatItDoesNotTrust: a deployment outside the
// trusted origins, or one sealing with another secret, gets no relay.
func TestPreview_ProductionRefusesWhatItDoesNotTrust(t *testing.T) {
	idp := newFakeIssuer(t, productionCallback, userInfo{Sub: "idp-3", Email: "eve@example.com", EmailVerified: true, Name: "Eve"})
	prod, _ := newTestDeployment(t, idp, productionURL)

	const outsider = "https://pr-7.attacker.example.net"
	stranger, _ := newTestDeployment(t, idp, outsider)
	b := newBrowser()
	back := idp.consent(t, b.redirect(t, stranger, outsider+"/auth/oauth/"+providerName+"/start"))
	if got := b.get(t, prod, back); got.status != oauthproxy.ErrInvalidState.Status || !strings.Contains(got.body, oauthproxy.ErrInvalidState.Code) {
		t.Fatalf("relay to an untrusted origin = %d %s", got.status, got.body)
	}

	d := testDeployment(idp, previewURL)
	d.ProxySecret = []byte("another-secret-of-at-least-32-bytes!")
	other := newTestHandler(t, d)
	back = idp.consent(t, b.redirect(t, other, previewURL+"/auth/oauth/"+providerName+"/start"))
	if got := b.get(t, prod, back); got.status != oauthproxy.ErrInvalidState.Status {
		t.Fatalf("relay sealed with another secret = %d %s", got.status, got.body)
	}
}

// TestDeploymentFromEnv: the host's variable names the preview, and a short
// proxy secret is refused.
func TestDeploymentFromEnv(t *testing.T) {
	env := map[string]string{
		"VERCEL_URL": "pr-7.preview.example.com", envProductionURL: productionURL, envProxySecret: proxySecret,
		envPreviewOrigins: previewOrigins + ", https://staging.example.com",
		envOIDCIssuer:     "https://idp.example.com", envOIDCID: testClientID, envOIDCSecret: testClientSecret,
	}
	d, err := deploymentFromEnv(func(k string) string { return env[k] })
	if err != nil || d.BaseURL != previewURL || len(d.PreviewOrigins) != 2 {
		t.Fatalf("deployment = %+v, %v", d, err)
	}
	env[envProxySecret] = "short"
	if _, err := deploymentFromEnv(func(k string) string { return env[k] }); err == nil {
		t.Fatal("a short proxy secret was accepted")
	}
}

// testDeployment is a deployment at baseURL of the app this test runs,
// against the fake issuer.
func testDeployment(idp *fakeIssuer, baseURL string) deployment {
	return deployment{
		BaseURL:        baseURL,
		ProductionURL:  productionURL,
		ProxySecret:    []byte(proxySecret),
		PreviewOrigins: []string{previewOrigins},
		Provider:       oauth.OIDC(providerName, idp.srv.URL, testClientID, testClientSecret),
	}
}

// newTestDeployment builds a deployment at baseURL on its own database and
// returns its handler and database.
func newTestDeployment(t *testing.T, idp *fakeIssuer, baseURL string) (http.Handler, *sql.DB) {
	t.Helper()
	d := testDeployment(idp, baseURL)
	db := openTestDB(t)
	return newTestHandlerOn(t, db, d), db
}

// newTestHandler builds d on a fresh database.
func newTestHandler(t *testing.T, d deployment) http.Handler {
	t.Helper()
	return newTestHandlerOn(t, openTestDB(t), d)
}

// newTestHandlerOn builds d on db, migrated, and returns its handler.
func newTestHandlerOn(t *testing.T, db *sql.DB, d deployment) http.Handler {
	t.Helper()
	a, err := newAuth(db, d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return newHandler(a)
}

// openTestDB opens a fresh SQLite file for one deployment.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// countUsers counts the deployment's users. Reading auth tables is allowed;
// only writes go through the library.
func countUsers(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM auth_user").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// redirectURIOf is the redirect_uri an authorization URL asks for.
func redirectURIOf(t *testing.T, authURL string) string {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("redirect_uri")
}
