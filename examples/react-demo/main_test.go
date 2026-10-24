package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/organization"
)

// TestReactDemo_RoutesTheSignInFormCalls walks every route SignInForm and
// useSession call, as the demo's browser run does: the provider list, a
// passkey ceremony start, a wrong and a right password for the seeded user,
// the session, a magic link into the inbox, and sign-out.
func TestReactDemo_RoutesTheSignInFormCalls(t *testing.T) {
	d, box, h := newTestDemo(t)
	if err := seed(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if err := seed(context.Background(), d); err != nil {
		t.Fatalf("a second seed must leave the user alone: %v", err)
	}
	d.auth.WaitDeliveries()
	box.clear() // the seed's own verification mail, which main clears too
	b := newBrowser(t, h)

	var providers oauth.ProvidersResult
	b.call(t, http.MethodGet, "/auth/oauth/providers", nil, http.StatusOK, &providers)
	if len(providers.Providers) != 1 || providers.Providers[0].ID != devOAuthID {
		t.Fatalf("providers = %+v, want only the pretend provider", providers.Providers)
	}
	b.call(t, http.MethodPost, "/auth/passkey/login-begin", map[string]string{}, http.StatusOK, nil)
	b.call(t, http.MethodGet, "/auth/session", nil, http.StatusUnauthorized, nil)

	var wrong struct {
		Error struct{ Code string } `json:"error"`
	}
	b.call(t, http.MethodPost, "/auth/password/sign-in", map[string]string{"identifier": demoUserEmail, "password": "nope nope nope"}, http.StatusUnauthorized, &wrong)
	if wrong.Error.Code != "password.invalid_credentials" {
		t.Fatalf("wrong password answered %q, want password.invalid_credentials (the form shows its message)", wrong.Error.Code)
	}
	b.call(t, http.MethodPost, "/auth/password/sign-in", map[string]string{"identifier": demoUserEmail, "password": demoUserPassword}, http.StatusOK, nil)
	b.call(t, http.MethodGet, "/auth/session", nil, http.StatusOK, nil)
	b.call(t, http.MethodPost, "/auth/sign-out", map[string]string{}, http.StatusOK, nil)

	b.call(t, http.MethodPost, "/auth/magiclink/send", map[string]string{"identifier": demoUserEmail}, http.StatusOK, nil)
	d.auth.WaitDeliveries()
	var inbox devMailResponse
	b.call(t, http.MethodGet, devMailPath, nil, http.StatusOK, &inbox)
	if len(inbox.Messages) != 1 || inbox.Messages[0].To != demoUserEmail || len(inbox.Messages[0].Links) == 0 {
		t.Fatalf("inbox = %+v, want one message with a link to %s", inbox.Messages, demoUserEmail)
	}
	box.clear()
	b.call(t, http.MethodGet, devMailPath, nil, http.StatusOK, &inbox)
	if len(inbox.Messages) != 0 {
		t.Fatalf("inbox after clear = %+v", inbox.Messages)
	}
}

// TestReactDemo_OrganizationRoutes walks the calls the organization
// components make (OrganizationSwitcher, OrganizationMembers): create, which
// makes the new organization active; the active organization; the member
// list; the invite permission; and an invitation, mailed to the demo inbox
// with a link to the /invitations page OrganizationInvitations serves.
func TestReactDemo_OrganizationRoutes(t *testing.T) {
	d, box, h := newTestDemo(t)
	if err := seed(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	d.auth.WaitDeliveries()
	box.clear()
	b := newBrowser(t, h)
	b.call(t, http.MethodPost, "/auth/password/sign-in", map[string]string{"identifier": demoUserEmail, "password": demoUserPassword}, http.StatusOK, nil)

	var created organization.Org
	b.call(t, http.MethodPost, "/auth/organization/create", map[string]string{"name": "Acme Labs", "slug": "acme-labs"}, http.StatusOK, &created)
	var active organization.ActiveResult
	b.call(t, http.MethodGet, "/auth/organization/active", nil, http.StatusOK, &active)
	if active.OrgID == nil || *active.OrgID != created.ID {
		t.Fatalf("active = %+v, want the new organization %s (the switcher shows it after create)", active, created.ID)
	}
	var members organization.MembersResult
	b.call(t, http.MethodGet, "/auth/organization/members?page=1&limit=10", nil, http.StatusOK, &members)
	if members.Total != 1 || len(members.Members) != 1 || members.Members[0].Role != organization.RoleOwner {
		t.Fatalf("members = %+v, want the creator as the only owner", members)
	}
	var allowed organization.PermissionResult
	b.call(t, http.MethodPost, "/auth/organization/has-permission", map[string]any{"permissions": map[string][]string{"invitation": {"create"}}}, http.StatusOK, &allowed)
	if !allowed.Success {
		t.Fatal("the owner may not invite: OrganizationMembers would hide its invite form")
	}
	b.call(t, http.MethodPost, "/auth/organization/invite", map[string]string{"email": "grace@demo.test", "role": "admin"}, http.StatusOK, nil)
	d.auth.WaitDeliveries()
	var inbox devMailResponse
	b.call(t, http.MethodGet, devMailPath, nil, http.StatusOK, &inbox)
	if len(inbox.Messages) != 1 || inbox.Messages[0].To != "grace@demo.test" {
		t.Fatalf("inbox = %+v, want one invitation to grace@demo.test", inbox.Messages)
	}
	if !strings.Contains(strings.Join(inbox.Messages[0].Links, " "), "/invitations") {
		t.Fatalf("invitation links = %v, want the /invitations page", inbox.Messages[0].Links)
	}
}

// TestReactDemo_PretendProviderSignsIn runs the whole authorization-code
// flow against the pretend provider: start, consent, approve, callback, and
// a session for the persona.
func TestReactDemo_PretendProviderSignsIn(t *testing.T) {
	_, _, h := newTestDemo(t)
	b := newBrowser(t, h)
	b.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	start := b.location(t, "/auth/oauth/demo/start?returnTo=/")
	authorize, err := url.Parse(start)
	if err != nil || authorize.Path != devOAuthPrefix+"/authorize" {
		t.Fatalf("start redirected to %q, want the pretend provider", start)
	}
	q := authorize.Query()
	if !strings.HasPrefix(q.Get("redirect_uri"), baseURL) {
		t.Fatalf("redirect_uri = %q, want the app's callback", q.Get("redirect_uri"))
	}
	approve := devOAuthPrefix + "/approve?" + url.Values{"persona": {"grace"}, "redirect_uri": {q.Get("redirect_uri")}, "state": {q.Get("state")}}.Encode()
	callback, err := url.Parse(b.location(t, approve))
	if err != nil {
		t.Fatal(err)
	}
	b.location(t, callback.RequestURI())
	var session struct {
		User struct{ Name string } `json:"user"`
	}
	b.call(t, http.MethodGet, "/auth/session", nil, http.StatusOK, &session)
	if session.User.Name != "Grace Hopper" {
		t.Fatalf("session user = %q, want the persona", session.User.Name)
	}

	bad := devOAuthPrefix + "/approve?" + url.Values{"persona": {"grace"}, "redirect_uri": {"https://evil.example/cb"}}.Encode()
	res, err := b.client.Get(b.srv.URL + bad)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("approve to another site answered %d, want 400", res.StatusCode)
	}
}

// TestReactDemo_Providers pins that real provider credentials add a provider.
func TestReactDemo_Providers(t *testing.T) {
	if got := providersFromEnv(env(nil)); len(got) != 0 {
		t.Fatalf("no variables: %d providers, want none", len(got))
	}
	got := providersFromEnv(env(map[string]string{envGitHubID: "id", envGitHubSecret: "secret"}))
	if len(got) != 1 || got[0].Name() != "github" {
		t.Fatalf("GitHub credentials: %d providers, want GitHub", len(got))
	}
}

// env is a getenv over a fixed map.
func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

// newTestDemo builds the demo on a fresh SQLite file with the pretend
// provider pointed at the app's base URL, as main does.
func newTestDemo(t *testing.T) (demo, *devMailbox, http.Handler) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	box := &devMailbox{}
	pretend := newDevOAuth(baseURL)
	// The token exchange is server to server; a plain HTTP server stands in
	// for apiURL, since the TLS test server's certificate is not trusted by
	// the plugin's client.
	tokenSrv := httptest.NewServer(pretend)
	t.Cleanup(tokenSrv.Close)
	h := http.NewServeMux()
	d, err := newDemo(db, box, make([]byte, auth.SealKeySize), []oauth.Provider{pretend.provider(tokenSrv.URL)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.auth.Close() })
	if _, err := d.auth.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.Handle("/", newHandler(d.auth, box, pretend))
	return d, box, h
}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the app's Origin, like the page behind Vite's proxy. TLS because the
// session cookie is __Host- and a jar keeps it only for https.
type browser struct {
	srv    *httptest.Server
	client *http.Client
}

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

// location sends a GET and returns its redirect target, failing unless it redirects.
func (b *browser) location(t *testing.T, path string) string {
	t.Helper()
	res, err := b.client.Get(b.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode < 300 || res.StatusCode >= 400 {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("GET %s: %d %s, want a redirect", path, res.StatusCode, raw)
	}
	return res.Header.Get("Location")
}

// call sends body as JSON (nil for a GET), checks the status and decodes the answer into out when it is not nil.
func (b *browser) call(t *testing.T, method, path string, body any, status int, out any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, b.srv.URL+path, r)
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
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != status {
		t.Fatalf("%s %s: %d %s, want %d", method, path, res.StatusCode, raw, status)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s %s: %v in %s", method, path, err, raw)
		}
	}
}

// TestFreshWindow: DEMO_FRESH_WINDOW unset keeps the library default, a
// positive duration becomes one option, anything else refuses to start.
func TestFreshWindow(t *testing.T) {
	if opts, err := freshWindow(""); err != nil || opts != nil {
		t.Fatalf("unset = %v, %v", opts, err)
	}
	if opts, err := freshWindow("6s"); err != nil || len(opts) != 1 {
		t.Fatalf("6s = %v, %v", opts, err)
	}
	for _, bad := range []string{"soon", "0s", "-1s"} {
		if _, err := freshWindow(bad); err == nil || !strings.Contains(err.Error(), envFreshWindow) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
}
