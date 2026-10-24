package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/scim"
)

const (
	testToken    = "test-scim-token"
	testPassword = "correct horse battery staple"
	adaEmail     = "ada@acme.test"
	scimType     = "application/scim+json"
)

// TestSCIM_JoinerAndLeaver is the whole life of a provisioned user: the IdP
// creates Ada, she sets a password through the forgot flow and signs in, the
// IdP puts her in a group (the mapper hears her library id), then
// deactivates her the way Entra does ("False"), and her session and her
// next sign-in are refused until the IdP reactivates her.
func TestSCIM_JoinerAndLeaver(t *testing.T) {
	w := newWorld(t)

	created := w.idp(t, http.MethodPost, "/Users", map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": adaEmail, "name": map[string]string{"givenName": "Ada", "familyName": "Lovelace"},
		"emails": []map[string]any{{"value": adaEmail, "type": "work", "primary": true}},
	}, http.StatusCreated)
	scimID, _ := created["id"].(string)
	if scimID == "" {
		t.Fatalf("POST /Users answered no id: %v", created)
	}

	ada := newBrowser(t, w.h)
	post[none](t, ada, "/auth/password/forgot", fields{"identifier": adaEmail}, http.StatusOK)
	post[none](t, ada, "/auth/password/reset", fields{"token": w.box.lastToken(t, w.a, adaEmail), "password": testPassword}, http.StatusOK)
	post[none](t, ada, "/auth/password/sign-in", fields{"identifier": adaEmail, "password": testPassword}, http.StatusOK)
	me := get[meResponse](t, ada, "/me", http.StatusOK)
	if me.Name != "Ada Lovelace" {
		t.Fatalf("/me = %+v", me)
	}

	group := w.idp(t, http.MethodPost, "/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Engineering", "members": []map[string]string{{"value": scimID}},
	}, http.StatusCreated)
	if ref := group["members"].([]any)[0].(map[string]any)["$ref"]; ref != baseURL+scimPrefix+"/Users/"+scimID {
		t.Fatalf("member $ref = %v", ref)
	}
	if got := w.groups.members("Engineering"); !slices.Equal(got, []string{me.ID}) {
		t.Fatalf("mapper heard members %v, want [%s]", got, me.ID)
	}

	w.setActive(t, scimID, "False")
	get[errorAnswer](t, ada, "/me", http.StatusUnauthorized)
	// A sign-in with the right password is refused too, with the reason.
	if e := post[errorAnswer](t, newBrowser(t, w.h), "/auth/password/sign-in", fields{"identifier": adaEmail, "password": testPassword}, http.StatusForbidden); e.Error.Code != scim.ErrDeactivated.Code {
		t.Fatalf("deactivated sign-in: %+v", e.Error)
	}

	w.setActive(t, scimID, "True")
	back := newBrowser(t, w.h)
	post[none](t, back, "/auth/password/sign-in", fields{"identifier": adaEmail, "password": testPassword}, http.StatusOK)
	if again := get[meResponse](t, back, "/me", http.StatusOK); again.ID != me.ID {
		t.Fatalf("reactivated sign-in reached %s, want %s", again.ID, me.ID)
	}
}

// TestSCIM_TokenGuardsEverythingButDiscovery: discovery answers anyone; a
// missing or wrong token answers 401 with the Bearer challenge.
func TestSCIM_TokenGuardsEverythingButDiscovery(t *testing.T) {
	w := newWorld(t)
	srv := httptest.NewServer(w.h)
	t.Cleanup(srv.Close)

	for _, c := range []struct {
		path, token string
		status      int
	}{
		{"/ServiceProviderConfig", "", http.StatusOK},
		{"/Users", "", http.StatusUnauthorized},
		{"/Users", "not-the-token", http.StatusUnauthorized},
		{"/Users", testToken, http.StatusOK},
	} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+scimPrefix+c.path, nil)
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode != c.status {
			t.Fatalf("GET %s with %q: status %d, want %d", c.path, c.token, res.StatusCode, c.status)
		}
		if c.status == http.StatusUnauthorized && !strings.HasPrefix(res.Header.Get("WWW-Authenticate"), "Bearer") {
			t.Fatalf("GET %s: WWW-Authenticate %q", c.path, res.Header.Get("WWW-Authenticate"))
		}
	}
}

// world is the app wired as main wires it, with a recording group mapper
// and mailbox, and the IdP's side of SCIM.
type world struct {
	a      *auth.Auth
	h      http.Handler
	box    *mailbox
	groups *recordGroups
	scim   *httptest.Server
}

func newWorld(t *testing.T) *world {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	w := &world{box: &mailbox{}, groups: &recordGroups{byName: map[string][]string{}}}
	sp := newSCIM(testToken, w.groups)
	if w.a, err = newAuth(db, w.box, sp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.a.Close() })
	if _, err := w.a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	w.h = newHandler(w.a, sp)
	w.scim = httptest.NewServer(w.h)
	t.Cleanup(w.scim.Close)
	return w
}

// idp sends a SCIM request as the IdP does, with the token, and decodes the
// answer.
func (w *world) idp(t *testing.T, method, path string, body any, status int) map[string]any {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(method, w.scim.URL+scimPrefix+path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", scimType)
	res, err := w.scim.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	if res.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d: %v", method, path, res.StatusCode, status, out)
	}
	return out
}

// setActive PATCHes active the way Microsoft Entra sends it: a capitalised
// op and a string boolean.
func (w *world) setActive(t *testing.T, scimID, value string) {
	t.Helper()
	w.idp(t, http.MethodPatch, "/Users/"+scimID, map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]string{{"op": "Replace", "path": "active", "value": value}},
	}, http.StatusOK)
}

// recordGroups is a GroupMapper that keeps each group's latest members.
type recordGroups struct {
	mu     sync.Mutex
	byName map[string][]string
}

func (r *recordGroups) SyncGroup(_ context.Context, g scim.GroupState) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byName[g.DisplayName] = g.UserIDs
	return nil
}

func (r *recordGroups) DeleteGroup(context.Context, string, string) error { return nil }

func (r *recordGroups) members(name string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byName[name]
}

// mailbox records every mail sent.
type mailbox struct {
	mu   sync.Mutex
	sent []email.Mail
}

func (m *mailbox) Send(_ context.Context, mail email.Mail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, mail)
	return nil
}

// lastToken returns the token of the newest link mailed to addr, after the
// deliveries queued by committed transactions have run.
func (m *mailbox) lastToken(t *testing.T, a *auth.Auth, addr string) string {
	t.Helper()
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To != addr {
			continue
		}
		for _, field := range strings.Fields(m.sent[i].Text) {
			if u, err := url.Parse(field); err == nil && u.Query().Get("token") != "" {
				return u.Query().Get("token")
			}
		}
	}
	t.Fatalf("no link mailed to %s", addr)
	return ""
}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the app's Origin. HTTPS, because the session cookie is __Host- and Secure.
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

// fields is a JSON request body as a client writes it.
type fields map[string]string

// none is the answer of a call whose body the test does not read.
type none struct{}

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// post sends in as JSON with the app's Origin, checks the status and decodes
// the answer as Out.
func post[Out, In any](t *testing.T, b *browser, path string, in In, status int) Out {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, b.srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
	return do[Out](t, b, req, status)
}

// get fetches path, checks the status and decodes the answer as Out.
func get[Out any](t *testing.T, b *browser, path string, status int) Out {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
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
