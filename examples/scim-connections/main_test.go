package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/organization/orgtest"
	"github.com/ubgo/auth/plugin/scim"
)

const (
	// testSecret is the app secret of every test: 32 bytes, as WithSecret asks.
	testSecret = "test-secret-test-secret-test-sec"
	// scimType is the SCIM media type the IdP sends.
	scimType = "application/scim+json"
	// adaExternalID is the IdP's own id for Ada, which ActiveUser resolves.
	adaExternalID = "okta-00u1ada"
)

// world is the app on the harness: SQLite in memory, recorded mail, the
// example's plugins and routes, a recording group mapper, and the IdP's
// plain-HTTP side of SCIM.
type world struct {
	env    *authtest.Env
	sp     *scim.Plugin
	groups *recordGroups
	h      http.Handler
	idpSrv *httptest.Server
	f      *orgtest.Factory
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{groups: &recordGroups{deleted: map[string]bool{}}}
	w.sp = newSCIM(w.groups)
	w.env = authtest.New(t,
		authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin { return plugins(e.Mail, w.sp) }),
		authtest.WithOptions(auth.WithSecret([]byte(testSecret))),
	)
	h, err := newHandler(w.env.Auth, w.sp)
	if err != nil {
		t.Fatal(err)
	}
	w.h = h
	w.idpSrv = httptest.NewServer(h)
	t.Cleanup(w.idpSrv.Close)
	w.f = orgtest.New(w.env)
	return w
}

// customer is one organization and a browser signed in as its owner.
type customer struct {
	org   organization.Org
	owner auth.User
	b     *authtest.Browser
}

// newCustomer creates an organization owned by a new user, through the
// orgtest fixtures, and signs the owner in.
func (w *world) newCustomer(t *testing.T, name string) customer {
	t.Helper()
	owner := w.env.CreateUser(name + " Owner")
	org := w.f.SaveOrganization(w.f.NewOrganization(owner.ID, name))
	b := w.env.Browser(w.h)
	b.SetSession(w.env.SignIn(owner.ID))
	return customer{org: org, owner: owner, b: b}
}

// connections is the customer's settings path.
func (c customer) connections() string { return "/orgs/" + c.org.ID + "/scim/connections" }

// connect creates a connection for c as its owner.
func (w *world) connect(t *testing.T, c customer, requestID string) issuedResponse {
	t.Helper()
	var out issuedResponse
	c.b.Post(c.connections(), createRequest{RequestID: requestID}).Expect(http.StatusCreated).Decode(&out)
	return out
}

// idp sends a SCIM request with token as the IdP does and returns the
// status and the decoded answer.
func (w *world) idp(t *testing.T, token, method, path string, body map[string]any) (int, map[string]any) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, w.idpSrv.URL+scimPrefix+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", scimType)
	res, err := w.idpSrv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out) // a 401 may have no body worth reading
	return res.StatusCode, out
}

// listUsers is the IdP's cheapest authenticated call.
func (w *world) listUsers(t *testing.T, token string) int {
	t.Helper()
	status, _ := w.idp(t, token, http.MethodGet, "/Users", nil)
	return status
}

// TestConnections_CustomerConnectsTheirIdP: the owner creates a connection
// and the IdP provisions with its token; a retried create, a member, another
// customer and a cross-site page are each refused.
func TestConnections_CustomerConnectsTheirIdP(t *testing.T) {
	w := newWorld(t)
	acme := w.newCustomer(t, "Acme")

	conn := w.connect(t, acme, "acme-create-0001-form")
	if !strings.HasPrefix(conn.Token, scim.ManagedTokenPrefix) || conn.Connection.ProvisioningDomainID != acme.org.ID {
		t.Fatalf("issued %+v", conn)
	}
	if status, _ := w.idp(t, conn.Token, http.MethodPost, "/Users", adaUser()); status != http.StatusCreated {
		t.Fatalf("POST /Users with the new token: %d", status)
	}

	if code := acme.b.Post(acme.connections(), createRequest{RequestID: "acme-create-0001-form"}).Expect(http.StatusConflict).ErrorCode(); code != scim.ErrCreationRequestConflict.Code {
		t.Fatalf("a retried create: %q", code)
	}

	member := w.env.CreateUser("Bob")
	w.f.AddMember(acme.org.ID, member.ID, organization.RoleMember)
	asBob := w.env.Browser(w.h)
	asBob.SetSession(w.env.SignIn(member.ID))
	if code := asBob.Post(acme.connections(), createRequest{RequestID: "bob-create-0001-form"}).Expect(http.StatusForbidden).ErrorCode(); code != organization.ErrForbidden.Code {
		t.Fatalf("a member creating: %q", code)
	}

	// Globex's owner names Acme's connection under Globex: the domain is
	// Globex's, so the connection does not exist for them.
	globex := w.newCustomer(t, "Globex")
	if code := globex.b.Get(globex.connections() + "/" + conn.Connection.ID + "/events").Expect(http.StatusNotFound).ErrorCode(); code != scim.ErrConnectionNotFound.Code {
		t.Fatalf("another customer's connection: %q", code)
	}
	var theirs []scim.ManagedConnection
	globex.b.Get(globex.connections()).Expect(http.StatusOK).Decode(&theirs)
	if len(theirs) != 0 {
		t.Fatalf("Globex lists %d connections", len(theirs))
	}

	req, err := http.NewRequest(http.MethodPost, acme.b.URL()+acme.connections(), strings.NewReader(`{"requestId":"evil-create-0001-form"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://evil.example")
	if code := acme.b.Do(req).Expect(http.StatusForbidden).ErrorCode(); code != auth.ErrOriginNotTrusted.Code {
		t.Fatalf("a cross-site create: %q", code)
	}
	var mine []scim.ManagedConnection
	acme.b.Get(acme.connections()).Expect(http.StatusOK).Decode(&mine)
	if len(mine) != 1 || len(mine[0].Credentials) != 1 {
		t.Fatalf("Acme's connections = %+v", mine)
	}
}

// TestConnections_RotateThenRevoke: a rotation adds a token beside the old
// one, both work until the old one is revoked, and the event log records
// every step.
//
//ds:def id=scimconn-rotatetest-4n7vq2km
func TestConnections_RotateThenRevoke(t *testing.T) {
	w := newWorld(t)
	acme := w.newCustomer(t, "Acme")
	first := w.connect(t, acme, "acme-create-0001-form")
	connPath := acme.connections() + "/" + first.Connection.ID

	var second issuedResponse
	acme.b.Post(connPath+"/rotate", nil).Expect(http.StatusCreated).Decode(&second)
	for _, tok := range []string{first.Token, second.Token} {
		if status := w.listUsers(t, tok); status != http.StatusOK {
			t.Fatalf("during the rotation a token answered %d", status)
		}
	}

	acme.b.Post(connPath+"/credentials/"+first.CredentialID+"/revoke", nil).Expect(http.StatusOK)
	if status := w.listUsers(t, first.Token); status != http.StatusUnauthorized {
		t.Fatalf("the revoked token answered %d", status)
	}
	if status := w.listUsers(t, second.Token); status != http.StatusOK {
		t.Fatalf("the new token answered %d", status)
	}
	if code := acme.b.Post(connPath+"/credentials/"+first.CredentialID+"/revoke", nil).Expect(http.StatusNotFound).ErrorCode(); code != scim.ErrCredentialNotFound.Code {
		t.Fatalf("revoking twice: %q", code)
	}

	want := []scim.EventKind{scim.EventConnectionCreated, scim.EventCredentialIssued, scim.EventCredentialRotated, scim.EventCredentialRevoked}
	if got := w.eventKinds(t, acme, connPath); !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

// TestConnections_DecommissionEndsAccess: retiring the connection stops its
// token, deactivates and signs out the user it provisioned, tells the group
// mapper the group is gone, and refuses any later rotation.
func TestConnections_DecommissionEndsAccess(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	acme := w.newCustomer(t, "Acme")
	conn := w.connect(t, acme, "acme-create-0001-form")
	connPath := acme.connections() + "/" + conn.Connection.ID

	status, ada := w.idp(t, conn.Token, http.MethodPost, "/Users", adaUser())
	if status != http.StatusCreated {
		t.Fatalf("POST /Users: %d", status)
	}
	if status, _ := w.idp(t, conn.Token, http.MethodPost, "/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Engineering", "members": []map[string]any{{"value": ada["id"]}},
	}); status != http.StatusCreated {
		t.Fatalf("POST /Groups: %d", status)
	}
	_, adaID, err := w.sp.ActiveUser(ctx, conn.Connection.ID, adaExternalID)
	if err != nil {
		t.Fatal(err)
	}
	asAda := w.env.Browser(w.h)
	asAda.SetSession(w.env.SignIn(adaID))
	asAda.Get("/me").Expect(http.StatusOK)

	var res decommissionResponse
	acme.b.Post(connPath+"/decommission", nil).Expect(http.StatusOK).Decode(&res)
	if res.Status != scim.DecommissionComplete || res.ReconciledUsers != 1 {
		t.Fatalf("decommission = %+v", res)
	}
	if status := w.listUsers(t, conn.Token); status != http.StatusUnauthorized {
		t.Fatalf("the retired connection's token answered %d", status)
	}
	asAda.Get("/me").Expect(http.StatusUnauthorized)
	if !w.groups.wasDeleted(conn.Connection.ID) {
		t.Fatal("the group mapper was not told the group is gone")
	}
	if code := acme.b.Post(connPath+"/rotate", nil).Expect(http.StatusConflict).ErrorCode(); code != scim.ErrConnectionDecommission.Code {
		t.Fatalf("rotating a retired connection: %q", code)
	}

	// A second call is safe: it reports the finished decommission again.
	acme.b.Post(connPath+"/decommission", nil).Expect(http.StatusOK).Decode(&res)
	if res.Status != scim.DecommissionComplete {
		t.Fatalf("a repeated decommission = %+v", res)
	}
	kinds := w.eventKinds(t, acme, connPath)
	if !slices.Contains(kinds, scim.EventConnectionDecommissioning) || kinds[len(kinds)-1] != scim.EventConnectionDecommissioned {
		t.Fatalf("events = %v", kinds)
	}
}

// eventKinds reads the connection's event log through the settings route.
func (w *world) eventKinds(t *testing.T, c customer, connPath string) []scim.EventKind {
	t.Helper()
	var es []scim.Event
	c.b.Get(connPath + "/events").Expect(http.StatusOK).Decode(&es)
	kinds := make([]scim.EventKind, 0, len(es))
	for _, e := range es {
		kinds = append(kinds, e.Type)
	}
	return kinds
}

// adaUser is the SCIM user the IdP creates.
func adaUser() map[string]any {
	return map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   "ada@acme.test",
		"externalId": adaExternalID,
		"name":       map[string]string{"givenName": "Ada", "familyName": "Lovelace"},
		"emails":     []map[string]any{{"value": "ada@acme.test", "type": "work", "primary": true}},
	}
}

// recordGroups is a GroupMapper that remembers which connections lost a group.
type recordGroups struct {
	mu      sync.Mutex
	deleted map[string]bool
}

func (r *recordGroups) SyncGroup(context.Context, scim.GroupState) error { return nil }

func (r *recordGroups) DeleteGroup(_ context.Context, connection, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleted[connection] = true
	return nil
}

func (r *recordGroups) wasDeleted(connection string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.deleted[connection]
}
