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
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
)

const testPassword = "correct horse battery staple"

// zone is a fake DNS zone: the TXT records published under each name. A
// name holds several, as in DNS.
type zone struct {
	mu      sync.Mutex
	records map[string][]string
}

// publish adds a TXT record to name.
func (z *zone) publish(name, value string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.records[name] = append(z.records[name], value)
}

// verifier is the zone as an organization.DomainVerifier.
func (z *zone) verifier() organization.DomainVerifier {
	return organization.DomainVerifierFunc(func(_ context.Context, ch organization.DomainChallenge) (bool, error) {
		z.mu.Lock()
		defer z.mu.Unlock()
		return slices.Contains(z.records[ch.RecordName], ch.RecordValue), nil
	})
}

// orgs lists the organizations b's user is in, by slug.
func orgs(t *testing.T, b *browser) map[string]organization.Role {
	t.Helper()
	out := map[string]organization.Role{}
	for _, o := range get[organization.ListResult](t, b, "/auth/organization/list", http.StatusOK).Orgs {
		out[o.Slug] = o.Role
	}
	return out
}

// TestDomains_AutoJoinOnlyAfterVerification walks the security core over
// HTTP: an admin claims acme.com and proves it with a TXT record; a
// colleague who signs up with an acme.com address joins only once that
// address is verified; a domain claimed but never proved enrolls nobody; a
// second organization cannot take a proved domain; a member cannot add a
// domain; a public mail domain is refused.
func TestDomains_AutoJoinOnlyAfterVerification(t *testing.T) {
	z := &zone{records: map[string][]string{}}
	a, box := newTestAuth(t, z.verifier())
	h := newHandler(a)
	alice, eve, bob, mallory, carl := newBrowser(t, h), newBrowser(t, h), newBrowser(t, h), newBrowser(t, h), newBrowser(t, h)

	// Alice's own address is elsewhere, so only DNS can prove acme.com.
	signUpVerified(t, a, box, alice, "alice@founders.dev", "Alice")
	acme := post[organization.Org](t, alice, "/auth/organization/create", organization.CreateRequest{Name: "Acme", Slug: "acme"}, http.StatusOK)
	signUpVerified(t, a, box, eve, "eve@squat.dev", "Eve")
	squat := post[organization.Org](t, eve, "/auth/organization/create", organization.CreateRequest{Name: "Squat", Slug: "squat"}, http.StatusOK)

	if e := post[errorAnswer](t, alice, "/auth/organization/add-domain", organization.AddDomainRequest{OrgID: acme.ID, Domain: "Gmail.com"}, http.StatusBadRequest); e.Error.Code != organization.ErrPublicDomain.Code {
		t.Fatalf("public domain: %+v", e.Error)
	}
	dom := post[organization.OrgDomain](t, alice, "/auth/organization/add-domain", organization.AddDomainRequest{OrgID: acme.ID, Domain: " ACME.com. ", Enrollment: organization.EnrollJoin, Role: organization.RoleMember}, http.StatusOK)
	if dom.Domain != "acme.com" || dom.Verified || dom.RecordName != "_auth-verification.acme.com" || !strings.HasPrefix(dom.RecordValue, "auth-domain-verification=") {
		t.Fatalf("added = %+v", dom)
	}
	// Eve may claim acme.com too while nobody has proved it: a claim alone
	// blocks no one.
	eveDom := post[organization.OrgDomain](t, eve, "/auth/organization/add-domain", organization.AddDomainRequest{OrgID: squat.ID, Domain: "acme.com", Enrollment: organization.EnrollJoin}, http.StatusOK)

	// Unproved: Bob verifies an acme.com address and joins nothing.
	signUpVerified(t, a, box, bob, "bob@acme.com", "Bob")
	if got := orgs(t, bob); len(got) != 0 {
		t.Fatalf("an unverified domain enrolled bob: %v", got)
	}
	if e := post[errorAnswer](t, alice, "/auth/organization/verify-domain", organization.DomainRequest{DomainID: dom.ID}, http.StatusConflict); e.Error.Code != organization.ErrDomainNotVerified.Code {
		t.Fatalf("verify before publishing: %+v", e.Error)
	}
	z.publish(dom.RecordName, dom.RecordValue)
	if v := post[organization.OrgDomain](t, alice, "/auth/organization/verify-domain", organization.DomainRequest{DomainID: dom.ID}, http.StatusOK); !v.Verified {
		t.Fatalf("verified = %+v", v)
	}
	// Even with her own record published, Eve cannot have it: Acme proved
	// it first.
	z.publish(eveDom.RecordName, eveDom.RecordValue)
	if e := post[errorAnswer](t, eve, "/auth/organization/verify-domain", organization.DomainRequest{DomainID: eveDom.ID}, http.StatusConflict); e.Error.Code != organization.ErrDomainTaken.Code {
		t.Fatalf("second organization verifying acme.com: %+v", e.Error)
	}
	if e := post[errorAnswer](t, eve, "/auth/organization/add-domain", organization.AddDomainRequest{OrgID: squat.ID, Domain: "acme.com"}, http.StatusConflict); e.Error.Code != organization.ErrDomainTaken.Code {
		t.Fatalf("adding a proved domain: %+v", e.Error)
	}
	other := post[organization.Org](t, eve, "/auth/organization/create", organization.CreateRequest{Name: "Other", Slug: "other"}, http.StatusOK)
	if e := post[errorAnswer](t, eve, "/auth/organization/add-domain", organization.AddDomainRequest{OrgID: other.ID, Domain: "acme.com"}, http.StatusConflict); e.Error.Code != organization.ErrDomainTaken.Code {
		t.Fatalf("a fresh organization adding a proved domain: %+v", e.Error)
	}

	// Mallory signs up with an acme.com address but never verifies it.
	post[none](t, mallory, "/auth/password/sign-up", fields{"identifier": "mallory@acme.com", "password": testPassword, "name": "Mallory"}, http.StatusOK)
	if got := orgs(t, mallory); len(got) != 0 {
		t.Fatalf("an unverified address joined: %v", got)
	}
	// Carl verifies his: he is a member at once.
	signUpVerified(t, a, box, carl, "carl@acme.com", "Carl")
	if got := orgs(t, carl); got["acme"] != organization.RoleMember || len(got) != 1 {
		t.Fatalf("carl's organizations = %v", got)
	}
	// Mallory verifying later joins then, not before.
	post[none](t, mallory, "/auth/email/verify", fields{"token": box.lastToken(t, a, "mallory@acme.com")}, http.StatusOK)
	if got := orgs(t, mallory); got["acme"] != organization.RoleMember {
		t.Fatalf("mallory after verifying = %v", got)
	}

	// Carl is a plain member: he cannot add, change or remove a domain.
	if e := post[errorAnswer](t, carl, "/auth/organization/add-domain", organization.AddDomainRequest{OrgID: acme.ID, Domain: "acme.io"}, http.StatusForbidden); e.Error.Code != organization.ErrForbidden.Code {
		t.Fatalf("member adding a domain: %+v", e.Error)
	}
	if e := post[errorAnswer](t, carl, "/auth/organization/remove-domain", organization.DomainRequest{DomainID: dom.ID}, http.StatusForbidden); e.Error.Code != organization.ErrForbidden.Code {
		t.Fatalf("member removing a domain: %+v", e.Error)
	}
	// A stranger cannot tell the domain exists.
	if e := post[errorAnswer](t, eve, "/auth/organization/remove-domain", organization.DomainRequest{DomainID: dom.ID}, http.StatusNotFound); e.Error.Code != organization.ErrDomainNotFound.Code {
		t.Fatalf("stranger removing a domain: %+v", e.Error)
	}
	// Nobody becomes an owner through a domain.
	owner := organization.RoleOwner
	if e := post[errorAnswer](t, alice, "/auth/organization/update-domain", organization.UpdateDomainRequest{DomainID: dom.ID, Role: &owner}, http.StatusBadRequest); e.Error.Code != organization.ErrDomainRole.Code {
		t.Fatalf("owner role on a domain: %+v", e.Error)
	}
	list := get[organization.DomainsResult](t, carl, "/auth/organization/list-domains?orgId="+acme.ID, http.StatusOK)
	if len(list.Domains) != 1 || !list.Domains[0].Verified {
		t.Fatalf("list = %+v", list)
	}
}

// TestDomains_SuggestionAndInvitation: in suggestion mode a verified
// colleague sees the organization, asks to join and an admin approves; in
// invitation mode the colleague gets a pending invitation to accept.
func TestDomains_SuggestionAndInvitation(t *testing.T) {
	a, box := newTestAuth(t, nil)
	h := newHandler(a)
	alice, dave, erin, frank := newBrowser(t, h), newBrowser(t, h), newBrowser(t, h), newBrowser(t, h)

	// TrustVerifiedEmail: Alice's verified acme.com address proves the
	// domain when she adds it, with no DNS.
	signUpVerified(t, a, box, alice, "alice@acme.com", "Alice")
	acme := post[organization.Org](t, alice, "/auth/organization/create", organization.CreateRequest{Name: "Acme", Slug: "acme"}, http.StatusOK)
	dom := post[organization.OrgDomain](t, alice, "/auth/organization/add-domain", organization.AddDomainRequest{OrgID: acme.ID, Domain: "acme.com", Enrollment: organization.EnrollSuggestion}, http.StatusOK)
	if !dom.Verified {
		t.Fatalf("a verified address at the domain should prove it: %+v", dom)
	}

	signUpVerified(t, a, box, dave, "dave@acme.com", "Dave")
	if got := orgs(t, dave); len(got) != 0 {
		t.Fatalf("suggestion mode joined dave: %v", got)
	}
	sug := get[organization.SuggestionsResult](t, dave, "/auth/organization/domain-suggestions", http.StatusOK).Suggestions
	if len(sug) != 1 || sug[0].OrgID != acme.ID || sug[0].Requested {
		t.Fatalf("suggestions = %+v", sug)
	}
	req := post[organization.MembershipRequest](t, dave, "/auth/organization/accept-suggestion", organization.DomainRequest{DomainID: dom.ID}, http.StatusOK)
	if sug := get[organization.SuggestionsResult](t, dave, "/auth/organization/domain-suggestions", http.StatusOK).Suggestions; len(sug) != 1 || !sug[0].Requested {
		t.Fatalf("after asking = %+v", sug)
	}
	// Dave cannot approve himself.
	if e := post[errorAnswer](t, dave, "/auth/organization/approve-membership-request", organization.RequestIDRequest{RequestID: req.ID}, http.StatusNotFound); e.Error.Code != organization.ErrRequestInvalid.Code {
		t.Fatalf("self-approval: %+v", e.Error)
	}
	reqs := get[organization.MembershipRequestsResult](t, alice, "/auth/organization/list-membership-requests?orgId="+acme.ID, http.StatusOK).Requests
	if len(reqs) != 1 || reqs[0].User.Name != "Dave" {
		t.Fatalf("requests = %+v", reqs)
	}
	post[none](t, alice, "/auth/organization/approve-membership-request", organization.RequestIDRequest{RequestID: req.ID}, http.StatusOK)
	if got := orgs(t, dave); got["acme"] != organization.RoleMember {
		t.Fatalf("dave after approval = %v", got)
	}

	// Frank asks and is rejected: Acme is not suggested to him again.
	signUpVerified(t, a, box, frank, "frank@acme.com", "Frank")
	freq := post[organization.MembershipRequest](t, frank, "/auth/organization/accept-suggestion", organization.DomainRequest{DomainID: dom.ID}, http.StatusOK)
	post[none](t, alice, "/auth/organization/reject-membership-request", organization.RequestIDRequest{RequestID: freq.ID}, http.StatusOK)
	if sug := get[organization.SuggestionsResult](t, frank, "/auth/organization/domain-suggestions", http.StatusOK).Suggestions; len(sug) != 0 {
		t.Fatalf("rejected user still sees %+v", sug)
	}
	if e := post[errorAnswer](t, frank, "/auth/organization/accept-suggestion", organization.DomainRequest{DomainID: dom.ID}, http.StatusNotFound); e.Error.Code != organization.ErrRequestInvalid.Code {
		t.Fatalf("asking again after rejection: %+v", e.Error)
	}

	mode := organization.EnrollInvitation
	post[organization.OrgDomain](t, alice, "/auth/organization/update-domain", organization.UpdateDomainRequest{DomainID: dom.ID, Enrollment: &mode}, http.StatusOK)
	signUpVerified(t, a, box, erin, "erin@acme.com", "Erin")
	invites := get[organization.InvitesResult](t, erin, "/auth/organization/invites", http.StatusOK).Invites
	if len(invites) != 1 || invites[0].OrgID != acme.ID {
		t.Fatalf("erin's invitations = %+v", invites)
	}
	post[organization.Org](t, erin, "/auth/organization/accept", organization.AcceptRequest{InviteID: invites[0].ID}, http.StatusOK)
	if got := orgs(t, erin); got["acme"] != organization.RoleMember {
		t.Fatalf("erin after accepting = %v", got)
	}
}

// TestPermissionsOf_RuntimeRole: PermissionsOf merges a role created at run
// time (DynamicRoles) with a static part, deduplicated and sorted, and a
// runtime role of another organization grants nothing.
func TestPermissionsOf_RuntimeRole(t *testing.T) {
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	box := &mailbox{}
	org := organization.New(organization.DynamicRoles(organization.DynamicRolesConfig{}))
	a, err := auth.New(auth.WithDB(db, sqlb.SQLiteDialect{}), auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(box)), password.New(), org))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	alice := newBrowser(t, newHandler(a))
	signUpVerified(t, a, box, alice, "alice@acme.com", "Alice")
	acme := post[organization.Org](t, alice, "/auth/organization/create", organization.CreateRequest{Name: "Acme", Slug: "acme"}, http.StatusOK)
	other := post[organization.Org](t, alice, "/auth/organization/create", organization.CreateRequest{Name: "Other", Slug: "other"}, http.StatusOK)
	post[organization.OrgRole](t, alice, "/auth/organization/create-role", organization.CreateRoleRequest{
		OrgID: acme.ID, Role: "auditor",
		Permission: access.Permissions{organization.ResourceTeam: {organization.ActionUpdate, organization.ActionCreate}, organization.ResourceAC: {organization.ActionRead}},
	}, http.StatusOK)

	got, err := org.PermissionsOf(context.Background(), acme.ID, "auditor,member")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got[organization.ResourceTeam], []string{organization.ActionCreate, organization.ActionUpdate}) || !slices.Equal(got[organization.ResourceAC], []string{organization.ActionRead}) {
		t.Fatalf("auditor,member in acme = %v", got)
	}
	got, err = org.PermissionsOf(context.Background(), other.ID, "auditor")
	if err != nil || len(got) != 0 {
		t.Fatalf("acme's runtime role in another organization = %v, %v", got, err)
	}
}

// signUpVerified signs name up in b and verifies the address from the mail.
func signUpVerified(t *testing.T, a *auth.Auth, box *mailbox, b *browser, addr, name string) {
	t.Helper()
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": addr, "password": testPassword, "name": name}, http.StatusOK)
	post[none](t, b, "/auth/email/verify", fields{"token": box.lastToken(t, a, addr)}, http.StatusOK)
}

// newTestAuth builds the app's Auth on a fresh SQLite file with a mailbox
// that records mail instead of printing it.
func newTestAuth(t *testing.T, verifier organization.DomainVerifier) (*auth.Auth, *mailbox) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	box := &mailbox{}
	a, err := newAuth(db, box, verifier)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, box
}

// mailbox records every mail sent.
type mailbox struct {
	mu   sync.Mutex
	sent []email.Mail
}

// Send records m.
func (m *mailbox) Send(_ context.Context, mail email.Mail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, mail)
	return nil
}

// last returns the newest mail sent to addr, after every delivery in flight.
func (m *mailbox) last(t *testing.T, a *auth.Auth, addr string) email.Mail {
	t.Helper()
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To == addr {
			return m.sent[i]
		}
	}
	t.Fatalf("no mail sent to %s", addr)
	return email.Mail{}
}

// lastToken returns the token of the newest link mailed to addr.
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

// fields is a JSON request body as a client writes it. The library's request
// types that carry a secret (auth.Token) encode it as "[redacted]" on
// purpose, so those bodies are written as plain maps.
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
