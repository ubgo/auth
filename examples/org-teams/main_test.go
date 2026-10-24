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
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/phone"
)

const (
	alice        = "alice@example.com"
	bob          = "bob@example.com"
	carol        = "carol@example.com"
	testPassword = "correct horse battery staple"
	// carolPhone is Carol's number as she types it; carolE164 is how the
	// phone plugin stores it.
	carolPhone = "+1 (555) 010-0177"
	carolE164  = "+15550100177"
	// designerRole is the role Acme defines for itself at run time.
	designerRole organization.Role = "designer"
)

// TestOrgTeams_TeamsRolesAndInvites walks the whole flow: Alice creates Acme
// (it becomes her active organization and gets a default team), adds a
// Design team, defines a "designer" role, and invites Bob by email into
// Design with it and Carol by text message. Bob, as a designer, may manage
// team members but not create teams; the hook refuses a reserved team name
// and reports every member who joins.
func TestOrgTeams_TeamsRolesAndInvites(t *testing.T) {
	a, box, joins := newTestAuth(t)
	h, err := newHandler(a)
	if err != nil {
		t.Fatal(err)
	}
	aliceB, bobB, carolB := newBrowser(t, h), newBrowser(t, h), newBrowser(t, h)

	signUpVerified(t, a, box, aliceB, alice, "Alice")
	if e := get[errorAnswer](t, aliceB, "/workspace", http.StatusConflict); e.Error.Code != errNoWorkspace.Code {
		t.Fatalf("workspace before any organization: %+v", e.Error)
	}
	org := post[organization.Org](t, aliceB, "/auth/organization/create", organization.CreateRequest{Name: "Acme", Slug: "acme"}, http.StatusOK)

	// Creating made Acme active, so the calls below leave orgId out.
	active := get[organization.ActiveResult](t, aliceB, "/auth/organization/active", http.StatusOK)
	if active.OrgID == nil || *active.OrgID != org.ID {
		t.Fatalf("active after create = %+v", active)
	}
	if ws := get[workspaceResponse](t, aliceB, "/workspace", http.StatusOK); ws.OrgID != org.ID || ws.TeamID != "" {
		t.Fatalf("/workspace = %+v", ws)
	}
	teams := get[organization.TeamsResult](t, aliceB, "/auth/organization/list-teams", http.StatusOK).Teams
	if len(teams) != 1 || teams[0].Name != "Acme" || teams[0].MemberCount != 1 {
		t.Fatalf("default team = %+v", teams)
	}
	design := post[organization.Team](t, aliceB, "/auth/organization/create-team", organization.CreateTeamRequest{Name: "Design"}, http.StatusOK)
	if e := post[errorAnswer](t, aliceB, "/auth/organization/create-team", organization.CreateTeamRequest{Name: "Everyone"}, http.StatusBadRequest); e.Error.Code != ErrReservedTeamName.Code {
		t.Fatalf("reserved team name: %+v", e.Error)
	}

	// A role of Acme's own: may add and remove team members, nothing else.
	role := post[organization.OrgRole](t, aliceB, "/auth/organization/create-role", organization.CreateRoleRequest{
		Role: designerRole, Permission: access.Permissions{organization.ResourceTeam: {organization.ActionUpdate}},
	}, http.StatusOK)
	if role.Role != designerRole {
		t.Fatalf("created role = %+v", role)
	}

	// Bob is invited by email, into Design, as a designer.
	post[none](t, aliceB, "/auth/organization/invite", organization.InviteRequest{Email: bob, Role: designerRole, TeamID: design.ID}, http.StatusOK)
	signUpVerified(t, a, box, bobB, bob, "Bob")
	bobInvite := get[organization.InvitesResult](t, bobB, "/auth/organization/invites", http.StatusOK).Invites
	if len(bobInvite) != 1 || bobInvite[0].Role != designerRole {
		t.Fatalf("bob's invitations = %+v", bobInvite)
	}
	post[organization.Org](t, bobB, "/auth/organization/accept", organization.AcceptRequest{InviteID: bobInvite[0].ID}, http.StatusOK)
	bobTeams := get[organization.TeamsResult](t, bobB, "/auth/organization/list-user-teams", http.StatusOK).Teams
	if len(bobTeams) != 1 || bobTeams[0].ID != design.ID {
		t.Fatalf("bob's teams = %+v", bobTeams)
	}

	// Carol is invited by text message. She accepts once she holds that
	// number, verified, on her account.
	post[none](t, aliceB, "/auth/organization/invite", organization.InviteRequest{Kind: phone.KindPhone, Identifier: carolPhone, Role: organization.RoleMember}, http.StatusOK)
	if text := box.lastText(a, carolE164); !strings.Contains(text, baseURL+organization.DefaultInvitePage) {
		t.Fatalf("invitation text = %q", text)
	}
	signUpVerified(t, a, box, carolB, carol, "Carol")
	if got := get[organization.InvitesResult](t, carolB, "/auth/organization/invites", http.StatusOK).Invites; len(got) != 0 {
		t.Fatalf("carol's invitations before her number is verified = %+v", got)
	}
	post[auth.Done](t, carolB, "/auth/phone/add", fields{"phone": carolPhone}, http.StatusOK)
	post[auth.Done](t, carolB, "/auth/phone/verify", fields{"phone": carolPhone, "code": box.lastCode(t, a, carolE164)}, http.StatusOK)
	carolInvite := get[organization.InvitesResult](t, carolB, "/auth/organization/invites", http.StatusOK).Invites
	if len(carolInvite) != 1 || carolInvite[0].Kind != phone.KindPhone || carolInvite[0].Identifier != carolE164 {
		t.Fatalf("carol's invitations = %+v", carolInvite)
	}
	post[organization.Org](t, carolB, "/auth/organization/accept", organization.AcceptRequest{InviteID: carolInvite[0].ID}, http.StatusOK)

	// Bob's role grants team:update, so he adds Carol to Design; it does not
	// grant team:create.
	carolID := memberID(t, get[organization.MembersResult](t, aliceB, "/auth/organization/members", http.StatusOK).Members, "Carol")
	post[none](t, bobB, "/auth/organization/add-team-member", organization.TeamMemberRequest{TeamID: design.ID, UserID: carolID}, http.StatusOK)
	if e := post[errorAnswer](t, bobB, "/auth/organization/create-team", organization.CreateTeamRequest{OrgID: org.ID, Name: "Bob's"}, http.StatusForbidden); e.Error.Code != organization.ErrForbidden.Code {
		t.Fatalf("designer creating a team: %+v", e.Error)
	}

	// Choosing a team makes its organization active too.
	post[organization.ActiveResult](t, carolB, "/auth/organization/set-active-team", fields{"teamId": design.ID}, http.StatusOK)
	if ws := get[workspaceResponse](t, carolB, "/workspace", http.StatusOK); ws.OrgID != org.ID || ws.TeamID != design.ID {
		t.Fatalf("carol's /workspace = %+v", ws)
	}

	// The hook saw both joins, with the roles they joined with.
	got := joins.roles()
	if !slices.Equal(got, []organization.Role{designerRole, organization.RoleMember}) {
		t.Fatalf("joins seen by the hook = %v", got)
	}
}

// TestOrgTeams_ErrorsUndoTheOperation: a hook's refusal leaves nothing
// behind, and a role in use cannot be deleted.
func TestOrgTeams_ErrorsUndoTheOperation(t *testing.T) {
	a, box, _ := newTestAuth(t)
	h, err := newHandler(a)
	if err != nil {
		t.Fatal(err)
	}
	aliceB, bobB := newBrowser(t, h), newBrowser(t, h)
	signUpVerified(t, a, box, aliceB, alice, "Alice")
	post[organization.Org](t, aliceB, "/auth/organization/create", organization.CreateRequest{Name: "Acme", Slug: "acme"}, http.StatusOK)
	post[errorAnswer](t, aliceB, "/auth/organization/create-team", organization.CreateTeamRequest{Name: " everyone "}, http.StatusBadRequest)
	if teams := get[organization.TeamsResult](t, aliceB, "/auth/organization/list-teams", http.StatusOK).Teams; len(teams) != 1 {
		t.Fatalf("teams after a refused create = %+v", teams)
	}

	post[organization.OrgRole](t, aliceB, "/auth/organization/create-role", organization.CreateRoleRequest{
		Role: designerRole, Permission: access.Permissions{organization.ResourceTeam: {organization.ActionUpdate}},
	}, http.StatusOK)
	post[none](t, aliceB, "/auth/organization/invite", organization.InviteRequest{Email: bob, Role: designerRole}, http.StatusOK)
	signUpVerified(t, a, box, bobB, bob, "Bob")
	inv := get[organization.InvitesResult](t, bobB, "/auth/organization/invites", http.StatusOK).Invites
	post[organization.Org](t, bobB, "/auth/organization/accept", organization.AcceptRequest{InviteID: inv[0].ID}, http.StatusOK)
	if e := post[errorAnswer](t, aliceB, "/auth/organization/delete-role", fields{"roleName": string(designerRole)}, http.StatusConflict); e.Error.Code != organization.ErrRoleInUse.Code {
		t.Fatalf("deleting a role in use: %+v", e.Error)
	}
}

// joinLog records the members the AfterAddMember hook reported.
type joinLog struct {
	mu      sync.Mutex
	changes []organization.MemberChange
}

// add records m; it is the joined callback newAuth takes.
func (j *joinLog) add(m organization.MemberChange) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.changes = append(j.changes, m)
}

// roles returns the role of each recorded join, in order.
func (j *joinLog) roles() []organization.Role {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]organization.Role, 0, len(j.changes))
	for _, c := range j.changes {
		out = append(out, c.Role)
	}
	return out
}

// signUpVerified signs name up in b and verifies the address from the mail.
func signUpVerified(t *testing.T, a *auth.Auth, box *outbox, b *browser, addr, name string) {
	t.Helper()
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": addr, "password": testPassword, "name": name}, http.StatusOK)
	post[none](t, b, "/auth/email/verify", fields{"token": box.lastToken(t, a, addr)}, http.StatusOK)
}

// memberID finds a member's user id by name.
func memberID(t *testing.T, members []organization.MemberView, name string) string {
	t.Helper()
	for _, m := range members {
		if m.User.Name == name {
			return m.User.ID
		}
	}
	t.Fatalf("no member named %s in %+v", name, members)
	return ""
}

// newTestAuth builds the app's Auth on a fresh SQLite file with an outbox
// that records mail and texts, and a log of the joins the hook reports.
func newTestAuth(t *testing.T) (*auth.Auth, *outbox, *joinLog) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	box, joins := &outbox{}, &joinLog{}
	a, err := newAuth(db, box, smsSender{box}, joins.add)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, box, joins
}

// message is one recorded mail or text.
type message struct{ to, text string }

// outbox records every mail and text sent.
type outbox struct {
	mu   sync.Mutex
	sent []message
}

// Send records a mail.
func (o *outbox) Send(_ context.Context, m email.Mail) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sent = append(o.sent, message{to: m.To, text: m.Text})
	return nil
}

// smsSender records texts in the same outbox.
type smsSender struct{ box *outbox }

// Send records a text.
func (s smsSender) Send(_ context.Context, to, text string) error {
	s.box.mu.Lock()
	defer s.box.mu.Unlock()
	s.box.sent = append(s.box.sent, message{to: to, text: text})
	return nil
}

// lastText returns the newest message to to, after deliveries finished.
func (o *outbox) lastText(a *auth.Auth, to string) string {
	a.WaitDeliveries()
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := len(o.sent) - 1; i >= 0; i-- {
		if o.sent[i].to == to {
			return o.sent[i].text
		}
	}
	return ""
}

// codeInText finds the six-digit code in a text.
var codeInText = regexp.MustCompile(`\b\d{6}\b`)

// lastCode returns the code in the newest text to number.
func (o *outbox) lastCode(t *testing.T, a *auth.Auth, number string) string {
	t.Helper()
	code := codeInText.FindString(o.lastText(a, number))
	if code == "" {
		t.Fatalf("no code texted to %s", number)
	}
	return code
}

// lastToken returns the token of the newest link mailed to addr.
func (o *outbox) lastToken(t *testing.T, a *auth.Auth, addr string) string {
	t.Helper()
	for _, field := range strings.Fields(o.lastText(a, addr)) {
		if u, err := url.Parse(field); err == nil && u.Query().Get("token") != "" {
			return u.Query().Get("token")
		}
	}
	t.Fatalf("no link mailed to %s", addr)
	return ""
}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would. HTTPS, because the session cookie is
// __Host- and Secure.
type browser struct {
	srv    *httptest.Server
	client *http.Client
}

// newBrowser serves h over HTTPS for the test and gives it a client with a
// cookie jar, so the __Host- session cookie is kept between calls.
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
	req, err := http.NewRequest(http.MethodPost, b.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
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

// do sends req, checks the status and decodes the answer as Out; a wrong
// status fails the test with the body.
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
