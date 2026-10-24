package organization

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// TestAuditAccessors: every request names its organization and, where it
// has one, its target member, so plugin/audit files the event correctly.
func TestAuditAccessors(t *testing.T) {
	orgs := map[string]interface{ AuditOrgID() string }{
		"org": OrgRequest{OrgID: "o"}, "invite": InviteRequest{OrgID: "o"}, "member": MemberRequest{OrgID: "o"},
		"set-role": SetRoleRequest{OrgID: "o"}, "update": UpdateRequest{OrgID: "o"}, "get": GetRequest{OrgID: "o"},
		"set-active": SetActiveRequest{OrgID: "o"}, "permission": PermissionRequest{OrgID: "o"}, "team": CreateTeamRequest{OrgID: "o"},
		"create-role": CreateRoleRequest{OrgID: "o"}, "update-role": UpdateRoleRequest{OrgID: "o"}, "role": RoleRequest{OrgID: "o"},
	}
	for name, r := range orgs {
		if r.AuditOrgID() != "o" {
			t.Errorf("%s: AuditOrgID = %q", name, r.AuditOrgID())
		}
	}
	targets := map[string]interface{ TargetUserID() string }{
		"member": MemberRequest{UserID: "u"}, "set-role": SetRoleRequest{UserID: "u"}, "team-member": TeamMemberRequest{UserID: "u"},
	}
	for name, r := range targets {
		if r.TargetUserID() != "u" {
			t.Errorf("%s: TargetUserID = %q", name, r.TargetUserID())
		}
	}
}

// TestTopLevelFields_RejectBadJSON: each request with top-level fields
// refuses a body that is not a JSON object rather than half-decoding it.
func TestTopLevelFields_RejectBadJSON(t *testing.T) {
	for name, dst := range map[string]any{
		"create": &CreateRequest{}, "org-update": &OrgUpdate{}, "invite": &InviteRequest{}, "team": &CreateTeamRequest{},
		"team-update": &TeamUpdate{}, "role": &CreateRoleRequest{}, "role-update": &RoleUpdate{},
	} {
		if err := json.Unmarshal([]byte(`[1]`), dst); err == nil {
			t.Errorf("%s decoded a list", name)
		}
	}
}

// TestSession_NeedsASessionRow: a call with no session, or an API key's,
// has nowhere to hold an active organization; resolving "the active one"
// for it is ErrNoActiveOrg.
func TestSession_NeedsASessionRow(t *testing.T) {
	for _, c := range []*auth.Call{{}, {Session: &auth.Session{APIKeyID: "key_1"}}} {
		if _, err := session(c); !errors.Is(err, auth.ErrSessionDataUnavailable) {
			t.Errorf("session(%+v) = %v", c.Session, err)
		}
		if _, err := New().resolveOrg(context.Background(), c, ""); !errors.Is(err, ErrNoActiveOrg) {
			t.Errorf("resolveOrg = %v", err)
		}
	}
	if s, err := session(&auth.Call{Session: &auth.Session{ID: "ses_1"}}); err != nil || s.ID != "ses_1" {
		t.Fatalf("a real session = %+v %v", s, err)
	}
}

// TestMembersPageQuery_PagesInJoinOrder pins the paged statement: the
// members query, ordered by joined-at then user id so a page boundary never
// splits ties differently, with the limit and offset bound.
func TestMembersPageQuery_PagesInJoinOrder(t *testing.T) {
	p := wireNoDB(t)
	var m Member
	q, err := MembersPageQuery(p.core, "org_1", &m, 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`INNER JOIN "auth_user"`, `ORDER BY "om"."joined_at" ASC, "om"."user_id" ASC`, `LIMIT`, `OFFSET`} {
		if !strings.Contains(q.SQL, want) {
			t.Fatalf("SQL lacks %s:\n%s", want, q.SQL)
		}
	}
	if len(q.Args) != 3 || q.Args[0] != "org_1" || q.Args[1] != 10 || q.Args[2] != 20 {
		t.Fatalf("args = %#v", q.Args)
	}
}
