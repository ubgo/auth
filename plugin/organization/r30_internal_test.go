package organization

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/sqlb"
)

func TestRole_PartsHasJoin(t *testing.T) {
	r := Role(" admin , billing,,admin")
	if got := r.Parts(); len(got) != 3 || got[0] != RoleAdmin || got[1] != "billing" {
		t.Fatalf("parts = %v", got)
	}
	if !r.Has("billing") || r.Has("bill") || Role("").Has("") {
		t.Fatal("Has is not exact")
	}
	if got := JoinRoles(RoleAdmin, "billing,admin", "", RoleMember); got != "admin,billing,member" {
		t.Fatalf("join = %q", got)
	}
	if Role("member,owner").Rank() != RoleOwner.Rank() || Role("billing").Rank() != 0 {
		t.Fatal("rank of several roles is not the highest")
	}
}

func TestRole_UnmarshalJSON(t *testing.T) {
	var in SetRoleRequest
	if err := json.Unmarshal([]byte(`{"role":["admin","member","admin"]}`), &in); err != nil || in.Role != "admin,member" {
		t.Fatalf("array = %q %v", in.Role, err)
	}
	if err := json.Unmarshal([]byte(`{"role":"owner"}`), &in); err != nil || in.Role != RoleOwner {
		t.Fatalf("string = %q %v", in.Role, err)
	}
	if err := json.Unmarshal([]byte(`{"role":{"x":1}}`), &in); !errors.Is(err, ErrBadRole) {
		t.Fatalf("object: %v", err)
	}
}

func TestCheckMetadata(t *testing.T) {
	for raw, ok := range map[string]bool{"": true, `{}`: true, `{"a":[1]}`: true, `[]`: false, `"s"`: false, `null`: false, `{`: false} {
		if err := checkMetadata(auth.AppData(raw)); (err == nil) != ok {
			t.Errorf("%q: %v", raw, err)
		}
	}
	big := auth.AppData(`{"a":"` + strings.Repeat("x", MaxMetadataSize) + `"}`)
	if !errors.Is(checkMetadata(big), ErrBadMetadata) {
		t.Fatal("oversized metadata accepted")
	}
}

func TestMemberOrderAndFilter(t *testing.T) {
	for _, by := range MemberSortValues {
		for _, dir := range []Direction{"", Asc, Desc} {
			if _, err := memberOrder(by, dir); err != nil {
				t.Errorf("%s %s: %v", by, dir, err)
			}
		}
	}
	if _, err := memberOrder("email", Asc); !errors.Is(err, ErrBadQuery) {
		t.Fatal("unknown sort accepted")
	}
	if _, err := memberOrder(SortName, "up"); !errors.Is(err, ErrBadQuery) {
		t.Fatal("unknown direction accepted")
	}
	for _, f := range []MemberField{FieldRole, FieldUserID, FieldName} {
		for _, op := range []FilterOperator{"", OpEq, OpNe, OpIn, OpNotIn, OpContains, OpStartsWith, OpEndsWith} {
			for _, engine := range []string{auth.EngineSQLite, auth.EnginePostgres} {
				if _, err := memberFilter(engine, f, op, "a,b"); err != nil {
					t.Errorf("%s %s %s: %v", engine, f, op, err)
				}
			}
		}
	}
	for _, f := range []MemberField{FieldJoinedAt, FieldCreatedAt} {
		for _, op := range []FilterOperator{"", OpEq, OpNe, OpLt, OpLte, OpGt, OpGte} {
			if _, err := memberFilter(auth.EngineSQLite, f, op, "2026-10-08T10:00:00Z"); err != nil {
				t.Errorf("%s %s: %v", f, op, err)
			}
		}
	}
	for _, c := range []struct {
		f  MemberField
		op FilterOperator
		v  string
	}{
		{"email", OpEq, "a"}, {FieldRole, OpGt, "a"}, {FieldName, OpLte, "a"}, {FieldRole, OpIn, ","}, {FieldRole, "like", "a"},
		{FieldJoinedAt, OpEq, "yesterday"}, {FieldJoinedAt, OpContains, "2026-10-08T10:00:00Z"}, {FieldCreatedAt, OpIn, "2026-10-08T10:00:00Z"},
	} {
		if _, err := memberFilter(auth.EngineSQLite, c.f, c.op, c.v); !errors.Is(err, ErrBadQuery) {
			t.Errorf("%+v: %v", c, err)
		}
	}
	if len(FilterOperatorValues) != 11 || len(MemberFieldValues) != 5 || len(InviteStatusValues) != 4 {
		t.Fatal("a closed set lost a value")
	}
}

func TestPermissionDoc_RoundTrip(t *testing.T) {
	d := PermissionDoc{ResourceMember: {ActionCreate}}
	v, err := d.Value()
	if err != nil || v != `{"member":["create"]}` {
		t.Fatalf("value = %v %v", v, err)
	}
	var back PermissionDoc
	for _, src := range []any{v, []byte(v.(string))} {
		if err := back.Scan(src); err != nil || back[ResourceMember][0] != ActionCreate {
			t.Fatalf("scan %T: %v %v", src, back, err)
		}
	}
	if err := back.Scan(42); err == nil {
		t.Fatal("scanned an int")
	}
	if err := back.Scan("{"); err == nil {
		t.Fatal("scanned bad JSON")
	}
}

func TestDefaultRoles_MatchBetterAuth(t *testing.T) {
	roles := DefaultRoles()
	can := func(r Role, res, act string) bool {
		return roles[r].Allows(access.Request{res: access.All(act)})
	}
	if !can(RoleOwner, ResourceOrganization, ActionDelete) || can(RoleAdmin, ResourceOrganization, ActionDelete) {
		t.Fatal("only the owner deletes an organization")
	}
	if !can(RoleAdmin, ResourceInvitation, ActionCancel) || can(RoleMember, ResourceInvitation, ActionCreate) {
		t.Fatal("admin invites, member does not")
	}
	if !can(RoleMember, ResourceAC, ActionRead) || can(RoleMember, ResourceAC, ActionCreate) {
		t.Fatal("member reads roles only")
	}
	roles[RoleOwner] = access.Role{}
	if !DefaultRoles()[RoleOwner].Allows(access.Request{ResourceTeam: access.All(ActionCreate)}) {
		t.Fatal("DefaultRoles shares its map")
	}
}

func TestGuardCreator(t *testing.T) {
	p := New()
	if p.guardCreator(RoleAdmin, RoleMember, "admin,member") != nil {
		t.Fatal("admin blocked from non-owner roles")
	}
	if !errors.Is(p.guardCreator(RoleAdmin, "member,owner"), ErrForbidden) {
		t.Fatal("admin granted owner among several")
	}
	if p.guardCreator("member,owner", RoleOwner) != nil {
		t.Fatal("owner blocked")
	}
}

func TestOptionalTablesOperationsAndMigrations(t *testing.T) {
	plain := New()
	full := New(Teams(TeamsConfig{}), DynamicRoles(DynamicRolesConfig{}))
	if len(full.Tables())-len(plain.Tables()) != 3 || len(full.UserTables())-len(plain.UserTables()) != 1 {
		t.Fatal("teams and roles tables are not optional")
	}
	if len(full.Operations())-len(plain.Operations()) != 14 {
		t.Fatalf("operations: %d vs %d", len(full.Operations()), len(plain.Operations()))
	}
	mail := email.New(email.WithMailer(email.MailerFunc(func(context.Context, email.Mail) error { return nil })))
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(signInStub{}, mail, full)); err != nil {
		t.Fatal(err)
	}
	for _, e := range []string{auth.EnginePostgres, auth.EngineMySQL, auth.EngineSQLite} {
		ms, err := full.TypedMigrations(e, auth.TypesFor(e))
		if err != nil || len(ms) != 6 || ms[5].Name != migrationIdentifier {
			t.Fatalf("%s: %d %v", e, len(ms), err)
		}
		if e == auth.EngineMySQL && !strings.Contains(ms[2].Statements[0], "INDEX") {
			t.Fatal("mysql declares the active index inline")
		}
		if e != auth.EngineMySQL && len(ms[2].Statements) != 2 {
			t.Fatal("the active index is a separate statement")
		}
	}
	if _, err := full.TypedMigrations("oracle", auth.TypesFor("oracle")); err == nil {
		t.Fatal("unsupported engine accepted")
	}
}

func TestHardStop(t *testing.T) {
	now := time.Now()
	later := now.Add(time.Hour)
	if !hardStop(auth.Session{ExpiresAt: now}).Equal(now) || !hardStop(auth.Session{ExpiresAt: now, MaxExpiresAt: &later}).Equal(later) {
		t.Fatal("hard stop")
	}
}

func TestErrIsNoRows(t *testing.T) {
	other := errors.New("x")
	if errIsNoRows(sqlb.ErrNoRows, ErrNotMember) != ErrNotMember || errIsNoRows(other, ErrNotMember) != other {
		t.Fatal("mapping")
	}
}

// TestNoDatabase_NewOperations: the new operations surface the missing
// database rather than answering empty.
func TestNoDatabase_NewOperations(t *testing.T) {
	p := wireNoDB(t)
	ctx := context.Background()
	if _, err := p.RoleOf(ctx, "o", "u"); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("RoleOf: %v", err)
	}
	if _, err := p.Can(ctx, "o", "u", access.Request{}, ""); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("Can: %v", err)
	}
	if err := p.SessionEnded(ctx, "u", "s"); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("SessionEnded: %v", err)
	}
	if err := p.UserSessionsEnded(ctx, "u", "s"); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("UserSessionsEnded: %v", err)
	}
	if err := p.SessionReplaced(ctx, auth.Session{ID: "a"}, auth.Session{ID: "b"}); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("SessionReplaced: %v", err)
	}
	if _, err := p.Sweep(ctx, time.Now()); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("Sweep: %v", err)
	}
}

// TestMemberTextMatchIsCaseSensitive pins the fragment operators' SQL per
// engine: LIKE where it already keeps case, GLOB with the value's glob
// syntax escaped on SQLite, whose LIKE ignores case.
func TestMemberTextMatchIsCaseSensitive(t *testing.T) {
	render := func(engine string, op FilterOperator, v string) (string, []any) {
		t.Helper()
		var d sqlb.Dialect = sqlb.PostgresDialect{}
		if engine == auth.EngineSQLite {
			d = sqlb.SQLiteDialect{}
		}
		q, err := sqlb.NewSelect(d).Exprs(MemberUserID).From(TableMember).Where(memberTextMatch(engine, auth.UserName, op, v)).Build()
		if err != nil {
			t.Fatal(err)
		}
		return q.SQL, q.Args
	}
	for op, want := range map[FilterOperator]string{OpContains: "*a[*]b*", OpStartsWith: "a[*]b*", OpEndsWith: "*a[*]b"} {
		q, args := render(auth.EngineSQLite, op, "a*b")
		if !strings.Contains(q, "GLOB") || len(args) != 1 || args[0] != want {
			t.Errorf("sqlite %s: %s %v", op, q, args)
		}
		if q, _ := render(auth.EnginePostgres, op, "a*b"); !strings.Contains(q, "LIKE") {
			t.Errorf("postgres %s: %s", op, q)
		}
	}
	if got := escapeGlob("x?[y]*"); got != "x[?][[]y][*]" {
		t.Fatalf("escapeGlob = %q", got)
	}
}

// TestPredefined: only a request naming a configured role by name, never by
// id, is a predefined one.
func TestPredefined(t *testing.T) {
	p := New(WithRoles(map[Role]access.Role{"billing": DefaultAccessControl.MustRole(access.Permissions{})}))
	for _, c := range []struct {
		id   string
		name Role
		want bool
	}{{"", RoleOwner, true}, {"", "billing", true}, {"", "custom", false}, {"role_1", RoleOwner, false}, {"", "", false}} {
		if got := p.predefined(c.id, c.name); got != c.want {
			t.Errorf("predefined(%q, %q) = %v", c.id, c.name, got)
		}
	}
}
