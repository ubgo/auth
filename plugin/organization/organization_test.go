package organization_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/sqlb"
)

type signIn struct{}

func (signIn) Name() string  { return "signin" }
func (signIn) SignsIn() bool { return true }

var noMail = email.MailerFunc(func(context.Context, email.Mail) error { return nil })

func wire(t *testing.T) *auth.Auth {
	t.Helper()
	a, err := auth.New(auth.WithBaseURL("https://app.example.com"),
		auth.WithPlugins(signIn{}, email.New(email.WithMailer(noMail)), organization.New()))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestPendingInvitesQuery_RequiresVerifiedIdentity(t *testing.T) {
	a := wire(t)
	var inv organization.Invite
	q, err := organization.PendingInvitesQuery(a, "usr_1", time.Now(), &inv)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"oid"."verified_at" IS NOT NULL`, `"oi"."accepted_at" IS NULL`, `"oi"."expires_at" >`, `"oid"."value" = "oi"."identifier"`, `"oid"."kind" = "oi"."identifier_kind"`} {
		if !strings.Contains(q.SQL, want) {
			t.Errorf("SQL lacks %s:\n%s", want, q.SQL)
		}
	}
	if strings.Contains(strings.ToLower(q.SQL), "lower(") {
		t.Errorf("the address match must be exact: %s", q.SQL)
	}
}

func TestNew_RequiresTheEmailPlugin(t *testing.T) {
	_, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(signIn{}, organization.New()))
	if err == nil || !strings.Contains(err.Error(), "requires \"email\"") {
		t.Fatalf("err = %v", err)
	}
}

func TestRole_RankOrdering(t *testing.T) {
	if !organization.RoleOwner.AtLeast(organization.RoleAdmin) || organization.RoleMember.AtLeast(organization.RoleAdmin) {
		t.Fatal("rank order is wrong")
	}
	if organization.Role("root").Rank() != 0 || organization.Role("root").AtLeast(organization.RoleMember) {
		t.Fatal("an unknown role must grant nothing")
	}
}

func TestSlugPattern(t *testing.T) {
	for s, ok := range map[string]bool{"acme": true, "acme-2": true, "a": false, "-acme": false, "Acme": false, "ac me": false} {
		if organization.SlugPattern.MatchString(s) != ok {
			t.Errorf("slug %q: want %v", s, ok)
		}
	}
}

func TestUserJoin_BindsOrgIDRatherThanInterpolating(t *testing.T) {
	a := wire(t)
	var m organization.UserMembership
	q, err := a.Select().Columns(organization.UserBindings(&m)...).From(auth.TableUser).
		Join(organization.UserJoin("org'; DROP TABLE x; --")).Where(sqlb.Eq(auth.UserID, "u")).Build()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(q.SQL, "DROP") || q.Args[0] != "org'; DROP TABLE x; --" {
		t.Fatalf("org id interpolated: %s %v", q.SQL, q.Args)
	}
	if (&organization.UserMembership{}).IsMember() {
		t.Fatal("zero membership is not a member")
	}
}

func TestMigrations_EveryEngine(t *testing.T) {
	p := organization.New()
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(signIn{}, email.New(email.WithMailer(noMail)), p)); err != nil {
		t.Fatal(err)
	}
	for _, e := range []string{auth.EnginePostgres, auth.EngineMySQL, auth.EngineSQLite} {
		ms, err := p.TypedMigrations(e, auth.TypesFor(e))
		if err != nil || len(ms[0].Statements) != 3 {
			t.Fatalf("%s: %+v %v", e, ms, err)
		}
	}
}
