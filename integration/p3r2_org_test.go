package integration

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/organization/orgtest"
	"github.com/ubgo/auth/plugin/password"
)

// p3r2Seen records the Data of every invitation message the email plugin's
// template renders.
type p3r2Seen struct {
	mu   sync.Mutex
	data []any
}

func (s *p3r2Seen) template(m auth.Message) (string, string) {
	if m.Purpose == organization.PurposeInvite {
		s.mu.Lock()
		s.data = append(s.data, m.Data)
		s.mu.Unlock()
	}
	return email.DefaultTemplates(m)
}

func (s *p3r2Seen) last(t *testing.T, a *auth.Auth) organization.InvitationData {
	t.Helper()
	a.WaitDeliveries()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data) == 0 {
		t.Fatal("no invitation was rendered")
	}
	d, ok := s.data[len(s.data)-1].(organization.InvitationData)
	if !ok {
		t.Fatalf("invitation data is %T, want organization.InvitationData", s.data[len(s.data)-1])
	}
	return d
}

// TestP3R2Org_InvitationDataReachesTheTemplate: an invitation mail carries
// InvitationData, typed, to the app's template.
func TestP3R2Org_InvitationDataReachesTheTemplate(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) { p3r2Invitation(t, e, false) })
}

// TestP3R2Org_InvitationDataThroughTheOutbox is the same invitation sent from
// the delivery outbox after its first send died.
func TestP3R2Org_InvitationDataThroughTheOutbox(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) { p3r2Invitation(t, e, true) })
}

func p3r2Invitation(t *testing.T, e *env, outbox bool) {
	seen := &p3r2Seen{}
	em := e.emailPlugin(email.Templates(seen.template))
	pw, org := e.passwordPlugin(), organization.New()
	var opts []auth.Option
	var crash atomic.Bool
	if outbox {
		// Once crash is set, a first send dies with its context, so
		// the invitation is delivered only by the outbox sweep, from
		// the stored row. Before that, mail goes out as usual.
		dead, kill := context.WithCancel(context.Background())
		kill()
		bg := orderedBackground(t)
		opts = append(opts, auth.WithDeliveryOutbox(sessKey), auth.WithBackground(func(ctx context.Context, task func(context.Context)) {
			if crash.Load() {
				task(dead)
				return
			}
			bg(ctx, task)
		}))
	}
	a := e.newAuth(t, opts, em, pw, org)
	owner := signUpVerified(t, e, a, pw, em)
	a.WaitDeliveries()
	crash.Store(true)
	o := must[organization.Org](t)(org.Create(request(a, owner.Token), organization.CreateRequest{Name: "Acme", Slug: "acme"}))
	if err := org.Invite(request(a, owner.Token), organization.InviteRequest{OrgID: o.ID, Email: "dave@example.com", Role: organization.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	if outbox {
		a.WaitDeliveries()
		seen.mu.Lock()
		before := len(seen.data)
		seen.mu.Unlock()
		e.clock.Advance(time.Hour)
		if n, err := a.SendOutbox(context.Background()); err != nil || n.Sent != 1 {
			t.Fatalf("outbox sweep: %+v, %v; want the invitation sent", n, err)
		}
		a.WaitDeliveries()
		seen.mu.Lock()
		after := len(seen.data)
		seen.mu.Unlock()
		if after != before+1 {
			t.Fatalf("the sweep rendered %d invitations, want 1", after-before)
		}
	}
	d := seen.last(t, a)
	if d.InvitationID == "" || d.Email != "dave@example.com" || d.Role != organization.RoleAdmin || d.OrganizationID != o.ID ||
		d.OrganizationName != "Acme" || d.OrganizationSlug != "acme" || d.InviterID != owner.User.ID || d.InviterEmail != alice || d.ExpiresAt.IsZero() {
		t.Fatalf("outbox=%v: invitation data %+v", outbox, d)
	}
}

// TestP3R2Org_Factory: orgtest builds an organization in memory and saves it
// through the plugin, owner and members included, on the authtest Env.
func TestP3R2Org_Factory(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		env := authtest.New(t, authtest.WithDB(e.db, e.d), authtest.WithOptions(auth.WithTablePrefix(tablePrefix())),
			authtest.WithPlugins(func(env *authtest.Env) []auth.Plugin {
				return []auth.Plugin{email.New(email.Login(), email.Recover(), email.WithMailer(env.Mail)), password.New(password.Argon2(fastArgon2)), organization.New()}
			}))
		owner := env.SaveUser(env.NewUser("Owner"))
		bob := env.SaveUser(env.NewUser("Bob"))
		f := orgtest.New(env)
		fix := f.NewOrganization(owner.ID, "")
		if fix.Name != orgtest.DefaultOrgName || !organization.SlugPattern.MatchString(fix.Slug) || fix.Slug == f.NewOrganization(owner.ID, "x").Slug {
			t.Fatalf("fixture %+v", fix)
		}
		fix.Members = []orgtest.Member{{UserID: bob.ID, Role: organization.RoleAdmin}}
		o := f.SaveOrganization(fix)
		org, err := auth.PluginOf[*organization.Plugin](env.Auth)
		if err != nil {
			t.Fatal(err)
		}
		for id, want := range map[string]organization.Role{owner.ID: organization.RoleOwner, bob.ID: organization.RoleAdmin} {
			if got, err := org.RoleOf(context.Background(), o.ID, id); err != nil || got != want {
				t.Fatalf("role of %s = %s, %v; want %s", id, got, err, want)
			}
		}

		// A refusal fails the test that asked for it.
		rec := &p3r2TB{TB: t}
		env.T = rec
		func() {
			defer func() { _ = recover() }()
			f.AddMember("org_missing", bob.ID, organization.RoleMember)
		}()
		if !strings.Contains(rec.msg, "orgtest: add") {
			t.Fatalf("an add to a missing organization did not fail the test: %q", rec.msg)
		}
	})
}

// TestP3R2Org_FactoryHelpers pins each orgtest helper on its own: New fails
// the test when the plugin is not wired, NewOrganization keeps a given name
// and writes nothing, SaveOrganization stores the fixture's logo and metadata
// and fails the test on a refused slug, and AddMember adds a member.
func TestP3R2Org_FactoryHelpers(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		mails := func(env *authtest.Env) []auth.Plugin {
			return []auth.Plugin{email.New(email.Login(), email.Recover(), email.WithMailer(env.Mail)), password.New(password.Argon2(fastArgon2))}
		}
		bare := authtest.New(t, authtest.WithDB(e.db, e.d), authtest.WithOptions(auth.WithTablePrefix(tablePrefix())), authtest.WithPlugins(mails))
		rec := &p3r2TB{TB: t}
		bare.T = rec
		func() {
			defer func() { _ = recover() }()
			orgtest.New(bare)
		}()
		if !strings.HasPrefix(rec.msg, "orgtest: ") {
			t.Fatalf("New on an Auth without the organization plugin did not fail the test: %q", rec.msg)
		}

		env := authtest.New(t, authtest.WithDB(e.db, e.d), authtest.WithOptions(auth.WithTablePrefix(tablePrefix())),
			authtest.WithPlugins(func(env *authtest.Env) []auth.Plugin { return append(mails(env), organization.New()) }))
		org, err := auth.PluginOf[*organization.Plugin](env.Auth)
		if err != nil {
			t.Fatal(err)
		}
		owner := env.SaveUser(env.NewUser("Owner"))
		carol := env.SaveUser(env.NewUser("Carol"))
		f := orgtest.New(env)

		fix := f.NewOrganization(owner.ID, "Globex")
		if fix.Name != "Globex" || fix.OwnerID != owner.ID || len(fix.Members) != 0 {
			t.Fatalf("fixture %+v", fix)
		}
		if all, err := org.ListAll(ctx, organization.AllOrgsRequest{Search: fix.Slug}); err != nil || all.Total != 0 {
			t.Fatalf("NewOrganization wrote: total %d, %v", all.Total, err)
		}

		logo := "https://cdn.example.com/globex.png"
		fix.Logo, fix.Metadata = &logo, auth.AppData(`{"plan":"pro"}`)
		o := f.SaveOrganization(fix)
		got, err := org.GetFor(ctx, o.ID)
		if err != nil || got.Name != "Globex" || got.Slug != fix.Slug || got.Logo == nil || *got.Logo != logo || string(got.Metadata) != `{"plan":"pro"}` {
			t.Fatalf("stored %+v, %v", got, err)
		}

		f.AddMember(o.ID, carol.ID, organization.RoleMember)
		if role, err := org.RoleOf(ctx, o.ID, carol.ID); err != nil || role != organization.RoleMember {
			t.Fatalf("role of carol = %s, %v; want member", role, err)
		}

		rec = &p3r2TB{TB: t}
		env.T = rec
		func() {
			defer func() { _ = recover() }()
			f.SaveOrganization(fix)
		}()
		if !strings.Contains(rec.msg, "orgtest: save organization") {
			t.Fatalf("a taken slug did not fail the test: %q", rec.msg)
		}
	})
}

// p3r2TB records a Fatalf and stops the call, as a failing test would.
type p3r2TB struct {
	testing.TB
	msg string
}

func (r *p3r2TB) Fatalf(format string, args ...any) {
	r.msg = strings.TrimSpace(strings.ReplaceAll(fmt.Sprintf(format, args...), "\n", " "))
	panic(r.msg)
}

func (r *p3r2TB) Helper() {}

// TestP3R2Org_AdminPageSizeFromCore: auth.WithDefaultPageSize sets the admin
// lists' default page, the users list and all-sessions alike; a requested
// limit still wins.
func TestP3R2Org_AdminPageSizeFromCore(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := p3AdminWorld(t, e, []auth.Option{auth.WithDefaultPageSize(1)})
		if r := must[admin.UsersResult](t)(w.ad.Users(w.bossCtx(), admin.UsersRequest{})); r.Limit != 1 || len(r.Users) != 1 || r.Total < 2 {
			t.Fatalf("users with the core default: limit %d, %d rows of %d", r.Limit, len(r.Users), r.Total)
		}
		if r := must[admin.UsersResult](t)(w.ad.Users(w.bossCtx(), admin.UsersRequest{Limit: 2})); r.Limit != 2 || len(r.Users) != 2 {
			t.Fatalf("a requested limit: %d, %d rows", r.Limit, len(r.Users))
		}
		if r := must[admin.AllSessionsResult](t)(w.ad.AllSessions(w.bossCtx(), admin.AllSessionsRequest{})); r.Limit != 1 || len(r.Sessions) != 1 {
			t.Fatalf("all-sessions with the core default: limit %d, %d rows", r.Limit, len(r.Sessions))
		}
	})
}
