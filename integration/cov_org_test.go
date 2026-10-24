package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/terms"
)

// orgWorld is an app with the organization plugin, an owner (alice, verified)
// and one organization she owns.
type orgWorld struct {
	a     *auth.Auth
	em    *email.Plugin
	pw    *password.Plugin
	org   *organization.Plugin
	owner password.SignInResult
	o     organization.Org
}

func orgSetup(t *testing.T, e *env, opts ...organization.Option) *orgWorld {
	t.Helper()
	w := &orgWorld{em: e.emailPlugin(), pw: e.passwordPlugin(), org: organization.New(opts...)}
	w.a = e.newAuth(t, nil, w.em, w.pw, w.org)
	w.owner = signUpVerified(t, e, w.a, w.pw, w.em)
	w.o = must[organization.Org](t)(w.org.Create(request(w.a, w.owner.Token), organization.CreateRequest{Name: "Acme", Slug: "acme"}))
	return w
}

// orgUser signs up addr and verifies it, so invitations to it can be accepted.
func (w *orgWorld) orgUser(t *testing.T, e *env, addr string) password.SignInResult {
	t.Helper()
	res := must[password.SignInResult](t)(w.pw.SignUp(anon(w.a), password.SignUpRequest{Identifier: addr, Password: secret}))
	if _, err := w.em.Verify(anon(w.a), e.mail.LastToken(t, w.a, addr)); err != nil {
		t.Fatal(err)
	}
	return res
}

// orgJoin makes u a member of the organization with role, through an
// invitation from the owner.
func (w *orgWorld) orgJoin(t *testing.T, u password.SignInResult, addr string, role organization.Role) {
	t.Helper()
	if err := w.org.Invite(request(w.a, w.owner.Token), organization.InviteRequest{OrgID: w.o.ID, Email: addr, Role: role}); err != nil {
		t.Fatal(err)
	}
	list := must[[]organization.Invite](t)(w.org.Invites(request(w.a, u.Token)))
	if len(list) == 0 {
		t.Fatalf("no invitation for %s", addr)
	}
	must[organization.Org](t)(w.org.Accept(request(w.a, u.Token), list[len(list)-1].ID))
}

func (w *orgWorld) orgRole(t *testing.T, userID string) (organization.Role, error) {
	t.Helper()
	return w.org.RoleOf(context.Background(), w.o.ID, userID)
}

func TestOrgCov_InviteTTLLinkAndSweep(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const link = "https://links.example.com/inv"
		w := orgSetup(t, e, organization.WithInviteTTL(time.Hour), organization.InviteLink(func() string { return link }))
		bob := w.orgUser(t, e, "bob@example.com")
		sent := e.clock.Now()
		if err := w.org.Invite(request(w.a, w.owner.Token), organization.InviteRequest{OrgID: w.o.ID, Email: "bob@example.com", Role: organization.RoleMember}); err != nil {
			t.Fatal(err)
		}
		mail := e.mail.To(w.a, "bob@example.com")
		// The plugin's own wording, not the email plugin's generic fallback.
		if last := mail[len(mail)-1]; last.Subject != "You are invited to join an organization" || !strings.HasSuffix(last.Text, "accept the invitation here:\n\n"+link) {
			t.Fatalf("invitation mail = %q / %q", last.Subject, last.Text)
		}
		list := must[[]organization.Invite](t)(w.org.Invites(request(w.a, bob.Token)))
		if len(list) != 1 || !list[0].ExpiresAt.Equal(sent.Add(time.Hour)) || list[0].OrgName != "Acme" {
			t.Fatalf("invites = %+v, want one expiring at %v", list, sent.Add(time.Hour))
		}
		must[organization.Org](t)(w.org.Accept(request(w.a, bob.Token), list[0].ID))

		// carol's invitation lapses unaccepted; dave's is fresh.
		if err := w.org.Invite(request(w.a, w.owner.Token), organization.InviteRequest{OrgID: w.o.ID, Email: "carol@example.com", Role: organization.RoleMember}); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(2 * time.Hour)
		if err := w.org.Invite(request(w.a, w.owner.Token), organization.InviteRequest{OrgID: w.o.ID, Email: "dave@example.com", Role: organization.RoleMember}); err != nil {
			t.Fatal(err)
		}
		n, err := w.org.Sweep(context.Background(), e.clock.Now())
		if err != nil || n != 1 {
			t.Fatalf("sweep = %d %v, want only carol's expired invitation", n, err)
		}
		// bob's accepted one stays as a record of who invited whom.
		if got := count(t, e, organization.TableNameInvite); got != 2 {
			t.Fatalf("invitations left = %d, want 2", got)
		}
	})
}

func TestOrgCov_RefusalsAndRoleRules(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := orgSetup(t, e)
		ownerCtx := func() context.Context { return request(w.a, w.owner.Token) }
		bob := w.orgUser(t, e, "bob@example.com")
		carol := w.orgUser(t, e, "carol@example.com")
		eve := w.orgUser(t, e, "eve@example.com")
		w.orgJoin(t, bob, "bob@example.com", organization.RoleAdmin)
		w.orgJoin(t, carol, "carol@example.com", organization.RoleMember)
		invite := func(ctx context.Context, addr string, role organization.Role) error {
			return w.org.Invite(ctx, organization.InviteRequest{OrgID: w.o.ID, Email: addr, Role: role})
		}

		// Invitations.
		if err := invite(request(w.a, eve.Token), "x@example.com", organization.RoleMember); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("stranger invites: %v", err)
		}
		if err := invite(ownerCtx(), "x@example.com", "root"); !errors.Is(err, organization.ErrBadRole) {
			t.Fatalf("unknown role: %v", err)
		}
		if err := invite(request(w.a, bob.Token), "x@example.com", organization.RoleOwner); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("admin grants a role above their own: %v", err)
		}
		if err := invite(ownerCtx(), "not an address", organization.RoleMember); !errors.Is(err, auth.ErrIdentifierInvalid) {
			t.Fatalf("invalid address: %v", err)
		}
		if got := count(t, e, organization.TableNameInvite); got != 2 {
			t.Fatalf("a refused invitation was stored: %d rows", got)
		}

		// Removal.
		remove := func(ctx context.Context, userID string) error {
			return w.org.RemoveMember(ctx, organization.MemberRequest{OrgID: w.o.ID, UserID: userID})
		}
		if err := remove(request(w.a, eve.Token), carol.User.ID); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("stranger removes: %v", err)
		}
		if err := remove(ownerCtx(), eve.User.ID); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("removing a non-member: %v", err)
		}
		if err := remove(request(w.a, carol.Token), bob.User.ID); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("member removes an admin: %v", err)
		}
		if err := remove(request(w.a, bob.Token), w.owner.User.ID); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("admin removes the owner: %v", err)
		}

		// Role changes.
		setRole := func(ctx context.Context, userID string, role organization.Role) error {
			return w.org.SetRole(ctx, organization.SetRoleRequest{OrgID: w.o.ID, UserID: userID, Role: role})
		}
		if err := setRole(ownerCtx(), carol.User.ID, "root"); !errors.Is(err, organization.ErrBadRole) {
			t.Fatalf("unknown role: %v", err)
		}
		if err := setRole(request(w.a, eve.Token), carol.User.ID, organization.RoleAdmin); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("stranger sets a role: %v", err)
		}
		if err := setRole(ownerCtx(), eve.User.ID, organization.RoleAdmin); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("role of a non-member: %v", err)
		}

		// With a second owner, one owner may be demoted and another removed.
		if err := setRole(ownerCtx(), bob.User.ID, organization.RoleOwner); err != nil {
			t.Fatal(err)
		}
		if err := setRole(ownerCtx(), bob.User.ID, organization.RoleAdmin); err != nil {
			t.Fatalf("demoting one of two owners: %v", err)
		}
		if got, _ := w.orgRole(t, bob.User.ID); got != organization.RoleAdmin {
			t.Fatalf("bob = %q, want admin", got)
		}
		if err := setRole(ownerCtx(), bob.User.ID, organization.RoleOwner); err != nil {
			t.Fatal(err)
		}
		if err := remove(request(w.a, bob.Token), w.owner.User.ID); err != nil {
			t.Fatalf("an owner removes another owner: %v", err)
		}
		if _, err := w.orgRole(t, w.owner.User.ID); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("removed owner still a member: %v", err)
		}
	})
}

// TestOrgCov_AcceptingAsAMemberKeepsTheRole: an invitation to someone already
// in the organization is accepted without changing their role, so an
// invitation can never be used to demote (or promote) an existing member.
func TestOrgCov_AcceptingAsAMemberKeepsTheRole(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := orgSetup(t, e)
		if err := w.org.Invite(request(w.a, w.owner.Token), organization.InviteRequest{OrgID: w.o.ID, Email: alice, Role: organization.RoleMember}); err != nil {
			t.Fatal(err)
		}
		list := must[[]organization.Invite](t)(w.org.Invites(request(w.a, w.owner.Token)))
		got := must[organization.Org](t)(w.org.Accept(request(w.a, w.owner.Token), list[0].ID))
		if got.ID != w.o.ID {
			t.Fatalf("accepted into %+v", got)
		}
		if role, err := w.orgRole(t, w.owner.User.ID); err != nil || role != organization.RoleOwner {
			t.Fatalf("role after accepting = %q %v, want owner", role, err)
		}
	})
}

// TestOrgCov_ConcurrentAcceptLosesTheRace: when the invitation is marked
// accepted by someone else between listing and updating, the update matches no
// row and the second acceptance is refused. A SQLite trigger that ignores the
// update stands in for the concurrent writer, deterministically.
func TestOrgCov_ConcurrentAcceptLosesTheRace(t *testing.T) {
	db, d := openSQLite(t)
	e := newEnv(t, auth.EngineSQLite, db, d)
	w := orgSetup(t, e)
	bob := w.orgUser(t, e, "bob@example.com")
	if err := w.org.Invite(request(w.a, w.owner.Token), organization.InviteRequest{OrgID: w.o.ID, Email: "bob@example.com", Role: organization.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TRIGGER org_cov_race BEFORE UPDATE ON " + tbl(organization.TableNameInvite) + " BEGIN SELECT RAISE(IGNORE); END"); err != nil {
		t.Fatal(err)
	}
	list := must[[]organization.Invite](t)(w.org.Invites(request(w.a, bob.Token)))
	if _, err := w.org.Accept(request(w.a, bob.Token), list[0].ID); !errors.Is(err, organization.ErrInviteInvalid) {
		t.Fatalf("losing acceptance: %v", err)
	}
	if _, err := w.orgRole(t, bob.User.ID); !errors.Is(err, organization.ErrNotMember) {
		t.Fatalf("the losing request must not add a member: %v", err)
	}
}

func TestOrgCov_RequireRoleRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := orgSetup(t, e)
		carol := w.orgUser(t, e, "carol@example.com")
		w.orgJoin(t, carol, "carol@example.com", organization.RoleMember)
		ok := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusNoContent) })
		h := authhttp.Middleware(w.a)(w.org.RequireRole(func(*http.Request) string { return w.o.ID }, organization.RoleAdmin)(ok))
		serve := func(tok auth.Token) int {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok.Reveal())
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			return rec.Code
		}
		if c := serve(""); c != http.StatusUnauthorized {
			t.Fatalf("signed out: %d", c)
		}
		if c := serve(carol.Token); c != http.StatusForbidden {
			t.Fatalf("member below admin: %d", c)
		}
		if c := serve(w.owner.Token); c != http.StatusNoContent {
			t.Fatalf("owner: %d", c)
		}
	})
}

// orgFaultWorld is orgWorld on a fault-injecting database, with bob an admin
// and carol a member, so every operation has someone to act on.
type orgFaultWorld struct {
	*orgWorld
	env        *env
	bob, carol password.SignInResult
}

func orgFaultSetup(t *testing.T, e *faultEnv) *orgFaultWorld {
	t.Helper()
	w := &orgFaultWorld{orgWorld: orgSetup(t, e.env), env: e.env}
	w.bob = w.orgUser(t, e.env, "bob@example.com")
	w.carol = w.orgUser(t, e.env, "carol@example.com")
	w.orgJoin(t, w.bob, "bob@example.com", organization.RoleOwner)
	w.orgJoin(t, w.carol, "carol@example.com", organization.RoleMember)
	return w
}

// TestOrgCov_EveryDatabaseFailureSurfaces sweeps each operation with a fault at
// every database call it makes.
func TestOrgCov_EveryDatabaseFailureSurfaces(t *testing.T) {
	cases := map[string]func(t *testing.T, w *orgFaultWorld) func(context.Context) error{
		"create": func(_ *testing.T, w *orgFaultWorld) func(context.Context) error {
			return func(context.Context) error {
				_, err := w.org.Create(request(w.a, w.owner.Token), organization.CreateRequest{Name: "Beta", Slug: "beta"})
				return err
			}
		},
		"list": func(_ *testing.T, w *orgFaultWorld) func(context.Context) error {
			return func(context.Context) error { _, err := w.org.List(request(w.a, w.owner.Token)); return err }
		},
		"members": func(_ *testing.T, w *orgFaultWorld) func(context.Context) error {
			return func(context.Context) error { _, err := w.org.Members(request(w.a, w.owner.Token), w.o.ID); return err }
		},
		"invite": func(_ *testing.T, w *orgFaultWorld) func(context.Context) error {
			return func(context.Context) error {
				return w.org.Invite(request(w.a, w.owner.Token), organization.InviteRequest{OrgID: w.o.ID, Email: "dave@example.com", Role: organization.RoleMember})
			}
		},
		"invites": func(_ *testing.T, w *orgFaultWorld) func(context.Context) error {
			return func(context.Context) error { _, err := w.org.Invites(request(w.a, w.owner.Token)); return err }
		},
		"accept": func(t *testing.T, w *orgFaultWorld) func(context.Context) error {
			dave := w.orgUser(t, w.env, "dave@example.com")
			if err := w.org.Invite(request(w.a, w.owner.Token), organization.InviteRequest{OrgID: w.o.ID, Email: "dave@example.com", Role: organization.RoleMember}); err != nil {
				t.Fatal(err)
			}
			list := must[[]organization.Invite](t)(w.org.Invites(request(w.a, dave.Token)))
			return func(context.Context) error { _, err := w.org.Accept(request(w.a, dave.Token), list[0].ID); return err }
		},
		"remove-owner": func(_ *testing.T, w *orgFaultWorld) func(context.Context) error {
			return func(context.Context) error {
				return w.org.RemoveMember(request(w.a, w.owner.Token), organization.MemberRequest{OrgID: w.o.ID, UserID: w.bob.User.ID})
			}
		},
		"demote-owner": func(_ *testing.T, w *orgFaultWorld) func(context.Context) error {
			return func(context.Context) error {
				return w.org.SetRole(request(w.a, w.owner.Token), organization.SetRoleRequest{OrgID: w.o.ID, UserID: w.bob.User.ID, Role: organization.RoleMember})
			}
		},
		"sweep": func(_ *testing.T, w *orgFaultWorld) func(context.Context) error {
			return func(ctx context.Context) error { _, err := w.org.Sweep(ctx, w.a.Now()); return err }
		},
	}
	for name, op := range cases {
		t.Run(name, func(t *testing.T) {
			sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error { return op(t, orgFaultSetup(t, e)) })
		})
	}
}

// orgAdminWorld is an app with the admin plugin: boss (alice) is an admin,
// bob an ordinary user.
type orgAdminWorld struct {
	a         *auth.Auth
	pw        *password.Plugin
	ad        *admin.Plugin
	boss, bob password.SignInResult
}

func orgAdminSetup(t *testing.T, e *env) *orgAdminWorld {
	t.Helper()
	em := e.emailPlugin()
	w := &orgAdminWorld{pw: e.passwordPlugin(), ad: admin.New()}
	w.a = e.newAuth(t, nil, em, w.pw, w.ad)
	w.boss = signUpVerified(t, e, w.a, w.pw, em)
	if err := w.ad.Grant(context.Background(), w.boss.User.ID); err != nil {
		t.Fatal(err)
	}
	w.bob = must[password.SignInResult](t)(w.pw.SignUp(anon(w.a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret, Name: "Bob"}))
	return w
}

func (w *orgAdminWorld) orgBossCtx() context.Context { return request(w.a, w.boss.Token) }

// TestOrgCov_AdminRefusesNonAdminsAndUnknownUsers: every operation checks the
// caller before the target, and an unknown target is a not-found error rather
// than a silent success.
func TestOrgCov_AdminRefusesNonAdminsAndUnknownUsers(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := orgAdminSetup(t, e)
		const ghost = "usr_doesnotexist"
		bobCtx := func() context.Context { return request(w.a, w.bob.Token) }
		calls := map[string]func(ctx context.Context, userID string) error{
			"user":            func(ctx context.Context, id string) error { _, err := w.ad.User(ctx, id); return err },
			"ban":             func(ctx context.Context, id string) error { return w.ad.Ban(ctx, id, "") },
			"unban":           func(ctx context.Context, id string) error { return w.ad.Unban(ctx, id) },
			"revoke-sessions": func(ctx context.Context, id string) error { return w.ad.RevokeSessions(ctx, id) },
			"set-admin":       func(ctx context.Context, id string) error { return w.ad.SetAdmin(ctx, id, true) },
			"impersonate": func(ctx context.Context, id string) error {
				_, err := w.ad.Impersonate(ctx, admin.ImpersonateRequest{UserID: id})
				return err
			},
		}
		for name, call := range calls {
			if err := call(bobCtx(), w.boss.User.ID); !errors.Is(err, admin.ErrForbidden) {
				t.Errorf("%s by a non-admin: %v", name, err)
			}
			if err := call(w.orgBossCtx(), ghost); !errors.Is(err, auth.ErrUserNotFound) {
				t.Errorf("%s on an unknown user: %v", name, err)
			}
		}
		if err := w.ad.Grant(context.Background(), ghost); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("granting an unknown user: %v", err)
		}
	})
}

func TestOrgCov_AdminPagingNoOpsRevokeAndBannedTarget(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := orgAdminSetup(t, e)
		page := must[admin.UsersResult](t)(w.ad.Users(w.orgBossCtx(), admin.UsersRequest{Limit: admin.MaxPageSize + 1, Page: -3}))
		if page.Limit != admin.MaxPageSize || page.Page != 1 || page.Total != 2 {
			t.Fatalf("clamped page = %+v", page)
		}
		byID := must[admin.UsersResult](t)(w.ad.Users(w.orgBossCtx(), admin.UsersRequest{Query: w.bob.User.ID}))
		if byID.Total != 1 || byID.Users[0].ID != w.bob.User.ID {
			t.Fatalf("search by user id = %+v", byID)
		}

		// Granting an admin and removing a non-admin change nothing.
		before := must[admin.UserDetail](t)(w.ad.User(w.orgBossCtx(), w.boss.User.ID))
		if err := w.ad.SetAdmin(w.orgBossCtx(), w.boss.User.ID, true); err != nil {
			t.Fatal(err)
		}
		if err := w.ad.SetAdmin(w.orgBossCtx(), w.bob.User.ID, false); err != nil {
			t.Fatal(err)
		}
		after := must[admin.UserDetail](t)(w.ad.User(w.orgBossCtx(), w.boss.User.ID))
		bob := must[admin.UserDetail](t)(w.ad.User(w.orgBossCtx(), w.bob.User.ID))
		if !before.User.Admin || !after.User.Admin || bob.User.Admin {
			t.Fatalf("no-op grants changed state: boss %+v → %+v, bob %+v", before.User, after.User, bob.User)
		}

		// Revoking ends bob's sessions without banning him.
		if bob.Sessions != 1 {
			t.Fatalf("bob sessions = %d", bob.Sessions)
		}
		if err := w.ad.RevokeSessions(w.orgBossCtx(), w.bob.User.ID); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := w.a.ResolveSession(context.Background(), w.bob.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("revoked session still works: %v", err)
		}
		again := must[password.SignInResult](t)(w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: secret}))
		if _, _, _, err := w.a.ResolveSession(context.Background(), again.Token); err != nil {
			t.Fatalf("revoking must not ban: %v", err)
		}

		// A banned user cannot be impersonated.
		if err := w.ad.Ban(w.orgBossCtx(), w.bob.User.ID, "spam"); err != nil {
			t.Fatal(err)
		}
		if _, err := w.ad.Impersonate(w.orgBossCtx(), admin.ImpersonateRequest{UserID: w.bob.User.ID}); !errors.Is(err, admin.ErrBannedTarget) {
			t.Fatalf("impersonating a banned user: %v", err)
		}
	})
}

// TestOrgCov_AdminEveryDatabaseFailureSurfaces sweeps each admin operation
// with a fault at every database call. The users search is included because
// a failed identity lookup used to be swallowed and shown as an empty page.
func TestOrgCov_AdminEveryDatabaseFailureSurfaces(t *testing.T) {
	cases := map[string]func(t *testing.T, w *orgAdminWorld) func(context.Context) error{
		"users-search": func(_ *testing.T, w *orgAdminWorld) func(context.Context) error {
			return func(context.Context) error {
				_, err := w.ad.Users(w.orgBossCtx(), admin.UsersRequest{Query: "bob@example.com"})
				return err
			}
		},
		"user": func(_ *testing.T, w *orgAdminWorld) func(context.Context) error {
			return func(context.Context) error { _, err := w.ad.User(w.orgBossCtx(), w.bob.User.ID); return err }
		},
		"ban": func(_ *testing.T, w *orgAdminWorld) func(context.Context) error {
			return func(context.Context) error { return w.ad.Ban(w.orgBossCtx(), w.bob.User.ID, "spam") }
		},
		"unban": func(t *testing.T, w *orgAdminWorld) func(context.Context) error {
			if err := w.ad.Ban(w.orgBossCtx(), w.bob.User.ID, "spam"); err != nil {
				t.Fatal(err)
			}
			return func(context.Context) error { return w.ad.Unban(w.orgBossCtx(), w.bob.User.ID) }
		},
		"revoke-sessions": func(_ *testing.T, w *orgAdminWorld) func(context.Context) error {
			return func(context.Context) error { return w.ad.RevokeSessions(w.orgBossCtx(), w.bob.User.ID) }
		},
		"grant-admin": func(_ *testing.T, w *orgAdminWorld) func(context.Context) error {
			return func(context.Context) error { return w.ad.SetAdmin(w.orgBossCtx(), w.bob.User.ID, true) }
		},
		"remove-admin": func(t *testing.T, w *orgAdminWorld) func(context.Context) error {
			if err := w.ad.Grant(context.Background(), w.bob.User.ID); err != nil {
				t.Fatal(err)
			}
			return func(context.Context) error { return w.ad.SetAdmin(w.orgBossCtx(), w.bob.User.ID, false) }
		},
		"impersonate": func(_ *testing.T, w *orgAdminWorld) func(context.Context) error {
			return func(context.Context) error {
				_, err := w.ad.Impersonate(w.orgBossCtx(), admin.ImpersonateRequest{UserID: w.bob.User.ID})
				return err
			}
		},
		"stop-impersonating": func(t *testing.T, w *orgAdminWorld) func(context.Context) error {
			as := must[admin.ImpersonateResult](t)(w.ad.Impersonate(w.orgBossCtx(), admin.ImpersonateRequest{UserID: w.bob.User.ID}))
			return func(context.Context) error { _, err := w.ad.StopImpersonating(request(w.a, as.Token)); return err }
		},
		"grant": func(_ *testing.T, w *orgAdminWorld) func(context.Context) error {
			return func(ctx context.Context) error { return w.ad.Grant(ctx, w.bob.User.ID) }
		},
	}
	for name, op := range cases {
		t.Run(name, func(t *testing.T) {
			sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error { return op(t, orgAdminSetup(t, e.env)) })
		})
	}
}

func TestOrgCov_TermsRefusalsAndFailures(t *testing.T) {
	const version = "2026-09"
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tm := e.emailPlugin(), e.passwordPlugin(), terms.New(terms.Current(version))
		a := e.newAuth(t, nil, em, pw, tm)
		h := authhttp.Middleware(a)(tm.RequireCurrent()(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusNoContent) })))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("signed out: %d", rec.Code)
		}
		if _, err := tm.Accepted(context.Background(), "usr_doesnotexist"); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("Accepted for an unknown user: %v", err)
		}
	})
	t.Run("faults", func(t *testing.T) {
		setup := func(t *testing.T, e *faultEnv) (*auth.Auth, *terms.Plugin, password.SignInResult) {
			em, pw, tm := e.emailPlugin(), e.passwordPlugin(), terms.New(terms.Current(version))
			a := e.newAuth(t, nil, em, pw, tm)
			return a, tm, signUpVerified(t, e.env, a, pw, em)
		}
		t.Run("accept", func(t *testing.T) {
			sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
				a, tm, up := setup(t, e)
				return func(context.Context) error { return tm.Accept(request(a, up.Token), version) }
			})
		})
		t.Run("require-current", func(t *testing.T) {
			sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
				a, tm, up := setup(t, e)
				if err := tm.Accept(request(a, up.Token), version); err != nil {
					t.Fatal(err)
				}
				h := authhttp.Middleware(a)(tm.RequireCurrent()(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusNoContent) })))
				return func(context.Context) error {
					req := httptest.NewRequest(http.MethodGet, "/", nil)
					req.Header.Set("Authorization", "Bearer "+up.Token.Reveal())
					rec := httptest.NewRecorder()
					h.ServeHTTP(rec, req)
					if rec.Code != http.StatusNoContent {
						return errors.New(rec.Body.String())
					}
					return nil
				}
			})
		})
	})
}

// errOrgIDs is the failure of an id generator that refuses the plugin's
// prefixes.
var errOrgIDs = errors.New("integration: id generator failed")

// TestOrgCov_BadSlugAndIDFailures: a bad slug and a failing id generator are
// refused before anything is written.
func TestOrgCov_BadSlugAndIDFailures(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		failFor := map[string]bool{}
		ids := auth.WithIDs(func(prefix string) (string, error) {
			if failFor[prefix] {
				return "", errOrgIDs
			}
			return auth.NewID(prefix)
		})
		em, pw, org := e.emailPlugin(), e.passwordPlugin(), organization.New()
		a := e.newAuth(t, []auth.Option{ids}, em, pw, org)
		up := signUpVerified(t, e, a, pw, em)
		if _, err := org.Create(request(a, up.Token), organization.CreateRequest{Name: "Acme", Slug: "-acme"}); !errors.Is(err, organization.ErrBadSlug) {
			t.Fatalf("bad slug: %v", err)
		}
		o := must[organization.Org](t)(org.Create(request(a, up.Token), organization.CreateRequest{Name: "Acme", Slug: "acme"}))
		failFor["org"], failFor["inv"] = true, true
		if _, err := org.Create(request(a, up.Token), organization.CreateRequest{Name: "Beta", Slug: "beta"}); !errors.Is(err, errOrgIDs) {
			t.Fatalf("create with a failing id generator: %v", err)
		}
		if err := org.Invite(request(a, up.Token), organization.InviteRequest{OrgID: o.ID, Email: "bob@example.com", Role: organization.RoleMember}); !errors.Is(err, errOrgIDs) {
			t.Fatalf("invite with a failing id generator: %v", err)
		}
		if got := count(t, e, organization.TableNameOrg) + count(t, e, organization.TableNameInvite); got != 1 {
			t.Fatalf("rows after refusals = %d, want only acme", got)
		}
	})
}
