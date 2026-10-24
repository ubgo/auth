package integration

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
)

// vetoPlugin refuses one user name through a data hook, and records the
// user ids it saw deleted.
type vetoPlugin struct{ deleted []string }

var errVetoed = auth.NewError("veto.refused", http.StatusConflict, "Refused.")

func (*vetoPlugin) Name() string { return "veto" }
func (v *vetoPlugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{User: auth.TableHooks[auth.User]{
		BeforeCreate: func(_ context.Context, _ sqlb.DBTX, u *auth.User) error {
			if u.Name == "Refused" {
				return errVetoed
			}
			return nil
		},
		BeforeDelete: func(_ context.Context, _ sqlb.DBTX, u *auth.User) error {
			v.deleted = append(v.deleted, u.ID)
			return nil
		},
	}}
}

func count(t *testing.T, e *env, table string) int {
	t.Helper()
	table = tbl(table)
	var n int
	if err := e.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestDataHooks_VetoRollsBackAndDeleteCascades(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, veto := e.emailPlugin(), e.passwordPlugin(), &vetoPlugin{}
		a := e.newAuth(t, nil, em, pw, veto)
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret, Name: "Refused"}); !errors.Is(err, errVetoed) {
			t.Fatalf("vetoed sign-up: %v", err)
		}
		if n := count(t, e, auth.TableNameUser); n != 0 {
			t.Fatalf("%d users after a vetoed sign-up", n)
		}
		up := signUpVerified(t, e, a, pw, em)
		if err := a.DeleteUser(context.Background(), up.User.ID); err != nil {
			t.Fatal(err)
		}
		if len(veto.deleted) != 1 || veto.deleted[0] != up.User.ID {
			t.Fatalf("BeforeDelete saw %v", veto.deleted)
		}
		for _, table := range []string{auth.TableNameIdentity, auth.TableNameSession, password.TableNamePassword} {
			if n := count(t, e, table); n != 0 {
				t.Errorf("%s has %d rows after the user was deleted; the cascade did not run", table, n)
			}
		}
		if _, err := a.User(context.Background(), up.User.ID); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("deleted user: %v", err)
		}
	})
}

func TestSessions_ListRevokeAndSignOutEverywhere(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		one := signUpVerified(t, e, a, pw, em)
		two := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
		three := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))

		op, _ := a.Operation(auth.EndpointSessions)
		out, err := op.Invoke(request(a, one.Token), func(any) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		list := out.(auth.SessionsResult).Sessions
		current := 0
		for _, s := range list {
			if s.Current {
				current++
			}
		}
		if len(list) != 3 || current != 1 {
			t.Fatalf("sessions = %+v", list)
		}

		// Revoke the second session by id from the first.
		s2, _, _, _ := a.ResolveSession(context.Background(), two.Token)
		rv, _ := a.Operation(auth.EndpointRevokeSession)
		if _, err := rv.Invoke(request(a, one.Token), func(dst any) error {
			*(dst.(*auth.RevokeSessionRequest)) = auth.RevokeSessionRequest{ID: s2.ID}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := a.ResolveSession(context.Background(), two.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("revoked session: %v", err)
		}

		if err := a.SignOutAll(request(a, one.Token)); err != nil {
			t.Fatal(err)
		}
		for _, tok := range []auth.Token{one.Token, three.Token} {
			if _, _, _, err := a.ResolveSession(context.Background(), tok); !errors.Is(err, auth.ErrSignedOut) {
				t.Fatalf("after sign-out-all: %v", err)
			}
		}
	})
}

func TestEmail_ResendOnlyForUnverified(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret}))
		before := len(e.mail.To(a, alice))
		if err := em.Resend(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		if got := len(e.mail.To(a, alice)); got != before+1 {
			t.Fatalf("resend for an unverified address sent %d", got-before)
		}
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, alice)); err != nil {
			t.Fatal(err)
		}
		before = len(e.mail.To(a, alice))
		for _, addr := range []string{alice, "nobody@example.com", "not an address"} {
			if err := em.Resend(anon(a), addr); err != nil {
				t.Fatalf("resend(%q) must succeed silently: %v", addr, err)
			}
		}
		if got := len(e.mail.To(a, alice)); got != before {
			t.Fatal("resend sent mail to an already verified address")
		}
	})
}

func TestOAuth_LinkFromSettings(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		fake := newFakeProvider(t)
		var web *app
		em, pw := e.emailPlugin(), e.passwordPlugin()
		oa := oauth.New(oauth.WithProviders(fake.provider()), oauth.CallbackURL(func(p string) string {
			return web.srv.URL + "/auth/oauth/" + p + "/callback"
		}))
		a := e.newAuth(t, nil, em, pw, oa)
		web = newApp(t, a)
		if res := web.post(t, "/auth/password/sign-up", map[string]string{"identifier": alice, "password": secret}); res.StatusCode != http.StatusOK {
			t.Fatalf("sign-up: %d", res.StatusCode)
		}
		owner := userIDByEmail0(t, a)
		// The provider reports a different, unverified address: only a link
		// flow started by the signed-in user can attach it.
		fake.profile = oauth.Profile{Subject: "g-9", Email: "other@example.com", EmailVerified: false}
		res, loc := oauthRoundTrip(t, web, "/auth/oauth/fake/start?link="+oauth.LinkFlag+"&returnTo=/settings")
		if res.StatusCode != http.StatusFound || loc != "/settings" {
			t.Fatalf("link: %d to %q %s", res.StatusCode, loc, readAll(t, res))
		}
		if accs := must[[]oauth.Account](t)(oa.Accounts(context.Background(), owner)); len(accs) != 1 {
			t.Fatalf("accounts after link = %+v", accs)
		}
		// Signed out, a link flow cannot start.
		anonWeb := newApp(t, a)
		anonWeb.srv.Close()
		anonWeb.srv = web.srv
		if res := anonWeb.get(t, "/auth/oauth/fake/start?link="+oauth.LinkFlag); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("anonymous link start: %d", res.StatusCode)
		}
	})
}

// userIDByEmail0 finds alice's user through her unverified identity.
func userIDByEmail0(t *testing.T, a *auth.Auth) string {
	t.Helper()
	idn, err := a.FindIdentity(context.Background(), email.KindEmail, alice, false)
	if err != nil {
		t.Fatal(err)
	}
	return idn.UserID
}

func TestOrganization_RolesAndRemoval(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, org := e.emailPlugin(), e.passwordPlugin(), organization.New()
		a := e.newAuth(t, nil, em, pw, org)
		owner := signUpVerified(t, e, a, pw, em)
		o := must[organization.Org](t)(org.Create(request(a, owner.Token), organization.CreateRequest{Name: "Acme", Slug: "acme"}))
		if _, err := org.Create(request(a, owner.Token), organization.CreateRequest{Name: "Acme 2", Slug: "ACME"}); !errors.Is(err, organization.ErrSlugTaken) {
			t.Fatalf("duplicate slug: %v", err)
		}

		const bob = "bob@example.com"
		if err := org.Invite(request(a, owner.Token), organization.InviteRequest{OrgID: o.ID, Email: bob, Role: organization.RoleMember}); err != nil {
			t.Fatal(err)
		}
		b := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: bob, Password: secret}))
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, bob)); err != nil {
			t.Fatal(err)
		}
		inv := must[[]organization.Invite](t)(org.Invites(request(a, b.Token)))
		must[organization.Org](t)(org.Accept(request(a, b.Token), inv[0].ID))
		if _, err := org.Accept(request(a, b.Token), inv[0].ID); !errors.Is(err, organization.ErrInviteInvalid) {
			t.Fatalf("accepting twice: %v", err)
		}

		// A member cannot invite, promote or remove others.
		if err := org.Invite(request(a, b.Token), organization.InviteRequest{OrgID: o.ID, Email: "c@example.com", Role: organization.RoleMember}); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("member invites: %v", err)
		}
		if err := org.SetRole(request(a, b.Token), organization.SetRoleRequest{OrgID: o.ID, UserID: b.User.ID, Role: organization.RoleOwner}); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("member promotes self: %v", err)
		}
		if err := org.SetRole(request(a, owner.Token), organization.SetRoleRequest{OrgID: o.ID, UserID: owner.User.ID, Role: organization.RoleAdmin}); !errors.Is(err, organization.ErrLastOwner) {
			t.Fatalf("last owner demoted: %v", err)
		}
		if err := org.SetRole(request(a, owner.Token), organization.SetRoleRequest{OrgID: o.ID, UserID: b.User.ID, Role: organization.RoleAdmin}); err != nil {
			t.Fatal(err)
		}
		list := must[[]organization.OrgWithRole](t)(org.List(request(a, b.Token)))
		if len(list) != 1 || list[0].Role != organization.RoleAdmin {
			t.Fatalf("bob's orgs = %+v", list)
		}
		// Leaving is always allowed for a non-last-owner.
		if err := org.RemoveMember(request(a, b.Token), organization.MemberRequest{OrgID: o.ID, UserID: b.User.ID}); err != nil {
			t.Fatal(err)
		}
		if _, err := org.Members(request(a, b.Token), o.ID); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("former member lists members: %v", err)
		}
		if !strings.HasPrefix(o.ID, "org_") {
			t.Fatalf("org id %q", o.ID)
		}
	})
}

// userIDByEmail0Addr finds a user through any identity with addr, verified or
// not.
func userIDByEmail0Addr(t *testing.T, a *auth.Auth, addr string) string {
	t.Helper()
	idn, err := a.FindIdentity(context.Background(), email.KindEmail, addr, false)
	if err != nil {
		t.Fatal(err)
	}
	return idn.UserID
}
