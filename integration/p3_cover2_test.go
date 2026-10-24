package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/emailchallenge"
	"github.com/ubgo/auth/plugin/invite"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/referral"
	"github.com/ubgo/auth/plugin/scim"
	"github.com/ubgo/auth/plugin/username"
	"github.com/ubgo/sqlb"
)

// TestP3Cover2_APIKeyStampFaults: under StampEveryUse the stamp is a check,
// not a best-effort write, so every database failure of a key's use,
// the stamp's included, fails the request.
func TestP3Cover2_APIKeyStampFaults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak := apikey.New(apikey.Scopes("s"), apikey.StampEveryUse())
		a := e.newAuth(t, nil, em, pw, ak)
		up := signUpVerified(t, e.env, a, pw, em)
		made := must[apikey.CreateResult](t)(ak.Create(request(a, up.Token), apikey.CreateRequest{Name: "k"}))
		return func(context.Context) error { return tokensUse(a, made.Secret) }
	})
}

// p3Cover2DropFails is the app's cache whose Delete fails: the entry of a
// key deleted behind it cannot be dropped.
type p3Cover2DropFails struct{ *apikey.MemoryCache }

func (p3Cover2DropFails) Delete(context.Context, string) error { return errors.New("cache down") }

// TestP3Cover2_APIKeyStampDropFails: a key deleted behind its cache entry is
// refused under StampEveryUse even when its entry cannot be dropped; the
// failed drop is only logged, because the refusal does not depend on it.
func TestP3Cover2_APIKeyStampDropFails(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		cache := p3Cover2DropFails{apikey.NewMemoryCacheAt(e.clock.Now)}
		a, ak, up := r6Keyed(t, e, apikey.Scopes("read"), apikey.DistinctErrors(), apikey.StampEveryUse(), apikey.WithCache(cache, 10*time.Minute))
		k := must[apikey.CreateResult](t)(ak.Create(request(a, up.Token), apikey.CreateRequest{Name: "k"}))
		if v, err := ak.Verify(context.Background(), k.Secret); err != nil || !v.Valid {
			t.Fatalf("first use: %+v %v", v, err)
		}
		r6DeleteRow(t, a, k.Key.ID)
		v, err := ak.Verify(context.Background(), k.Secret)
		if err != nil || v.Valid || !errors.Is(v.Reason, apikey.ErrInvalidKey) {
			t.Fatalf("a deleted key whose entry cannot be dropped: %+v %v", v, err)
		}
	})
}

// p3Cover2Org is an organization owner with a pending invitation to
// x@acme.test, on an Auth whose background tasks are held until the test
// ends: a sweep then counts only the operation's own database calls, never
// a post-commit send.
func p3Cover2Org(t *testing.T, e *faultEnv, opts ...auth.Option) (*auth.Auth, *organization.Plugin, context.Context, organization.Org) {
	t.Helper()
	em, pw := e.emailPlugin(), e.passwordPlugin()
	org := organization.New()
	var queued []func()
	opts = append(opts, auth.WithBackground(func(ctx context.Context, task func(context.Context)) {
		queued = append(queued, func() { task(ctx) })
	}))
	a := e.newAuth(t, opts, em, pw, org)
	// Registered after newAuth's Close, so it runs first: the held sends
	// run once the sweep has disarmed, and Close finds no delivery waiting.
	t.Cleanup(func() {
		for _, run := range queued {
			run()
		}
	})
	up := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret}))
	ctx := request(a, up.Token)
	o := must[organization.Org](t)(org.Create(ctx, organization.CreateRequest{Name: "Acme", Slug: "acme"}))
	if err := org.Invite(ctx, organization.InviteRequest{OrgID: o.ID, Email: "x@acme.test", Role: organization.RoleMember}); err != nil {
		t.Fatal(err)
	}
	return a, org, ctx, o
}

// TestP3Cover2_OrgResendFaults: a resend reads the pending invitation,
// extends it and writes the mail to the delivery outbox in one transaction;
// every database failure among them fails the resend.
func TestP3Cover2_OrgResendFaults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		_, org, ctx, o := p3Cover2Org(t, e, auth.WithDeliveryOutbox(make([]byte, 32)))
		return func(context.Context) error {
			return org.Invite(ctx, organization.InviteRequest{OrgID: o.ID, Email: "x@acme.test", Role: organization.RoleMember, Resend: true})
		}
	})
}

// TestP3Cover2_OrgListAllFaults: the platform list reads the page and the
// total; a failure of either fails the list.
func TestP3Cover2_OrgListAllFaults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		_, org, _, _ := p3Cover2Org(t, e)
		return func(ctx context.Context) error {
			r, err := org.ListAll(ctx, organization.AllOrgsRequest{})
			if err == nil && (r.Total != 1 || len(r.Orgs) != 1) {
				return fmt.Errorf("list all = %+v", r)
			}
			return err
		}
	})
}

// TestP3Cover2_OrgUpdateForUnknown: the platform update of an id that names
// no organization is ErrNotMember, the code every read gives for one.
func TestP3Cover2_OrgUpdateForUnknown(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		org := organization.New()
		e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), org)
		name := "x"
		if _, err := org.UpdateFor(context.Background(), "org_missing", organization.OrgUpdate{Name: &name}); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("update of an unknown organization: %v", err)
		}
	})
}

// TestP3Cover2_OrgTeamMembersFaults: list-team-members without a team id
// reads the session's active team; a failure of that read fails the list.
func TestP3Cover2_OrgTeamMembersFaults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		org := organization.New(organization.Teams(organization.TeamsConfig{}))
		a := e.newAuth(t, nil, em, pw, org)
		up := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret}))
		ctx := request(a, up.Token)
		o := must[organization.Org](t)(org.Create(ctx, organization.CreateRequest{Name: "Acme", Slug: "acme"}))
		team := must[organization.Team](t)(org.CreateTeam(ctx, organization.CreateTeamRequest{OrgID: o.ID, Name: "Core"}))
		if err := org.AddTeamMember(ctx, organization.TeamMemberRequest{TeamID: team.ID, UserID: up.User.ID}); err != nil {
			t.Fatal(err)
		}
		must[organization.ActiveResult](t)(org.SetActiveTeam(ctx, team.ID))
		return func(context.Context) error {
			m, err := org.ListTeamMembers(ctx, "")
			if err == nil && len(m) != 1 {
				return fmt.Errorf("members = %+v", m)
			}
			return err
		}
	})
}

// p3Cover2SCIM is a SCIM world whose resolver links every new SCIM user to
// target under ProfileManage, with the username kind registered so the
// target can hold an identity that is not an address. extra are the app's
// own plugins (data hooks).
func p3Cover2SCIM(t *testing.T, e *env, target *string, extra ...auth.Plugin) *scimWorld {
	t.Helper()
	rec := &recordingMapper{state: map[string][]string{}}
	sp := scim.New(
		scim.Connections(scim.Connection{ID: "acme", Credentials: []scim.Credential{{ID: "full", Token: scimToken}}}),
		scim.WithGroupMapper(rec),
		scim.ResolveUser(func(context.Context, scim.ResolveInput) (scim.Resolution, error) {
			return scim.Resolution{UserID: *target, Profile: scim.ProfileManage}, nil
		}),
	)
	plugins := append([]auth.Plugin{e.emailPlugin(), e.passwordPlugin(), username.New(), sp}, extra...)
	a := e.newAuth(t, nil, plugins...)
	mux := http.NewServeMux()
	mux.Handle("/scim/v2/", http.StripPrefix("/scim/v2", sp.Handler()))
	return &scimWorld{a: a, sp: sp, h: mux, groups: rec}
}

// p3Cover2Target is a library user with a primary address and a username,
// the shape a managed claim walks past (the username) and replaces (the
// address).
func p3Cover2Target(t *testing.T, a *auth.Auth) string {
	t.Helper()
	id, _ := identUser(t, a, "old@acme.test")
	must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: id, Kind: username.KindUsername, Raw: "ada"}))
	return id
}

// TestP3Cover2_SCIMClaimFaults: a managed claim renames the user, reads its
// identities (passing over the username), creates the IdP's address and
// removes the old one; every database failure among them fails the
// provisioning request. TestP3Cover2_SCIMClaimRefusals checks the result
// of a claim that succeeds.
func TestP3Cover2_SCIMClaimFaults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		var target string
		w := p3Cover2SCIM(t, e.env, &target)
		target = p3Cover2Target(t, w.a)
		return func(context.Context) error {
			if code, body := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("ada@acme.test", "ada@acme.test", "ext-a")); code != http.StatusCreated {
				return fmt.Errorf("claim = %d %v", code, body)
			}
			return nil
		}
	})
}

// p3Cover2Refuse is the app's plugin whose data hooks refuse a user update
// or an identity removal while on.
type p3Cover2Refuse struct{ user, delete bool }

func (*p3Cover2Refuse) Name() string { return "p3cover2_refuse" }

func (r *p3Cover2Refuse) DataHooks() auth.DataHooks {
	errRefused := errors.New("refused by the app")
	return auth.DataHooks{
		User: auth.TableHooks[auth.User]{BeforeUpdate: func(context.Context, sqlb.DBTX, *auth.User, *auth.User) error {
			if r.user {
				return errRefused
			}
			return nil
		}},
		Identity: auth.TableHooks[auth.Identity]{BeforeDelete: func(context.Context, sqlb.DBTX, *auth.Identity) error {
			if r.delete {
				return errRefused
			}
			return nil
		}},
	}
}

// TestP3Cover2_SCIMClaimRefusals: a managed claim the app's own hooks refuse
// (the rename, the removal of the old address) fails and leaves the user's
// address as it was; a SCIM email the email kind refuses (no dot in the
// domain, which SCIM's own RFC 5322 check allows) cannot become the managed
// one; and the claim the hooks allow replaces the old address with the
// IdP's, passing over the username.
func TestP3Cover2_SCIMClaimRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var target string
		hooks := &p3Cover2Refuse{}
		w := p3Cover2SCIM(t, e, &target, hooks)
		target = p3Cover2Target(t, w.a)
		for _, h := range []p3Cover2Refuse{{user: true}, {delete: true}} {
			*hooks = h
			if code, body := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("ada@acme.test", "ada@acme.test", "")); code != http.StatusInternalServerError {
				t.Fatalf("refused %+v = %d %v", h, code, body)
			}
			if _, ok := libraryUser(t, w.a, "old@acme.test"); !ok {
				t.Fatalf("refused %+v: the old address went", h)
			}
		}
		*hooks = p3Cover2Refuse{}
		if code, body := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("bad", "ada@localhost", "")); code != http.StatusBadRequest {
			t.Fatalf("a managed claim of an address the email kind refuses = %d %v", code, body)
		}
		if code, body := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("ada@acme.test", "ada@acme.test", "")); code != http.StatusCreated {
			t.Fatalf("claim = %d %v", code, body)
		}
		if _, ok := libraryUser(t, w.a, "old@acme.test"); ok {
			t.Fatal("the old address survived the claim")
		}
		if idn, ok := libraryUser(t, w.a, "ada@acme.test"); !ok || idn.UserID != target {
			t.Fatalf("the IdP's address = %+v %v", idn, ok)
		}
	})
}

// TestP3Cover2_PluginCookieNamesAreValid pins the reason COVERAGE.md gives
// for the cookie-setting error branches of invite, emailchallenge and
// referral: Effects.SetCookie fails only on a bad name, and each plugin sets
// one fixed name that the core accepts.
func TestP3Cover2_PluginCookieNamesAreValid(t *testing.T) {
	for _, name := range []string{invite.CookieName, emailchallenge.CookieName, referral.CookieName} {
		if err := auth.CheckCookieName(name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
