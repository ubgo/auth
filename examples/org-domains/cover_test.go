package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
)

// idBytes is the random part of a test id; enough that two ids in one test
// never collide.
const idBytes = 12

// ids is an id generator that can be told to fail for one prefix, so the
// tests reach the "no id could be drawn" branches.
type ids struct {
	mu   sync.Mutex
	fail string
}

func (g *ids) gen(prefix string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if prefix == g.fail {
		return "", errors.New("no randomness")
	}
	b := make([]byte, idBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(b), nil
}

func (g *ids) failFor(prefix string) {
	g.mu.Lock()
	g.fail = prefix
	g.mu.Unlock()
}

// world is an Auth with domains, dynamic roles and a two-member cap, Acme
// owned by Alice (who also holds a verified alice@acme.com), and Carl, a
// plain member.
type world struct {
	e     *authtest.Env
	org   *organization.Plugin
	ids   *ids
	dns   func(organization.DomainChallenge) (bool, error)
	alice *authtest.Session
	carl  *authtest.Session
	acme  organization.Org
}

func (w *world) ctx(s *authtest.Session) context.Context { return s.Context(context.Background()) }

// user creates a user with verified emails and signs them in.
func (w *world) user(name string, addrs ...string) *authtest.Session {
	w.e.T.Helper()
	var idn []authtest.Identity
	for _, a := range addrs {
		idn = append(idn, authtest.Identity{Kind: email.KindEmail, Value: a})
	}
	return w.e.SignIn(w.e.CreateUser(name, idn...).ID)
}

func newWorld(t *testing.T, f *authtest.Faults) *world { return newWorldWith(t, f, nil, nil) }

// newWorldWith is newWorld with more authtest options (a shared database)
// and more organization options (another CreatorRole).
func newWorldWith(t *testing.T, f *authtest.Faults, extra []authtest.Option, orgOpts []organization.Option) *world {
	t.Helper()
	w := buildWorld(t, f, extra, orgOpts)
	var err error
	w.alice = w.user("Alice", "alice@founders.dev", "alice@acme.com")
	w.carl = w.user("Carl", "carl@elsewhere.dev")
	if w.acme, err = w.org.Create(w.ctx(w.alice), organization.CreateRequest{Name: "Acme", Slug: "acme"}); err != nil {
		t.Fatal(err)
	}
	if err := w.org.AddMember(context.Background(), w.acme.ID, w.carl.Session.UserID, organization.RoleMember); err != nil {
		t.Fatal(err)
	}
	return w
}

// buildWorld wires the Auth and nothing else: no users, no organization.
func buildWorld(t *testing.T, f *authtest.Faults, extra []authtest.Option, orgOpts []organization.Option) *world {
	t.Helper()
	w := &world{ids: &ids{}, dns: func(organization.DomainChallenge) (bool, error) { return true, nil }}
	opts := []authtest.Option{
		authtest.WithOptions(auth.WithIDs(w.ids.gen)),
		authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin {
			return []auth.Plugin{
				email.New(email.Login(), email.Recover(), email.WithMailer(e.Mail)),
				password.New(),
				organization.New(append([]organization.Option{
					organization.MaxMembers(maxMembersInTests),
					organization.DynamicRoles(organization.DynamicRolesConfig{}),
					organization.Domains(organization.DomainsConfig{
						TrustVerifiedEmail: true,
						MaxDomains:         maxDomainsInTests,
						Verifier: organization.DomainVerifierFunc(func(_ context.Context, ch organization.DomainChallenge) (bool, error) {
							return w.dns(ch)
						}),
					}),
				}, orgOpts...)...),
			}
		}),
	}
	if f != nil {
		opts = append(opts, authtest.WithFaults(f))
	}
	opts = append(opts, extra...)
	w.e = authtest.New(t, opts...)
	org, err := auth.PluginOf[*organization.Plugin](w.e.Auth)
	if err != nil {
		t.Fatal(err)
	}
	w.org = org
	return w
}

// maxMembersInTests and maxDomainsInTests are small, so the caps are
// reached with a handful of rows.
const (
	maxMembersInTests = 4
	maxDomainsInTests = 3
)

// addDomain adds and returns a domain of Acme, failing the test on error.
func (w *world) addDomain(t *testing.T, name string, mode organization.EnrollmentMode, role organization.Role) organization.OrgDomain {
	t.Helper()
	d, err := w.org.AddDomain(w.ctx(w.alice), organization.AddDomainRequest{OrgID: w.acme.ID, Domain: name, Enrollment: mode, Role: role})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func wantCode(t *testing.T, what string, err error, want *auth.Error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: %v, want %s", what, err, want.Code)
	}
}

// TestDomains_GoAPIRefusals walks the Go API through every refusal the
// HTTP tests do not reach.
func TestDomains_GoAPIRefusals(t *testing.T) {
	w := newWorld(t, nil)
	alice, carl := w.ctx(w.alice), w.ctx(w.carl)
	stranger := w.ctx(w.user("Sam", "sam@nowhere.dev"))

	// acme.com is proved by Alice's own verified address (TrustVerifiedEmail).
	acme := w.addDomain(t, "acme.com", organization.EnrollSuggestion, "")
	if !acme.Verified || acme.Role != organization.RoleMember || acme.Enrollment != organization.EnrollSuggestion {
		t.Fatalf("acme.com = %+v", acme)
	}
	_, err := w.org.AddDomain(alice, organization.AddDomainRequest{OrgID: w.acme.ID, Domain: "acme.com"})
	wantCode(t, "same domain twice", err, organization.ErrDomainTaken)
	_, err = w.org.AddDomain(alice, organization.AddDomainRequest{OrgID: w.acme.ID, Domain: "beta.io", Enrollment: "sometimes"})
	wantCode(t, "unknown mode", err, organization.ErrBadEnrollment)
	_, err = w.org.AddDomain(alice, organization.AddDomainRequest{OrgID: w.acme.ID, Domain: "not a domain"})
	wantCode(t, "bad domain", err, organization.ErrBadDomain)
	_, err = w.org.AddDomain(stranger, organization.AddDomainRequest{OrgID: w.acme.ID, Domain: "beta.io"})
	wantCode(t, "stranger adding", err, organization.ErrNotMember)
	_, err = w.org.AddDomain(stranger, organization.AddDomainRequest{Domain: "beta.io"})
	wantCode(t, "no active organization", err, organization.ErrNoActiveOrg)
	_, err = w.org.ListDomains(stranger, "")
	wantCode(t, "list with no active organization", err, organization.ErrNoActiveOrg)
	_, err = w.org.ListDomains(stranger, w.acme.ID)
	wantCode(t, "stranger listing", err, organization.ErrNotMember)
	_, err = w.org.ListMembershipRequests(stranger, "")
	wantCode(t, "requests with no active organization", err, organization.ErrNoActiveOrg)

	// beta.io needs DNS; a verifier that cannot look is a 503, never a pass.
	beta := w.addDomain(t, "beta.io", organization.EnrollManual, "")
	_, err = w.org.AddDomain(alice, organization.AddDomainRequest{OrgID: w.acme.ID, Domain: "beta.io"})
	wantCode(t, "an unproved domain twice in one organization", err, organization.ErrDomainTaken)
	w.dns = func(organization.DomainChallenge) (bool, error) { return false, errors.New("resolver down") }
	_, err = w.org.VerifyDomain(alice, beta.ID)
	wantCode(t, "verifier failure", err, organization.ErrDomainCheckFailed)
	w.dns = func(organization.DomainChallenge) (bool, error) { return true, nil }
	if v, err := w.org.VerifyDomain(alice, beta.ID); err != nil || !v.Verified {
		t.Fatalf("verify = %+v, %v", v, err)
	}
	if v, err := w.org.VerifyDomain(alice, beta.ID); err != nil || !v.Verified {
		t.Fatalf("verifying again = %+v, %v", v, err)
	}
	if v, err := w.org.MarkDomainVerified(context.Background(), beta.ID); err != nil || !v.Verified {
		t.Fatalf("marking a verified domain = %+v, %v", v, err)
	}
	_, err = w.org.MarkDomainVerified(context.Background(), "odom_unknown")
	wantCode(t, "mark unknown", err, organization.ErrDomainNotFound)
	w.addDomain(t, "gamma.io", organization.EnrollManual, "")
	_, err = w.org.AddDomain(alice, organization.AddDomainRequest{OrgID: w.acme.ID, Domain: "delta.io"})
	wantCode(t, "over MaxDomains", err, organization.ErrDomainsLimit)

	// Another organization's claim on beta.io cannot be marked verified.
	other, err := w.org.Create(stranger, organization.CreateRequest{Name: "Other", Slug: "other"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.org.AddDomain(stranger, organization.AddDomainRequest{OrgID: other.ID, Domain: "beta.io"}); !errors.Is(err, organization.ErrDomainTaken) {
		t.Fatalf("claiming a proved domain: %v", err)
	}
	if err := w.org.RemoveDomain(alice, beta.ID); err != nil {
		t.Fatal(err)
	}
	claim, err := w.org.AddDomain(stranger, organization.AddDomainRequest{OrgID: other.ID, Domain: "zeta.io"})
	if err != nil {
		t.Fatal(err)
	}
	mine := w.addDomain(t, "zeta.io", organization.EnrollManual, "")
	if _, err := w.org.MarkDomainVerified(context.Background(), mine.ID); err != nil {
		t.Fatal(err)
	}
	_, err = w.org.MarkDomainVerified(context.Background(), claim.ID)
	wantCode(t, "marking a domain another organization proved", err, organization.ErrDomainTaken)

	// Carl, a member, cannot manage domains or requests.
	_, err = w.org.UpdateDomain(carl, organization.UpdateDomainRequest{DomainID: acme.ID})
	wantCode(t, "member updating", err, organization.ErrForbidden)
	_, err = w.org.ListMembershipRequests(carl, w.acme.ID)
	wantCode(t, "member listing requests", err, organization.ErrForbidden)

	// Suggestions: Dave asks, asking again is the same request, Carl cannot
	// decide it, Alice approves, approving again is refused.
	daveS := w.user("Dave", "dave@acme.com", "dave@home.dev")
	dave, daveID := w.ctx(daveS), daveS.Session.UserID
	if s, err := w.org.DomainSuggestions(alice); err != nil || len(s) != 0 {
		t.Fatalf("a member is suggested her own organization: %+v %v", s, err)
	}
	req, err := w.org.AcceptSuggestion(dave, acme.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := w.org.AcceptSuggestion(dave, acme.ID); err != nil || again.ID != req.ID {
		t.Fatalf("asking again = %+v, %v", again, err)
	}
	if s, err := w.org.DomainSuggestions(w.ctx(w.e.SignIn(w.e.CreateUser("No Mail").ID))); err != nil || len(s) != 0 {
		t.Fatalf("a user with no email = %+v, %v", s, err)
	}
	_, err = w.org.AcceptSuggestion(dave, "odom_unknown")
	wantCode(t, "unknown suggestion", err, organization.ErrRequestInvalid)
	wantCode(t, "member approving", w.org.ApproveMembershipRequest(carl, req.ID), organization.ErrForbidden)
	wantCode(t, "unknown request", w.org.ApproveMembershipRequest(alice, "oreq_unknown"), organization.ErrRequestInvalid)
	if list, err := w.org.ListMembershipRequests(alice, w.acme.ID); err != nil || len(list) != 1 {
		t.Fatalf("requests = %+v, %v", list, err)
	}
	if err := w.org.ApproveMembershipRequest(alice, req.ID); err != nil {
		t.Fatal(err)
	}
	wantCode(t, "approving twice", w.org.ApproveMembershipRequest(alice, req.ID), organization.ErrRequestInvalid)
	_, err = w.org.AcceptSuggestion(dave, acme.ID)
	wantCode(t, "a member asking", err, organization.ErrRequestInvalid)

	// Dave leaves, then asks again: the approved request is replaced.
	if err := w.org.RemoveMember(dave, organization.MemberRequest{OrgID: w.acme.ID, UserID: daveID}); err != nil {
		t.Fatal(err)
	}
	req2, err := w.org.AcceptSuggestion(dave, acme.ID)
	if err != nil || req2.ID == req.ID {
		t.Fatalf("asking after leaving = %+v, %v", req2, err)
	}
	// He removes his acme.com address: the request can no longer be approved.
	idns, err := w.e.Auth.VerifiedIdentities(context.Background(), daveID, email.KindEmail)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range idns {
		if i.Value == "dave@acme.com" {
			if err := w.e.Auth.DeleteIdentity(context.Background(), daveID, i.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	wantCode(t, "approving after the address went", w.org.ApproveMembershipRequest(alice, req2.ID), organization.ErrRequestInvalid)
	if err := w.org.RejectMembershipRequest(alice, req2.ID); err != nil {
		t.Fatal(err)
	}

	// The organization is full: approval refuses, enrollment skips.
	frank := w.ctx(w.user("Frank", "frank@acme.com"))
	freq, err := w.org.AcceptSuggestion(frank, acme.ID)
	if err != nil {
		t.Fatal(err)
	}
	w.user("Gina", "gina@elsewhere.dev")
	for _, name := range []string{"x1", "x2"} {
		u := w.e.CreateUser(name)
		if err := w.org.AddMember(context.Background(), w.acme.ID, u.ID, organization.RoleMember); err != nil {
			t.Fatal(err)
		}
	}
	wantCode(t, "approving into a full organization", w.org.ApproveMembershipRequest(alice, freq.ID), organization.ErrMembersLimit)
	join := organization.EnrollJoin
	if _, err := w.org.UpdateDomain(alice, organization.UpdateDomainRequest{DomainID: acme.ID, Enrollment: &join}); err != nil {
		t.Fatal(err)
	}
	hana := w.user("Hana", "hana@acme.com")
	if _, err := w.org.RoleOf(context.Background(), w.acme.ID, hana.Session.UserID); !errors.Is(err, organization.ErrNotMember) {
		t.Fatalf("a full organization enrolled hana: %v", err)
	}
}

// TestDomains_EnrollmentEdges: an automatic invitation is not duplicated
// for an address already invited, a member gets none, and a domain whose
// runtime role was deleted enrolls nobody.
func TestDomains_EnrollmentEdges(t *testing.T) {
	w := newWorld(t, nil)
	alice := w.ctx(w.alice)
	if _, err := w.org.CreateRole(alice, organization.CreateRoleRequest{OrgID: w.acme.ID, Role: "auditor", Permission: access.Permissions{organization.ResourceAC: {organization.ActionRead}}}); err != nil {
		t.Fatal(err)
	}
	d := w.addDomain(t, "acme.com", organization.EnrollInvitation, "auditor")

	if err := w.org.Invite(alice, organization.InviteRequest{OrgID: w.acme.ID, Email: "ivy@acme.com", Role: organization.RoleMember}); err != nil {
		t.Fatal(err)
	}
	ivy := w.ctx(w.user("Ivy", "ivy@acme.com"))
	if inv, err := w.org.Invites(ivy); err != nil || len(inv) != 1 || inv[0].Role != organization.RoleMember {
		t.Fatalf("ivy's invitations = %+v, %v", inv, err)
	}
	// Carl, a member, verifies an acme.com address: no invitation.
	if _, err := w.e.Auth.CreateIdentity(context.Background(), auth.NewIdentity{UserID: w.carl.Session.UserID, Kind: email.KindEmail, Raw: "carl@acme.com", Verified: true}); err != nil {
		t.Fatal(err)
	}
	if inv, err := w.org.Invites(w.ctx(w.carl)); err != nil || len(inv) != 0 {
		t.Fatalf("a member was invited: %+v, %v", inv, err)
	}
	if err := w.org.DeleteRole(alice, organization.RoleRequest{OrgID: w.acme.ID, RoleName: "auditor"}); err != nil {
		t.Fatal(err)
	}
	jo := w.ctx(w.user("Jo", "jo@acme.com"))
	if inv, err := w.org.Invites(jo); err != nil || len(inv) != 0 {
		t.Fatalf("a deleted role still enrolls: %+v, %v", inv, err)
	}
	if _, err := w.org.UpdateDomain(alice, organization.UpdateDomainRequest{DomainID: d.ID}); !errors.Is(err, organization.ErrBadRole) {
		t.Fatalf("a domain keeping a deleted role: %v", err)
	}
}

// TestDomains_NoIDs: every insert refuses cleanly when no id can be drawn,
// and enrollment fails the verification rather than half-enrolling.
func TestDomains_NoIDs(t *testing.T) {
	w := newWorld(t, nil)
	alice := w.ctx(w.alice)
	d := w.addDomain(t, "acme.com", organization.EnrollSuggestion, "")
	w.ids.failFor("odom")
	if _, err := w.org.AddDomain(alice, organization.AddDomainRequest{OrgID: w.acme.ID, Domain: "beta.io"}); err == nil {
		t.Fatal("add-domain without an id")
	}
	dave := w.ctx(w.user("Dave", "dave@acme.com"))
	w.ids.failFor("oreq")
	if _, err := w.org.AcceptSuggestion(dave, d.ID); err == nil {
		t.Fatal("accept-suggestion without an id")
	}
	mode := organization.EnrollInvitation
	if _, err := w.org.UpdateDomain(alice, organization.UpdateDomainRequest{DomainID: d.ID, Enrollment: &mode}); err != nil {
		t.Fatal(err)
	}
	w.ids.failFor("inv")
	u := w.e.CreateUser("Eve")
	if _, err := w.e.Auth.CreateIdentity(context.Background(), auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: "eve@acme.com", Verified: true}); err == nil {
		t.Fatal("an automatic invitation without an id")
	}
}

// TestDomains_EveryDatabaseFailureSurfaces fails each database call of each
// domain operation in turn and checks the failure reaches the caller.
func TestDomains_EveryDatabaseFailureSurfaces(t *testing.T) {
	type op func(t *testing.T, w *world) func(context.Context) error
	cases := map[string]op{
		"add-domain": func(_ *testing.T, w *world) func(context.Context) error {
			return func(context.Context) error {
				_, err := w.org.AddDomain(w.ctx(w.alice), organization.AddDomainRequest{OrgID: w.acme.ID, Domain: "acme.com"})
				return err
			}
		},
		"list-domains": func(t *testing.T, w *world) func(context.Context) error {
			w.addDomain(t, "acme.com", organization.EnrollManual, "")
			return func(context.Context) error { _, err := w.org.ListDomains(w.ctx(w.alice), w.acme.ID); return err }
		},
		"verify-domain": func(t *testing.T, w *world) func(context.Context) error {
			d := w.addDomain(t, "beta.io", organization.EnrollManual, "")
			return func(context.Context) error { _, err := w.org.VerifyDomain(w.ctx(w.alice), d.ID); return err }
		},
		"update-domain": func(t *testing.T, w *world) func(context.Context) error {
			d := w.addDomain(t, "acme.com", organization.EnrollManual, "")
			mode := organization.EnrollJoin
			return func(context.Context) error {
				_, err := w.org.UpdateDomain(w.ctx(w.alice), organization.UpdateDomainRequest{DomainID: d.ID, Enrollment: &mode})
				return err
			}
		},
		"remove-domain": func(t *testing.T, w *world) func(context.Context) error {
			d := w.addDomain(t, "acme.com", organization.EnrollManual, "")
			return func(context.Context) error { return w.org.RemoveDomain(w.ctx(w.alice), d.ID) }
		},
		"mark-verified": func(t *testing.T, w *world) func(context.Context) error {
			d := w.addDomain(t, "beta.io", organization.EnrollManual, "")
			return func(context.Context) error {
				_, err := w.org.MarkDomainVerified(context.Background(), d.ID)
				return err
			}
		},
		"suggestions": func(t *testing.T, w *world) func(context.Context) error {
			w.addDomain(t, "acme.com", organization.EnrollSuggestion, "")
			dave := w.user("Dave", "dave@acme.com")
			return func(context.Context) error { _, err := w.org.DomainSuggestions(w.ctx(dave)); return err }
		},
		"accept-suggestion": func(t *testing.T, w *world) func(context.Context) error {
			d := w.addDomain(t, "acme.com", organization.EnrollSuggestion, "")
			dave := w.user("Dave", "dave@acme.com")
			first, err := w.org.AcceptSuggestion(w.ctx(dave), d.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err := w.org.ApproveMembershipRequest(w.ctx(w.alice), first.ID); err != nil {
				t.Fatal(err)
			}
			if err := w.org.RemoveMember(w.ctx(dave), organization.MemberRequest{OrgID: w.acme.ID, UserID: dave.Session.UserID}); err != nil {
				t.Fatal(err)
			}
			return func(context.Context) error { _, err := w.org.AcceptSuggestion(w.ctx(dave), d.ID); return err }
		},
		"list-requests": func(t *testing.T, w *world) func(context.Context) error {
			d := w.addDomain(t, "acme.com", organization.EnrollSuggestion, "")
			dave := w.user("Dave", "dave@acme.com")
			if _, err := w.org.AcceptSuggestion(w.ctx(dave), d.ID); err != nil {
				t.Fatal(err)
			}
			return func(context.Context) error {
				_, err := w.org.ListMembershipRequests(w.ctx(w.alice), w.acme.ID)
				return err
			}
		},
		"approve": func(t *testing.T, w *world) func(context.Context) error {
			d := w.addDomain(t, "acme.com", organization.EnrollSuggestion, "")
			dave := w.user("Dave", "dave@acme.com")
			r, err := w.org.AcceptSuggestion(w.ctx(dave), d.ID)
			if err != nil {
				t.Fatal(err)
			}
			return func(context.Context) error { return w.org.ApproveMembershipRequest(w.ctx(w.alice), r.ID) }
		},
		"reject": func(t *testing.T, w *world) func(context.Context) error {
			d := w.addDomain(t, "acme.com", organization.EnrollSuggestion, "")
			dave := w.user("Dave", "dave@acme.com")
			r, err := w.org.AcceptSuggestion(w.ctx(dave), d.ID)
			if err != nil {
				t.Fatal(err)
			}
			return func(context.Context) error { return w.org.RejectMembershipRequest(w.ctx(w.alice), r.ID) }
		},
		"enroll-join": func(t *testing.T, w *world) func(context.Context) error {
			w.addDomain(t, "acme.com", organization.EnrollJoin, "")
			u := w.e.CreateUser("Dave")
			return func(context.Context) error {
				_, err := w.e.Auth.CreateIdentity(context.Background(), auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: "dave@acme.com", Verified: true})
				return err
			}
		},
		"enroll-invitation": func(t *testing.T, w *world) func(context.Context) error {
			w.addDomain(t, "acme.com", organization.EnrollInvitation, "")
			u := w.e.CreateUser("Dave")
			return func(context.Context) error {
				_, err := w.e.Auth.CreateIdentity(context.Background(), auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: "dave@acme.com", Verified: true})
				return err
			}
		},
		"permissions-of": func(t *testing.T, w *world) func(context.Context) error {
			return func(context.Context) error {
				_, err := w.org.PermissionsOf(context.Background(), w.acme.ID, "auditor")
				return err
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			authtest.SweepFaults(t,
				func() (*world, *authtest.Faults) { f := authtest.NewFaults(); return newWorld(t, f), f },
				func(w *world) func(context.Context) error { return setup(t, w) })
		})
	}
}
