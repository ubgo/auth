package integration

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/username"
	"github.com/ubgo/sqlb"
)

// Addresses the ident tests use beside alice.
const (
	identWork = "work@example.com"
	identNext = "next@example.com"
	identBob  = "bob@example.com"
)

// identUser creates a user whose only identity is addr, verified and primary,
// with a fresh session, straight through the core so a test pays for no
// password hashing. It returns the user id and the session token.
func identUser(t *testing.T, a *auth.Auth, addr string) (string, auth.Token) {
	t.Helper()
	ctx := context.Background()
	u := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{}))
	if addr != "" {
		must[auth.Identity](t)(a.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: addr, Verified: true, Primary: true}))
	}
	_, tok, err := a.CreateSession(ctx, u.ID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	return u.ID, tok
}

// identAddresses lists the user's addresses as "value[v][p]" strings, sorted,
// so a test compares the whole state as a set in one line. Sorted because
// rows created in the same clock tick have no insertion order an engine keeps:
// MySQL and SQLite return them differently.
func identAddresses(t *testing.T, em *email.Plugin, a *auth.Auth, tok auth.Token) string {
	t.Helper()
	var parts []string
	for _, ad := range must[[]email.Address](t)(em.List(request(a, tok))) {
		s := ad.Email
		if ad.Verified {
			s += "[v]"
		}
		if ad.Primary {
			s += "[p]"
		}
		parts = append(parts, s)
	}
	slices.Sort(parts)
	return strings.Join(parts, " ")
}

// identLink returns the token of the newest link to page mailed to addr.
// Deliveries run concurrently, so "the newest mail" can be a verify link sent
// just before a change link; matching the page picks the right one.
func identLink(t *testing.T, e *env, a *auth.Auth, addr, page string) auth.Token {
	t.Helper()
	list := e.mail.To(a, addr)
	for i := len(list) - 1; i >= 0; i-- {
		if !strings.Contains(list[i].Text, page) {
			continue
		}
		if m := tokenInLink.FindStringSubmatch(list[i].Text); m != nil {
			return auth.Token(m[1])
		}
	}
	t.Fatalf("no %s link mailed to %s", page, addr)
	return ""
}

// identSignedIn reports whether tok still resolves to a signed-in user.
func identSignedIn(t *testing.T, a *auth.Auth, tok auth.Token) bool {
	t.Helper()
	ctx := request(a, tok)
	if err := a.Resolve(ctx); err != nil {
		t.Fatal(err)
	}
	_, ok := auth.CurrentUser(ctx)
	return ok
}

// identPrimaryColumn reads the auth_user copy of the primary address.
func identPrimaryColumn(t *testing.T, a *auth.Auth, userID string) string {
	t.Helper()
	var cols email.EmailColumns
	if err := a.LoadUserColumns(context.Background(), userID, email.Bindings(&cols)...); err != nil {
		t.Fatal(err)
	}
	if cols.PrimaryEmail == nil {
		return ""
	}
	return *cols.PrimaryEmail
}

func TestIdentEmail_TTLOptions(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.Multiple(), email.WithVerifyTTL(time.Minute), email.WithUndoTTL(time.Hour))
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		_, tok := identUser(t, a, alice)
		if err := em.Add(request(a, tok), identWork); err != nil {
			t.Fatal(err)
		}
		link := e.mail.LastToken(t, a, identWork)
		e.clock.Advance(2 * time.Minute)
		if _, err := em.Verify(anon(a), link); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("verify link past WithVerifyTTL = %v", err)
		}

		_, tok = identUser(t, a, identBob)
		if err := em.Change(request(a, tok), identNext); err != nil {
			t.Fatal(err)
		}
		if _, err := em.ConfirmChange(anon(a), e.mail.LastToken(t, a, identNext)); err != nil {
			t.Fatal(err)
		}
		undo := e.mail.LastToken(t, a, identBob)
		e.clock.Advance(2 * time.Hour)
		if err := em.UndoChange(anon(a), undo); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("undo link past WithUndoTTL = %v", err)
		}
	})
}

// TestIdentEmail_VerifyRefusals: a bad token, and a link to an address that
// was removed after it was sent, are both just invalid links.
func TestIdentEmail_VerifyRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.Multiple())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		if _, err := em.Verify(anon(a), "not-a-token"); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("bad token = %v", err)
		}
		_, tok := identUser(t, a, alice)
		if err := em.Add(request(a, tok), identWork); err != nil {
			t.Fatal(err)
		}
		link := e.mail.LastToken(t, a, identWork)
		if err := em.Remove(request(a, tok), identWork); err != nil {
			t.Fatal(err)
		}
		if _, err := em.Verify(anon(a), link); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("link to a removed address = %v", err)
		}
	})
}

// TestIdentEmail_ResendSignedIn: a signed-in resend looks only at the user's
// own addresses, so it cannot be used to mail somebody else's.
func TestIdentEmail_ResendSignedIn(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.Multiple())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		_, tok := identUser(t, a, alice)
		if err := em.Add(request(a, tok), identWork); err != nil {
			t.Fatal(err)
		}
		before := len(e.mail.To(a, identWork))
		if err := em.Resend(request(a, tok), " WORK@example.com"); err != nil {
			t.Fatal(err)
		}
		if n := len(e.mail.To(a, identWork)); n != before+1 {
			t.Fatalf("resend to own unverified address: %d mails, want %d", n, before+1)
		}
		// Another user's unverified address: same answer, nothing sent.
		_, bobTok := identUser(t, a, identBob)
		if err := em.Resend(request(a, bobTok), identWork); err != nil {
			t.Fatal(err)
		}
		if n := len(e.mail.To(a, identWork)); n != before+1 {
			t.Fatalf("resend to another user's address sent mail: %d", n)
		}
	})
}

// TestIdentEmail_SingleAddress: without Multiple a user has at most one
// address, and the first one can still be added.
func TestIdentEmail_SingleAddress(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		single := e.emailPlugin()
		a := e.newAuth(t, nil, single, e.passwordPlugin())
		_, tok := identUser(t, a, alice)
		if err := single.Add(request(a, tok), identWork); !errors.Is(err, email.ErrSingleAddress) {
			t.Fatalf("second address without Multiple = %v", err)
		}
		// A user with no address may add their first one.
		_, bare := identUser(t, a, "")
		if err := single.Add(request(a, bare), identWork); err != nil {
			t.Fatal(err)
		}
		if got := identAddresses(t, single, a, bare); got != identWork {
			t.Fatalf("addresses = %q", got)
		}
	})
}

// TestIdentEmail_AddTwiceIsANoOp: re-adding an address the user has sends
// nothing and adds no row; an invalid one is refused.
func TestIdentEmail_AddTwiceIsANoOp(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.Multiple())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		_, tok := identUser(t, a, alice)
		before := len(e.mail.To(a, alice))
		if err := em.Add(request(a, tok), "ALICE@example.com"); err != nil {
			t.Fatalf("adding an address the user has = %v, want a no-op", err)
		}
		if n := len(e.mail.To(a, alice)); n != before {
			t.Fatal("a no-op add sent mail")
		}
		if err := em.Add(request(a, tok), "not an address"); !errors.Is(err, auth.ErrIdentifierInvalid) {
			t.Fatalf("invalid address = %v", err)
		}
		if got := identAddresses(t, em, a, tok); got != alice+"[v][p]" {
			t.Fatalf("addresses = %q", got)
		}
	})
}

// TestIdentEmail_NotTheUsersAddress: operations on an address the user does
// not have, or on something that is not an address, change nothing.
func TestIdentEmail_NotTheUsersAddress(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.Multiple())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		_, tok := identUser(t, a, alice)
		identUser(t, a, identBob)
		ctx := request(a, tok)
		if err := em.MakePrimary(ctx, identBob); !errors.Is(err, auth.ErrIdentityNotFound) {
			t.Fatalf("make-primary of another user's address = %v", err)
		}
		if err := em.Remove(ctx, identBob); !errors.Is(err, auth.ErrIdentityNotFound) {
			t.Fatalf("remove of another user's address = %v", err)
		}
		if err := em.MakePrimary(ctx, "nonsense"); !errors.Is(err, auth.ErrIdentifierInvalid) {
			t.Fatalf("make-primary of a non-address = %v", err)
		}
		if err := em.Change(ctx, "nonsense"); !errors.Is(err, auth.ErrIdentifierInvalid) {
			t.Fatalf("change to a non-address = %v", err)
		}
		if got := identAddresses(t, em, a, tok); got != alice+"[v][p]" {
			t.Fatalf("addresses = %q", got)
		}
	})
}

// TestIdentEmail_RemovePrimaryPromotesTheNext: removing the primary address
// hands primary to the next verified one, and auth_user's copy follows.
func TestIdentEmail_RemovePrimaryPromotesTheNext(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.Multiple())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		uid, tok := identUser(t, a, alice)
		if err := em.Add(request(a, tok), identWork); err != nil {
			t.Fatal(err)
		}
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, identWork)); err != nil {
			t.Fatal(err)
		}
		if got := identAddresses(t, em, a, tok); got != alice+"[v][p] "+identWork+"[v]" {
			t.Fatalf("before = %q", got)
		}
		if err := em.Remove(request(a, tok), alice); err != nil {
			t.Fatal(err)
		}
		if got := identAddresses(t, em, a, tok); got != identWork+"[v][p]" {
			t.Fatalf("after = %q", got)
		}
		if got := identPrimaryColumn(t, a, uid); got != identWork {
			t.Fatalf("auth_user primary_email = %q", got)
		}
	})
}

// TestIdentEmail_ConfirmChangeToOwnUnverifiedAddress: when the new address is
// already a row of the user, it is verified and made primary, not duplicated,
// and the old primary is told with an undo link.
func TestIdentEmail_ConfirmChangeToOwnUnverifiedAddress(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.Multiple())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		uid, tok := identUser(t, a, alice)
		if err := em.Add(request(a, tok), identWork); err != nil {
			t.Fatal(err)
		}
		if err := em.Change(request(a, tok), identWork); err != nil {
			t.Fatal(err)
		}
		res, err := em.ConfirmChange(anon(a), identLink(t, e, a, identWork, email.DefaultChangePage))
		if err != nil || res.Email != identWork {
			t.Fatalf("confirm = %+v %v", res, err)
		}
		if got := identAddresses(t, em, a, tok); got != alice+"[v] "+identWork+"[v][p]" {
			t.Fatalf("addresses = %q", got)
		}
		if got := identPrimaryColumn(t, a, uid); got != identWork {
			t.Fatalf("auth_user primary_email = %q", got)
		}
		// Undo: alice exists (Multiple kept her), so she is made primary
		// again rather than re-created, and the replacing address goes.
		if err := em.UndoChange(anon(a), identLink(t, e, a, alice, email.DefaultUndoPage)); err != nil {
			t.Fatal(err)
		}
		ids := must[[]auth.Identity](t)(a.Identities(context.Background(), uid))
		if len(ids) != 1 || ids[0].Value != alice || !ids[0].IsPrimary {
			t.Fatalf("after undo = %+v", ids)
		}
	})
}

// TestIdentEmail_ConfirmChangeToATakenAddress: another user's verified
// address cannot be taken over by a change link.
func TestIdentEmail_ConfirmChangeToATakenAddress(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin()
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		uid, tok := identUser(t, a, alice)
		if err := em.Change(request(a, tok), identBob); err != nil {
			t.Fatal(err)
		}
		link := e.mail.LastToken(t, a, identBob)
		identUser(t, a, identBob) // bob verifies the address first
		if _, err := em.ConfirmChange(anon(a), link); !errors.Is(err, auth.ErrIdentityTaken) {
			t.Fatalf("confirm to a taken address = %v", err)
		}
		if got := identPrimaryColumn(t, a, uid); got != alice {
			t.Fatalf("alice's primary changed to %q", got)
		}
		if _, err := em.ConfirmChange(anon(a), "not-a-token"); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("bad token = %v", err)
		}
	})
}

// TestIdentEmail_ChangeWithoutAVerifiedPrimarySendsNoUndo: an undo link goes
// only to a proven address; an unverified one could be anybody's.
func TestIdentEmail_ChangeWithoutAVerifiedPrimarySendsNoUndo(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin()
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		_, tok := identUser(t, a, "")
		if err := em.Add(request(a, tok), alice); err != nil {
			t.Fatal(err)
		}
		before := len(e.mail.To(a, alice))
		if err := em.Change(request(a, tok), identNext); err != nil {
			t.Fatal(err)
		}
		if _, err := em.ConfirmChange(anon(a), e.mail.LastToken(t, a, identNext)); err != nil {
			t.Fatal(err)
		}
		if n := len(e.mail.To(a, alice)); n != before {
			t.Fatalf("an unverified old address got %d new mails", n-before)
		}
		if got := identAddresses(t, em, a, tok); got != identNext+"[v][p]" {
			t.Fatalf("addresses = %q", got)
		}
	})
}

func TestIdentEmail_UndoRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin()
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		uid, tok := identUser(t, a, alice)
		if err := em.UndoChange(anon(a), "not-a-token"); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("bad token = %v", err)
		}
		// Only this plugin writes undo tokens, so a Meta without the
		// separator is an internal error, and nothing is changed.
		bad := must[auth.Token](t)(a.IssueVerification(context.Background(), email.PurposeUndoToken, uid, time.Hour, "no separator"))
		if err := em.UndoChange(anon(a), bad); err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("malformed undo token = %v", err)
		}
		if !identSignedIn(t, a, tok) {
			t.Fatal("a refused undo signed the user out")
		}
		if got := identPrimaryColumn(t, a, uid); got != alice {
			t.Fatalf("primary = %q", got)
		}
	})
}

// TestIdentEmail_CodeEdgeCases: malformed addresses get the uniform answers,
// and a code for an address whose owner has since gone signs nobody in.
func TestIdentEmail_CodeEdgeCases(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.Multiple(), email.SignInWithCode())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		if err := em.SendCode(anon(a), "nonsense"); err != nil {
			t.Fatalf("send-code to a non-address = %v, want the uniform answer", err)
		}
		if _, err := em.SignInCode(anon(a), "nonsense", "123456"); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("sign-in-code with a non-address = %v", err)
		}
		_, tok := identUser(t, a, alice)
		if err := em.Add(request(a, tok), identWork); err != nil {
			t.Fatal(err)
		}
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, identWork)); err != nil {
			t.Fatal(err)
		}
		if err := em.SendCode(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		code := lastMailCode(t, e, a, alice)
		if err := em.Remove(request(a, tok), alice); err != nil {
			t.Fatal(err)
		}
		if _, err := em.SignInCode(anon(a), alice, code); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("code for an address removed since = %v", err)
		}
	})
}

// TestIdentEmail_MakePrimarySendsNoWelcome: moving primary between verified
// addresses moves auth_user's copy and is not a first verification, so no
// welcome follows.
func TestIdentEmail_MakePrimarySendsNoWelcome(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.Multiple(), email.Welcome())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		uid, tok := identUser(t, a, alice)
		if err := em.Add(request(a, tok), identWork); err != nil {
			t.Fatal(err)
		}
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, identWork)); err != nil {
			t.Fatal(err)
		}
		welcomes := func() int {
			n := 0
			for _, m := range append(e.mail.To(a, alice), e.mail.To(a, identWork)...) {
				if m.Subject == "Welcome" {
					n++
				}
			}
			return n
		}
		before := welcomes()
		if err := em.MakePrimary(request(a, tok), identWork); err != nil {
			t.Fatal(err)
		}
		if got := identAddresses(t, em, a, tok); got != alice+"[v] "+identWork+"[v][p]" {
			t.Fatalf("addresses = %q", got)
		}
		if n := welcomes(); n != before {
			t.Fatalf("make-primary sent %d welcome mails", n-before)
		}
		if got := identPrimaryColumn(t, a, uid); got != identWork {
			t.Fatalf("auth_user primary_email = %q", got)
		}
	})
}

// TestIdentEmail_VerifiedNonPrimaryCreateIsPromoted: an address created
// verified but not primary, for a user with no primary, becomes primary, and
// the welcome goes to it.
func TestIdentEmail_VerifiedNonPrimaryCreateIsPromoted(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.Welcome())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		uid, _ := identUser(t, a, "")
		must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: uid, Kind: email.KindEmail, Raw: alice, Verified: true}))
		if got := identPrimaryColumn(t, a, uid); got != alice {
			t.Fatalf("auth_user primary_email = %q, want the promoted address", got)
		}
		mails := e.mail.To(a, alice)
		if len(mails) != 1 || mails[0].Subject != "Welcome" {
			t.Fatalf("mail = %+v, want one welcome", mails)
		}
	})
}

// TestIdentEmail_UndoAfterTheNewAddressWasRemoved: the undo still restores
// the old address and signs every session out when the replacing address is
// already gone.
func TestIdentEmail_UndoAfterTheNewAddressWasRemoved(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.Multiple())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		uid, tok := identUser(t, a, alice)
		if err := em.Change(request(a, tok), identNext); err != nil {
			t.Fatal(err)
		}
		if _, err := em.ConfirmChange(anon(a), identLink(t, e, a, identNext, email.DefaultChangePage)); err != nil {
			t.Fatal(err)
		}
		if err := em.Remove(request(a, tok), identNext); err != nil {
			t.Fatal(err)
		}
		if err := em.UndoChange(anon(a), identLink(t, e, a, alice, email.DefaultUndoPage)); err != nil {
			t.Fatal(err)
		}
		ids := must[[]auth.Identity](t)(a.Identities(context.Background(), uid))
		if len(ids) != 1 || ids[0].Value != alice || !ids[0].IsPrimary {
			t.Fatalf("after undo = %+v", ids)
		}
		if identSignedIn(t, a, tok) {
			t.Fatal("undo must sign every session out")
		}
	})
}

// TestIdentEmail_UndoLinkWhenTheNewAddressIsOlder pins a bug: confirm-change
// found the old primary in the same pass that found the new address, so when
// the new address's row came first (it is older) the old primary was never
// seen and got no undo link. Which row comes first varied by engine.
func TestIdentEmail_UndoLinkWhenTheNewAddressIsOlder(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.Multiple())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		uid, tok := identUser(t, a, "")
		if err := em.Add(request(a, tok), identWork); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(time.Second) // alice is created after work
		must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: uid, Kind: email.KindEmail, Raw: alice, Verified: true, Primary: true}))
		if err := em.Change(request(a, tok), identWork); err != nil {
			t.Fatal(err)
		}
		if _, err := em.ConfirmChange(anon(a), identLink(t, e, a, identWork, email.DefaultChangePage)); err != nil {
			t.Fatal(err)
		}
		if err := em.UndoChange(anon(a), identLink(t, e, a, alice, email.DefaultUndoPage)); err != nil {
			t.Fatalf("undo through the link the old primary received: %v", err)
		}
		if got := identPrimaryColumn(t, a, uid); got != alice {
			t.Fatalf("primary after undo = %q", got)
		}
	})
}

// TestIdentEmail_CodeOptions: WithCodeTTL and WithMaxAttempts replace the
// code lifetime and the per-code guess cap.
func TestIdentEmail_CodeOptions(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.SignUpWithCode(), email.WithCodeTTL(2*time.Minute), email.WithMaxAttempts(2))
		a := e.newAuth(t, nil, em)
		if err := em.SendCode(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		code := lastMailCode(t, e, a, alice)
		wrong := "000000"
		if code == wrong {
			wrong = "111111"
		}
		for range 2 {
			if _, err := em.SignInCode(anon(a), alice, wrong); !errors.Is(err, auth.ErrCodeInvalid) {
				t.Fatalf("wrong code: %v", err)
			}
		}
		if _, err := em.SignInCode(anon(a), alice, code); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("right code after WithMaxAttempts(2) guesses = %v, want spent", err)
		}
		if err := em.SendCode(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		code = lastMailCode(t, e, a, alice)
		e.clock.Advance(3 * time.Minute)
		if _, err := em.SignInCode(anon(a), alice, code); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("code past WithCodeTTL = %v", err)
		}
	})
}

// TestIdentEmail_SignInOnVerify: with the option, the verify link signs its
// user in and the result carries the session; without it, no session.
func TestIdentEmail_SignInOnVerify(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.SignInOnVerify())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		uid, _ := identUser(t, a, "")
		must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: uid, Kind: email.KindEmail, Raw: alice}))
		res, err := em.Verify(anon(a), identLink(t, e, a, alice, email.DefaultVerifyPage))
		if err != nil || !res.SignedIn || res.Token == "" || res.SecondFactorRequired {
			t.Fatalf("verify = %+v %v", res, err)
		}
		if !identSignedIn(t, a, res.Token) {
			t.Fatal("the token from verify does not resolve to a session")
		}
	})
}

// TestIdentEmail_VerifyWithoutSignInOnVerify: the default verify issues no
// session, so an app that never asked for one sees no change.
func TestIdentEmail_VerifyWithoutSignInOnVerify(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin()
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		uid, _ := identUser(t, a, "")
		must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: uid, Kind: email.KindEmail, Raw: identBob}))
		res, err := em.Verify(anon(a), identLink(t, e, a, identBob, email.DefaultVerifyPage))
		if err != nil || res.SignedIn || res.Token != "" {
			t.Fatalf("verify without the option = %+v %v, want no session", res, err)
		}
	})
}

// TestIdentUsername_ImmutableAndNormalizer: Immutable refuses a rename but
// allows the first handle; a custom normalizer decides what is stored.
func TestIdentUsername_ImmutableAndNormalizer(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		un := username.New(username.Login(), username.Immutable(), username.Length(3, 10),
			username.WithNormalizer(func(raw string) (string, error) {
				return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(raw)), "0", "o"), nil
			}))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), un)
		_, tok := identUser(t, a, alice)
		if _, err := un.Set(request(a, tok), "ab"); !errors.Is(err, auth.ErrIdentifierInvalid) {
			t.Fatalf("2 characters under Length(3, 10) = %v", err)
		}
		res, err := un.Set(request(a, tok), "L0velace")
		if err != nil || res.Username != "lovelace" {
			t.Fatalf("set = %+v %v, want the custom normal form", res, err)
		}
		if _, err := un.Set(request(a, tok), "ada"); !errors.Is(err, username.ErrImmutable) {
			t.Fatalf("rename under Immutable = %v", err)
		}
		if ok, err := un.Available(anon(a), "LOVELACE"); err != nil || ok {
			t.Fatalf("available = %v %v", ok, err)
		}
	})
}

// TestIdentMagicLink_SendLimitOption: WithSendLimit replaces the default of
// three links per identifier.
func TestIdentMagicLink_SendLimitOption(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ml := magiclink.New(magiclink.SignUp(), magiclink.WithSendLimit(2, time.Hour))
		a := e.newAuth(t, nil, e.emailPlugin(), ml)
		for range 2 {
			if err := ml.Send(anon(a), alice); err != nil {
				t.Fatal(err)
			}
		}
		if err := ml.Send(anon(a), alice); !errors.Is(err, auth.ErrRateLimited) {
			t.Fatalf("third link under WithSendLimit(2) = %v", err)
		}
	})
}

// TestIdentEmail_ApproveChangeFirst: with the option, the current address
// approves a change before the new address is asked; a user with no verified
// current address gets the one-step flow.
func TestIdentEmail_ApproveChangeFirst(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.ApproveChangeFirst())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		uid, tok := identUser(t, a, alice)
		if err := em.Change(request(a, tok), identNext); err != nil {
			t.Fatal(err)
		}
		if n := len(e.mail.To(a, identNext)); n != 0 {
			t.Fatalf("the new address got %d mails before approval", n)
		}
		approve := identLink(t, e, a, alice, email.DefaultApprovePage)
		if err := em.ApproveChange(anon(a), "not-a-token"); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("bad approval token = %v", err)
		}
		if err := em.ApproveChange(anon(a), approve); err != nil {
			t.Fatal(err)
		}
		if _, err := em.ConfirmChange(anon(a), identLink(t, e, a, identNext, email.DefaultChangePage)); err != nil {
			t.Fatal(err)
		}
		if got := identPrimaryColumn(t, a, uid); got != identNext {
			t.Fatalf("primary after the approved change = %q", got)
		}
		if err := em.ApproveChange(anon(a), approve); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("approval token used twice = %v", err)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.ApproveChangeFirst())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		_, tok := identUser(t, a, "")
		if err := em.Add(request(a, tok), identBob); err != nil {
			t.Fatal(err)
		}
		if err := em.Change(request(a, tok), identWork); err != nil {
			t.Fatal(err)
		}
		// Nobody verified is there to ask: the confirm link goes straight out.
		identLink(t, e, a, identWork, email.DefaultChangePage)
	})
}

// TestIdentResendOnSignIn: SendVerification sends a fresh verify link or code
// only with ResendOnSignIn, and never for a verified identity, so the core's
// call after a refused sign-in mails and texts nobody by default.
func TestIdentResendOnSignIn(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, ph := e.emailPlugin(email.ResendOnSignIn()), e.phonePlugin(phone.ResendOnSignIn())
		a := e.newAuth(t, nil, em, e.passwordPlugin(), ph)
		uid, tok := identUser(t, a, alice)
		unverified := must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: uid, Kind: email.KindEmail, Raw: identWork}))
		before := len(e.mail.To(a, identWork))
		if err := em.SendVerification(context.Background(), unverified); err != nil {
			t.Fatal(err)
		}
		if n := len(e.mail.To(a, identWork)); n != before+1 {
			t.Fatalf("unverified address got %d new mails, want 1", n-before)
		}
		verified := must[auth.Identity](t)(a.FindIdentity(context.Background(), email.KindEmail, alice, true))
		before = len(e.mail.To(a, alice))
		if err := em.SendVerification(context.Background(), verified); err != nil || len(e.mail.To(a, alice)) != before {
			t.Fatalf("verified address: err %v, mails %d", err, len(e.mail.To(a, alice))-before)
		}
		if err := ph.Add(request(a, tok), identNumber); err != nil {
			t.Fatal(err)
		}
		number := must[auth.Identity](t)(a.FindIdentity(context.Background(), phone.KindPhone, identNumber, false))
		if err := ph.SendVerification(context.Background(), number); err != nil {
			t.Fatal(err)
		}
		if n := e.sms.Count(a, identNumber); n != 2 {
			t.Fatalf("texts after add + SendVerification = %d, want 2", n)
		}
		if err := ph.Verify(request(a, tok), identNumber, e.sms.LastCode(t, a, identNumber)); err != nil {
			t.Fatal(err)
		}
		number = must[auth.Identity](t)(a.FindIdentity(context.Background(), phone.KindPhone, identNumber, true))
		if err := ph.SendVerification(context.Background(), number); err != nil || e.sms.Count(a, identNumber) != 2 {
			t.Fatalf("verified number: err %v, texts %d", err, e.sms.Count(a, identNumber))
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin()
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		uid, _ := identUser(t, a, "")
		unverified := must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: uid, Kind: email.KindEmail, Raw: identBob}))
		before := len(e.mail.To(a, identBob))
		if err := em.SendVerification(context.Background(), unverified); err != nil || len(e.mail.To(a, identBob)) != before {
			t.Fatalf("without ResendOnSignIn: err %v, %d new mails", err, len(e.mail.To(a, identBob))-before)
		}
	})
}

// TestIdentNameOnCreate: the name given with a sign-in code or a magic link
// is the new account's name, and is ignored for an account that exists.
func TestIdentNameOnCreate(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, ml := e.emailPlugin(email.SignUpWithCode()), magiclink.New(magiclink.SignUp())
		a := e.newAuth(t, nil, em, ml)
		if err := em.SendCode(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		in, err := em.SignInCodeAs(anon(a), alice, lastMailCode(t, e, a, alice), "Alice")
		if err != nil || !in.Created || in.User.Name != "Alice" {
			t.Fatalf("code sign-up with a name = %+v %v", in, err)
		}
		if err := em.SendCode(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		if in, err := em.SignInCodeAs(anon(a), alice, lastMailCode(t, e, a, alice), "Mallory"); err != nil || in.Created || in.User.Name != "Alice" {
			t.Fatalf("code sign-in with a name for an existing user = %+v %v", in, err)
		}
		if err := ml.SendAs(anon(a), identBob, "Bob"); err != nil {
			t.Fatal(err)
		}
		res, err := ml.SignIn(anon(a), identLink(t, e, a, identBob, magiclink.DefaultPage))
		if err != nil || !res.Created || res.User.Name != "Bob" {
			t.Fatalf("link sign-up with a name = %+v %v", res, err)
		}
		if err := ml.SendAs(anon(a), identBob, "Mallory"); err != nil {
			t.Fatal(err)
		}
		if res, err := ml.SignIn(anon(a), identLink(t, e, a, identBob, magiclink.DefaultPage)); err != nil || res.Created || res.User.Name != "Bob" {
			t.Fatalf("link sign-in with a name for an existing user = %+v %v", res, err)
		}
	})
}

// TestIdentMagicLink_NameAndTenantInOneToken: a link sent in a tenant with a
// name keeps both, so the tenant check still applies.
func TestIdentMagicLink_NameAndTenantInOneToken(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ml := magiclink.New(magiclink.SignUp())
		a := e.newAuth(t, nil, e.emailPlugin(email.ScopedByTenant()), ml)
		if err := ml.SendAs(auth.WithScope(anon(a), "acme"), alice, "Alice"); err != nil {
			t.Fatal(err)
		}
		link := identLink(t, e, a, alice, magiclink.DefaultPage)
		if _, err := ml.SignIn(auth.WithScope(anon(a), "globex"), link); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("link clicked in another tenant = %v", err)
		}
		res, err := ml.SignIn(anon(a), link)
		if err != nil || res.User.Name != "Alice" {
			t.Fatalf("link in its tenant = %+v %v", res, err)
		}
	})
}

// TestIdentCodeLength: auth.WithCodeLength changes the digits of every code
// the identifier plugins send and accept.
func TestIdentCodeLength(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, ph := e.emailPlugin(email.SignUpWithCode()), e.phonePlugin(phone.Login(), phone.SignInWithCode())
		a := e.newAuth(t, []auth.Option{auth.WithCodeLength(8)}, em, ph)
		if err := em.SendCode(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		mails := e.mail.To(a, alice)
		code := regexp.MustCompile(`\b\d{8}\b`).FindString(mails[len(mails)-1].Text)
		if code == "" {
			t.Fatalf("no 8-digit code in %q", mails[len(mails)-1].Text)
		}
		if _, err := em.SignInCode(anon(a), alice, code); err != nil {
			t.Fatalf("8-digit email code: %v", err)
		}
		if err := ph.SendCode(anon(a), identNumber); err != nil {
			t.Fatal(err)
		}
		text := identLastText(t, e, a, identNumber)
		if code = regexp.MustCompile(`\b\d{8}\b`).FindString(text); code == "" {
			t.Fatalf("no 8-digit code in %q", text)
		}
		if _, err := ph.SignIn(anon(a), identNumber, code); err != nil {
			t.Fatalf("8-digit phone code: %v", err)
		}
	})
}

// TestIdentUsername_Claim: Claim applies the same rules as set — reserved,
// taken, immutable — and replaces an existing handle otherwise, from inside a
// larger operation rather than a route of its own.
func TestIdentUsername_Claim(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		un := username.New(username.Login())
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), un)
		uid, tok := identUser(t, a, alice)
		other, _ := identUser(t, a, identBob)
		ctx := context.Background()
		if err := un.Claim(ctx, uid, "Ada"); err != nil {
			t.Fatal(err)
		}
		if _, err := a.FindIdentity(ctx, username.KindUsername, "ada", false); err != nil {
			t.Fatalf("the claimed handle must exist: %v", err)
		}
		if err := un.Claim(ctx, other, "ada"); !errors.Is(err, auth.ErrIdentityTaken) {
			t.Fatalf("a taken handle = %v", err)
		}
		if err := un.Claim(ctx, other, "admin"); !errors.Is(err, username.ErrReserved) {
			t.Fatalf("a reserved handle = %v", err)
		}
		if err := un.Claim(ctx, other, "a b"); !errors.Is(err, auth.ErrIdentifierInvalid) {
			t.Fatalf("an invalid handle = %v", err)
		}
		if err := un.Claim(ctx, uid, "lovelace"); err != nil {
			t.Fatal(err)
		}
		var d username.Data
		if err := a.LoadUser(request(a, tok), uid, &handleView{d: &d}); err != nil {
			t.Fatal(err)
		}
		if d.Handle != "lovelace" {
			t.Fatalf("after a second Claim the handle = %q, want the replacement", d.Handle)
		}
	})
}

// TestIdentUsername_ClaimImmutable: a second Claim under Immutable is refused.
func TestIdentUsername_ClaimImmutable(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		un := username.New(username.Login(), username.Immutable())
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), un)
		uid, _ := identUser(t, a, alice)
		if err := un.Claim(context.Background(), uid, "ada"); err != nil {
			t.Fatal(err)
		}
		if err := un.Claim(context.Background(), uid, "lovelace"); !errors.Is(err, username.ErrImmutable) {
			t.Fatalf("Claim under Immutable = %v", err)
		}
	})
}

// handleView scans a user's handle through the plugin's join, for the Claim
// test.
type handleView struct{ d *username.Data }

func (h *handleView) Bindings() []sqlb.Binding { return username.UserBindings(h.d) }
func (h *handleView) Joins() []sqlb.Join       { return []sqlb.Join{username.UserJoin()} }
