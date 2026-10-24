package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

// mailHasLink reports whether the newest mail to addr carries a link.
func mailHasLink(t *testing.T, e *env, a *auth.Auth, addr string) bool {
	t.Helper()
	list := e.mail.To(a, addr)
	if len(list) == 0 {
		t.Fatalf("no mail to %s", addr)
	}
	return strings.Contains(list[len(list)-1].Text, testBaseURL)
}

// TestEmailVerifyByCode_VerifiesWithACode: under VerifyByCode the verify
// mail carries a code and no link; the code verifies the address once, a
// wrong code and an unknown address answer alike, and a resend mails a new
// code.
func TestEmailVerifyByCode_VerifiesWithACode(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(email.VerifyByCode(), email.RequireVerified()), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		up, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret})
		if err != nil || !up.VerificationRequired {
			t.Fatalf("sign-up = %+v %v", up, err)
		}
		if mailHasLink(t, e, a, alice) {
			t.Fatal("the verify mail must carry a code, not a link")
		}
		code := lastMailCode(t, e, a, alice)
		if _, err := em.VerifyCode(anon(a), alice, "000000"); !errors.Is(err, auth.ErrCodeInvalid) && code != "000000" {
			t.Fatalf("a wrong code = %v", err)
		}
		if _, err := em.VerifyCode(anon(a), "nobody@example.com", code); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("an unknown address = %v", err)
		}
		if _, err := em.VerifyCode(anon(a), "not an address", code); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("a malformed address = %v", err)
		}
		// A resend replaces the code.
		if err := em.Resend(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		fresh := lastMailCode(t, e, a, alice)
		if _, err := em.VerifyCode(anon(a), alice, code); fresh != code && !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("the replaced code = %v", err)
		}
		res, err := em.VerifyCode(anon(a), " ALICE@example.com ", fresh)
		if err != nil || res.Email != alice || res.SignedIn {
			t.Fatalf("verify-code = %+v %v", res, err)
		}
		if _, err := em.VerifyCode(anon(a), alice, fresh); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("a verified address = %v", err)
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatalf("sign-in after verifying by code: %v", err)
		}
	})
}

// TestEmailVerifyByCode_SignedInAndSignInOnVerify: a signed-in user verifies
// their own added address by code, and SignInOnVerify starts a session from
// the code as it does from the link.
func TestEmailVerifyByCode_SignedInAndSignInOnVerify(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.VerifyByCode(), email.Multiple(), email.SignInOnVerify())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		uid, tok := identUser(t, a, alice)
		if err := em.Add(request(a, tok), identWork); err != nil {
			t.Fatal(err)
		}
		code := lastMailCode(t, e, a, identWork)
		// Another user's session cannot spend it: the code is bound to the
		// owner's row, and a signed-in call looks among the caller's own.
		_, otherTok := identUser(t, a, identBob)
		if _, err := em.VerifyCode(request(a, otherTok), identWork, code); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("another user's session = %v", err)
		}
		res, err := em.VerifyCode(request(a, tok), identWork, code)
		if err != nil || res.Email != identWork || !res.SignedIn || res.Token == "" {
			t.Fatalf("verify-code signed in = %+v %v", res, err)
		}
		if _, err := a.FindIdentity(context.Background(), email.KindEmail, identWork, true); err != nil {
			t.Fatal(err)
		}
		if !identSignedIn(t, a, res.Token) {
			t.Fatal("SignInOnVerify must start a session from a code")
		}
		_ = uid
	})
}

// TestEmailVerifyByCode_ChangeByCode: a change mails a code to the new
// address; confirming by code replaces the address and still mails the undo
// link to the old one; the approval mail of ApproveChangeFirst stays a link.
func TestEmailVerifyByCode_ChangeByCode(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.VerifyByCode())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		uid, tok := identUser(t, a, alice)
		if err := em.Change(request(a, tok), identNext); err != nil {
			t.Fatal(err)
		}
		if mailHasLink(t, e, a, identNext) {
			t.Fatal("the confirm mail must carry a code")
		}
		code := lastMailCode(t, e, a, identNext)
		// The code is bound to the address it went to.
		if _, err := em.ConfirmChangeCode(request(a, tok), identWork, code); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("the code for another address = %v", err)
		}
		// And to the user who asked.
		_, otherTok := identUser(t, a, identBob)
		if _, err := em.ConfirmChangeCode(request(a, otherTok), identNext, code); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("another user's session = %v", err)
		}
		if _, err := em.ConfirmChangeCode(request(a, tok), "not an address", code); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("a malformed address = %v", err)
		}
		res, err := em.ConfirmChangeCode(request(a, tok), identNext, code)
		if err != nil || res.Email != identNext {
			t.Fatalf("confirm by code = %+v %v", res, err)
		}
		if got := identAddresses(t, em, a, tok); got != identNext+"[v][p]" {
			t.Fatalf("addresses = %q", got)
		}
		if identPrimaryColumn(t, a, uid) != identNext {
			t.Fatal("auth_user's primary copy must follow")
		}
		// The old owner still gets an undo link, and it still works.
		undo := identLink(t, e, a, alice, email.DefaultUndoPage)
		if err := em.UndoChange(anon(a), undo); err != nil {
			t.Fatal(err)
		}
	})
}

// TestEmailVerifyByCode_ChangeWithApprovalFirst: under VerifyByCode the
// approval mail to the current address carries a code and no link; the code
// is checked by the signed-in user for the address it was mailed for (a
// wrong code, another address, a check-code peek of the wrong kind and
// another user's session all answer alike and spend nothing); only then does
// the confirm code go to the new address. The approve-change link route
// stays registered for links sent before the switch.
func TestEmailVerifyByCode_ChangeWithApprovalFirst(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.VerifyByCode(), email.ApproveChangeFirst())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		_, tok := identUser(t, a, alice)
		_, other := identUser(t, a, identBob)
		if err := em.Change(request(a, tok), identNext); err != nil {
			t.Fatal(err)
		}
		if mailHasLink(t, e, a, alice) {
			t.Fatal("under VerifyByCode the approval mail must carry a code, not a link")
		}
		if len(e.mail.To(a, identNext)) != 0 {
			t.Fatal("nothing may reach the new address before the approval")
		}
		code := lastMailCode(t, e, a, alice)
		if err := em.ApproveChangeCode(request(a, tok), identNext, "000000"); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("a wrong approval code: %v", err)
		}
		if err := em.ApproveChangeCode(request(a, tok), "not an address", code); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("an address that is not one: %v", err)
		}
		if err := em.ApproveChangeCode(request(a, tok), identWork, code); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("the approval code for another address: %v", err)
		}
		if err := em.ApproveChangeCode(request(a, other), identNext, code); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("another user's session: %v", err)
		}
		if err := em.ApproveChangeCode(anon(a), identNext, code); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("signed out: %v", err)
		}
		// A peek of the right kind sees it; the change kind does not, since
		// the two purposes are distinct.
		if err := em.CheckCode(request(a, tok), email.CodeKindApprove, identNext, code); err != nil {
			t.Fatalf("peek at the approval code: %v", err)
		}
		if err := em.CheckCode(request(a, tok), email.CodeKindChange, identNext, code); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("an approval code is not a change code: %v", err)
		}
		if err := em.CheckCode(anon(a), email.CodeKindApprove, identNext, code); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("a signed-out peek at an approval code: %v", err)
		}
		if len(e.mail.To(a, identNext)) != 0 {
			t.Fatal("refused approvals must send nothing")
		}
		if err := em.ApproveChangeCode(request(a, tok), identNext, code); err != nil {
			t.Fatal(err)
		}
		if err := em.ApproveChangeCode(request(a, tok), identNext, code); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("an approval code used twice: %v", err)
		}
		if mailHasLink(t, e, a, identNext) {
			t.Fatal("after approval the confirm mail must carry a code")
		}
		if _, err := em.ConfirmChangeCode(request(a, tok), identNext, lastMailCode(t, e, a, identNext)); err != nil {
			t.Fatal(err)
		}
		if _, ok := a.Operation(email.EndpointApproveChange); !ok {
			t.Fatal("the approve-change link route must stay registered")
		}
	})
}

// TestEmailVerifyByCode_RoutesOnlyWhenOn: the code routes exist only under
// VerifyByCode; the link routes always do.
func TestEmailVerifyByCode_RoutesOnlyWhenOn(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin())
		for _, id := range []auth.EndpointID{email.EndpointVerifyCode, email.EndpointConfirmCode} {
			if _, ok := a.Operation(id); ok {
				t.Fatalf("%s registered without VerifyByCode", id)
			}
		}
		b := e.newAuth(t, nil, e.emailPlugin(email.VerifyByCode()), e.passwordPlugin())
		for _, id := range []auth.EndpointID{email.EndpointVerifyCode, email.EndpointConfirmCode, email.EndpointVerify, email.EndpointConfirmChange} {
			if _, ok := b.Operation(id); !ok {
				t.Fatalf("%s missing under VerifyByCode", id)
			}
		}
		// approve-change-code needs both switches: without ApproveChangeFirst
		// there is no approval, without VerifyByCode it is a link.
		if _, ok := b.Operation(email.EndpointApproveCode); ok {
			t.Fatal("approve-change-code registered without ApproveChangeFirst")
		}
		c := e.newAuth(t, nil, e.emailPlugin(email.ApproveChangeFirst()), e.passwordPlugin())
		if _, ok := c.Operation(email.EndpointApproveCode); ok {
			t.Fatal("approve-change-code registered without VerifyByCode")
		}
	})
}

// TestIdentFaults_EmailVerifyByCode: the code paths surface every database
// failure.
func TestIdentFaults_EmailVerifyByCode(t *testing.T) {
	identRun(t, []identSweep{
		{"verify by code, signed out", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.VerifyByCode())
			uid, _ := identUser(t, a, "")
			must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: uid, Kind: email.KindEmail, Raw: alice}))
			code := lastMailCode(t, e.env, a, alice)
			return func(context.Context) error { _, err := em.VerifyCode(anon(a), alice, code); return err }
		}},
		{"verify by code, signed in with sign-in on verify", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.VerifyByCode(), email.Multiple(), email.SignInOnVerify())
			_, tok := identUser(t, a, alice)
			identWithWork(t, e, a, em, tok, false)
			code := lastMailCode(t, e.env, a, identWork)
			return func(context.Context) error { _, err := em.VerifyCode(request(a, tok), identWork, code); return err }
		}},
		{"resend by code", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.VerifyByCode())
			uid, _ := identUser(t, a, "")
			must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: uid, Kind: email.KindEmail, Raw: alice}))
			return func(context.Context) error { return em.Resend(anon(a), alice) }
		}},
		{"change by code", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.VerifyByCode())
			_, tok := identUser(t, a, alice)
			return func(context.Context) error { return em.Change(request(a, tok), identNext) }
		}},
		{"set for, verified replace", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e)
			uid, _ := identUser(t, a, alice)
			return func(ctx context.Context) error { return em.SetFor(ctx, uid, identWork, true) }
		}},
		{"set for, verify an own address", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.Multiple())
			uid, tok := identUser(t, a, alice)
			identWithWork(t, e, a, em, tok, false)
			return func(ctx context.Context) error { return em.SetFor(ctx, uid, identWork, true) }
		}},
		{"change by code with approval first", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.VerifyByCode(), email.ApproveChangeFirst())
			_, tok := identUser(t, a, alice)
			return func(context.Context) error { return em.Change(request(a, tok), identNext) }
		}},
		{"approve a change by code", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.VerifyByCode(), email.ApproveChangeFirst())
			_, tok := identUser(t, a, alice)
			if err := em.Change(request(a, tok), identNext); err != nil {
				t.Fatal(err)
			}
			code := lastMailCode(t, e.env, a, alice)
			return func(context.Context) error { return em.ApproveChangeCode(request(a, tok), identNext, code) }
		}},
		{"check an approval code", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.VerifyByCode(), email.ApproveChangeFirst())
			_, tok := identUser(t, a, alice)
			if err := em.Change(request(a, tok), identNext); err != nil {
				t.Fatal(err)
			}
			code := lastMailCode(t, e.env, a, alice)
			return func(context.Context) error {
				return em.CheckCode(request(a, tok), email.CodeKindApprove, identNext, code)
			}
		}},
		{"check a sign-in code", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.SignInWithCode())
			identUser(t, a, alice)
			if err := em.SendCode(anon(a), alice); err != nil {
				t.Fatal(err)
			}
			code := lastMailCode(t, e.env, a, alice)
			return func(context.Context) error { return em.CheckCode(anon(a), email.CodeKindSignIn, alice, code) }
		}},
		{"check a verify code", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.VerifyByCode())
			uid, _ := identUser(t, a, "")
			must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: uid, Kind: email.KindEmail, Raw: alice}))
			code := lastMailCode(t, e.env, a, alice)
			return func(context.Context) error { return em.CheckCode(anon(a), email.CodeKindVerify, alice, code) }
		}},
		{"confirm change by code", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.VerifyByCode())
			_, tok := identUser(t, a, alice)
			if err := em.Change(request(a, tok), identNext); err != nil {
				t.Fatal(err)
			}
			code := lastMailCode(t, e.env, a, identNext)
			return func(context.Context) error {
				_, err := em.ConfirmChangeCode(request(a, tok), identNext, code)
				return err
			}
		}},
	})
}

// TestEmail_SetFor: the server-side set of a user's address under the
// plugin's rules: replace (or add, with Multiple), verified or not, refuse a
// taken address, verify an own one in place, unknown user.
func TestEmail_SetFor(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin()
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		ctx := context.Background()
		uid, tok := identUser(t, a, alice)
		other, _ := identUser(t, a, identBob)
		if err := em.SetFor(ctx, "usr_nobody", identWork, true); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("unknown user = %v", err)
		}
		if err := em.SetFor(ctx, uid, "not an address", true); !errors.Is(err, auth.ErrIdentifierInvalid) {
			t.Fatalf("malformed = %v", err)
		}
		if err := em.SetFor(ctx, uid, identBob, true); !errors.Is(err, auth.ErrIdentityTaken) {
			t.Fatalf("another user's verified address = %v", err)
		}
		// Replace, unverified: the verify link goes out, the old address is
		// gone, the primary copy on auth_user is cleared.
		if err := em.SetFor(ctx, uid, identWork, false); err != nil {
			t.Fatal(err)
		}
		if got := identAddresses(t, em, a, tok); got != identWork {
			t.Fatalf("after an unverified replace = %q", got)
		}
		if identPrimaryColumn(t, a, uid) != "" {
			t.Fatal("the primary copy must clear with the old address")
		}
		e.mail.LastToken(t, a, identWork) // a verify link was mailed
		// Verified=false for an address the user holds is a no-op; true
		// verifies it in place.
		if err := em.SetFor(ctx, uid, identWork, false); err != nil {
			t.Fatal(err)
		}
		if err := em.SetFor(ctx, uid, " WORK@example.com ", true); err != nil {
			t.Fatal(err)
		}
		if got := identAddresses(t, em, a, tok); got != identWork+"[v][p]" || identPrimaryColumn(t, a, uid) != identWork {
			t.Fatalf("after verifying in place = %q", got)
		}
		// Replace, verified: primary at once.
		if err := em.SetFor(ctx, uid, identNext, true); err != nil {
			t.Fatal(err)
		}
		if got := identAddresses(t, em, a, tok); got != identNext+"[v][p]" || identPrimaryColumn(t, a, uid) != identNext {
			t.Fatalf("after a verified replace = %q", got)
		}
		_ = other
	})
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.Multiple())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		uid, tok := identUser(t, a, alice)
		if err := em.SetFor(context.Background(), uid, identWork, true); err != nil {
			t.Fatal(err)
		}
		if got := identAddresses(t, em, a, tok); got != alice+"[v] "+identWork+"[v][p]" {
			t.Fatalf("with Multiple the address is added and primary = %q", got)
		}
		if err := email.New(email.WithMailer(e.mail)).SetFor(context.Background(), uid, identWork, true); !errors.Is(err, auth.ErrOperationNotWired) {
			t.Fatal("unwired SetFor must say so")
		}
	})
}

// TestEmail_CheckCode: a peek says whether a code is right without spending
// it, for all three kinds; a wrong peek counts an attempt; a kind whose
// feature is off, an unknown address and a change code signed out answer
// alike.
func TestEmail_CheckCode(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.VerifyByCode(), email.SignInWithCode(), email.Multiple(), email.WithMaxAttempts(2))
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		ctx := context.Background()
		uid, tok := identUser(t, a, alice)
		if err := em.CheckCode(anon(a), email.CodeKind("bogus"), alice, "000000"); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("an unknown kind = %v", err)
		}
		if err := em.CheckCode(anon(a), email.CodeKindVerify, "not an address", "000000"); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("a malformed address = %v", err)
		}
		if err := em.CheckCode(anon(a), email.CodeKindVerify, "nobody@example.com", "000000"); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("a verify peek for an unknown address = %v", err)
		}
		// Sign-in code: peek, peek, then the real sign-in still works.
		if err := em.SendCode(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		code := lastMailCode(t, e, a, alice)
		if err := em.CheckCode(anon(a), email.CodeKindSignIn, alice, code); err != nil {
			t.Fatalf("peek at the right code = %v", err)
		}
		if err := em.CheckCode(anon(a), email.CodeKindSignIn, alice, code); err != nil {
			t.Fatalf("a peek must not spend the code: %v", err)
		}
		if _, err := em.SignInCode(anon(a), alice, code); err != nil {
			t.Fatalf("sign-in after peeking = %v", err)
		}
		// Wrong peeks count attempts: two of them exhaust a code with
		// WithMaxAttempts(2), and the right code is then refused.
		if err := em.SendCode(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		code = lastMailCode(t, e, a, alice)
		wrong := "000000"
		if wrong == code {
			wrong = "000001"
		}
		for range 2 {
			if err := em.CheckCode(anon(a), email.CodeKindSignIn, alice, wrong); !errors.Is(err, auth.ErrCodeInvalid) {
				t.Fatalf("a wrong peek = %v", err)
			}
		}
		if _, err := em.SignInCode(anon(a), alice, code); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("after two wrong peeks the code must be spent: %v", err)
		}
		// Verify code for an added address, signed in; signed out too.
		if err := em.Add(request(a, tok), identWork); err != nil {
			t.Fatal(err)
		}
		vcode := lastMailCode(t, e, a, identWork)
		if err := em.CheckCode(request(a, tok), email.CodeKindVerify, identWork, vcode); err != nil {
			t.Fatalf("peek at a verify code signed in = %v", err)
		}
		if err := em.CheckCode(anon(a), email.CodeKindVerify, identWork, vcode); err != nil {
			t.Fatalf("peek at a verify code signed out = %v", err)
		}
		if _, err := em.VerifyCode(request(a, tok), identWork, vcode); err != nil {
			t.Fatal(err)
		}
		if err := em.CheckCode(anon(a), email.CodeKindVerify, identWork, vcode); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("peek at a verified address = %v", err)
		}
		// Change code: bound to the signed-in user; signed out it is unknown.
		if err := em.Change(request(a, tok), identNext); err != nil {
			t.Fatal(err)
		}
		ccode := lastMailCode(t, e, a, identNext)
		if err := em.CheckCode(anon(a), email.CodeKindChange, identNext, ccode); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("a change peek signed out = %v", err)
		}
		if err := em.CheckCode(request(a, tok), email.CodeKindChange, identNext, ccode); err != nil {
			t.Fatalf("a change peek = %v", err)
		}
		_ = uid
		_ = ctx
	})
	eachEngine(t, func(t *testing.T, e *env) {
		// Without VerifyByCode or SignInWithCode the route does not exist;
		// with only SignInWithCode a verify peek is refused.
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin())
		if _, ok := a.Operation(email.EndpointCheckCode); ok {
			t.Fatal("check-code registered without codes")
		}
		em := e.emailPlugin(email.SignInWithCode())
		b := e.newAuth(t, nil, em, e.passwordPlugin())
		identUser(t, b, alice)
		if err := em.CheckCode(anon(b), email.CodeKindVerify, alice, "000000"); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("verify peek without VerifyByCode = %v", err)
		}
		if err := em.CheckCode(anon(b), email.CodeKindChange, alice, "000000"); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("change peek without VerifyByCode = %v", err)
		}
		// And the reverse: only VerifyByCode, so a sign-in peek is refused.
		vm := e.emailPlugin(email.VerifyByCode())
		c := e.newAuth(t, nil, vm, e.passwordPlugin())
		identUser(t, c, identBob) // alice already exists on this database
		if err := vm.CheckCode(anon(c), email.CodeKindSignIn, identBob, "000000"); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("sign-in peek without SignInWithCode = %v", err)
		}
	})
}
