package integration

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/emailchallenge"
	"github.com/ubgo/auth/plugin/invite"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/referral"
	"github.com/ubgo/sqlb"
)

// p3Req is a browser request with a session token, request headers and
// plugin cookies, for the hooks that read what a sign-up brought.
func p3Req(a *auth.Auth, tok auth.Token, ip string, headers, cookies map[string]string) context.Context {
	req := auth.Request{
		Transport: auth.TransportHTTP,
		Client:    auth.Client{IP: ip, UserAgent: "p3-browser", Origin: testBaseURL},
		Header:    func(n string) string { return headers[n] },
		Cookie: func(n string) (string, bool) {
			v, ok := cookies[n]
			return v, ok
		},
	}
	if tok != "" {
		req.Credential, req.Token = auth.CredentialCookie, tok
	}
	return a.WithRequest(context.Background(), req)
}

// p3SignUp signs up identifier with password, carrying headers and cookies.
func p3SignUp(a *auth.Auth, pw *password.Plugin, identifier, name string, headers, cookies map[string]string) (password.SignInResult, error) {
	return pw.SignUp(p3Req(a, "", "203.0.113.20", headers, cookies), password.SignUpRequest{Identifier: identifier, Password: secret, Name: name})
}

// p3SessionFor signs userID in directly and returns a request carrying the
// session.
func p3SessionFor(t *testing.T, a *auth.Auth, userID string) context.Context {
	t.Helper()
	_, tok, err := a.CreateSession(context.Background(), userID, auth.Client{IP: "203.0.113.9"})
	if err != nil {
		t.Fatal(err)
	}
	return request(a, tok)
}

// p3UserID returns the id of the account that owns addr.
func p3UserID(t *testing.T, a *auth.Auth, addr string) string {
	t.Helper()
	id, err := a.FindIdentity(context.Background(), "email", addr, false)
	if err != nil {
		t.Fatalf("no account for %s: %v", addr, err)
	}
	return id.UserID
}

var p3OTPInText = regexp.MustCompile(`page that asked: (\d+)`)

// p3OTP returns the code in the newest challenge mail to addr.
func p3OTP(t *testing.T, e *env, a *auth.Auth, addr string) string {
	t.Helper()
	list := e.mail.To(a, addr)
	for i := len(list) - 1; i >= 0; i-- {
		if m := p3OTPInText.FindStringSubmatch(list[i].Text); m != nil {
			return m[1]
		}
	}
	t.Fatalf("no challenge code sent to %s: %+v", addr, list)
	return ""
}

// TestP3CommunityEmailChallenge_CrossDevice walks better-auth-email-challenge's
// default flow: the link opened on another device shows the request and
// approves only on a POST, and only the asking browser's poll signs in, once.
// ds:def id=testp3communityemailchallenge-crossdevice-m4avx27a owner=@khanakia stability=stable
func TestP3CommunityEmailChallenge_CrossDevice(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, ec := e.emailPlugin(), e.passwordPlugin(), emailchallenge.New()
		a := e.newAuth(t, nil, em, pw, ec)
		owner := signUpVerified(t, e, a, pw, em)

		asking := p3Req(a, "", "198.51.100.1", nil, nil)
		st := must[emailchallenge.Result](t)(ec.Start(asking, " ALICE@example.com ", ""))
		if st.PollToken == "" || st.ExpiresAt == nil || st.State != emailchallenge.StatePending {
			t.Fatalf("start = %+v", st)
		}
		if p, _ := ec.Poll(anon(a), st.PollToken.Token()); p.State != emailchallenge.StatePending {
			t.Fatalf("poll before approval = %+v", p)
		}
		approval := e.mail.LastToken(t, a, alice)

		// The phone opens the link: context shows the request and changes
		// nothing, so a scanner that fetches it approves nothing.
		phone := p3Req(a, "", "198.51.100.2", nil, nil)
		cx := must[emailchallenge.ContextResult](t)(ec.Context(phone, approval))
		if cx.State != emailchallenge.StateNeedsConfirmation || cx.Identifier != alice || cx.IP != "198.51.100.1" || cx.UserAgent != "p3-browser" {
			t.Fatalf("context on another device = %+v", cx)
		}
		if p, _ := ec.Poll(anon(a), st.PollToken.Token()); p.State != emailchallenge.StatePending {
			t.Fatalf("a GET approved: %+v", p)
		}
		ap := must[emailchallenge.Result](t)(ec.Approve(phone, approval))
		if ap.State != emailchallenge.StateApproved || ap.Token != "" || ap.User != nil {
			t.Fatalf("approve must sign nobody in: %+v", ap)
		}
		// A second click is a success too.
		must[emailchallenge.Result](t)(ec.Approve(phone, approval))
		if p, _ := ec.Poll(anon(a), "not-the-poll-token"); p.State != emailchallenge.StateExpired {
			t.Fatalf("a stranger's poll = %+v", p)
		}

		done := must[emailchallenge.Result](t)(ec.Poll(anon(a), st.PollToken.Token()))
		if done.State != emailchallenge.StateCompleted || done.Token == "" || done.User == nil || done.User.ID != owner.User.ID || done.Created {
			t.Fatalf("completed poll = %+v", done)
		}
		if again, _ := ec.Poll(anon(a), st.PollToken.Token()); again.State != emailchallenge.StateExpired {
			t.Fatalf("a spent challenge polled = %+v", again)
		}
		if _, err := ec.Approve(phone, approval); !errors.Is(err, emailchallenge.ErrInvalid) {
			t.Fatalf("approving a spent challenge: %v", err)
		}
	})
}

// TestP3CommunityEmailChallenge_SameBrowserAndOTP: the asking browser's own
// click approves through context; the code completes a challenge from the
// asking browser and survives only WithMaxAttempts wrong guesses.
func TestP3CommunityEmailChallenge_SameBrowserAndOTP(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, ec := e.emailPlugin(), e.passwordPlugin(), emailchallenge.New()
		a := e.newAuth(t, nil, em, pw, ec)
		owner := signUpVerified(t, e, a, pw, em)

		st := must[emailchallenge.Result](t)(ec.Start(anon(a), alice, ""))
		same := p3Req(a, "", "198.51.100.1", nil, map[string]string{emailchallenge.CookieName: st.PollToken.Reveal()})
		cx := must[emailchallenge.ContextResult](t)(ec.Context(same, e.mail.LastToken(t, a, alice)))
		if cx.State != emailchallenge.StateApproved {
			t.Fatalf("the asking browser's click = %+v", cx)
		}
		// The cookie is the poll token, so the browser polls with no body.
		if p := must[emailchallenge.Result](t)(ec.Poll(same, "")); p.State != emailchallenge.StateCompleted {
			t.Fatalf("cookie poll = %+v", p)
		}

		st = must[emailchallenge.Result](t)(ec.Start(anon(a), alice, ""))
		code := p3OTP(t, e, a, alice)
		wrong := "000000"
		if code == wrong {
			wrong = "111111"
		}
		for range emailchallenge.DefaultMaxAttempts {
			if _, err := ec.VerifyOTP(anon(a), st.PollToken.Token(), wrong); !errors.Is(err, auth.ErrCodeInvalid) {
				t.Fatalf("wrong code: %v", err)
			}
		}
		if _, err := ec.VerifyOTP(anon(a), st.PollToken.Token(), code); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("the right code after the attempts ran out: %v", err)
		}

		st = must[emailchallenge.Result](t)(ec.Start(anon(a), alice, ""))
		code = p3OTP(t, e, a, alice)
		if _, err := ec.VerifyOTP(anon(a), "", code); !errors.Is(err, emailchallenge.ErrInvalid) {
			t.Fatalf("a code without the poll token: %v", err)
		}
		in := must[emailchallenge.Result](t)(ec.VerifyOTP(anon(a), st.PollToken.Token(), code))
		if in.State != emailchallenge.StateCompleted || in.User.ID != owner.User.ID || in.Token == "" {
			t.Fatalf("code sign-in = %+v", in)
		}
	})
}

// TestP3CommunityEmailChallenge_UnknownAndExpiry: a challenge to an unknown
// address answers and polls like any other and is never delivered; with
// SignUp it creates the account; an expired challenge is gone everywhere.
func TestP3CommunityEmailChallenge_UnknownAndExpiry(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, ec := e.emailPlugin(), emailchallenge.New()
		a := e.newAuth(t, nil, em, ec)
		st := must[emailchallenge.Result](t)(ec.Start(anon(a), "nobody@example.com", ""))
		if st.PollToken == "" {
			t.Fatal("an unknown address must get the same answer")
		}
		if n := len(e.mail.To(a, "nobody@example.com")); n != 0 {
			t.Fatalf("%d mails to an unknown address", n)
		}
		if p, _ := ec.Poll(anon(a), st.PollToken.Token()); p.State != emailchallenge.StatePending {
			t.Fatalf("unknown address poll = %+v", p)
		}
		if _, err := ec.Start(anon(a), "not an address", ""); !errors.Is(err, auth.ErrIdentifierInvalid) {
			t.Fatalf("malformed identifier: %v", err)
		}
		e.clock.Advance(emailchallenge.DefaultTTL + time.Second)
		if p, _ := ec.Poll(anon(a), st.PollToken.Token()); p.State != emailchallenge.StateExpired {
			t.Fatalf("expired poll = %+v", p)
		}

		em2, ec2 := e.emailPlugin(), emailchallenge.New(emailchallenge.SignUp())
		a2 := e.newAuth(t, nil, em2, ec2)
		st = must[emailchallenge.Result](t)(ec2.Start(anon(a2), "new@example.com", "Newt"))
		tok := e.mail.LastToken(t, a2, "new@example.com")
		e.clock.Advance(emailchallenge.DefaultTTL + time.Second)
		if cx, _ := ec2.Context(anon(a2), tok); cx.State != emailchallenge.StateInvalid || cx.Identifier != "" {
			t.Fatalf("context of an expired challenge = %+v", cx)
		}
		if _, err := ec2.Approve(anon(a2), tok); !errors.Is(err, emailchallenge.ErrInvalid) {
			t.Fatalf("approve an expired challenge: %v", err)
		}
		st = must[emailchallenge.Result](t)(ec2.Start(anon(a2), "new@example.com", "Newt"))
		must[emailchallenge.Result](t)(ec2.Approve(anon(a2), e.mail.LastToken(t, a2, "new@example.com")))
		in := must[emailchallenge.Result](t)(ec2.Poll(anon(a2), st.PollToken.Token()))
		if !in.Created || in.User.Name != "Newt" {
			t.Fatalf("sign-up by challenge = %+v", in)
		}
		if _, err := a2.FindIdentity(anon(a2), "email", "new@example.com", true); err != nil {
			t.Fatalf("the address must be verified: %v", err)
		}
		n, err := ec2.Sweep(context.Background(), e.clock.Now().Add(time.Hour))
		if err != nil || n != 1 {
			t.Fatalf("sweep: the expired challenge, not the completed one = %d %v", n, err)
		}
	})
}

// TestP3CommunityEmailChallenge_SameDeviceMode refuses every click from
// another browser.
func TestP3CommunityEmailChallenge_SameDeviceMode(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, ec := e.emailPlugin(), e.passwordPlugin(), emailchallenge.New(emailchallenge.WithLinkMode(emailchallenge.SameDevice))
		a := e.newAuth(t, nil, em, pw, ec)
		signUpVerified(t, e, a, pw, em)
		st := must[emailchallenge.Result](t)(ec.Start(anon(a), alice, ""))
		tok := e.mail.LastToken(t, a, alice)
		if cx := must[emailchallenge.ContextResult](t)(ec.Context(anon(a), tok)); cx.State != emailchallenge.StateWrongBrowser {
			t.Fatalf("other browser context = %+v", cx)
		}
		if _, err := ec.Approve(anon(a), tok); !errors.Is(err, emailchallenge.ErrWrongBrowser) {
			t.Fatalf("other browser approve: %v", err)
		}
		same := p3Req(a, "", "198.51.100.1", nil, map[string]string{emailchallenge.CookieName: st.PollToken.Reveal()})
		must[emailchallenge.Result](t)(ec.Approve(same, tok))
		if p := must[emailchallenge.Result](t)(ec.Poll(same, "")); p.State != emailchallenge.StateCompleted {
			t.Fatalf("poll = %+v", p)
		}
	})
}

// p3Inviter creates a user from Go (never refused by Required) and signs
// them in.
func p3Inviter(t *testing.T, a *auth.Auth, name string) (auth.User, context.Context) {
	t.Helper()
	u, err := a.CreateUser(context.Background(), auth.NewUser{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	return u, p3SessionFor(t, a, u.ID)
}

// p3Count counts the rows of a library table matching where.
func p3Count(t *testing.T, a *auth.Auth, table sqlb.Table, where ...sqlb.Predicate) int64 {
	t.Helper()
	var n int64
	if err := a.One(context.Background(), a.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(table).Where(where...)); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestP3CommunityInvite_RequiredPublicInvite: with Required, a client
// sign-up needs a valid invite; a public invite is spent per use, its uses
// recorded, and it closes when they run out.
func TestP3CommunityInvite_RequiredPublicInvite(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, iv := e.emailPlugin(), e.passwordPlugin(), invite.New(invite.Required())
		a := e.newAuth(t, nil, em, pw, iv)
		inviter, ctx := p3Inviter(t, a, "Ines")

		if _, err := p3SignUp(a, pw, "nobody@example.com", "", nil, nil); !errors.Is(err, invite.ErrRequired) {
			t.Fatalf("sign-up without an invite: %v", err)
		}
		if _, err := a.FindIdentity(context.Background(), "email", "nobody@example.com", false); !errors.Is(err, auth.ErrIdentityNotFound) {
			t.Fatalf("a refused sign-up left an account: %v", err)
		}
		cr := must[invite.Created](t)(iv.Create(ctx, invite.Request{MaxUses: 2}))
		if cr.Token == "" || cr.URL == "" {
			t.Fatalf("public invite = %+v", cr)
		}
		v := must[invite.View](t)(iv.Get(anon(a), cr.Token.Token()))
		if v.InviterName != "Ines" || v.Private || v.Status != invite.StatusPending {
			t.Fatalf("view = %+v", v)
		}
		hdr := map[string]string{invite.InviteHeader: cr.Token.Reveal()}
		if _, err := p3SignUp(a, pw, "u1@example.com", "", hdr, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := p3SignUp(a, pw, "u2@example.com", "", hdr, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := p3SignUp(a, pw, "u3@example.com", "", hdr, nil); !errors.Is(err, invite.ErrInvalid) {
			t.Fatalf("a third use of a two-use invite: %v", err)
		}
		if _, err := iv.Get(anon(a), cr.Token.Token()); !errors.Is(err, invite.ErrInvalid) {
			t.Fatalf("get of a used-up invite: %v", err)
		}
		l := must[invite.ListResult](t)(iv.List(ctx, invite.ListRequest{}))
		if l.Total != 1 || l.Invites[0].Uses != 2 || l.Invites[0].Status != invite.StatusUsed {
			t.Fatalf("list = %+v", l)
		}
		if n := p3Count(t, a, invite.TableUse, sqlb.Eq(invite.UseInviteID, cr.ID)); n != 2 {
			t.Fatalf("%d use rows", n)
		}
		// A user the app creates from Go is not refused.
		if _, err := a.CreateUser(context.Background(), auth.NewUser{Name: "Imported"}); err != nil {
			t.Fatalf("Go-created user refused: %v", err)
		}
		if err := a.DeleteUser(context.Background(), inviter.ID); err != nil {
			t.Fatal(err)
		}
		if n := p3Count(t, a, invite.TableInvite, sqlb.Eq(invite.InviteCreatedBy, inviter.ID)); n != 0 {
			t.Fatalf("%d invites outlived their creator", n)
		}
	})
}

// TestP3CommunityInvite_PrivateRoleCookie: a private invite is mailed, its
// token never answered, and it is single use; a role needs CanCreate and reaches OnAccepted;
// a signed-out visitor's activate keeps the invite in the cookie the sign-up
// reads, and a signed-in user's activate uses it at once.
// ds:def id=testp3communityinvite-privaterolecookie-gfqv25w5 owner=@khanakia stability=stable
func TestP3CommunityInvite_PrivateRoleCookie(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		var got []invite.Accepted
		iv := invite.New(
			invite.CanCreate(func(_ context.Context, u auth.User, in invite.Request) error {
				if in.Role == "admin" && u.Name != "Root" {
					return invite.ErrForbidden
				}
				return nil
			}),
			invite.OnAccepted(func(_ context.Context, acc invite.Accepted) error {
				got = append(got, acc)
				return nil
			}),
		)
		a := e.newAuth(t, nil, em, pw, iv)
		_, ines := p3Inviter(t, a, "Ines")
		root, rootCtx := p3Inviter(t, a, "Root")

		if _, err := iv.Create(ines, invite.Request{Role: "admin"}); !errors.Is(err, invite.ErrForbidden) {
			t.Fatalf("an admin invite by a non-root: %v", err)
		}
		cr := must[invite.Created](t)(iv.Create(rootCtx, invite.Request{Email: "Bob@Example.com", Role: "admin", MaxUses: 9}))
		if cr.Token != "" || cr.URL != "" {
			t.Fatalf("a private invite's token must go by mail only: %+v", cr)
		}
		tok := e.mail.LastToken(t, a, "bob@example.com")
		act := must[invite.ActivateResult](t)(iv.Activate(anon(a), tok))
		if act.Action != invite.ActionSignInRequired {
			t.Fatalf("signed-out activate = %+v", act)
		}
		if _, err := p3SignUp(a, pw, "bob@example.com", "Bob", nil, map[string]string{invite.CookieName: tok.Reveal()}); err != nil {
			t.Fatal(err)
		}
		bob := p3UserID(t, a, "bob@example.com")
		if len(got) != 1 || got[0].UserID != bob || got[0].Role != "admin" || got[0].CreatedBy != root.ID || !got[0].NewAccount {
			t.Fatalf("accepted = %+v", got)
		}
		if l := must[invite.ListResult](t)(iv.List(rootCtx, invite.ListRequest{})); l.Invites[0].MaxUses != 1 || l.Invites[0].Email != "bob@example.com" {
			t.Fatalf("a private invite is single-use: %+v", l)
		}

		pub := must[invite.Created](t)(iv.Create(ines, invite.Request{}))
		carolCtx := p3SessionFor(t, a, root.ID)
		act = must[invite.ActivateResult](t)(iv.Activate(carolCtx, pub.Token.Token()))
		if act.Action != invite.ActionAccepted || len(got) != 2 || got[1].NewAccount {
			t.Fatalf("signed-in activate = %+v %+v", act, got)
		}
		if _, err := iv.Activate(carolCtx, pub.Token.Token()); !errors.Is(err, invite.ErrInvalid) {
			t.Fatalf("one user used one invite twice: %v", err)
		}
	})
}

// TestP3CommunityInvite_CancelRejectExpire: only the creator cancels, only
// the addressee rejects, and an expired invite is invalid everywhere.
func TestP3CommunityInvite_CancelRejectExpire(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, iv := e.emailPlugin(), e.passwordPlugin(), invite.New()
		a := e.newAuth(t, nil, em, pw, iv)
		_, ines := p3Inviter(t, a, "Ines")
		_, other := p3Inviter(t, a, "Otto")

		pub := must[invite.Created](t)(iv.Create(ines, invite.Request{}))
		if err := iv.Cancel(other, pub.ID); !errors.Is(err, invite.ErrInvalid) {
			t.Fatalf("a stranger canceled: %v", err)
		}
		if err := iv.Cancel(ines, pub.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := iv.Get(anon(a), pub.Token.Token()); !errors.Is(err, invite.ErrInvalid) {
			t.Fatalf("a canceled invite: %v", err)
		}

		e.clock.Advance(time.Second) // newest first: the private invite heads the list
		must[invite.Created](t)(iv.Create(ines, invite.Request{Email: alice}))
		tok := e.mail.LastToken(t, a, alice)
		if err := iv.Reject(other, tok); !errors.Is(err, invite.ErrInvalid) {
			t.Fatalf("a stranger rejected: %v", err)
		}
		owner := signUpVerified(t, e, a, pw, em)
		if err := iv.Reject(p3SessionFor(t, a, owner.User.ID), tok); err != nil {
			t.Fatalf("the addressee's reject: %v", err)
		}
		if l := must[invite.ListResult](t)(iv.List(ines, invite.ListRequest{Limit: 1})); l.Total != 2 || len(l.Invites) != 1 || l.Invites[0].Status != invite.StatusRejected {
			t.Fatalf("list page = %+v", l)
		}

		short := must[invite.Created](t)(iv.Create(ines, invite.Request{ExpiresIn: 60}))
		e.clock.Advance(61 * time.Second)
		if _, err := iv.Activate(anon(a), short.Token.Token()); !errors.Is(err, invite.ErrInvalid) {
			t.Fatalf("an expired invite: %v", err)
		}
		if _, err := iv.Create(ines, invite.Request{ExpiresIn: int64(invite.MaxTTL/time.Second) + 1}); !errors.Is(err, auth.ErrBadRequest) {
			t.Fatalf("an invite past MaxTTL: %v", err)
		}
	})
}

// TestP3CommunityReferral walks a referral from the code to completion: the
// header and the remembered cookie record it, a code naming nobody refuses
// the sign-up, steps from Go complete it once, and the referrer's list masks
// addresses.
// ds:def id=testp3communityreferral-ht6p5vdu owner=@khanakia stability=stable
func TestP3CommunityReferral(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var completed, signedUp atomic.Int32
		em, pw := e.emailPlugin(), e.passwordPlugin()
		rf := referral.New(referral.Steps("first_purchase"),
			referral.AfterSignUp(func(context.Context, referral.Event) { signedUp.Add(1) }),
			referral.AfterCompleted(func(_ context.Context, ev referral.Event) {
				if ev.Referrer.Name == "Alice" {
					completed.Add(1)
				}
			}))
		a := e.newAuth(t, nil, em, pw, rf)
		owner := signUpVerified(t, e, a, pw, em)
		me := p3SessionFor(t, a, owner.User.ID)
		dash := must[referral.Dashboard](t)(rf.MyDashboard(me))
		if len(dash.Code) != referral.CodeLength || dash.Stats.Total != 0 {
			t.Fatalf("dashboard = %+v", dash)
		}

		if _, err := p3SignUp(a, pw, "mallory@example.com", "", map[string]string{referral.ReferralHeader: "ZZZZZZZZ"}, nil); !errors.Is(err, referral.ErrInvalidCode) {
			t.Fatalf("a code naming nobody: %v", err)
		}
		if _, err := p3SignUp(a, pw, "bob@example.com", "Bob", map[string]string{referral.ReferralHeader: " " + dash.Code + " "}, nil); err != nil {
			t.Fatal(err)
		}
		if err := rf.Remember(anon(a), "nope"); !errors.Is(err, referral.ErrInvalidCode) {
			t.Fatalf("remember a bad code: %v", err)
		}
		if err := rf.Remember(anon(a), dash.Code); err != nil {
			t.Fatal(err)
		}
		if _, err := p3SignUp(a, pw, "carol@example.com", "Carol", nil, map[string]string{referral.CookieName: dash.Code}); err != nil {
			t.Fatal(err)
		}
		bob := p3UserID(t, a, "bob@example.com")
		res := must[referral.StepResult](t)(rf.MarkStep(context.Background(), bob, "first_purchase", map[string]string{"order": "o-1"}))
		if res.AlreadyCompleted || res.Status != referral.StatusCompleted || !res.Progress.IsCompleted {
			t.Fatalf("step = %+v", res)
		}
		again := must[referral.StepResult](t)(rf.MarkStep(context.Background(), bob, "first_purchase", nil))
		if !again.AlreadyCompleted {
			t.Fatalf("repeat step = %+v", again)
		}
		if _, err := rf.MarkStep(context.Background(), bob, "made_up", nil); !errors.Is(err, referral.ErrUnknownStep) {
			t.Fatalf("unknown step: %v", err)
		}
		if _, err := rf.MarkStep(context.Background(), owner.User.ID, "first_purchase", nil); !errors.Is(err, referral.ErrNotFound) {
			t.Fatalf("a user nobody referred: %v", err)
		}
		a.WaitDeliveries()
		if completed.Load() != 1 || signedUp.Load() != 2 {
			t.Fatalf("callbacks: completed %d signed-up %d", completed.Load(), signedUp.Load())
		}

		dash = must[referral.Dashboard](t)(rf.MyDashboard(me))
		if dash.Stats != (referral.Stats{Total: 2, Completed: 1, Pending: 1, JoinedToday: 2}) {
			t.Fatalf("stats = %+v", dash.Stats)
		}
		l := must[referral.ListResult](t)(rf.List(me, referral.ListRequest{}))
		if l.Total != 2 || len(l.Referrals) != 2 {
			t.Fatalf("list = %+v", l)
		}
		for _, r := range l.Referrals {
			switch r.ReferredUser.Name {
			case "Bob":
				if r.ReferredUser.Email != "b***@example.com" || r.Status != referral.StatusCompleted || r.CompletedAt == nil {
					t.Fatalf("bob's row = %+v", r)
				}
			case "Carol":
				if r.Status != referral.StatusPending || len(r.Progress.RemainingSteps) != 1 {
					t.Fatalf("carol's row = %+v", r)
				}
			default:
				t.Fatalf("row = %+v", r)
			}
		}
	})
}

// TestP3CommunityFaults: every database failure each operation of the
// three plugins can meet reaches the caller.
func TestP3CommunityFaults(t *testing.T) {
	type ecSetup struct {
		a        *auth.Auth
		ec       *emailchallenge.Plugin
		poll     auth.Token
		approval auth.Token
	}
	// challenge builds an Auth with a verified owner and one open challenge.
	challenge := func(t *testing.T, e *faultEnv, opts ...emailchallenge.Option) ecSetup {
		em, pw, ec := e.emailPlugin(), e.passwordPlugin(), emailchallenge.New(opts...)
		a := e.newAuth(t, nil, em, pw, ec)
		signUpVerified(t, e.env, a, pw, em)
		st, err := ec.Start(anon(a), alice, "")
		if err != nil {
			t.Fatal(err)
		}
		return ecSetup{a: a, ec: ec, poll: st.PollToken.Token(), approval: e.mail.LastToken(t, a, alice)}
	}
	t.Run("challenge start", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			s := challenge(t, e)
			return func(context.Context) error { _, err := s.ec.Start(anon(s.a), alice, ""); return err }
		})
	})
	t.Run("challenge start, sign-up", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			s := challenge(t, e, emailchallenge.SignUp())
			return func(context.Context) error { _, err := s.ec.Start(anon(s.a), "new@example.com", ""); return err }
		})
	})
	t.Run("challenge approve and poll", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			s := challenge(t, e)
			return func(context.Context) error {
				if _, err := s.ec.Approve(anon(s.a), s.approval); err != nil {
					return err
				}
				_, err := s.ec.Poll(anon(s.a), s.poll)
				return err
			}
		})
	})
	t.Run("challenge same-browser context", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			s := challenge(t, e)
			return func(context.Context) error {
				_, err := s.ec.Context(p3Req(s.a, "", "198.51.100.1", nil, map[string]string{emailchallenge.CookieName: s.poll.Reveal()}), s.approval)
				return err
			}
		})
	})
	// An expired challenge's poll answers expired and deletes the row after
	// the call; a failed delete is logged (call 4 is that delete), since
	// the sweep removes the row later anyway.
	t.Run("challenge expired poll", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			s := challenge(t, e)
			e.clock.Advance(emailchallenge.DefaultTTL + time.Second)
			return func(context.Context) error { _, err := s.ec.Poll(anon(s.a), s.poll); return err }
		}, 4)
	})
	t.Run("challenge code", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			s := challenge(t, e)
			code := p3OTP(t, e.env, s.a, alice)
			return func(context.Context) error { _, err := s.ec.VerifyOTP(anon(s.a), s.poll, code); return err }
		})
	})

	type invSetup struct {
		a      *auth.Auth
		pw     *password.Plugin
		iv     *invite.Plugin
		ines   context.Context
		pub    invite.Created
		bobTok auth.Token
	}
	// invites builds an Auth with an inviter, one public invite and one
	// private invite to an account that exists.
	invites := func(t *testing.T, e *faultEnv) invSetup {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		iv := invite.New(invite.OnAccepted(func(context.Context, invite.Accepted) error { return nil }))
		a := e.newAuth(t, nil, em, pw, iv)
		_, ines := p3Inviter(t, a, "Ines")
		pub, err := iv.Create(ines, invite.Request{MaxUses: 1})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := iv.Create(ines, invite.Request{Email: alice}); err != nil {
			t.Fatal(err)
		}
		tok := e.mail.LastToken(t, a, alice)
		signUpVerified(t, e.env, a, pw, em)
		return invSetup{a: a, pw: pw, iv: iv, ines: ines, pub: pub, bobTok: tok}
	}
	t.Run("invite create", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			s := invites(t, e)
			return func(context.Context) error {
				if _, err := s.iv.Create(s.ines, invite.Request{}); err != nil {
					return err
				}
				_, err := s.iv.Create(s.ines, invite.Request{Email: "z@example.com"})
				return err
			}
		})
	})
	t.Run("invite reads", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			s := invites(t, e)
			return func(context.Context) error {
				if _, err := s.iv.Get(anon(s.a), s.pub.Token.Token()); err != nil {
					return err
				}
				_, err := s.iv.List(s.ines, invite.ListRequest{})
				return err
			}
		})
	})
	t.Run("invite sign-up", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			s := invites(t, e)
			return func(context.Context) error {
				_, err := p3SignUp(s.a, s.pw, "u1@example.com", "", map[string]string{invite.InviteHeader: s.pub.Token.Reveal()}, nil)
				return err
			}
		})
	})
	t.Run("invite activate, reject, cancel", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			s := invites(t, e)
			alice := p3SessionFor(t, s.a, p3UserID(t, s.a, alice))
			return func(context.Context) error {
				if _, err := s.iv.Activate(anon(s.a), s.pub.Token.Token()); err != nil {
					return err
				}
				if _, err := s.iv.Activate(alice, s.pub.Token.Token()); err != nil {
					return err
				}
				if err := s.iv.Reject(alice, s.bobTok); err != nil {
					return err
				}
				fresh, err := s.iv.Create(s.ines, invite.Request{})
				if err != nil {
					return err
				}
				return s.iv.Cancel(s.ines, fresh.ID)
			}
		})
	})
	t.Run("invite sign-in with the cookie", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			s := invites(t, e)
			return func(context.Context) error {
				_, err := s.pw.SignIn(p3Req(s.a, "", "203.0.113.20", nil, map[string]string{invite.CookieName: s.pub.Token.Reveal()}),
					password.SignInRequest{Identifier: alice, Password: secret})
				return err
			}
		})
	})

	type refSetup struct {
		a    *auth.Auth
		pw   *password.Plugin
		rf   *referral.Plugin
		me   context.Context
		code string
	}
	refs := func(t *testing.T, e *faultEnv) refSetup {
		em, pw, rf := e.emailPlugin(), e.passwordPlugin(), referral.New(referral.Steps("paid"), referral.ShowEmails())
		a := e.newAuth(t, nil, em, pw, rf)
		owner := signUpVerified(t, e.env, a, pw, em)
		me := p3SessionFor(t, a, owner.User.ID)
		d, err := rf.MyDashboard(me)
		if err != nil {
			t.Fatal(err)
		}
		return refSetup{a: a, pw: pw, rf: rf, me: me, code: d.Code}
	}
	t.Run("referral sign-up and step", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			s := refs(t, e)
			return func(context.Context) error {
				if _, err := p3SignUp(s.a, s.pw, "bob@example.com", "Bob", map[string]string{referral.ReferralHeader: s.code}, nil); err != nil {
					return err
				}
				id, err := s.a.FindIdentity(context.Background(), "email", "bob@example.com", false)
				if err != nil {
					return err
				}
				_, err = s.rf.MarkStep(context.Background(), id.UserID, "paid", map[string]string{"order": "1"})
				return err
			}
		})
	})
	t.Run("referral reads", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			s := refs(t, e)
			if _, err := p3SignUp(s.a, s.pw, "bob@example.com", "Bob", map[string]string{referral.ReferralHeader: s.code}, nil); err != nil {
				t.Fatal(err)
			}
			return func(context.Context) error {
				if err := s.rf.Remember(anon(s.a), s.code); err != nil {
					return err
				}
				if _, err := s.rf.MyDashboard(s.me); err != nil {
					return err
				}
				_, err := s.rf.List(s.me, referral.ListRequest{Limit: 500})
				return err
			}
		})
	})
}

// p3FailIDs makes the id generator fail for one prefix only, so the plugin's
// own NewID call fails while the core's succeed.
func p3FailIDs(prefix string) auth.Option {
	n := 0
	return auth.WithIDs(func(p string) (string, error) {
		if p == prefix {
			return "", errFault
		}
		n++
		return fmt.Sprintf("%s_p3_%d", p, n), nil
	})
}

// TestP3CommunityEmailChallenge_Edges: tenants, a vanished owner, kinds
// outside Kinds, empty tokens, an approval seen from another device, and an
// id generator that fails.
func TestP3CommunityEmailChallenge_Edges(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, ec := e.emailPlugin(email.ScopedByTenant()), emailchallenge.New(emailchallenge.SignUp())
		a := e.newAuth(t, nil, em, ec)
		acme := auth.WithScope(anon(a), "acme")
		st := must[emailchallenge.Result](t)(ec.Start(acme, alice, ""))
		must[emailchallenge.Result](t)(ec.Approve(anon(a), e.mail.LastToken(t, a, alice)))
		if p, _ := ec.Poll(auth.WithScope(anon(a), "globex"), st.PollToken.Token()); p.State != emailchallenge.StateExpired {
			t.Fatalf("a poll in another tenant = %+v", p)
		}
		st = must[emailchallenge.Result](t)(ec.Start(acme, alice, ""))
		tok := e.mail.LastToken(t, a, alice)
		must[emailchallenge.Result](t)(ec.Approve(anon(a), tok))
		if cx := must[emailchallenge.ContextResult](t)(ec.Context(anon(a), tok)); cx.State != emailchallenge.StateApproved {
			t.Fatalf("context after approval on another device = %+v", cx)
		}
		in := must[emailchallenge.Result](t)(ec.Poll(anon(a), st.PollToken.Token())) // no tenant on the poll
		if in.State != emailchallenge.StateCompleted || !in.Created {
			t.Fatalf("poll without a tenant = %+v", in)
		}
		if _, err := a.FindIdentity(acme, email.KindEmail, alice, true); err != nil {
			t.Fatalf("the account must be in acme: %v", err)
		}
		if cx := must[emailchallenge.ContextResult](t)(ec.Context(anon(a), "")); cx.State != emailchallenge.StateInvalid {
			t.Fatalf("context without a token = %+v", cx)
		}

		// The owner deleted between approval and poll: the poll expires.
		st = must[emailchallenge.Result](t)(ec.Start(acme, alice, ""))
		must[emailchallenge.Result](t)(ec.Approve(anon(a), e.mail.LastToken(t, a, alice)))
		if err := a.DeleteUser(context.Background(), in.User.ID); err != nil {
			t.Fatal(err)
		}
		if p := must[emailchallenge.Result](t)(ec.Poll(auth.WithScope(anon(a), "acme"), st.PollToken.Token())); p.State != emailchallenge.StateCompleted || !p.Created {
			t.Fatalf("with SignUp a vanished owner is created again: %+v", p)
		}

		em3, pw3, ph3 := e.emailPlugin(), e.passwordPlugin(), e.phonePlugin(phone.Login())
		ec3 := emailchallenge.New(emailchallenge.Kinds(email.KindEmail))
		a3 := e.newAuth(t, nil, em3, pw3, ph3, ec3)
		if _, err := ec3.Start(anon(a3), "+14155550100", ""); !errors.Is(err, auth.ErrIdentifierInvalid) {
			t.Fatalf("a phone number with Kinds(email): %v", err)
		}
		// The same database as a: a fresh address, verified by hand.
		const dave = "dave@example.com"
		owner := must[password.SignInResult](t)(pw3.SignUp(anon(a3), password.SignUpRequest{Identifier: dave, Password: secret}))
		if _, err := em3.Verify(anon(a3), e.mail.LastToken(t, a3, dave)); err != nil {
			t.Fatal(err)
		}
		st = must[emailchallenge.Result](t)(ec3.Start(anon(a3), dave, ""))
		must[emailchallenge.Result](t)(ec3.Approve(anon(a3), e.mail.LastToken(t, a3, dave)))
		if err := a3.DeleteUser(context.Background(), owner.User.ID); err != nil {
			t.Fatal(err)
		}
		if p := must[emailchallenge.Result](t)(ec3.Poll(anon(a3), st.PollToken.Token())); p.State != emailchallenge.StateExpired {
			t.Fatalf("an approved challenge whose owner is gone = %+v", p)
		}

		ec4 := emailchallenge.New(emailchallenge.SignUp())
		a4 := e.newAuth(t, []auth.Option{p3FailIDs("ech")}, e.emailPlugin(), ec4)
		if _, err := ec4.Start(anon(a4), alice, ""); !errors.Is(err, errFault) {
			t.Fatalf("a failing id generator: %v", err)
		}
	})
}

// TestP3CommunityInvite_Edges: tokens that name nothing, a role without
// CanCreate, a bad address, a hidden inviter, paging bounds, a reject that
// is not the addressee's, a cookie capped by the invite's expiry, and an id
// generator that fails.
func TestP3CommunityInvite_Edges(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, iv := e.emailPlugin(), e.passwordPlugin(), invite.New(invite.HideInviter())
		a := e.newAuth(t, nil, em, pw, iv)
		_, ines := p3Inviter(t, a, "Ines")
		for _, tok := range []auth.Token{"", "no-such-invite"} {
			if _, err := iv.Get(anon(a), tok); !errors.Is(err, invite.ErrInvalid) {
				t.Fatalf("get %q: %v", tok, err)
			}
		}
		if _, err := iv.Create(ines, invite.Request{Role: "member"}); !errors.Is(err, invite.ErrForbidden) {
			t.Fatalf("a role without CanCreate: %v", err)
		}
		if _, err := iv.Create(ines, invite.Request{Email: "not an address"}); !errors.Is(err, auth.ErrIdentifierInvalid) {
			t.Fatalf("a bad address: %v", err)
		}
		if _, err := iv.Create(ines, invite.Request{MaxUses: -1}); !errors.Is(err, auth.ErrBadRequest) {
			t.Fatalf("negative uses: %v", err)
		}
		must[invite.Created](t)(iv.Create(ines, invite.Request{Email: "zoe@example.com"}))
		mail := e.mail.To(a, "zoe@example.com")
		if len(mail) != 1 || strings.Contains(mail[0].Text, "Ines") {
			t.Fatalf("a hidden inviter named in the mail: %+v", mail)
		}
		pub := must[invite.Created](t)(iv.Create(ines, invite.Request{ExpiresIn: 30}))
		if v := must[invite.View](t)(iv.Get(anon(a), pub.Token.Token())); v.InviterName != "" {
			t.Fatalf("a hidden inviter named in get: %+v", v)
		}
		if err := iv.Reject(ines, pub.Token.Token()); !errors.Is(err, invite.ErrInvalid) {
			t.Fatalf("rejecting a public invite: %v", err)
		}
		for _, bad := range []invite.ListRequest{{Limit: invite.MaxListLimit + 1}, {Offset: -1}} {
			if _, err := iv.List(ines, bad); !errors.Is(err, auth.ErrBadRequest) {
				t.Fatalf("list %+v: %v", bad, err)
			}
		}
		// The cookie lives no longer than the invite (30s, under the 10min
		// default): checked through the effect the call recorded.
		ctx := anon(a)
		must[invite.ActivateResult](t)(iv.Activate(ctx, pub.Token.Token()))
		var set bool
		for _, ef := range auth.RequestEffects(ctx) {
			if ef.Kind == auth.EffectCookie && ef.Name == invite.CookieName {
				set = true
				if want := e.clock.Now().Add(30 * time.Second); !ef.ExpiresAt.Equal(want) {
					t.Fatalf("cookie expires %v, want %v", ef.ExpiresAt, want)
				}
			}
		}
		if !set {
			t.Fatal("no invite cookie")
		}

		iv2 := invite.New()
		a2 := e.newAuth(t, []auth.Option{p3FailIDs("inv")}, e.emailPlugin(), e.passwordPlugin(), iv2)
		_, x := p3Inviter(t, a2, "X")
		if _, err := iv2.Create(x, invite.Request{}); !errors.Is(err, errFault) {
			t.Fatalf("a failing id generator: %v", err)
		}
	})
}

// TestP3CommunityReferral_Edges: AfterStep, metadata bounds, list paging,
// a generator that repeats, and an id generator that fails.
func TestP3CommunityReferral_Edges(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var steps atomic.Int32
		em, pw := e.emailPlugin(), e.passwordPlugin()
		rf := referral.New(referral.Steps("paid"), referral.ShowEmails(), referral.AfterStep(func(_ context.Context, ev referral.Event) {
			if ev.Step != "" && ev.Referred.Name == "Bob" {
				steps.Add(1)
			}
		}))
		a := e.newAuth(t, nil, em, pw, rf)
		owner := signUpVerified(t, e, a, pw, em)
		me := p3SessionFor(t, a, owner.User.ID)
		code := must[referral.Dashboard](t)(rf.MyDashboard(me)).Code
		if _, err := p3SignUp(a, pw, "bob@example.com", "Bob", map[string]string{referral.ReferralHeader: code}, nil); err != nil {
			t.Fatal(err)
		}
		bob := p3UserID(t, a, "bob@example.com")
		big := map[string]string{"note": strings.Repeat("x", referral.MaxMetadataLength)}
		if _, err := rf.MarkStep(context.Background(), bob, "paid", big); !errors.Is(err, auth.ErrBadRequest) {
			t.Fatalf("oversized metadata: %v", err)
		}
		must[referral.StepResult](t)(rf.MarkStep(context.Background(), bob, "paid", nil))
		if steps.Load() != 2 { // sign_up and paid
			t.Fatalf("AfterStep ran %d times", steps.Load())
		}
		if _, err := rf.List(me, referral.ListRequest{Offset: -1}); !errors.Is(err, auth.ErrBadRequest) {
			t.Fatalf("negative offset: %v", err)
		}
		l := must[referral.ListResult](t)(rf.List(me, referral.ListRequest{Limit: 1000}))
		if l.Limit != referral.MaxListLimit || l.Referrals[0].ReferredUser.Email != "bob@example.com" {
			t.Fatalf("list clamps the page and ShowEmails shows the address: %+v", l)
		}

		// A generator that always draws the same code: the first user gets
		// it, the next sign-up runs out of draws; a draw of the wrong shape
		// is a failed draw too.
		rf2 := referral.New(referral.GenerateCode(func() string { return "same0001" }))
		pw2 := e.passwordPlugin()
		a2 := e.newAuth(t, nil, e.emailPlugin(), pw2, rf2)
		if _, err := p3SignUp(a2, pw2, "g1@example.com", "", nil, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := p3SignUp(a2, pw2, "g2@example.com", "", nil, nil); !errors.Is(err, referral.ErrNoCode) {
			t.Fatalf("a repeating generator: %v", err)
		}
		rf3 := referral.New(referral.GenerateCode(func() string { return "bad" }))
		pw3 := e.passwordPlugin()
		a3 := e.newAuth(t, nil, e.emailPlugin(), pw3, rf3)
		if _, err := p3SignUp(a3, pw3, "g3@example.com", "", nil, nil); !errors.Is(err, referral.ErrNoCode) {
			t.Fatalf("a malformed generator: %v", err)
		}

		rf4 := referral.New()
		pw4 := e.passwordPlugin()
		a4 := e.newAuth(t, []auth.Option{p3FailIDs("rfl")}, e.emailPlugin(), pw4, rf4)
		if _, err := p3SignUp(a4, pw4, "g4@example.com", "", map[string]string{referral.ReferralHeader: code}, nil); !errors.Is(err, errFault) {
			t.Fatalf("a failing id generator: %v", err)
		}
	})
}

// TestP3CommunityFaults_Outbox: with the delivery outbox, the mail of a
// challenge and of a private invite is written in the operation's
// transaction, so a failure to write it fails the operation.
func TestP3CommunityFaults_Outbox(t *testing.T) {
	outbox := []auth.Option{auth.WithDeliveryOutbox(sessKey)}
	t.Run("challenge", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw, ec := e.emailPlugin(), e.passwordPlugin(), emailchallenge.New()
			a := e.newAuth(t, outbox, em, pw, ec)
			signUpVerified(t, e.env, a, pw, em)
			return func(context.Context) error { _, err := ec.Start(anon(a), alice, ""); return err }
		})
	})
	t.Run("private invite", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			iv := invite.New()
			a := e.newAuth(t, outbox, e.emailPlugin(), e.passwordPlugin(), iv)
			_, ines := p3Inviter(t, a, "Ines")
			return func(context.Context) error {
				_, err := iv.Create(ines, invite.Request{Email: "z@example.com"})
				return err
			}
		})
	})
}
