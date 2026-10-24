package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/anonymous"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
)

// linkLog records every call of the app's OnLink hook, so a test can assert
// who was linked to whom and that nothing links twice.
type linkLog struct {
	calls [][2]string // guest id, user id
	fail  error
}

func (l *linkLog) hook(_ context.Context, _ sqlb.DBTX, guest, user auth.User) error {
	l.calls = append(l.calls, [2]string{guest.ID, user.ID})
	return l.fail
}

// guestSession starts a guest session and returns its user id and token.
func guestSession(t *testing.T, a *auth.Auth, an *anonymous.Plugin) (string, auth.Token) {
	t.Helper()
	r, err := an.SignIn(anon(a))
	if err != nil {
		t.Fatalf("guest sign-in: %v", err)
	}
	if r.Token == "" || r.User.ID == "" || r.User.Name == "" {
		t.Fatalf("guest = %+v", r)
	}
	return r.User.ID, r.Token
}

// userGone reports whether the user row was deleted.
func userGone(t *testing.T, a *auth.Auth, id string) bool {
	t.Helper()
	_, err := a.User(context.Background(), id)
	if err != nil && !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatal(err)
	}
	return err != nil
}

// TestAnonymous_GuestSignsUpAndIsLinked: a guest gets a session, is refused a
// second guest session, and signing up from the guest session links the guest
// to the new account and deletes the guest row.
func TestAnonymous_GuestSignsUpAndIsLinked(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		log := &linkLog{}
		em, pw, an := e.emailPlugin(), e.passwordPlugin(), anonymous.New(anonymous.OnLink(log.hook))
		a := e.newAuth(t, nil, em, pw, an)

		guestID, guestTok := guestSession(t, a, an)
		if !identSignedIn(t, a, guestTok) {
			t.Fatal("a guest session must sign the guest in")
		}
		if u := must[auth.User](t)(a.User(context.Background(), guestID)); u.Name != anonymous.DefaultName {
			t.Fatalf("a guest is named %q by default", u.Name)
		}
		if anon, err := an.IsAnonymous(context.Background(), guestID); err != nil || !anon {
			t.Fatalf("IsAnonymous = %v %v", anon, err)
		}
		if _, err := an.SignIn(request(a, guestTok)); !errors.Is(err, anonymous.ErrAlreadyAnonymous) {
			t.Fatalf("a second guest session from a guest: %v", err)
		}

		up, err := pw.SignUp(request(a, guestTok), password.SignUpRequest{Identifier: alice, Password: secret, Name: "Alice"})
		if err != nil {
			t.Fatalf("sign up from a guest session: %v", err)
		}
		if len(log.calls) != 1 || log.calls[0] != [2]string{guestID, up.User.ID} {
			t.Fatalf("link calls = %v, want guest %s to %s", log.calls, guestID, up.User.ID)
		}
		if !userGone(t, a, guestID) {
			t.Fatal("the guest row must be deleted once linked")
		}
		if identSignedIn(t, a, guestTok) {
			t.Fatal("the guest session must end with the guest")
		}
		if !identSignedIn(t, a, up.Token) {
			t.Fatal("the new account's session must work")
		}
		// A real user asking for a guest session gets one; nothing links.
		if _, err := an.SignIn(request(a, up.Token)); err != nil {
			t.Fatalf("a real user asking for a guest: %v", err)
		}
		if len(log.calls) != 1 {
			t.Fatalf("a guest created by a real user must not link: %v", log.calls)
		}
	})
}

// TestAnonymous_LinksOnEverySignInPath: password sign-in, a magic link and an
// email code all end in a session, so all three link the guest.
func TestAnonymous_LinksOnEverySignInPath(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		log := &linkLog{}
		em, pw := e.emailPlugin(email.SignInWithCode()), e.passwordPlugin()
		ml, an := magiclink.New(), anonymous.New(anonymous.OnLink(log.hook))
		a := e.newAuth(t, nil, em, pw, ml, an)
		owner := signUpVerified(t, e, a, pw, em)

		g1, t1 := guestSession(t, a, an)
		if _, err := pw.SignIn(request(a, t1), password.SignInRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatal(err)
		}
		g2, t2 := guestSession(t, a, an)
		if err := ml.Send(request(a, t2), alice); err != nil {
			t.Fatal(err)
		}
		if _, err := ml.SignIn(request(a, t2), e.mail.LastToken(t, a, alice)); err != nil {
			t.Fatal(err)
		}
		g3, t3 := guestSession(t, a, an)
		if err := em.SendCode(request(a, t3), alice); err != nil {
			t.Fatal(err)
		}
		if _, err := em.SignInCode(request(a, t3), alice, lastMailCode(t, e, a, alice)); err != nil {
			t.Fatal(err)
		}
		want := [][2]string{{g1, owner.User.ID}, {g2, owner.User.ID}, {g3, owner.User.ID}}
		if len(log.calls) != len(want) {
			t.Fatalf("link calls = %v, want %v", log.calls, want)
		}
		for i := range want {
			if log.calls[i] != want[i] {
				t.Fatalf("link call %d = %v, want %v", i, log.calls[i], want[i])
			}
		}
		for _, g := range []string{g1, g2, g3} {
			if !userGone(t, a, g) {
				t.Fatalf("guest %s must be deleted", g)
			}
		}
		// A sign-in without a guest session links nothing.
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatal(err)
		}
		if len(log.calls) != len(want) {
			t.Fatalf("a plain sign-in linked: %v", log.calls)
		}
	})
}

// TestAnonymous_LinkErrorFailsTheSignIn: an OnLink error rolls the sign-in
// back and leaves the guest in place, so no data is lost half way.
func TestAnonymous_LinkErrorFailsTheSignIn(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		log := &linkLog{fail: errors.New("app: cart move failed")}
		em, pw, an := e.emailPlugin(), e.passwordPlugin(), anonymous.New(anonymous.OnLink(log.hook))
		a := e.newAuth(t, nil, em, pw, an)
		signUpVerified(t, e, a, pw, em)
		guestID, guestTok := guestSession(t, a, an)
		if _, err := pw.SignIn(request(a, guestTok), password.SignInRequest{Identifier: alice, Password: secret}); !errors.Is(err, log.fail) {
			t.Fatalf("sign-in with a failing link = %v", err)
		}
		if userGone(t, a, guestID) || !identSignedIn(t, a, guestTok) {
			t.Fatal("the guest and its session must survive a failed link")
		}
	})
}

// TestAnonymous_KeepUsers: the guest row stays after linking, and there is no
// delete route.
func TestAnonymous_KeepUsers(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		log := &linkLog{}
		em, pw, an := e.emailPlugin(), e.passwordPlugin(), anonymous.New(anonymous.KeepUsers(), anonymous.OnLink(log.hook))
		a := e.newAuth(t, nil, em, pw, an)
		if _, ok := a.Operation(anonymous.EndpointDelete); ok {
			t.Fatal("KeepUsers must leave the delete route out")
		}
		guestID, guestTok := guestSession(t, a, an)
		up, err := pw.SignUp(request(a, guestTok), password.SignUpRequest{Identifier: alice, Password: secret})
		if err != nil {
			t.Fatal(err)
		}
		if len(log.calls) != 1 || log.calls[0] != [2]string{guestID, up.User.ID} {
			t.Fatalf("link calls = %v", log.calls)
		}
		if userGone(t, a, guestID) {
			t.Fatal("KeepUsers must keep the guest row")
		}
		if _, err := an.SignIn(request(a, guestTok)); !errors.Is(err, anonymous.ErrAlreadyAnonymous) {
			t.Fatalf("the kept guest is still a guest: %v", err)
		}
		// The route is not registered, so the Go method reports it unwired,
		// as the email plugin's code methods do without SignInWithCode.
		if err := an.Delete(request(a, guestTok)); !errors.Is(err, auth.ErrOperationNotWired) {
			t.Fatalf("delete without the route = %v", err)
		}
	})
}

// TestAnonymous_DeleteOwnAccount: a guest deletes their own row and session;
// a real user is refused.
func TestAnonymous_DeleteOwnAccount(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, an := e.emailPlugin(), e.passwordPlugin(), anonymous.New()
		a := e.newAuth(t, nil, em, pw, an)
		guestID, guestTok := guestSession(t, a, an)
		if err := an.Delete(request(a, guestTok)); err != nil {
			t.Fatal(err)
		}
		if !userGone(t, a, guestID) || identSignedIn(t, a, guestTok) {
			t.Fatal("delete must remove the guest and end the session")
		}
		owner := signUpVerified(t, e, a, pw, em)
		if err := an.Delete(request(a, owner.Token)); !errors.Is(err, anonymous.ErrNotAnonymous) {
			t.Fatalf("delete by a real user = %v", err)
		}
		if err := an.Delete(anon(a)); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("delete signed out = %v", err)
		}
	})
}

// TestAnonymous_VerifiedIdentifierEndsGuestStatus: a guest who adds and
// verifies an address of their own is a regular user from then on: the flag
// clears, and a later sign-in to another account no longer links them away.
func TestAnonymous_VerifiedIdentifierEndsGuestStatus(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		log := &linkLog{}
		em, pw, an := e.emailPlugin(), e.passwordPlugin(), anonymous.New(anonymous.OnLink(log.hook))
		a := e.newAuth(t, nil, em, pw, an)
		owner := signUpVerified(t, e, a, pw, em)
		guestID, guestTok := guestSession(t, a, an)
		if err := em.Add(request(a, guestTok), identBob); err != nil {
			t.Fatal(err)
		}
		if anon, _ := an.IsAnonymous(context.Background(), guestID); !anon {
			t.Fatal("an unverified address must not end guest status")
		}
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, identBob)); err != nil {
			t.Fatal(err)
		}
		if anon, _ := an.IsAnonymous(context.Background(), guestID); anon {
			t.Fatal("a verified address must end guest status")
		}
		if _, err := pw.SignIn(request(a, guestTok), password.SignInRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatal(err)
		}
		if len(log.calls) != 0 || userGone(t, a, guestID) {
			t.Fatalf("a former guest must not be linked away: %v", log.calls)
		}
		_ = owner
		// A user created with a verified identity was never a guest; the
		// hook sees the flag already false and writes nothing.
		uid, _ := identUser(t, a, identWork)
		if anon, err := an.IsAnonymous(context.Background(), uid); err != nil || anon {
			t.Fatalf("a regular user = %v %v", anon, err)
		}
	})
}

// TestAnonymous_SweepStale: a.Sweep deletes guests whose sessions have all
// expired and who are older than the retention, and nothing else; without
// SweepStale it deletes no guest.
func TestAnonymous_SweepStale(t *testing.T) {
	const day = 24 * time.Hour
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, an := e.emailPlugin(), e.passwordPlugin(), anonymous.New(anonymous.SweepStale())
		a := e.newAuth(t, nil, em, pw, an)
		owner := signUpVerified(t, e, a, pw, em)
		old, _ := guestSession(t, a, an)
		// Ten days on, the old guest's session has idled out (7 days); a
		// fresh guest has a live one.
		e.clock.Advance(10 * day)
		live, _ := guestSession(t, a, an)
		res, err := a.Sweep(context.Background(), day)
		if err != nil {
			t.Fatal(err)
		}
		if res[anonymous.PluginName] != 1 || !userGone(t, a, old) || userGone(t, a, live) || userGone(t, a, owner.User.ID) {
			t.Fatalf("sweep = %v; old gone %v, live gone %v", res, userGone(t, a, old), userGone(t, a, live))
		}
		// Two days on, the fresh guest is older than the retention but its
		// session is still live: kept.
		e.clock.Advance(2 * day)
		if res, err = a.Sweep(context.Background(), day); err != nil || res[anonymous.PluginName] != 0 || userGone(t, a, live) {
			t.Fatalf("sweep with a live session = %v %v", res, err)
		}
		// Once that session has idled out too, the guest goes.
		e.clock.Advance(auth.DefaultSessionConfig.IdleTimeout)
		if res, err = a.Sweep(context.Background(), day); err != nil || res[anonymous.PluginName] != 1 || !userGone(t, a, live) {
			t.Fatalf("sweep after expiry = %v %v", res, err)
		}
	})
}

// TestAnonymous_SweepOffByDefault: without SweepStale a sweep deletes no
// guest, however old.
func TestAnonymous_SweepOffByDefault(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		an := anonymous.New()
		a := e.newAuth(t, nil, e.emailPlugin(), an)
		old, _ := guestSession(t, a, an)
		e.clock.Advance(auth.DefaultSessionConfig.MaxLifetime + time.Hour)
		res, err := a.Sweep(context.Background(), time.Hour)
		if err != nil || res[anonymous.PluginName] != 0 || userGone(t, a, old) {
			t.Fatalf("without SweepStale = %v %v", res, err)
		}
	})
}

// vanishing refuses the delete of one user as "not found", the way a second
// instance's sweep that got there first would make the core answer.
type vanishing struct{ userID string }

func (*vanishing) Name() string { return "vanishing" }

// DataHooks reads v.userID when the hook runs, not when auth.New wired it,
// so the test can name the guest after creating it.
func (v *vanishing) DataHooks() auth.DataHooks {
	return auth.DataHooks{User: auth.TableHooks[auth.User]{
		BeforeDelete: func(_ context.Context, _ sqlb.DBTX, u *auth.User) error {
			if u.ID == v.userID {
				return auth.ErrUserNotFound
			}
			return nil
		},
	}}
}

// TestAnonymous_SweepSkipsAGuestAnotherSweepDeleted: a guest gone between
// the listing and its delete is skipped, not counted, and the sweep goes on.
func TestAnonymous_SweepSkipsAGuestAnotherSweepDeleted(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		an := anonymous.New(anonymous.SweepStale(), anonymous.WithName(func() string { return "Visitor" }))
		gone := &vanishing{}
		a := e.newAuth(t, nil, e.emailPlugin(), an, gone)
		first, _ := guestSession(t, a, an)
		second, _ := guestSession(t, a, an)
		if u := must[auth.User](t)(a.User(context.Background(), first)); u.Name != "Visitor" {
			t.Fatalf("WithName: guest named %q", u.Name)
		}
		gone.userID = first
		e.clock.Advance(auth.DefaultSessionConfig.MaxLifetime + time.Hour)
		res, err := a.Sweep(context.Background(), time.Hour)
		if err != nil || res[anonymous.PluginName] != 1 || !userGone(t, a, second) {
			t.Fatalf("sweep with one guest vanishing = %v %v", res, err)
		}
	})
}

// TestAnonymous_RateAndRemember: guest creation is limited per IP, and
// remember=false makes a transient session.
func TestAnonymous_RateAndRemember(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		an := anonymous.New(anonymous.WithSignInLimit(2, time.Hour))
		a := e.newAuth(t, nil, e.emailPlugin(), an)
		for range 2 {
			if _, err := an.SignIn(anon(a)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := an.SignIn(anon(a)); !errors.Is(err, auth.ErrRateLimited) {
			t.Fatalf("third guest from one IP = %v", err)
		}
		e.clock.Advance(time.Hour + time.Second)
		op, _ := a.Operation(anonymous.EndpointSignIn)
		ctx := anon(a)
		out, err := op.Invoke(ctx, func(dst any) error {
			in, ok := dst.(*anonymous.SignInRequest)
			if !ok {
				t.Fatalf("input type %T", dst)
			}
			no := false
			in.Remember = &no
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := out.(anonymous.SignInResult); !ok {
			t.Fatalf("output type %T", out)
		}
		var issued *auth.Effect
		for _, ef := range auth.RequestEffects(ctx) {
			if ef.Kind == auth.EffectIssueSession {
				issued = &ef
			}
		}
		if issued == nil || !issued.Transient {
			t.Fatalf("remember=false must issue a transient session: %+v", issued)
		}
	})
}
