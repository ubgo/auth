package integration

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/sqlb"
)

// Round 2 of the feature work, the core's features: each test
// shows the feature on a real database and that its absence keeps today's
// behaviour.

// freshRequest is a browser request carrying tok as a cookie, so a FreshSignIn
// operation called from Go sees the session.
func freshRequest(a *auth.Auth, tok auth.Token) context.Context {
	return a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialCookie, Token: tok, Client: auth.Client{Origin: testBaseURL}})
}

// accountGone fails unless the user, every identity and every session are gone.
func accountGone(t *testing.T, a *auth.Auth, userID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := a.User(ctx, userID); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("user after deletion: %v, want ErrUserNotFound", err)
	}
	if ids, err := a.Identities(ctx, userID); err != nil || len(ids) != 0 {
		t.Fatalf("identities after deletion: %v %v", ids, err)
	}
	if list, err := a.Sessions(ctx, userID); err != nil || len(list) != 0 {
		t.Fatalf("sessions after deletion: %v %v", list, err)
	}
}

func TestDeleteAccount_DeletesAtOnceAndClearsTheSession(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := coreAuth(t, e, nil, auth.WithAccountDeletion(auth.AccountDeletion{}))
		u, tok := coreSignedIn(t, a)
		ctx := freshRequest(a, tok)
		res, err := a.DeleteAccount(ctx)
		if err != nil || !res.Deleted || res.ConfirmationSent {
			t.Fatalf("DeleteAccount = %+v, %v", res, err)
		}
		accountGone(t, a, u.ID)
		var cleared bool
		for _, ef := range auth.RequestEffects(ctx) {
			cleared = cleared || ef.Kind == auth.EffectClearSession
		}
		if !cleared {
			t.Fatal("the deleting request must clear the client's session")
		}
		if _, _, _, err := a.ResolveSession(context.Background(), tok); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("the token after deletion: %v, want ErrSignedOut", err)
		}
	})
}

func TestDeleteAccount_NeedsAFreshSession(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil, auth.WithAccountDeletion(auth.AccountDeletion{}))
	u, tok := coreSignedIn(t, a)
	e.clock.Advance(auth.DefaultFreshWindow + time.Minute)
	if _, err := a.DeleteAccount(freshRequest(a, tok)); !errors.Is(err, auth.ErrFreshSessionRequired) {
		t.Fatalf("stale session: %v, want ErrFreshSessionRequired", err)
	}
	if _, err := a.User(context.Background(), u.ID); err != nil {
		t.Fatalf("the refused call must change nothing: %v", err)
	}
}

func TestDeleteAccount_ByLinkSendsThenDeletesOnConfirm(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := coreAuth(t, e, nil, auth.WithAccountDeletion(auth.AccountDeletion{ConfirmByLink: true}))
		u, tok := coreSignedIn(t, a)
		res, err := a.DeleteAccount(freshRequest(a, tok))
		if err != nil || res.Deleted || !res.ConfirmationSent {
			t.Fatalf("DeleteAccount = %+v, %v", res, err)
		}
		if _, err := a.User(context.Background(), u.ID); err != nil {
			t.Fatalf("the account must exist until the link is spent: %v", err)
		}
		mails := e.mail.To(a, alice)
		if len(mails) != 1 || !strings.Contains(mails[0].Text, testBaseURL+auth.DefaultDeleteAccountPage+"?token=") || mails[0].Subject == "" {
			t.Fatalf("confirmation mail: %+v", mails)
		}
		link := e.mail.LastToken(t, a, alice)

		// The link is opened in a browser with no session: the token alone
		// deletes, and a second use is refused like a wrong one.
		if err := a.ConfirmDeleteAccount(context.Background(), link); err != nil {
			t.Fatalf("confirm: %v", err)
		}
		accountGone(t, a, u.ID)
		if err := a.ConfirmDeleteAccount(context.Background(), link); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("spent link: %v, want ErrTokenInvalid", err)
		}
		if err := a.ConfirmDeleteAccount(context.Background(), "not-a-token"); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("wrong token: %v, want ErrTokenInvalid", err)
		}
	})
}

func TestDeleteAccount_LinkExpiresAndUsesTheAppsBuilder(t *testing.T) {
	e := newFaultEnv(t)
	var built auth.Token
	a := coreAuth(t, e.env, nil, auth.WithAccountDeletion(auth.AccountDeletion{
		ConfirmByLink: true, LinkTTL: time.Minute,
		Link: func(tok auth.Token) string { built = tok; return "https://app.example.com/bye#" + tok.Reveal() },
	}))
	u, tok := coreSignedIn(t, a)
	if _, err := a.DeleteAccount(freshRequest(a, tok)); err != nil {
		t.Fatal(err)
	}
	mails := e.mail.To(a, alice)
	if len(mails) != 1 || !strings.Contains(mails[0].Text, "https://app.example.com/bye#"+built.Reveal()) {
		t.Fatalf("the app's link must be the one sent: %+v", mails)
	}
	e.clock.Advance(2 * time.Minute)
	if err := a.ConfirmDeleteAccount(context.Background(), built); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("expired link: %v, want ErrTokenInvalid", err)
	}
	if _, err := a.User(context.Background(), u.ID); err != nil {
		t.Fatalf("an expired link deletes nothing: %v", err)
	}
}

func TestDeleteAccount_ByLinkNeedsARecoveryChannel(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil, auth.WithAccountDeletion(auth.AccountDeletion{ConfirmByLink: true}))
	u := must[auth.User](t)(a.CreateUser(context.Background(), auth.NewUser{Name: "Nobody"}))
	_, tok, err := a.CreateSession(context.Background(), u.ID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.DeleteAccount(freshRequest(a, tok)); !errors.Is(err, auth.ErrNoRecoveryChannel) {
		t.Fatalf("no verified address: %v, want ErrNoRecoveryChannel", err)
	}
}

func TestDeleteAccount_ConfirmFromTheUsersOwnSessionClearsIt(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil, auth.WithAccountDeletion(auth.AccountDeletion{ConfirmByLink: true}))
	_, tok := coreSignedIn(t, a)
	if _, err := a.DeleteAccount(freshRequest(a, tok)); err != nil {
		t.Fatal(err)
	}
	ctx := freshRequest(a, tok)
	if err := a.ConfirmDeleteAccount(ctx, e.mail.LastToken(t, a, alice)); err != nil {
		t.Fatal(err)
	}
	var cleared bool
	for _, ef := range auth.RequestEffects(ctx) {
		cleared = cleared || ef.Kind == auth.EffectClearSession
	}
	if !cleared {
		t.Fatal("confirming from the user's own browser must clear its session")
	}
}

func TestDeleteAccount_AppHooksRefuseOrClean(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		refused := errors.New("owner of a workspace")
		var cleaned []string
		a := coreAuth(t, e, nil, auth.WithAccountDeletion(auth.AccountDeletion{}),
			auth.WithDataHooks(auth.DataHooks{User: auth.TableHooks[auth.User]{
				BeforeDelete: func(_ context.Context, tx sqlb.DBTX, u *auth.User) error {
					if u.Name == "Owner" {
						return refused
					}
					if tx == nil {
						return errors.New("the hook must see the deleting transaction")
					}
					cleaned = append(cleaned, u.ID)
					return nil
				},
			}}),
			auth.WithOperationHooks(auth.OperationHook{Match: []auth.EndpointID{auth.EndpointDeleteAccount},
				Before: func(_ context.Context, c *auth.Call) error {
					if c.User.Name == "Locked" {
						return refused
					}
					return nil
				}}),
		)
		ctx := context.Background()
		owner := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{Name: "Owner"}))
		if err := a.DeleteUser(ctx, owner.ID); !errors.Is(err, refused) {
			t.Fatalf("the data hook must refuse: %v", err)
		}
		if _, err := a.User(ctx, owner.ID); err != nil {
			t.Fatalf("a refused deletion changes nothing: %v", err)
		}
		locked := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{Name: "Locked"}))
		_, tok, err := a.CreateSession(ctx, locked.ID, auth.Client{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.DeleteAccount(freshRequest(a, tok)); !errors.Is(err, refused) {
			t.Fatalf("the operation hook must refuse self-service: %v", err)
		}
		// An admin path (the Go API) is not under the operation hook.
		if err := a.DeleteUser(ctx, locked.ID); err != nil {
			t.Fatalf("DeleteUser of the locked user: %v", err)
		}
		if len(cleaned) != 1 || cleaned[0] != locked.ID {
			t.Fatalf("the data hook cleaned %v, want %q", cleaned, locked.ID)
		}
	})
}

func TestDeleteAccount_EndsSessionsInAStoreOutsideTheDatabase(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil, auth.WithAccountDeletion(auth.AccountDeletion{}), auth.WithSessionStore(auth.NewMemorySessionStore()))
	u, tok := coreSignedIn(t, a)
	_, other, err := a.CreateSession(context.Background(), u.ID, auth.Client{UserAgent: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.DeleteAccount(freshRequest(a, tok)); err != nil {
		t.Fatal(err)
	}
	// No cascade reaches a memory store: the core must have asked it.
	if list, err := a.SessionStore().List(context.Background(), u.ID, a.Now()); err != nil || len(list) != 0 {
		t.Fatalf("memory store after deletion: %v %v", list, err)
	}
	if _, _, _, err := a.ResolveSession(context.Background(), other); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("the other device after deletion: %v, want ErrSignedOut", err)
	}
}

func TestDeleteAccount_OverHTTP(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil, auth.WithAccountDeletion(auth.AccountDeletion{}))
	_, tok := coreSignedIn(t, a)
	web := newApp(t, a)
	withSession(t, web, tok)
	if res := web.get(t, "/app/me"); res.StatusCode != http.StatusOK {
		t.Fatalf("/app/me before: %d", res.StatusCode)
	}
	res := web.post(t, "/auth/account/delete", nil)
	if body := readAll(t, res); res.StatusCode != http.StatusOK || !strings.Contains(body, `"deleted":true`) {
		t.Fatalf("delete: %d %s", res.StatusCode, body)
	}
	if res := web.get(t, "/app/me"); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/app/me after: %d, want 401 (cookie cleared, row gone)", res.StatusCode)
	}
}

func TestDeleteAccount_Faults(t *testing.T) {
	t.Run("at once", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil, auth.WithAccountDeletion(auth.AccountDeletion{}))
			_, tok := coreSignedIn(t, a)
			return func(context.Context) error { _, err := a.DeleteAccount(freshRequest(a, tok)); return err }
		})
	})
	t.Run("send link", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil, auth.WithAccountDeletion(auth.AccountDeletion{ConfirmByLink: true}))
			_, tok := coreSignedIn(t, a)
			return func(context.Context) error { _, err := a.DeleteAccount(freshRequest(a, tok)); return err }
		})
	})
	t.Run("confirm", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil, auth.WithAccountDeletion(auth.AccountDeletion{ConfirmByLink: true}))
			_, tok := coreSignedIn(t, a)
			if _, err := a.DeleteAccount(freshRequest(a, tok)); err != nil {
				t.Fatal(err)
			}
			link := e.mail.LastToken(t, a, alice)
			return func(ctx context.Context) error { return a.ConfirmDeleteAccount(ctx, link) }
		})
	})
}

// The email plugin words the confirmation itself only through the message's
// own default wording; this pins that a mail never goes out empty.
func TestDeleteAccount_MailHasWordingWithoutATemplate(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil, auth.WithAccountDeletion(auth.AccountDeletion{ConfirmByLink: true}))
	_, tok := coreSignedIn(t, a)
	if _, err := a.DeleteAccount(freshRequest(a, tok)); err != nil {
		t.Fatal(err)
	}
	m := e.mail.To(a, alice)[0]
	if m.Subject != "Confirm deleting your account" || !strings.Contains(m.Text, "delete your account") {
		t.Fatalf("mail = %+v", m)
	}
}

// Multi-session: several accounts on one device.

// deviceRequest is a browser request whose active session is active and
// whose device also holds the other tokens.
func deviceRequest(a *auth.Auth, active auth.Token, others ...auth.Token) context.Context {
	return a.WithRequest(context.Background(), auth.Request{
		Transport: auth.TransportHTTP, Credential: auth.CredentialCookie, Token: active, DeviceTokens: others,
		Client: auth.Client{Origin: testBaseURL},
	})
}

// issueOp is a stub sign-in operation: it creates a session for the user
// named in the input and issues it, like a password sign-in does, so the
// device cap can be exercised without a password plugin.
type issueRequest struct {
	UserID string `json:"userId"`
}

func issueOp(name string) (*auth.Op[issueRequest, auth.Done], auth.EndpointID) {
	id := auth.EndpointID(name + ".issue")
	return auth.Define(auth.OpInfo{ID: id, Kind: auth.Mutation, Require: auth.Public, Path: "/issue"},
		func(ctx context.Context, c *auth.Call, in issueRequest) (auth.Done, error) {
			s, tok, err := c.Auth.CreateSession(ctx, in.UserID, c.Client)
			if err != nil {
				return auth.Done{}, err
			}
			c.Effects.IssueSessionOf(s, tok)
			return auth.Done{OK: true}, nil
		}), id
}

// effectTokens returns the tokens of every effect of kind on the request.
func effectTokens(ctx context.Context, kind auth.EffectKind) []auth.Token {
	var out []auth.Token
	for _, ef := range auth.RequestEffects(ctx) {
		if ef.Kind == kind {
			out = append(out, ef.Token)
		}
	}
	return out
}

// secondUser is another user with a session, for a device holding two.
func secondUser(t *testing.T, a *auth.Auth, addr string) (auth.User, auth.Token) {
	t.Helper()
	ctx := context.Background()
	u := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{Name: "Bob"}))
	must[auth.Identity](t)(a.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: addr, Verified: true, Primary: true}))
	_, tok, err := a.CreateSession(ctx, u.ID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	return u, tok
}

func TestMultiSession_ListSwitchRevoke(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := coreAuth(t, e, nil, auth.WithMultiSession(0))
		ua, tokA := coreSignedIn(t, a)
		ub, tokB := secondUser(t, a, "bob@example.com")

		ctx := deviceRequest(a, tokA, tokB, tokB, "") // a duplicate and an empty token are ignored
		list, err := a.DeviceSessions(ctx)
		if err != nil || len(list.Sessions) != 2 || !list.Sessions[0].Active || list.Sessions[0].User.ID != ua.ID ||
			list.Sessions[1].Active || list.Sessions[1].User.ID != ub.ID {
			t.Fatalf("device sessions = %+v, %v", list, err)
		}
		if len(auth.RequestEffects(ctx)) != 0 {
			t.Fatalf("listing live sessions records no effect: %+v", auth.RequestEffects(ctx))
		}

		// Switch: the other token is issued again, so it becomes the active
		// cookie; the active one is accepted and changes nothing.
		ctx = deviceRequest(a, tokA, tokB)
		if err := a.SwitchDeviceSession(ctx, list.Sessions[1].ID); err != nil {
			t.Fatal(err)
		}
		if got := effectTokens(ctx, auth.EffectIssueSession); len(got) != 1 || got[0] != tokB {
			t.Fatalf("switch issued %v, want the other token", got)
		}
		ctx = deviceRequest(a, tokA, tokB)
		if err := a.SwitchDeviceSession(ctx, list.Sessions[0].ID); err != nil || len(auth.RequestEffects(ctx)) != 0 {
			t.Fatalf("switch to the active session: %v, effects %+v", err, auth.RequestEffects(ctx))
		}
		if err := a.SwitchDeviceSession(deviceRequest(a, tokA, tokB), "ses_nope"); !errors.Is(err, auth.ErrDeviceSessionNotFound) {
			t.Fatalf("switch to an unknown id: %v", err)
		}
		// A session the user holds elsewhere but this device does not is
		// not on this device.
		_, elsewhere, err := a.CreateSession(context.Background(), ub.ID, auth.Client{})
		if err != nil {
			t.Fatal(err)
		}
		s, _, _, _ := a.ResolveSession(context.Background(), elsewhere)
		if err := a.SwitchDeviceSession(deviceRequest(a, tokA, tokB), s.ID); !errors.Is(err, auth.ErrDeviceSessionNotFound) {
			t.Fatalf("switch to another device's session: %v", err)
		}

		// Revoke: the other session is gone and the device forgets its token.
		ctx = deviceRequest(a, tokA, tokB)
		if err := a.RevokeDeviceSession(ctx, list.Sessions[1].ID); err != nil {
			t.Fatal(err)
		}
		if got := effectTokens(ctx, auth.EffectForgetDeviceSession); len(got) != 1 || got[0] != tokB {
			t.Fatalf("revoke forgot %v, want the other token", got)
		}
		if _, _, _, err := a.ResolveSession(context.Background(), tokB); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("revoked session still opens: %v", err)
		}
		if err := a.RevokeDeviceSession(deviceRequest(a, tokA), list.Sessions[0].ID); !errors.Is(err, auth.ErrDeviceSessionNotFound) {
			t.Fatalf("revoking the active session here: %v, want ErrDeviceSessionNotFound (sign-out does it)", err)
		}

		// A token that stopped opening is dropped from the list and the
		// device is told to forget it.
		ctx = deviceRequest(a, tokA, tokB)
		list, err = a.DeviceSessions(ctx)
		if err != nil || len(list.Sessions) != 1 {
			t.Fatalf("after revoke: %+v %v", list, err)
		}
		if got := effectTokens(ctx, auth.EffectForgetDeviceSession); len(got) != 1 || got[0] != tokB {
			t.Fatalf("stale token: forgot %v", got)
		}
	})
}

func TestMultiSession_CapRefusesTheExtraSignIn(t *testing.T) {
	e := newFaultEnv(t)
	op, _ := issueOp(coreStubName)
	a := coreAuth(t, e.env, &coreStub{ops: []auth.Operation{op}}, auth.WithMultiSession(2))
	_, tokA := coreSignedIn(t, a)
	ub, tokB := secondUser(t, a, "bob@example.com")
	uc := must[auth.User](t)(a.CreateUser(context.Background(), auth.NewUser{Name: "Cy"}))
	before := len(must[[]auth.Session](t)(a.Sessions(context.Background(), uc.ID)))

	// Two held, a third refused; the refused session is rolled back.
	if _, err := op.Call(deviceRequest(a, tokA, tokB), issueRequest{UserID: uc.ID}); !errors.Is(err, auth.ErrTooManyDeviceSessions) {
		t.Fatalf("third sign-in: %v, want ErrTooManyDeviceSessions", err)
	}
	if after := len(must[[]auth.Session](t)(a.Sessions(context.Background(), uc.ID))); after != before {
		t.Fatalf("the refused sign-in left a session: %d → %d", before, after)
	}
	// One held: a second fits. A signed-out device: the first fits.
	ctx := deviceRequest(a, tokA)
	if _, err := op.Call(ctx, issueRequest{UserID: uc.ID}); err != nil {
		t.Fatalf("second sign-in: %v", err)
	}
	if _, err := op.Call(a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP}), issueRequest{UserID: uc.ID}); err != nil {
		t.Fatalf("first sign-in on an empty device: %v", err)
	}
	// Switching at the cap reissues a held token: no new session, allowed.
	s, _, _, _ := a.ResolveSession(context.Background(), tokB)
	if err := a.SwitchDeviceSession(deviceRequest(a, tokA, tokB), s.ID); err != nil {
		t.Fatalf("switch at the cap: %v", err)
	}
	_ = ub
	// Without the option there is no cap.
	freeOp, _ := issueOp(coreStubName)
	free := coreAuth(t, e.env, &coreStub{ops: []auth.Operation{freeOp}})
	_, fa := secondUser(t, free, "dave@example.com")
	_, fb := secondUser(t, free, "carol@example.com")
	if _, err := freeOp.Call(deviceRequest(free, fa, fb), issueRequest{UserID: uc.ID}); err != nil {
		t.Fatalf("without the option a third sign-in is fine: %v", err)
	}
}

func TestMultiSession_SignOutEndsEveryAccountOnTheDevice(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := coreAuth(t, e, nil, auth.WithMultiSession(0))
		_, tokA := coreSignedIn(t, a)
		_, tokB := secondUser(t, a, "bob@example.com")
		ctx := deviceRequest(a, tokA, tokB)
		if err := a.SignOut(ctx); err != nil {
			t.Fatal(err)
		}
		for _, tok := range []auth.Token{tokA, tokB} {
			if _, _, _, err := a.ResolveSession(context.Background(), tok); !errors.Is(err, auth.ErrSignedOut) {
				t.Fatalf("a device session survived sign-out: %v", err)
			}
		}
		if got := effectTokens(ctx, auth.EffectForgetDeviceSession); len(got) != 1 || got[0] != tokB {
			t.Fatalf("sign-out forgot %v", got)
		}

		// Without the option, sign-out ends the active session only, even
		// when a transport passes device tokens.
		plain := coreAuth(t, e, nil)
		_, pa := secondUser(t, plain, "dave@example.com")
		_, pb := secondUser(t, plain, "carol@example.com")
		if err := plain.SignOut(deviceRequest(plain, pa, pb)); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := plain.ResolveSession(context.Background(), pb); err != nil {
			t.Fatalf("by default the other account stays signed in: %v", err)
		}
	})
}

func TestMultiSession_Stateless(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil, auth.WithMultiSession(0), auth.WithStatelessSessions(sessKey))
	ua, tokA := coreSignedIn(t, a)
	ub, tokB := secondUser(t, a, "bob@example.com")
	list, err := a.DeviceSessions(deviceRequest(a, tokA, tokB))
	if err != nil || len(list.Sessions) != 2 || list.Sessions[0].User.ID != ua.ID || list.Sessions[1].User.ID != ub.ID {
		t.Fatalf("stateless list = %+v %v", list, err)
	}
	// Nothing to delete: the device forgets the token and that ends it here.
	ctx := deviceRequest(a, tokA, tokB)
	if err := a.RevokeDeviceSession(ctx, list.Sessions[1].ID); err != nil {
		t.Fatal(err)
	}
	if got := effectTokens(ctx, auth.EffectForgetDeviceSession); len(got) != 1 || got[0] != tokB {
		t.Fatalf("stateless revoke forgot %v", got)
	}
}

func TestMultiSession_WithACache(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil, auth.WithMultiSession(0), auth.WithSessionCache(auth.NewMemorySessionCache(10), 0))
	_, tokA := coreSignedIn(t, a)
	_, tokB := secondUser(t, a, "bob@example.com")
	// Warm the cache for B, then revoke B from A's device: the cached entry
	// must go with the row.
	if _, err := a.Session(freshRequest(a, tokB)); err != nil {
		t.Fatal(err)
	}
	list := must[auth.DeviceSessionsResult](t)(a.DeviceSessions(deviceRequest(a, tokA, tokB)))
	if err := a.RevokeDeviceSession(deviceRequest(a, tokA, tokB), list.Sessions[1].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Session(freshRequest(a, tokB)); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("the revoked account still answers from the cache: %v", err)
	}
}

func TestMultiSession_Faults(t *testing.T) {
	setup := func(t *testing.T, e *faultEnv, opts ...auth.Option) (*auth.Auth, auth.Token, auth.Token, string) {
		t.Helper()
		a := coreAuth(t, e.env, nil, append([]auth.Option{auth.WithMultiSession(0)}, opts...)...)
		_, tokA := coreSignedIn(t, a)
		_, tokB := secondUser(t, a, "bob@example.com")
		s, _, _, err := a.ResolveSession(context.Background(), tokB)
		if err != nil {
			t.Fatal(err)
		}
		return a, tokA, tokB, s.ID
	}
	t.Run("list", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, tokA, tokB, _ := setup(t, e)
			return func(context.Context) error { _, err := a.DeviceSessions(deviceRequest(a, tokA, tokB)); return err }
		})
	})
	t.Run("switch", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, tokA, tokB, id := setup(t, e)
			return func(context.Context) error { return a.SwitchDeviceSession(deviceRequest(a, tokA, tokB), id) }
		})
	})
	t.Run("revoke", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, tokA, tokB, id := setup(t, e)
			return func(context.Context) error { return a.RevokeDeviceSession(deviceRequest(a, tokA, tokB), id) }
		})
	})
	t.Run("sign-out", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, tokA, tokB, _ := setup(t, e)
			return func(context.Context) error { return a.SignOut(deviceRequest(a, tokA, tokB)) }
		})
	})
	t.Run("capped sign-in", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			op, _ := issueOp(coreStubName)
			a := coreAuth(t, e.env, &coreStub{ops: []auth.Operation{op}}, auth.WithMultiSession(3))
			_, tokA := coreSignedIn(t, a)
			_, tokB := secondUser(t, a, "bob@example.com")
			uc := must[auth.User](t)(a.CreateUser(context.Background(), auth.NewUser{Name: "Cy"}))
			return func(context.Context) error {
				_, err := op.Call(deviceRequest(a, tokA, tokB), issueRequest{UserID: uc.ID})
				return err
			}
		})
	})
}

// Deferred session refresh and the FreshSignIn cache bypass.

func TestDeferredRefresh_ReadsNeverSlide(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := coreAuth(t, e, nil, auth.WithDeferredSessionRefresh())
		_, tok := coreSignedIn(t, a)
		first := must[auth.SessionResult](t)(a.Session(freshRequest(a, tok)))
		if first.NeedsRefresh {
			t.Fatal("a fresh session needs no refresh")
		}
		e.clock.Advance(2 * 24 * time.Hour) // past the default RefreshAfter of a day
		read := must[auth.SessionResult](t)(a.Session(freshRequest(a, tok)))
		if !read.NeedsRefresh || !read.ExpiresAt.Equal(first.ExpiresAt) {
			t.Fatalf("a read under deferred refresh: needsRefresh=%v expires %v → %v", read.NeedsRefresh, first.ExpiresAt, read.ExpiresAt)
		}
		// The refresh route slides it and the cookie learns the new expiry.
		ctx := freshRequest(a, tok)
		after := must[auth.SessionResult](t)(a.RefreshSession(ctx))
		if !after.ExpiresAt.After(first.ExpiresAt) || after.NeedsRefresh {
			t.Fatalf("refresh: %+v (was %v)", after, first.ExpiresAt)
		}
		if got := effectTokens(ctx, auth.EffectIssueSession); len(got) != 1 || got[0] != tok {
			t.Fatalf("refresh must reissue the cookie: %v", got)
		}
		if again := must[auth.SessionResult](t)(a.Session(freshRequest(a, tok))); again.NeedsRefresh {
			t.Fatal("after the refresh nothing is due")
		}
		// A mutation slides on its own, as before.
		e.clock.Advance(2 * 24 * time.Hour)
		if _, err := a.UpdateProfile(freshRequest(a, tok), auth.ProfileRequest{}); err != nil {
			t.Fatal(err)
		}
		if got := must[auth.SessionResult](t)(a.Session(freshRequest(a, tok))); !got.ExpiresAt.After(after.ExpiresAt) || got.NeedsRefresh {
			t.Fatalf("a mutation under deferred refresh: %+v", got)
		}

		// The default slides on a read and never reports needsRefresh.
		plain := coreAuth(t, e, nil)
		_, ptok := secondUser(t, plain, "dave@example.com")
		p0 := must[auth.SessionResult](t)(plain.Session(freshRequest(plain, ptok)))
		e.clock.Advance(2 * 24 * time.Hour)
		p1 := must[auth.SessionResult](t)(plain.Session(freshRequest(plain, ptok)))
		if p1.NeedsRefresh || !p1.ExpiresAt.After(p0.ExpiresAt) {
			t.Fatalf("by default a read slides: %+v → %+v", p0, p1)
		}
	})
}

func TestDeferredRefresh_Faults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		a := coreAuth(t, e.env, nil, auth.WithDeferredSessionRefresh())
		_, tok := coreSignedIn(t, a)
		e.clock.Advance(2 * 24 * time.Hour)
		return func(context.Context) error { _, err := a.RefreshSession(freshRequest(a, tok)); return err }
	})
}

func TestFreshSignIn_BypassesTheSessionCache(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := coreAuth(t, e, nil, auth.WithAccountDeletion(auth.AccountDeletion{}), auth.WithSessionCache(auth.NewMemorySessionCache(10), 0))
		u, tok := coreSignedIn(t, a)
		// Warm the cache, then end the session behind its back.
		if _, err := a.Session(freshRequest(a, tok)); err != nil {
			t.Fatal(err)
		}
		if err := a.SessionStore().DeleteUser(context.Background(), u.ID, ""); err != nil {
			t.Fatal(err)
		}
		// A SignedIn read still answers from the cache: that is the cache's
		// documented trade.
		if _, err := a.Session(freshRequest(a, tok)); err != nil {
			t.Fatalf("a cached read after revocation: %v (the cache answers until its TTL)", err)
		}
		// A FreshSignIn operation does not: it is refused, the entry dropped,
		// and the client told to clear its copy.
		ctx := freshRequest(a, tok)
		if _, err := a.DeleteAccount(ctx); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("FreshSignIn on a revoked, cached session: %v, want ErrSignedOut", err)
		}
		if _, err := a.Session(freshRequest(a, tok)); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("the cache entry must be gone after the bypass found nothing: %v", err)
		}
		if _, err := a.User(context.Background(), u.ID); err != nil {
			t.Fatalf("the refused call deleted the account: %v", err)
		}

		// A live cached session passes the bypass and keeps working.
		live, tok2 := secondUser(t, a, "dave@example.com")
		if _, err := a.Session(freshRequest(a, tok2)); err != nil {
			t.Fatal(err)
		}
		ctx = freshRequest(a, tok2)
		if _, err := a.DeleteAccount(ctx); err != nil {
			t.Fatalf("FreshSignIn on a live cached session: %v", err)
		}
		accountGone(t, a, live.ID)
	})
}

func TestFreshSignIn_Faults_WithACache(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		a := coreAuth(t, e.env, nil, auth.WithAccountDeletion(auth.AccountDeletion{}), auth.WithSessionCache(auth.NewMemorySessionCache(10), 0))
		_, tok := coreSignedIn(t, a)
		if _, err := a.Session(freshRequest(a, tok)); err != nil {
			t.Fatal(err)
		}
		return func(context.Context) error { _, err := a.DeleteAccount(freshRequest(a, tok)); return err }
	})
}

// The schema check.

func TestCheckSchema_FindsWhatTheDatabaseLacks(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		fresh, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithRateStore(auth.NewMemoryRateStore(e.clock.Now)),
			auth.WithPlugins(e.emailPlugin(), e.passwordPlugin()))
		if err != nil {
			t.Fatal(err)
		}
		r := must[auth.SchemaReport](t)(fresh.CheckSchema(ctx))
		if r.OK() || len(r.PendingMigrations) == 0 || len(r.MissingTables) == 0 || !slices.Contains(r.MissingTables, tbl(auth.TableNameUser)) {
			t.Fatalf("an empty database: %+v", r)
		}
		if err := fresh.RequireSchema(ctx); !errors.Is(err, auth.ErrSchemaBehind) || !strings.Contains(err.Error(), tbl(auth.TableNameUser)) {
			t.Fatalf("RequireSchema on an empty database: %v", err)
		}
		if _, err := fresh.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		if r := must[auth.SchemaReport](t)(fresh.CheckSchema(ctx)); !r.OK() {
			t.Fatalf("after migrate: %s", r.Error())
		}
		if err := fresh.RequireSchema(ctx); err != nil {
			t.Fatalf("RequireSchema after migrate: %v", err)
		}
		// A hand-edited schema: a dropped column is found although the
		// ledger says every migration ran.
		if _, err := e.db.ExecContext(ctx, "ALTER TABLE "+tbl(auth.TableNameUser)+" DROP COLUMN "+auth.ColUserSessionsValidAfter); err != nil {
			t.Fatalf("drop column: %v", err)
		}
		r = must[auth.SchemaReport](t)(fresh.CheckSchema(ctx))
		if r.OK() || len(r.PendingMigrations) != 0 || !slices.Contains(r.MissingColumns, tbl(auth.TableNameUser)+"."+auth.ColUserSessionsValidAfter) {
			t.Fatalf("after dropping a column: %+v", r)
		}
		if _, err := e.db.ExecContext(ctx, "DROP TABLE "+tbl(auth.TableNameVerification)); err != nil {
			t.Fatalf("drop table: %v", err)
		}
		r = must[auth.SchemaReport](t)(fresh.CheckSchema(ctx))
		if !slices.Contains(r.MissingTables, tbl(auth.TableNameVerification)) {
			t.Fatalf("after dropping a table: %+v", r)
		}
	})
}

func TestCheckSchema_Faults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		a := coreAuth(t, e.env, nil)
		return func(ctx context.Context) error { _, err := a.CheckSchema(ctx); return err }
	})
}

func TestCLI_MigrateCheck(t *testing.T) {
	e := newFaultEnv(t)
	a, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithRateStore(auth.NewMemoryRateStore(e.clock.Now)), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin()))
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string) {
		var out, errb bytes.Buffer
		code := authcli.Main(context.Background(), a, args, &out, &errb)
		return code, out.String() + errb.String()
	}
	if code, out := run("migrate", "check"); code != authcli.ExitFailed || !strings.Contains(out, "pending\t") || !strings.Contains(out, "missing table\t"+tbl(auth.TableNameUser)) {
		t.Fatalf("check on an empty database: %d %s", code, out)
	}
	if code, out := run("migrate"); code != authcli.ExitOK {
		t.Fatalf("migrate: %d %s", code, out)
	}
	if code, out := run("migrate", "check"); code != authcli.ExitOK || !strings.Contains(out, "schema ok") {
		t.Fatalf("check after migrate: %d %s", code, out)
	}
	if _, err := e.db.Exec("ALTER TABLE " + tbl(auth.TableNameUser) + " DROP COLUMN " + auth.ColUserName); err != nil {
		t.Fatal(err)
	}
	if code, out := run("migrate", "check"); code != authcli.ExitFailed || !strings.Contains(out, "missing column\t"+tbl(auth.TableNameUser)+"."+auth.ColUserName) {
		t.Fatalf("check after a dropped column: %d %s", code, out)
	}
	e.f.arm(1)
	code, out := run("migrate", "check")
	e.f.disarm()
	if code != authcli.ExitFailed || !strings.Contains(out, "auth migrate:") {
		t.Fatalf("check with a failing database: %d %s", code, out)
	}
}

// The revoked-session archive.

func TestSessionArchive_KeepsRevokedRows(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		a := coreAuth(t, e, nil, auth.WithSessionArchive())
		u, tok := coreSignedIn(t, a)
		_, other, err := a.CreateSession(ctx, u.ID, auth.Client{UserAgent: "phone"})
		if err != nil {
			t.Fatal(err)
		}
		first, _, _, _ := a.ResolveSession(ctx, tok)
		if err := a.SignOut(freshRequest(a, tok)); err != nil {
			t.Fatal(err)
		}
		// The session is over for every lookup and list, and the row stays.
		if _, _, _, err := a.ResolveSession(ctx, tok); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("a revoked session still opens: %v", err)
		}
		if list := must[[]auth.Session](t)(a.Sessions(ctx, u.ID)); len(list) != 1 {
			t.Fatalf("live sessions after sign-out: %+v", list)
		}
		revoked := must[[]auth.Session](t)(a.RevokedSessions(ctx, u.ID))
		if len(revoked) != 1 || revoked[0].ID != first.ID || revoked[0].RevokedAt == nil || !revoked[0].RevokedAt.Equal(e.clock.Now()) {
			t.Fatalf("revoked sessions: %+v", revoked)
		}
		firstRevokedAt := *revoked[0].RevokedAt
		// A refresh cannot revive it.
		e.clock.Advance(2 * 24 * time.Hour)
		if moved, err := a.SessionStore().Touch(ctx, first.ID, e.clock.Now().Add(time.Hour), e.clock.Now()); err != nil || moved {
			t.Fatalf("touch of a revoked row: moved=%v %v", moved, err)
		}
		// Sign out everywhere archives the rest; a second revocation keeps
		// the first time.
		if err := a.DeleteUserSessions(ctx, u.ID, ""); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := a.ResolveSession(ctx, other); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("the other device after sign-out everywhere: %v", err)
		}
		revoked = must[[]auth.Session](t)(a.RevokedSessions(ctx, u.ID))
		if len(revoked) != 2 || !revoked[1].RevokedAt.Equal(firstRevokedAt) {
			t.Fatalf("after sign-out everywhere: %+v", revoked)
		}
		// Sweep keeps them within the retention and removes them after.
		if n := must[auth.SweepResult](t)(a.Sweep(ctx, auth.DefaultSweepRetention)); len(must[[]auth.Session](t)(a.RevokedSessions(ctx, u.ID))) != 2 {
			t.Fatalf("sweep within retention removed revoked rows: %v", n)
		}
		e.clock.Advance(auth.DefaultSweepRetention + time.Hour)
		res := must[auth.SweepResult](t)(a.Sweep(ctx, auth.DefaultSweepRetention))
		if left := must[[]auth.Session](t)(a.RevokedSessions(ctx, u.ID)); len(left) != 0 || res[auth.CorePluginName+"."+auth.TableNameSession] < 2 {
			t.Fatalf("sweep after retention: left %+v, swept %v", left, res)
		}

		// Without the option sign-out deletes the row, as before.
		plain := coreAuth(t, e, nil)
		pu, ptok := secondUser(t, plain, "dave@example.com")
		if err := plain.SignOut(freshRequest(plain, ptok)); err != nil {
			t.Fatal(err)
		}
		if revoked := must[[]auth.Session](t)(plain.RevokedSessions(ctx, pu.ID)); len(revoked) != 0 {
			t.Fatalf("by default nothing is kept: %+v", revoked)
		}
	})
}

func TestSessionArchive_Faults(t *testing.T) {
	t.Run("sign-out", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil, auth.WithSessionArchive())
			_, tok := coreSignedIn(t, a)
			return func(context.Context) error { return a.SignOut(freshRequest(a, tok)) }
		})
	})
	t.Run("list revoked", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil, auth.WithSessionArchive())
			u, _ := coreSignedIn(t, a)
			return func(ctx context.Context) error { _, err := a.RevokedSessions(ctx, u.ID); return err }
		})
	})
	t.Run("sweep", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil, auth.WithSessionArchive())
			return func(ctx context.Context) error { _, err := a.Sweep(ctx, auth.DefaultSweepRetention); return err }
		})
	})
}

// Failure paths that need a cache or a store that fails on demand.

// failingCache is a SessionCache whose Drop fails, in front of a memory cache.
type failingCache struct {
	auth.SessionCache
	dropErr error
}

func (c failingCache) Drop(ctx context.Context, k auth.CacheKey) error {
	if c.dropErr != nil {
		return c.dropErr
	}
	return c.SessionCache.Drop(ctx, k)
}

// failingStore is a SessionStore whose DeleteUser fails.
type failingStore struct {
	auth.SessionStore
	err error
}

func (s failingStore) DeleteUser(context.Context, string, string) error { return s.err }

func TestR2_CacheAndStoreFailuresReachTheCaller(t *testing.T) {
	e := newFaultEnv(t)
	boom := errors.New("cache down")
	a := coreAuth(t, e.env, nil, auth.WithAccountDeletion(auth.AccountDeletion{}), auth.WithMultiSession(0), auth.WithSessionCache(failingCache{SessionCache: auth.NewMemorySessionCache(10), dropErr: boom}, 0))
	u, tok := coreSignedIn(t, a)
	// Account deletion forgets the session after deleting it: the drop
	// failure is reported (the row is gone, which the next request shows).
	if _, err := a.DeleteAccount(freshRequest(a, tok)); !errors.Is(err, boom) {
		t.Fatalf("delete with a failing cache: %v", err)
	}
	// Revoking a device session drops its cache entry.
	_, tokA := secondUser(t, a, "dave@example.com")
	_, tokB := secondUser(t, a, "carol@example.com")
	s, _, _, _ := a.ResolveSession(context.Background(), tokB)
	if err := a.RevokeDeviceSession(deviceRequest(a, tokA, tokB), s.ID); !errors.Is(err, boom) {
		t.Fatalf("revoke with a failing cache: %v", err)
	}
	_ = u

	// A FreshSignIn call on a cached session that the store no longer has
	// drops the entry; the drop failure is reported, not swallowed.
	b := coreAuth(t, e.env, nil, auth.WithAccountDeletion(auth.AccountDeletion{}), auth.WithSessionCache(failingCache{SessionCache: auth.NewMemorySessionCache(10), dropErr: boom}, 0))
	v, vtok := secondUser(t, b, "erin@example.com")
	if _, err := b.Session(freshRequest(b, vtok)); err != nil {
		t.Fatal(err)
	}
	if err := b.SessionStore().DeleteUser(context.Background(), v.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := b.DeleteAccount(freshRequest(b, vtok)); !errors.Is(err, boom) {
		t.Fatalf("fresh bypass with a failing cache: %v", err)
	}

	// Deleting a user whose sessions live in a store outside the database
	// reports the store's failure and rolls the deletion back.
	c := coreAuth(t, e.env, nil, auth.WithAccountDeletion(auth.AccountDeletion{}), auth.WithSessionStore(failingStore{SessionStore: auth.NewMemorySessionStore(), err: boom}))
	w, _ := secondUser(t, c, "frank@example.com")
	if err := c.DeleteUser(context.Background(), w.ID); !errors.Is(err, boom) {
		t.Fatalf("delete user with a failing store: %v", err)
	}
	if _, err := c.User(context.Background(), w.ID); err != nil {
		t.Fatalf("the failed deletion must leave the user: %v", err)
	}
}

func TestFreshSignIn_CachedSessionDueForRefreshIsReissued(t *testing.T) {
	e := newFaultEnv(t)
	cfg := auth.DefaultSessionConfig
	cfg.RefreshAfter = time.Minute
	a := coreAuth(t, e.env, nil, auth.WithAccountDeletion(auth.AccountDeletion{}), auth.WithSession(cfg), auth.WithSessionCache(auth.NewMemorySessionCache(10), auth.MaxSessionCacheTTL))
	_, tok := coreSignedIn(t, a)
	if _, err := a.Session(freshRequest(a, tok)); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(2 * time.Minute) // the refresh is due, the cache entry is not expired
	ctx := freshRequest(a, tok)
	if _, err := a.DeleteAccount(ctx); err != nil {
		t.Fatal(err)
	}
	// The bypass read the store, slid the expiry and reissued the cookie
	// before the deletion cleared it.
	if got := effectTokens(ctx, auth.EffectIssueSession); len(got) != 1 || got[0] != tok {
		t.Fatalf("the refreshed session must be reissued: %v", got)
	}
}

func TestMultiSession_RevokeTheSecondOfTwoOthersAndCapWithoutARequest(t *testing.T) {
	e := newFaultEnv(t)
	op, _ := issueOp(coreStubName)
	a := coreAuth(t, e.env, &coreStub{ops: []auth.Operation{op}}, auth.WithMultiSession(2))
	_, tokA := coreSignedIn(t, a)
	_, tokB := secondUser(t, a, "dave@example.com")
	_, tokC := secondUser(t, a, "carol@example.com")
	sc, _, _, _ := a.ResolveSession(context.Background(), tokC)
	if err := a.RevokeDeviceSession(deviceRequest(a, tokA, tokB, tokC), sc.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := a.ResolveSession(context.Background(), tokB); err != nil {
		t.Fatalf("the first other session must survive: %v", err)
	}
	// A Go call with no request has no device: the cap does not apply.
	uc := must[auth.User](t)(a.CreateUser(context.Background(), auth.NewUser{Name: "Cy"}))
	if _, err := op.Call(context.Background(), issueRequest{UserID: uc.ID}); err != nil {
		t.Fatalf("sign-in from Go without a request: %v", err)
	}
}

func TestCheckSchema_ReportsAChangedMigration(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil)
	if _, err := e.db.Exec("UPDATE " + tbl(auth.TableNameMigrations) + " SET checksum = 'edited' WHERE name = '0001_core_tables'"); err != nil {
		t.Fatal(err)
	}
	r := must[auth.SchemaReport](t)(a.CheckSchema(context.Background()))
	if r.OK() || len(r.ChangedMigrations) != 1 || r.ChangedMigrations[0] != auth.CorePluginName+"/0001_core_tables" {
		t.Fatalf("report = %+v", r)
	}
	var out, errb bytes.Buffer
	if code := authcli.Main(context.Background(), a, []string{"migrate", "check"}, &out, &errb); code != authcli.ExitFailed || !strings.Contains(out.String(), "CHANGED\tcore/0001_core_tables") {
		t.Fatalf("migrate check: %d %s%s", code, out.String(), errb.String())
	}
}

// Bulk import.

func TestImportUsers_WritesThroughTheCoreAndSendsNothing(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		a := coreAuth(t, e, nil)
		then := e.clock.Now().Add(-365 * 24 * time.Hour)
		res, err := a.ImportUsers(ctx, []auth.ImportUser{
			{ID: "usr_legacy_1", Name: "Ada", CreatedAt: then, Identities: []auth.ImportIdentity{{Kind: email.KindEmail, Value: "Ada@Example.com", Verified: true, Primary: true}}},
			{Name: "Bob", Identities: []auth.ImportIdentity{{Kind: email.KindEmail, Value: "bob@example.com"}}},
			{ID: "usr_legacy_1", Name: "Dup"}, // id taken
			{Name: "Eve", Identities: []auth.ImportIdentity{{Kind: email.KindEmail, Value: "ada@example.com", Verified: true}}}, // address taken
			{Name: "Bad", Identities: []auth.ImportIdentity{{Kind: email.KindEmail, Value: "not an address"}}},
		})
		if !errors.Is(err, auth.ErrImportFailed) || len(res) != 5 {
			t.Fatalf("ImportUsers: %v, %d results", err, len(res))
		}
		if res[0].Err != nil || res[0].User.ID != "usr_legacy_1" || !res[0].User.CreatedAt.Equal(then) {
			t.Fatalf("row 0: %+v", res[0])
		}
		if res[1].Err != nil || res[1].User.ID == "" || res[1].User.Name != "Bob" {
			t.Fatalf("row 1: %+v", res[1])
		}
		if !errors.Is(res[2].Err, auth.ErrUserExists) || !errors.Is(res[3].Err, auth.ErrIdentityTaken) || !errors.Is(res[4].Err, auth.ErrIdentifierInvalid) {
			t.Fatalf("rows 2-4: %v %v %v", res[2].Err, res[3].Err, res[4].Err)
		}
		for _, i := range []int{2, 3, 4} {
			if res[i].Index != i || res[i].User.ID != "" {
				t.Fatalf("a failed row carries no user: %+v", res[i])
			}
		}
		// Failed rows left nothing: Eve and Bad have no user.
		ids := must[[]auth.Identity](t)(a.Identities(ctx, "usr_legacy_1"))
		if len(ids) != 1 || !ids[0].Verified() || !ids[0].IsPrimary || ids[0].Value != "ada@example.com" || ids[0].ValueRaw != "Ada@Example.com" {
			t.Fatalf("Ada's identities: %+v", ids)
		}
		if n := len(e.mail.To(a, "bob@example.com")) + len(e.mail.To(a, "ada@example.com")); n != 0 {
			t.Fatalf("an import sent %d mail(s)", n)
		}
		// The email plugin's hooks ran: the primary address column is set.
		var primary *string
		q := a.Select().Columns(sqlb.Bind(sqlb.Col[*string](auth.TableUser, email.ColPrimaryEmail), &primary)).From(auth.TableUser).Where(sqlb.Eq(auth.UserID, "usr_legacy_1"))
		if err := a.One(ctx, q); err != nil || primary == nil || *primary != "ada@example.com" {
			t.Fatalf("primary email after import: %v %v", primary, err)
		}
		// A clean import returns no error.
		if res, err := a.ImportUsers(ctx, []auth.ImportUser{{Name: "Zed"}}); err != nil || len(res) != 1 || res[0].Err != nil {
			t.Fatalf("clean import: %v %+v", err, res)
		}
	})
}

func TestImportUsers_Faults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		a := coreAuth(t, e.env, nil)
		return func(ctx context.Context) error {
			res, err := a.ImportUsers(ctx, []auth.ImportUser{{Name: "Ada", Identities: []auth.ImportIdentity{{Kind: email.KindEmail, Value: alice, Verified: true}}}})
			if err == nil && len(res) == 1 && res[0].Err != nil {
				return res[0].Err
			}
			return err
		}
	})
}

func TestQuiet_DropsDeliveries(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil)
	_, idn := coreUser(t, a)
	before := len(e.mail.To(a, alice))
	if err := a.Deliver(auth.Quiet(context.Background()), idn, auth.Message{Purpose: auth.PurposeWelcome}); err != nil {
		t.Fatal(err)
	}
	if n := len(e.mail.To(a, alice)); n != before {
		t.Fatalf("a quiet Deliver sent mail: %d → %d", before, n)
	}
	if err := a.Deliver(context.Background(), idn, auth.Message{Purpose: auth.PurposeWelcome}); err != nil {
		t.Fatal(err)
	}
	if n := len(e.mail.To(a, alice)); n != before+1 {
		t.Fatalf("a plain Deliver after a quiet one: %d → %d, want one more", before, n)
	}
}

// Core additions for the other round-2 plugins that need a database.

func TestRotateSessionToken_KeepsTheRowAndEndsTheOldToken(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		for name, opts := range map[string][]auth.Option{
			"sql":       nil,
			"cache":     {auth.WithSessionCache(auth.NewMemorySessionCache(10), 0)},
			"memory":    {auth.WithSessionStore(auth.NewMemorySessionStore())},
			"stateless": {auth.WithStatelessSessions(sessKey)},
		} {
			t.Run(name, func(t *testing.T) {
				a := coreAuth(t, e, nil, opts...)
				u, tok := secondUser(t, a, name+"@example.com")
				ctx := freshRequest(a, tok)
				before := must[auth.SessionResult](t)(a.Session(ctx)) // resolves (and caches) the session
				var rotated auth.Token
				hook := auth.OperationHook{Match: []auth.EndpointID{auth.EndpointSession}, After: func(ctx context.Context, c *auth.Call, _ any) error {
					var err error
					rotated, err = a.RotateSessionToken(ctx, c)
					return err
				}}
				b := coreAuth(t, e, nil, append(append([]auth.Option{}, opts...), auth.WithOperationHooks(hook))...)
				if _, err := b.Session(freshRequest(b, tok)); err != nil {
					t.Fatal(err)
				}
				if rotated == "" || rotated == tok {
					t.Fatal("a new token is returned")
				}
				s, _, _, err := b.ResolveSession(context.Background(), rotated)
				if err != nil || s.UserID != u.ID || !s.ExpiresAt.Equal(before.ExpiresAt) {
					t.Fatalf("the rotated token: %+v %v (expiry was %v)", s, err, before.ExpiresAt)
				}
				if name != "stateless" {
					if _, _, _, err := b.ResolveSession(context.Background(), tok); !errors.Is(err, auth.ErrSignedOut) {
						t.Fatalf("the old token still opens: %v", err)
					}
					if _, err := b.Session(freshRequest(b, tok)); !errors.Is(err, auth.ErrSignedOut) {
						t.Fatalf("the old token answers through the request path (cache): %v", err)
					}
				}
			})
		}
	})
}

func TestRotateSessionToken_Faults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		var rotateErr error
		hook := auth.OperationHook{Match: []auth.EndpointID{auth.EndpointSession}, After: func(ctx context.Context, c *auth.Call, _ any) error {
			_, rotateErr = c.Auth.RotateSessionToken(ctx, c)
			return rotateErr
		}}
		a := coreAuth(t, e.env, nil, auth.WithOperationHooks(hook))
		_, tok := coreSignedIn(t, a)
		return func(context.Context) error { _, err := a.Session(freshRequest(a, tok)); return err }
	})
}

func TestPeekCode_MatchesWithoutSpendingAndCountsWrongGuesses(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		a := coreAuth(t, e, nil)
		code := must[string](t)(a.IssueCode(ctx, corePurpose, "subject", time.Hour))
		if err := a.PeekCode(ctx, corePurpose, "subject", code, 3); err != nil {
			t.Fatalf("peek the right code: %v", err)
		}
		if err := a.PeekCode(ctx, corePurpose, "subject", code, 3); err != nil {
			t.Fatalf("peek again, the row is still there: %v", err)
		}
		for i := 0; i < 3; i++ {
			if err := a.PeekCode(ctx, corePurpose, "subject", "000000", 3); !errors.Is(err, auth.ErrCodeInvalid) {
				t.Fatalf("wrong guess %d: %v", i, err)
			}
		}
		// Three wrong peeks spent the attempts: the right code is refused.
		if err := a.CheckCode(ctx, corePurpose, "subject", code, 3); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("after the attempts: %v, want ErrCodeInvalid", err)
		}
		// A fresh code: peek, then spend, then it is gone.
		code = must[string](t)(a.IssueCode(ctx, corePurpose, "other", time.Hour))
		if err := a.PeekCode(ctx, corePurpose, "other", code, 0); err != nil {
			t.Fatal(err)
		}
		if err := a.CheckCode(ctx, corePurpose, "other", code, 0); err != nil {
			t.Fatal(err)
		}
		if err := a.PeekCode(ctx, corePurpose, "other", code, 0); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("a spent code: %v", err)
		}
	})
}

func TestPeekCode_Faults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		a := coreAuth(t, e.env, nil)
		code := must[string](t)(a.IssueCode(context.Background(), corePurpose, "subject", time.Hour))
		return func(ctx context.Context) error { return a.PeekCode(ctx, corePurpose, "subject", code, 3) }
	})
}

func TestOperationOf_ReachesDataHooks(t *testing.T) {
	e := newFaultEnv(t)
	var seen []auth.EndpointID
	a := coreAuth(t, e.env, nil, auth.WithDataHooks(auth.DataHooks{Session: auth.TableHooks[auth.Session]{
		AfterCreate: func(ctx context.Context, _ sqlb.DBTX, _ *auth.Session) error {
			if info, ok := auth.OperationOf(ctx); ok {
				seen = append(seen, info.ID)
			} else {
				seen = append(seen, "")
			}
			return nil
		},
	}}))
	u, _ := coreUser(t, a)
	// A direct Go call: no operation.
	if _, _, err := a.CreateSession(context.Background(), u.ID, auth.Client{}); err != nil {
		t.Fatal(err)
	}
	// Through an operation: the hook sees which one.
	op, _ := issueOp(coreStubName)
	b := coreAuth(t, e.env, &coreStub{ops: []auth.Operation{op}}, auth.WithDataHooks(auth.DataHooks{Session: auth.TableHooks[auth.Session]{
		AfterCreate: func(ctx context.Context, _ sqlb.DBTX, _ *auth.Session) error {
			info, _ := auth.OperationOf(ctx)
			seen = append(seen, info.ID)
			return nil
		},
	}}))
	if _, err := op.Call(b.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP}), issueRequest{UserID: u.ID}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] != "" || seen[1] != auth.EndpointID(coreStubName+".issue") {
		t.Fatalf("seen = %v", seen)
	}
}

func TestSignedInOrPending_SeesBothSessions(t *testing.T) {
	e := newFaultEnv(t)
	var got []bool
	op := auth.Define(auth.OpInfo{ID: auth.EndpointID(coreStubName + ".both"), Kind: auth.Mutation, Require: auth.SignedInOrPending, Path: "/both"},
		func(_ context.Context, c *auth.Call, _ struct{}) (auth.Done, error) {
			if c.User == nil {
				return auth.Done{}, errors.New("no user")
			}
			got = append(got, c.Session.SecondFactorPending)
			return auth.Done{OK: true}, nil
		})
	a := coreAuth(t, e.env, &coreStub{second: true, ops: []auth.Operation{op}})
	u, pendingTok := coreSignedIn(t, a) // the stub requires a second factor: pending
	if _, err := op.Call(freshRequest(a, pendingTok), struct{}{}); err != nil {
		t.Fatalf("pending session: %v", err)
	}
	_, fullTok, err := a.CreateMultiFactorSession(context.Background(), u.ID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Call(freshRequest(a, fullTok), struct{}{}); err != nil {
		t.Fatalf("full session: %v", err)
	}
	if len(got) != 2 || !got[0] || got[1] {
		t.Fatalf("pending flags = %v, want [true false]", got)
	}
}

func TestSignedInOrPending_RefusesAnAPIKey(t *testing.T) {
	e := newFaultEnv(t)
	op := auth.Define(auth.OpInfo{ID: auth.EndpointID(coreStubName + ".both"), Kind: auth.Mutation, Require: auth.SignedInOrPending, Path: "/both"},
		func(context.Context, *auth.Call, struct{}) (auth.Done, error) { return auth.Done{OK: true}, nil })
	em, pw, ak := e.emailPlugin(), e.passwordPlugin(), apikey.New(apikey.Scopes("orders:read"))
	a := e.newAuth(t, nil, em, pw, ak, &coreStub{name: coreStubName, ops: []auth.Operation{op}})
	up := signUpVerified(t, e.env, a, pw, em)
	made := must[apikey.CreateResult](t)(ak.Create(request(a, up.Token), apikey.CreateRequest{Name: "ci", Scopes: []string{"orders:read"}, ExpiresInDays: 1}))
	keyCtx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialBearer, Token: auth.Token(made.Secret)})
	if _, err := op.Call(keyCtx, struct{}{}); !errors.Is(err, auth.ErrAPIKeyRefused) {
		t.Fatalf("an API key on a SignedInOrPending operation: %v, want ErrAPIKeyRefused", err)
	}
}
