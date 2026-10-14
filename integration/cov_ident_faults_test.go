package integration

import (
	"context"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/username"
)

// identNumber is the phone number the ident fault sweeps use.
const identNumber = "+15550100100"

// identSweep is one operation of an identifier plugin under sweepFaults.
type identSweep struct {
	name  string
	setup func(t *testing.T, e *faultEnv) func(ctx context.Context) error
}

// identRun sweeps every case as a subtest.
func identRun(t *testing.T, cases []identSweep) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { sweepFaults(t, c.setup) })
	}
}

// identEmailAuth wires the email plugin with opts beside password, on a
// database that fails on demand.
func identEmailAuth(t *testing.T, e *faultEnv, opts ...email.Option) (*auth.Auth, *email.Plugin) {
	t.Helper()
	em := e.emailPlugin(opts...)
	return e.newAuth(t, nil, em, e.passwordPlugin()), em
}

// identWithWork gives the user of tok a second address, verified when
// verified is set.
func identWithWork(t *testing.T, e *faultEnv, a *auth.Auth, em *email.Plugin, tok auth.Token, verified bool) {
	t.Helper()
	if err := em.Add(request(a, tok), identWork); err != nil {
		t.Fatal(err)
	}
	if verified {
		if _, err := em.Verify(anon(a), identLink(t, e.env, a, identWork, email.DefaultVerifyPage)); err != nil {
			t.Fatal(err)
		}
	}
}

// TestIdentFaults_Email: every email operation surfaces every database failure
// on each of its paths, instead of reporting success for work not done.
func TestIdentFaults_Email(t *testing.T) {
	identRun(t, []identSweep{
		{"verify first address with welcome", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.Welcome())
			uid, _ := identUser(t, a, "")
			must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: uid, Kind: email.KindEmail, Raw: alice}))
			tok := identLink(t, e.env, a, alice, email.DefaultVerifyPage)
			return func(context.Context) error { _, err := em.Verify(anon(a), tok); return err }
		}},
		{"verify with sign-in on verify", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.SignInOnVerify())
			uid, _ := identUser(t, a, "")
			must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: uid, Kind: email.KindEmail, Raw: alice}))
			tok := identLink(t, e.env, a, alice, email.DefaultVerifyPage)
			return func(context.Context) error { _, err := em.Verify(anon(a), tok); return err }
		}},
		{"verify second address with welcome", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.Multiple(), email.Welcome())
			_, tok := identUser(t, a, alice)
			identWithWork(t, e, a, em, tok, false)
			link := identLink(t, e.env, a, identWork, email.DefaultVerifyPage)
			return func(context.Context) error { _, err := em.Verify(anon(a), link); return err }
		}},
		{"create verified non-primary with welcome", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, _ := identEmailAuth(t, e, email.Welcome())
			uid, _ := identUser(t, a, "")
			return func(ctx context.Context) error {
				_, err := a.CreateIdentity(ctx, auth.NewIdentity{UserID: uid, Kind: email.KindEmail, Raw: alice, Verified: true})
				return err
			}
		}},
		{"resend signed out", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e)
			uid, _ := identUser(t, a, "")
			must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: uid, Kind: email.KindEmail, Raw: alice}))
			return func(context.Context) error { return em.Resend(anon(a), alice) }
		}},
		{"resend signed in", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.Multiple())
			_, tok := identUser(t, a, alice)
			identWithWork(t, e, a, em, tok, false)
			return func(context.Context) error { return em.Resend(request(a, tok), identWork) }
		}},
		{"list", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e)
			_, tok := identUser(t, a, alice)
			return func(context.Context) error { _, err := em.List(request(a, tok)); return err }
		}},
		{"add first address, single", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e)
			_, tok := identUser(t, a, "")
			return func(context.Context) error { return em.Add(request(a, tok), alice) }
		}},
		{"add second address, multiple", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.Multiple())
			_, tok := identUser(t, a, alice)
			return func(context.Context) error { return em.Add(request(a, tok), identWork) }
		}},
		{"make primary", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.Multiple())
			_, tok := identUser(t, a, alice)
			identWithWork(t, e, a, em, tok, true)
			return func(context.Context) error { return em.MakePrimary(request(a, tok), identWork) }
		}},
		{"remove primary with another verified", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.Multiple())
			_, tok := identUser(t, a, alice)
			identWithWork(t, e, a, em, tok, true)
			return func(context.Context) error { return em.Remove(request(a, tok), alice) }
		}},
		{"change", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e)
			_, tok := identUser(t, a, alice)
			return func(context.Context) error { return em.Change(request(a, tok), identNext) }
		}},
		{"change with approval first", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.ApproveChangeFirst())
			_, tok := identUser(t, a, alice)
			return func(context.Context) error { return em.Change(request(a, tok), identNext) }
		}},
		{"approve change", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.ApproveChangeFirst())
			_, tok := identUser(t, a, alice)
			if err := em.Change(request(a, tok), identNext); err != nil {
				t.Fatal(err)
			}
			link := identLink(t, e.env, a, alice, email.DefaultApprovePage)
			return func(context.Context) error { return em.ApproveChange(anon(a), link) }
		}},
		{"confirm change to a new address, single", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e)
			_, tok := identUser(t, a, alice)
			if err := em.Change(request(a, tok), identNext); err != nil {
				t.Fatal(err)
			}
			link := identLink(t, e.env, a, identNext, email.DefaultChangePage)
			return func(context.Context) error { _, err := em.ConfirmChange(anon(a), link); return err }
		}},
		{"confirm change to an own address, multiple", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.Multiple())
			_, tok := identUser(t, a, alice)
			identWithWork(t, e, a, em, tok, false)
			if err := em.Change(request(a, tok), identWork); err != nil {
				t.Fatal(err)
			}
			link := identLink(t, e.env, a, identWork, email.DefaultChangePage)
			return func(context.Context) error { _, err := em.ConfirmChange(anon(a), link); return err }
		}},
		{"undo change, old address gone", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e)
			_, tok := identUser(t, a, alice)
			if err := em.Change(request(a, tok), identNext); err != nil {
				t.Fatal(err)
			}
			if _, err := em.ConfirmChange(anon(a), identLink(t, e.env, a, identNext, email.DefaultChangePage)); err != nil {
				t.Fatal(err)
			}
			undo := identLink(t, e.env, a, alice, email.DefaultUndoPage)
			return func(context.Context) error { return em.UndoChange(anon(a), undo) }
		}},
		{"undo change, old address kept", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.Multiple())
			_, tok := identUser(t, a, alice)
			if err := em.Change(request(a, tok), identNext); err != nil {
				t.Fatal(err)
			}
			if _, err := em.ConfirmChange(anon(a), identLink(t, e.env, a, identNext, email.DefaultChangePage)); err != nil {
				t.Fatal(err)
			}
			undo := identLink(t, e.env, a, alice, email.DefaultUndoPage)
			return func(context.Context) error { return em.UndoChange(anon(a), undo) }
		}},
		{"send code", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.SignInWithCode())
			identUser(t, a, alice)
			return func(context.Context) error { return em.SendCode(anon(a), alice) }
		}},
		{"sign in with code, owner", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.SignInWithCode())
			identUser(t, a, alice)
			if err := em.SendCode(anon(a), alice); err != nil {
				t.Fatal(err)
			}
			code := lastMailCode(t, e.env, a, alice)
			return func(context.Context) error { _, err := em.SignInCode(anon(a), alice, code); return err }
		}},
		{"sign up with code, welcome", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, em := identEmailAuth(t, e, email.SignUpWithCode(), email.Welcome())
			if err := em.SendCode(anon(a), alice); err != nil {
				t.Fatal(err)
			}
			code := lastMailCode(t, e.env, a, alice)
			return func(context.Context) error { _, err := em.SignInCode(anon(a), alice, code); return err }
		}},
	})
}

// TestIdentFaults_Phone: the same proof for the phone plugin.
func TestIdentFaults_Phone(t *testing.T) {
	phoneAuth := func(t *testing.T, e *faultEnv) (*auth.Auth, *phone.Plugin) {
		ph := e.phonePlugin(phone.Login(), phone.SignInWithCode())
		return e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), ph), ph
	}
	withNumber := func(t *testing.T, a *auth.Auth, ph *phone.Plugin, tok auth.Token) {
		t.Helper()
		if err := ph.Add(request(a, tok), identNumber); err != nil {
			t.Fatal(err)
		}
	}
	identRun(t, []identSweep{
		{"add", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ph := phoneAuth(t, e)
			_, tok := identUser(t, a, alice)
			return func(context.Context) error { return ph.Add(request(a, tok), identNumber) }
		}},
		{"verify", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ph := phoneAuth(t, e)
			_, tok := identUser(t, a, alice)
			withNumber(t, a, ph, tok)
			code := e.sms.LastCode(t, a, identNumber)
			return func(context.Context) error { return ph.Verify(request(a, tok), identNumber, code) }
		}},
		{"resend", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ph := phoneAuth(t, e)
			_, tok := identUser(t, a, alice)
			withNumber(t, a, ph, tok)
			return func(context.Context) error { return ph.Resend(request(a, tok), identNumber) }
		}},
		{"remove", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ph := phoneAuth(t, e)
			_, tok := identUser(t, a, alice)
			withNumber(t, a, ph, tok)
			return func(context.Context) error { return ph.Remove(request(a, tok), identNumber) }
		}},
		{"send code", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ph := phoneAuth(t, e)
			return func(context.Context) error { return ph.SendCode(anon(a), identNumber) }
		}},
		{"sign in, new account", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ph := phoneAuth(t, e)
			if err := ph.SendCode(anon(a), identNumber); err != nil {
				t.Fatal(err)
			}
			code := e.sms.LastCode(t, a, identNumber)
			return func(context.Context) error { _, err := ph.SignIn(anon(a), identNumber, code); return err }
		}},
		{"sign in, owner", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ph := phoneAuth(t, e)
			_, tok := identUser(t, a, alice)
			withNumber(t, a, ph, tok)
			if err := ph.Verify(request(a, tok), identNumber, e.sms.LastCode(t, a, identNumber)); err != nil {
				t.Fatal(err)
			}
			if err := ph.SendCode(anon(a), identNumber); err != nil {
				t.Fatal(err)
			}
			code := e.sms.LastCode(t, a, identNumber)
			return func(context.Context) error { _, err := ph.SignIn(anon(a), identNumber, code); return err }
		}},
	})
}

// TestIdentFaults_Username: setting a handle when one exists reads, inserts
// and deletes; availability reads.
func TestIdentFaults_Username(t *testing.T) {
	identRun(t, []identSweep{
		{"set replacing a handle", func(t *testing.T, e *faultEnv) func(context.Context) error {
			un := username.New(username.Login())
			a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), un)
			_, tok := identUser(t, a, alice)
			if _, err := un.Set(request(a, tok), "ada"); err != nil {
				t.Fatal(err)
			}
			return func(context.Context) error { _, err := un.Set(request(a, tok), "lovelace"); return err }
		}},
		{"claim replacing a handle", func(t *testing.T, e *faultEnv) func(context.Context) error {
			un := username.New(username.Login())
			a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), un)
			uid, _ := identUser(t, a, alice)
			if err := un.Claim(context.Background(), uid, "ada"); err != nil {
				t.Fatal(err)
			}
			return func(ctx context.Context) error { return un.Claim(ctx, uid, "lovelace") }
		}},
		{"available", func(t *testing.T, e *faultEnv) func(context.Context) error {
			un := username.New(username.Login())
			a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), un)
			return func(context.Context) error { _, err := un.Available(anon(a), "ada"); return err }
		}},
	})
}

// TestIdentFaults_MagicLink: sending looks up the owner and issues a token;
// signing in spends it and reads, or creates, the user.
func TestIdentFaults_MagicLink(t *testing.T) {
	identRun(t, []identSweep{
		{"send", func(t *testing.T, e *faultEnv) func(context.Context) error {
			ml := magiclink.New()
			a := e.newAuth(t, nil, e.emailPlugin(), ml)
			identUser(t, a, alice)
			return func(context.Context) error { return ml.Send(anon(a), alice) }
		}},
		{"sign in, owner", func(t *testing.T, e *faultEnv) func(context.Context) error {
			ml := magiclink.New()
			a := e.newAuth(t, nil, e.emailPlugin(), ml)
			identUser(t, a, alice)
			if err := ml.Send(anon(a), alice); err != nil {
				t.Fatal(err)
			}
			link := identLink(t, e.env, a, alice, magiclink.DefaultPage)
			return func(context.Context) error { _, err := ml.SignIn(anon(a), link); return err }
		}},
		{"sign up", func(t *testing.T, e *faultEnv) func(context.Context) error {
			ml := magiclink.New(magiclink.SignUp())
			a := e.newAuth(t, nil, e.emailPlugin(), ml)
			if err := ml.Send(anon(a), alice); err != nil {
				t.Fatal(err)
			}
			link := identLink(t, e.env, a, alice, magiclink.DefaultPage)
			return func(context.Context) error { _, err := ml.SignIn(anon(a), link); return err }
		}},
	})
}
