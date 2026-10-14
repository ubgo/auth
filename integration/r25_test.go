package integration

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
)

// Round 25 on real databases: the password history and expiry policies,
// and the passkey authenticator deny-list.

// historyRows counts every row of the password history table; the tests
// that call it have one user.
func historyRows(t *testing.T, e *env) int {
	t.Helper()
	var n int
	if err := e.db.QueryRow("SELECT COUNT(*) FROM " + tbl(password.TableNamePasswordHistory)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestR25_PasswordHistoryRefusesRecentPasswords: under History(3) a change
// to the current password or either of the two before it is ErrReused, the
// table keeps exactly two earlier hashes, a fourth password frees the
// oldest, a reset refused for reuse leaves its link unspent (the transaction
// rolls back), and DeleteUser clears the history.
func TestR25_PasswordHistoryRefusesRecentPasswords(t *testing.T) {
	const p2, p3, p4, p5 = "second passphrase here", "third passphrase here", "fourth passphrase here", "fifth passphrase here"
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin(password.History(3))
		a := e.newAuth(t, nil, em, pw)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		change := func(cur, next string) error {
			return pw.Change(ctx, password.ChangeRequest{Current: password.Secret(cur), New: password.Secret(next)})
		}
		if err := change(secret, secret); !errors.Is(err, password.ErrReused) {
			t.Fatalf("the current password again: %v, want ErrReused", err)
		}
		must0(t, change(secret, p2))
		must0(t, change(p2, p3))
		for _, old := range []string{secret, p2, p3} {
			if err := change(p3, old); !errors.Is(err, password.ErrReused) {
				t.Fatalf("change to %q: %v, want ErrReused", old, err)
			}
		}
		if n := historyRows(t, e); n != 2 {
			t.Fatalf("history rows = %d, want 2", n)
		}
		must0(t, change(p3, p4))
		if n := historyRows(t, e); n != 2 {
			t.Fatalf("history rows after a fourth password = %d, want 2", n)
		}
		// p4 is current, p3 and p2 remembered: secret has aged out. A reset
		// to p2 is refused and the link survives the refusal.
		must[password.ForgotResult](t)(pw.Forgot(anon(a), alice))
		a.WaitDeliveries()
		link := e.mail.LastToken(t, a, alice)
		if err := pw.Reset(anon(a), password.ResetRequest{Token: link.Wire(), Password: p2}); !errors.Is(err, password.ErrReused) {
			t.Fatalf("reset to a remembered password: %v, want ErrReused", err)
		}
		must0(t, pw.Reset(anon(a), password.ResetRequest{Token: link.Wire(), Password: secret}))
		if err := pw.SetPassword(context.Background(), up.User.ID, p4); !errors.Is(err, password.ErrReused) {
			t.Fatalf("SetPassword to a remembered password: %v, want ErrReused", err)
		}
		must0(t, pw.SetPassword(context.Background(), up.User.ID, p5))
		must0(t, a.DeleteUser(context.Background(), up.User.ID))
		if n := historyRows(t, e); n != 0 {
			t.Fatalf("history rows after DeleteUser = %d, want 0", n)
		}
	})
}

// TestR25_PasswordExpiryForcesAChange: under ExpireAfter a sign-in with the
// right password past the period is ErrExpired and a wrong one stays
// ErrInvalidCredentials; change-expired refuses the expired password itself,
// a wrong current password and an unknown account, then changes it and signs
// in; the old password no longer works, and a second change-expired is
// ErrNotExpired. A re-hash at sign-in does not restart the clock.
func TestR25_PasswordExpiryForcesAChange(t *testing.T) {
	const fresh = "a fresh passphrase now"
	const period = 24 * time.Hour
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin(password.ExpireAfter(period))
		a := e.newAuth(t, nil, em, pw)
		signUpVerified(t, e, a, pw, em)
		signIn := func(p *password.Plugin, a *auth.Auth, pass string) (password.SignInResult, error) {
			return p.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: password.Secret(pass)})
		}

		// A stronger argon2 cost re-hashes at sign-in 23 hours in; the
		// password is still a day old an hour later.
		e.clock.Advance(period - time.Hour)
		stronger := password.New(password.Argon2(password.Argon2Params{Memory: 128, Time: 1, Threads: 1}), password.ExpireAfter(period))
		a2 := e.newAuth(t, nil, e.emailPlugin(), stronger)
		must[password.SignInResult](t)(signIn(stronger, a2, secret))
		e.clock.Advance(time.Hour)
		if _, err := signIn(stronger, a2, secret); !errors.Is(err, password.ErrExpired) {
			t.Fatalf("after the re-hash and the period: %v, want ErrExpired", err)
		}

		if _, err := signIn(pw, a, secret); !errors.Is(err, password.ErrExpired) {
			t.Fatalf("right expired password: %v, want ErrExpired", err)
		}
		if _, err := signIn(pw, a, "not the password"); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("wrong password: %v, want ErrInvalidCredentials", err)
		}
		ce := func(id, cur, next string) (password.SignInResult, error) {
			return pw.ChangeExpired(anon(a), password.ChangeExpiredRequest{Identifier: id, Current: password.Secret(cur), New: password.Secret(next)})
		}
		if _, err := ce(alice, secret, secret); !errors.Is(err, password.ErrReused) {
			t.Fatalf("the expired password again: %v, want ErrReused", err)
		}
		if _, err := ce(alice, "not the password", fresh); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("wrong current: %v, want ErrInvalidCredentials", err)
		}
		if _, err := ce("nobody@example.com", secret, fresh); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("unknown account: %v, want ErrInvalidCredentials", err)
		}
		res, err := ce(alice, secret, fresh)
		if err != nil || res.Token == "" {
			t.Fatalf("change-expired = %+v, %v", res, err)
		}
		if _, err := a.Session(request(a, res.Token)); err != nil {
			t.Fatalf("the change-expired session: %v", err)
		}
		if _, err := signIn(pw, a, secret); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("the old password: %v, want ErrInvalidCredentials", err)
		}
		must[password.SignInResult](t)(signIn(pw, a, fresh))
		if _, err := ce(alice, fresh, "yet another passphrase"); !errors.Is(err, password.ErrNotExpired) {
			t.Fatalf("not expired: %v, want ErrNotExpired", err)
		}
	})
}

// onePasswordAAGUID is the 1Password authenticator model, as the
// passkey-authenticator-aaguids registry lists it.
const onePasswordAAGUID = "bada5566-a7aa-401f-bd96-45619a55120d"

// passkeyRows counts every passkey row; the test that calls it has one user.
func passkeyRows(t *testing.T, e *env) int {
	t.Helper()
	var n int
	if err := e.db.QueryRow("SELECT COUNT(*) FROM " + tbl(passkey.TableNamePasskey)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestR25_PasskeyDenyListRefusesAModel: a real registration ceremony from a
// denied model is ErrAuthenticatorNotAllowed and stores no row, while a
// model that keeps its AAGUID private registers and signs in.
func TestR25_PasskeyDenyListRefusesAModel(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		pk := passkey.New(passkey.DenyAuthenticators(onePasswordAAGUID))
		a := e.newAuth(t, nil, em, pw, pk)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)

		denied := newAuthenticator(t)
		raw, err := hex.DecodeString(strings.ReplaceAll(onePasswordAAGUID, "-", ""))
		if err != nil {
			t.Fatal(err)
		}
		denied.aaguid = raw
		begin := must[passkey.BeginResult](t)(pk.RegisterBegin(ctx))
		if _, err := pk.RegisterFinish(ctx, passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: denied.register(t, begin.Options)}); !errors.Is(err, passkey.ErrAuthenticatorNotAllowed) {
			t.Fatalf("a denied model: %v, want ErrAuthenticatorNotAllowed", err)
		}
		if n := passkeyRows(t, e); n != 0 {
			t.Fatalf("passkey rows after a refusal = %d, want 0", n)
		}

		private := newAuthenticator(t)
		begin = must[passkey.BeginResult](t)(pk.RegisterBegin(ctx))
		must[passkey.Passkey](t)(pk.RegisterFinish(ctx, passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: private.register(t, begin.Options)}))
		lb := must[passkey.BeginResult](t)(pk.LoginBegin(anon(a)))
		if _, err := pk.LoginFinish(anon(a), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: private.assert(t, lb.Options, up.User.ID)}); err != nil {
			t.Fatalf("sign-in with the private model: %v", err)
		}
	})
}
