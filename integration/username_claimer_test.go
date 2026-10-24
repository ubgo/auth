package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

// handleClaimer is an app's own handle scheme standing in for the username
// plugin (password.UsernameClaimer).
type handleClaimer struct {
	userID, handle, display string
	err                     error
}

func (*handleClaimer) Name() string { return "handles" }

func (h *handleClaimer) ClaimWithDisplay(_ context.Context, userID, handle, display string) error {
	h.userID, h.handle, h.display = userID, handle, display
	return h.err
}

// TestUsernameClaimer_SignUpUsesAnyClaimer: sign-up with a username claims it
// through whatever UsernameClaimer is wired, a refusal fails the whole
// sign-up with no account left, and with no claimer the answer is
// ErrNoUsernames.
func TestUsernameClaimer_SignUpUsesAnyClaimer(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		h := &handleClaimer{}
		pw := e.passwordPlugin()
		a := e.newAuth(t, nil, e.emailPlugin(), pw, h)
		res := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret, Username: "bobby", DisplayUsername: "Bobby"}))
		if h.userID != res.User.ID || h.handle != "bobby" || h.display != "Bobby" {
			t.Fatalf("claimer got %+v for user %s", h, res.User.ID)
		}
		h.err = errors.New("handle taken")
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: "carol@example.com", Password: secret, Username: "carol"}); !errors.Is(err, h.err) {
			t.Fatalf("a refused claim must fail the sign-up: %v", err)
		}
		if _, err := a.FindIdentity(anon(a), email.KindEmail, "carol@example.com", false); !errors.Is(err, auth.ErrIdentityNotFound) {
			t.Fatalf("a refused claim left the account: %v", err)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		pw := e.passwordPlugin()
		a := e.newAuth(t, nil, e.emailPlugin(), pw)
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret, Username: "bobby"}); !errors.Is(err, password.ErrNoUsernames) {
			t.Fatalf("sign-up with no claimer = %v", err)
		}
	})
}
