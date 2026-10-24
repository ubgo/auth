package twofactor

import (
	"context"
	"testing"

	"github.com/ubgo/auth"
)

// TestDefaultPolicy_AsksAfterCredentialSignInsOnly: the default rule. The
// default asks after a password sign-in and after a sign-in naming no
// operation, never after OAuth, SSO, a magic link, a passkey or a one-time
// code, and never from a trusted device; AskEverySignIn asks after every
// method except from a trusted device.
func TestDefaultPolicy_AsksAfterCredentialSignInsOnly(t *testing.T) {
	cases := map[auth.EndpointID]bool{
		"":                          true,
		"password.sign-in":          true,
		"password.change-expired":   true,
		"oauth.google-callback":     false,
		"oauth.google-id-token":     false,
		"sso.callback":              false,
		"sso.saml-acs":              false,
		"magiclink.verify":          false,
		"magiclink.sign-in":         false,
		"email.sign-in-code":        false,
		"phone.sign-in":             false,
		"passkey.login-finish":      false,
		"emailchallenge.verify-otp": false,
	}
	for op, want := range cases {
		in := PolicyRequest{SignInAttempt: auth.SignInAttempt{UserID: "usr_1", Operation: op}}
		if ask, err := DefaultPolicy(context.Background(), in); err != nil || ask != want {
			t.Errorf("%q: ask=%v err=%v, want %v", op, ask, err, want)
		}
		if ask, err := AskEverySignIn(context.Background(), in); err != nil || !ask {
			t.Errorf("AskEverySignIn %q: ask=%v err=%v", op, ask, err)
		}
		in.DeviceTrusted = true
		if ask, err := DefaultPolicy(context.Background(), in); err != nil || ask {
			t.Errorf("%q trusted: ask=%v err=%v", op, ask, err)
		}
		if ask, err := AskEverySignIn(context.Background(), in); err != nil || ask {
			t.Errorf("AskEverySignIn %q trusted: ask=%v err=%v", op, ask, err)
		}
	}
}

// TestDefaultPolicy_AsksAfterASingleFactorSignIn: a method that reports it
// proved one factor (a passkey without user verification) is asked for the
// factor whatever its operation, except from a trusted device.
func TestDefaultPolicy_AsksAfterASingleFactorSignIn(t *testing.T) {
	for _, op := range []auth.EndpointID{"passkey.login-finish", "oauth.google-callback", ""} {
		in := PolicyRequest{SignInAttempt: auth.SignInAttempt{UserID: "usr_1", Operation: op, SingleFactor: true}}
		if ask, err := DefaultPolicy(context.Background(), in); err != nil || !ask {
			t.Errorf("%q single factor: ask=%v err=%v", op, ask, err)
		}
		in.DeviceTrusted = true
		if ask, err := DefaultPolicy(context.Background(), in); err != nil || ask {
			t.Errorf("%q single factor, trusted: ask=%v err=%v", op, ask, err)
		}
	}
}

// TestWithPolicy_SetsThePolicy: WithPolicy stores the function and nil keeps
// the default.
func TestWithPolicy_SetsThePolicy(t *testing.T) {
	if New().policy != nil || New(WithPolicy(nil)).policy != nil {
		t.Fatal("the default policy is nil")
	}
	if New(WithPolicy(DefaultPolicy)).policy == nil {
		t.Fatal("WithPolicy did not set the policy")
	}
}
