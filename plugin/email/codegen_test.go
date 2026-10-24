package email_test

import (
	"errors"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

// TestReuseCodeOnResend_NeedsSecret: a reused code is stored sealed under a
// key from the app secret, so auth.New refuses the option without one.
func TestReuseCodeOnResend_NeedsSecret(t *testing.T) {
	if _, err := newCodes(email.ReuseCodeOnResend()); !errors.Is(err, auth.ErrNoSecret) {
		t.Fatalf("reuse without a secret: %v", err)
	}
	if _, err := newCodes(email.ReuseCodeOnResend(), auth.WithSecret([]byte("0123456789abcdef0123456789abcdef"))); err != nil {
		t.Fatalf("reuse with a secret: %v", err)
	}
}

// newCodes builds an app with code sign-in, the plugin option o and the core
// options opts.
func newCodes(o email.Option, opts ...auth.Option) (*auth.Auth, error) {
	return auth.New(append([]auth.Option{auth.WithBaseURL("https://x.example"),
		auth.WithPlugins(email.New(email.Login(), email.WithMailer(noMail), email.SignUpWithCode(), o))}, opts...)...)
}
