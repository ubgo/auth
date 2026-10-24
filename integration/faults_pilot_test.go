package integration

import (
	"context"
	"testing"

	"github.com/ubgo/auth/plugin/password"
)

func TestFaults_PasswordSignUpAndSignIn(t *testing.T) {
	t.Run("sign-up", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			pw := e.passwordPlugin()
			a := e.newAuth(t, nil, e.emailPlugin(), pw)
			return func(context.Context) error {
				_, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: "alice@example.com", Password: "correct horse battery", Name: "Alice"})
				return err
			}
		})
	})
	t.Run("sign-in", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			pw := e.passwordPlugin()
			a := e.newAuth(t, nil, e.emailPlugin(), pw)
			if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: "alice@example.com", Password: "correct horse battery"}); err != nil {
				t.Fatal(err)
			}
			return func(context.Context) error {
				_, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: "alice@example.com", Password: "correct horse battery"})
				return err
			}
		})
	})
}
