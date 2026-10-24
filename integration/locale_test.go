package integration

import (
	"context"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

// TestDeliver_CarriesTheRequestLocale: a template sees the language of the
// request that caused the message, without the sending plugin knowing about
// languages at all.
func TestDeliver_CarriesTheRequestLocale(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		seen := make(chan string, 4)
		em := e.emailPlugin(email.Templates(func(m auth.Message) (string, string) {
			seen <- m.Locale
			return email.DefaultTemplates(m)
		}))
		pw := e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{Locale: "de-CH"}})
		if _, err := pw.SignUp(ctx, password.SignUpRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatal(err)
		}
		a.WaitDeliveries()
		if got := <-seen; got != "de-CH" {
			t.Fatalf("template saw locale %q, want de-CH", got)
		}
	})
}
