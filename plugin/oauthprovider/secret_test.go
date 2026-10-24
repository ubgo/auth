package oauthprovider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// Every feature that signs with a key from auth.WithSecret is refused at
// start-up without one, so it cannot fail on its first request instead:
// before this check a trusted client with EnableEndSession started, and its
// first GET /oauth2/end-session without a hint answered 500 "auth: no secret
// configured". The same configuration with a secret starts.
func TestValidate_SecretUsersNeedASecret(t *testing.T) {
	yes := func(context.Context, GateInfo) bool { return true }
	secret := auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize)))
	for name, c := range map[string]struct {
		opt  Option
		want []error
	}{
		"trusted end session": {TrustedClients(TrustedClient{ClientID: "rp", ClientSpec: ClientSpec{EnableEndSession: true,
			ClientMetadata: ClientMetadata{Name: "RP", RedirectURIs: []string{"https://rp.example.com/cb"}, AuthMethod: AuthMethodNone}}}), []error{ErrNoSecret}},
		"prelogin":   {AllowPublicClientPrelogin(), []error{ErrNoSecret}},
		"post-login": {PostLogin(PostLoginGate{Page: "/org", ShouldRedirect: yes}), []error{ErrNoSecret, ErrBadGate}},
	} {
		t.Run(name, func(t *testing.T) {
			start := func(opts ...auth.Option) error {
				j := newSigner(testIssuer)
				p := New(j, Issuer(testIssuer), LoginPage("/login"), c.opt)
				_, err := auth.New(append(opts, auth.WithBaseURL(testIssuer), auth.WithPlugins(signIn(), j, p))...)
				return err
			}
			err := start()
			for _, w := range c.want {
				if !errors.Is(err, w) {
					t.Fatalf("without a secret = %v, want %v", err, w)
				}
			}
			if err := start(secret); err != nil {
				t.Fatalf("with a secret: %v", err)
			}
		})
	}
}

// With a secret, the pre-login lookup still refuses a query it did not
// sign, before it reads any client: the refusal that the start-up check
// leaves as the only one.
func TestPublicClientPrelogin_RefusesAnUnsignedQuery(t *testing.T) {
	j := newSigner(testIssuer)
	p := New(j, Issuer(testIssuer), LoginPage("/login"), AllowPublicClientPrelogin())
	if _, err := auth.New(auth.WithBaseURL(testIssuer), auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize))), auth.WithPlugins(signIn(), j, p)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.PublicClientPrelogin(context.Background(), PreloginRequest{OAuthQuery: "client_id=rp&sig=forged&exp=9999999999"}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("prelogin with a forged query = %v, want ErrInvalidSignature", err)
	}
}
