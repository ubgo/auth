package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

// burnCases are the refused exchanges of a valid, unexpired, unused code:
// each one names the error the refusal answers with and the request that
// makes it, given the code's own client and another registered one.
func burnCases() map[string]struct {
	want error
	req  func(reg, other oauthprovider.Registration, code string) oauthprovider.TokenRequest
} {
	return map[string]struct {
		want error
		req  func(reg, other oauthprovider.Registration, code string) oauthprovider.TokenRequest
	}{
		"wrong verifier": {oauthprovider.ErrInvalidGrant, func(reg, _ oauthprovider.Registration, code string) oauthprovider.TokenRequest {
			return exchange(reg, code, strings.Repeat("a", 43))
		}},
		"no verifier": {oauthprovider.ErrInvalidGrant, func(reg, _ oauthprovider.Registration, code string) oauthprovider.TokenRequest {
			return exchange(reg, code, "")
		}},
		"wrong redirect": {oauthprovider.ErrInvalidGrant, func(reg, _ oauthprovider.Registration, code string) oauthprovider.TokenRequest {
			r := exchange(reg, code, opVerifier)
			r.RedirectURI = opRedirect + "/x"
			return r
		}},
		"other client": {oauthprovider.ErrInvalidGrant, func(_, other oauthprovider.Registration, code string) oauthprovider.TokenRequest {
			return exchange(other, code, opVerifier)
		}},
		"unauthenticated client": {oauthprovider.ErrInvalidClient, func(reg, _ oauthprovider.Registration, code string) oauthprovider.TokenRequest {
			r := exchange(reg, code, opVerifier)
			r.ClientSecret = oauthprovider.PrefixClientSecret + "wrong"
			return r
		}},
	}
}

// A refused exchange of a valid code spends the code: the request that
// follows with the right verifier, redirect URI and client gets
// invalid_grant, although the refused request rolled its transaction back
// (OAuth 2.1 section 4.1.3; a stolen code gets one guess).
//
//ds:def id=testoauthprovider-failedexchangeburnscode-r7k2mx4q owner=@khanakia stability=stable
func TestOAuthProvider_FailedExchangeBurnsCode(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		reg := o.client(t, oauthprovider.ClientSpec{})
		other := o.client(t, oauthprovider.ClientSpec{})
		for name, c := range burnCases() {
			code := o.code(t, authzReq(reg.ClientID))
			if _, err := o.op.Token(anon(o.a), c.req(reg, other, code)); !errors.Is(err, c.want) {
				t.Fatalf("%s: %v, want %v", name, err, c.want)
			}
			if _, err := o.op.Token(anon(o.a), exchange(reg, code, opVerifier)); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
				t.Errorf("%s: the right request after the refused one = %v, want invalid_grant", name, err)
			}
		}
		// A code no one tried is untouched by the others' refusals.
		must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
	})
}

// A redemption that slips in between the refused request's rollback and
// the write that spends its code gets tokens that are already revoked: no
// live token comes out of a code a refused request held.
func TestOAuthProvider_FailedExchangeRevokesARacingRedemption(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var (
			op   *oauthprovider.Plugin
			race func(ctx context.Context)
		)
		hook := auth.OperationHook{Match: []auth.EndpointID{oauthprovider.EndpointToken}, Before: func(ctx context.Context, c *auth.Call) error {
			if race != nil {
				// Registered before the operation runs, so it runs right
				// after the rollback and before the refusal's own write.
				fn := race
				race = nil
				c.Auth.AfterTx(ctx, fn)
			}
			return nil
		}}
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
		op = oauthprovider.New(jw, oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login"), oauthprovider.ConsentPage("/consent"))
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, []auth.Option{auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize))), auth.WithOperationHooks(hook)}, em, pw, jw, op)
		up := signUpVerified(t, e, a, pw, em)
		o := opEnv{pw: pw, e: e, a: a, jw: jw, op: op, user: up.User, token: up.Token}
		reg := o.client(t, oauthprovider.ClientSpec{})
		code := o.code(t, authzReq(reg.ClientID))
		var raced oauthprovider.TokenResponse
		var racedErr error
		race = func(context.Context) { raced, racedErr = op.Token(anon(a), exchange(reg, code, opVerifier)) }
		if _, err := op.Token(anon(a), exchange(reg, code, strings.Repeat("a", 43))); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("wrong verifier: %v", err)
		}
		if racedErr != nil || raced.AccessToken == "" {
			t.Fatalf("the racing redemption did not run as set up: %v", racedErr)
		}
		if _, err := op.VerifyAccessToken(context.Background(), raced.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("a redemption racing a refused one kept a live access token: %v", err)
		}
		ref := oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: raced.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
		if _, err := op.Token(anon(a), ref); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("a redemption racing a refused one kept a live refresh token: %v", err)
		}
	})
}

// Every database call of a refused exchange fails in turn, the write that
// spends the code included: the failure reaches the caller, never a plain
// invalid_grant that would hide a code left unspent.
func TestOAuthProvider_FailedExchangeBurnFaultSweep(t *testing.T) {
	for name, c := range burnCases() {
		t.Run(name, func(t *testing.T) {
			sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
				o := newOPEnv(t, fe.env)
				reg := o.client(t, oauthprovider.ClientSpec{})
				other := o.client(t, oauthprovider.ClientSpec{})
				code := o.code(t, authzReq(reg.ClientID))
				return func(context.Context) error {
					if _, err := o.op.Token(anon(o.a), c.req(reg, other, code)); !errors.Is(err, c.want) {
						return err
					}
					return nil
				}
			})
		})
	}
}
