package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

// refreshTTLShort is the refresh-token lifetime of these tests: shorter
// than the access token's, so an expired refresh token still has a live
// access token in its family, whose revocation the test can see.
const refreshTTLShort = 30 * time.Minute

// refreshWorld is a provider with a confidential client, another client and
// a DPoP-bound client, and a signed-in user, for the refresh refusals.
type refreshWorld struct {
	o            opEnv
	reg, other   oauthprovider.Registration
	bound        oauthprovider.Registration
	key, otherKy dpopKey
}

func newRefreshWorld(t *testing.T, e *env) refreshWorld {
	t.Helper()
	o := newOPEnv(t, e, oauthprovider.RefreshTokenTTL(refreshTTLShort))
	return refreshWorld{
		o: o, reg: o.client(t, oauthprovider.ClientSpec{SkipConsent: true}), other: o.client(t, oauthprovider.ClientSpec{SkipConsent: true}),
		bound: o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{DPoPBoundAccessTokens: true}}),
		key:   newDPoPKey(t, e.clock.Now), otherKy: newDPoPKey(t, e.clock.Now),
	}
}

const refreshTokenURL = testBaseURL + "/oauth2/token"

// pair runs a code exchange for reg and returns its tokens; a bound client
// proves w.key.
func (w refreshWorld) pair(t *testing.T, reg oauthprovider.Registration) oauthprovider.TokenResponse {
	t.Helper()
	req := exchange(reg, w.o.code(t, authzReq(reg.ClientID)), opVerifier)
	if reg.ClientID == w.bound.ClientID {
		req.DPoPProof = w.key.proof(t, "POST", refreshTokenURL, "", 0, nil)
	}
	return must[oauthprovider.TokenResponse](t)(w.o.op.Token(anon(w.o.a), req))
}

// refreshReq is the right refresh request for a pair of reg; a bound client
// proves w.key.
func (w refreshWorld) refreshReq(t *testing.T, reg oauthprovider.Registration, refresh string) oauthprovider.TokenRequest {
	t.Helper()
	req := oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: refresh, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
	if reg.ClientID == w.bound.ClientID {
		req.DPoPProof = w.key.proof(t, "POST", refreshTokenURL, "", 0, nil)
	}
	return req
}

// refreshBurnCase is a refused refresh: the client the pair is issued to,
// what the refusal answers, and the request that makes it.
type refreshBurnCase struct {
	owner func(w refreshWorld) oauthprovider.Registration
	want  error
	req   func(t *testing.T, w refreshWorld, refresh string) oauthprovider.TokenRequest
	// before runs between issuing the pair and the refused request.
	before func(t *testing.T, w refreshWorld)
}

func refreshBurnCases() map[string]refreshBurnCase {
	plain := func(w refreshWorld) oauthprovider.Registration { return w.reg }
	return map[string]refreshBurnCase{
		"other client": {owner: plain, want: oauthprovider.ErrInvalidGrant, req: func(t *testing.T, w refreshWorld, refresh string) oauthprovider.TokenRequest {
			return w.refreshReq(t, w.other, refresh)
		}},
		"unauthenticated client": {owner: plain, want: oauthprovider.ErrInvalidClient, req: func(t *testing.T, w refreshWorld, refresh string) oauthprovider.TokenRequest {
			r := w.refreshReq(t, w.reg, refresh)
			r.ClientSecret = oauthprovider.PrefixClientSecret + "wrong"
			return r
		}},
		"proof of another key": {owner: func(w refreshWorld) oauthprovider.Registration { return w.bound }, want: oauthprovider.ErrInvalidDPoPProof, req: func(t *testing.T, w refreshWorld, refresh string) oauthprovider.TokenRequest {
			r := w.refreshReq(t, w.bound, refresh)
			r.DPoPProof = w.otherKy.proof(t, "POST", refreshTokenURL, "", 0, nil)
			return r
		}},
		"user gone": {owner: plain, want: oauthprovider.ErrInvalidUser, before: func(t *testing.T, w refreshWorld) {
			// A user removed without DeleteUser (which deletes the tokens
			// too): the token row names a user that no longer exists.
			q := "UPDATE " + tbl(oauthprovider.TableNameToken) + " SET " + oauthprovider.ColUserID + " = " + w.o.e.d.Placeholder(1) + " WHERE " + oauthprovider.ColClientID + " = " + w.o.e.d.Placeholder(2)
			if _, err := w.o.e.db.Exec(q, "usr_gone", w.reg.ClientID); err != nil {
				t.Fatal(err)
			}
		}, req: func(t *testing.T, w refreshWorld, refresh string) oauthprovider.TokenRequest {
			return w.refreshReq(t, w.reg, refresh)
		}},
		"expired": {owner: plain, want: oauthprovider.ErrInvalidGrant, before: func(t *testing.T, w refreshWorld) { w.o.e.clock.Advance(refreshTTLShort + time.Minute) },
			req: func(t *testing.T, w refreshWorld, refresh string) oauthprovider.TokenRequest {
				return w.refreshReq(t, w.reg, refresh)
			}},
	}
}

// A refused refresh request for another client, with an expired token, with
// a DPoP proof of another key, or from a client that fails to authenticate
// revokes the refresh token's family, as a reuse does: the right request
// after it gets invalid_grant and the family's access token is dead,
// although the refused request rolled its transaction back.
//
//ds:def id=testoauthprovider-failedrefreshrevokesfamily-m6t3wq8z owner=@khanakia stability=stable
func TestOAuthProvider_FailedRefreshRevokesFamily(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		// One world: each case starts from a pair of its own, issued after
		// any earlier case moved the clock.
		w := newRefreshWorld(t, e)
		for name, c := range refreshBurnCases() {
			t.Run(name, func(t *testing.T) {
				owner := c.owner(w)
				tok := w.pair(t, owner)
				if c.before != nil {
					c.before(t, w)
				}
				if _, err := w.o.op.Token(anon(w.o.a), c.req(t, w, tok.RefreshToken)); !errors.Is(err, c.want) {
					t.Fatalf("refused request = %v, want %v", err, c.want)
				}
				if _, err := w.o.op.VerifyAccessToken(context.Background(), tok.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
					t.Errorf("the family's access token after the refusal = %v, want invalid_token", err)
				}
				if _, err := w.o.op.Token(anon(w.o.a), w.refreshReq(t, owner, tok.RefreshToken)); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
					t.Errorf("the right request after the refused one = %v, want invalid_grant", err)
				}
			})
		}
	})
}

// A rotation that slips in between the refused request's rollback and the
// write that revokes the family is revoked with it: no live token comes out
// of a refresh token a refused request presented.
func TestOAuthProvider_FailedRefreshRevokesARacingRotation(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var race func(ctx context.Context)
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
		op := oauthprovider.New(jw, oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login"), oauthprovider.ConsentPage("/consent"))
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, []auth.Option{auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize))), auth.WithOperationHooks(hook)}, em, pw, jw, op)
		up := signUpVerified(t, e, a, pw, em)
		o := opEnv{pw: pw, e: e, a: a, jw: jw, op: op, user: up.User, token: up.Token}
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		other := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		tok := must[oauthprovider.TokenResponse](t)(op.Token(anon(a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		right := oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: tok.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
		var raced oauthprovider.TokenResponse
		var racedErr error
		race = func(context.Context) { raced, racedErr = op.Token(anon(a), right) }
		wrong := right
		wrong.ClientID, wrong.ClientSecret = other.ClientID, other.Secret
		if _, err := op.Token(anon(a), wrong); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("other client: %v", err)
		}
		if racedErr != nil || raced.AccessToken == "" {
			t.Fatalf("the racing rotation did not run as set up: %v", racedErr)
		}
		if _, err := op.VerifyAccessToken(context.Background(), raced.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("a rotation racing a refused refresh kept a live access token: %v", err)
		}
		right.RefreshToken = raced.RefreshToken
		if _, err := op.Token(anon(a), right); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("a rotation racing a refused refresh kept a live refresh token: %v", err)
		}
	})
}

// Every database call of a refused refresh fails in turn, the writes that
// revoke the family included: the failure reaches the caller, never a plain
// refusal that would hide a family left alive.
func TestOAuthProvider_FailedRefreshFaultSweep(t *testing.T) {
	for name, c := range refreshBurnCases() {
		t.Run(name, func(t *testing.T) {
			sweepFaults(t, func(t *testing.T, fe *faultEnv) func(context.Context) error {
				w := newRefreshWorld(t, fe.env)
				tok := w.pair(t, c.owner(w))
				if c.before != nil {
					c.before(t, w)
				}
				req := c.req(t, w, tok.RefreshToken)
				return func(context.Context) error {
					if _, err := w.o.op.Token(anon(w.o.a), req); !errors.Is(err, c.want) {
						return err
					}
					return nil
				}
			})
		})
	}
}
