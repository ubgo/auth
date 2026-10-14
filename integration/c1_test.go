package integration

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/auth/plugin/password"
)

// opSweep runs a strict fault sweep over one provider operation: every
// database call the operation makes fails once, and that failure itself
// must reach the caller, neither swallowed nor turned into a protocol
// verdict (invalid_grant, an inactive token) that a client would act on.
// setup runs unfaulted on a fresh provider and returns the operation.
func opSweep(t *testing.T, opts []oauthprovider.Option, setup func(t *testing.T, o opEnv) func(ctx context.Context) error) {
	t.Helper()
	for k := 1; k <= maxFaultSteps; k++ {
		e := newFaultEnv(t)
		op := setup(t, newOPEnv(t, e.env, opts...))
		e.f.arm(k)
		err := op(context.Background())
		if !e.f.disarm() {
			if err != nil {
				t.Fatalf("run with no fault reached (step %d) failed: %v", k, err)
			}
			if k == 1 {
				t.Fatal("the operation made no database call; the sweep proves nothing")
			}
			return
		}
		if !errors.Is(err, errFault) {
			t.Errorf("fault at database call %d became %v", k, err)
		}
	}
	t.Fatalf("no run finished within %d database calls", maxFaultSteps)
}

// Every provider operation that reads or writes the database surfaces a
// failed call as an error rather than a half-done success.
func TestOAuthProviderFaults_Clients(t *testing.T) {
	meta := oauthprovider.ClientMetadata{Name: "Mine", RedirectURIs: []string{opRedirect}}
	cases := map[string]func(t *testing.T, o opEnv) func(context.Context) error{
		"create": func(t *testing.T, o opEnv) func(context.Context) error {
			return func(ctx context.Context) error {
				_, err := o.op.CreateClient(ctx, oauthprovider.ClientSpec{ClientMetadata: meta})
				return err
			}
		},
		"get": func(t *testing.T, o opEnv) func(context.Context) error {
			reg := o.client(t, oauthprovider.ClientSpec{})
			return func(ctx context.Context) error { _, err := o.op.Client(ctx, reg.ClientID); return err }
		},
		"update": func(t *testing.T, o opEnv) func(context.Context) error {
			reg := o.client(t, oauthprovider.ClientSpec{})
			return func(ctx context.Context) error {
				_, err := o.op.UpdateClient(ctx, reg.ClientID, oauthprovider.ClientSpec{ClientMetadata: meta})
				return err
			}
		},
		"disable": func(t *testing.T, o opEnv) func(context.Context) error {
			reg := o.client(t, oauthprovider.ClientSpec{})
			return func(ctx context.Context) error { return o.op.SetClientDisabled(ctx, reg.ClientID, true) }
		},
		"delete": func(t *testing.T, o opEnv) func(context.Context) error {
			reg := o.client(t, oauthprovider.ClientSpec{})
			return func(ctx context.Context) error { return o.op.DeleteClient(ctx, reg.ClientID) }
		},
		"create owned": func(t *testing.T, o opEnv) func(context.Context) error {
			return func(context.Context) error { _, err := o.op.CreateOwnedClient(request(o.a, o.token), meta); return err }
		},
		"list owned": func(t *testing.T, o opEnv) func(context.Context) error {
			must[oauthprovider.Registration](t)(o.op.CreateOwnedClient(request(o.a, o.token), meta))
			return func(context.Context) error { _, err := o.op.Clients(request(o.a, o.token)); return err }
		},
		"get owned": func(t *testing.T, o opEnv) func(context.Context) error {
			reg := must[oauthprovider.Registration](t)(o.op.CreateOwnedClient(request(o.a, o.token), meta))
			return func(context.Context) error {
				_, err := o.op.OwnedClient(request(o.a, o.token), reg.ClientID)
				return err
			}
		},
		"update owned": func(t *testing.T, o opEnv) func(context.Context) error {
			reg := must[oauthprovider.Registration](t)(o.op.CreateOwnedClient(request(o.a, o.token), meta))
			return func(context.Context) error {
				_, err := o.op.UpdateOwnedClient(request(o.a, o.token), oauthprovider.UpdateClientRequest{ClientID: reg.ClientID, Metadata: meta})
				return err
			}
		},
		"rotate": func(t *testing.T, o opEnv) func(context.Context) error {
			reg := must[oauthprovider.Registration](t)(o.op.CreateOwnedClient(request(o.a, o.token), meta))
			return func(context.Context) error {
				_, err := o.op.RotateSecret(request(o.a, o.token), reg.ClientID)
				return err
			}
		},
		"delete owned": func(t *testing.T, o opEnv) func(context.Context) error {
			reg := must[oauthprovider.Registration](t)(o.op.CreateOwnedClient(request(o.a, o.token), meta))
			return func(context.Context) error { return o.op.DeleteOwnedClient(request(o.a, o.token), reg.ClientID) }
		},
		"public info": func(t *testing.T, o opEnv) func(context.Context) error {
			reg := o.client(t, oauthprovider.ClientSpec{})
			return func(context.Context) error {
				_, err := o.op.PublicClientInfo(request(o.a, o.token), reg.ClientID)
				return err
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) { opSweep(t, nil, setup) })
	}
	t.Run("register", func(t *testing.T) {
		opSweep(t, []oauthprovider.Option{oauthprovider.AllowDynamicRegistration()}, func(t *testing.T, o opEnv) func(context.Context) error {
			return func(context.Context) error { _, err := o.op.Register(request(o.a, o.token), meta); return err }
		})
	})
}

// The protocol flows under fault: authorize, consent, every grant,
// introspection, revocation, userinfo, logout, the consent records, the
// resource registry, the sweep and the session listeners.
func TestOAuthProviderFaults_Flows(t *testing.T) {
	type setupFn = func(t *testing.T, o opEnv) func(context.Context) error
	// issued is a code exchanged for tokens, with the client.
	issued := func(t *testing.T, o opEnv, spec oauthprovider.ClientSpec) (oauthprovider.Registration, oauthprovider.TokenResponse) {
		reg := o.client(t, spec)
		return reg, must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
	}
	ccScopes := []oauthprovider.Option{oauthprovider.Scopes("openid", "profile", "email", "offline_access", "api:read")}
	cases := map[string]struct {
		opts  []oauthprovider.Option
		setup setupFn
	}{
		"authorize asks consent": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			reg := o.client(t, oauthprovider.ClientSpec{})
			return func(context.Context) error {
				_, err := o.op.Authorize(request(o.a, o.token), authzReq(reg.ClientID))
				return err
			}
		}},
		"authorize issues a code": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
			return func(context.Context) error {
				_, err := o.op.Authorize(request(o.a, o.token), authzReq(reg.ClientID))
				return err
			}
		}},
		"consent": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			reg := o.client(t, oauthprovider.ClientSpec{})
			res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), authzReq(reg.ClientID)))
			q := must[*url.URL](t)(url.Parse(res.RedirectTo)).RawQuery
			return func(context.Context) error {
				_, err := o.op.Consent(request(o.a, o.token), oauthprovider.ConsentRequest{Query: q, Accept: true})
				return err
			}
		}},
		"code exchange": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
			code := o.code(t, authzReq(reg.ClientID))
			return func(context.Context) error {
				_, err := o.op.Token(anon(o.a), exchange(reg, code, opVerifier))
				return err
			}
		}},
		"refresh": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			reg, tok := issued(t, o, oauthprovider.ClientSpec{SkipConsent: true})
			return func(context.Context) error {
				_, err := o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: tok.RefreshToken, Scope: "openid", ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})
				return err
			}
		}},
		"client credentials": {ccScopes, func(t *testing.T, o opEnv) func(context.Context) error {
			reg := o.client(t, oauthprovider.ClientSpec{ClientCredentialsScopes: []string{"api:read"}, ClientMetadata: oauthprovider.ClientMetadata{GrantTypes: []string{"client_credentials"}, Scope: "api:read"}})
			return func(context.Context) error {
				_, err := o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "client_credentials", ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})
				return err
			}
		}},
		"introspect": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			reg, tok := issued(t, o, oauthprovider.ClientSpec{SkipConsent: true})
			return func(context.Context) error {
				_, err := o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: tok.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})
				return err
			}
		}},
		"revoke": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			reg, tok := issued(t, o, oauthprovider.ClientSpec{SkipConsent: true})
			return func(context.Context) error {
				return o.op.Revoke(anon(o.a), oauthprovider.RevokeRequest{Token: tok.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})
			}
		}},
		"userinfo": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			_, tok := issued(t, o, oauthprovider.ClientSpec{SkipConsent: true})
			return func(context.Context) error { _, err := o.op.UserInfo(anon(o.a), tok.AccessToken); return err }
		}},
		"verify access token": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			_, tok := issued(t, o, oauthprovider.ClientSpec{SkipConsent: true})
			return func(ctx context.Context) error { _, err := o.op.VerifyAccessToken(ctx, tok.AccessToken); return err }
		}},
		"end session": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			_, tok := issued(t, o, oauthprovider.ClientSpec{SkipConsent: true, EnableEndSession: true})
			return func(context.Context) error {
				_, err := o.op.EndSession(request(o.a, o.token), oauthprovider.EndSessionRequest{IDTokenHint: tok.IDToken})
				return err
			}
		}},
		"consents": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			o.code(t, authzReq(o.client(t, oauthprovider.ClientSpec{}).ClientID))
			return func(context.Context) error { _, err := o.op.Consents(request(o.a, o.token)); return err }
		}},
		"consent by id": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			o.code(t, authzReq(o.client(t, oauthprovider.ClientSpec{}).ClientID))
			id := must[oauthprovider.ConsentList](t)(o.op.Consents(request(o.a, o.token))).Consents[0].ID
			return func(context.Context) error { _, err := o.op.ConsentByID(request(o.a, o.token), id); return err }
		}},
		"update consent": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			o.code(t, authzReq(o.client(t, oauthprovider.ClientSpec{}).ClientID))
			id := must[oauthprovider.ConsentList](t)(o.op.Consents(request(o.a, o.token))).Consents[0].ID
			return func(context.Context) error {
				_, err := o.op.UpdateConsent(request(o.a, o.token), oauthprovider.UpdateConsentRequest{ID: id, Scope: "openid"})
				return err
			}
		}},
		"revoke consent": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			reg := o.client(t, oauthprovider.ClientSpec{})
			o.code(t, authzReq(reg.ClientID))
			return func(context.Context) error { return o.op.RevokeConsent(request(o.a, o.token), reg.ClientID) }
		}},
		"sweep": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			issued(t, o, oauthprovider.ClientSpec{SkipConsent: true})
			return func(ctx context.Context) error {
				_, err := o.op.Sweep(ctx, o.e.clock.Now().Add(1000*time.Hour))
				return err
			}
		}},
		"session ended": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			issued(t, o, oauthprovider.ClientSpec{SkipConsent: true})
			sess := must[*auth.Session](t)(func() (*auth.Session, error) {
				s, _, _, err := o.a.ResolveSession(context.Background(), o.token)
				return s, err
			}())
			return func(ctx context.Context) error { return o.op.SessionEnded(ctx, o.user.ID, sess.ID) }
		}},
		"user sessions ended": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			issued(t, o, oauthprovider.ClientSpec{SkipConsent: true})
			return func(ctx context.Context) error { return o.op.UserSessionsEnded(ctx, o.user.ID, "other") }
		}},
		"session replaced": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			issued(t, o, oauthprovider.ClientSpec{SkipConsent: true})
			sess := must[*auth.Session](t)(func() (*auth.Session, error) {
				s, _, _, err := o.a.ResolveSession(context.Background(), o.token)
				return s, err
			}())
			return func(ctx context.Context) error {
				return o.op.SessionReplaced(ctx, *sess, auth.Session{ID: "replacement", UserID: o.user.ID})
			}
		}},
		"end session, hinted, no browser": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			_, tok := issued(t, o, oauthprovider.ClientSpec{SkipConsent: true, EnableEndSession: true})
			return func(context.Context) error {
				_, err := o.op.EndSession(anon(o.a), oauthprovider.EndSessionRequest{IDTokenHint: tok.IDToken})
				return err
			}
		}},
		"end session, client named": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, EnableEndSession: true})
			return func(context.Context) error {
				_, err := o.op.EndSession(request(o.a, o.token), oauthprovider.EndSessionRequest{ClientID: reg.ClientID, Browser: true})
				return err
			}
		}},
		"confirm end session": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			const after = "https://client.example/bye"
			reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, EnableEndSession: true, ClientMetadata: oauthprovider.ClientMetadata{PostLogoutRedirectURIs: []string{after}}})
			w := c1Do(o.op.Handler(), http.MethodGet, "/oauth2/end-session?client_id="+url.QueryEscape(reg.ClientID)+"&post_logout_redirect_uri="+url.QueryEscape(after), "", "", http.Header{"Accept": {"text/html"}, "Cookie": {"__Host-auth_session=" + o.token.Reveal()}})
			state := w.Result().Cookies()[0].Value
			ctx := o.a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{Origin: testBaseURL}, Credential: auth.CredentialCookie, Token: o.token,
				Cookie: func(string) (string, bool) { return state, true }})
			return func(context.Context) error {
				_, err := o.op.ConfirmEndSession(ctx, oauthprovider.EndSessionConfirmRequest{Action: "confirm", Browser: true})
				return err
			}
		}},
		"introspect by a linked resource server": {[]oauthprovider.Option{oauthprovider.Scopes("openid", "profile", "email", "offline_access", "pay:read")}, func(t *testing.T, o opEnv) func(context.Context) error {
			const api = "https://api.example.com/pay"
			must[oauthprovider.Resource](t)(o.op.CreateResource(context.Background(), oauthprovider.Resource{Identifier: api, CustomClaims: map[string]any{"tier": "gold"}}))
			reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
			rs := o.client(t, oauthprovider.ClientSpec{})
			for _, id := range []string{reg.ClientID, rs.ClientID} {
				must[bool](t)(o.op.LinkClient(context.Background(), api, id))
			}
			in := authzReq(reg.ClientID)
			in.Scope, in.Resource = "openid pay:read", api
			tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, in), opVerifier)))
			return func(context.Context) error {
				got, err := o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: tok.AccessToken, ClientID: rs.ClientID, ClientSecret: rs.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})
				if err == nil && (!got.Active || got.Extra["tier"] != "gold") {
					t.Errorf("linked introspection = %+v", got)
				}
				return err
			}
		}},
		"prelogin": {[]oauthprovider.Option{oauthprovider.AllowPublicClientPrelogin()}, func(t *testing.T, o opEnv) func(context.Context) error {
			reg := o.client(t, oauthprovider.ClientSpec{})
			res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), authzReq(reg.ClientID)))
			q := must[*url.URL](t)(url.Parse(res.RedirectTo)).RawQuery
			return func(context.Context) error {
				_, err := o.op.PublicClientPrelogin(anon(o.a), oauthprovider.PreloginRequest{OAuthQuery: q})
				return err
			}
		}},
		"continue": {[]oauthprovider.Option{oauthprovider.SelectAccount(oauthprovider.SelectAccountGate{Page: "/select"})}, func(t *testing.T, o opEnv) func(context.Context) error {
			reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
			in := authzReq(reg.ClientID)
			in.Prompt = "select_account"
			q := pageQuery(t, must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), in)), "/select")
			return func(context.Context) error {
				_, err := o.op.Continue(request(o.a, o.token), oauthprovider.ContinueRequest{Query: q, Selected: true})
				return err
			}
		}},
		"create with default resources": {[]oauthprovider.Option{oauthprovider.Scopes("openid", "profile", "email", "offline_access", "api:read"), oauthprovider.ProtectedResource("https://api.example.com/v1", "api:read"), oauthprovider.RegistrationDefaultResources("https://api.example.com/v1")}, func(t *testing.T, o opEnv) func(context.Context) error {
			return func(context.Context) error {
				_, err := o.op.CreateOwnedClient(request(o.a, o.token), oauthprovider.ClientMetadata{Name: "x", RedirectURIs: []string{opRedirect}})
				return err
			}
		}},
		"client credentials for a resource": {append(slices.Clone(ccScopes), oauthprovider.ProtectedResource("https://api.example.com/v1", "api:read")), func(t *testing.T, o opEnv) func(context.Context) error {
			reg := o.client(t, oauthprovider.ClientSpec{ClientCredentialsScopes: []string{"api:read"}, ClientMetadata: oauthprovider.ClientMetadata{GrantTypes: []string{"client_credentials"}, Scope: "api:read"}})
			must[bool](t)(o.op.LinkClient(context.Background(), "https://api.example.com/v1", reg.ClientID))
			return func(context.Context) error {
				_, err := o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "client_credentials", Resource: "https://api.example.com/v1", ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})
				return err
			}
		}},
		"cimd first fetch": {[]oauthprovider.Option{c1CIMD(nil)}, func(t *testing.T, o opEnv) func(context.Context) error {
			return func(context.Context) error {
				_, err := o.op.Authorize(request(o.a, o.token), authzReq(c1DocURL))
				return err
			}
		}},
		"cimd refetch": {[]oauthprovider.Option{c1CIMD(nil)}, func(t *testing.T, o opEnv) func(context.Context) error {
			must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), authzReq(c1DocURL)))
			o.e.clock.Advance(oauthprovider.DefaultCIMDRevalidate + time.Second)
			return func(context.Context) error {
				_, err := o.op.Authorize(request(o.a, o.token), authzReq(c1DocURL))
				return err
			}
		}},
		"cimd not modified": {[]oauthprovider.Option{c1CIMD(map[string]string{"ETag": `"v1"`})}, func(t *testing.T, o opEnv) func(context.Context) error {
			must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), authzReq(c1DocURL)))
			o.e.clock.Advance(oauthprovider.DefaultCIMDRevalidate + time.Second)
			return func(context.Context) error {
				_, err := o.op.Authorize(request(o.a, o.token), authzReq(c1DocURL))
				return err
			}
		}},
		"dpop bound exchange": {nil, func(t *testing.T, o opEnv) func(context.Context) error {
			key := newDPoPKey(t, o.e.clock.Now)
			reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{DPoPBoundAccessTokens: true}})
			req := exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)
			req.DPoPProof = key.proof(t, "POST", testBaseURL+"/oauth2/token", "", 0, nil)
			return func(context.Context) error { _, err := o.op.Token(anon(o.a), req); return err }
		}},
		"discovered client, first use": {[]oauthprovider.Option{c1Discovery(nil)}, func(t *testing.T, o opEnv) func(context.Context) error {
			return func(context.Context) error {
				_, err := o.op.Authorize(request(o.a, o.token), authzReq("static:app"))
				return err
			}
		}},
		"discovered client, refresh": {[]oauthprovider.Option{c1Discovery(nil)}, func(t *testing.T, o opEnv) func(context.Context) error {
			must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), authzReq("static:app")))
			o.e.clock.Advance(2 * time.Hour)
			return func(context.Context) error {
				_, err := o.op.Authorize(request(o.a, o.token), authzReq("static:app"))
				return err
			}
		}},
		"code exchange for a resource": {[]oauthprovider.Option{oauthprovider.Scopes("openid", "profile", "email", "offline_access", "api:read"), oauthprovider.ProtectedResource("https://api.example.com/v1", "api:read"), oauthprovider.EnforcePerClientResources(false)}, func(t *testing.T, o opEnv) func(context.Context) error {
			reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
			in := authzReq(reg.ClientID)
			in.Resource = "https://api.example.com/v1"
			req := exchange(reg, o.code(t, in), opVerifier)
			req.Resource = in.Resource
			return func(context.Context) error { _, err := o.op.Token(anon(o.a), req); return err }
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) { opSweep(t, c.opts, c.setup) })
	}
}

// The resource registry under fault.
func TestOAuthProviderFaults_Resources(t *testing.T) {
	const api = "https://api.example.com/pay"
	create := func(t *testing.T, o opEnv) {
		if _, err := o.op.CreateResource(context.Background(), oauthprovider.Resource{Identifier: api, Name: "Pay"}); err != nil {
			t.Fatal(err)
		}
	}
	cases := map[string]func(t *testing.T, o opEnv) func(context.Context) error{
		"create": func(t *testing.T, o opEnv) func(context.Context) error {
			return func(ctx context.Context) error {
				_, err := o.op.CreateResource(ctx, oauthprovider.Resource{Identifier: api})
				return err
			}
		},
		"get": func(t *testing.T, o opEnv) func(context.Context) error {
			create(t, o)
			return func(ctx context.Context) error { _, err := o.op.Resource(ctx, api); return err }
		},
		"list": func(t *testing.T, o opEnv) func(context.Context) error {
			create(t, o)
			return func(ctx context.Context) error { _, err := o.op.Resources(ctx); return err }
		},
		"update": func(t *testing.T, o opEnv) func(context.Context) error {
			create(t, o)
			return func(ctx context.Context) error {
				_, err := o.op.UpdateResource(ctx, oauthprovider.Resource{Identifier: api, Name: "Renamed"})
				return err
			}
		},
		"delete": func(t *testing.T, o opEnv) func(context.Context) error {
			create(t, o)
			return func(ctx context.Context) error { return o.op.DeleteResource(ctx, api) }
		},
		"link": func(t *testing.T, o opEnv) func(context.Context) error {
			create(t, o)
			reg := o.client(t, oauthprovider.ClientSpec{})
			return func(ctx context.Context) error { _, err := o.op.LinkClient(ctx, api, reg.ClientID); return err }
		},
		"unlink": func(t *testing.T, o opEnv) func(context.Context) error {
			create(t, o)
			reg := o.client(t, oauthprovider.ClientSpec{})
			must[bool](t)(o.op.LinkClient(context.Background(), api, reg.ClientID))
			return func(ctx context.Context) error { return o.op.UnlinkClient(ctx, api, reg.ClientID) }
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) { opSweep(t, nil, setup) })
	}
}

// c1Do serves one request through h and returns the recorder; body is a
// form unless contentType says otherwise.
func c1Do(h http.Handler, method, target, contentType, body string, hdr http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, testBaseURL+target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// c1Error is the RFC 6749 error code of an answer.
func c1Error(w *httptest.ResponseRecorder) string {
	var b struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &b)
	return b.Error
}

const formType = "application/x-www-form-urlencoded"

// The endpoints' request shapes: a form where one is required, one
// parameter at a time, one client authentication method, one place for the
// access token, and the browser pages of a logout.
func TestOAuthProvider_HTTPRequestShapes(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, EnableEndSession: true})
		h := o.op.Handler()
		cookie := http.Header{"Cookie": {"__Host-auth_session=" + o.token.Reveal()}, "Origin": {testBaseURL}}
		html := http.Header{"Accept": {"text/html"}}
		authz := url.Values{"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {opRedirect}, "scope": {"openid"}, "state": {"s"}, "code_challenge": {opChallenge(opVerifier)}, "code_challenge_method": {"S256"}}

		// Authorize by POST: a form, answered 303 so the browser follows
		// with GET; another media type is refused.
		if w := c1Do(h, http.MethodPost, "/oauth2/authorize", "text/plain", authz.Encode(), cookie); w.Code != 400 || c1Error(w) != "invalid_request" {
			t.Fatalf("authorize text/plain = %d %s", w.Code, w.Body)
		}
		w := c1Do(h, http.MethodPost, "/oauth2/authorize", formType, authz.Encode(), cookie)
		if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, opRedirect+"?code=") {
			t.Fatalf("authorize POST = %d %s", w.Code, loc)
		}
		if w := c1Do(h, http.MethodGet, "/oauth2/authorize?client_id=a&client_id=b", "", "", nil); w.Code != 400 || c1Error(w) != "invalid_request" {
			t.Fatalf("repeated authorize parameter = %d %s", w.Code, w.Body)
		}
		// A form body that does not parse.
		if w := c1Do(h, http.MethodPost, "/oauth2/token", formType, "a=%zz", nil); w.Code != 400 || c1Error(w) != "invalid_request" {
			t.Fatalf("broken form = %d %s", w.Code, w.Body)
		}

		// Client authentication by assertion: exactly one method, a
		// non-empty assertion, and the client named by the assertion's sub
		// when the form names none.
		basic := http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(reg.ClientID+":"+reg.Secret))}}
		jwtBearer := "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
		grant := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"ubor_x"}}
		with := func(extra url.Values) string {
			f := url.Values{}
			for k, v := range grant {
				f[k] = v
			}
			for k, v := range extra {
				f[k] = v
			}
			return f.Encode()
		}
		if w := c1Do(h, http.MethodPost, "/oauth2/token", formType, with(url.Values{"client_assertion": {"a.b.c"}, "client_assertion_type": {jwtBearer}}), basic); w.Code != 400 || c1Error(w) != "invalid_request" {
			t.Fatalf("assertion and Basic = %d %s", w.Code, w.Body)
		}
		if w := c1Do(h, http.MethodPost, "/oauth2/token", formType, with(url.Values{"client_assertion_type": {jwtBearer}}), nil); w.Code != 401 || c1Error(w) != "invalid_client" {
			t.Fatalf("empty assertion = %d %s", w.Code, w.Body)
		}
		if w := c1Do(h, http.MethodPost, "/oauth2/token", formType, with(url.Values{"client_assertion": {"not-a-jwt"}, "client_assertion_type": {jwtBearer}}), nil); w.Code != 401 || c1Error(w) != "invalid_client" {
			t.Fatalf("unreadable assertion = %d %s", w.Code, w.Body)
		}
		// A well-formed assertion naming a client_secret_basic client by its
		// sub: the method is wrong for that client, so it is refused.
		forged := "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"`+reg.ClientID+`"}`)) + ".c2ln"
		if w := c1Do(h, http.MethodPost, "/oauth2/token", formType, with(url.Values{"client_assertion": {forged}, "client_assertion_type": {jwtBearer}}), nil); w.Code != 401 || c1Error(w) != "invalid_client" {
			t.Fatalf("assertion for a secret client = %d %s", w.Code, w.Body)
		}

		// Userinfo: the token in the header or the form, never both, and
		// only a Bearer or DPoP header.
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		bearer := http.Header{"Authorization": {"Bearer " + tok.AccessToken}}
		if w := c1Do(h, http.MethodGet, "/oauth2/userinfo", "", "", http.Header{"Authorization": {"Basic eDp5"}}); w.Code != 401 || c1Error(w) != "invalid_token" {
			t.Fatalf("userinfo Basic = %d %s", w.Code, w.Body)
		}
		if w := c1Do(h, http.MethodPost, "/oauth2/userinfo", "text/plain", "access_token="+tok.AccessToken, nil); w.Code != 400 {
			t.Fatalf("userinfo text/plain = %d %s", w.Code, w.Body)
		}
		if w := c1Do(h, http.MethodPost, "/oauth2/userinfo", formType, "access_token="+tok.AccessToken, bearer); w.Code != 400 || c1Error(w) != "invalid_request" {
			t.Fatalf("userinfo token twice = %d %s", w.Code, w.Body)
		}
		w = c1Do(h, http.MethodPost, "/oauth2/userinfo", formType, "access_token="+tok.AccessToken, nil)
		var info map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &info)
		if w.Code != 200 || info["sub"] != o.user.ID {
			t.Fatalf("userinfo by form = %d %s", w.Code, w.Body)
		}
		// A client certificate on the connection rides along; an unbound
		// token still answers.
		req := httptest.NewRequest(http.MethodGet, testBaseURL+"/oauth2/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{selfSigned(t, "client")}}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("userinfo over mutual TLS = %d %s", rec.Code, rec.Body)
		}

		// Registration: a JSON body, and only a Bearer initial access token.
		meta := `{"client_name":"x","redirect_uris":["` + opRedirect + `"]}`
		if w := c1Do(h, http.MethodPost, "/oauth2/register", "application/json", "{", nil); w.Code != 400 || c1Error(w) != "invalid_client_metadata" {
			t.Fatalf("register broken JSON = %d %s", w.Code, w.Body)
		}
		if w := c1Do(h, http.MethodPost, "/oauth2/register", "application/json", meta, http.Header{"Authorization": {"Basic eDp5"}}); w.Code != 400 || c1Error(w) != "invalid_request" {
			t.Fatalf("register Basic = %d %s", w.Code, w.Body)
		}
		if w := c1Do(h, http.MethodPost, "/oauth2/register", "application/json", meta, http.Header{"Authorization": {"Bearer iat-1"}}); w.Code != 401 || c1Error(w) != "invalid_token" {
			t.Fatalf("register with an unvalidated initial access token = %d %s", w.Code, w.Body)
		}

		// Logout: a form for POST, one value per parameter, the success page
		// with its notice for a browser and {"ok":true} for a script.
		if w := c1Do(h, http.MethodPost, "/oauth2/end-session", "text/plain", "", nil); w.Code != 400 {
			t.Fatalf("end-session text/plain = %d", w.Code)
		}
		if w := c1Do(h, http.MethodGet, "/oauth2/end-session?state=a&state=b", "", "", nil); w.Code != 400 || c1Error(w) != "invalid_request" {
			t.Fatalf("repeated logout parameter = %d %s", w.Code, w.Body)
		}
		if w := c1Do(h, http.MethodPost, "/oauth2/end-session/confirm", "text/plain", "action=confirm", nil); w.Code != 400 {
			t.Fatalf("confirm text/plain = %d", w.Code)
		}
		// A script's cross-origin fetch is no browser, even accepting HTML:
		// no confirmation page.
		if w := c1Do(h, http.MethodGet, "/oauth2/end-session", "", "", http.Header{"Accept": {"text/html"}, "Sec-Fetch-Mode": {"cors"}}); w.Code != 400 || c1Error(w) != "invalid_request" {
			t.Fatalf("cors fetch = %d %s", w.Code, w.Body)
		}
		page := url.Values{"id_token_hint": {tok.IDToken}, "post_logout_redirect_uri": {"https://evil.example/"}}
		w = c1Do(h, http.MethodPost, "/oauth2/end-session", formType, page.Encode(), http.Header{"Cookie": cookie["Cookie"], "Origin": cookie["Origin"], "Accept": html["Accept"]})
		if w.Code != 200 || !strings.Contains(w.Body.String(), "<h1>Logged out</h1>") || !strings.Contains(w.Body.String(), "<p>The requested post-logout redirect was not registered.</p>") {
			t.Fatalf("logout page = %d %s", w.Code, w.Body)
		}
		// A script with a valid hint for a session the browser does not
		// carry: the hinted session ends, the answer is JSON.
		again := must[password.SignInResult](t)(o.pw.SignIn(anon(o.a), password.SignInRequest{Identifier: aliceRaw, Password: secret}))
		o2 := o
		o2.token = again.Token
		tok2 := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o2.code(t, authzReq(reg.ClientID)), opVerifier)))
		w = c1Do(h, http.MethodGet, "/oauth2/end-session?id_token_hint="+tok2.IDToken, "", "", nil)
		if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"ok":true}` {
			t.Fatalf("script logout = %d %s", w.Code, w.Body)
		}
		if _, _, _, err := o.a.ResolveSession(context.Background(), again.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("hinted session survived: %v", err)
		}
	})
}

// A failed session read in front of every endpoint answers 500 and runs
// nothing: the browser's session, or an API key header the app's options
// name, is resolved before the operation.
func TestOAuthProvider_HTTPSessionReadFails(t *testing.T) {
	cookie := func(o opEnv) http.Header {
		return http.Header{"Cookie": {"__Host-auth_session=" + o.token.Reveal()}, "Origin": {testBaseURL}}
	}
	apiKey := func(opEnv) http.Header { return http.Header{"X-Api-Key": {"key-1"}} }
	// userinfo answers a request with no access token before reading any
	// session (RFC 6750's bare challenge), so its case carries one.
	apiKeyBearer := func(opEnv) http.Header {
		return http.Header{"X-Api-Key": {"key-1"}, "Authorization": {"Bearer uboa_x"}}
	}
	for name, c := range map[string]struct {
		method, target, ct, body string
		hdr                      func(opEnv) http.Header
	}{
		"authorize":   {http.MethodGet, "/oauth2/authorize?response_type=code&client_id=x", "", "", cookie},
		"end-session": {http.MethodGet, "/oauth2/end-session", "", "", cookie},
		"confirm":     {http.MethodPost, "/oauth2/end-session/confirm", formType, "action=confirm", cookie},
		"register":    {http.MethodPost, "/oauth2/register", "application/json", `{"client_name":"x"}`, cookie},
		"token":       {http.MethodPost, "/oauth2/token", formType, "grant_type=refresh_token&client_id=x", apiKey},
		"userinfo":    {http.MethodGet, "/oauth2/userinfo", "", "", apiKeyBearer},
	} {
		t.Run(name, func(t *testing.T) {
			fe := newFaultEnv(t)
			o := newOPEnv(t, fe.env)
			h := o.op.Handler(authhttp.APIKeyHeader("X-Api-Key"))
			fe.f.arm(1)
			w := c1Do(h, c.method, c.target, c.ct, c.body, c.hdr(o))
			if !fe.f.disarm() {
				t.Fatal("the request made no database call")
			}
			if w.Code != http.StatusInternalServerError || w.Header().Get("Location") != "" {
				t.Fatalf("%s = %d %s", name, w.Code, w.Body)
			}
		})
	}
	// An operation that fails inside is a 500 too, logged, never a redirect.
	fe := newFaultEnv(t)
	o := newOPEnv(t, fe.env)
	reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
	fe.f.arm(1)
	w := c1Do(o.op.Handler(), http.MethodGet, "/oauth2/authorize?response_type=code&client_id="+reg.ClientID, "", "", nil)
	if !fe.f.disarm() || w.Code != http.StatusInternalServerError || w.Header().Get("Location") != "" {
		t.Fatalf("failed authorize = %d %s", w.Code, w.Body)
	}
}

// Client metadata the provider cannot serve safely is refused at creation,
// each rule on its own.
func TestOAuthProvider_ClientMetadataRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		attest := oauthprovider.ClientAuthMethod{Method: "attest", Authenticate: func(context.Context, oauthprovider.Client, oauthprovider.ClientCredentials) (*oauthprovider.Confirmation, error) {
			return nil, nil
		}}
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "profile", "email", "offline_access", "api:read"), oauthprovider.Extend(oauthprovider.Extension{ID: "attest", ClientAuthentication: []oauthprovider.ClientAuthMethod{attest}}))
		base := func() oauthprovider.ClientMetadata {
			return oauthprovider.ClientMetadata{Name: "x", RedirectURIs: []string{opRedirect}}
		}
		for name, c := range map[string]struct {
			mutate func(*oauthprovider.ClientMetadata)
			want   error
		}{
			"unknown auth method":         {func(m *oauthprovider.ClientMetadata) { m.AuthMethod = "client_secret_jwt" }, oauthprovider.ErrInvalidClientMetadata},
			"grant not served":            {func(m *oauthprovider.ClientMetadata) { m.GrantTypes = []string{"password"} }, oauthprovider.ErrInvalidClientMetadata},
			"implicit response type":      {func(m *oauthprovider.ClientMetadata) { m.ResponseTypes = []string{"token"} }, oauthprovider.ErrInvalidClientMetadata},
			"no redirect URI":             {func(m *oauthprovider.ClientMetadata) { m.RedirectURIs = nil }, oauthprovider.ErrInvalidRedirectURI},
			"too many contacts":           {func(m *oauthprovider.ClientMetadata) { m.Contacts = make([]string, 100) }, oauthprovider.ErrInvalidClientMetadata},
			"unknown application type":    {func(m *oauthprovider.ClientMetadata) { m.ApplicationType = "desktop" }, oauthprovider.ErrInvalidClientMetadata},
			"too many post-logout URIs":   {func(m *oauthprovider.ClientMetadata) { m.PostLogoutRedirectURIs = make([]string, 100) }, oauthprovider.ErrInvalidClientMetadata},
			"bad post-logout URI":         {func(m *oauthprovider.ClientMetadata) { m.PostLogoutRedirectURIs = []string{"http://evil.example/"} }, oauthprovider.ErrInvalidRedirectURI},
			"private_key_jwt without key": {func(m *oauthprovider.ClientMetadata) { m.AuthMethod = oauthprovider.AuthMethodPrivateKeyJWT }, oauthprovider.ErrInvalidClientMetadata},
			"keys nothing uses":           {func(m *oauthprovider.ClientMetadata) { m.JWKS = json.RawMessage(`{"keys":[]}`) }, oauthprovider.ErrInvalidClientMetadata},
			"relative client URI":         {func(m *oauthprovider.ClientMetadata) { m.ClientURI = "/about" }, oauthprovider.ErrInvalidClientMetadata},
			"contact with a space":        {func(m *oauthprovider.ClientMetadata) { m.Contacts = []string{"a b@example.com"} }, oauthprovider.ErrInvalidClientMetadata},
			"empty contact":               {func(m *oauthprovider.ClientMetadata) { m.Contacts = []string{""} }, oauthprovider.ErrInvalidClientMetadata},
			"unknown scope":               {func(m *oauthprovider.ClientMetadata) { m.Scope = "openid admin" }, oauthprovider.ErrInvalidScope},
			"back-channel with fragment":  {func(m *oauthprovider.ClientMetadata) { m.BackchannelLogoutURI = "https://rp.example/bc#x" }, oauthprovider.ErrInvalidClientMetadata},
			"extension method, bad keys": {func(m *oauthprovider.ClientMetadata) {
				m.AuthMethod, m.JWKS = "attest", json.RawMessage(`{"keys":"nope"}`)
			}, oauthprovider.ErrInvalidClientMetadata},
		} {
			m := base()
			c.mutate(&m)
			if _, err := o.op.CreateClient(context.Background(), oauthprovider.ClientSpec{ClientMetadata: m}); !errors.Is(err, c.want) {
				t.Errorf("%s: %v, want %v", name, err, c.want)
			}
		}
		// A private_key_jwt client with a key set that does not parse.
		bad := base()
		bad.AuthMethod, bad.JWKS = oauthprovider.AuthMethodPrivateKeyJWT, json.RawMessage(`{"keys":"nope"}`)
		if _, err := o.op.CreateClient(context.Background(), oauthprovider.ClientSpec{ClientMetadata: bad}); err == nil {
			t.Fatal("an unreadable key set was accepted")
		}
	})
}

// The client registry's refusals: unknown clients, a method that cannot
// change, restricted fields an admin sets wrongly, a public client's
// missing secret, and the app's privileges hook on every owner action.
func TestOAuthProvider_ClientManagementRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var deny string
		o := newOPEnv(t, e, oauthprovider.ClientPrivileges(func(_ context.Context, action string, _ *auth.Call, _ *oauthprovider.Client) bool {
			return action != deny
		}))
		ctx := context.Background()
		meta := oauthprovider.ClientMetadata{Name: "Mine", RedirectURIs: []string{opRedirect}}
		if err := o.op.SetClientDisabled(ctx, "oac_unknown", true); !errors.Is(err, oauthprovider.ErrClientNotFound) {
			t.Fatalf("disable unknown: %v", err)
		}
		if err := o.op.DeleteClient(ctx, "oac_unknown"); !errors.Is(err, oauthprovider.ErrClientNotFound) {
			t.Fatalf("delete unknown: %v", err)
		}
		if _, err := o.op.UpdateClient(ctx, "oac_unknown", oauthprovider.ClientSpec{ClientMetadata: meta}); !errors.Is(err, oauthprovider.ErrClientNotFound) {
			t.Fatalf("update unknown: %v", err)
		}
		reg := o.client(t, oauthprovider.ClientSpec{})
		for name, c := range map[string]struct {
			spec oauthprovider.ClientSpec
			want error
		}{
			"method change":      {oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "x", RedirectURIs: []string{opRedirect}, AuthMethod: oauthprovider.AuthMethodNone}}, oauthprovider.ErrInvalidClientMetadata},
			"bad metadata":       {oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "x"}}, oauthprovider.ErrInvalidRedirectURI},
			"user scope for M2M": {oauthprovider.ClientSpec{ClientMetadata: meta, ClientCredentialsScopes: []string{"openid"}}, oauthprovider.ErrInvalidScope},
			"metadata not JSON":  {oauthprovider.ClientSpec{ClientMetadata: meta, Metadata: json.RawMessage(`{`)}, oauthprovider.ErrInvalidClientMetadata},
		} {
			if _, err := o.op.UpdateClient(ctx, reg.ClientID, c.spec); !errors.Is(err, c.want) {
				t.Errorf("update %s: %v, want %v", name, err, c.want)
			}
		}
		if _, err := o.op.CreateClient(ctx, oauthprovider.ClientSpec{ClientMetadata: meta, Metadata: json.RawMessage(`{`)}); !errors.Is(err, oauthprovider.ErrInvalidClientMetadata) {
			t.Fatalf("create with metadata that is not JSON: %v", err)
		}
		// A disabled client has no public page.
		must[struct{}](t)(struct{}{}, o.op.SetClientDisabled(ctx, reg.ClientID, true))
		if _, err := o.op.PublicClientInfo(request(o.a, o.token), reg.ClientID); !errors.Is(err, oauthprovider.ErrClientNotFound) {
			t.Fatalf("public info of a disabled client: %v", err)
		}

		// Owner actions on a client that is not there.
		sctx := request(o.a, o.token)
		if _, err := o.op.OwnedClient(sctx, "oac_unknown"); !errors.Is(err, oauthprovider.ErrClientNotFound) {
			t.Fatalf("get unknown: %v", err)
		}
		if _, err := o.op.UpdateOwnedClient(sctx, oauthprovider.UpdateClientRequest{ClientID: "oac_unknown", Metadata: meta}); !errors.Is(err, oauthprovider.ErrClientNotFound) {
			t.Fatalf("update unknown: %v", err)
		}
		if _, err := o.op.RotateSecret(sctx, "oac_unknown"); !errors.Is(err, oauthprovider.ErrClientNotFound) {
			t.Fatalf("rotate unknown: %v", err)
		}
		if err := o.op.DeleteOwnedClient(sctx, "oac_unknown"); !errors.Is(err, oauthprovider.ErrClientNotFound) {
			t.Fatalf("delete unknown: %v", err)
		}
		mine := must[oauthprovider.Registration](t)(o.op.CreateOwnedClient(sctx, meta))
		if _, err := o.op.UpdateOwnedClient(sctx, oauthprovider.UpdateClientRequest{ClientID: mine.ClientID, Metadata: oauthprovider.ClientMetadata{Name: "x"}}); !errors.Is(err, oauthprovider.ErrInvalidRedirectURI) {
			t.Fatalf("owner update with bad metadata: %v", err)
		}
		public := must[oauthprovider.Registration](t)(o.op.CreateOwnedClient(sctx, oauthprovider.ClientMetadata{Name: "SPA", RedirectURIs: []string{opRedirect}, AuthMethod: oauthprovider.AuthMethodNone}))
		if _, err := o.op.RotateSecret(sctx, public.ClientID); !errors.Is(err, oauthprovider.ErrInvalidClientMetadata) {
			t.Fatalf("rotate a public client's secret: %v", err)
		}
		// The privileges hook refuses each action by name.
		for action, call := range map[string]func() error{
			oauthprovider.ActionCreate: func() error { _, err := o.op.CreateOwnedClient(sctx, meta); return err },
			oauthprovider.ActionList:   func() error { _, err := o.op.Clients(sctx); return err },
			oauthprovider.ActionRead:   func() error { _, err := o.op.OwnedClient(sctx, mine.ClientID); return err },
			oauthprovider.ActionUpdate: func() error {
				_, err := o.op.UpdateOwnedClient(sctx, oauthprovider.UpdateClientRequest{ClientID: mine.ClientID, Metadata: meta})
				return err
			},
			oauthprovider.ActionRotate: func() error { _, err := o.op.RotateSecret(sctx, mine.ClientID); return err },
			oauthprovider.ActionDelete: func() error { return o.op.DeleteOwnedClient(sctx, mine.ClientID) },
		} {
			deny = action
			if err := call(); !errors.Is(err, oauthprovider.ErrForbidden) {
				t.Errorf("%s denied: %v", action, err)
			}
		}
		deny = ""
		if _, err := o.op.OwnedClient(sctx, mine.ClientID); err != nil {
			t.Fatalf("the refused delete deleted: %v", err)
		}
	})
}

// newOPEnvWith is newOPEnv with the core's options in place of the plugin
// cookie secret, for a provider built without one or with a failing id
// generator.
func newOPEnvWith(t *testing.T, e *env, authOpts []auth.Option, opts ...oauthprovider.Option) opEnv {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	return newOPEnvJWT(t, e, jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL)), authOpts, opts...)
}

// newOPEnvJWT is newOPEnvWith with the caller's jwt plugin.
func newOPEnvJWT(t *testing.T, e *env, jw *jwt.Plugin, authOpts []auth.Option, opts ...oauthprovider.Option) opEnv {
	t.Helper()
	op := oauthprovider.New(jw, append([]oauthprovider.Option{oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login"), oauthprovider.ConsentPage("/consent")}, opts...)...)
	em, pw := e.emailPlugin(), e.passwordPlugin()
	a := e.newAuth(t, authOpts, em, pw, jw, op)
	up := signUpVerified(t, e, a, pw, em)
	return opEnv{pw: pw, e: e, a: a, jw: jw, op: op, user: up.User, token: up.Token}
}

// Authorization requests the provider refuses, each at the client's
// redirect URI except those that must not be redirected.
func TestOAuthProvider_AuthorizeRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "profile", "email", "offline_access", "api:read"))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{Scope: "openid"}})
		m2m := o.client(t, oauthprovider.ClientSpec{ClientCredentialsScopes: []string{"api:read"}, ClientMetadata: oauthprovider.ClientMetadata{GrantTypes: []string{"client_credentials"}}})
		for name, c := range map[string]struct {
			mutate func(*oauthprovider.AuthorizeRequest)
			want   error
		}{
			"state too long":           {func(r *oauthprovider.AuthorizeRequest) { r.State = strings.Repeat("s", 1025) }, oauthprovider.ErrBadRedirectTarget},
			"fragment mode":            {func(r *oauthprovider.AuthorizeRequest) { r.ResponseMode = "fragment" }, oauthprovider.ErrInvalidRequest},
			"no code grant":            {func(r *oauthprovider.AuthorizeRequest) { r.ClientID = m2m.ClientID }, oauthprovider.ErrUnauthorizedClient},
			"unknown scope":            {func(r *oauthprovider.AuthorizeRequest) { r.Scope = "admin" }, oauthprovider.ErrInvalidScope},
			"plain PKCE":               {func(r *oauthprovider.AuthorizeRequest) { r.CodeChallengeMethod = "plain" }, oauthprovider.ErrInvalidRequest},
			"method without PKCE":      {func(r *oauthprovider.AuthorizeRequest) { r.CodeChallenge = "" }, oauthprovider.ErrInvalidRequest},
			"bad dpop_jkt":             {func(r *oauthprovider.AuthorizeRequest) { r.DPoPJKT = "short" }, oauthprovider.ErrInvalidRequest},
			"nonce too long":           {func(r *oauthprovider.AuthorizeRequest) { r.Nonce = strings.Repeat("n", 513) }, oauthprovider.ErrInvalidRequest},
			"none with another prompt": {func(r *oauthprovider.AuthorizeRequest) { r.Prompt = "none login" }, oauthprovider.ErrInvalidRequest},
			"request and request_uri":  {func(r *oauthprovider.AuthorizeRequest) { r.Request, r.RequestURI = "x.y.z", "urn:x" }, oauthprovider.ErrInvalidRequest},
		} {
			in := authzReq(reg.ClientID)
			in.Scope = "openid"
			c.mutate(&in)
			_, err := o.op.Authorize(request(o.a, o.token), in)
			if !errors.Is(err, c.want) {
				t.Errorf("%s: %v, want %v", name, err, c.want)
				continue
			}
			var re *oauthprovider.RedirectError
			if errors.As(err, &re) && (err.Error() == "" || !strings.HasPrefix(re.RedirectTo, opRedirect)) {
				t.Errorf("%s: redirect error %q to %q", name, err.Error(), re.RedirectTo)
			}
		}
		// The method without a challenge is refused even when the client
		// does not require PKCE.
		opt := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, OptionalPKCE: true})
		in := authzReq(opt.ClientID)
		in.CodeChallenge = ""
		if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("method without challenge: %v", err)
		}
		// No redirect_uri with one registered uses it; no scope uses the
		// client's.
		in = authzReq(reg.ClientID)
		in.RedirectURI, in.Scope = "", ""
		res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), in))
		if !strings.HasPrefix(res.RedirectTo, opRedirect+"?code=") {
			t.Fatalf("defaults = %s", res.RedirectTo)
		}
		// prompt=create without a sign-up page goes to the login page.
		in = authzReq(reg.ClientID)
		in.Scope, in.Prompt = "openid", "create"
		if res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), in)); !strings.HasPrefix(res.RedirectTo, "/login?") {
			t.Fatalf("prompt=create = %s", res.RedirectTo)
		}
	})
}

// Token requests the provider refuses, and the narrowing a refresh may do.
func TestOAuthProvider_TokenRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const api = "https://api.example.com/v1"
		var failEncode bool
		format := oauthprovider.RefreshTokenFormat{
			Encode: func(_ context.Context, tok, _ string) (string, error) {
				if failEncode {
					return "", errors.New("encoder down")
				}
				return tok, nil
			},
			Decode: func(_ context.Context, s string) (string, error) { return s, nil },
		}
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "profile", "email", "offline_access", "api:read"), oauthprovider.FormatRefreshToken(format),
			oauthprovider.Claims(func(_ context.Context, _ auth.User, _ []string) map[string]any {
				return map[string]any{"tier": "gold", "sub": "forged", "iss": "forged"}
			}))
		ctx := context.Background()
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		other := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		cred := func(r oauthprovider.Registration, in oauthprovider.TokenRequest) oauthprovider.TokenRequest {
			in.ClientID, in.ClientSecret, in.ClientAuthMethod = r.ClientID, r.Secret, oauthprovider.AuthMethodBasic
			return in
		}
		for name, c := range map[string]struct {
			in   oauthprovider.TokenRequest
			want error
		}{
			"password grant": {cred(reg, oauthprovider.TokenRequest{GrantType: "password"}), oauthprovider.ErrUnsupportedGrantType},
			"no code":        {cred(reg, oauthprovider.TokenRequest{GrantType: "authorization_code"}), oauthprovider.ErrInvalidRequest},
			"no refresh":     {cred(reg, oauthprovider.TokenRequest{GrantType: "refresh_token"}), oauthprovider.ErrInvalidRequest},
			"no M2M ceiling": {cred(reg, oauthprovider.TokenRequest{GrantType: "client_credentials"}), oauthprovider.ErrUnauthorizedClient},
			"undecodable":    {cred(reg, oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: "ubor_"}), oauthprovider.ErrInvalidGrant},
		} {
			if _, err := o.op.Token(anon(o.a), c.in); !errors.Is(err, c.want) {
				t.Errorf("%s: %v, want %v", name, err, c.want)
			}
		}
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		// The app's claims reach the ID token and userinfo; a protected
		// claim is never replaced.
		info := must[map[string]any](t)(o.op.UserInfo(anon(o.a), tok.AccessToken))
		if info["tier"] != "gold" || info["sub"] != o.user.ID || info["iss"] != nil {
			t.Fatalf("userinfo with app claims = %v", info)
		}
		refresh := func(r oauthprovider.Registration, rt, scope, resource string) (oauthprovider.TokenResponse, error) {
			return o.op.Token(anon(o.a), cred(r, oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: rt, Scope: scope, Resource: resource}))
		}
		if _, err := refresh(other, tok.RefreshToken, "", ""); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("another client's refresh token: %v", err)
		}
		if _, err := refresh(reg, tok.RefreshToken, "openid admin", ""); !errors.Is(err, oauthprovider.ErrInvalidScope) {
			t.Fatalf("widening refresh: %v", err)
		}
		if _, err := refresh(reg, tok.RefreshToken, "", api); !errors.Is(err, oauthprovider.ErrInvalidTarget) {
			t.Fatalf("refresh for another resource: %v", err)
		}
		narrowed := must[oauthprovider.TokenResponse](t)(refresh(reg, tok.RefreshToken, "openid offline_access openid", ""))
		if narrowed.Scope != "openid offline_access" {
			t.Fatalf("narrowed = %q", narrowed.Scope)
		}
		// A refresh whose encoder fails issues nothing.
		failEncode = true
		if _, err := refresh(reg, narrowed.RefreshToken, "", ""); err == nil || errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("failing encoder: %v", err)
		}
		failEncode = false
		// The failed refresh rolled back: the token still refreshes.
		narrowed = must[oauthprovider.TokenResponse](t)(refresh(reg, narrowed.RefreshToken, "", ""))
		// A token without openid has no userinfo; a malformed one is no
		// token at all.
		noID := authzReq(reg.ClientID)
		noID.Scope = "profile"
		plain := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, noID), opVerifier)))
		if _, err := o.op.UserInfo(anon(o.a), plain.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidScope) {
			t.Fatalf("userinfo without openid: %v", err)
		}
		if _, err := o.op.VerifyAccessToken(ctx, "not-a-token"); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("malformed token: %v", err)
		}
		// Introspection and revocation need a token.
		if _, err := o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("introspect nothing: %v", err)
		}
		if err := o.op.Revoke(anon(o.a), oauthprovider.RevokeRequest{ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("revoke nothing: %v", err)
		}
		// A spent refresh token introspects inactive; so does an expired
		// access token.
		in := must[oauthprovider.Introspection](t)(o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: tok.RefreshToken, TokenTypeHint: "refresh_token", ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		if in.Active {
			t.Fatalf("rotated refresh token = %+v", in)
		}
		e.clock.Advance(2 * time.Hour)
		in = must[oauthprovider.Introspection](t)(o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: narrowed.AccessToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		if in.Active {
			t.Fatalf("expired access token = %+v", in)
		}
		// A deleted user's grants are dead: invalid_grant for a code and a
		// refresh token, invalid_token at userinfo.
		code := o.code(t, authzReq(reg.ClientID))
		live := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		if err := o.a.DeleteUser(ctx, o.user.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := o.op.Token(anon(o.a), exchange(reg, code, opVerifier)); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("code of a deleted user: %v", err)
		}
		if _, err := refresh(reg, live.RefreshToken, "", ""); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("refresh of a deleted user: %v", err)
		}
	})
}

// Without a secret nothing is signed: a page's query is the plain request,
// so the consent and continue operations parse it themselves and refuse
// what does not parse. Pre-login lookups need a signature, so auth.New
// refuses AllowPublicClientPrelogin without a secret (ErrNoSecret,
// TestValidate_SecretUsersNeedASecret in the provider's own tests).
func TestOAuthProvider_UnsignedQueries(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnvWith(t, e, nil, oauthprovider.SelectAccount(oauthprovider.SelectAccountGate{Page: "/select"}))
		reg := o.client(t, oauthprovider.ClientSpec{})
		ctx := request(o.a, o.token)
		res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(ctx, authzReq(reg.ClientID)))
		q := must[*url.URL](t)(url.Parse(res.RedirectTo)).Query()
		if q.Get("sig") != "" || q.Get("client_id") != reg.ClientID {
			t.Fatalf("unsigned page query = %s", res.RedirectTo)
		}
		for name, raw := range map[string]string{"unparsable": "a=%zz", "repeated": "client_id=a&client_id=b"} {
			if _, err := o.op.Consent(ctx, oauthprovider.ConsentRequest{Query: raw, Accept: true}); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
				t.Errorf("consent %s: %v", name, err)
			}
			if _, err := o.op.Continue(ctx, oauthprovider.ContinueRequest{Query: raw, Selected: true}); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
				t.Errorf("continue %s: %v", name, err)
			}
		}
		// Continue drops the prompt its gate answered and keeps the rest:
		// with consent on record, prompt=consent still asks, and
		// select_account alone goes straight to the code.
		o.code(t, authzReq(reg.ClientID))
		in := authzReq(reg.ClientID)
		v := url.Values{"response_type": {in.ResponseType}, "client_id": {in.ClientID}, "redirect_uri": {in.RedirectURI}, "scope": {in.Scope}, "state": {in.State},
			"code_challenge": {in.CodeChallenge}, "code_challenge_method": {in.CodeChallengeMethod}, "prompt": {"select_account consent"}}
		res = must[oauthprovider.AuthorizeResult](t)(o.op.Continue(ctx, oauthprovider.ContinueRequest{Query: v.Encode(), Selected: true}))
		if u := must[*url.URL](t)(url.Parse(res.RedirectTo)); u.Path != "/consent" {
			t.Fatalf("continue after the picker, consent asked = %s", res.RedirectTo)
		}
		v.Set("prompt", "select_account")
		res = must[oauthprovider.AuthorizeResult](t)(o.op.Continue(ctx, oauthprovider.ContinueRequest{Query: v.Encode(), Selected: true}))
		if !strings.HasPrefix(res.RedirectTo, opRedirect+"?code=") {
			t.Fatalf("continue after the picker = %s", res.RedirectTo)
		}
	})
}

// Signed queries refuse what was not signed as is; pre-login lookups are
// off unless enabled.
func TestOAuthProvider_SignedQueryRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		reg := o.client(t, oauthprovider.ClientSpec{})
		res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), authzReq(reg.ClientID)))
		signed := must[*url.URL](t)(url.Parse(res.RedirectTo)).RawQuery
		if err := o.op.VerifyOAuthQuery(signed); err != nil {
			t.Fatalf("own query: %v", err)
		}
		if err := o.op.VerifyOAuthQuery("a=%zz"); !errors.Is(err, oauthprovider.ErrInvalidSignature) {
			t.Fatalf("unparsable: %v", err)
		}
		// A parameter repeated with the same value is a different query.
		if err := o.op.VerifyOAuthQuery(signed + "&state=st"); !errors.Is(err, oauthprovider.ErrInvalidSignature) {
			t.Fatalf("duplicated pair: %v", err)
		}
		if _, err := o.op.PublicClientPrelogin(anon(o.a), oauthprovider.PreloginRequest{OAuthQuery: signed}); !errors.Is(err, oauthprovider.ErrClientNotFound) {
			t.Fatalf("prelogin not enabled: %v", err)
		}
	})
}

// The request_uri resolver's own failure, and stored parameters that do
// not decode, end the request before any client is looked at.
func TestOAuthProvider_RequestURIResolverFailures(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		errStore := errors.New("par store down")
		o := newOPEnv(t, e, oauthprovider.RequestURIResolver(func(_ context.Context, uri, _ string) (url.Values, error) {
			if uri == "urn:down" {
				return nil, errStore
			}
			return url.Values{"state": {"a", "b"}}, nil
		}))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		if _, err := o.op.Authorize(request(o.a, o.token), oauthprovider.AuthorizeRequest{ClientID: reg.ClientID, RequestURI: "urn:down"}); !errors.Is(err, errStore) {
			t.Fatalf("resolver failure: %v", err)
		}
		if _, err := o.op.Authorize(request(o.a, o.token), oauthprovider.AuthorizeRequest{ClientID: reg.ClientID, RequestURI: "urn:repeated"}); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("repeated stored parameter: %v", err)
		}
	})
}

// The sign-up gate needs a trusted page: its own, else SignupPage, else it
// is a configuration error at request time.
func TestOAuthProvider_SignupGatePages(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		gate := oauthprovider.SignupRedirect(func(context.Context, oauthprovider.GateInfo) (bool, string) { return true, "" })
		o := newOPEnv(t, e, gate, oauthprovider.SignupPage("/signup"))
		reg := o.client(t, oauthprovider.ClientSpec{})
		res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), authzReq(reg.ClientID)))
		if !strings.HasPrefix(res.RedirectTo, "/signup?") {
			t.Fatalf("sign-up gate = %s", res.RedirectTo)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		bare := newOPEnv(t, e, oauthprovider.SignupRedirect(func(context.Context, oauthprovider.GateInfo) (bool, string) { return true, "" }))
		reg := bare.client(t, oauthprovider.ClientSpec{})
		if _, err := bare.op.Authorize(request(bare.a, bare.token), authzReq(reg.ClientID)); !errors.Is(err, oauthprovider.ErrBadGate) {
			t.Fatalf("sign-up gate without a page: %v", err)
		}
	})
}

// An extension grant's decision is checked like any other: a user that
// does not exist is invalid_grant, and a decision without a user cannot
// carry a scope that acts for one.
func TestOAuthProvider_ExtensionGrantDecisions(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const grantType = "urn:example:grant"
		grant := oauthprovider.ExtensionGrant{Type: grantType, Handle: func(_ context.Context, _ oauthprovider.Client, in oauthprovider.TokenRequest) (oauthprovider.GrantDecision, error) {
			if in.DeviceCode == "ghost" {
				return oauthprovider.GrantDecision{UserID: "usr_ghost", Scopes: []string{"openid"}}, nil
			}
			return oauthprovider.GrantDecision{Scopes: []string{"openid"}}, nil
		}}
		o := newOPEnv(t, e, oauthprovider.WithGrant(grant))
		reg := o.client(t, oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{GrantTypes: []string{grantType}}})
		req := oauthprovider.TokenRequest{GrantType: grantType, DeviceCode: "ghost", ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
		if _, err := o.op.Token(anon(o.a), req); !errors.Is(err, oauthprovider.ErrInvalidUser) {
			t.Fatalf("unknown user: %v", err)
		}
		req.DeviceCode = "nobody"
		if _, err := o.op.Token(anon(o.a), req); !errors.Is(err, oauthprovider.ErrInvalidScope) {
			t.Fatalf("user scope without a user: %v", err)
		}
	})
}

// A failing id generator (auth.WithIDs) stops every write that needs a new
// id, and nothing half-made is left behind.
func TestOAuthProvider_IDGeneratorFailures(t *testing.T) {
	errIDs := errors.New("id service down")
	const grantType = "urn:example:grant"
	for _, prefix := range []string{"oac", "oacn", "oaco", "oat", "oaf"} {
		t.Run(prefix, func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				var failOn string
				gen := func(p string) (string, error) {
					if p == failOn {
						return "", errIDs
					}
					return auth.NewID(p)
				}
				grant := oauthprovider.ExtensionGrant{Type: grantType, Handle: func(context.Context, oauthprovider.Client, oauthprovider.TokenRequest) (oauthprovider.GrantDecision, error) {
					return oauthprovider.GrantDecision{Scopes: []string{"api:read"}}, nil
				}}
				o := newOPEnvWith(t, e, []auth.Option{auth.WithIDs(gen), auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize)))},
					oauthprovider.Scopes("openid", "profile", "email", "offline_access", "api:read"), oauthprovider.WithGrant(grant))
				reg := o.client(t, oauthprovider.ClientSpec{ClientCredentialsScopes: []string{"api:read"}, ClientMetadata: oauthprovider.ClientMetadata{GrantTypes: []string{"authorization_code", "refresh_token", "client_credentials", grantType}}})
				var code string
				if prefix == "oat" || prefix == "oaf" {
					code = o.code(t, authzReq(reg.ClientID))
				}
				failOn = prefix
				var err error
				switch prefix {
				case "oac":
					_, err = o.op.CreateClient(context.Background(), oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "x", RedirectURIs: []string{opRedirect}}})
				case "oacn":
					res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), authzReq(reg.ClientID)))
					_, err = o.op.Consent(request(o.a, o.token), oauthprovider.ConsentRequest{Query: must[*url.URL](t)(url.Parse(res.RedirectTo)).RawQuery, Accept: true})
				case "oaco":
					failOn = ""
					res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), authzReq(reg.ClientID)))
					failOn = prefix
					_, err = o.op.Consent(request(o.a, o.token), oauthprovider.ConsentRequest{Query: must[*url.URL](t)(url.Parse(res.RedirectTo)).RawQuery, Accept: true})
				case "oat":
					_, err = o.op.Token(anon(o.a), exchange(reg, code, opVerifier))
				case "oaf":
					cred := func(in oauthprovider.TokenRequest) oauthprovider.TokenRequest {
						in.ClientID, in.ClientSecret, in.ClientAuthMethod = reg.ClientID, reg.Secret, oauthprovider.AuthMethodBasic
						return in
					}
					if _, err := o.op.Token(anon(o.a), cred(oauthprovider.TokenRequest{GrantType: grantType})); !errors.Is(err, errIDs) {
						t.Fatalf("extension grant: %v", err)
					}
					_, err = o.op.Token(anon(o.a), cred(oauthprovider.TokenRequest{GrantType: "client_credentials"}))
				}
				if !errors.Is(err, errIDs) {
					t.Fatalf("%s: %v", prefix, err)
				}
				failOn = ""
				// The code was not spent by the failed exchange.
				if code != "" && prefix == "oat" {
					must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, code, opVerifier)))
				}
			})
		})
	}
}

// A consent given under one post-login reference is replaced, not widened,
// when the user consents under another: the narrower answer is what the
// user said last.
func TestOAuthProvider_ConsentReferenceReplaced(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ref := "org_1"
		o := newOPEnv(t, e, oauthprovider.PostLogin(oauthprovider.PostLoginGate{Page: "/org",
			ShouldRedirect:     func(context.Context, oauthprovider.GateInfo) bool { return true },
			ConsentReferenceID: func(context.Context, oauthprovider.GateInfo) string { return ref }}))
		reg := o.client(t, oauthprovider.ClientSpec{})
		ctx := request(o.a, o.token)
		consent := func(scope string) {
			q := pageQuery(t, must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(ctx, authzReq(reg.ClientID))), "/org")
			cq := pageQuery(t, must[oauthprovider.AuthorizeResult](t)(o.op.Continue(ctx, oauthprovider.ContinueRequest{Query: q, PostLogin: true})), "/consent")
			must[oauthprovider.AuthorizeResult](t)(o.op.Consent(ctx, oauthprovider.ConsentRequest{Query: cq, Accept: true, Scope: scope}))
		}
		consent("openid profile email")
		ref = "org_2"
		consent("openid")
		list := must[oauthprovider.ConsentList](t)(o.op.Consents(ctx))
		if len(list.Consents) != 1 || strings.Join(list.Consents[0].Scopes, " ") != "openid" {
			t.Fatalf("consents = %+v", list)
		}
	})
}

// Logout's less travelled paths: a hint whose client is gone, a forged
// hint naming a client, a hinted session already over, the confirmation
// of a client changed since, and a confirmation without a browser session.
func TestOAuthProvider_EndSessionEdges(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.AccessTokenTTL(time.Minute))
		const after = "https://client.example/bye"
		spec := oauthprovider.ClientSpec{SkipConsent: true, EnableEndSession: true, ClientMetadata: oauthprovider.ClientMetadata{Name: "C", RedirectURIs: []string{opRedirect}, PostLogoutRedirectURIs: []string{after}}}
		reg := o.client(t, spec)
		gone := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, EnableEndSession: true})
		goneTok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(gone, o.code(t, authzReq(gone.ClientID)), opVerifier)))
		must[struct{}](t)(struct{}{}, o.op.DeleteClient(context.Background(), gone.ClientID))
		ctx := request(o.a, o.token)
		if res := must[oauthprovider.EndSessionResult](t)(o.op.EndSession(ctx, oauthprovider.EndSessionRequest{IDTokenHint: goneTok.IDToken, Browser: true})); res.Page != oauthprovider.PageConfirm {
			t.Fatalf("hint of a deleted client in a browser = %+v", res)
		}
		if _, err := o.op.EndSession(ctx, oauthprovider.EndSessionRequest{IDTokenHint: goneTok.IDToken}); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("hint of a deleted client: %v", err)
		}
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		if res := must[oauthprovider.EndSessionResult](t)(o.op.EndSession(ctx, oauthprovider.EndSessionRequest{IDTokenHint: tok.IDToken + "x", ClientID: reg.ClientID, PostLogoutRedirectURI: after, Browser: true})); res.Page != oauthprovider.PageConfirm {
			t.Fatalf("forged hint naming the client = %+v", res)
		}
		// The Go API without the signed confirmation state is refused.
		if _, err := o.op.ConfirmEndSession(ctx, oauthprovider.EndSessionConfirmRequest{Action: "confirm"}); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("confirm without state: %v", err)
		}
		// A hint for a session that already ended, from no browser: nothing
		// left to end, still a success.
		if err := o.a.SignOut(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := o.op.EndSession(anon(o.a), oauthprovider.EndSessionRequest{IDTokenHint: tok.IDToken}); err != nil {
			t.Fatalf("hint for an ended session: %v", err)
		}
		// A hint whose sid the client no longer holds a token for (swept
		// after expiry) ends nothing: the session stays.
		again := must[password.SignInResult](t)(o.pw.SignIn(anon(o.a), password.SignInRequest{Identifier: aliceRaw, Password: secret}))
		o2 := o
		o2.token = again.Token
		short := authzReq(reg.ClientID)
		short.Scope = "openid"
		swept := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o2.code(t, short), opVerifier)))
		if swept.ExpiresIn != 60 {
			t.Fatalf("AccessTokenTTL: expires_in = %d", swept.ExpiresIn)
		}
		e.clock.Advance(2 * time.Minute)
		if _, err := o.op.Sweep(context.Background(), e.clock.Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := o.op.EndSession(anon(o.a), oauthprovider.EndSessionRequest{IDTokenHint: swept.IDToken}); err != nil {
			t.Fatalf("hint with no token left: %v", err)
		}
		if _, _, _, err := o.a.ResolveSession(context.Background(), again.Token); err != nil {
			t.Fatalf("a hint the client holds no token for ended the session: %v", err)
		}

		// Confirmation over HTTP: the state cookie the page set, then the
		// client changes before the user confirms.
		h := o.op.Handler()
		session := "__Host-auth_session=" + again.Token.Reveal()
		page := func() string {
			w := c1Do(h, http.MethodGet, "/oauth2/end-session?client_id="+url.QueryEscape(reg.ClientID)+"&post_logout_redirect_uri="+url.QueryEscape(after)+"&state=z", "", "", http.Header{"Accept": {"text/html"}, "Cookie": {session}})
			if w.Code != 200 || len(w.Result().Cookies()) == 0 {
				t.Fatalf("confirmation page = %d %s", w.Code, w.Body)
			}
			c := w.Result().Cookies()[0]
			return c.Name + "=" + c.Value
		}
		confirm := func(state, sess string) *httptest.ResponseRecorder {
			cookies := state
			if sess != "" {
				cookies += "; " + sess
			}
			return c1Do(h, http.MethodPost, "/oauth2/end-session/confirm", formType, "action=confirm", http.Header{"Accept": {"text/html"}, "Origin": {testBaseURL}, "Cookie": {cookies}})
		}
		// The URI was removed from the client: logged out, success page with
		// the notice, no redirect.
		state := page()
		spec.PostLogoutRedirectURIs = []string{"https://client.example/other"}
		must[oauthprovider.Client](t)(o.op.UpdateClient(context.Background(), reg.ClientID, spec))
		if w := confirm(state, session); w.Code != 200 || w.Header().Get("Location") != "" || !strings.Contains(w.Body.String(), "not registered") {
			t.Fatalf("confirm after the URI was removed = %d %s", w.Code, w.Body)
		}
		// Signed out already, a browser confirming sees the success page; a
		// confirmation state made for another session is refused.
		third := must[password.SignInResult](t)(o.pw.SignIn(anon(o.a), password.SignInRequest{Identifier: aliceRaw, Password: secret}))
		session = "__Host-auth_session=" + third.Token.Reveal()
		state = page()
		// The client may no longer end sessions: no redirect at all.
		spec.EnableEndSession = false
		must[oauthprovider.Client](t)(o.op.UpdateClient(context.Background(), reg.ClientID, spec))
		if w := confirm(state, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "Logged out") {
			t.Fatalf("confirm with no session = %d %s", w.Code, w.Body)
		}
		fourth := must[password.SignInResult](t)(o.pw.SignIn(anon(o.a), password.SignInRequest{Identifier: aliceRaw, Password: secret}))
		if w := confirm(state, "__Host-auth_session="+fourth.Token.Reveal()); w.Code != 400 {
			t.Fatalf("state of another session = %d %s", w.Code, w.Body)
		}
		if _, _, _, err := o.a.ResolveSession(context.Background(), fourth.Token); err != nil {
			t.Fatalf("a refused confirmation ended the session: %v", err)
		}
		// A script (no HTML) confirming with no session and nowhere to go is
		// refused.
		w := c1Do(h, http.MethodPost, "/oauth2/end-session/confirm", formType, "action=confirm", http.Header{"Origin": {testBaseURL}, "Cookie": {state}})
		if w.Code != 400 {
			t.Fatalf("script confirm with nowhere to go = %d %s", w.Code, w.Body)
		}
	})
	// Without a secret there is no signed state, so a browser cannot be
	// asked to confirm.
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnvWith(t, e, nil)
		if _, err := o.op.EndSession(request(o.a, o.token), oauthprovider.EndSessionRequest{Browser: true}); err == nil {
			t.Fatal("a confirmation without a secret was offered")
		}
	})
}

// flakySigner signs with an Ed25519 key until down is set, as a remote
// signer (KMS) that becomes unreachable; with keyless set (when not nil) it
// publishes no key at all, as one whose keys were all retired.
type flakySigner struct {
	key     ed25519.PrivateKey
	down    *atomic.Bool
	keyless *atomic.Bool
}

func (s flakySigner) PublicKeys() []crypto.PublicKey {
	if s.keyless != nil && s.keyless.Load() {
		return nil
	}
	return []crypto.PublicKey{s.key.Public()}
}

func (s flakySigner) Sign(_ context.Context, _ crypto.PublicKey, in []byte) ([]byte, error) {
	if s.down.Load() {
		return nil, errSignerDown
	}
	return ed25519.Sign(s.key, in), nil
}

var errSignerDown = errors.New("signer unreachable")

// syncBuffer is a log sink background deliveries may write to while the
// test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// A signer that cannot sign stops the provider at start (the issuer probe)
// and fails every issuance that signs: the ID token, a JWT access token,
// and a back-channel logout token, which is logged and not sent.
func TestOAuthProvider_SignerOutage(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		down := &atomic.Bool{}
		down.Store(true)
		jw := jwt.New(jwt.WithSigner(flakySigner{key: key, down: down}), jwt.Issuer(testBaseURL))
		op := oauthprovider.New(jw, oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login"))
		if _, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), jw, op)); !errors.Is(err, errSignerDown) {
			t.Fatalf("start with the signer down: %v", err)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		const api = "https://api.example.com/v1"
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		down := &atomic.Bool{}
		var sent atomic.Int32
		rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sent.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(rp.Close)
		logs := &syncBuffer{}
		keyless := &atomic.Bool{}
		jw := jwt.New(jwt.WithSigner(flakySigner{key: key, down: down, keyless: keyless}), jwt.Issuer(testBaseURL))
		o := newOPEnvJWT(t, e, jw, []auth.Option{auth.WithLogger(slog.New(slog.NewTextHandler(logs, nil)))},
			oauthprovider.Scopes("openid", "profile", "email", "offline_access", "api:read"), oauthprovider.ProtectedResource(api, "api:read"), oauthprovider.EnforcePerClientResources(false),
			oauthprovider.BackchannelHTTPClient(rp.Client()))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{BackchannelLogoutURI: rp.URL + "/bc"}})
		code := o.code(t, authzReq(reg.ClientID))
		in := authzReq(reg.ClientID)
		in.Scope, in.Resource = "api:read", api
		resCode := o.code(t, in)
		// A token issued while the signer worked, for the logout later.
		must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		// A signer with no published key: no at_hash can be computed and the
		// ID token is not signed.
		keyless.Store(true)
		if _, err := o.op.Token(anon(o.a), exchange(reg, code, opVerifier)); !errors.Is(err, jwt.ErrSignerKey) {
			t.Fatalf("ID token with no published key: %v", err)
		}
		keyless.Store(false)
		code = o.code(t, authzReq(reg.ClientID))
		down.Store(true)
		if _, err := o.op.Token(anon(o.a), exchange(reg, code, opVerifier)); !errors.Is(err, errSignerDown) {
			t.Fatalf("ID token with the signer down: %v", err)
		}
		r := exchange(reg, resCode, opVerifier)
		r.Resource = api
		if _, err := o.op.Token(anon(o.a), r); !errors.Is(err, errSignerDown) {
			t.Fatalf("JWT access token with the signer down: %v", err)
		}
		if err := o.a.SignOut(request(o.a, o.token)); err != nil {
			t.Fatal(err)
		}
		o.a.WaitDeliveries()
		if sent.Load() != 0 || !strings.Contains(logs.String(), "back-channel logout token") {
			t.Fatalf("logout with the signer down: sent %d, logs %s", sent.Load(), logs.String())
		}
		// With the signer back, a client answering 500 is logged.
		down.Store(false)
		again := must[password.SignInResult](t)(o.pw.SignIn(anon(o.a), password.SignInRequest{Identifier: aliceRaw, Password: secret}))
		o2 := o
		o2.token = again.Token
		must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o2.code(t, authzReq(reg.ClientID)), opVerifier)))
		if err := o.a.SignOut(request(o.a, again.Token)); err != nil {
			t.Fatal(err)
		}
		o.a.WaitDeliveries()
		if sent.Load() != 1 || !strings.Contains(logs.String(), "back-channel logout answered") {
			t.Fatalf("logout answered 500: sent %d, logs %s", sent.Load(), logs.String())
		}
		// A client that cannot be reached is logged too.
		rp.Close()
		third := must[password.SignInResult](t)(o.pw.SignIn(anon(o.a), password.SignInRequest{Identifier: aliceRaw, Password: secret}))
		o2.token = third.Token
		must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o2.code(t, authzReq(reg.ClientID)), opVerifier)))
		if err := o.a.SignOut(request(o.a, third.Token)); err != nil {
			t.Fatal(err)
		}
		o.a.WaitDeliveries()
		if !strings.Contains(logs.String(), "back-channel logout failed") {
			t.Fatalf("unreachable client: logs %s", logs.String())
		}
	})
}

// The resource registry's refusals and round trips: a custom identifier
// rule, claims and metadata that must be JSON, unknown resources, a
// refresh lifetime the resource shortens, and an unknown client to link.
func TestOAuthProvider_ResourceRegistryEdges(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "profile", "email", "offline_access", "api:read"),
			oauthprovider.IdentifierValidator(func(id string) bool { return strings.HasPrefix(id, "urn:api:") }))
		if _, err := o.op.CreateResource(ctx, oauthprovider.Resource{Identifier: "https://api.example.com/v1"}); !errors.Is(err, oauthprovider.ErrInvalidTarget) {
			t.Fatalf("identifier the validator refuses: %v", err)
		}
		const api = "urn:api:pay"
		if _, err := o.op.CreateResource(ctx, oauthprovider.Resource{Identifier: api, CustomClaims: map[string]any{"bad": make(chan int)}}); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("claims that do not encode: %v", err)
		}
		if _, err := o.op.CreateResource(ctx, oauthprovider.Resource{Identifier: api, Metadata: json.RawMessage(`{`)}); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("metadata that is not JSON: %v", err)
		}
		ttl := int64(600)
		must[oauthprovider.Resource](t)(o.op.CreateResource(ctx, oauthprovider.Resource{Identifier: api, RefreshTTL: &ttl, Metadata: json.RawMessage(`{"team":"pay"}`)}))
		got := must[oauthprovider.Resource](t)(o.op.Resource(ctx, api))
		if string(got.Metadata) != `{"team":"pay"}` || got.RefreshTTL == nil || *got.RefreshTTL != ttl {
			t.Fatalf("resource = %+v", got)
		}
		if _, err := o.op.UpdateResource(ctx, oauthprovider.Resource{Identifier: api, Metadata: json.RawMessage(`{`)}); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("update with bad metadata: %v", err)
		}
		if _, err := o.op.UpdateResource(ctx, oauthprovider.Resource{Identifier: "urn:api:none"}); !errors.Is(err, oauthprovider.ErrInvalidTarget) {
			t.Fatalf("update unknown: %v", err)
		}
		if err := o.op.DeleteResource(ctx, "urn:api:none"); !errors.Is(err, oauthprovider.ErrInvalidTarget) {
			t.Fatalf("delete unknown: %v", err)
		}
		if _, err := o.op.LinkClient(ctx, api, "oac_unknown"); !errors.Is(err, oauthprovider.ErrClientNotFound) {
			t.Fatalf("link unknown client: %v", err)
		}
		// The resource's shorter refresh lifetime is the refresh token's.
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		must[bool](t)(o.op.LinkClient(ctx, api, reg.ClientID))
		in := authzReq(reg.ClientID)
		in.Resource = api
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), func() oauthprovider.TokenRequest {
			r := exchange(reg, o.code(t, in), opVerifier)
			r.Resource = api
			return r
		}()))
		info := must[oauthprovider.Introspection](t)(o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: tok.RefreshToken, TokenTypeHint: "refresh_token", ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		if !info.Active || info.ExpiresAt != e.clock.Now().Unix()+ttl {
			t.Fatalf("refresh lifetime = %+v (now %d)", info, e.clock.Now().Unix())
		}
		// Deleting the resource leaves its tokens inactive.
		if err := o.op.DeleteResource(ctx, api); err != nil {
			t.Fatal(err)
		}
		if _, err := o.op.VerifyAccessToken(ctx, tok.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("token of a deleted resource: %v", err)
		}
	})
}

// c1DocURL is a client metadata document client_id.
const c1DocURL = "https://tool.example.com/oauth/client.json"

// c1CIMD serves c1DocURL's document; with validators it answers 304 to a
// conditional request, without repeating the validators.
func c1CIMD(validators map[string]string) oauthprovider.Option {
	doc := `{"client_id":"` + c1DocURL + `","client_name":"Tool","redirect_uris":["` + opRedirect + `"]}`
	return oauthprovider.ClientIDMetadataDocuments(oauthprovider.CIMDTransport(func(_ context.Context, _ string, cond http.Header) (oauthprovider.CIMDResponse, error) {
		if validators != nil && cond.Get("If-None-Match") != "" {
			return oauthprovider.CIMDResponse{Status: http.StatusNotModified, Header: http.Header{}}, nil
		}
		h := http.Header{"Content-Type": {"application/json"}}
		for k, v := range validators {
			h.Set(k, v)
		}
		return oauthprovider.CIMDResponse{Status: http.StatusOK, Body: []byte(doc), Header: h}, nil
	}))
}

// A 304 for a stored document keeps the stored validators when the answer
// repeats none, so the next revalidation is conditional again.
func TestOAuthProvider_CIMDNotModifiedKeepsValidators(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var conds []string
		doc := `{"client_id":"` + c1DocURL + `","client_name":"Tool","redirect_uris":["` + opRedirect + `"]}`
		o := newOPEnv(t, e, oauthprovider.ClientIDMetadataDocuments(oauthprovider.CIMDTransport(func(_ context.Context, _ string, cond http.Header) (oauthprovider.CIMDResponse, error) {
			conds = append(conds, cond.Get("If-None-Match"))
			if cond.Get("If-None-Match") != "" {
				// No headers at all: the revalidation interval applies.
				return oauthprovider.CIMDResponse{Status: http.StatusNotModified}, nil
			}
			return oauthprovider.CIMDResponse{Status: http.StatusOK, Body: []byte(doc), Header: http.Header{"Content-Type": {"application/json"}, "Etag": {`"v1"`}}}, nil
		})))
		for range 3 {
			must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), authzReq(c1DocURL)))
			e.clock.Advance(oauthprovider.DefaultCIMDRevalidate + time.Second)
		}
		if strings.Join(conds, ",") != `,"v1","v1"` {
			t.Fatalf("conditional requests = %q", conds)
		}
	})
}

// Smaller refusals and policies: an empty client id, consent to withdraw
// that was never given, the per-owner client cap, a secret generator that
// produces too little, an initial access token from a signed-in user, a
// failing token response hook, and tokens nobody issued.
func TestOAuthProvider_MiscEdges(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		short := false
		errFields := errors.New("fields hook down")
		failFields := false
		o := newOPEnv(t, e, oauthprovider.GenerateClientSecret(func() string {
			if short {
				return "x"
			}
			return strings.Repeat("s", 32)
		}), oauthprovider.ValidateInitialAccessToken(func(_ context.Context, tok string) (string, bool) { return "ref-" + tok, tok == "iat-ok" }),
			oauthprovider.TokenResponseFields(func(context.Context, oauthprovider.TokenFieldsInfo) (map[string]any, error) {
				if failFields {
					return nil, errFields
				}
				return nil, nil
			}))
		ctx := request(o.a, o.token)
		if _, err := o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: "ubor_x"}); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("no client id: %v", err)
		}
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		if err := o.op.RevokeConsent(ctx, reg.ClientID); !errors.Is(err, oauthprovider.ErrClientNotFound) {
			t.Fatalf("withdraw a consent never given: %v", err)
		}
		failFields = true
		if _, err := o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)); !errors.Is(err, errFields) {
			t.Fatalf("failing fields hook: %v", err)
		}
		failFields = false
		// Tokens nobody issued introspect inactive, with or without a hint.
		for _, hint := range []string{"", "refresh_token"} {
			in := must[oauthprovider.Introspection](t)(o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: "garbage", TokenTypeHint: hint, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
			if in.Active {
				t.Fatalf("unknown token (hint %q) = %+v", hint, in)
			}
		}
		// An initial access token from a signed-in user: the user owns the
		// client and the validator's reference is kept.
		meta := oauthprovider.ClientMetadata{Name: "x", RedirectURIs: []string{opRedirect}, InitialAccessToken: "iat-ok"}
		dcr := must[oauthprovider.Registration](t)(o.op.Register(ctx, meta))
		if dcr.ReferenceID != "ref-iat-ok" {
			t.Fatalf("registration with an initial access token = %+v", dcr)
		}
		// A generator that produces too little stops a new secret.
		short = true
		if _, err := o.op.CreateClient(context.Background(), oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "x", RedirectURIs: []string{opRedirect}}}); !errors.Is(err, oauthprovider.ErrShortGenerated) {
			t.Fatalf("short secret at creation: %v", err)
		}
		owned := must[oauthprovider.Registration](t)(func() (oauthprovider.Registration, error) {
			short = false
			defer func() { short = true }()
			return o.op.CreateOwnedClient(ctx, oauthprovider.ClientMetadata{Name: "mine", RedirectURIs: []string{opRedirect}})
		}())
		if _, err := o.op.RotateSecret(ctx, owned.ClientID); !errors.Is(err, oauthprovider.ErrShortGenerated) {
			t.Fatalf("short secret at rotation: %v", err)
		}
		short = false
		// The per-owner cap.
		list := must[oauthprovider.ClientList](t)(o.op.Clients(ctx))
		for i := len(list.Clients); i < 50; i++ {
			must[oauthprovider.Registration](t)(o.op.CreateOwnedClient(ctx, oauthprovider.ClientMetadata{Name: "c", RedirectURIs: []string{opRedirect}, AuthMethod: oauthprovider.AuthMethodNone}))
		}
		if _, err := o.op.CreateOwnedClient(ctx, oauthprovider.ClientMetadata{Name: "one too many", RedirectURIs: []string{opRedirect}}); !errors.Is(err, oauthprovider.ErrInvalidClientMetadata) {
			t.Fatalf("over the per-owner cap: %v", err)
		}
	})
}

// A back-channel delivery is never redirected: the default client stops at
// the 302 and logs the status.
func TestOAuthProvider_BackchannelNoRedirect(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var followed atomic.Bool
		rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/elsewhere" {
				followed.Store(true)
				return
			}
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}))
		t.Cleanup(rp.Close)
		logs := &syncBuffer{}
		o := newOPEnvWith(t, e, []auth.Option{auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize))), auth.WithLogger(slog.New(slog.NewTextHandler(logs, nil)))})
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{BackchannelLogoutURI: rp.URL + "/bc"}})
		must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		if err := o.a.SignOut(request(o.a, o.token)); err != nil {
			t.Fatal(err)
		}
		o.a.WaitDeliveries()
		if followed.Load() || !strings.Contains(logs.String(), "back-channel logout answered") || !strings.Contains(logs.String(), "status=302") {
			t.Fatalf("redirected delivery: followed %v, logs %s", followed.Load(), logs.String())
		}
	})
}

// With an ECDSA key the ID token's at_hash is the left half of the access
// token's SHA-256 (OpenID Connect Core section 3.1.3.6).
func TestOAuthProvider_AtHashES256(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
		o := newOPEnvJWT(t, e, jw, []auth.Option{auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize)))})
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		idt := must[jwt.Verified](t)(jwt.Verifier{Keys: jwt.KeysFromJWKS(jw.PublicKeys()), Issuer: testBaseURL, Audience: reg.ClientID, Now: e.clock.Now}.Verify(tok.IDToken))
		sum := sha256.Sum256([]byte(tok.AccessToken))
		if want := `"` + base64.RawURLEncoding.EncodeToString(sum[:16]) + `"`; string(idt.Extra["at_hash"]) != want {
			t.Fatalf("at_hash = %s, want %s", idt.Extra["at_hash"], want)
		}
	})
}

// A trusted client lives in configuration, so a deploy can remove it while
// its tokens remain: they stop verifying, and a logout passes over the
// client with nobody to notify.
func TestOAuthProvider_TrustedClientRemoved(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const id = "first-party-cli"
		tc := oauthprovider.TrustedClient{ClientID: id, ClientSpec: oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{Name: "CLI", RedirectURIs: []string{opRedirect}, AuthMethod: oauthprovider.AuthMethodNone}}}
		o := newOPEnv(t, e, oauthprovider.TrustedClients(tc))
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "authorization_code", Code: o.code(t, authzReq(id)), RedirectURI: opRedirect, CodeVerifier: opVerifier, ClientID: id, ClientAuthMethod: oauthprovider.AuthMethodNone}))
		// The next deploy, on the same database, without the client.
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
		op := oauthprovider.New(jw, oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login"))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), jw, op)
		if _, err := op.VerifyAccessToken(context.Background(), tok.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("token of a removed client: %v", err)
		}
		if err := a.SignOut(request(a, o.token)); err != nil {
			t.Fatalf("logout over a removed client's tokens: %v", err)
		}
		if _, _, _, err := a.ResolveSession(context.Background(), o.token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("session after logout: %v", err)
		}
	})
}

// c1Discovery is a client discoverer for "static:" ids; matches, when set,
// replaces the id test.
func c1Discovery(matches func(string) bool) oauthprovider.Option {
	if matches == nil {
		matches = func(id string) bool { return strings.HasPrefix(id, "static:") }
	}
	return oauthprovider.Extend(oauthprovider.Extension{ID: "c1", ClientDiscovery: []oauthprovider.ClientDiscoverer{{ID: "static", Refresh: time.Hour, Matches: matches,
		Resolve: func(_ context.Context, id string) (oauthprovider.ClientMetadata, error) {
			if id == "static:no-redirect" {
				return oauthprovider.ClientMetadata{Name: "Broken", AuthMethod: oauthprovider.AuthMethodNone}, nil
			}
			return oauthprovider.ClientMetadata{Name: "Static", RedirectURIs: []string{opRedirect}, AuthMethod: oauthprovider.AuthMethodNone}, nil
		}}}})
}

// Discovery refuses metadata the provider could not register, logging why;
// a registered client the discoverer also matches is kept as registered.
func TestOAuthProvider_DiscoveryRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		logs := &syncBuffer{}
		o := newOPEnvWith(t, e, []auth.Option{auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize))), auth.WithLogger(slog.New(slog.NewTextHandler(logs, nil)))},
			c1Discovery(func(string) bool { return true }))
		if _, err := o.op.Authorize(request(o.a, o.token), authzReq("static:no-redirect")); !errors.Is(err, oauthprovider.ErrBadRedirectTarget) {
			t.Fatalf("discovered metadata without a redirect URI: %v", err)
		}
		if !strings.Contains(logs.String(), "client discovery refused") {
			t.Fatalf("refusal not logged: %s", logs.String())
		}
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{Name: "Registered"}})
		o.code(t, authzReq(reg.ClientID))
		if c := must[oauthprovider.Client](t)(o.op.Client(context.Background(), reg.ClientID)); c.Name != "Registered" {
			t.Fatalf("registered client replaced by discovery: %+v", c)
		}
	})
}

// Smaller token-lifecycle edges: a disabled client's tokens stop, a public
// client may not present a secret, an extension assertion is refused for a
// client of another method, and a refused replay whose family revocation
// fails is logged.
func TestOAuthProvider_ClientAuthAndLifecycleEdges(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		ctx := context.Background()
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		must[struct{}](t)(struct{}{}, o.op.SetClientDisabled(ctx, reg.ClientID, true))
		if _, err := o.op.VerifyAccessToken(ctx, tok.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("token of a disabled client: %v", err)
		}
		pub := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{AuthMethod: oauthprovider.AuthMethodNone}})
		code := o.code(t, authzReq(pub.ClientID))
		withSecret := oauthprovider.TokenRequest{GrantType: "authorization_code", Code: code, RedirectURI: opRedirect, CodeVerifier: opVerifier, ClientID: pub.ClientID, ClientSecret: "guess"}
		if _, err := o.op.Token(anon(o.a), withSecret); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("public client with a secret: %v", err)
		}
		basic := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		asserted := exchange(basic, o.code(t, authzReq(basic.ClientID)), opVerifier)
		asserted.ClientSecret, asserted.ClientAssertion, asserted.ClientAssertionType = "", "x", "urn:example:attest"
		if _, err := o.op.Token(anon(o.a), asserted); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("extension assertion for a basic client: %v", err)
		}
	})
	// The family revocation after a refused replay runs outside the
	// request; its failure cannot reach the client, so it is logged.
	logs := &syncBuffer{}
	fe := newFaultEnv(t)
	o := newOPEnvWith(t, fe.env, []auth.Option{auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize))), auth.WithLogger(slog.New(slog.NewTextHandler(logs, nil)))})
	reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
	tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
	ref := oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: tok.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
	must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), ref))
	for k := 1; k <= maxFaultSteps; k++ {
		fe.f.arm(k)
		_, err := o.op.Token(anon(o.a), ref)
		hit := fe.f.disarm()
		if !hit {
			t.Fatal("the family revocation failure was never logged")
		}
		if strings.Contains(logs.String(), "revoke token family") {
			if !errors.Is(err, oauthprovider.ErrInvalidGrant) {
				t.Fatalf("replay with a failed revocation answered %v", err)
			}
			return
		}
	}
}

// A trusted client may use an https client_id under client metadata
// documents: it is configuration, so nothing is fetched for it.
func TestOAuthProvider_TrustedURLClientUnderCIMD(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const id = "https://first.example.com/oauth/client"
		fetched := false
		o := newOPEnv(t, e, oauthprovider.ClientIDMetadataDocuments(oauthprovider.CIMDFetch(func(context.Context, string) ([]byte, error) {
			fetched = true
			return nil, errors.New("not served")
		})), oauthprovider.TrustedClients(oauthprovider.TrustedClient{ClientID: id, ClientSpec: oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{Name: "First", RedirectURIs: []string{opRedirect}, AuthMethod: oauthprovider.AuthMethodNone}}}))
		o.code(t, authzReq(id))
		if fetched {
			t.Fatal("a trusted client's document was fetched")
		}
	})
}

// A client metadata document is refused when a post-logout URI is on
// another origin or does not parse, and when a refetch turns it into
// metadata the provider cannot serve; loopback and private-use post-logout
// URIs name no origin and pass.
func TestOAuthProvider_CIMDDocumentRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		docs := map[string]string{}
		o := newOPEnv(t, e, oauthprovider.ClientIDMetadataDocuments(oauthprovider.CIMDFetch(func(_ context.Context, u string) ([]byte, error) {
			d, ok := docs[u]
			if !ok {
				return nil, errors.New("not found")
			}
			return []byte(d), nil
		})))
		doc := func(id, extra string) string {
			return `{"client_id":"` + id + `","client_name":"Tool","redirect_uris":["` + opRedirect + `"]` + extra + `}`
		}
		const base = "https://client.example/"
		for name, extra := range map[string]string{
			"other origin": `,"post_logout_redirect_uris":["https://evil.example/bye"]`,
			"unparsable":   `,"post_logout_redirect_uris":["http://[::1"]`,
		} {
			id := base + strings.ReplaceAll(name, " ", "-") + ".json"
			docs[id] = doc(id, extra)
			if _, err := o.op.Authorize(request(o.a, o.token), authzReq(id)); !errors.Is(err, oauthprovider.ErrBadRedirectTarget) {
				t.Errorf("%s: %v", name, err)
			}
		}
		okID := base + "loopback.json"
		docs[okID] = doc(okID, `,"application_type":"native","post_logout_redirect_uris":["http://127.0.0.1:9/bye","com.example.app:/bye"]`)
		o.code(t, authzReq(okID))
		// A refetch that drops the redirect URIs leaves the client unknown.
		docs[okID] = `{"client_id":"` + okID + `","client_name":"Tool"}`
		e.clock.Advance(oauthprovider.DefaultCIMDRevalidate + time.Second)
		if _, err := o.op.Authorize(request(o.a, o.token), authzReq(okID)); !errors.Is(err, oauthprovider.ErrBadRedirectTarget) {
			t.Fatalf("refetched without redirect URIs: %v", err)
		}
	})
}

// Concurrent first uses of one document share one fetch; a request that
// gives up while waiting gets its own context's error.
func TestOAuthProvider_CIMDSharedFetch(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		entered, release := make(chan struct{}), make(chan struct{})
		var fetches atomic.Int32
		doc := `{"client_id":"` + c1DocURL + `","client_name":"Tool","redirect_uris":["` + opRedirect + `"]}`
		o := newOPEnv(t, e, oauthprovider.ClientIDMetadataDocuments(oauthprovider.CIMDFetch(func(context.Context, string) ([]byte, error) {
			if fetches.Add(1) == 1 {
				close(entered)
				<-release
			}
			return []byte(doc), nil
		})))
		first := make(chan error, 1)
		go func() {
			_, err := o.op.Authorize(request(o.a, o.token), authzReq(c1DocURL))
			first <- err
		}()
		<-entered
		ctx, cancel := context.WithTimeout(request(o.a, o.token), 200*time.Millisecond)
		defer cancel()
		if _, err := o.op.Authorize(ctx, authzReq(c1DocURL)); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("waiting request that gave up: %v", err)
		}
		joined := make(chan error, 1)
		go func() {
			_, err := o.op.Authorize(request(o.a, o.token), authzReq(c1DocURL))
			joined <- err
		}()
		// The assertions hold whether or not the second request reached the
		// flight before the release; the pause only makes the join likely.
		time.Sleep(50 * time.Millisecond)
		close(release)
		for _, ch := range []chan error{first, joined} {
			if err := <-ch; err != nil {
				t.Fatalf("shared fetch: %v", err)
			}
		}
		if n := fetches.Load(); n != 1 {
			t.Fatalf("fetches = %d, want 1", n)
		}
	})
}

// With stateless sessions the server cannot end a session by id, so a
// hinted logout from no browser ends nothing and still answers success.
func TestOAuthProvider_EndSessionStateless(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		secret := []byte(strings.Repeat("s", auth.MinSecretSize))
		o := newOPEnvWith(t, e, []auth.Option{auth.WithSecret(secret), auth.WithStatelessSessions(secret)})
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, EnableEndSession: true})
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		if _, err := o.op.EndSession(anon(o.a), oauthprovider.EndSessionRequest{IDTokenHint: tok.IDToken}); err != nil {
			t.Fatalf("hinted logout with stateless sessions: %v", err)
		}
	})
}
