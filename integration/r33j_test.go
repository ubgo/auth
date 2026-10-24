package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/ubgo/auth/plugin/deviceauth"
	"github.com/ubgo/auth/plugin/deviceauth/oauthdevice"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

// The device grant through the provider applies the resource registry
// twice: /device/code stores the scopes narrowed to the resource's
// allowlist (what the approval page shows), and the token exchange checks
// the resource and the client's link again.
func TestOAuthDevice_ResourceNarrowedAndRechecked(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		const api = "https://api.example.com/reports"
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
		dev := oauthdevice.New(testBaseURL + "/auth/device/code")
		dp := deviceauth.New(deviceauth.WithGrant(dev))
		op := oauthprovider.New(jw, oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login"),
			oauthprovider.Scopes("openid", "offline_access", "reports:read", "reports:write"),
			oauthprovider.WithGrant(dev.ExtensionGrant()), oauthprovider.DeviceAuthorizationEndpoint(dev.Endpoint()))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), jw, op, dp, dev)
		_, tok := identUser(t, a, alice)
		must[oauthprovider.Resource](t)(op.CreateResource(ctx, oauthprovider.Resource{Identifier: api, AllowedScopes: []string{"reports:read"}}))
		reg := must[oauthprovider.Registration](t)(op.CreateClient(ctx, oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "CLI",
			RedirectURIs: []string{"https://cli.example.com/cb"}, GrantTypes: []string{deviceauth.GrantType}, AuthMethod: oauthprovider.AuthMethodPost}}))
		ask := func() (deviceauth.CodeResult, error) {
			return dp.Code(anon(a), deviceauth.CodeRequest{ClientID: reg.ClientID, ClientSecret: reg.Secret, Scope: "reports:read reports:write", Resource: api})
		}
		if _, err := ask(); deviceauth.RFCErrorCode(err) != "invalid_target" {
			t.Fatalf("unlinked client at /device/code: %v", err)
		}
		must[bool](t)(op.LinkClient(ctx, api, reg.ClientID))
		code := must[deviceauth.CodeResult](t)(ask())
		v := must[deviceauth.VerifyResult](t)(dp.Verify(request(a, tok), code.UserCode))
		if v.Scope != "reports:read" || v.Resource != api {
			t.Fatalf("stored scope = %q resource %q", v.Scope, v.Resource)
		}
		if err := dp.Approve(request(a, tok), code.UserCode); err != nil {
			t.Fatal(err)
		}
		// The link is removed while the user approved: the exchange rechecks.
		if err := op.UnlinkClient(ctx, api, reg.ClientID); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(time.Minute)
		poll := oauthprovider.TokenRequest{GrantType: deviceauth.GrantType, DeviceCode: code.DeviceCode, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodPost}
		if _, err := op.Token(anon(a), poll); !errors.Is(err, oauthprovider.ErrInvalidTarget) {
			t.Fatalf("exchange after unlinking: %v", err)
		}
	})
}

// The pre-login endpoint answers a client's public fields only with a
// valid signed query for that client, and only when enabled; a signed
// query expires with the code lifetime.
func TestOAuthProvider_SignedQueryPrelogin(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.AllowPublicClientPrelogin())
		reg := o.client(t, oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "Shop"}})
		res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(anon(o.a), authzReq(reg.ClientID)))
		raw := must[*url.URL](t)(url.Parse(res.RedirectTo)).RawQuery
		pc := must[oauthprovider.PublicClient](t)(o.op.PublicClientPrelogin(anon(o.a), oauthprovider.PreloginRequest{OAuthQuery: raw}))
		if pc.Name != "Shop" {
			t.Fatalf("prelogin = %+v", pc)
		}
		other := o.client(t, oauthprovider.ClientSpec{})
		if _, err := o.op.PublicClientPrelogin(anon(o.a), oauthprovider.PreloginRequest{ClientID: other.ClientID, OAuthQuery: raw}); !errors.Is(err, oauthprovider.ErrInvalidSignature) {
			t.Fatalf("another client with this query: %v", err)
		}
		e.clock.Advance(oauthprovider.DefaultCodeTTL + time.Second)
		if err := o.op.VerifyOAuthQuery(raw); !errors.Is(err, oauthprovider.ErrInvalidSignature) {
			t.Fatalf("expired query: %v", err)
		}
	})
}
