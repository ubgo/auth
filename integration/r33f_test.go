package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

// The resource registry: a registered resource narrows scopes to its
// allowlist, shortens lifetimes, adds custom claims, can require DPoP, needs
// a client link, and stops new tokens when disabled; deleting it ends its
// tokens.
func TestOAuthProvider_ResourceRegistry(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const api = "https://api.example.com/pay"
		const extra = "https://api.example.com/extra"
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "profile", "email", "offline_access", "pay:read", "pay:write"), oauthprovider.RegistrationAllowedResources(extra))
		ctx := context.Background()
		ttl := int64(120)
		if _, err := o.op.CreateResource(ctx, oauthprovider.Resource{Identifier: api, Name: "Payments", AccessTTL: &ttl, AllowedScopes: []string{"pay:read"}, CustomClaims: map[string]any{"tier": "gold", "sub": "forged"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := o.op.CreateResource(ctx, oauthprovider.Resource{Identifier: api}); !errors.Is(err, oauthprovider.ErrResourceExists) {
			t.Fatalf("duplicate: %v", err)
		}
		if _, err := o.op.CreateResource(ctx, oauthprovider.Resource{Identifier: "relative/path"}); !errors.Is(err, oauthprovider.ErrInvalidTarget) {
			t.Fatalf("relative identifier: %v", err)
		}
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		in := authzReq(reg.ClientID)
		in.Scope, in.Resource = "pay:read pay:write", api
		if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.Is(err, oauthprovider.ErrInvalidTarget) {
			t.Fatalf("unlinked client: %v", err)
		}
		if again, err := o.op.LinkClient(ctx, api, reg.ClientID); err != nil || again {
			t.Fatalf("link = %v %v", again, err)
		}
		if again, err := o.op.LinkClient(ctx, api, reg.ClientID); err != nil || !again {
			t.Fatalf("second link = %v %v", again, err)
		}
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, in), opVerifier)))
		if tok.Scope != "pay:read" || tok.ExpiresIn != 120 {
			t.Fatalf("narrowed token = %+v", tok)
		}
		v := jwt.Verifier{Keys: jwt.KeysFromJWKS(o.jw.PublicKeys()), Issuer: testBaseURL, Audience: api, Now: e.clock.Now, Types: []string{oauthprovider.AccessTokenType}}
		claims := must[jwt.Verified](t)(v.Verify(tok.AccessToken))
		if string(claims.Extra["tier"]) != `"gold"` || claims.Subject != o.user.ID {
			t.Fatalf("custom claims = %+v", claims)
		}
		// Only allowlisted scopes: none left is invalid_scope.
		in.Scope = "pay:write"
		if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.Is(err, oauthprovider.ErrInvalidScope) {
			t.Fatalf("no allowed scope left: %v", err)
		}
		// A resource server linked to the resource introspects the token
		// and sees its claims; an unlinked client does not.
		rs := o.client(t, oauthprovider.ClientSpec{})
		other := o.client(t, oauthprovider.ClientSpec{})
		must[bool](t)(o.op.LinkClient(ctx, api, rs.ClientID))
		intro := func(c oauthprovider.Registration) oauthprovider.Introspection {
			return must[oauthprovider.Introspection](t)(o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: tok.AccessToken, ClientID: c.ClientID, ClientSecret: c.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		}
		got := intro(rs)
		b := must[[]byte](t)(got.MarshalJSON())
		if !got.Active || !strings.Contains(string(b), `"tier":"gold"`) || strings.Contains(string(b), "forged") {
			t.Fatalf("linked introspection = %s", b)
		}
		if intro(other).Active {
			t.Fatal("an unlinked client introspected another client's token")
		}
		// Disabled: no new token, the issued one still verifies.
		r := must[oauthprovider.Resource](t)(o.op.Resource(ctx, api))
		r.Disabled = true
		must[oauthprovider.Resource](t)(o.op.UpdateResource(ctx, r))
		in.Scope = "pay:read"
		if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.Is(err, oauthprovider.ErrInvalidTarget) {
			t.Fatalf("disabled resource: %v", err)
		}
		if _, err := o.op.VerifyAccessToken(ctx, tok.AccessToken); err != nil {
			t.Fatalf("disabled resource ended an issued token: %v", err)
		}
		// Deleted: the token ends.
		if err := o.op.DeleteResource(ctx, api); err != nil {
			t.Fatal(err)
		}
		if _, err := o.op.VerifyAccessToken(ctx, tok.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("deleted resource's token: %v", err)
		}
		// A resource that requires DPoP refuses a token request without a proof.
		must[oauthprovider.Resource](t)(o.op.CreateResource(ctx, oauthprovider.Resource{Identifier: api, DPoPRequired: true}))
		must[bool](t)(o.op.LinkClient(ctx, api, reg.ClientID))
		in.Scope = "pay:read"
		if _, err := o.op.Token(anon(o.a), exchange(reg, o.code(t, in), opVerifier)); !errors.Is(err, oauthprovider.ErrInvalidDPoPProof) {
			t.Fatalf("DPoP-required resource without a proof: %v", err)
		}
		if err := o.op.UnlinkClient(ctx, api, reg.ClientID); err != nil {
			t.Fatal(err)
		}
		if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.Is(err, oauthprovider.ErrInvalidTarget) {
			t.Fatalf("unlinked again: %v", err)
		}
		// Registration links allowed resources; others are refused.
		must[oauthprovider.Resource](t)(o.op.CreateResource(ctx, oauthprovider.Resource{Identifier: extra}))
		c := o.client(t, oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Resources: []string{extra}}})
		if in := (oauthprovider.AuthorizeRequest{ResponseType: "code", ClientID: c.ClientID, RedirectURI: opRedirect, Scope: "pay:read", Resource: extra, CodeChallenge: opChallenge(opVerifier), CodeChallengeMethod: "S256", State: "s"}); true {
			o.code(t, in)
		}
		if _, err := o.op.CreateClient(ctx, oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "x", RedirectURIs: []string{opRedirect}, Resources: []string{api}}}); !errors.Is(err, oauthprovider.ErrInvalidTarget) {
			t.Fatalf("registration asking for a resource not allowed: %v", err)
		}
	})
}
