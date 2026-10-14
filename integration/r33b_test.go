package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/auth/plugin/password"
)

const opResource = "https://api.example.com/v1"

// A token for an RFC 8707 resource is a JWT whose aud is the resource,
// verifiable offline; it is still revocable and introspectable, and a
// route of one resource refuses a token for another or for none.
func TestOAuthProvider_ResourceJWTAccessTokens(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "profile", "email", "offline_access", "api:read", "other:read"),
			oauthprovider.ProtectedResource(opResource, "api:read"), oauthprovider.ProtectedResource("https://other.example.com/x", "other:read"),
			oauthprovider.RegistrationDefaultResources(opResource, "https://other.example.com/x"))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientCredentialsScopes: []string{"api:read"}, ClientMetadata: oauthprovider.ClientMetadata{GrantTypes: []string{"authorization_code", "refresh_token", "client_credentials"}}})
		in := authzReq(reg.ClientID)
		in.Scope, in.Resource = "openid offline_access api:read", opResource
		code := o.code(t, in)
		// A different resource at the exchange is refused, and leaves the code.
		bad := exchange(reg, code, opVerifier)
		bad.Resource = "https://other.example.com/x"
		if _, err := o.op.Token(anon(o.a), bad); !errors.Is(err, oauthprovider.ErrInvalidTarget) {
			t.Fatalf("other resource at exchange: %v", err)
		}
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, code, opVerifier)))
		v := jwt.Verifier{Keys: jwt.KeysFromJWKS(o.jw.PublicKeys()), Issuer: testBaseURL, Audience: opResource, Now: e.clock.Now, Types: []string{oauthprovider.AccessTokenType}}
		claims, err := v.Verify(tok.AccessToken)
		if err != nil || claims.Subject != o.user.ID || string(claims.Extra["client_id"]) != `"`+reg.ClientID+`"` || string(claims.Extra["scope"]) != `"openid offline_access api:read"` {
			t.Fatalf("JWT access token = %+v %v", claims, err)
		}
		at := must[oauthprovider.AccessToken](t)(o.op.VerifyAccessToken(context.Background(), tok.AccessToken))
		if at.Resource != opResource {
			t.Fatalf("verified = %+v", at)
		}
		intro := must[oauthprovider.Introspection](t)(o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: tok.AccessToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		if !intro.Active || intro.Audience != opResource {
			t.Fatalf("introspection = %+v", intro)
		}
		// at_hash: the left half of SHA-512 (EdDSA) of the access token.
		idt := must[jwt.Verified](t)(jwt.Verifier{Keys: jwt.KeysFromJWKS(o.jw.PublicKeys()), Issuer: testBaseURL, Audience: reg.ClientID, Now: e.clock.Now}.Verify(tok.IDToken))
		sum := sha512.Sum512([]byte(tok.AccessToken))
		if string(idt.Extra["at_hash"]) != `"`+base64.RawURLEncoding.EncodeToString(sum[:32])+`"` {
			t.Fatalf("at_hash = %s", idt.Extra["at_hash"])
		}
		// The refreshed token stays bound to the resource.
		ref := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: tok.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		if _, err := v.Verify(ref.AccessToken); err != nil {
			t.Fatalf("refreshed token lost its audience: %v", err)
		}
		// A revoked JWT access token stops at verification, signature or not.
		if err := o.op.Revoke(anon(o.a), oauthprovider.RevokeRequest{Token: ref.AccessToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}); err != nil {
			t.Fatal(err)
		}
		if _, err := o.op.VerifyAccessToken(context.Background(), ref.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("revoked JWT access token: %v", err)
		}
		// Unknown resource, and a scope the resource did not declare.
		in.Resource = "https://unknown.example.com"
		if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.Is(err, oauthprovider.ErrInvalidTarget) {
			t.Fatalf("unknown resource: %v", err)
		}
		// client_credentials for a resource: the subject is the client.
		cc := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "client_credentials", Scope: "api:read", Resource: opResource, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		if c, err := v.Verify(cc.AccessToken); err != nil || c.Subject != reg.ClientID {
			t.Fatalf("client credentials JWT = %+v %v", c, err)
		}
	})
}

// RefreshReuseInterval lets a just-rotated refresh token work again within
// the window; after it, reuse revokes the family as without the option.
func TestOAuthProvider_RefreshReuseInterval(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.RefreshReuseInterval(30*time.Second))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		ref := oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: tok.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
		first := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), ref))
		second := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), ref))
		if _, err := o.op.VerifyAccessToken(context.Background(), first.AccessToken); err != nil {
			t.Fatalf("reuse inside the window revoked the family: %v", err)
		}
		if second.RefreshToken == first.RefreshToken {
			t.Fatal("the reuse handed out the same refresh token")
		}
		e.clock.Advance(31 * time.Second)
		if _, err := o.op.Token(anon(o.a), ref); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("reuse after the window: %v", err)
		}
		if _, err := o.op.VerifyAccessToken(context.Background(), second.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("family survived a late reuse: %v", err)
		}
	})
}

// max_age re-authenticates a stale session; request objects are refused;
// login_hint reaches the login page.
func TestOAuthProvider_MaxAgeAndRequestObjects(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		in := authzReq(reg.ClientID)
		in.MaxAge, in.LoginHint = "60", "alice@example.com"
		if res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), in)); !strings.HasPrefix(res.RedirectTo, opRedirect) {
			t.Fatalf("fresh session = %s", res.RedirectTo)
		}
		e.clock.Advance(2 * time.Minute)
		res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), in))
		u := must[*url.URL](t)(url.Parse(res.RedirectTo))
		if u.Path != "/login" || u.Query().Get("login_hint") != "alice@example.com" {
			t.Fatalf("stale session = %s", res.RedirectTo)
		}
		in.MaxAge = "-1"
		if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("negative max_age: %v", err)
		}
		in.MaxAge, in.Request = "", "eyJ..."
		if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.Is(err, oauthprovider.ErrRequestNotSupported) {
			t.Fatalf("request object: %v", err)
		}
		in.Request, in.RequestURI = "", "urn:x"
		if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.Is(err, oauthprovider.ErrRequestURINotSupported) {
			t.Fatalf("request_uri: %v", err)
		}
	})
}

// assertion signs an RFC 7523 client assertion with an Ed25519 key.
func assertion(t *testing.T, key ed25519.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding
	h := must[[]byte](t)(json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": kid}))
	c := must[[]byte](t)(json.Marshal(claims))
	in := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	return in + "." + enc.EncodeToString(ed25519.Sign(key, []byte(in)))
}

// private_key_jwt: an assertion signed by a key in the client's JWKS, for
// this endpoint, short-lived and used once.
func TestOAuthProvider_PrivateKeyJWT(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "api:read"))
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		jwks := must[[]byte](t)(json.Marshal(map[string]any{"keys": []map[string]string{{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub), "kid": "k1", "alg": "EdDSA", "use": "sig"}}}))
		reg := o.client(t, oauthprovider.ClientSpec{ClientCredentialsScopes: []string{"api:read"}, ClientMetadata: oauthprovider.ClientMetadata{AuthMethod: oauthprovider.AuthMethodPrivateKeyJWT, JWKS: jwks, GrantTypes: []string{"client_credentials"}, Scope: "api:read"}})
		if reg.Secret != "" {
			t.Fatal("a private_key_jwt client got a secret")
		}
		now := e.clock.Now()
		claims := func(jti string, aud any, exp time.Duration) map[string]any {
			return map[string]any{"iss": reg.ClientID, "sub": reg.ClientID, "aud": aud, "jti": jti, "iat": now.Unix(), "exp": now.Add(exp).Unix()}
		}
		cc := func(a string) error {
			_, err := o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "client_credentials", ClientID: reg.ClientID, ClientAuthMethod: oauthprovider.AuthMethodPrivateKeyJWT, ClientAssertion: a})
			return err
		}
		if err := cc(assertion(t, key, "k1", claims("j1", testBaseURL+"/oauth2/token", time.Minute))); err != nil {
			t.Fatalf("valid assertion: %v", err)
		}
		_, other, _ := ed25519.GenerateKey(rand.Reader)
		for name, a := range map[string]string{
			"replayed jti":     assertion(t, key, "k1", claims("j1", testBaseURL+"/oauth2/token", time.Minute)),
			"other endpoint":   assertion(t, key, "k1", claims("j2", testBaseURL+"/oauth2/introspect", time.Minute)),
			"too long-lived":   assertion(t, key, "k1", claims("j3", testBaseURL, time.Hour)),
			"expired":          assertion(t, key, "k1", claims("j4", testBaseURL, -time.Hour)),
			"unregistered key": assertion(t, other, "k1", claims("j5", testBaseURL, time.Minute)),
			"no jti":           assertion(t, key, "k1", claims("", testBaseURL, time.Minute)),
		} {
			if err := cc(a); !errors.Is(err, oauthprovider.ErrInvalidClient) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		// The issuer as audience is accepted too.
		if err := cc(assertion(t, key, "k1", claims("j6", testBaseURL, time.Minute))); err != nil {
			t.Fatalf("issuer audience: %v", err)
		}
		// A secret is not a private_key_jwt client's method.
		if _, err := o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "client_credentials", ClientID: reg.ClientID, ClientSecret: "x", ClientAuthMethod: oauthprovider.AuthMethodPost}); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("secret for a key client: %v", err)
		}
		// Registration refuses a private key or no key set.
		priv := must[[]byte](t)(json.Marshal(map[string]any{"keys": []map[string]string{{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub), "d": base64.RawURLEncoding.EncodeToString(key.Seed()), "kid": "k", "alg": "EdDSA", "use": "sig"}}}))
		for _, set := range [][]byte{nil, priv, []byte(`{"keys":[]}`), []byte(`[1]`)} {
			if _, err := o.op.CreateClient(context.Background(), oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "k", AuthMethod: oauthprovider.AuthMethodPrivateKeyJWT, JWKS: set, GrantTypes: []string{"client_credentials"}}}); !errors.Is(err, oauthprovider.ErrInvalidClientMetadata) {
				t.Fatalf("key set %s: %v", set, err)
			}
		}
	})
}

// RP-initiated logout, as better-auth: a valid hint for the browser's user
// ends the session at once; no hint, a bad hint or another user's needs the
// browser to confirm, and a caller that is not a browser is refused.
func TestOAuthProvider_EndSession(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		const after = "https://client.example/bye"
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, EnableEndSession: true, ClientMetadata: oauthprovider.ClientMetadata{PostLogoutRedirectURIs: []string{after}}})
		plain := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		plainTok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(plain, o.code(t, authzReq(plain.ClientID)), opVerifier)))
		for name, c := range map[string]struct {
			in   oauthprovider.EndSessionRequest
			want error
		}{
			"no hint, not a browser":      {oauthprovider.EndSessionRequest{PostLogoutRedirectURI: after}, oauthprovider.ErrInvalidRequest},
			"forged hint":                 {oauthprovider.EndSessionRequest{IDTokenHint: tok.IDToken + "x"}, oauthprovider.ErrInvalidToken},
			"client not enabled":          {oauthprovider.EndSessionRequest{IDTokenHint: plainTok.IDToken}, oauthprovider.ErrInvalidClient},
			"no hint, client not enabled": {oauthprovider.EndSessionRequest{ClientID: plain.ClientID, Browser: true}, oauthprovider.ErrInvalidClient},
		} {
			if _, err := o.op.EndSession(request(o.a, o.token), c.in); !errors.Is(err, c.want) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		// A browser with a bad hint is asked to confirm, not signed out.
		if res := must[oauthprovider.EndSessionResult](t)(o.op.EndSession(request(o.a, o.token), oauthprovider.EndSessionRequest{IDTokenHint: tok.IDToken + "x", Browser: true})); res.Page != oauthprovider.PageConfirm {
			t.Fatalf("bad hint in a browser = %+v", res)
		}
		// Another user's hint while signed in: confirm, never sign out.
		bob := must[password.SignInResult](t)(o.pw.SignUp(anon(o.a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret}))
		if _, err := o.op.EndSession(request(o.a, bob.Token), oauthprovider.EndSessionRequest{IDTokenHint: tok.IDToken}); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("another user's hint: %v", err)
		}
		if _, _, _, err := o.a.ResolveSession(context.Background(), bob.Token); err != nil {
			t.Fatalf("another user's hint signed bob out: %v", err)
		}
		if _, _, _, err := o.a.ResolveSession(context.Background(), o.token); err != nil {
			t.Fatalf("a refused logout signed the user out: %v", err)
		}
		// A valid hint with an unregistered URI: logged out, success page with
		// the notice, no redirect.
		res := must[oauthprovider.EndSessionResult](t)(o.op.EndSession(request(o.a, o.token), oauthprovider.EndSessionRequest{IDTokenHint: tok.IDToken, PostLogoutRedirectURI: "https://evil.example/", Browser: true}))
		if res.RedirectTo != "" || res.Page != oauthprovider.PageSuccess || res.Notice == "" {
			t.Fatalf("unregistered URI = %+v", res)
		}
		if _, _, _, err := o.a.ResolveSession(context.Background(), o.token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("session after logout: %v", err)
		}
		// A valid hint and a registered URI redirect with the state.
		again := must[password.SignInResult](t)(o.pw.SignIn(anon(o.a), password.SignInRequest{Identifier: aliceRaw, Password: secret}))
		// The old hint's sid names the ended session, not this one: a browser
		// is asked to confirm, a non-browser refused.
		if _, err := o.op.EndSession(request(o.a, again.Token), oauthprovider.EndSessionRequest{IDTokenHint: tok.IDToken}); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("hint for another session: %v", err)
		}
		o2 := o
		o2.token = again.Token
		tok2 := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o2.code(t, authzReq(reg.ClientID)), opVerifier)))
		res = must[oauthprovider.EndSessionResult](t)(o.op.EndSession(request(o.a, again.Token), oauthprovider.EndSessionRequest{IDTokenHint: tok2.IDToken, PostLogoutRedirectURI: after, State: "s1"}))
		if res.RedirectTo != after+"?state=s1" {
			t.Fatalf("redirect = %+v", res)
		}
		if _, _, _, err := o.a.ResolveSession(context.Background(), again.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("session after hinted logout: %v", err)
		}
	})
}

// A valid hint with no browser session ends the session its sid names, as
// better-auth's findHintedSession; the ID token carries that sid.
func TestOAuthProvider_EndSessionHintedSession(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, EnableEndSession: true})
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		sess, _, _, err := o.a.ResolveSession(context.Background(), o.token)
		if err != nil {
			t.Fatal(err)
		}
		idt := must[jwt.Verified](t)(jwt.Verifier{Keys: jwt.KeysFromJWKS(o.jw.PublicKeys()), Issuer: testBaseURL, Audience: reg.ClientID, Now: e.clock.Now}.Verify(tok.IDToken))
		if idt.SessionID != sess.ID {
			t.Fatalf("ID token sid = %q, session %q", idt.SessionID, sess.ID)
		}
		if _, err := o.op.EndSession(anon(o.a), oauthprovider.EndSessionRequest{IDTokenHint: tok.IDToken}); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := o.a.ResolveSession(context.Background(), o.token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("hinted session survived: %v", err)
		}
	})
}

// The browser confirmation over HTTP: no hint shows the page and sets the
// signed state; the form's post signs the user out and redirects; a forged
// or missing state is refused.
func TestOAuthProvider_EndSessionConfirmHTTP(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		const after = "https://client.example/bye"
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, EnableEndSession: true, ClientMetadata: oauthprovider.ClientMetadata{PostLogoutRedirectURIs: []string{after}}})
		srv := httptest.NewServer(o.op.Handler())
		t.Cleanup(srv.Close)
		noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		session := &http.Cookie{Name: "__Host-auth_session", Value: o.token.Reveal()}
		req := must[*http.Request](t)(http.NewRequest(http.MethodGet, srv.URL+"/oauth2/end-session?client_id="+url.QueryEscape(reg.ClientID)+"&post_logout_redirect_uri="+url.QueryEscape(after)+"&state=z", nil))
		req.Header.Set("Accept", "text/html")
		req.AddCookie(session)
		res := must[*http.Response](t)(noRedirect.Do(req))
		body := must[[]byte](t)(io.ReadAll(res.Body))
		res.Body.Close()
		if res.StatusCode != 200 || !strings.Contains(string(body), "Confirm logout") || !strings.Contains(res.Header.Get("Content-Security-Policy"), "default-src 'none'") || len(res.Cookies()) == 0 {
			t.Fatalf("confirmation page = %d %s %v", res.StatusCode, body, res.Header)
		}
		state := res.Cookies()[0]
		confirm := func(c *http.Cookie, action string) *http.Response {
			r := must[*http.Request](t)(http.NewRequest(http.MethodPost, srv.URL+"/oauth2/end-session/confirm", strings.NewReader(url.Values{"action": {action}}.Encode())))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", testBaseURL)
			r.Header.Set("Accept", "text/html")
			r.AddCookie(session)
			if c != nil {
				r.AddCookie(c)
			}
			res := must[*http.Response](t)(noRedirect.Do(r))
			res.Body.Close()
			return res
		}
		// Flip a character inside the MAC: changing the last characters can
		// decode to the same bytes, since base64 ignores their unused bits.
		mid := len(state.Value) - 10
		flip := byte('A')
		if state.Value[mid] == 'A' {
			flip = 'B'
		}
		forged := &http.Cookie{Name: state.Name, Value: state.Value[:mid] + string(flip) + state.Value[mid+1:]}
		for name, r := range map[string]*http.Response{"no state": confirm(nil, "confirm"), "forged state": confirm(forged, "confirm"), "wrong action": confirm(state, "cancel")} {
			if r.StatusCode != 400 {
				t.Fatalf("%s = %d", name, r.StatusCode)
			}
		}
		if _, _, _, err := o.a.ResolveSession(context.Background(), o.token); err != nil {
			t.Fatalf("a refused confirmation signed the user out: %v", err)
		}
		// A confirmation older than five minutes is refused.
		e.clock.Advance(6 * time.Minute)
		if r := confirm(state, "confirm"); r.StatusCode != 400 {
			t.Fatalf("expired confirmation = %d", r.StatusCode)
		}
		res = must[*http.Response](t)(noRedirect.Do(req.Clone(context.Background())))
		res.Body.Close()
		state = res.Cookies()[0]
		r := confirm(state, "confirm")
		if r.StatusCode != 302 || r.Header.Get("Location") != after+"?state=z" {
			t.Fatalf("confirmed = %d %s", r.StatusCode, r.Header.Get("Location"))
		}
		if _, _, _, err := o.a.ResolveSession(context.Background(), o.token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("session after confirmation: %v", err)
		}
	})
}

// Consent read and update by id, owner only; admin update of restricted
// fields; per-endpoint rate limits.
func TestOAuthProvider_ConsentsAdminAndLimits(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.RateLimit(oauthprovider.EndpointToken, 2, time.Minute))
		reg := o.client(t, oauthprovider.ClientSpec{})
		o.code(t, authzReq(reg.ClientID))
		list := must[oauthprovider.ConsentList](t)(o.op.Consents(request(o.a, o.token)))
		id := list.Consents[0].ID
		got := must[oauthprovider.Consent](t)(o.op.ConsentByID(request(o.a, o.token), id))
		if got.ClientID != reg.ClientID {
			t.Fatalf("consent = %+v", got)
		}
		up := must[oauthprovider.Consent](t)(o.op.UpdateConsent(request(o.a, o.token), oauthprovider.UpdateConsentRequest{ID: id, Scope: "openid"}))
		if strings.Join(up.Scopes, " ") != "openid" {
			t.Fatalf("updated = %+v", up)
		}
		if _, err := o.op.UpdateConsent(request(o.a, o.token), oauthprovider.UpdateConsentRequest{ID: id, Scope: "admin"}); !errors.Is(err, oauthprovider.ErrInvalidScope) {
			t.Fatalf("unknown scope: %v", err)
		}
		if _, err := o.op.ConsentByID(request(o.a, o.token), "oacn_other"); !errors.Is(err, oauthprovider.ErrClientNotFound) {
			t.Fatalf("unknown consent: %v", err)
		}
		bob := must[password.SignInResult](t)(o.pw.SignUp(anon(o.a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret}))
		if _, err := o.op.ConsentByID(request(o.a, bob.Token), id); !errors.Is(err, oauthprovider.ErrClientNotFound) {
			t.Fatalf("another user's consent: %v", err)
		}
		cl := must[oauthprovider.Client](t)(o.op.UpdateClient(context.Background(), reg.ClientID, oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "Renamed", RedirectURIs: []string{opRedirect}}, SkipConsent: true, IntrospectAny: true}))
		if cl.Name != "Renamed" || !cl.SkipConsent || !cl.IntrospectAny {
			t.Fatalf("admin update = %+v", cl)
		}
		bad := oauthprovider.TokenRequest{GrantType: "authorization_code", Code: "uboc_x", RedirectURI: opRedirect, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
		for range 2 {
			if _, err := o.op.Token(anon(o.a), bad); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
				t.Fatalf("within the limit: %v", err)
			}
		}
		if _, err := o.op.Token(anon(o.a), bad); !errors.Is(err, auth.ErrRateLimited) {
			t.Fatalf("over the limit: %v", err)
		}
	})
}

// CIMD: an https client_id is a metadata document, fetched on first use,
// trusted for the revalidation interval, refused when it claims what only
// the server decides.
func TestOAuthProvider_CIMD(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const docURL = "https://tool.example.com/oauth/client.json"
		docs := map[string]string{}
		fetches := 0
		fetch := func(_ context.Context, u string) ([]byte, error) {
			fetches++
			d, ok := docs[u]
			if !ok {
				return nil, errors.New("not found")
			}
			return []byte(d), nil
		}
		o := newOPEnv(t, e, oauthprovider.ClientIDMetadataDocuments(oauthprovider.CIMDFetch(fetch), oauthprovider.CIMDProfileMCP(), oauthprovider.CIMDAllow(func(id string) bool { return !strings.Contains(id, "blocked") })))
		docs[docURL] = `{"client_id":"` + docURL + `","client_name":"Tool","redirect_uris":["` + opRedirect + `"],"unknown":"ignored"}`
		in := authzReq(docURL)
		code := o.code(t, in)
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "authorization_code", Code: code, RedirectURI: opRedirect, CodeVerifier: opVerifier, ClientID: docURL, ClientAuthMethod: oauthprovider.AuthMethodNone}))
		if tok.AccessToken == "" {
			t.Fatal("no token for a document client")
		}
		if fetches != 1 {
			t.Fatalf("fetches = %d, want 1 (cached between authorize and token)", fetches)
		}
		cl := must[oauthprovider.Client](t)(o.op.Client(context.Background(), docURL))
		if cl.Name != "Tool" || !cl.Public || !cl.RequirePKCE {
			t.Fatalf("document client = %+v", cl)
		}
		// After the interval it is fetched again; a failed refetch fails
		// closed.
		e.clock.Advance(oauthprovider.DefaultCIMDRevalidate + time.Second)
		delete(docs, docURL)
		if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.Is(err, oauthprovider.ErrBadRedirectTarget) {
			t.Fatalf("failed revalidation: %v", err)
		}
		for name, doc := range map[string]string{
			"server field":       `{"client_id":"%s","client_name":"T","redirect_uris":["` + opRedirect + `"],"skip_consent":true}`,
			"secret method":      `{"client_id":"%s","client_name":"T","redirect_uris":["` + opRedirect + `"],"token_endpoint_auth_method":"client_secret_basic"}`,
			"client_id differs":  `{"client_id":"https://other.example.com/c.json","client_name":"T","redirect_uris":["` + opRedirect + `"]}`,
			"mcp profile":        `{"client_id":"%s","redirect_uris":["` + opRedirect + `"]}`,
			"foreign client_uri": `{"client_id":"%s","client_name":"T","redirect_uris":["` + opRedirect + `"],"client_uri":"https://evil.example"}`,
			"not json":           `nope`,
		} {
			u := "https://tool.example.com/" + strings.ReplaceAll(name, " ", "-") + ".json"
			if strings.Contains(doc, "%s") {
				doc = strings.ReplaceAll(doc, "%s", u)
			}
			docs[u] = doc
			if _, err := o.op.Authorize(request(o.a, o.token), authzReq(u)); !errors.Is(err, oauthprovider.ErrBadRedirectTarget) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		before := fetches
		for _, u := range []string{"https://tool.example.com/", "https://tool.example.com/a/../b.json", "https://blocked.example.com/c.json"} {
			if _, err := o.op.Authorize(request(o.a, o.token), authzReq(u)); !errors.Is(err, oauthprovider.ErrBadRedirectTarget) {
				t.Fatalf("%s: %v", u, err)
			}
		}
		if fetches != before {
			t.Fatal("a refused client_id URL was fetched")
		}
	})
}
