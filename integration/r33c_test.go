package integration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/ubgo/auth/plugin/jwt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

const extGrantType = "urn:example:params:oauth:grant-type:fake"

// An extension grant runs after client authentication and the client's
// grant check, issues through the shared path, and keeps its own error
// codes on the wire.
func TestOAuthProvider_ExtensionGrant(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var o opEnv
		grant := oauthprovider.ExtensionGrant{Type: extGrantType, ErrorNamespace: "fakegrant", Handle: func(_ context.Context, c oauthprovider.Client, in oauthprovider.TokenRequest) (oauthprovider.GrantDecision, error) {
			switch in.DeviceCode {
			case "pending":
				return oauthprovider.GrantDecision{}, errPending
			case "wide":
				return oauthprovider.GrantDecision{UserID: o.user.ID, Scopes: []string{"admin"}}, nil
			}
			return oauthprovider.GrantDecision{UserID: o.user.ID, Scopes: []string{"openid", "offline_access"}}, nil
		}}
		o = newOPEnv(t, e, oauthprovider.WithGrant(grant), oauthprovider.DeviceAuthorizationEndpoint(testBaseURL+"/device/code"))
		reg := o.client(t, oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{GrantTypes: []string{extGrantType, "refresh_token"}}})
		req := oauthprovider.TokenRequest{GrantType: extGrantType, DeviceCode: "ok", ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), req))
		if tok.RefreshToken == "" || tok.IDToken == "" {
			t.Fatalf("extension tokens = %+v", tok)
		}
		req.DeviceCode = "wide"
		if _, err := o.op.Token(anon(o.a), req); !errors.Is(err, oauthprovider.ErrInvalidScope) {
			t.Fatalf("scope beyond the provider: %v", err)
		}
		other := o.client(t, oauthprovider.ClientSpec{})
		if _, err := o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: extGrantType, ClientID: other.ClientID, ClientSecret: other.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}); !errors.Is(err, oauthprovider.ErrUnauthorizedClient) {
			t.Fatalf("client without the grant: %v", err)
		}
		if _, err := o.op.AuthenticateClient(context.Background(), oauthprovider.ClientCredentials{ID: reg.ClientID, Secret: "nope", Method: oauthprovider.AuthMethodBasic}, testBaseURL+"/device/code"); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("AuthenticateClient with a wrong secret: %v", err)
		}
		if c, err := o.op.AuthenticateClient(context.Background(), oauthprovider.ClientCredentials{ID: reg.ClientID, Secret: reg.Secret, Method: oauthprovider.AuthMethodBasic}, testBaseURL+"/device/code"); err != nil || c.ClientID != reg.ClientID {
			t.Fatalf("AuthenticateClient = %+v %v", c, err)
		}
		srv := httptest.NewServer(o.op.Handler())
		t.Cleanup(srv.Close)
		form := url.Values{"grant_type": {extGrantType}, "device_code": {"pending"}}
		hreq := must[*http.Request](t)(http.NewRequest(http.MethodPost, srv.URL+"/oauth2/token", strings.NewReader(form.Encode())))
		hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		hreq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(reg.ClientID+":"+reg.Secret)))
		res := must[*http.Response](t)(http.DefaultClient.Do(hreq))
		var body map[string]any
		_ = json.NewDecoder(res.Body).Decode(&body)
		res.Body.Close()
		if res.StatusCode != 400 || body["error"] != "authorization_pending" {
			t.Fatalf("pending = %d %v", res.StatusCode, body)
		}
		md := o.op.Metadata()
		if md.DeviceAuthorizationEndpoint != testBaseURL+"/device/code" || md.GrantTypesSupported[len(md.GrantTypesSupported)-1] != extGrantType {
			t.Fatalf("metadata = %+v", md)
		}
	})
}

// errPending is the extension grant's "not approved yet".
var errPending = auth.NewError("fakegrant.authorization_pending", http.StatusBadRequest, "The user has not approved yet.")

// The provider options: custom redirect validation, prompt=create,
// lifetimes per grant and scope, access-token claims, advertised metadata,
// id generators, and JSON redirects for fetch callers.
func TestOAuthProvider_Options(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const preview = "https://pr-7.preview.example.com/cb"
		n := 0
		o := newOPEnv(t, e,
			oauthprovider.Scopes("openid", "profile", "email", "offline_access", "pay:write"),
			oauthprovider.ProtectedResource(opResource, "pay:write"), oauthprovider.RegistrationDefaultResources(opResource),
			oauthprovider.SignupPage("/signup"),
			oauthprovider.M2MAccessTokenTTL(10*time.Minute),
			oauthprovider.ScopeExpirations(map[string]time.Duration{"pay:write": 5 * time.Minute}),
			oauthprovider.AdvertisedScopes("openid"), oauthprovider.AdvertisedClaims("sub"),
			oauthprovider.AccessTokenClaims(func(_ context.Context, in oauthprovider.AccessTokenClaimsInfo) map[string]any {
				return map[string]any{"tier": "gold", "sub": "forged"}
			}),
			oauthprovider.GenerateClientID(func() string { n++; return strings.Repeat("c", 21) + string(rune('a'+n)) }),
			oauthprovider.ValidateRedirectURI(func(uri string, registered []string, def bool) bool {
				if uri == opRedirect {
					return false // the validator's answer replaces the exact match
				}
				return def || strings.HasSuffix(strings.SplitN(uri, "/cb", 2)[0], ".preview.example.com")
			}),
		)
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientCredentialsScopes: []string{"pay:write"}, ClientMetadata: oauthprovider.ClientMetadata{GrantTypes: []string{"authorization_code", "refresh_token", "client_credentials"}}})
		if len(reg.ClientID) != 22 {
			t.Fatalf("generated client id = %q", reg.ClientID)
		}
		in := authzReq(reg.ClientID)
		if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.Is(err, oauthprovider.ErrBadRedirectTarget) {
			t.Fatalf("validator refusing the exact URI: %v", err)
		}
		in.RedirectURI = preview
		res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), in))
		if !strings.HasPrefix(res.RedirectTo, preview+"?code=") {
			t.Fatalf("validator-accepted URI = %s", res.RedirectTo)
		}
		in.Prompt = "create"
		if res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), in)); !strings.HasPrefix(res.RedirectTo, "/signup?") {
			t.Fatalf("prompt=create = %s", res.RedirectTo)
		}
		cc := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "client_credentials", Scope: "pay:write", Resource: opResource, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		if cc.ExpiresIn != 300 {
			t.Fatalf("scope expiration = %d", cc.ExpiresIn)
		}
		v := jwt.Verifier{Keys: jwt.KeysFromJWKS(o.jw.PublicKeys()), Issuer: testBaseURL, Audience: opResource, Now: e.clock.Now, Types: []string{oauthprovider.AccessTokenType}}
		claims := must[jwt.Verified](t)(v.Verify(cc.AccessToken))
		if string(claims.Extra["tier"]) != `"gold"` || claims.Subject != reg.ClientID {
			t.Fatalf("access token claims = %+v", claims)
		}
		m2m := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "client_credentials", Scope: "pay:write", ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		if m2m.ExpiresIn != 300 {
			t.Fatalf("m2m with a short scope = %d", m2m.ExpiresIn)
		}
		md := o.op.Metadata()
		if strings.Join(md.ScopesSupported, " ") != "openid" || strings.Join(md.ClaimsSupported, " ") != "sub" {
			t.Fatalf("advertised = %v %v", md.ScopesSupported, md.ClaimsSupported)
		}
		// Fetch callers get the redirect as JSON.
		srv := httptest.NewServer(o.op.Handler())
		t.Cleanup(srv.Close)
		q := url.Values{"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {preview}, "scope": {"openid"}, "code_challenge": {opChallenge(opVerifier)}, "code_challenge_method": {"S256"}}
		req := must[*http.Request](t)(http.NewRequest(http.MethodGet, srv.URL+"/oauth2/authorize?"+q.Encode(), nil))
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.AddCookie(&http.Cookie{Name: "__Host-auth_session", Value: o.token.Reveal()})
		hres := must[*http.Response](t)(http.DefaultClient.Do(req))
		var body map[string]any
		_ = json.NewDecoder(hres.Body).Decode(&body)
		hres.Body.Close()
		if hres.StatusCode != 200 || body["redirect"] != true || !strings.HasPrefix(body["url"].(string), preview+"?code=") {
			t.Fatalf("fetch redirect = %d %v", hres.StatusCode, body)
		}
	})
}

// A generator that returns a short id, or a URL, fails registration.
func TestOAuthProvider_GeneratorRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var id string
		o := newOPEnv(t, e, oauthprovider.GenerateClientID(func() string { return id }))
		for _, id = range []string{"short", "https://tool.example.com/client.json"} {
			if _, err := o.op.CreateClient(context.Background(), oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "x", RedirectURIs: []string{opRedirect}}}); !errors.Is(err, oauthprovider.ErrShortGenerated) {
				t.Fatalf("%q: %v", id, err)
			}
		}
	})
}

// Pairwise subjects: a pairwise client sees each user as
// base64(HMAC-SHA256(secret, "<sector>.<user>")) in ID tokens, userinfo and
// introspection; clients on different hosts see different subs.
func TestOAuthProvider_PairwiseSubjects(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const secretP = "pairwise-secret-of-at-least-32-chars!"
		o := newOPEnv(t, e, oauthprovider.PairwiseSecret(secretP))
		pw := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{SubjectType: oauthprovider.SubjectPairwise}})
		const other = "https://other.example/cb"
		pw2 := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{SubjectType: oauthprovider.SubjectPairwise, RedirectURIs: []string{other}}})
		pub := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		want := func(host string) string {
			m := hmac.New(sha256.New, []byte(secretP))
			m.Write([]byte(host + "." + o.user.ID))
			return base64.StdEncoding.EncodeToString(m.Sum(nil))
		}
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(pw, o.code(t, authzReq(pw.ClientID)), opVerifier)))
		v := jwt.Verifier{Keys: jwt.KeysFromJWKS(o.jw.PublicKeys()), Issuer: testBaseURL, Audience: pw.ClientID, Now: e.clock.Now}
		if idt := must[jwt.Verified](t)(v.Verify(tok.IDToken)); idt.Subject != want("client.example") {
			t.Fatalf("pairwise ID token sub = %s", idt.Subject)
		}
		if info := must[map[string]any](t)(o.op.UserInfo(anon(o.a), tok.AccessToken)); info["sub"] != want("client.example") {
			t.Fatalf("pairwise userinfo sub = %v", info["sub"])
		}
		if in := must[oauthprovider.Introspection](t)(o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: tok.AccessToken, ClientID: pw.ClientID, ClientSecret: pw.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})); in.Subject != want("client.example") {
			t.Fatalf("pairwise introspection sub = %s", in.Subject)
		}
		in2 := authzReq(pw2.ClientID)
		in2.RedirectURI = other
		code2 := o.code(t, in2)
		t2 := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "authorization_code", Code: code2, RedirectURI: other, CodeVerifier: opVerifier, ClientID: pw2.ClientID, ClientSecret: pw2.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		if info := must[map[string]any](t)(o.op.UserInfo(anon(o.a), t2.AccessToken)); info["sub"] != want("other.example") || info["sub"] == want("client.example") {
			t.Fatalf("second sector sub = %v", info["sub"])
		}
		tp := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(pub, o.code(t, authzReq(pub.ClientID)), opVerifier)))
		if info := must[map[string]any](t)(o.op.UserInfo(anon(o.a), tp.AccessToken)); info["sub"] != o.user.ID {
			t.Fatalf("public sub = %v", info["sub"])
		}
		if md := o.op.Metadata(); strings.Join(md.SubjectTypesSupported, " ") != "public pairwise" {
			t.Fatalf("subject types = %v", md.SubjectTypesSupported)
		}
		// Redirect URIs on two hosts have no single sector.
		if _, err := o.op.CreateClient(context.Background(), oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "x", SubjectType: oauthprovider.SubjectPairwise, RedirectURIs: []string{opRedirect, other}}}); !errors.Is(err, oauthprovider.ErrInvalidClientMetadata) {
			t.Fatalf("two sectors: %v", err)
		}
	})
}

// Without PairwiseSecret a pairwise registration is refused.
func TestOAuthProvider_PairwiseNeedsSecret(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		if _, err := o.op.CreateClient(context.Background(), oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "x", SubjectType: oauthprovider.SubjectPairwise, RedirectURIs: []string{opRedirect}}}); !errors.Is(err, oauthprovider.ErrInvalidClientMetadata) {
			t.Fatalf("pairwise without a secret: %v", err)
		}
	})
}

// The OpenID Connect claims parameter: it needs openid and
// a valid object; an essential acr other than "0" is access_denied; the
// userinfo names it asks for are consented and then released at userinfo
// without their scope.
func TestOAuthProvider_ClaimsParameter(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		reg := o.client(t, oauthprovider.ClientSpec{})
		in := authzReq(reg.ClientID)
		in.Scope = "openid"
		for name, c := range map[string]struct {
			scope, claims string
			want          error
		}{
			"without openid": {"profile", `{"userinfo":{"email":null}}`, oauthprovider.ErrInvalidRequest},
			"not JSON":       {"openid", `{`, oauthprovider.ErrInvalidRequest},
			"member not obj": {"openid", `{"userinfo":{"email":1}}`, oauthprovider.ErrInvalidRequest},
			"essential acr":  {"openid", `{"id_token":{"acr":{"essential":true,"values":["2"]}}}`, oauthprovider.ErrAccessDenied},
		} {
			bad := in
			bad.Scope, bad.Claims = c.scope, c.claims
			_, err := o.op.Authorize(request(o.a, o.token), bad)
			var re *oauthprovider.RedirectError
			if !errors.Is(err, c.want) || !errors.As(err, &re) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		in.Claims = `{"userinfo":{"email":null,"unknown_claim":null},"id_token":{"acr":{"essential":true,"values":["0","1"]}}}`
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, in), opVerifier)))
		info := must[map[string]any](t)(o.op.UserInfo(anon(o.a), tok.AccessToken))
		if info["email"] != alice || info["name"] != nil || info["unknown_claim"] != nil {
			t.Fatalf("userinfo = %v", info)
		}
		// An unsupported name is dropped, so it needs no new consent.
		in.Claims = `{"userinfo":{"email":null,"another_unknown":null}}`
		if res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), in)); !strings.HasPrefix(res.RedirectTo, opRedirect+"?code=") {
			t.Fatalf("unsupported claim asked for consent: %s", res.RedirectTo)
		}
		// The same scopes with a claim the consent does not cover ask again.
		in.Claims = `{"userinfo":{"name":null}}`
		res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), in))
		if !strings.HasPrefix(res.RedirectTo, "/consent?") {
			t.Fatalf("uncovered claim = %s", res.RedirectTo)
		}
		md := o.op.Metadata()
		if !md.ClaimsParameterSupported || strings.Join(md.ACRValuesSupported, ",") != "0" {
			t.Fatalf("metadata = %+v", md)
		}
	})
}

// request_uri through RequestURIResolver (RFC 9126): every
// parameter comes from the stored request except client_id; an unknown one
// is invalid_request_uri; request with request_uri is invalid_request.
func TestOAuthProvider_RequestURIResolver(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		stored := map[string]url.Values{}
		o := newOPEnv(t, e, oauthprovider.RequestURIResolver(func(_ context.Context, uri, clientID string) (url.Values, error) {
			return stored[uri], nil
		}))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		stored["urn:ietf:params:oauth:request_uri:abc"] = url.Values{
			"response_type": {"code"}, "client_id": {"ignored"}, "redirect_uri": {opRedirect}, "scope": {"openid"},
			"state": {"from-par"}, "code_challenge": {opChallenge(opVerifier)}, "code_challenge_method": {"S256"},
		}
		res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), oauthprovider.AuthorizeRequest{ClientID: reg.ClientID, RequestURI: "urn:ietf:params:oauth:request_uri:abc", State: "from-url"}))
		u := must[*url.URL](t)(url.Parse(res.RedirectTo))
		if u.Query().Get("code") == "" || u.Query().Get("state") != "from-par" {
			t.Fatalf("resolved = %s", res.RedirectTo)
		}
		if _, err := o.op.Authorize(request(o.a, o.token), oauthprovider.AuthorizeRequest{ClientID: reg.ClientID, RequestURI: "urn:unknown"}); !errors.Is(err, oauthprovider.ErrInvalidRequestURI) {
			t.Fatalf("unknown request_uri: %v", err)
		}
		if _, err := o.op.Authorize(request(o.a, o.token), oauthprovider.AuthorizeRequest{ClientID: reg.ClientID, RequestURI: "urn:ietf:params:oauth:request_uri:abc", Request: "x"}); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("request with request_uri: %v", err)
		}
		stored["urn:nested"] = url.Values{"request_uri": {"urn:ietf:params:oauth:request_uri:abc"}}
		if _, err := o.op.Authorize(request(o.a, o.token), oauthprovider.AuthorizeRequest{ClientID: reg.ClientID, RequestURI: "urn:nested"}); !errors.Is(err, oauthprovider.ErrInvalidRequestURI) {
			t.Fatalf("nested request_uri: %v", err)
		}
	})
}

// Back-channel logout: when a session ends, its access
// tokens stop, refresh tokens without offline_access stop, and each client
// with a backchannel_logout_uri gets a logout+jwt with sub, sid and the
// event, signed with the ID-token key.
func TestOAuthProvider_BackchannelLogout(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		got := make(chan string, 4)
		rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			got <- r.PostForm.Get("logout_token")
		}))
		t.Cleanup(rp.Close)
		o := newOPEnv(t, e)
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{BackchannelLogoutURI: rp.URL + "/bc", BackchannelLogoutSessionRequired: true}})
		online := authzReq(reg.ClientID)
		online.Scope = "openid"
		short := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, online), opVerifier)))
		long := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		sess := must[*auth.Session](t)(func() (*auth.Session, error) {
			s, _, _, err := o.a.ResolveSession(context.Background(), o.token)
			return s, err
		}())
		if err := o.a.SignOut(request(o.a, o.token)); err != nil {
			t.Fatal(err)
		}
		o.a.WaitDeliveries()
		var tok string
		select {
		case tok = <-got:
		default:
			t.Fatal("no logout token was delivered")
		}
		v := jwt.Verifier{Keys: jwt.KeysFromJWKS(o.jw.PublicKeys()), Issuer: testBaseURL, Audience: reg.ClientID, Now: e.clock.Now, Types: []string{oauthprovider.LogoutTokenType}}
		lt, err := v.Verify(tok)
		if err != nil || lt.Subject != o.user.ID || lt.SessionID != sess.ID || !strings.Contains(string(lt.Extra["events"]), "backchannel-logout") || lt.Extra["nonce"] != nil {
			t.Fatalf("logout token = %+v %v", lt, err)
		}
		if len(got) != 0 {
			t.Fatal("one session and client got two logout tokens")
		}
		for _, at := range []string{short.AccessToken, long.AccessToken} {
			if _, err := o.op.VerifyAccessToken(context.Background(), at); !errors.Is(err, oauthprovider.ErrInvalidToken) {
				t.Fatalf("access token outlived the session: %v", err)
			}
		}
		rt := func(r string) error {
			_, err := o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: r, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})
			return err
		}
		if short.RefreshToken != "" {
			t.Fatal("a token without offline_access got a refresh token")
		}
		if err := rt(long.RefreshToken); err != nil {
			t.Fatalf("offline_access refresh token ended with the session: %v", err)
		}
		if _, err := o.op.CreateClient(context.Background(), oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "x", RedirectURIs: []string{opRedirect}, BackchannelLogoutURI: "http://rp.example/bc"}}); !errors.Is(err, oauthprovider.ErrInvalidClientMetadata) {
			t.Fatalf("plain-http back-channel URI: %v", err)
		}
	})
}
