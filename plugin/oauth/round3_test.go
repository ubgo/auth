package oauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// decodeJWS splits a compact JWS into its decoded header and claims, for
// tests that inspect what a signer wrote.
func decodeJWS(t *testing.T, tok string) (map[string]string, map[string]any, []byte, []byte) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	hb, errH := b64dec(parts[0])
	cb, errC := b64dec(parts[1])
	sig, errS := b64dec(parts[2])
	if errH != nil || errC != nil || errS != nil {
		t.Fatal(errH, errC, errS)
	}
	var h map[string]string
	var c map[string]any
	if err := json.Unmarshal(hb, &h); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(cb, &c); err != nil {
		t.Fatal(err)
	}
	return h, c, []byte(parts[0] + "." + parts[1]), sig
}

func b64dec(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// discoveryServer serves a discovery document built from its own URL plus
// the given routes.
func discoveryServer(t *testing.T, doc func(base string) string, routes map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	var base string
	all := map[string]http.HandlerFunc{discoveryPath: func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(doc(base)))
	}}
	for k, v := range routes {
		all[k] = v
	}
	srv := providerServer(t, all)
	base = srv.URL
	return srv
}

func TestClientAssertion_ES256AndRS256(t *testing.T) {
	keys := newTestKeys(t)
	now := time.Now().Add(-time.Minute)
	for _, c := range []struct {
		name string
		key  crypto.Signer
		alg  string
	}{{"ec", keys.ec, algES256}, {"rsa", keys.rsa, algRS256}} {
		t.Run(c.name, func(t *testing.T) {
			fn, err := ClientAssertion("client-1", "kid-1", c.key)
			if err != nil {
				t.Fatal(err)
			}
			tok, err := fn(context.Background(), "https://idp.test/token")
			if err != nil {
				t.Fatal(err)
			}
			h, claims, input, sig := decodeJWS(t, tok)
			if h["alg"] != c.alg || h["typ"] != jwtType || h["kid"] != "kid-1" {
				t.Fatalf("header = %v", h)
			}
			if claims["iss"] != "client-1" || claims["sub"] != "client-1" || claims["aud"] != "https://idp.test/token" || claims["jti"] == "" {
				t.Fatalf("claims = %v", claims)
			}
			iat, exp := claims["iat"].(float64), claims["exp"].(float64)
			if time.Duration(exp-iat)*time.Second != assertionLifetime || iat < float64(now.Unix()) {
				t.Fatalf("iat %v exp %v", iat, exp)
			}
			// The signature verifies under the provider's view of the key: the
			// same verifier the ID-token path uses.
			var pk publicKey
			switch k := c.key.(type) {
			case *ecdsa.PrivateKey:
				pk = publicKey{alg: algES256, key: &k.PublicKey}
			case *rsa.PrivateKey:
				pk = publicKey{alg: algRS256, key: &k.PublicKey}
			}
			if !verifySignature(pk, c.alg, input, sig) {
				t.Fatal("signature does not verify")
			}
			// Two assertions differ: a fresh jti each time.
			tok2, _ := fn(context.Background(), "https://idp.test/token")
			if tok2 == tok {
				t.Fatal("two assertions are identical")
			}
		})
	}
	// Refused keys and configuration.
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ClientAssertion("c", "k", p384); !errors.Is(err, ErrAssertionKey) {
		t.Fatalf("P-384: %v", err)
	}
	if _, err := ClientAssertion("c", "k", keys.ed); !errors.Is(err, ErrAssertionKey) {
		t.Fatalf("Ed25519: %v", err)
	}
	if _, err := ClientAssertion("", "k", keys.ec); !errors.Is(err, ErrAssertionConfig) {
		t.Fatalf("empty client id: %v", err)
	}
}

func TestTokenAuth_PrivateKeyJWT(t *testing.T) {
	keys := newTestKeys(t)
	rec := &tokenRequestRecorder{answer: `{"access_token":"at"}`}
	srv := providerServer(t, map[string]http.HandlerFunc{"/token": rec.handler()})
	assertion, err := ClientAssertion("id-1", "k", keys.ec)
	if err != nil {
		t.Fatal(err)
	}
	profile := func(context.Context, *http.Client, string) (Profile, error) { return Profile{Subject: "s"}, nil }
	o := &OAuth2{ID: "t", ClientID: "id-1", AuthURL: "https://idp/auth", TokenURL: srv.URL + "/token", FetchProfile: profile, TokenAuth: PrivateKeyJWT, ClientAssertion: assertion}
	if _, err := o.Exchange(context.Background(), srv.Client(), "code", "ver", "https://app/cb"); err != nil {
		t.Fatal(err)
	}
	if rec.hasBasic || rec.form.Has(paramClientSecret) || rec.form.Get(paramAssertionType) != assertionTypeJWT || rec.form.Get(paramClientID) != "id-1" {
		t.Fatalf("form = %v basic %v", rec.form, rec.hasBasic)
	}
	_, claims, _, _ := decodeJWS(t, rec.form.Get(paramAssertion))
	if claims["aud"] != srv.URL+"/token" {
		t.Fatalf("assertion aud = %v, want the token endpoint", claims["aud"])
	}
	// A TokenParams entry cannot replace the assertion.
	o.TokenParams = url.Values{paramAssertion: {"forged"}, paramAssertionType: {"x"}, "audience": {"api"}}
	if _, err := o.Exchange(context.Background(), srv.Client(), "code", "ver", "https://app/cb"); err != nil {
		t.Fatal(err)
	}
	if rec.form.Get(paramAssertion) == "forged" || rec.form.Get(paramAssertionType) != assertionTypeJWT || rec.form.Get("audience") != "api" {
		t.Fatalf("form = %v", rec.form)
	}
	// A failing assertion signer fails the exchange as ErrExchange.
	o.ClientAssertion = func(context.Context, string) (string, error) { return "", errors.New("hsm down") }
	if _, err := o.Exchange(context.Background(), srv.Client(), "code", "ver", "https://app/cb"); !errors.Is(err, ErrExchange) {
		t.Fatalf("failing signer: %v", err)
	}

	// Configuration: the assertion and PrivateKeyJWT go together, and a
	// secret has no place beside them.
	good := func() *OAuth2 {
		return &OAuth2{ID: "t", ClientID: "id-1", AuthURL: "https://idp/auth", TokenURL: "https://idp/token", FetchProfile: profile, TokenAuth: PrivateKeyJWT, ClientAssertion: assertion}
	}
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(good())))); err != nil {
		t.Fatal(err)
	}
	noAssertion := good()
	noAssertion.ClientAssertion = nil
	withPost := good()
	withPost.TokenAuth = ClientSecretPost
	withPost.ClientSecret = "s"
	withSecret := good()
	withSecret.ClientSecret = "s"
	for name, o := range map[string]*OAuth2{"no assertion": noAssertion, "assertion with post": withPost} {
		if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(o)))); !errors.Is(err, ErrAssertionConfig) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(withSecret)))); !errors.Is(err, ErrProviderIncomplete) {
		t.Fatalf("secret with PrivateKeyJWT: %v", err)
	}
	// The same rules on an OIDC provider, checked before discovery.
	oidc := OIDC("okta", "https://okta.test", "id", "")
	oidc.TokenAuth = PrivateKeyJWT
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(oidc)))); !errors.Is(err, ErrAssertionConfig) {
		t.Fatalf("oidc without assertion: %v", err)
	}
	oidc.ClientAssertion = assertion
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(oidc)))); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshParams_OnlyOnTheRefreshGrant(t *testing.T) {
	rec := &tokenRequestRecorder{answer: `{"access_token":"at","refresh_token":"rt"}`}
	srv := providerServer(t, map[string]http.HandlerFunc{"/token": rec.handler()})
	o := &OAuth2{ID: "t", ClientID: "c", ClientSecret: "s", TokenURL: srv.URL + "/token",
		FetchProfile:  func(context.Context, *http.Client, string) (Profile, error) { return Profile{Subject: "s"}, nil },
		TokenParams:   url.Values{"shared": {"1"}},
		RefreshParams: url.Values{"only_refresh": {"1"}, paramGrantType: {"forged"}}}
	if _, err := o.Exchange(context.Background(), srv.Client(), "code", "ver", "https://app/cb"); err != nil {
		t.Fatal(err)
	}
	if rec.form.Has("only_refresh") || rec.form.Get("shared") != "1" {
		t.Fatalf("exchange form = %v", rec.form)
	}
	if _, err := o.Refresh(context.Background(), srv.Client(), "rt"); err != nil {
		t.Fatal(err)
	}
	if rec.form.Get("only_refresh") != "1" || rec.form.Get("shared") != "1" || rec.form.Get(paramGrantType) != grantRefreshToken {
		t.Fatalf("refresh form = %v", rec.form)
	}
}

func TestRevoke_RFC7009(t *testing.T) {
	rec := &tokenRequestRecorder{answer: `{}`}
	srv := providerServer(t, map[string]http.HandlerFunc{"/revoke": rec.handler(), "/down": answer(http.StatusServiceUnavailable, "")})
	o := &OAuth2{ID: "t", ClientID: "c:1", ClientSecret: "s%", RevokeURL: srv.URL + "/revoke"}
	ctx := context.Background()
	// The refresh token is preferred: revoking it revokes its access tokens.
	if err := o.Revoke(ctx, srv.Client(), TokenSet{AccessToken: "at", RefreshToken: "rt"}); err != nil {
		t.Fatal(err)
	}
	if rec.form.Get(paramToken) != "rt" || rec.form.Get(paramTokenTypeHint) != tokenTypeRefresh || rec.form.Get(paramClientSecret) != "s%" || rec.form.Get(paramClientID) != "c:1" {
		t.Fatalf("form = %v", rec.form)
	}
	// Without one, the access token; with neither, nothing is sent.
	if err := o.Revoke(ctx, srv.Client(), TokenSet{AccessToken: "at"}); err != nil || rec.form.Get(paramToken) != "at" || rec.form.Get(paramTokenTypeHint) != tokenTypeAccess {
		t.Fatalf("access: %v form %v", err, rec.form)
	}
	rec.form = nil
	if err := o.Revoke(ctx, srv.Client(), TokenSet{}); err != nil || rec.form != nil {
		t.Fatalf("empty set: %v form %v", err, rec.form)
	}
	// Basic authentication, and no RevokeURL, and a provider that answers
	// with an error.
	o.TokenAuth = ClientSecretBasic
	if err := o.Revoke(ctx, srv.Client(), TokenSet{AccessToken: "at"}); err != nil || !rec.hasBasic || rec.form.Has(paramClientSecret) {
		t.Fatalf("basic: %v %v %v", err, rec.hasBasic, rec.form)
	}
	none := &OAuth2{ID: "t", ClientID: "c"}
	if err := none.Revoke(ctx, srv.Client(), TokenSet{AccessToken: "at"}); err != nil {
		t.Fatalf("no RevokeURL: %v", err)
	}
	down := &OAuth2{ID: "t", ClientID: "c", RevokeURL: srv.URL + "/down"}
	if err := down.Revoke(ctx, srv.Client(), TokenSet{AccessToken: "at"}); !errors.Is(err, ErrExchange) {
		t.Fatalf("503: %v", err)
	}
	failing := &OAuth2{ID: "t", ClientID: "c", RevokeURL: srv.URL + "/revoke", ClientSecretFunc: func(context.Context) (string, error) { return "", errors.New("no") }}
	if err := failing.Revoke(ctx, srv.Client(), TokenSet{AccessToken: "at"}); !errors.Is(err, ErrExchange) {
		t.Fatalf("secret failure: %v", err)
	}
	bad := &OAuth2{ID: "t", ClientID: "c", RevokeURL: "http://[::1"}
	if err := bad.Revoke(ctx, srv.Client(), TokenSet{AccessToken: "at"}); !errors.Is(err, ErrExchange) {
		t.Fatalf("bad URL: %v", err)
	}
	unreachable := &OAuth2{ID: "t", ClientID: "c", RevokeURL: unreachableURL(t)}
	if err := unreachable.Revoke(ctx, http.DefaultClient, TokenSet{AccessToken: "at"}); !errors.Is(err, ErrExchange) {
		t.Fatalf("unreachable: %v", err)
	}
}

func TestTokenSet_ScopeRefreshExpiryAndRaw(t *testing.T) {
	body := `{"access_token":"at","refresh_token":"rt","expires_in":60,"refresh_token_expires_in":3600,"scope":"openid email","openid":"wx-1"}`
	srv := providerServer(t, map[string]http.HandlerFunc{"/token": answer(http.StatusOK, body)})
	var got TokenSet
	o := &OAuth2{ID: "t", ClientID: "c", ClientSecret: "s", TokenURL: srv.URL + "/token",
		FetchProfileFromTokens: func(_ context.Context, _ *http.Client, ts TokenSet) (Profile, error) {
			got = ts
			var raw struct {
				OpenID string `json:"openid"`
			}
			if err := json.Unmarshal(ts.Raw, &raw); err != nil {
				return Profile{}, err
			}
			return Profile{Subject: raw.OpenID}, nil
		},
		// Ignored while FetchProfileFromTokens is set.
		FetchProfile: func(context.Context, *http.Client, string) (Profile, error) { return Profile{Subject: "wrong"}, nil },
	}
	before := time.Now()
	p, err := o.Exchange(context.Background(), srv.Client(), "code", "ver", "https://app/cb")
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "wx-1" || got.Scope != "openid email" || string(got.Raw) != body || p.Tokens.Scope != "openid email" {
		t.Fatalf("profile %+v tokens %+v", p, got)
	}
	if d := got.RefreshExpiresAt.Sub(before); d < 59*time.Minute || d > 61*time.Minute {
		t.Fatalf("refresh expiry in %v", d)
	}
	if d := got.ExpiresAt.Sub(before); d < 59*time.Second || d > 61*time.Second {
		t.Fatalf("expiry in %v", d)
	}
	// Keycloak's spelling, and no refresh expiry without a refresh token.
	kc := tokenResponse{AccessToken: "at", RefreshToken: "rt", RefreshExpiresInAlt: 120}
	if ts := kc.tokenSet(0); ts.RefreshExpiresAt.IsZero() {
		t.Fatal("refresh_expires_in ignored")
	}
	none := tokenResponse{AccessToken: "at", RefreshExpiresIn: 120}
	if ts := none.tokenSet(0); !ts.RefreshExpiresAt.IsZero() {
		t.Fatal("a refresh expiry without a refresh token")
	}
	// FetchProfileWith: the order of sources, and none at all.
	withBoth := &OAuth2{FetchProfile: func(context.Context, *http.Client, string) (Profile, error) { return Profile{Subject: "a"}, nil }}
	if p, err := withBoth.FetchProfileWith(context.Background(), srv.Client(), TokenSet{AccessToken: "x"}); err != nil || p.Subject != "a" {
		t.Fatalf("FetchProfile fallback: %+v %v", p, err)
	}
	if _, err := (&OAuth2{}).FetchProfileWith(context.Background(), srv.Client(), TokenSet{}); !errors.Is(err, ErrProfileUnsupported) {
		t.Fatalf("no source: %v", err)
	}
	// Validate accepts FetchProfileFromTokens as the one profile source.
	only := &OAuth2{ID: "t", ClientID: "c", ClientSecret: "s", AuthURL: "https://a", TokenURL: "https://b", FetchProfileFromTokens: o.FetchProfileFromTokens}
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(only)))); err != nil {
		t.Fatal(err)
	}
}

func TestUserInfoProfile_SubjectClaimAndClaims(t *testing.T) {
	srv := providerServer(t, map[string]http.HandlerFunc{
		"/str":    answer(http.StatusOK, `{"sub":"s-1","oid":"o-1","email":"a@b.co","email_verified":"true","name":"Ann","hd":"acme.example"}`),
		"/num":    answer(http.StatusOK, `{"sub":"s-1","id":12345678901234567890,"email_verified":false}`),
		"/object": answer(http.StatusOK, `{"sub":"s-1","oid":{"x":1}}`),
		"/array":  answer(http.StatusOK, `[1]`),
	})
	ctx := context.Background()
	p, err := UserInfoProfile(srv.URL+"/str", "oid")(ctx, srv.Client(), "at")
	if err != nil || p.Subject != "o-1" || !p.EmailVerified || string(p.Claims["hd"]) != `"acme.example"` || p.Name != "Ann" {
		t.Fatalf("string claim: %+v %v", p, err)
	}
	// A string email_verified is read as the boolean it spells.
	p, err = UserInfoProfile(srv.URL+"/num", "id")(ctx, srv.Client(), "at")
	if err != nil || p.Subject != "12345678901234567890" || p.EmailVerified {
		t.Fatalf("numeric claim: %+v %v", p, err)
	}
	// sub by default; an object is no subject, which the exchange refuses.
	p, err = UserInfoProfile(srv.URL+"/str", "")(ctx, srv.Client(), "at")
	if err != nil || p.Subject != "s-1" {
		t.Fatalf("default claim: %+v %v", p, err)
	}
	p, err = UserInfoProfile(srv.URL+"/object", "oid")(ctx, srv.Client(), "at")
	if err != nil || p.Subject != "" {
		t.Fatalf("object claim: %+v %v", p, err)
	}
	if _, err := UserInfoProfile(srv.URL+"/array", "")(ctx, srv.Client(), "at"); !errors.Is(err, ErrExchange) {
		t.Fatalf("array body: %v", err)
	}
	if claimsOf(json.RawMessage(`[1]`)) != nil {
		t.Fatal("claims of an array")
	}
	// GitHub's profile keeps the /user object as claims.
	gh := providerServer(t, map[string]http.HandlerFunc{
		"/user":        answer(http.StatusOK, `{"id":7,"login":"ann","avatar_url":"https://img/a"}`),
		"/user/emails": answer(http.StatusOK, `[{"email":"a@b.co","primary":true,"verified":true}]`),
	})
	p, err = GitHubProfile(gh.URL)(ctx, gh.Client(), "at")
	if err != nil || string(p.Claims["login"]) != `"ann"` || p.Subject != "7" {
		t.Fatalf("github claims: %+v %v", p, err)
	}
	ghBad := providerServer(t, map[string]http.HandlerFunc{"/user": answer(http.StatusOK, `[]`)})
	if _, err := GitHubProfile(ghBad.URL)(ctx, ghBad.Client(), "at"); !errors.Is(err, ErrExchange) {
		t.Fatalf("github array user: %v", err)
	}
	ghEmails := providerServer(t, map[string]http.HandlerFunc{"/user": answer(http.StatusOK, `{"id":7}`), "/user/emails": answer(http.StatusOK, `{"not":"a list"}`)})
	if _, err := GitHubProfile(ghEmails.URL)(ctx, ghEmails.Client(), "at"); !errors.Is(err, ErrExchange) {
		t.Fatalf("github emails object: %v", err)
	}
}

func TestGoogleIDTokens_HostedDomain(t *testing.T) {
	cfg := GoogleIDTokens("ios-1", "android-1")
	if cfg.JWKSURL != GoogleJWKSURL || len(cfg.Issuers) != 2 || cfg.HostedDomain != "" || len(cfg.Audiences) != 2 || !cfg.Enabled() {
		t.Fatalf("config = %+v", cfg)
	}
	if GoogleIDTokensFor("acme.example").HostedDomain != "acme.example" {
		t.Fatal("hosted domain not kept")
	}
	// Google keeps its id-token route off until the config is set.
	g := Google("web", "s")
	if _, ok := Provider(g).(IDTokenVerifier); !ok || g.IDToken.Enabled() {
		t.Fatalf("Google accepts ID tokens by default: %+v", g.IDToken)
	}
	g.IDToken = GoogleIDTokens()
	p := New(WithProviders(g))
	if _, ok := findOp(p, IDTokenEndpoint("google")); !ok {
		t.Fatal("no id-token operation once configured")
	}

	// The hd claim is enforced on the token, case-insensitively, and its
	// raw claims reach the profile.
	e := newIDTokenEnv(t)
	e.v.cfg.HostedDomain = "acme.example"
	tok := e.keys.sign(t, algES256, kidEC, e.claims(map[string]any{"hd": "ACME.example"}))
	c, err := e.v.verify(context.Background(), e.hc, tok, "")
	if err != nil || string(c.raw["hd"]) != `"ACME.example"` {
		t.Fatalf("matching hd: %v %v", err, c.raw)
	}
	if string(profileFromClaims(c).Claims["email"]) != `"a@b.co"` {
		t.Fatal("profile lost the raw claims")
	}
	for _, hd := range []any{"other.example", nil} {
		over := map[string]any{}
		if hd != nil {
			over["hd"] = hd
		}
		tok := e.keys.sign(t, algES256, kidEC, e.claims(over))
		if _, err := e.v.verify(context.Background(), e.hc, tok, ""); !errors.Is(err, ErrIDTokenInvalid) {
			t.Fatalf("hd %v: %v", hd, err)
		}
	}
}

func TestOIDC_DiscoveryFillsRevocationAndIssuerParameter(t *testing.T) {
	rec := &tokenRequestRecorder{answer: `{}`}
	for _, supported := range []bool{true, false} {
		s := discoveryServer(t, func(base string) string {
			return `{"issuer":"` + base + `","authorization_endpoint":"` + base + `/auth","token_endpoint":"` + base + `/token","userinfo_endpoint":"` + base + `/me",` +
				`"revocation_endpoint":"` + base + `/revoke","authorization_response_iss_parameter_supported":` + boolString(supported) + `}`
		}, map[string]http.HandlerFunc{"/revoke": rec.handler()})
		o := OIDC("idp", s.URL, "cid", "sec")
		if got := o.ExpectedIssuer(); got != "" {
			t.Fatalf("issuer before discovery = %q", got)
		}
		if err := o.Discover(context.Background(), s.Client()); err != nil {
			t.Fatal(err)
		}
		want := ""
		if supported {
			want = s.URL
		}
		if got := o.ExpectedIssuer(); got != want {
			t.Fatalf("supported %v: issuer = %q, want %q", supported, got, want)
		}
		if err := o.Revoke(context.Background(), s.Client(), TokenSet{AccessToken: "at"}); err != nil || rec.form.Get(paramToken) != "at" {
			t.Fatalf("revoke: %v %v", err, rec.form)
		}
	}
	// A hand-set RevokeURL and SubjectClaim reach the discovered provider.
	s := discoveryServer(t, func(base string) string {
		return `{"issuer":"` + base + `","authorization_endpoint":"` + base + `/auth","token_endpoint":"` + base + `/token","userinfo_endpoint":"` + base + `/me"}`
	}, map[string]http.HandlerFunc{"/me": answer(http.StatusOK, `{"sub":"s","oid":"o"}`)})
	o := OIDC("idp", s.URL, "cid", "sec")
	o.RevokeURL, o.SubjectClaim, o.RefreshParams = "https://x/revoke", "oid", url.Values{"a": {"b"}}
	c, err := o.discover(context.Background(), s.Client())
	if err != nil || c.RevokeURL != "https://x/revoke" || c.RefreshParams.Get("a") != "b" || c.AuthorizationIssuer != "" {
		t.Fatalf("discovered = %+v %v", c, err)
	}
	p, err := o.FetchProfileWith(context.Background(), s.Client(), TokenSet{AccessToken: "at"})
	if err != nil || p.Subject != "o" {
		t.Fatalf("profile = %+v %v", p, err)
	}
	// Discovery failures surface through the new methods too.
	dead := OIDC("idp", unreachableURL(t), "cid", "sec")
	if _, err := dead.FetchProfileWith(context.Background(), http.DefaultClient, TokenSet{}); err == nil {
		t.Fatal("profile without discovery")
	}
	if err := dead.Revoke(context.Background(), http.DefaultClient, TokenSet{AccessToken: "at"}); err == nil {
		t.Fatal("revoke without discovery")
	}
	// The plain OAuth2 reports its field.
	if (&OAuth2{AuthorizationIssuer: "https://i"}).ExpectedIssuer() != "https://i" {
		t.Fatal("OAuth2 issuer")
	}
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
