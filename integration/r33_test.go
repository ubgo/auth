package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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
	"github.com/ubgo/sqlb"
)

// Fixtures of the OAuth provider tests.
const (
	opRedirect = "https://client.example/cb"
	opVerifier = "dBjftJeZ4CVP-mJ92K9oAiBz7l3Pa3qL0w9bQ8xSaYkx"
	opScopes   = "openid profile email offline_access"
)

func opChallenge(v string) string {
	s := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

// opEnv is one provider wired with email, password and jwt, and a signed-in
// user.
type opEnv struct {
	pw    *password.Plugin
	e     *env
	a     *auth.Auth
	jw    *jwt.Plugin
	op    *oauthprovider.Plugin
	user  auth.UserView
	token auth.Token
}

func newOPEnv(t *testing.T, e *env, opts ...oauthprovider.Option) opEnv {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
	op := oauthprovider.New(jw, append([]oauthprovider.Option{oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login"), oauthprovider.ConsentPage("/consent")}, opts...)...)
	em, pw := e.emailPlugin(), e.passwordPlugin()
	// A secret signs plugin cookies (the logout confirmation).
	a := e.newAuth(t, []auth.Option{auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize)))}, em, pw, jw, op)
	up := signUpVerified(t, e, a, pw, em)
	return opEnv{pw: pw, e: e, a: a, jw: jw, op: op, user: up.User, token: up.Token}
}

func (o opEnv) client(t *testing.T, spec oauthprovider.ClientSpec) oauthprovider.Registration {
	t.Helper()
	if len(spec.RedirectURIs) == 0 {
		spec.RedirectURIs = []string{opRedirect}
	}
	if spec.Name == "" {
		spec.Name = "Client"
	}
	reg, err := o.op.CreateClient(context.Background(), spec)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	return reg
}

func authzReq(clientID string) oauthprovider.AuthorizeRequest {
	return oauthprovider.AuthorizeRequest{ResponseType: "code", ClientID: clientID, RedirectURI: opRedirect, Scope: opScopes, State: "st", CodeChallenge: opChallenge(opVerifier), CodeChallengeMethod: "S256", Nonce: "n-1"}
}

// code runs authorize (and consent when asked) and returns the code.
func (o opEnv) code(t *testing.T, in oauthprovider.AuthorizeRequest) string {
	t.Helper()
	res, err := o.op.Authorize(request(o.a, o.token), in)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	u := must[*url.URL](t)(url.Parse(res.RedirectTo))
	if u.Path == "/consent" {
		res, err = o.op.Consent(request(o.a, o.token), oauthprovider.ConsentRequest{Query: u.RawQuery, Accept: true})
		if err != nil {
			t.Fatalf("consent: %v", err)
		}
		u = must[*url.URL](t)(url.Parse(res.RedirectTo))
	}
	q := u.Query()
	if q.Get("state") != in.State || q.Get("iss") != testBaseURL || q.Get("code") == "" {
		t.Fatalf("redirect = %s", res.RedirectTo)
	}
	return q.Get("code")
}

func exchange(reg oauthprovider.Registration, code, verifier string) oauthprovider.TokenRequest {
	return oauthprovider.TokenRequest{GrantType: "authorization_code", Code: code, RedirectURI: opRedirect, CodeVerifier: verifier, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
}

func TestOAuthProvider_CodeFlowEndToEnd(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		reg := o.client(t, oauthprovider.ClientSpec{})
		if !strings.HasPrefix(reg.Secret, oauthprovider.PrefixClientSecret) {
			t.Fatalf("secret = %q", reg.Secret)
		}
		// First visit asks for consent; the consent page's answer issues the
		// code; the second visit does not ask again.
		res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), authzReq(reg.ClientID)))
		if !strings.HasPrefix(res.RedirectTo, "/consent?") {
			t.Fatalf("first authorize = %s", res.RedirectTo)
		}
		code := o.code(t, authzReq(reg.ClientID))
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, code, opVerifier)))
		if tok.TokenType != "Bearer" || tok.RefreshToken == "" || tok.IDToken == "" || tok.Scope != opScopes || tok.ExpiresIn != 3600 {
			t.Fatalf("token = %+v", tok)
		}
		// The ID token verifies against the published keys, for this client,
		// with the request's nonce.
		v := jwt.Verifier{Keys: jwt.KeysFromJWKS(o.jw.PublicKeys()), Issuer: testBaseURL, Audience: reg.ClientID, Now: e.clock.Now}
		idt, err := v.Verify(tok.IDToken)
		if err != nil || idt.Subject != o.user.ID || string(idt.Extra["nonce"]) != `"n-1"` || string(idt.Extra["email"]) != `"`+alice+`"` || string(idt.Extra["email_verified"]) != "true" {
			t.Fatalf("id token = %+v %v", idt, err)
		}
		info := must[map[string]any](t)(o.op.UserInfo(anon(o.a), tok.AccessToken))
		if info["sub"] != o.user.ID || info["email"] != alice || info["name"] != "Alice" {
			t.Fatalf("userinfo = %v", info)
		}
		in := must[oauthprovider.Introspection](t)(o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: tok.AccessToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		if !in.Active || in.Subject != o.user.ID || in.ClientID != reg.ClientID || in.TokenType != "access_token" {
			t.Fatalf("introspection = %+v", in)
		}
		// Refresh rotates; the old refresh token is spent, and its reuse
		// revokes the whole family, the new pair included.
		ref := oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: tok.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
		tok2 := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), ref))
		if tok2.RefreshToken == "" || tok2.RefreshToken == tok.RefreshToken || tok2.IDToken == "" {
			t.Fatalf("refreshed = %+v", tok2)
		}
		if _, err := o.op.Token(anon(o.a), ref); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("reused refresh token: %v", err)
		}
		if _, err := o.op.VerifyAccessToken(context.Background(), tok2.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("family survived a reused refresh token: %v", err)
		}
		ref.RefreshToken = tok2.RefreshToken
		if _, err := o.op.Token(anon(o.a), ref); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("refresh from a revoked family: %v", err)
		}
		// Revocation of an access token ends it; userinfo then refuses.
		tok3 := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		if err := o.op.Revoke(anon(o.a), oauthprovider.RevokeRequest{Token: tok3.AccessToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}); err != nil {
			t.Fatal(err)
		}
		if _, err := o.op.UserInfo(anon(o.a), tok3.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("revoked token at userinfo: %v", err)
		}
	})
}

// A code is single use, bound to its client, redirect URI and verifier, and
// expires; a replay revokes what the code was exchanged for.
func TestOAuthProvider_CodeRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		reg := o.client(t, oauthprovider.ClientSpec{})
		other := o.client(t, oauthprovider.ClientSpec{})
		code := o.code(t, authzReq(reg.ClientID))
		for name, req := range map[string]oauthprovider.TokenRequest{
			"wrong verifier": exchange(reg, code, strings.Repeat("a", 43)),
			"no verifier":    exchange(reg, code, ""),
			"other client":   exchange(other, code, opVerifier),
			"wrong redirect": func() oauthprovider.TokenRequest {
				r := exchange(reg, code, opVerifier)
				r.RedirectURI = opRedirect + "/x"
				return r
			}(),
			"no redirect":        func() oauthprovider.TokenRequest { r := exchange(reg, code, opVerifier); r.RedirectURI = ""; return r }(),
			"unknown code":       exchange(reg, "uboc_nope", opVerifier),
			"plain verifier hit": exchange(reg, code, opChallenge(opVerifier)),
		} {
			if _, err := o.op.Token(anon(o.a), req); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		// The refusals left the code unspent; it still works once.
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, code, opVerifier)))
		if _, err := o.op.Token(anon(o.a), exchange(reg, code, opVerifier)); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("replayed code: %v", err)
		}
		if _, err := o.op.VerifyAccessToken(context.Background(), tok.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("a replayed code left its token alive: %v", err)
		}
		// A code issued without a challenge refuses a verifier (a stripped
		// challenge is never upgraded past), and works without one.
		conf := o.client(t, oauthprovider.ClientSpec{OptionalPKCE: true})
		noPKCE := authzReq(conf.ClientID)
		noPKCE.CodeChallenge, noPKCE.CodeChallengeMethod = "", ""
		plain := o.code(t, noPKCE)
		if _, err := o.op.Token(anon(o.a), exchange(conf, plain, opVerifier)); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("verifier for a code without a challenge: %v", err)
		}
		must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(conf, plain, "")))
		// An expired code is refused.
		late := o.code(t, authzReq(reg.ClientID))
		e.clock.Advance(oauthprovider.DefaultCodeTTL + time.Second)
		if _, err := o.op.Token(anon(o.a), exchange(reg, late, opVerifier)); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("expired code: %v", err)
		}
	})
}

// The redirect URI matches a registered one exactly, and a mismatch or an
// unknown client is never redirected to.
func TestOAuthProvider_RedirectURIExactMatch(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		reg := o.client(t, oauthprovider.ClientSpec{})
		for _, uri := range []string{opRedirect + "/", opRedirect + "?x=1", "https://CLIENT.example/cb", "https://client.example/cb/../cb", "https://evil.example/cb", "http://client.example/cb"} {
			in := authzReq(reg.ClientID)
			in.RedirectURI = uri
			_, err := o.op.Authorize(request(o.a, o.token), in)
			var re *oauthprovider.RedirectError
			if !errors.Is(err, oauthprovider.ErrBadRedirectTarget) || errors.As(err, &re) {
				t.Fatalf("%s: %v", uri, err)
			}
		}
		in := authzReq("oac_unknown")
		if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.Is(err, oauthprovider.ErrBadRedirectTarget) {
			t.Fatalf("unknown client: %v", err)
		}
		// Registration refuses what could never match safely.
		for _, uri := range []string{"https://client.example/cb#f", "http://client.example/cb", "javascript:alert(1)", "/relative", "https://user:pw@client.example/cb"} {
			if _, err := o.op.CreateClient(context.Background(), oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "x", RedirectURIs: []string{uri}}}); !errors.Is(err, oauthprovider.ErrInvalidRedirectURI) {
				t.Fatalf("registered %s: %v", uri, err)
			}
		}
		// A loopback and a private-use scheme are fine for native apps.
		if _, err := o.op.CreateClient(context.Background(), oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "x", RedirectURIs: []string{"http://127.0.0.1:8080/cb", "com.example.app:/cb"}, AuthMethod: oauthprovider.AuthMethodNone, ApplicationType: "native"}}); err != nil {
			t.Fatal(err)
		}
	})
}

// Client authentication: the secret is compared in constant time against
// its hash, the registered method is enforced, and public clients must use
// PKCE and cannot use client_credentials.
func TestOAuthProvider_ClientAuthentication(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "profile", "email", "offline_access", "api:read"))
		reg := o.client(t, oauthprovider.ClientSpec{ClientCredentialsScopes: []string{"api:read"}, ClientMetadata: oauthprovider.ClientMetadata{GrantTypes: []string{"authorization_code", "refresh_token", "client_credentials"}, Scope: "openid api:read"}})
		code := o.code(t, func() oauthprovider.AuthorizeRequest { r := authzReq(reg.ClientID); r.Scope = "openid"; return r }())
		for name, mutate := range map[string]func(*oauthprovider.TokenRequest){
			"wrong secret":   func(r *oauthprovider.TokenRequest) { r.ClientSecret += "x" },
			"no secret":      func(r *oauthprovider.TokenRequest) { r.ClientSecret = "" },
			"other method":   func(r *oauthprovider.TokenRequest) { r.ClientAuthMethod = oauthprovider.AuthMethodPost },
			"unknown client": func(r *oauthprovider.TokenRequest) { r.ClientID = "oac_unknown" },
		} {
			r := exchange(reg, code, opVerifier)
			mutate(&r)
			if _, err := o.op.Token(anon(o.a), r); !errors.Is(err, oauthprovider.ErrInvalidClient) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		// A disabled client fails authentication too.
		if err := o.op.SetClientDisabled(context.Background(), reg.ClientID, true); err != nil {
			t.Fatal(err)
		}
		if _, err := o.op.Token(anon(o.a), exchange(reg, code, opVerifier)); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("disabled client: %v", err)
		}
		if err := o.op.SetClientDisabled(context.Background(), reg.ClientID, false); err != nil {
			t.Fatal(err)
		}
		// client_credentials: no user scope, ever.
		cc := oauthprovider.TokenRequest{GrantType: "client_credentials", ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), cc))
		if tok.Scope != "api:read" || tok.RefreshToken != "" || tok.IDToken != "" {
			t.Fatalf("client credentials = %+v", tok)
		}
		cc.Scope = "openid"
		if _, err := o.op.Token(anon(o.a), cc); !errors.Is(err, oauthprovider.ErrInvalidScope) {
			t.Fatalf("user scope by client credentials: %v", err)
		}
		// A public client: PKCE is mandatory, client_credentials impossible.
		pub := o.client(t, oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{AuthMethod: oauthprovider.AuthMethodNone}, OptionalPKCE: true})
		if pub.Secret != "" || !pub.RequirePKCE {
			t.Fatalf("public client = %+v", pub)
		}
		in := authzReq(pub.ClientID)
		in.CodeChallenge, in.CodeChallengeMethod = "", ""
		_, err := o.op.Authorize(request(o.a, o.token), in)
		var re *oauthprovider.RedirectError
		if !errors.As(err, &re) || !errors.Is(err, oauthprovider.ErrInvalidRequest) || !strings.Contains(re.RedirectTo, "error=invalid_request") {
			t.Fatalf("public client without PKCE: %v", err)
		}
		in = authzReq(pub.ClientID)
		in.CodeChallengeMethod = "plain"
		if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("plain PKCE: %v", err)
		}
		if _, err := o.op.CreateClient(context.Background(), oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "p", RedirectURIs: []string{opRedirect}, AuthMethod: oauthprovider.AuthMethodNone, GrantTypes: []string{"client_credentials"}}}); !errors.Is(err, oauthprovider.ErrInvalidClientMetadata) {
			t.Fatalf("public client_credentials client: %v", err)
		}
		pcode := o.code(t, authzReq(pub.ClientID))
		ptok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "authorization_code", Code: pcode, RedirectURI: opRedirect, CodeVerifier: opVerifier, ClientID: pub.ClientID, ClientAuthMethod: oauthprovider.AuthMethodNone}))
		if ptok.AccessToken == "" {
			t.Fatal("public client got no token")
		}
		// A public client cannot introspect: it holds no secret.
		if _, err := o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: ptok.AccessToken, ClientID: pub.ClientID, ClientAuthMethod: oauthprovider.AuthMethodNone}); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("public introspection: %v", err)
		}
		// Another confidential client sees the token as inactive.
		other := o.client(t, oauthprovider.ClientSpec{})
		if in, err := o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: ptok.AccessToken, ClientID: other.ClientID, ClientSecret: other.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}); err != nil || in.Active {
			t.Fatalf("other client's introspection = %+v %v", in, err)
		}
		rs := o.client(t, oauthprovider.ClientSpec{IntrospectAny: true})
		if in, err := o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: ptok.AccessToken, ClientID: rs.ClientID, ClientSecret: rs.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}); err != nil || !in.Active {
			t.Fatalf("resource server introspection = %+v %v", in, err)
		}
	})
}

// Every secret is stored as its SHA-256: the raw value is nowhere in the
// tables.
func TestOAuthProvider_HashedAtRest(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		reg := o.client(t, oauthprovider.ClientSpec{})
		code := o.code(t, authzReq(reg.ClientID))
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, code, opVerifier)))
		count := func(tbl sqlb.Table, col sqlb.Expr[[]byte], v []byte) int64 {
			var n int64
			if err := o.a.One(context.Background(), o.a.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(tbl).Where(sqlb.Eq(col, v))); err != nil {
				t.Fatal(err)
			}
			return n
		}
		for _, c := range []struct {
			tbl sqlb.Table
			col sqlb.Expr[[]byte]
			raw string
		}{
			{oauthprovider.TableClient, oauthprovider.ClientSecret, reg.Secret},
			{oauthprovider.TableCode, oauthprovider.CodeHash, code},
			{oauthprovider.TableToken, oauthprovider.TokenAccessHash, tok.AccessToken},
			{oauthprovider.TableToken, oauthprovider.TokenRefresh, tok.RefreshToken},
		} {
			if count(c.tbl, c.col, []byte(c.raw)) != 0 || count(c.tbl, c.col, auth.HashToken(auth.Token(c.raw))) != 1 {
				t.Fatalf("%s.%s is not stored as a hash", c.tbl.Name, c.raw[:5])
			}
		}
	})
}

// Sign-in, prompt and consent: a signed-out browser goes to the login page
// with the request; prompt=none never shows a page; a denial reaches the
// client; a withdrawn consent revokes the client's tokens.
func TestOAuthProvider_LoginPromptAndConsent(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		reg := o.client(t, oauthprovider.ClientSpec{})
		res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(anon(o.a), authzReq(reg.ClientID)))
		u := must[*url.URL](t)(url.Parse(res.RedirectTo))
		if u.Path != "/login" || u.Query().Get("client_id") != reg.ClientID {
			t.Fatalf("signed out = %s", res.RedirectTo)
		}
		if resume := o.op.ResumeURL(u.Query()); !strings.HasPrefix(resume, testBaseURL+"/oauth2/authorize?") {
			t.Fatalf("resume = %s", resume)
		}
		none := authzReq(reg.ClientID)
		none.Prompt = "none"
		if _, err := o.op.Authorize(anon(o.a), none); !errors.Is(err, oauthprovider.ErrLoginRequired) {
			t.Fatalf("prompt=none signed out: %v", err)
		}
		if _, err := o.op.Authorize(request(o.a, o.token), none); !errors.Is(err, oauthprovider.ErrConsentRequired) {
			t.Fatalf("prompt=none without consent: %v", err)
		}
		// prompt=login sends a signed-in user to the login page, without the
		// prompt, so the page cannot loop.
		login := authzReq(reg.ClientID)
		login.Prompt = "login"
		res = must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), login))
		if !strings.HasPrefix(res.RedirectTo, "/login?") || strings.Contains(res.RedirectTo, "prompt=") {
			t.Fatalf("prompt=login = %s", res.RedirectTo)
		}
		// Deny.
		// The consent page gets the signed query; it posts it back unchanged.
		ask := authzReq(reg.ClientID)
		ask.State = "s"
		page := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), ask))
		q := must[*url.URL](t)(url.Parse(page.RedirectTo)).Query()
		if q.Get("sig") == "" || q.Get("exp") == "" {
			t.Fatalf("consent page query is not signed: %s", page.RedirectTo)
		}
		tampered := url.Values{}
		for k, v := range q {
			tampered[k] = v
		}
		tampered.Set("scope", "openid profile email offline_access admin")
		if _, err := o.op.Consent(request(o.a, o.token), oauthprovider.ConsentRequest{Query: tampered.Encode(), Accept: true}); !errors.Is(err, oauthprovider.ErrInvalidSignature) {
			t.Fatalf("tampered query: %v", err)
		}
		unsigned := url.Values{"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {opRedirect}, "scope": {opScopes}}
		if _, err := o.op.Consent(request(o.a, o.token), oauthprovider.ConsentRequest{Query: unsigned.Encode(), Accept: true}); !errors.Is(err, oauthprovider.ErrInvalidSignature) {
			t.Fatalf("unsigned query: %v", err)
		}
		res = must[oauthprovider.AuthorizeResult](t)(o.op.Consent(request(o.a, o.token), oauthprovider.ConsentRequest{Query: q.Encode()}))
		if !strings.HasPrefix(res.RedirectTo, opRedirect+"?") || !strings.Contains(res.RedirectTo, "error=access_denied") || !strings.Contains(res.RedirectTo, "state=s") {
			t.Fatalf("deny = %s", res.RedirectTo)
		}
		// Grant a narrower set; a scope outside the request is refused.
		if _, err := o.op.Consent(request(o.a, o.token), oauthprovider.ConsentRequest{Query: q.Encode(), Accept: true, Scope: "openid admin"}); !errors.Is(err, oauthprovider.ErrInvalidScope) {
			t.Fatalf("widened consent: %v", err)
		}
		res = must[oauthprovider.AuthorizeResult](t)(o.op.Consent(request(o.a, o.token), oauthprovider.ConsentRequest{Query: q.Encode(), Accept: true, Scope: "openid"}))
		code := must[*url.URL](t)(url.Parse(res.RedirectTo)).Query().Get("code")
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, code, opVerifier)))
		if tok.Scope != "openid" || tok.RefreshToken != "" {
			t.Fatalf("narrowed = %+v", tok)
		}
		// The consent page needs a session, and only its owner sees it.
		if _, err := o.op.Consent(anon(o.a), oauthprovider.ConsentRequest{Query: q.Encode(), Accept: true}); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("consent signed out: %v", err)
		}
		list := must[oauthprovider.ConsentList](t)(o.op.Consents(request(o.a, o.token)))
		if len(list.Consents) != 1 || list.Consents[0].ClientID != reg.ClientID || list.Consents[0].ClientName != "Client" {
			t.Fatalf("consents = %+v", list)
		}
		if err := o.op.RevokeConsent(request(o.a, o.token), reg.ClientID); err != nil {
			t.Fatal(err)
		}
		if _, err := o.op.VerifyAccessToken(context.Background(), tok.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("withdrawn consent left the token alive: %v", err)
		}
		// A first-party client never asks.
		fp := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		res = must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), authzReq(fp.ClientID)))
		if !strings.HasPrefix(res.RedirectTo, opRedirect+"?code=") {
			t.Fatalf("first party = %s", res.RedirectTo)
		}
	})
}

// The owner's registry: a user manages their own clients only; rotation
// kills the old secret; registration is closed unless opened.
func TestOAuthProvider_OwnerRegistry(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		ctx := request(o.a, o.token)
		meta := oauthprovider.ClientMetadata{Name: "Mine", RedirectURIs: []string{opRedirect}}
		reg := must[oauthprovider.Registration](t)(o.op.CreateOwnedClient(ctx, meta))
		if reg.OwnerID != o.user.ID || reg.SkipConsent {
			t.Fatalf("owned = %+v", reg)
		}
		if list := must[oauthprovider.ClientList](t)(o.op.Clients(ctx)); len(list.Clients) != 1 {
			t.Fatalf("list = %+v", list)
		}
		other := o.client(t, oauthprovider.ClientSpec{})
		if _, err := o.op.OwnedClient(ctx, other.ClientID); !errors.Is(err, oauthprovider.ErrClientNotFound) {
			t.Fatalf("someone else's client: %v", err)
		}
		if err := o.op.DeleteOwnedClient(ctx, other.ClientID); !errors.Is(err, oauthprovider.ErrClientNotFound) {
			t.Fatalf("deleted someone else's client: %v", err)
		}
		rot := must[oauthprovider.Registration](t)(o.op.RotateSecret(ctx, reg.ClientID))
		cc := oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: "ubor_x", ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
		if _, err := o.op.Token(anon(o.a), cc); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("old secret after rotation: %v", err)
		}
		cc.ClientSecret = rot.Secret
		if _, err := o.op.Token(anon(o.a), cc); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("new secret: %v", err)
		}
		up := must[oauthprovider.Client](t)(o.op.UpdateOwnedClient(ctx, oauthprovider.UpdateClientRequest{ClientID: reg.ClientID, Metadata: oauthprovider.ClientMetadata{Name: "Renamed", RedirectURIs: []string{opRedirect}}}))
		if up.Name != "Renamed" {
			t.Fatalf("updated = %+v", up)
		}
		if _, err := o.op.UpdateOwnedClient(ctx, oauthprovider.UpdateClientRequest{ClientID: reg.ClientID, Metadata: oauthprovider.ClientMetadata{Name: "x", RedirectURIs: []string{opRedirect}, AuthMethod: oauthprovider.AuthMethodNone}}); !errors.Is(err, oauthprovider.ErrInvalidClientMetadata) {
			t.Fatalf("auth method changed: %v", err)
		}
		if err := o.op.DeleteOwnedClient(ctx, reg.ClientID); err != nil {
			t.Fatal(err)
		}
		if _, err := o.op.Register(anon(o.a), meta); !errors.Is(err, oauthprovider.ErrRegistrationClosed) {
			t.Fatalf("registration closed by default: %v", err)
		}
	})
}

func TestOAuthProvider_DynamicRegistration(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.AllowDynamicRegistration())
		meta := oauthprovider.ClientMetadata{Name: "MCP", RedirectURIs: []string{"http://127.0.0.1:3000/cb"}, AuthMethod: oauthprovider.AuthMethodNone, ApplicationType: "native"}
		if _, err := o.op.Register(anon(o.a), meta); !errors.Is(err, oauthprovider.ErrRegistrationClosed) {
			t.Fatalf("anonymous registration without the option: %v", err)
		}
		withToken := meta
		withToken.InitialAccessToken = "anything"
		if _, err := o.op.Register(anon(o.a), withToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("initial access token without a validator: %v", err)
		}
		if reg := must[oauthprovider.Registration](t)(o.op.Register(request(o.a, o.token), meta)); reg.OwnerID != o.user.ID {
			t.Fatalf("signed-in registration = %+v", reg)
		}
	})
}

func TestOAuthProvider_AnonymousRegistration(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		meta := oauthprovider.ClientMetadata{Name: "MCP", RedirectURIs: []string{"http://127.0.0.1:3000/cb"}, AuthMethod: oauthprovider.AuthMethodNone, ApplicationType: "native"}
		o2 := newOPEnv(t, e, oauthprovider.AllowUnauthenticatedRegistration())
		if reg := must[oauthprovider.Registration](t)(o2.op.Register(anon(o2.a), meta)); reg.OwnerID != "" || reg.ClientIDIssuedAt == 0 {
			t.Fatalf("anonymous registration = %+v", reg)
		}
	})
}

// The HTTP surface: discovery, keys, the token endpoint's form and Basic
// authentication, RFC 6749 error bodies, and userinfo with a bearer token.
func TestOAuthProvider_HTTP(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		reg := o.client(t, oauthprovider.ClientSpec{})
		srv := httptest.NewServer(o.op.Handler())
		t.Cleanup(srv.Close)
		get := func(path string, hdr http.Header) (*http.Response, map[string]any) {
			req := must[*http.Request](t)(http.NewRequest(http.MethodGet, srv.URL+path, nil))
			for k, v := range hdr {
				req.Header[k] = v
			}
			res := must[*http.Response](t)(http.DefaultClient.Do(req))
			defer res.Body.Close()
			var body map[string]any
			_ = json.NewDecoder(res.Body).Decode(&body)
			return res, body
		}
		post := func(path string, form url.Values, hdr http.Header) (*http.Response, map[string]any) {
			req := must[*http.Request](t)(http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(form.Encode())))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for k, v := range hdr {
				req.Header[k] = v
			}
			res := must[*http.Response](t)(http.DefaultClient.Do(req))
			defer res.Body.Close()
			var body map[string]any
			_ = json.NewDecoder(res.Body).Decode(&body)
			return res, body
		}
		res, doc := get("/.well-known/openid-configuration", nil)
		if res.StatusCode != 200 || doc["issuer"] != testBaseURL || doc["token_endpoint"] != testBaseURL+"/oauth2/token" || doc["registration_endpoint"] != nil {
			t.Fatalf("discovery = %d %v", res.StatusCode, doc)
		}
		if res.Header.Get("Cache-Control") != "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400" || len(doc["introspection_endpoint_auth_methods_supported"].([]any)) != 3 {
			t.Fatalf("discovery headers = %v %v", res.Header, doc["introspection_endpoint_auth_methods_supported"])
		}
		if res, doc := get("/.well-known/oauth-authorization-server", nil); res.StatusCode != 200 || doc["issuer"] != testBaseURL {
			t.Fatalf("RFC 8414 = %d %v", res.StatusCode, doc)
		}
		if res, keys := get("/oauth2/jwks", nil); res.StatusCode != 200 || len(keys["keys"].([]any)) != 1 {
			t.Fatalf("jwks = %d %v", res.StatusCode, keys)
		}
		basic := http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(reg.ClientID)+":"+url.QueryEscape(reg.Secret)))}}
		form := url.Values{"grant_type": {"authorization_code"}, "code": {o.code(t, authzReq(reg.ClientID))}, "redirect_uri": {opRedirect}, "code_verifier": {opVerifier}}
		// A repeated parameter is refused before anything is spent.
		dup := url.Values{}
		for k, v := range form {
			dup[k] = append([]string{}, v...)
		}
		dup.Add("code", "again")
		if res, body := post("/oauth2/token", dup, basic); res.StatusCode != 400 || body["error"] != "invalid_request" {
			t.Fatalf("repeated parameter = %d %v", res.StatusCode, body)
		}
		// Two client authentication methods at once.
		both := url.Values{"client_secret": {reg.Secret}}
		for k, v := range form {
			both[k] = v
		}
		if res, body := post("/oauth2/token", both, basic); res.StatusCode != 400 || body["error"] != "invalid_request" {
			t.Fatalf("two methods = %d %v", res.StatusCode, body)
		}
		// A wrong secret is 401 with a Basic challenge.
		bad := http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(reg.ClientID+":nope"))}}
		if res, body := post("/oauth2/token", form, bad); res.StatusCode != 401 || body["error"] != "invalid_client" || !strings.HasPrefix(res.Header.Get("WWW-Authenticate"), "Basic") {
			t.Fatalf("wrong secret = %d %v %v", res.StatusCode, body, res.Header)
		}
		// A browser session riding along is ignored: no CSRF refusal.
		withCookie := http.Header{"Authorization": basic["Authorization"], "Cookie": {"__Host-auth_session=" + o.token.Reveal()}, "Origin": {"https://spa.example"}}
		res, tok := post("/oauth2/token", form, withCookie)
		if res.StatusCode != 200 || tok["token_type"] != "Bearer" || res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("token = %d %v", res.StatusCode, tok)
		}
		if res, body := post("/oauth2/token", form, basic); res.StatusCode != 400 || body["error"] != "invalid_grant" {
			t.Fatalf("replay = %d %v", res.StatusCode, body)
		}
		// Userinfo with the (now revoked by the replay) token, then a fresh one.
		if res, body := get("/oauth2/userinfo", http.Header{"Authorization": {"Bearer " + tok["access_token"].(string)}}); res.StatusCode != 401 || body["error"] != "invalid_token" || !strings.Contains(res.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
			t.Fatalf("revoked userinfo = %d %v", res.StatusCode, body)
		}
		form.Set("code", o.code(t, authzReq(reg.ClientID)))
		_, tok = post("/oauth2/token", form, basic)
		if res, body := get("/oauth2/userinfo", http.Header{"Authorization": {"Bearer " + tok["access_token"].(string)}}); res.StatusCode != 200 || body["sub"] != o.user.ID {
			t.Fatalf("userinfo = %d %v", res.StatusCode, body)
		}
		if res, body := post("/oauth2/introspect", url.Values{"token": {tok["access_token"].(string)}}, basic); res.StatusCode != 200 || body["active"] != true {
			t.Fatalf("introspect = %d %v", res.StatusCode, body)
		}
		if res, _ := post("/oauth2/revoke", url.Values{"token": {tok["refresh_token"].(string)}, "token_type_hint": {"refresh_token"}}, basic); res.StatusCode != 200 {
			t.Fatalf("revoke = %d", res.StatusCode)
		}
		if _, body := post("/oauth2/introspect", url.Values{"token": {tok["access_token"].(string)}}, basic); body["active"] != false {
			t.Fatalf("after revoking the family = %v", body)
		}
		if res, _ := get("/oauth2/token", nil); res.StatusCode != 405 {
			t.Fatalf("GET token = %d", res.StatusCode)
		}
		// Authorize: a bad target is a page error, never a redirect.
		noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		r1 := must[*http.Response](t)(noRedirect.Get(srv.URL + "/oauth2/authorize?response_type=code&client_id=" + reg.ClientID + "&redirect_uri=https://evil.example/cb"))
		r1.Body.Close()
		if r1.StatusCode != 400 || r1.Header.Get("Location") != "" {
			t.Fatalf("bad target = %d %s", r1.StatusCode, r1.Header.Get("Location"))
		}
		r2 := must[*http.Response](t)(noRedirect.Get(srv.URL + "/oauth2/authorize?response_type=token&client_id=" + reg.ClientID + "&redirect_uri=" + url.QueryEscape(opRedirect) + "&state=z"))
		r2.Body.Close()
		if r2.StatusCode != 302 || !strings.Contains(r2.Header.Get("Location"), "error=unsupported_response_type") {
			t.Fatalf("implicit = %d %s", r2.StatusCode, r2.Header.Get("Location"))
		}
	})
}

// An MCP server: RFC 9728 metadata names the provider, and RequireToken
// answers the challenges an MCP client follows.
func TestOAuthProvider_ProtectedResource(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const mcpURL = "https://mcp.example.com/mcp"
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "profile", "email", "offline_access", "mcp:tools", "mcp:admin"), oauthprovider.ProtectedResource(mcpURL, "openid", "mcp:tools", "mcp:admin"), oauthprovider.RegistrationDefaultResources(mcpURL))
		srv := httptest.NewServer(o.op.Handler())
		t.Cleanup(srv.Close)
		res := must[*http.Response](t)(http.Get(srv.URL + "/.well-known/oauth-protected-resource/mcp"))
		var doc map[string]any
		_ = json.NewDecoder(res.Body).Decode(&doc)
		res.Body.Close()
		if res.StatusCode != 200 || doc["resource"] != mcpURL || doc["authorization_servers"].([]any)[0] != testBaseURL || len(doc["scopes_supported"].([]any)) != 2 || doc["dpop_signing_alg_values_supported"] == nil {
			t.Fatalf("resource metadata = %d %v", res.StatusCode, doc)
		}
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		in := authzReq(reg.ClientID)
		in.Scope = "openid mcp:tools"
		in.Resource = mcpURL
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, in), opVerifier)))

		mcp := httptest.NewServer(o.op.RequireToken(oauthprovider.RequireOptions{Resource: mcpURL, Scopes: []string{"mcp:tools"}, JSONRPC: true})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			at, ok := oauthprovider.TokenFrom(r.Context())
			if !ok || at.UserID != o.user.ID {
				t.Errorf("token in context = %+v %v", at, ok)
			}
			w.WriteHeader(http.StatusNoContent)
		})))
		t.Cleanup(mcp.Close)
		admin := httptest.NewServer(o.op.RequireToken(oauthprovider.RequireOptions{Resource: mcpURL, Scopes: []string{"mcp:tools", "mcp:admin"}})(http.NotFoundHandler()))
		t.Cleanup(admin.Close)
		call := func(url, token string) (*http.Response, string) {
			req := must[*http.Request](t)(http.NewRequest(http.MethodPost, url, nil))
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			res := must[*http.Response](t)(http.DefaultClient.Do(req))
			defer res.Body.Close()
			var b strings.Builder
			_, _ = io.Copy(&b, res.Body)
			return res, b.String()
		}
		meta := `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"`
		if res, body := call(mcp.URL, ""); res.StatusCode != 401 || res.Header.Get("WWW-Authenticate") != `Bearer scope="mcp:tools", `+meta || !strings.Contains(body, `"code":-32000`) || !strings.Contains(body, `"id":null`) {
			t.Fatalf("no token = %d %q %s", res.StatusCode, res.Header.Get("WWW-Authenticate"), body)
		}
		if res, _ := call(mcp.URL, "uboa_forged"); res.StatusCode != 401 || !strings.HasPrefix(res.Header.Get("WWW-Authenticate"), `Bearer error="invalid_token"`) {
			t.Fatalf("forged token = %d %q", res.StatusCode, res.Header.Get("WWW-Authenticate"))
		}
		if res, body := call(admin.URL, tok.AccessToken); res.StatusCode != 403 || res.Header.Get("WWW-Authenticate") != `Bearer error="insufficient_scope", scope="mcp:admin", `+meta || !strings.Contains(body, `"insufficient_scope"`) {
			t.Fatalf("missing scope = %d %q %s", res.StatusCode, res.Header.Get("WWW-Authenticate"), body)
		}
		// A token for no resource is not this server's.
		unbound := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		if res, _ := call(mcp.URL, unbound.AccessToken); res.StatusCode != 401 {
			t.Fatalf("token without the resource = %d", res.StatusCode)
		}
		if res, _ := call(mcp.URL, tok.AccessToken); res.StatusCode != 204 {
			t.Fatalf("granted = %d", res.StatusCode)
		}
	})
}
