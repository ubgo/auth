package integration

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
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

// selfSigned makes a client certificate for the mutual-TLS method.
func selfSigned(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	k := must[*ecdsa.PrivateKey](t)(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der := must[[]byte](t)(x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k))
	return must[*x509.Certificate](t)(x509.ParseCertificate(der))
}

// pageQuery is the signed query a gate's page received.
func pageQuery(t *testing.T, res oauthprovider.AuthorizeResult, path string) string {
	t.Helper()
	u := must[*url.URL](t)(url.Parse(res.RedirectTo))
	if u.Path != path {
		t.Fatalf("redirect = %s, want %s", res.RedirectTo, path)
	}
	return u.RawQuery
}

// The select-account, sign-up and post-login gates send a signed-in user
// to their pages, Continue resumes past each, the consent page carries the
// session's post-login marker, and the post-login reference ties consent
// and tokens.
func TestOAuthProvider_GatesAndContinue(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ref, onboard, pick := "org_1", true, false
		o := newOPEnv(t, e,
			oauthprovider.SelectAccount(oauthprovider.SelectAccountGate{Page: "/select", ShouldRedirect: func(context.Context, oauthprovider.GateInfo) bool { return pick }}),
			oauthprovider.SignupRedirect(func(context.Context, oauthprovider.GateInfo) (bool, string) { return onboard, "/onboard" }),
			oauthprovider.PostLogin(oauthprovider.PostLoginGate{Page: "/org",
				ShouldRedirect:     func(context.Context, oauthprovider.GateInfo) bool { return true },
				ConsentReferenceID: func(context.Context, oauthprovider.GateInfo) string { return ref }}))
		reg := o.client(t, oauthprovider.ClientSpec{})
		ctx := request(o.a, o.token)
		in := authzReq(reg.ClientID)
		in.Prompt = "select_account"
		q := pageQuery(t, must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(ctx, in)), "/select")
		q = pageQuery(t, must[oauthprovider.AuthorizeResult](t)(o.op.Continue(ctx, oauthprovider.ContinueRequest{Query: q, Selected: true})), "/onboard")
		q = pageQuery(t, must[oauthprovider.AuthorizeResult](t)(o.op.Continue(ctx, oauthprovider.ContinueRequest{Query: q, Created: true})), "/org")
		// The post-login page's own query cannot skip to consent.
		if _, err := o.op.Consent(ctx, oauthprovider.ConsentRequest{Query: q, Accept: true}); !errors.Is(err, oauthprovider.ErrInvalidSignature) {
			t.Fatalf("consent before the post-login gate: %v", err)
		}
		if _, err := o.op.Continue(ctx, oauthprovider.ContinueRequest{Query: q}); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("continue past nothing: %v", err)
		}
		if _, err := o.op.Continue(ctx, oauthprovider.ContinueRequest{Query: q + "&scope=admin", PostLogin: true}); !errors.Is(err, oauthprovider.ErrInvalidSignature) {
			t.Fatalf("continue with a tampered query: %v", err)
		}
		onboard = false
		cq := pageQuery(t, must[oauthprovider.AuthorizeResult](t)(o.op.Continue(ctx, oauthprovider.ContinueRequest{Query: q, PostLogin: true})), "/consent")
		// The marker is this session's: another user's session is refused.
		bob := must[password.SignInResult](t)(o.pw.SignUp(anon(o.a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret}))
		if _, err := o.op.Consent(request(o.a, bob.Token), oauthprovider.ConsentRequest{Query: cq, Accept: true}); !errors.Is(err, oauthprovider.ErrInvalidSignature) {
			t.Fatalf("marker of another session: %v", err)
		}
		res := must[oauthprovider.AuthorizeResult](t)(o.op.Consent(ctx, oauthprovider.ConsentRequest{Query: cq, Accept: true}))
		code := must[*url.URL](t)(url.Parse(res.RedirectTo)).Query().Get("code")
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, code, opVerifier)))
		at := must[oauthprovider.AccessToken](t)(o.op.VerifyAccessToken(context.Background(), tok.AccessToken))
		if at.ReferenceID != "org_1" {
			t.Fatalf("token reference = %+v", at)
		}
		refreshed := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: tok.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		if at := must[oauthprovider.AccessToken](t)(o.op.VerifyAccessToken(context.Background(), refreshed.AccessToken)); at.ReferenceID != "org_1" {
			t.Fatalf("refreshed reference = %+v", at)
		}
		// Same reference: the consent covers it, so the post-login gate leads
		// straight to the code. Another reference asks again.
		q = pageQuery(t, must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(ctx, authzReq(reg.ClientID))), "/org")
		res = must[oauthprovider.AuthorizeResult](t)(o.op.Continue(ctx, oauthprovider.ContinueRequest{Query: q, PostLogin: true}))
		if !strings.HasPrefix(res.RedirectTo, opRedirect) {
			t.Fatalf("consented reference = %s", res.RedirectTo)
		}
		ref = "org_2"
		pageQuery(t, must[oauthprovider.AuthorizeResult](t)(o.op.Continue(ctx, oauthprovider.ContinueRequest{Query: q, PostLogin: true})), "/consent")
		// prompt=none cannot show a gate.
		none := authzReq(reg.ClientID)
		none.Prompt = "none"
		var re *oauthprovider.RedirectError
		if _, err := o.op.Authorize(ctx, none); !errors.As(err, &re) || !strings.Contains(re.RedirectTo, "error=interaction_required") {
			t.Fatalf("prompt=none at a gate: %v", err)
		}
		pick = true
		if _, err := o.op.Authorize(ctx, none); !errors.As(err, &re) || !strings.Contains(re.RedirectTo, "error=account_selection_required") {
			t.Fatalf("prompt=none at the picker: %v", err)
		}
	})
}

// Extensions add discovery members, claims, a client authentication
// method and client discovery, each additive; a mutual-TLS method binds
// tokens to the certificate (cnf x5t#S256).
func TestOAuthProvider_Extensions(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const api = "https://api.example.com/x"
		thumbs := map[string]string{}
		name := "Static"
		mtls := oauthprovider.ClientAuthMethod{Method: "tls_client_auth", Authenticate: func(_ context.Context, c oauthprovider.Client, cred oauthprovider.ClientCredentials) (*oauthprovider.Confirmation, error) {
			if len(cred.Certificates) == 0 || oauthprovider.CertificateThumbprint(cred.Certificates[0]) != thumbs[c.ClientID] {
				return nil, errors.New("no certificate")
			}
			return &oauthprovider.Confirmation{X5TS256: thumbs[c.ClientID]}, nil
		}}
		attest := oauthprovider.ClientAuthMethod{Method: "attest", AssertionTypes: []string{"urn:example:attest"}, Authenticate: func(_ context.Context, _ oauthprovider.Client, cred oauthprovider.ClientCredentials) (*oauthprovider.Confirmation, error) {
			if cred.Assertion != "good" || cred.AssertionType != "urn:example:attest" {
				return nil, errors.New("bad attestation")
			}
			return nil, nil
		}}
		static := oauthprovider.ClientDiscoverer{ID: "static", Refresh: time.Hour, Matches: func(id string) bool { return strings.HasPrefix(id, "static:") },
			Resolve: func(_ context.Context, id string) (oauthprovider.ClientMetadata, error) {
				if id == "static:bad" {
					return oauthprovider.ClientMetadata{}, errors.New("unknown")
				}
				return oauthprovider.ClientMetadata{Name: name, RedirectURIs: []string{opRedirect}, AuthMethod: oauthprovider.AuthMethodNone}, nil
			}}
		first := oauthprovider.Extension{ID: "first", Metadata: map[string]any{"x_feature": "first", "issuer": "https://evil.example"},
			ClientAuthentication: []oauthprovider.ClientAuthMethod{mtls, attest}, ClientDiscovery: []oauthprovider.ClientDiscoverer{static},
			Claims: oauthprovider.ExtensionClaims{
				AccessToken: func(context.Context, oauthprovider.AccessTokenClaimsInfo) map[string]any {
					return map[string]any{"tenant": "ext", "plan": "ext", "iss": "https://evil.example", "cnf": "forged"}
				},
				IDToken: func(context.Context, oauthprovider.ClaimsInfo) map[string]any {
					return map[string]any{"team": "blue", "email": "evil@example.com", "sid": "forged"}
				},
				UserInfo: func(context.Context, oauthprovider.ClaimsInfo) map[string]any {
					return map[string]any{"team": "blue", "email": "evil@example.com"}
				},
			}}
		second := oauthprovider.Extension{ID: "second", Metadata: map[string]any{"x_feature": "second"},
			Claims: oauthprovider.ExtensionClaims{AccessToken: func(context.Context, oauthprovider.AccessTokenClaimsInfo) map[string]any {
				return map[string]any{"tenant": "second"}
			}}}
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "profile", "email", "offline_access", "api:read"), oauthprovider.Extend(first, second),
			oauthprovider.AccessTokenClaims(func(context.Context, oauthprovider.AccessTokenClaimsInfo) map[string]any {
				return map[string]any{"plan": "option"}
			}))
		ctx := context.Background()
		doc := must[[]byte](t)(json.Marshal(o.op.Metadata()))
		var m map[string]any
		_ = json.Unmarshal(doc, &m)
		if m["x_feature"] != "first" || m["issuer"] != testBaseURL || !strings.Contains(string(doc), `"tls_client_auth"`) {
			t.Fatalf("metadata = %s", doc)
		}
		// Mutual TLS: no secret is issued, the certificate authenticates and
		// binds the tokens.
		reg := must[oauthprovider.Registration](t)(o.op.CreateClient(ctx, oauthprovider.ClientSpec{ClientCredentialsScopes: []string{"api:read"},
			ClientMetadata: oauthprovider.ClientMetadata{Name: "M", AuthMethod: "tls_client_auth", GrantTypes: []string{"client_credentials"}}}))
		cert, other := selfSigned(t, "m"), selfSigned(t, "other")
		thumbs[reg.ClientID] = oauthprovider.CertificateThumbprint(cert)
		if reg.Secret != "" {
			t.Fatalf("an mTLS client got a secret")
		}
		must[oauthprovider.Resource](t)(o.op.CreateResource(ctx, oauthprovider.Resource{Identifier: api, CustomClaims: map[string]any{"plan": "resource"}}))
		must[bool](t)(o.op.LinkClient(ctx, api, reg.ClientID))
		cc := oauthprovider.TokenRequest{GrantType: "client_credentials", ClientID: reg.ClientID, ClientAuthMethod: oauthprovider.AuthMethodNone, Resource: api}
		if _, err := o.op.Token(anon(o.a), cc); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("no certificate: %v", err)
		}
		cc.ClientCertificates = []*x509.Certificate{other}
		if _, err := o.op.Token(anon(o.a), cc); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("another certificate: %v", err)
		}
		cc.ClientCertificates, cc.ClientSecret = []*x509.Certificate{cert}, "s"
		if _, err := o.op.Token(anon(o.a), cc); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("a secret with mTLS: %v", err)
		}
		cc.ClientSecret = ""
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), cc))
		if tok.TokenType != "Bearer" {
			t.Fatalf("token type = %q", tok.TokenType)
		}
		var claims map[string]any
		_ = json.Unmarshal(must[[]byte](t)(base64.RawURLEncoding.DecodeString(strings.Split(tok.AccessToken, ".")[1])), &claims)
		cnf, _ := claims["cnf"].(map[string]any)
		if cnf["x5t#S256"] != thumbs[reg.ClientID] || claims["iss"] != testBaseURL || claims["tenant"] != "ext" || claims["plan"] != "resource" {
			t.Fatalf("claims = %v", claims)
		}
		pt := oauthprovider.PresentedToken{Scheme: "Bearer", Token: tok.AccessToken, Certificate: cert}
		must[oauthprovider.AccessToken](t)(o.op.VerifyPresentedToken(ctx, pt))
		for _, c := range []*x509.Certificate{nil, other} {
			pt.Certificate = c
			if _, err := o.op.VerifyPresentedToken(ctx, pt); !errors.Is(err, oauthprovider.ErrInvalidToken) {
				t.Fatalf("bound token with certificate %v: %v", c, err)
			}
		}
		// An assertion of an extension's type authenticates its client only.
		at := must[oauthprovider.Registration](t)(o.op.CreateClient(ctx, oauthprovider.ClientSpec{ClientCredentialsScopes: []string{"api:read"},
			ClientMetadata: oauthprovider.ClientMetadata{Name: "A", AuthMethod: "attest", GrantTypes: []string{"client_credentials"}}}))
		ac := oauthprovider.TokenRequest{GrantType: "client_credentials", ClientID: at.ClientID, ClientAuthMethod: "attest", ClientAssertion: "bad", ClientAssertionType: "urn:example:attest"}
		if _, err := o.op.Token(anon(o.a), ac); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("bad attestation: %v", err)
		}
		ac.ClientAssertion = "good"
		must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), ac))
		ac.ClientID = reg.ClientID
		if _, err := o.op.Token(anon(o.a), ac); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("attestation for the mTLS client: %v", err)
		}
		// Extension ID token and userinfo claims are added, never replacing a
		// scope's claim or a reserved one.
		noEmail := authzReq("static:app")
		noEmail.Scope = "openid profile"
		code := o.code(t, noEmail)
		pub := oauthprovider.Registration{Client: oauthprovider.Client{ClientID: "static:app"}}
		ex := exchange(pub, code, opVerifier)
		ex.ClientAuthMethod = oauthprovider.AuthMethodNone
		ut := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), ex))
		var idc map[string]any
		_ = json.Unmarshal(must[[]byte](t)(base64.RawURLEncoding.DecodeString(strings.Split(ut.IDToken, ".")[1])), &idc)
		if _, email := idc["email"]; idc["team"] != "blue" || email || idc["sid"] == "forged" {
			t.Fatalf("id token claims = %v", idc)
		}
		info := must[map[string]any](t)(o.op.UserInfo(anon(o.a), ut.AccessToken))
		if _, email := info["email"]; info["team"] != "blue" || email {
			t.Fatalf("userinfo = %v", info)
		}
		// Discovery: an unresolvable client is unknown; a resolved one is
		// stored and resolved again after Refresh.
		if _, err := o.op.Authorize(request(o.a, o.token), authzReq("static:bad")); !errors.Is(err, oauthprovider.ErrBadRedirectTarget) {
			t.Fatalf("unresolvable client: %v", err)
		}
		name = "Renamed"
		if c := must[oauthprovider.Client](t)(o.op.Client(ctx, "static:app")); c.Name != "Static" {
			t.Fatalf("before refresh = %q", c.Name)
		}
		e.clock.Advance(2 * time.Hour)
		o.code(t, authzReq("static:app"))
		if c := must[oauthprovider.Client](t)(o.op.Client(ctx, "static:app")); c.Name != "Renamed" {
			t.Fatalf("after refresh = %q", c.Name)
		}
	})
}

// FormatRefreshToken encodes refresh tokens on the wire; refresh,
// introspection and revocation decode them, and a token the format
// refuses is unknown.
func TestOAuthProvider_RefreshTokenFormat(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var sessions []string
		o := newOPEnv(t, e, oauthprovider.FormatRefreshToken(oauthprovider.RefreshTokenFormat{
			Encode: func(_ context.Context, tok, sid string) (string, error) {
				sessions = append(sessions, sid)
				return base64.RawURLEncoding.EncodeToString([]byte(tok + "|" + sid)), nil
			},
			Decode: func(_ context.Context, enc string) (string, error) {
				inner, tampered := strings.CutSuffix(enc, "~t")
				b, err := base64.RawURLEncoding.DecodeString(inner)
				if tampered && err == nil {
					// An integrity failure that still yields the token (a
					// JWE whose tag does not verify) is a refusal.
					raw, _, _ := strings.Cut(string(b), "|")
					return raw, errors.New("integrity")
				}
				raw, _, ok := strings.Cut(string(b), "|")
				if err != nil || !ok {
					// A partial answer with an error is still a refusal.
					return enc, errors.New("not ours")
				}
				return raw, nil
			},
		}))
		reg := o.client(t, oauthprovider.ClientSpec{IntrospectAny: true})
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		if !strings.HasPrefix(tok.RefreshToken, oauthprovider.PrefixRefreshToken) || len(sessions) != 1 || sessions[0] == "" {
			t.Fatalf("refresh = %q sessions %v", tok.RefreshToken, sessions)
		}
		in := must[oauthprovider.Introspection](t)(o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: tok.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		if !in.Active || in.TokenType != "refresh_token" {
			t.Fatalf("introspect = %+v", in)
		}
		rt := oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: oauthprovider.PrefixRefreshToken + "garbage!", ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
		if _, err := o.op.Token(anon(o.a), rt); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("undecodable: %v", err)
		}
		rt.RefreshToken = tok.RefreshToken + "~t"
		if _, err := o.op.Token(anon(o.a), rt); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("decoded with an error: %v", err)
		}
		rt.RefreshToken = tok.RefreshToken
		next := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), rt))
		must[auth.Done](t)(auth.Done{}, o.op.Revoke(anon(o.a), oauthprovider.RevokeRequest{Token: next.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		rt.RefreshToken = next.RefreshToken
		if _, err := o.op.Token(anon(o.a), rt); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("revoked: %v", err)
		}
	})
}

// A gate needs a trusted page and its decision, and the post-login gate a
// secret to sign its marker with.
func TestOAuthProvider_GateConfig(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		yes := func(context.Context, oauthprovider.GateInfo) bool { return true }
		withSecret := auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize)))
		for name, c := range map[string]struct {
			gate   oauthprovider.Option
			secret bool
		}{
			"post-login without a secret":    {oauthprovider.PostLogin(oauthprovider.PostLoginGate{Page: "/org", ShouldRedirect: yes}), false},
			"post-login without a decision":  {oauthprovider.PostLogin(oauthprovider.PostLoginGate{Page: "/org"}), true},
			"post-login on another origin":   {oauthprovider.PostLogin(oauthprovider.PostLoginGate{Page: "https://evil.example/org", ShouldRedirect: yes}), true},
			"select-account without a page":  {oauthprovider.SelectAccount(oauthprovider.SelectAccountGate{}), true},
			"select-account on another site": {oauthprovider.SelectAccount(oauthprovider.SelectAccountGate{Page: "https://evil.example/s"}), true},
		} {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
			op := oauthprovider.New(jw, oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login"), c.gate)
			opts := []auth.Option{e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), jw, op)}
			if c.secret {
				opts = append(opts, withSecret)
			}
			if _, err := auth.New(opts...); !errors.Is(err, oauthprovider.ErrBadGate) {
				t.Errorf("%s: %v", name, err)
			}
		}
	})
}

// Dynamic registration keeps members the provider does not define as the
// client's metadata, without the names the provider owns.
func TestOAuthProvider_RegistrationExtraMembers(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.AllowUnauthenticatedRegistration())
		srv := httptest.NewServer(o.op.Handler())
		t.Cleanup(srv.Close)
		body := `{"client_name":"X","redirect_uris":["http://127.0.0.1:3000/cb"],"token_endpoint_auth_method":"none","application_type":"native",` +
			`"tenant_hint":"acme","public":false,"type":"web","client_secret":"forged","skip_consent":true,"metadata":{"a":1}}`
		res := must[*http.Response](t)(http.Post(srv.URL+"/oauth2/register", "application/json", strings.NewReader(body)))
		var reg oauthprovider.Registration
		_ = json.NewDecoder(res.Body).Decode(&reg)
		res.Body.Close()
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("register = %d", res.StatusCode)
		}
		c := must[oauthprovider.Client](t)(o.op.Client(context.Background(), reg.ClientID))
		if string(c.Metadata) != `{"tenant_hint":"acme"}` || c.SkipConsent {
			t.Fatalf("client = %+v metadata %s", c, c.Metadata)
		}
	})
}

// Trusted clients live in memory: they authenticate and get tokens, the
// admin operations refuse to change them, and a bad definition fails New.
func TestOAuthProvider_TrustedClients(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const id, sec = "first-party", "s3cret-value"
		o := newOPEnv(t, e, oauthprovider.TrustedClients(oauthprovider.TrustedClient{ClientID: id, Secret: sec,
			ClientSpec: oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{Name: "App", RedirectURIs: []string{opRedirect}}}}))
		ctx := context.Background()
		reg := oauthprovider.Registration{Client: oauthprovider.Client{ClientID: id}, Secret: sec}
		code := o.code(t, authzReq(id))
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, code, opVerifier)))
		must[oauthprovider.AccessToken](t)(o.op.VerifyAccessToken(ctx, tok.AccessToken))
		wrong := exchange(oauthprovider.Registration{Client: reg.Client, Secret: "nope"}, o.code(t, authzReq(id)), opVerifier)
		if _, err := o.op.Token(anon(o.a), wrong); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("wrong secret: %v", err)
		}
		if _, err := o.op.UpdateClient(ctx, id, oauthprovider.ClientSpec{}); !errors.Is(err, oauthprovider.ErrForbidden) {
			t.Fatalf("update: %v", err)
		}
		if err := o.op.DeleteClient(ctx, id); !errors.Is(err, oauthprovider.ErrForbidden) {
			t.Fatalf("delete: %v", err)
		}
		if err := o.op.SetClientDisabled(ctx, id, true); !errors.Is(err, oauthprovider.ErrForbidden) {
			t.Fatalf("disable: %v", err)
		}
		if _, err := o.op.OwnedClient(request(o.a, o.token), id); !errors.Is(err, oauthprovider.ErrClientNotFound) {
			t.Fatalf("owner read: %v", err)
		}
		for name, tc := range map[string]oauthprovider.TrustedClient{
			"no secret":  {ClientID: "c", ClientSpec: oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "A", RedirectURIs: []string{opRedirect}}}},
			"owner":      {ClientID: "c", Secret: "s", ClientSpec: oauthprovider.ClientSpec{OwnerID: "u", ClientMetadata: oauthprovider.ClientMetadata{Name: "A", RedirectURIs: []string{opRedirect}}}},
			"no id":      {Secret: "s", ClientSpec: oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "A", RedirectURIs: []string{opRedirect}}}},
			"bad method": {ClientID: "c", ClientSpec: oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "A", RedirectURIs: []string{"javascript:x"}, AuthMethod: oauthprovider.AuthMethodNone}}},
		} {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
			op := oauthprovider.New(jw, oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login"), oauthprovider.TrustedClients(tc))
			if _, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), jw, op)); !errors.Is(err, oauthprovider.ErrBadTrustedClient) {
				t.Errorf("%s: %v", name, err)
			}
		}
	})
}

// expires_at in the token response, RFC 8252 loopback ports, an opaque
// token's own claims at introspection, and a guard that introspects JWTs.
func TestOAuthProvider_Round7Details(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const api = "https://api.example.com/f"
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "profile", "email", "offline_access", "api:read"),
			oauthprovider.AccessTokenClaims(func(context.Context, oauthprovider.AccessTokenClaimsInfo) map[string]any {
				return map[string]any{"tenant": "t1", "iss": "https://evil.example"}
			}))
		ctx := context.Background()
		reg := o.client(t, oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{RedirectURIs: []string{"http://127.0.0.1/cb", "http://localhost/cb"},
			AuthMethod: oauthprovider.AuthMethodNone, ApplicationType: "native"}})
		rs := o.client(t, oauthprovider.ClientSpec{IntrospectAny: true})
		in := authzReq(reg.ClientID)
		in.RedirectURI = "http://127.0.0.1:53111/cb"
		res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), in))
		cq := pageQuery(t, res, "/consent")
		res = must[oauthprovider.AuthorizeResult](t)(o.op.Consent(request(o.a, o.token), oauthprovider.ConsentRequest{Query: cq, Accept: true}))
		if !strings.HasPrefix(res.RedirectTo, "http://127.0.0.1:53111/cb?") {
			t.Fatalf("loopback port = %s", res.RedirectTo)
		}
		for _, bad := range []string{"http://127.0.0.1:53111/other", "http://localhost:5000/cb", "https://127.0.0.1:53111/cb"} {
			in.RedirectURI = bad
			if _, err := o.op.Authorize(request(o.a, o.token), in); !errors.Is(err, oauthprovider.ErrBadRedirectTarget) {
				t.Errorf("%s: %v", bad, err)
			}
		}
		ex := exchange(reg, must[*url.URL](t)(url.Parse(res.RedirectTo)).Query().Get("code"), opVerifier)
		ex.RedirectURI, ex.ClientAuthMethod = "http://127.0.0.1:53111/cb", oauthprovider.AuthMethodNone
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), ex))
		if tok.ExpiresAt != e.clock.Now().Add(time.Hour).Unix() {
			t.Fatalf("expires_at = %d", tok.ExpiresAt)
		}
		intro := must[oauthprovider.Introspection](t)(o.op.Introspect(anon(o.a), oauthprovider.IntrospectRequest{Token: tok.AccessToken, ClientID: rs.ClientID, ClientSecret: rs.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		b := must[[]byte](t)(json.Marshal(intro))
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		if m["tenant"] != "t1" || m["iss"] != testBaseURL {
			t.Fatalf("introspection = %s", b)
		}
		// A guard with Force introspects a JWT, so a revoked one stops at
		// once; without Force it verifies offline until it expires.
		must[oauthprovider.Resource](t)(o.op.CreateResource(ctx, oauthprovider.Resource{Identifier: api}))
		cc := o.client(t, oauthprovider.ClientSpec{ClientCredentialsScopes: []string{"api:read"}, ClientMetadata: oauthprovider.ClientMetadata{GrantTypes: []string{"client_credentials"}}})
		must[bool](t)(o.op.LinkClient(ctx, api, cc.ClientID))
		jt := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "client_credentials", ClientID: cc.ClientID, ClientSecret: cc.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic, Resource: api}))
		must[auth.Done](t)(auth.Done{}, o.op.Revoke(anon(o.a), oauthprovider.RevokeRequest{Token: jt.AccessToken, ClientID: cc.ClientID, ClientSecret: cc.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
		provider := httptest.NewServer(o.op.Handler())
		t.Cleanup(provider.Close)
		keys := jwt.KeysFromJWKS(o.jw.PublicKeys())
		guard := oauthprovider.ResourceGuard{Issuer: testBaseURL, Audience: api, Now: e.clock.Now,
			Keys:          func(kid string) (crypto.PublicKey, bool) { k, ok := keys[kid]; return k, ok },
			IntrospectURL: provider.URL + "/oauth2/introspect", ClientID: rs.ClientID, ClientSecret: rs.Secret}
		status := func(g oauthprovider.ResourceGuard) int {
			srv := httptest.NewServer(g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })))
			defer srv.Close()
			r := must[*http.Request](t)(http.NewRequest(http.MethodGet, srv.URL, nil))
			r.Header.Set("Authorization", "Bearer "+jt.AccessToken)
			res := must[*http.Response](t)(http.DefaultClient.Do(r))
			res.Body.Close()
			return res.StatusCode
		}
		if got := status(guard); got != 204 {
			t.Fatalf("offline = %d", got)
		}
		guard.Force = true
		if got := status(guard); got != 401 {
			t.Fatalf("forced introspection of a revoked JWT = %d", got)
		}
	})
}
