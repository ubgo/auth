package sso

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/sso/ssotest"
)

// trustedPlugin is a plugin whose guarded client trusts origin.
func trustedPlugin(origins ...string) *Plugin {
	p := New(WithTrustedOrigins(origins...))
	p.hc = guardedClient(DefaultHTTPTimeout, p.trusted)
	return p
}

func wantDiscovery(t *testing.T, err error, code DiscoveryCode) {
	t.Helper()
	var de *DiscoveryError
	if !errors.As(err, &de) || de.Code != code {
		t.Fatalf("got %v, want %s", err, code)
	}
	if !errors.Is(err, discoveryErrors[code]) {
		t.Fatalf("%v does not answer %v", err, discoveryErrors[code])
	}
}

func TestDiscover_FillsEndpointsAndPicksTokenAuth(t *testing.T) {
	idp := ssotest.NewOIDC(t)
	p := trustedPlugin(idp.URL)
	cfg := OIDCConfig{ClientID: "c", TokenEndpoint: "https://explicit.example.com/token"}
	if err := p.Discover(context.Background(), idp.Issuer(), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.AuthorizationEndpoint != idp.URL+"/authorize" || cfg.TokenEndpoint != "https://explicit.example.com/token" ||
		cfg.JWKSEndpoint != idp.URL+"/jwks" || cfg.TokenEndpointAuthentication != oauth.ClientSecretBasic || cfg.DiscoveryEndpoint == "" {
		t.Fatalf("%+v", cfg)
	}
}

func TestDiscover_Refusals(t *testing.T) {
	doc := map[string]any{}
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect/.well-known/openid-configuration" {
			http.Redirect(w, r, "/.well-known/openid-configuration", http.StatusFound)
			return
		}
		w.WriteHeader(status)
		if doc == nil {
			_, _ = w.Write([]byte("{not json"))
			return
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)
	p := trustedPlugin(srv.URL)
	ctx := context.Background()
	full := func() map[string]any {
		return map[string]any{"issuer": srv.URL, "authorization_endpoint": "/a", "token_endpoint": "/t", "jwks_uri": "/k"}
	}

	doc = full()
	doc["issuer"] = "https://other.example.com"
	wantDiscovery(t, p.Discover(ctx, srv.URL, &OIDCConfig{}), DiscoveryIssuerMismatch)

	doc = full()
	delete(doc, "jwks_uri")
	wantDiscovery(t, p.Discover(ctx, srv.URL, &OIDCConfig{}), DiscoveryIncomplete)

	doc, status = full(), http.StatusNotFound
	wantDiscovery(t, p.Discover(ctx, srv.URL, &OIDCConfig{}), DiscoveryNotFound)
	status = http.StatusInternalServerError
	wantDiscovery(t, p.Discover(ctx, srv.URL, &OIDCConfig{}), DiscoveryUnexpectedFailed)

	doc, status = nil, http.StatusOK
	wantDiscovery(t, p.Discover(ctx, srv.URL, &OIDCConfig{}), DiscoveryInvalidJSON)

	doc = full()
	doc["token_endpoint_auth_methods_supported"] = []string{"tls_client_auth"}
	wantDiscovery(t, p.Discover(ctx, srv.URL, &OIDCConfig{}), DiscoveryUnsupportedAuth)

	doc = full()
	cfg := OIDCConfig{DiscoveryEndpoint: srv.URL + "/redirect/.well-known/openid-configuration"}
	wantDiscovery(t, p.Discover(ctx, srv.URL, &cfg), DiscoveryRedirect)

	// Relative endpoints resolve against the issuer.
	cfg = OIDCConfig{}
	if err := p.Discover(ctx, srv.URL, &cfg); err != nil || cfg.TokenEndpoint != srv.URL+"/t" {
		t.Fatalf("%+v %v", cfg, err)
	}

	// The same server without the trust: plain http and a loopback address.
	wantDiscovery(t, New().Discover(ctx, srv.URL, &OIDCConfig{}), DiscoveryInvalidURL)
	wantDiscovery(t, New().Discover(ctx, "https://127.0.0.1:1", &OIDCConfig{}), DiscoveryPrivateHost)
	wantDiscovery(t, New().Discover(ctx, "::not a url", &OIDCConfig{}), DiscoveryInvalidURL)

	// skipDiscovery fetches nothing and needs every endpoint.
	wantDiscovery(t, p.Discover(ctx, srv.URL, &OIDCConfig{SkipDiscovery: true}), DiscoveryIncomplete)
	cfg = OIDCConfig{SkipDiscovery: true, AuthorizationEndpoint: "a", TokenEndpoint: "t", JWKSEndpoint: "k"}
	if err := p.Discover(ctx, "https://unreachable.invalid", &cfg); err != nil || cfg.TokenEndpointAuthentication != oauth.ClientSecretBasic {
		t.Fatalf("%+v %v", cfg, err)
	}
}

// The guarded client refuses a private address at connect time, after DNS:
// "localhost" passes every check on its name and is still refused.
func TestGuardedClient_RefusesPrivateAddressesAfterResolution(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(srv.Close)
	port := srv.URL[strings.LastIndex(srv.URL, ":"):]
	_, err := guardedClient(DefaultHTTPTimeout, nil).Get("http://localhost" + port)
	if !errors.Is(err, errPrivateHost) {
		t.Fatalf("got %v", err)
	}
	wantDiscovery(t, classifyFetchError(err), DiscoveryPrivateHost)
	res, err := guardedClient(DefaultHTTPTimeout, []string{srv.URL}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
}

func TestPublicAddr(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "192.168.0.1", "172.16.0.1", "169.254.169.254", "100.64.0.1", "::1", "fe80::1", "fd00::1", "0.0.0.0", "224.0.0.1", "::ffff:127.0.0.1"} {
		if PublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s counted as public", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "2606:4700::1111"} {
		if !PublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s counted as private", s)
		}
	}
}

func TestSelectTokenAuthAndNormalize(t *testing.T) {
	for in, want := range map[string]oauth.TokenAuth{
		"":                                   oauth.ClientSecretBasic,
		"client_secret_post":                 oauth.ClientSecretPost,
		"private_key_jwt,client_secret_post": oauth.ClientSecretPost,
		"private_key_jwt":                    oauth.PrivateKeyJWT,
	} {
		var methods []string
		if in != "" {
			methods = strings.Split(in, ",")
		}
		if got, err := SelectTokenAuth(methods); err != nil || got != want {
			t.Errorf("%q: %s %v", in, got, err)
		}
	}
	for _, tc := range [][3]string{
		{"https://idp/tenant", "/oauth/token", "https://idp/tenant/oauth/token"},
		{"https://idp/tenant/", "oauth/token", "https://idp/tenant/oauth/token"},
		{"https://idp", "https://other/x", "https://other/x"},
	} {
		if got, err := NormalizeEndpoint(tc[0], tc[1]); err != nil || got != tc[2] {
			t.Errorf("%v: %s %v", tc, got, err)
		}
	}
	if _, err := NormalizeEndpoint("not-absolute", "/x"); err == nil {
		t.Error("relative issuer accepted")
	}
	if _, err := NormalizeEndpoint("https://idp", "%zz"); err == nil {
		t.Error("bad endpoint accepted")
	}
}

func TestMapClaims(t *testing.T) {
	c := map[string]any{"sub": "s", "email": " Ada@Acme.Test ", "email_verified": "true", "given_name": "Ada", "family_name": "L", "picture": "https://i", "dept": "eng", "oid": "o-1", "mail": "m@x"}
	got := MapClaims(OIDCMapping{ExtraFields: map[string]string{"department": "dept", "missing": "nope"}}, c)
	if got.Subject != "s" || got.Email != "ada@acme.test" || !got.EmailVerified || got.Name != "Ada L" || got.Image != "https://i" || got.Extra["department"] != "eng" || len(got.Extra) != 1 {
		t.Fatalf("%+v", got)
	}
	got = MapClaims(OIDCMapping{ID: "oid", Email: "mail", EmailVerified: "x"}, c)
	if got.Subject != "o-1" || got.Email != "m@x" || got.EmailVerified {
		t.Fatalf("%+v", got)
	}
	c["email_verified"] = "yes"
	if MapClaims(OIDCMapping{}, c).EmailVerified {
		t.Fatal(`"yes" counted as verified`)
	}
}

func TestDomains(t *testing.T) {
	if got := splitDomains(" Acme.com, ,sub.ACME.io "); strings.Join(got, "|") != "acme.com|sub.acme.io" {
		t.Fatal(got)
	}
	ds := []string{"acme.com"}
	for d, want := range map[string]bool{"acme.com": true, "eng.acme.com": true, "ACME.com": true, "notacme.com": false, "acme.com.evil": false} {
		if DomainMatches(ds, d) != want {
			t.Errorf("%s", d)
		}
	}
	if emailDomain("a@B.com") != "b.com" {
		t.Fatal("emailDomain")
	}
	if DomainRecordName("p", "okta", "acme.com") != "_p-okta.acme.com" {
		t.Fatal("record name")
	}
	if !RecordHoldsToken([]string{"other", "_p-okta=tok"}, "_p-okta", "tok") || !RecordHoldsToken([]string{" tok "}, "_p-okta", "tok") || RecordHoldsToken([]string{"tok2"}, "_p-okta", "tok") {
		t.Fatal("RecordHoldsToken")
	}
}

func TestProvider_ReferenceAndShape(t *testing.T) {
	pr := Provider{ProviderID: "okta", Issuer: "https://idp", Domain: "acme.com", OIDC: &OIDCConfig{ClientID: "abcdef", ClientSecret: "s"}}
	ref := pr.Reference()
	pr2 := pr
	o := *pr.OIDC
	o.ClientSecret = "rotated"
	pr2.OIDC = &o
	if pr2.Reference() != ref || boundaryChanged(pr, pr2) {
		t.Fatal("a secret rotation changed the reference")
	}
	o2 := o
	o2.ClientID = "other"
	pr2.OIDC = &o2
	if !boundaryChanged(pr, pr2) {
		t.Fatal("a client id change kept the reference")
	}
	if lastFour("abcdef") != "cdef" || lastFour("ab") != "ab" {
		t.Fatal("lastFour")
	}
	if got, err := chooseProtocol(pr, ""); err != nil || got != ProtocolOIDC {
		t.Fatal(got, err)
	}
	if _, err := chooseProtocol(pr, ProtocolSAML); !errors.Is(err, ErrProtocol) {
		t.Fatal(err)
	}
	if !(OIDCConfig{}).pkceOn() || len((OIDCConfig{}).scopes()) != 4 {
		t.Fatal("defaults")
	}
}

func TestCheckShape(t *testing.T) {
	p := New()
	ok := Provider{ProviderID: "x", Issuer: "https://i", Domain: "a.com", OIDC: &OIDCConfig{ClientID: "c", ClientSecret: "s"}}
	if err := p.checkShape(ok); err != nil {
		t.Fatal(err)
	}
	bad := []func(*Provider){
		func(p *Provider) { p.Issuer = "" },
		func(p *Provider) { p.Domain = " , " },
		func(p *Provider) { p.OIDC = nil },
		func(p *Provider) { p.OIDC = &OIDCConfig{ClientSecret: "s"} },
		func(p *Provider) { p.OIDC = &OIDCConfig{ClientID: "c"} },
		func(p *Provider) {
			p.OIDC = &OIDCConfig{ClientID: "c", ClientSecret: "s", TokenEndpointAuthentication: oauth.PrivateKeyJWT}
		},
		func(p *Provider) {
			p.OIDC = &OIDCConfig{ClientID: "c", TokenEndpointAuthentication: oauth.PrivateKeyJWT}
		},
		func(p *Provider) {
			p.OIDC = &OIDCConfig{ClientID: "c", ClientSecret: "s", TokenEndpointAuthentication: "magic"}
		},
		func(p *Provider) { p.OIDC, p.SAML = nil, &SAMLConfig{EntryPoint: "https://idp/sso"} },
	}
	for i, mod := range bad {
		pr := ok
		mod(&pr)
		if err := p.checkShape(pr); !errors.Is(err, ErrBadProvider) {
			t.Errorf("case %d: %v", i, err)
		}
	}
}

func TestValidate_Configuration(t *testing.T) {
	cfg := auth.Config{BaseURL: "https://app.example.com"}
	if err := New().Validate(&auth.Config{}); !errors.Is(err, ErrNoCallbackURL) {
		t.Fatal(err)
	}
	if err := New().Validate(&cfg); !errors.Is(err, ErrKeyDerivation) {
		t.Fatalf("no secret: %v", err)
	}
}

func TestNew_ConfigurationRefusals(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	build := func(opts ...Option) error {
		_, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithSecret(secret), auth.WithPlugins(New(opts...)))
		return err
	}
	if err := build(); err != nil {
		t.Fatal(err)
	}
	if err := build(WithSAMLEngine(nil)); !errors.Is(err, auth.ErrNilOption) {
		t.Fatalf("nil engine: %v", err)
	}
	if err := build(WithSAMLOptions(SAMLOptions{OnDeprecated: "loud"})); !errors.Is(err, ErrBadAlgorithmSet) {
		t.Fatalf("bad policy: %v", err)
	}
	def := Provider{ProviderID: "d", Issuer: "https://i", Domain: "a.com", OIDC: &OIDCConfig{ClientID: "c", ClientSecret: "s"}}
	if err := build(WithDefaultProviders(def, def)); !errors.Is(err, ErrBadDefault) {
		t.Fatalf("duplicate default: %v", err)
	}
	if err := build(WithDefaultProviders(Provider{ProviderID: "d"})); !errors.Is(err, ErrBadDefault) {
		t.Fatalf("broken default: %v", err)
	}
	if err := build(WithErrorURL("https://evil.example.com/x")); !errors.Is(err, ErrBadReturnTo) {
		t.Fatalf("foreign error URL: %v", err)
	}
}

// private_key_jwt: the resolver's key becomes the client assertion, the
// secret is never sent, and a resolver failure fails the flow.
func TestOAuthProvider_PrivateKeyJWT(t *testing.T) {
	key, _, _ := ssotest.KeyPair(t, "client")
	var asked PrivateKeyRequest
	p := New(WithPrivateKeyResolver(func(_ context.Context, r PrivateKeyRequest) (crypto.Signer, string, error) {
		asked = r
		if r.KeyID == "broken" {
			return nil, "", errors.New("kms down")
		}
		return key, "", nil
	}))
	pr := Provider{ProviderID: "acme", Issuer: "https://idp", Domain: "a.com", OIDC: &OIDCConfig{ClientID: "c", TokenEndpointAuthentication: oauth.PrivateKeyJWT,
		PrivateKeyID: "k1", PrivateKeyAlgorithm: "RS256", AuthorizationEndpoint: "https://idp/a", TokenEndpoint: "https://idp/t", JWKSEndpoint: "https://idp/k"}}
	if err := p.checkShape(pr); err != nil {
		t.Fatal(err)
	}
	o, err := p.oauthProvider(context.Background(), pr, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if o.ClientAssertion == nil || o.ClientSecret != "" || asked.KeyID != "k1" || asked.ProviderID != "acme" || asked.Algorithm != "RS256" {
		t.Fatalf("%+v %+v", o, asked)
	}
	jwt, err := o.ClientAssertion(context.Background(), "https://idp/t")
	if err != nil || strings.Count(jwt, ".") != 2 {
		t.Fatalf("assertion %q %v", jwt, err)
	}
	pr.OIDC.PrivateKeyID = "broken"
	if _, err := p.oauthProvider(context.Background(), pr, nil, nil); err == nil {
		t.Fatal("a resolver failure was ignored")
	}
	if _, err := New().oauthProvider(context.Background(), pr, nil, nil); !errors.Is(err, ErrBadProvider) {
		t.Fatalf("no resolver: %v", err)
	}
}
