package oauthprovider

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestValidateExt(t *testing.T) {
	auth := func(context.Context, Client, ClientCredentials) (*Confirmation, error) { return nil, nil }
	ok := func(string) bool { return true }
	res := func(context.Context, string) (ClientMetadata, error) { return ClientMetadata{}, nil }
	for name, e := range map[string][]Extension{
		"no id":              {{}},
		"repeated id":        {{ID: "a"}, {ID: "a"}},
		"built-in method":    {{ID: "a", ClientAuthentication: []ClientAuthMethod{{Method: AuthMethodBasic, Authenticate: auth}}}},
		"method twice":       {{ID: "a", ClientAuthentication: []ClientAuthMethod{{Method: "m", Authenticate: auth}, {Method: "m", Authenticate: auth}}}},
		"no authenticate":    {{ID: "a", ClientAuthentication: []ClientAuthMethod{{Method: "m"}}}},
		"relative type":      {{ID: "a", ClientAuthentication: []ClientAuthMethod{{Method: "m", Authenticate: auth, AssertionTypes: []string{"attest"}}}}},
		"jwt-bearer":         {{ID: "a", ClientAuthentication: []ClientAuthMethod{{Method: "m", Authenticate: auth, AssertionTypes: []string{ClientAssertionType}}}}},
		"discovery cimd":     {{ID: "a", ClientDiscovery: []ClientDiscoverer{{ID: discoveryCIMD, Matches: ok, Resolve: res}}}},
		"discovery no match": {{ID: "a", ClientDiscovery: []ClientDiscoverer{{ID: "d", Resolve: res}}}},
	} {
		if err := New(nil, Extend(e...)).validateExtensions(); !errors.Is(err, ErrBadExtension) {
			t.Errorf("%s: %v", name, err)
		}
	}
	good := Extension{ID: "a", Grants: []ExtensionGrant{{Type: "urn:x:y", Handle: func(context.Context, Client, TokenRequest) (GrantDecision, error) { return GrantDecision{}, nil }}},
		ClientAuthentication: []ClientAuthMethod{{Method: "m", Authenticate: auth, AssertionTypes: []string{"urn:x:attest"}}},
		ClientDiscovery:      []ClientDiscoverer{{ID: "d", Matches: ok, Resolve: res}}}
	p := New(nil, Extend(good))
	if err := p.validateExtensions(); err != nil {
		t.Fatal(err)
	}
	if !p.isExtensionMethod("m") || p.isExtensionMethod(AuthMethodBasic) || len(p.servedGrants()) != len(DefaultGrantTypes)+1 {
		t.Fatalf("methods %v grants %v", p.authMethods(), p.servedGrants())
	}
	if m, ok := p.authMethodForAssertion("urn:x:attest"); !ok || m.Method != "m" {
		t.Fatal("assertion type not found")
	}
	if _, ok := p.discoverer(""); ok {
		t.Fatal("an empty client_id was discovered")
	}
}

func TestMetadataExtra(t *testing.T) {
	b, err := json.Marshal(Metadata{Issuer: "https://op", Extra: map[string]any{"x": 1, "issuer": "evil", "userinfo_endpoint": "evil"}})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if m["x"] != float64(1) || m["issuer"] != "https://op" {
		t.Fatalf("doc = %s", b)
	}
	if _, set := m["userinfo_endpoint"]; set {
		t.Fatalf("an omitted provider member was supplied: %s", b)
	}
}

func TestCertificateThumbprint(t *testing.T) {
	c := &x509.Certificate{Raw: []byte("der")}
	sum := sha256.Sum256([]byte("der"))
	if got := CertificateThumbprint(c); got != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal(got)
	}
	if certificateMatches(nil, "x") || certificateMatches(c, "x") || !certificateMatches(c, CertificateThumbprint(c)) {
		t.Fatal("certificateMatches")
	}
}

func TestClientAuthExtension(t *testing.T) {
	p := New(nil, Extend(Extension{ID: "a", ClientAuthentication: []ClientAuthMethod{{Method: "attest", AssertionTypes: []string{"urn:x:attest"},
		Authenticate: func(context.Context, Client, ClientCredentials) (*Confirmation, error) { return nil, nil }}}}))
	form := url.Values{"client_assertion_type": {"urn:x:attest"}, "client_assertion": {"a"}, "client_id": {"c1"}}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	cert := &x509.Certificate{Raw: []byte("der")}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	got, err := p.clientAuth(r, form)
	if err != nil || got.Method != "attest" || got.AssertionType != "urn:x:attest" || got.ID != "c1" || len(got.Certificates) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	for name, f := range map[string]url.Values{
		"unknown type": {"client_assertion_type": {"urn:x:other"}, "client_assertion": {"a"}, "client_id": {"c1"}},
		"no client_id": {"client_assertion_type": {"urn:x:attest"}, "client_assertion": {"a"}},
		"no assertion": {"client_assertion_type": {"urn:x:attest"}, "client_id": {"c1"}},
	} {
		if _, err := p.clientAuth(r, f); !errors.Is(err, ErrInvalidClient) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAuthenticateExtension(t *testing.T) {
	conf := &Confirmation{X5TS256: "t"}
	var p Plugin
	m := ClientAuthMethod{Method: "tls", Authenticate: func(context.Context, Client, ClientCredentials) (*Confirmation, error) { return conf, nil }}
	r, err := p.authenticateExtension(context.Background(), m, clientRow{}, ClientCredentials{Method: AuthMethodNone})
	if err != nil || r.confirmation != conf {
		t.Fatalf("%+v %v", r, err)
	}
	for name, cred := range map[string]ClientCredentials{
		"secret":        {Method: AuthMethodNone, Secret: "s"},
		"other method":  {Method: AuthMethodBasic},
		"stray assert":  {Method: AuthMethodNone, Assertion: "a"},
		"jwt for none":  {Method: AuthMethodPrivateKeyJWT},
		"attest method": {Method: "attest"},
	} {
		if _, err := p.authenticateExtension(context.Background(), m, clientRow{}, cred); !errors.Is(err, ErrInvalidClient) {
			t.Errorf("%s: %v", name, err)
		}
	}
	m.Authenticate = func(context.Context, Client, ClientCredentials) (*Confirmation, error) {
		return &Confirmation{JKT: "k"}, nil
	}
	if _, err := p.authenticateExtension(context.Background(), m, clientRow{}, ClientCredentials{Method: AuthMethodNone}); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("a method binding a DPoP key: %v", err)
	}
	m.Authenticate = func(context.Context, Client, ClientCredentials) (*Confirmation, error) { return nil, errors.New("no") }
	if _, err := p.authenticateExtension(context.Background(), m, clientRow{}, ClientCredentials{Method: AuthMethodNone}); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("refused: %v", err)
	}
}

func TestIssuanceConfirmation(t *testing.T) {
	if (issuance{}).confirmation() != nil || (issuance{}).x5t() != "" {
		t.Fatal("unbound issuance has a cnf")
	}
	is := issuance{jkt: "k", client: clientRow{confirmation: &Confirmation{X5TS256: "x"}}}
	if c := is.confirmation(); c == nil || c.JKT != "k" || c.X5TS256 != "x" || is.x5t() != "x" {
		t.Fatalf("%+v", c)
	}
}

func TestRefreshFormatHelpers(t *testing.T) {
	if err := New(nil, Issuer("https://op.example"), LoginPage("/l"), FormatRefreshToken(RefreshTokenFormat{Encode: func(context.Context, string, string) (string, error) { return "", nil }})).validateOptions(); err == nil {
		t.Fatal("a format without Decode was accepted")
	}
	var plain Plugin
	enc, err := plain.encodeRefresh(context.Background(), "raw", "s")
	if err != nil || enc != PrefixRefreshToken+"raw" {
		t.Fatal(enc, err)
	}
	h, ok := plain.refreshHash(context.Background(), enc)
	if !ok || len(h) == 0 {
		t.Fatal("plain hash")
	}
	if _, ok := plain.refreshHash(context.Background(), "raw"); ok {
		t.Fatal("a token without the prefix was hashed")
	}
	f := &Plugin{refreshFormat: &RefreshTokenFormat{
		Encode: func(_ context.Context, tok, _ string) (string, error) { return strings.ToUpper(tok), nil },
		Decode: func(_ context.Context, s string) (string, error) {
			if s == "BAD" {
				return "", errors.New("bad")
			}
			return strings.ToLower(s), nil
		},
	}}
	enc, _ = f.encodeRefresh(context.Background(), "raw", "s")
	h2, ok := f.refreshHash(context.Background(), enc)
	if enc != PrefixRefreshToken+"RAW" || !ok || string(h2) != string(h) {
		t.Fatalf("formatted %q", enc)
	}
	if _, ok := f.refreshHash(context.Background(), PrefixRefreshToken+"BAD"); ok {
		t.Fatal("an undecodable token was hashed")
	}
	f.refreshFormat.Encode = func(context.Context, string, string) (string, error) { return "", errors.New("x") }
	if _, err := f.encodeRefresh(context.Background(), "raw", "s"); err == nil {
		t.Fatal("encode error lost")
	}
}

func TestPostLoginMarker(t *testing.T) {
	a, b := postLoginMarker([]byte("k1"), "s1"), postLoginMarker([]byte("k1"), "s2")
	if a == b || a != postLoginMarker([]byte("k1"), "s1") || a == postLoginMarker([]byte("k2"), "s1") {
		t.Fatal("marker is not bound to key and session")
	}
}
