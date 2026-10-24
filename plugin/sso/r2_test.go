package sso

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/sso/ssotest"
)

func TestKeyMatchesAlgorithm(t *testing.T) {
	rsaKey, _, _ := ssotest.KeyPair(t, "k")
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, tc := range []struct {
		name string
		err  error
	}{{"", nil}, {"RS256", nil}} {
		if err := keyMatchesAlgorithm(rsaKey, tc.name); err != nil {
			t.Fatal(tc.name, err)
		}
	}
	if err := keyMatchesAlgorithm(ecKey, "ES256"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"ES256", "PS512"} {
		if err := keyMatchesAlgorithm(rsaKey, bad); !errors.Is(err, ErrBadProvider) {
			t.Fatalf("%s accepted for an RSA key", bad)
		}
	}
	if err := keyMatchesAlgorithm(ecKey, "RS256"); !errors.Is(err, ErrBadProvider) {
		t.Fatal("RS256 accepted for an EC key")
	}
}

func TestValidateDiscoveryDocumentAndTrust(t *testing.T) {
	doc := DiscoveryDocument{Issuer: "https://idp/", AuthorizationEndpoint: "a", TokenEndpoint: "t", JWKSURI: "k"}
	if err := ValidateDiscoveryDocument(doc, "https://idp"); err != nil {
		t.Fatal(err)
	}
	doc.JWKSURI = ""
	wantDiscovery(t, ValidateDiscoveryDocument(doc, "https://idp"), DiscoveryIncomplete)
	if !NeedsRuntimeDiscovery(OIDCConfig{AuthorizationEndpoint: "a", TokenEndpoint: "t"}) || NeedsRuntimeDiscovery(OIDCConfig{AuthorizationEndpoint: "a", TokenEndpoint: "t", JWKSEndpoint: "k"}) {
		t.Fatal("NeedsRuntimeDiscovery")
	}
	p := New(WithTrustedOrigins("https://idp.corp"), RequireTrustedOrigins())
	if err := p.checkURL("https://idp.corp/x"); err != nil {
		t.Fatal(err)
	}
	wantDiscovery(t, p.checkURL("https://login.example.com/x"), DiscoveryUntrustedOrigin)
}

func TestDeriveSPPolicyAndIdP(t *testing.T) {
	md := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="sp1"><SPSSODescriptor WantAssertionsSigned="true"><NameIDFormat>` + NameIDEmail +
		`</NameIDFormat><AssertionConsumerService Binding="` + BindingPOST + `" Location="https://a/acs"/><AssertionConsumerService Binding="` + BindingRedirect + `" Location="https://a/r"/></SPSSODescriptor></EntityDescriptor>`
	pol, err := DeriveSPPolicy(md, DefaultMaxMetadataSize)
	if err != nil || pol.EntityID != "sp1" || !pol.WantAssertionsSigned || pol.NameIDFormat != NameIDEmail || len(pol.ACSURLs) != 1 {
		t.Fatalf("%+v %v", pol, err)
	}
	for _, bad := range []string{"<!DOCTYPE x><a/>", "<not xml"} {
		if _, err := DeriveSPPolicy(bad, DefaultMaxMetadataSize); !errors.Is(err, ErrBadProvider) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	if _, err := DeriveSPPolicy(md, 10); !errors.Is(err, ErrBadProvider) {
		t.Fatal("oversize SP metadata")
	}
	if id, err := DeriveIdPEntityID(SAMLConfig{IdPMetadata: IdPMetadata{EntityID: "e1"}}, DefaultMaxMetadataSize); err != nil || id != "e1" {
		t.Fatal(id, err)
	}
	cfg := SAMLConfig{IdPMetadata: IdPMetadata{SingleLogoutService: []Endpoint{{Binding: BindingRedirect, Location: "https://idp/slo"}}}}
	if idp, _ := cfg.IdP(DefaultMaxMetadataSize); idp.SLOURL != "https://idp/slo" {
		t.Fatal("SLO URL")
	}
}

func TestProviderPathsMiddleware(t *testing.T) {
	var seen *http.Request
	var body string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = r
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	})
	h := New().ProviderPaths("/auth/sso", next)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/sso/callback/acme?code=c&providerId=evil", nil))
	if seen.URL.Path != "/auth/sso/callback" || seen.URL.Query().Get("providerId") != "acme" || seen.URL.Query().Get("code") != "c" {
		t.Fatalf("callback rewrite %s", seen.URL)
	}
	r := httptest.NewRequest(http.MethodPost, "/auth/sso/saml2/sp/acs/acme", strings.NewReader("SAMLResponse=x&providerId=evil"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(httptest.NewRecorder(), r)
	f, _ := url.ParseQuery(body)
	if seen.URL.Path != "/auth/sso/saml2/sp/acs" || f.Get("providerId") != "acme" || f.Get("SAMLResponse") != "x" {
		t.Fatalf("acs rewrite %s %q", seen.URL, body)
	}
	for _, untouched := range []string{"/auth/sso/callback", "/auth/sso/callback/a/b", "/elsewhere/callback/x"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, untouched, nil))
		if seen.URL.Path != strings.Split(untouched, "?")[0] {
			t.Fatalf("%s rewritten to %s", untouched, seen.URL.Path)
		}
	}
	p := New(PerProviderPaths())
	p.callback, p.acs, p.slo = "https://a/cb", "https://a/acs", "https://a/slo"
	if p.callbackURLFor("x y") != "https://a/cb/x%20y" || p.acsURLFor("x") != "https://a/acs/x" || p.sloURLFor("x") != "https://a/slo/x" {
		t.Fatal("per-provider URLs")
	}
}

func TestProviderFields(t *testing.T) {
	p := New(WithProviderFields(ProviderField{Name: "plan", Required: true}, ProviderField{Name: "secret", NoInput: true}))
	if err := p.validateFields(); err != nil {
		t.Fatal(err)
	}
	if err := p.checkFieldInput(map[string]any{"plan": 1}, true); err != nil {
		t.Fatal(err)
	}
	if err := p.checkFieldInput(map[string]any{}, false); err != nil {
		t.Fatal("update needs no required field")
	}
	for _, in := range []map[string]any{{}, {"plan": 1, "secret": 2}, {"plan": 1, "x": 1}} {
		if err := p.checkFieldInput(in, true); err == nil {
			t.Fatalf("%v accepted", in)
		}
	}
	for _, bad := range [][]ProviderField{{{Name: ""}}, {{Name: "a"}, {Name: "a"}}, {{Name: "issuer"}}} {
		if err := New(WithProviderFields(bad...)).validateFields(); !errors.Is(err, ErrBadFields) {
			t.Fatalf("%v: %v", bad, err)
		}
	}
	if col, err := encodeFields(nil); col != nil || err != nil {
		t.Fatal("empty fields are NULL")
	}
}

func TestAssignOAuthIneligibleAndDisabled(t *testing.T) {
	p := New()
	got, err := p.AssignOAuth(context.Background(), oauth.ResolvedEvent{Linked: true})
	if err != nil || got != AssignIneligibleSource {
		t.Fatal(got, err)
	}
	if got, _ := p.AssignByVerifiedDomain(context.Background(), "u", "a@b.c", true); got != AssignDisabled {
		t.Fatal(got)
	}
	if err := p.OAuthAssignment()(context.Background(), nil, oauth.ResolvedEvent{Linked: true}); err != nil {
		t.Fatal(err)
	}
	if tok := newDomainToken(); len(tok) != domainTokenBytes || strings.ToLower(tok) != tok {
		t.Fatal(tok)
	}
}
