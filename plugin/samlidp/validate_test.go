package samlidp_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/samlidp"
)

const testIssuer = "https://id.example.test"

// build wires the plugin into auth.New and returns its refusal.
func build(t *testing.T, opts ...samlidp.Option) error {
	t.Helper()
	signIn := email.New(email.Login(), email.SignInWithCode(), email.WithMailer(email.MailerFunc(func(context.Context, email.Mail) error { return nil })))
	_, err := auth.New(auth.WithBaseURL(testIssuer), auth.WithPlugins(signIn, samlidp.New(opts...)))
	return err
}

// auth.New refuses every configuration that could not serve an SP safely,
// naming what to fix.
func TestValidate_RefusesBrokenConfigurations(t *testing.T) {
	now := time.Now()
	key, cert := keyPair(t, "idp", now)
	_, otherCert := keyPair(t, "other", now)
	sp := samlidp.ServiceProvider{EntityID: spEntityID, ACSURLs: []string{"https://sp.example.test/acs"}}
	ok := []samlidp.Option{samlidp.Issuer(testIssuer), samlidp.LoginPage("/login"), samlidp.SigningKey(key, cert), samlidp.ServiceProviders(sp)}
	with := func(extra ...samlidp.Option) []samlidp.Option {
		return append(append([]samlidp.Option{}, ok...), extra...)
	}
	spWith := func(edit func(*samlidp.ServiceProvider)) samlidp.Option {
		s := sp
		edit(&s)
		return samlidp.ServiceProviders(s)
	}
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	cases := map[string]struct {
		opts []samlidp.Option
		want error
	}{
		"no issuer":        {[]samlidp.Option{samlidp.LoginPage("/login"), samlidp.SigningKey(key, cert), samlidp.ServiceProviders(sp)}, samlidp.ErrNoIssuer},
		"http issuer":      {append([]samlidp.Option{samlidp.Issuer("http://id.example.test")}, ok[1:]...), samlidp.ErrNoIssuer},
		"issuer query":     {append([]samlidp.Option{samlidp.Issuer(testIssuer + "?a=1")}, ok[1:]...), samlidp.ErrNoIssuer},
		"no login page":    {[]samlidp.Option{samlidp.Issuer(testIssuer), samlidp.SigningKey(key, cert), samlidp.ServiceProviders(sp)}, samlidp.ErrNoLoginPage},
		"no key":           {[]samlidp.Option{samlidp.Issuer(testIssuer), samlidp.LoginPage("/login"), samlidp.ServiceProviders(sp)}, samlidp.ErrNoSigningKey},
		"key mismatch":     {append([]samlidp.Option{samlidp.SigningKey(key, otherCert)}, ok[0], ok[1], ok[3]), samlidp.ErrNoSigningKey},
		"ed25519 key":      {append([]samlidp.Option{samlidp.SigningKey(ed, cert)}, ok[0], ok[1], ok[3]), samlidp.ErrNoSigningKey},
		"no SPs":           {ok[:3], samlidp.ErrBadSP},
		"no entity ID":     {with(spWith(func(s *samlidp.ServiceProvider) { s.EntityID = "" })), samlidp.ErrBadSP},
		"no ACS":           {with(spWith(func(s *samlidp.ServiceProvider) { s.EntityID, s.ACSURLs = "b", nil })), samlidp.ErrBadSP},
		"http ACS":         {with(spWith(func(s *samlidp.ServiceProvider) { s.EntityID, s.ACSURLs = "b", []string{"http://sp.example/acs"} })), samlidp.ErrBadSP},
		"fragment ACS":     {with(spWith(func(s *samlidp.ServiceProvider) { s.EntityID, s.ACSURLs = "b", []string{"https://sp.example/acs#x"} })), samlidp.ErrBadSP},
		"relative ACS":     {with(spWith(func(s *samlidp.ServiceProvider) { s.EntityID, s.ACSURLs = "b", []string{"/acs"} })), samlidp.ErrBadSP},
		"signed, no cert":  {with(spWith(func(s *samlidp.ServiceProvider) { s.EntityID, s.RequireSignedRequests = "b", true })), samlidp.ErrBadSP},
		"want signed":      {with(samlidp.WantAuthnRequestsSigned()), samlidp.ErrBadSP},
		"nil cert":         {with(spWith(func(s *samlidp.ServiceProvider) { s.EntityID, s.Certificates = "b", []*x509.Certificate{nil} })), samlidp.ErrBadSP},
		"bad NameID":       {with(spWith(func(s *samlidp.ServiceProvider) { s.EntityID, s.NameIDFormat = "b", "urn:x" })), samlidp.ErrBadSP},
		"duplicate SP":     {with(samlidp.ServiceProviders(sp)), samlidp.ErrBadSP},
		"zero TTL":         {with(samlidp.AssertionTTL(0)), samlidp.ErrBadTTL},
		"zero max age":     {with(samlidp.RequestMaxAge(0)), samlidp.ErrBadTTL},
		"zero login TTL":   {with(samlidp.LoginTTL(-time.Second)), samlidp.ErrBadTTL},
		"negative skew":    {with(samlidp.ClockSkew(-time.Second)), samlidp.ErrBadTTL},
		"zero size":        {with(samlidp.MaxMessageSize(0)), samlidp.ErrBadTTL},
		"base path slash":  {with(samlidp.BasePath("/saml/")), samlidp.ErrBadBasePath},
		"relative base":    {with(samlidp.BasePath("saml")), samlidp.ErrBadBasePath},
		"nil access":       {with(samlidp.Access(nil)), auth.ErrNilOption},
		"nil store":        {with(samlidp.WithServiceProviderStore(nil)), auth.ErrNilOption},
		"nil guard":        {with(samlidp.WithRequestIDGuard(nil)), auth.ErrNilOption},
		"nil signing key":  {with(samlidp.SigningKey(nil, cert)), auth.ErrNilOption},
		"empty returnparm": {with(samlidp.ReturnParam("")), nil},
	}
	for name, c := range cases {
		err := build(t, c.opts...)
		if c.want == nil {
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
			continue
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	if err := build(t, with(samlidp.LoginPage("https://evil.example/login"))...); err == nil || !strings.Contains(err.Error(), "LoginPage") {
		t.Errorf("a login page on an untrusted origin: %v", err)
	}
	if err := build(t, ok...); err != nil {
		t.Fatalf("a valid configuration: %v", err)
	}
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: cert.SerialNumber, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ek.PublicKey, ek)
	ec, _ := x509.ParseCertificate(der)
	if err := build(t, samlidp.Issuer(testIssuer), samlidp.LoginPage("/login"), samlidp.SigningKey(ek, ec), samlidp.ServiceProviders(sp)); err != nil {
		t.Fatalf("an ECDSA key: %v", err)
	}
	ek2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := build(t, samlidp.Issuer(testIssuer), samlidp.LoginPage("/login"), samlidp.SigningKey(ek2, ec), samlidp.ServiceProviders(sp)); !errors.Is(err, samlidp.ErrNoSigningKey) {
		t.Fatalf("an ECDSA key that does not match its certificate: %v", err)
	}
}

// A store answers SPs at run time, each checked as a static one is; a store
// that answers another entity than asked, or an invalid SP, is refused.
func TestServiceProviderStore(t *testing.T) {
	now := time.Now()
	key, cert := keyPair(t, "idp", now)
	store := mapStore{}
	p := samlidp.New(samlidp.Issuer(testIssuer), samlidp.LoginPage("/login"), samlidp.SigningKey(key, cert), samlidp.WithServiceProviderStore(store))
	authtest.New(t, authtest.WithBaseURL(testIssuer), authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin {
		return []auth.Plugin{email.New(email.Login(), email.SignInWithCode(), email.WithMailer(e.Mail)), p}
	}))
	store["good"] = samlidp.ServiceProvider{EntityID: "good", ACSURLs: []string{"https://sp.example/acs"}}
	store["liar"] = samlidp.ServiceProvider{EntityID: "good", ACSURLs: []string{"https://sp.example/acs"}}
	store["bad"] = samlidp.ServiceProvider{EntityID: "bad", ACSURLs: []string{"http://sp.example/acs"}}
	for id, want := range map[string]error{"good": nil, "liar": samlidp.ErrUnknownSP, "bad": samlidp.ErrBadSP, "missing": samlidp.ErrUnknownSP} {
		_, err := samlidp.LookupForTest(p, id)
		if !errors.Is(err, want) && !(want == nil && err == nil) {
			t.Errorf("%s: got %v, want %v", id, err, want)
		}
	}
}

// mapStore is a ServiceProviderStore over a map.
type mapStore map[string]samlidp.ServiceProvider

func (m mapStore) ServiceProvider(_ context.Context, id string) (samlidp.ServiceProvider, error) {
	sp, ok := m[id]
	if !ok {
		return samlidp.ServiceProvider{}, samlidp.ErrUnknownSP
	}
	return sp, nil
}

// An SP that must sign its requests but has no certificate to check them
// with is refused from a store too, under its own flag or under
// WantAuthnRequestsSigned, so a signature that cannot be checked is only
// ever treated as absent for an SP that does not require one.
func TestServiceProviderStore_RequiredSignatureNeedsCertificates(t *testing.T) {
	key, cert := keyPair(t, "idp", time.Now())
	store := mapStore{
		"flag": {EntityID: "flag", ACSURLs: []string{"https://sp.example/acs"}, RequireSignedRequests: true},
		"none": {EntityID: "none", ACSURLs: []string{"https://sp.example/acs"}},
	}
	for _, c := range []struct {
		want   bool
		id     string
		global bool
	}{{false, "flag", false}, {false, "none", true}, {true, "none", false}} {
		opts := []samlidp.Option{samlidp.Issuer(testIssuer), samlidp.LoginPage("/login"), samlidp.SigningKey(key, cert), samlidp.WithServiceProviderStore(store)}
		if c.global {
			opts = append(opts, samlidp.WantAuthnRequestsSigned())
		}
		p := samlidp.New(opts...)
		if err := build(t, opts...); err != nil {
			t.Fatal(err)
		}
		authtest.New(t, authtest.WithBaseURL(testIssuer), authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin {
			return []auth.Plugin{email.New(email.Login(), email.SignInWithCode(), email.WithMailer(e.Mail)), p}
		}))
		_, err := samlidp.LookupForTest(p, c.id)
		if ok := err == nil; ok != c.want || (!ok && !errors.Is(err, samlidp.ErrBadSP)) {
			t.Errorf("%s (WantAuthnRequestsSigned %v): %v", c.id, c.global, err)
		}
	}
}
