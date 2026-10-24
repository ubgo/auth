package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/sso"
	"github.com/ubgo/auth/plugin/sso/ssotest"
)

const (
	// testSecret is AUTH_SECRET for the tests: 32 bytes, as auth.WithSecret requires.
	testSecret   = "an example secret of 32 bytes!!!"
	testPassword = "correct horse battery staple"
	owner        = "owner@acme.test"
	// The customer's domain, provider id and IdP. idpSLO is the IdP's single
	// logout URL; the app only redirects the browser there.
	acmeDomain = "acme.test"
	providerID = "acme-saml"
	idpEntity  = "https://idp.acme.test"
	idpSLO     = "https://idp.acme.test/slo"
	ada        = "ada@" + acmeDomain
	relayState = "relay-from-idp"
)

// spEntity is the SP entity id the owner chooses for the provider.
var spEntity = baseURL + "/sp/acme"

// TestSSODomains_VerifyJoinAndSingleLogout: the owner registers Acme's SAML
// IdP for the Acme organization; nobody can sign in through it until the
// TXT record is published and verified; Ada then signs in, joins Acme as a
// member, and single logout works from the app's side and from the IdP's.
func TestSSODomains_VerifyJoinAndSingleLogout(t *testing.T) {
	w := newWorld(t)
	ownerB := w.browser(t)
	post[none](t, ownerB, "/auth/password/sign-up", fields{"identifier": owner, "password": testPassword, "name": "Owner"}, http.StatusOK)
	org := post[organization.Org](t, ownerB, "/auth/organization/create", organization.CreateRequest{Name: "Acme", Slug: "acme"}, http.StatusOK)

	reg := post[sso.RegisterResult](t, ownerB, "/auth/sso/register", w.samlProvider(org.ID), http.StatusOK)
	if reg.DomainVerified || reg.DomainVerificationToken == "" || reg.OrganizationID != org.ID {
		t.Fatalf("registered = %+v", reg)
	}

	// Unverified: the provider signs nobody in.
	adaB := w.browser(t)
	if e := post[errorAnswer](t, adaB, "/auth/sso/sign-in", fields{"email": ada}, http.StatusUnauthorized); e.Error.Code != sso.ErrDomainUnverified.Code {
		t.Fatalf("sign-in before verification: %+v", e.Error)
	}
	// Verifying before the record exists says so and changes nothing.
	if e := post[errorAnswer](t, ownerB, "/auth/sso/verify-domain", sso.ProviderRequest{ProviderID: providerID}, http.StatusBadGateway); e.Error.Code != sso.ErrDomainNotProven.Code {
		t.Fatalf("verify without the record: %+v", e.Error)
	}
	w.dns.publish(sso.DomainRecordName(sso.DefaultDomainTokenPrefix, providerID, acmeDomain), reg.DomainVerificationToken)
	post[none](t, ownerB, "/auth/sso/verify-domain", sso.ProviderRequest{ProviderID: providerID}, http.StatusOK)

	// Ada signs in by her work email and joins Acme as a member.
	a1 := w.samlSignIn(t, adaB, fields{"email": ada, "callbackURL": "/me"})
	adaID := get[meResponse](t, adaB, "/me", http.StatusOK).ID
	members := get[organization.MembersResult](t, ownerB, "/auth/organization/members?orgId="+url.QueryEscape(org.ID), http.StatusOK).Members
	if !hasMember(members, adaID, organization.RoleMember) {
		t.Fatalf("members after Ada's first sign-in = %+v", members)
	}

	// Signing out of the app ends the session at once and sends the browser
	// to the IdP with a LogoutRequest naming Ada's IdP session.
	out := post[sso.LogoutResult](t, adaB, "/auth/sso/saml2/logout", sso.LogoutRequest{CallbackURL: "/bye"}, http.StatusOK)
	if !strings.HasPrefix(out.URL, idpSLO+"?SAMLRequest=") {
		t.Fatalf("logout answered %+v", out)
	}
	get[errorAnswer](t, adaB, "/me", http.StatusUnauthorized)
	u, err := url.Parse(out.URL)
	if err != nil {
		t.Fatal(err)
	}
	lr, err := sso.PeekLogout(sso.BindingMessage{Redirect: true, Param: "SAMLRequest", Value: u.Query().Get("SAMLRequest")}, sso.DefaultMaxResponseSize)
	if err != nil || lr.NameID != ada || len(lr.SessionIndexes) != 1 || lr.SessionIndexes[0] != sessionIndex(a1) {
		t.Fatalf("LogoutRequest = %+v, %v", lr, err)
	}
	// The IdP's signed answer lands on the callback, once.
	answer := w.idpMessage(t, sso.KindLogoutResponse, "", "", lr.ID)
	if loc := adaB.redirect(t, "/auth/sso/saml2/sp/slo?"+answer); loc != "/bye" {
		t.Fatalf("LogoutResponse landed on %q", loc)
	}

	// The IdP ends Ada's session from its side: signed in again by
	// organization slug, she is signed out by the IdP's LogoutRequest, and the
	// IdP gets a LogoutResponse back.
	a2 := w.samlSignIn(t, adaB, fields{"organizationSlug": "acme", "callbackURL": "/me"})
	get[meResponse](t, adaB, "/me", http.StatusOK)
	idpB := w.browser(t)
	loc := idpB.redirect(t, "/auth/sso/saml2/sp/slo?"+w.idpMessage(t, sso.KindLogoutRequest, ada, sessionIndex(a2), ""))
	if !strings.HasPrefix(loc, idpSLO+"?SAMLResponse=") || !strings.Contains(loc, "RelayState="+relayState) {
		t.Fatalf("IdP logout answered %q", loc)
	}
	get[errorAnswer](t, adaB, "/me", http.StatusUnauthorized)
}

// TestSSODomains_OnlyTheOwnerOrAdminRegisters: a plain member of the
// organization cannot attach an IdP to it, and a stranger is told they are
// not a member.
func TestSSODomains_OnlyTheOwnerOrAdminRegisters(t *testing.T) {
	w := newWorld(t)
	ownerB, memberB, strangerB := w.browser(t), w.browser(t), w.browser(t)
	post[none](t, ownerB, "/auth/password/sign-up", fields{"identifier": owner, "password": testPassword, "name": "Owner"}, http.StatusOK)
	org := post[organization.Org](t, ownerB, "/auth/organization/create", organization.CreateRequest{Name: "Acme", Slug: "acme"}, http.StatusOK)
	bob := post[password.SignInResult](t, memberB, "/auth/password/sign-up", fields{"identifier": "bob@" + acmeDomain, "password": testPassword, "name": "Bob"}, http.StatusOK)
	orgs, err := auth.PluginOf[*organization.Plugin](w.a)
	if err != nil {
		t.Fatal(err)
	}
	if err := orgs.AddMember(context.Background(), org.ID, bob.User.ID, organization.RoleMember); err != nil {
		t.Fatal(err)
	}
	if e := post[errorAnswer](t, memberB, "/auth/sso/register", w.samlProvider(org.ID), http.StatusForbidden); e.Error.Code != sso.ErrForbidden.Code {
		t.Fatalf("a member registering for Acme: %+v", e.Error)
	}
	post[none](t, strangerB, "/auth/password/sign-up", fields{"identifier": "eve@evil.test", "password": testPassword, "name": "Eve"}, http.StatusOK)
	if e := post[errorAnswer](t, strangerB, "/auth/sso/register", w.samlProvider(org.ID), http.StatusBadRequest); e.Error.Code != sso.ErrNotMember.Code {
		t.Fatalf("a stranger registering for Acme: %+v", e.Error)
	}
}

// sessionIndex is the SessionIndex ssotest's IdP writes for an assertion.
func sessionIndex(a ssotest.Assertion) string { return "_s" + a.ID }

// hasMember reports whether members holds userID with role.
func hasMember(members []organization.MemberView, userID string, role organization.Role) bool {
	for _, m := range members {
		if m.User.ID == userID && m.Role == role {
			return true
		}
	}
	return false
}

// world is one app under test with its fake IdP and fake DNS.
type world struct {
	a   *auth.Auth
	h   http.Handler
	idp *ssotest.SAMLIdP
	dns *fakeDNS
}

// newWorld builds the app on a fresh database with a fake SAML identity
// provider and a fake DNS, so the domain checks run without a network.
func newWorld(t *testing.T) *world {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	w := &world{idp: ssotest.NewSAMLIdP(t, idpEntity), dns: &fakeDNS{records: map[string][]string{}}}
	if w.a, err = newAuth(db, []byte(testSecret), discard{}, w.dns); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.a.Close() })
	if _, err := w.a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	w.h = newHandler(w.a)
	return w
}

// samlProvider is the registration the owner sends: Acme's IdP, its SLO URL,
// the domain, and the organization it belongs to.
func (w *world) samlProvider(orgID string) sso.RegisterRequest {
	return sso.RegisterRequest{
		ProviderID: providerID, Issuer: spEntity, Domain: acmeDomain, OrganizationID: orgID,
		SAMLConfig: &sso.SAMLConfig{EntryPoint: w.idp.SSOURL, Cert: w.idp.CertPEM, WantAssertionsSigned: true,
			IdPMetadata: sso.IdPMetadata{EntityID: w.idp.EntityID, SingleLogoutService: []sso.Endpoint{{Binding: sso.BindingRedirect, Location: idpSLO}}},
			SPMetadata:  sso.SPMetadata{EntityID: spEntity}},
	}
}

// samlSignIn starts a SAML sign-in with body, plays the IdP and posts its
// signed answer to the ACS, which must land on /me. It returns the assertion
// the IdP issued.
func (w *world) samlSignIn(t *testing.T, b *browser, body fields) ssotest.Assertion {
	t.Helper()
	start := post[sso.SignInResult](t, b, "/auth/sso/sign-in", body, http.StatusOK)
	reqID, acs, relay := ssotest.AuthnRequest(t, start.URL)
	as := w.idp.Valid(acs, spEntity, reqID, ada)
	if loc := b.postForm(t, "/auth/sso/saml2/sp/acs", url.Values{"SAMLResponse": {w.idp.Response(as)}, "RelayState": {relay}}); loc != "/me" {
		t.Fatalf("ACS redirected to %q", loc)
	}
	return as
}

// idpMessage builds the redirect-binding query of a logout message the IdP
// signs: a LogoutRequest for nameID and index, or a LogoutResponse to the
// request inResponseTo.
func (w *world) idpMessage(t *testing.T, kind, nameID, index, inResponseTo string) string {
	t.Helper()
	param := "SAMLRequest"
	if kind == sso.KindLogoutResponse {
		param = "SAMLResponse"
	}
	var indexes []string
	if index != "" {
		indexes = []string{index}
	}
	slo := baseURL + authPrefix + "/" + sso.PluginName + sso.PathSLO
	doc := sso.LogoutDocument(kind, "_idp"+auth.NewToken().Reveal(), w.idp.EntityID, slo, nameID, "", indexes, inResponseTo, sso.StatusSuccess, time.Now())
	u, err := sso.RedirectURL(slo, param, doc, relayState, w.idp.Signer(), sso.AlgRSASHA256)
	if err != nil {
		t.Fatal(err)
	}
	pu, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	return pu.RawQuery
}

// fakeDNS is the TXT resolver the test gives the plugin: records appear when
// the test publishes them, the way a customer adds one at their DNS host.
type fakeDNS struct {
	mu      sync.Mutex
	records map[string][]string
}

// publish adds a TXT record.
func (d *fakeDNS) publish(name, value string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.records[name] = append(d.records[name], value)
}

// LookupTXT answers the published records, or "not found" as a resolver does.
func (d *fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if v, ok := d.records[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// discard drops mail; no step here sends any that the test reads.
type discard struct{}

func (discard) Send(context.Context, email.Mail) error { return nil }

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would, and does not follow redirects. HTTPS,
// because the session and flow cookies are __Host- and Secure.
type browser struct {
	srv    *httptest.Server
	client *http.Client
}

// browser opens a new browser on the world's app: its own cookie jar, so two
// browsers are two people, and redirects are returned rather than followed.
func (w *world) browser(t *testing.T) *browser {
	t.Helper()
	srv := httptest.NewTLSServer(w.h)
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &browser{srv: srv, client: client}
}

// fields is a JSON request body as a client writes it.
type fields map[string]string

// none is the answer of a call whose body the test does not read.
type none struct{}

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// redirect gets path, checks the answer is a 302 and returns its Location.
func (b *browser) redirect(t *testing.T, path string) string {
	t.Helper()
	res, err := b.client.Get(b.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	return wantFound(t, res)
}

// postForm posts form as the IdP's auto-submitting page does: a cross-site
// form, so no Origin of this app. It checks for a 302 and returns Location.
func (b *browser) postForm(t *testing.T, path string, form url.Values) string {
	t.Helper()
	res, err := b.client.PostForm(b.srv.URL+path, form)
	if err != nil {
		t.Fatal(err)
	}
	return wantFound(t, res)
}

// wantFound checks res is a 302 and returns where it points; any other
// status fails the test with the body.
func wantFound(t *testing.T, res *http.Response) string {
	t.Helper()
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(res.Body) // the test is failing anyway; a partial body still helps
		t.Fatalf("%s %s: status %d, want 302: %s", res.Request.Method, res.Request.URL.Path, res.StatusCode, buf.String())
	}
	return res.Header.Get("Location")
}

// post sends in as JSON with the app's Origin, checks the status and decodes
// the answer as Out.
func post[Out, In any](t *testing.T, b *browser, path string, in In, status int) Out {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, b.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
	return do[Out](t, b, req, status)
}

// get fetches path, checks the status and decodes the answer as Out.
func get[Out any](t *testing.T, b *browser, path string, status int) Out {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return do[Out](t, b, req, status)
}

// do sends req, checks the status and decodes the answer as Out; a wrong
// status fails the test with the body.
func do[Out any](t *testing.T, b *browser, req *http.Request, status int) Out {
	t.Helper()
	var out Out
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d: %s", req.Method, req.URL.Path, res.StatusCode, status, buf.String())
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: decode %q: %v", req.Method, req.URL.Path, buf.String(), err)
	}
	return out
}
