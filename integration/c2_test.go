package integration

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/sso"
	"github.com/ubgo/auth/plugin/sso/ssotest"
)

// C2: the sso plugin's remaining paths, driven through its typed Go API —
// every database failure on every operation reaches the caller, and the
// refusals and branches the round-31 tests leave out.

const (
	c2OIDC   = "acme-oidc"
	c2SAML   = "acme-saml"
	c2Person = "ada@" + r31Domain
)

// c2World is one app with the sso plugin, an OIDC IdP, a SAML IdP, and an
// admin who registers providers.
type c2World struct {
	a     *auth.Auth
	p     *sso.Plugin
	oidc  *ssotest.OIDC
	saml  *ssotest.SAMLIdP
	admin auth.Token
	uid   string
	e     *env
}

// c2Build wires the plugin with opts on e. The OIDC IdP's origin is trusted,
// since httptest listens on a loopback address the guarded client refuses.
func c2Build(t *testing.T, e *env, opts ...sso.Option) *c2World {
	t.Helper()
	return c2BuildWith(t, e, nil, nil, opts...)
}

// c2BuildWith is c2Build with extra core options and plugins.
func c2BuildWith(t *testing.T, e *env, authOpts []auth.Option, plugins []auth.Plugin, opts ...sso.Option) *c2World {
	t.Helper()
	w := &c2World{oidc: ssotest.NewOIDC(t), saml: ssotest.NewSAMLIdP(t, "https://idp.example.com/acme"), e: e}
	w.p = sso.New(append([]sso.Option{sso.WithTrustedOrigins(w.oidc.URL)}, opts...)...)
	w.a = e.newAuth(t, append([]auth.Option{auth.WithSecret(r31Secret)}, authOpts...), append([]auth.Plugin{e.emailPlugin(), w.p}, plugins...)...)
	w.uid, w.admin = identUser(t, w.a, "admin@corp.test")
	return w
}

// c2Ctx is a browser request carrying a session token and a flow binding.
func c2Ctx(a *auth.Auth, tok, flow auth.Token) context.Context {
	req := auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{IP: "203.0.113.7", UserAgent: "test", Origin: testBaseURL}, Flow: flow}
	if tok != "" {
		req.Credential, req.Token = auth.CredentialCookie, tok
	}
	return a.WithRequest(context.Background(), req)
}

// as is the admin's request.
func (w *c2World) as() context.Context { return c2Ctx(w.a, w.admin, "") }

// oidcRequest is a registration of the world's OIDC IdP.
func (w *c2World) oidcRequest(id string) sso.RegisterRequest {
	return sso.RegisterRequest{ProviderID: id, Issuer: w.oidc.Issuer(), Domain: r31Domain,
		OIDCConfig: &sso.OIDCConfig{ClientID: w.oidc.ClientID, ClientSecret: w.oidc.ClientSecret}}
}

// samlConfig is a working SAML configuration of the world's IdP, with an
// IdP SLO endpoint and an SP signing key.
func (w *c2World) samlConfig(t *testing.T) *sso.SAMLConfig {
	t.Helper()
	key, _, certPEM := ssotest.KeyPair(t, "sp")
	return &sso.SAMLConfig{EntryPoint: w.saml.SSOURL, Cert: w.saml.CertPEM, WantAssertionsSigned: true, IdentifierFormat: sso.NameIDEmail,
		IdPMetadata: sso.IdPMetadata{EntityID: w.saml.EntityID, SingleLogoutService: []sso.Endpoint{{Binding: sso.BindingRedirect, Location: r31IdPSLO}}},
		SPMetadata:  sso.SPMetadata{EntityID: r31SP}, PrivateKey: ssotest.KeyPEM(key), SPCertificate: certPEM}
}

func (w *c2World) samlRequest(t *testing.T, id string) sso.RegisterRequest {
	t.Helper()
	return sso.RegisterRequest{ProviderID: id, Issuer: r31SP, Domain: r31Domain, SAMLConfig: w.samlConfig(t)}
}

func (w *c2World) register(t *testing.T, in sso.RegisterRequest) sso.RegisterResult {
	t.Helper()
	out, err := w.p.RegisterProvider(w.as(), in)
	if err != nil {
		t.Fatalf("register %s: %v", in.ProviderID, err)
	}
	return out
}

// oidcFlow starts an OIDC sign-in and walks the IdP; it returns the
// callback to send and the flow binding the browser holds.
func (w *c2World) oidcFlow(t *testing.T, in sso.SignInRequest) (sso.CallbackRequest, auth.Token) {
	t.Helper()
	out, err := w.p.SignIn(c2Ctx(w.a, "", ""), in)
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	q := w.oidc.Authorize(t, out.URL)
	return sso.CallbackRequest{Code: q.Get("code"), State: q.Get("state")}, auth.Token(q.Get("state"))
}

// oidcSignIn runs a whole OIDC sign-in.
func (w *c2World) oidcSignIn(t *testing.T, in sso.SignInRequest) (sso.CallbackResult, error) {
	t.Helper()
	cb, flow := w.oidcFlow(t, in)
	return w.p.Callback(c2Ctx(w.a, "", flow), cb)
}

// samlFlow starts a SAML sign-in and returns the ACS post that answers it.
func (w *c2World) samlFlow(t *testing.T, providerID string) (sso.ACSRequest, ssotest.Assertion) {
	t.Helper()
	out, err := w.p.SignIn(c2Ctx(w.a, "", ""), sso.SignInRequest{ProviderID: providerID, CallbackURL: "/home"})
	if err != nil {
		t.Fatalf("saml sign-in: %v", err)
	}
	reqID, _, relay := ssotest.AuthnRequest(t, out.URL)
	as := w.saml.Valid(r31ACS, r31SP, reqID, c2Person)
	return sso.ACSRequest{SAMLResponse: w.saml.Response(as), RelayState: relay}, as
}

// samlSignIn runs a whole SAML sign-in.
func (w *c2World) samlSignIn(t *testing.T, providerID string) (sso.CallbackResult, error) {
	t.Helper()
	in, _ := w.samlFlow(t, providerID)
	return w.p.ACS(c2Ctx(w.a, "", ""), in)
}

// idpLogout is an SLO message from the world's SAML IdP, as the redirect
// binding carries it.
func (w *c2World) idpLogout(t *testing.T, kind, nameID, sessionIndex, inResponseTo string) sso.SLORequest {
	t.Helper()
	var idx []string
	if sessionIndex != "" {
		idx = []string{sessionIndex}
	}
	slo := testBaseURL + "/auth/sso/saml2/sp/slo"
	doc := sso.LogoutDocument(kind, "_idp"+auth.NewToken().Reveal(), w.saml.EntityID, slo, nameID, "", idx, inResponseTo, sso.StatusSuccess, w.a.Now())
	param := "SAMLRequest"
	if kind == sso.KindLogoutResponse {
		param = "SAMLResponse"
	}
	u, err := sso.RedirectURL(slo, param, doc, "relay-x", w.saml.Signer(), sso.AlgRSASHA256)
	if err != nil {
		t.Fatal(err)
	}
	pu, _ := url.Parse(u)
	q := pu.Query()
	return sso.SLORequest{SAMLRequest: q.Get("SAMLRequest"), SAMLResponse: q.Get("SAMLResponse"), RelayState: q.Get("RelayState"), SigAlg: q.Get("SigAlg"), Signature: q.Get("Signature")}
}

// c2Sweep sweeps one sso operation over a database that fails on demand.
func c2Sweep(t *testing.T, name string, opts []sso.Option, setup func(t *testing.T, w *c2World) func(ctx context.Context) error) {
	t.Run(name, func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			return setup(t, c2Build(t, e.env, opts...))
		})
	})
}

// TestC2_FaultSweeps: every database failure on every sso operation path is
// returned to the caller, never reported as a sign-in, a registration or a
// logout that happened.
func TestC2_FaultSweeps(t *testing.T) {
	dv := sso.WithDomainVerification(sso.DomainVerification{Resolver: &r31Resolver{txts: map[string][]string{}}})
	slo := sso.WithSAMLOptions(sso.SAMLOptions{EnableSingleLogout: true})
	orgs := &r31Orgs{roles: map[string]string{}}
	withOrgs := sso.WithOrganizations(orgs, sso.OrganizationProvisioning{})
	fields := sso.WithProviderFields(sso.ProviderField{Name: "tier"})

	c2Sweep(t, "register oidc with domain verification", []sso.Option{dv}, func(t *testing.T, w *c2World) func(context.Context) error {
		return func(context.Context) error { _, err := w.p.RegisterProvider(w.as(), w.oidcRequest(c2OIDC)); return err }
	})
	c2Sweep(t, "register saml", nil, func(t *testing.T, w *c2World) func(context.Context) error {
		in := w.samlRequest(t, c2SAML)
		return func(context.Context) error { _, err := w.p.RegisterProvider(w.as(), in); return err }
	})
	c2Sweep(t, "list", nil, func(t *testing.T, w *c2World) func(context.Context) error {
		w.register(t, w.oidcRequest(c2OIDC))
		return func(context.Context) error { _, err := w.p.ListProviders(w.as()); return err }
	})
	c2Sweep(t, "get", nil, func(t *testing.T, w *c2World) func(context.Context) error {
		w.register(t, w.oidcRequest(c2OIDC))
		return func(context.Context) error { _, err := w.p.GetProvider(w.as(), c2OIDC); return err }
	})
	c2Sweep(t, "update, boundary change", []sso.Option{fields}, func(t *testing.T, w *c2World) func(context.Context) error {
		in := w.oidcRequest(c2OIDC)
		in.AdditionalFields = map[string]any{"tier": "silver"}
		w.register(t, in)
		d := "other.test"
		return func(context.Context) error {
			_, err := w.p.UpdateProvider(w.as(), sso.UpdateRequest{ProviderID: c2OIDC, Domain: &d, AdditionalFields: map[string]any{"tier": "gold"},
				OIDCConfig: &sso.OIDCConfig{ClientID: "client-2"}})
			return err
		}
	})
	c2Sweep(t, "delete", nil, func(t *testing.T, w *c2World) func(context.Context) error {
		w.register(t, w.oidcRequest(c2OIDC))
		return func(context.Context) error { return w.p.DeleteProvider(w.as(), c2OIDC) }
	})
	c2Sweep(t, "sign-in oidc by email", nil, func(t *testing.T, w *c2World) func(context.Context) error {
		w.register(t, w.oidcRequest(c2OIDC))
		return func(context.Context) error {
			_, err := w.p.SignIn(c2Ctx(w.a, "", ""), sso.SignInRequest{Email: "ada@eng." + r31Domain})
			return err
		}
	})
	c2Sweep(t, "sign-in by organization", []sso.Option{withOrgs}, func(t *testing.T, w *c2World) func(context.Context) error {
		orgs.AddMember(context.Background(), "org-1", w.uid, sso.RoleOwner)
		in := w.oidcRequest(c2OIDC)
		in.OrganizationID = "org-1"
		w.register(t, in)
		return func(context.Context) error {
			_, err := w.p.SignIn(c2Ctx(w.a, "", ""), sso.SignInRequest{OrganizationSlug: "acme"})
			return err
		}
	})
	c2Sweep(t, "oidc callback creates the user", []sso.Option{withOrgs}, func(t *testing.T, w *c2World) func(context.Context) error {
		orgs.AddMember(context.Background(), "org-1", w.uid, sso.RoleOwner)
		in := w.oidcRequest(c2OIDC)
		in.OrganizationID = "org-1"
		w.register(t, in)
		cb, flow := w.oidcFlow(t, sso.SignInRequest{ProviderID: c2OIDC})
		return func(context.Context) error { _, err := w.p.Callback(c2Ctx(w.a, "", flow), cb); return err }
	})
	c2Sweep(t, "oidc callback of a linked account", nil, func(t *testing.T, w *c2World) func(context.Context) error {
		w.register(t, w.oidcRequest(c2OIDC))
		if _, err := w.oidcSignIn(t, sso.SignInRequest{ProviderID: c2OIDC}); err != nil {
			t.Fatal(err)
		}
		cb, flow := w.oidcFlow(t, sso.SignInRequest{ProviderID: c2OIDC})
		return func(context.Context) error { _, err := w.p.Callback(c2Ctx(w.a, "", flow), cb); return err }
	})
	c2Sweep(t, "saml sign-in", nil, func(t *testing.T, w *c2World) func(context.Context) error {
		w.register(t, w.samlRequest(t, c2SAML))
		return func(context.Context) error {
			_, err := w.p.SignIn(c2Ctx(w.a, "", ""), sso.SignInRequest{ProviderID: c2SAML})
			return err
		}
	})
	c2Sweep(t, "saml acs with single logout", []sso.Option{slo}, func(t *testing.T, w *c2World) func(context.Context) error {
		w.register(t, w.samlRequest(t, c2SAML))
		in, _ := w.samlFlow(t, c2SAML)
		return func(context.Context) error { _, err := w.p.ACS(c2Ctx(w.a, "", ""), in); return err }
	})
	c2Sweep(t, "sp metadata", nil, func(t *testing.T, w *c2World) func(context.Context) error {
		w.register(t, w.samlRequest(t, c2SAML))
		return func(context.Context) error { _, err := w.p.SPMetadata(w.as(), c2SAML); return err }
	})
	c2Sweep(t, "initiate single logout", []sso.Option{slo}, func(t *testing.T, w *c2World) func(context.Context) error {
		w.register(t, w.samlRequest(t, c2SAML))
		res, err := w.samlSignIn(t, c2SAML)
		if err != nil {
			t.Fatal(err)
		}
		return func(context.Context) error {
			_, err := w.p.InitiateSLO(c2Ctx(w.a, res.Token, ""), sso.LogoutRequest{})
			return err
		}
	})
	c2Sweep(t, "idp logout request", []sso.Option{slo}, func(t *testing.T, w *c2World) func(context.Context) error {
		w.register(t, w.samlRequest(t, c2SAML))
		in, as := w.samlFlow(t, c2SAML)
		if _, err := w.p.ACS(c2Ctx(w.a, "", ""), in); err != nil {
			t.Fatal(err)
		}
		msg := w.idpLogout(t, sso.KindLogoutRequest, c2Person, "_s"+as.ID, "")
		// A session that could not be ended is reported to the IdP, whose
		// LogoutResponse then carries the Responder status rather than
		// Success: that answer is the failure reaching its caller.
		return func(context.Context) error {
			out, err := w.p.SLO(c2Ctx(w.a, "", ""), msg)
			if err != nil {
				return err
			}
			pu, _ := url.Parse(out.URL)
			lr, err := sso.PeekLogout(sso.BindingMessage{Redirect: true, Param: "SAMLResponse", Value: pu.Query().Get("SAMLResponse")}, sso.DefaultMaxResponseSize)
			switch {
			case err != nil:
				return err
			case lr.Status != sso.StatusSuccess:
				return errors.New("the IdP was told the logout failed: " + lr.Status)
			}
			return nil
		}
	})
	c2Sweep(t, "idp logout response", []sso.Option{slo}, func(t *testing.T, w *c2World) func(context.Context) error {
		w.register(t, w.samlRequest(t, c2SAML))
		res, err := w.samlSignIn(t, c2SAML)
		if err != nil {
			t.Fatal(err)
		}
		out, err := w.p.InitiateSLO(c2Ctx(w.a, res.Token, ""), sso.LogoutRequest{})
		if err != nil {
			t.Fatal(err)
		}
		pu, _ := url.Parse(out.URL)
		lr, err := sso.PeekLogout(sso.BindingMessage{Redirect: true, Param: "SAMLRequest", Value: pu.Query().Get("SAMLRequest")}, sso.DefaultMaxResponseSize)
		if err != nil {
			t.Fatal(err)
		}
		msg := w.idpLogout(t, sso.KindLogoutResponse, "", "", lr.ID)
		return func(context.Context) error { _, err := w.p.SLO(c2Ctx(w.a, "", ""), msg); return err }
	})
	c2Sweep(t, "sign out forgets the saml session", []sso.Option{slo}, func(t *testing.T, w *c2World) func(context.Context) error {
		w.register(t, w.samlRequest(t, c2SAML))
		res, err := w.samlSignIn(t, c2SAML)
		if err != nil {
			t.Fatal(err)
		}
		return func(context.Context) error { return w.a.SignOut(c2Ctx(w.a, res.Token, "")) }
	})
	c2Sweep(t, "request domain verification", []sso.Option{dv}, func(t *testing.T, w *c2World) func(context.Context) error {
		w.register(t, w.oidcRequest(c2OIDC))
		return func(context.Context) error { _, err := w.p.RequestDomainVerification(w.as(), c2OIDC); return err }
	})
	dns := &r31Resolver{txts: map[string][]string{}}
	c2Sweep(t, "verify domain", []sso.Option{sso.WithDomainVerification(sso.DomainVerification{Resolver: dns})}, func(t *testing.T, w *c2World) func(context.Context) error {
		reg := w.register(t, w.oidcRequest(c2OIDC))
		dns.mu.Lock()
		dns.txts[sso.DomainRecordName(sso.DefaultDomainTokenPrefix, c2OIDC, r31Domain)] = []string{reg.DomainVerificationToken}
		dns.mu.Unlock()
		return func(context.Context) error { return w.p.VerifyDomain(w.as(), c2OIDC) }
	})
	c2Sweep(t, "request a fresh domain token after expiry", []sso.Option{dv}, func(t *testing.T, w *c2World) func(context.Context) error {
		w.register(t, w.oidcRequest(c2OIDC))
		w.e.clock.Advance(sso.DefaultDomainTokenTTL + time.Minute)
		_, tok, err := w.a.CreateSession(context.Background(), w.uid, auth.Client{})
		if err != nil {
			t.Fatal(err)
		}
		w.admin = tok
		return func(context.Context) error { _, err := w.p.RequestDomainVerification(w.as(), c2OIDC); return err }
	})
	c2Sweep(t, "assign by verified domain", []sso.Option{withOrgs}, func(t *testing.T, w *c2World) func(context.Context) error {
		return func(ctx context.Context) error {
			_, err := w.p.AssignByVerifiedDomain(ctx, w.uid, c2Person, true)
			return err
		}
	})
	c2Sweep(t, "set provider fields", []sso.Option{fields}, func(t *testing.T, w *c2World) func(context.Context) error {
		w.register(t, w.oidcRequest(c2OIDC))
		return func(ctx context.Context) error {
			return w.p.SetProviderFields(ctx, c2OIDC, map[string]any{"tier": "gold"})
		}
	})
}

// c2Code fails unless err is a refused SAML message with code.
func c2Code(t *testing.T, what string, err error, code sso.SAMLCode) {
	t.Helper()
	var se *sso.SAMLError
	if !errors.As(err, &se) || se.Code != code {
		t.Fatalf("%s: %v, want SAML code %s", what, err, code)
	}
}

// c2Want fails unless err is want.
func c2Want(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: %v, want %v", what, err, want)
	}
}

// TestC2_SAMLACSRefusals: each way an ACS post can fail to belong to a flow
// this app started, or to carry a usable assertion, is refused with its own
// answer, and none signs anyone in.
func TestC2_SAMLACSRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := c2Build(t, e)
		w.register(t, w.samlRequest(t, c2SAML))
		ctx, bg := c2Ctx(w.a, "", ""), context.Background()

		_, err := w.p.ACS(ctx, sso.ACSRequest{RelayState: "x"})
		c2Code(t, "no SAMLResponse", err, sso.SAMLInvalidEncoding)
		for _, meta := range []string{"{", `{"p":"someone-else"}`} {
			relay, err := w.a.IssueVerification(bg, sso.PurposeSAMLRelay, c2SAML, time.Minute, meta)
			if err != nil {
				t.Fatal(err)
			}
			_, err = w.p.ACS(ctx, sso.ACSRequest{SAMLResponse: "x", RelayState: relay.Reveal()})
			c2Want(t, "relay meta "+meta, err, sso.ErrStateInvalid)
		}
		in, _ := w.samlFlow(t, c2SAML)
		in.ProviderID = "another"
		_, err = w.p.ACS(ctx, in)
		c2Want(t, "a relay at another provider's ACS URL", err, sso.ErrStateInvalid)
		for _, relay := range []string{"", "not a provider id!"} {
			_, err = w.p.ACS(ctx, sso.ACSRequest{SAMLResponse: "x", RelayState: relay})
			c2Code(t, "unsolicited relay "+relay, err, sso.SAMLUnsolicited)
		}
		in, _ = w.samlFlow(t, c2SAML)
		in.SAMLResponse = "%%%"
		_, err = w.p.ACS(ctx, in)
		c2Code(t, "a response that is not base64", err, sso.SAMLInvalidEncoding)

		// The AuthnRequest's ID is spent, or was issued for another
		// provider, before the response arrives.
		in, as := w.samlFlow(t, c2SAML)
		if _, err := w.a.ConsumeVerification(bg, sso.PurposeSAMLRequest, auth.Token(as.InResponseTo)); err != nil {
			t.Fatal(err)
		}
		_, err = w.p.ACS(ctx, in)
		c2Code(t, "a spent request ID", err, sso.SAMLUnknownRequest)
		// A relay naming a request ID another provider's flow issued.
		w.register(t, w.samlRequest(t, "acme-other"))
		_, other := w.samlFlow(t, "acme-other")
		pr, err := w.p.ProviderByID(bg, c2SAML)
		if err != nil {
			t.Fatal(err)
		}
		meta, _ := json.Marshal(map[string]any{"p": c2SAML, "r": pr.Reference(), "t": sso.ProtocolSAML, "u": "/", "q": other.InResponseTo})
		relay, err := w.a.IssueVerification(bg, sso.PurposeSAMLRelay, c2SAML, time.Minute, string(meta))
		if err != nil {
			t.Fatal(err)
		}
		as = w.saml.Valid(r31ACS, r31SP, other.InResponseTo, c2Person)
		_, err = w.p.ACS(ctx, sso.ACSRequest{SAMLResponse: w.saml.Response(as), RelayState: relay.Reveal()})
		c2Code(t, "another provider's request ID", err, sso.SAMLUnknownRequest)

		// An assertion with no NameID names nobody.
		in, as = w.samlFlow(t, c2SAML)
		as.NameID, as.Attributes = "", nil
		in.SAMLResponse = w.saml.Response(as)
		_, err = w.p.ACS(ctx, in)
		c2Code(t, "no NameID", err, sso.SAMLMissingSubjectOrEmail)

		// The provider was repointed between the start and the ACS.
		in, _ = w.samlFlow(t, c2SAML)
		cfg := w.samlConfig(t)
		cfg.Audience = r31SP // the effective audience is unchanged; the reference is not
		if _, err := w.p.UpdateProvider(w.as(), sso.UpdateRequest{ProviderID: c2SAML, SAMLConfig: cfg}); err != nil {
			t.Fatal(err)
		}
		_, err = w.p.ACS(ctx, in)
		c2Want(t, "a repointed provider", err, sso.ErrProviderChanged)
		if n := r31Count(t, e, "auth_sso_account", ""); n != 0 {
			t.Fatalf("%d accounts after refusals only", n)
		}
	})
}

// TestC2_SAMLAssertionWithoutTimestamps: an assertion whose Conditions carry
// no time bounds is accepted (RequireTimestamps off) and reserved against
// replay until its subject confirmation expires, the later bound.
func TestC2_SAMLAssertionWithoutTimestamps(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := c2Build(t, e)
		w.register(t, w.samlRequest(t, c2SAML))
		in, as := w.samlFlow(t, c2SAML)
		as.NotBefore, as.NotOnOrAfter, as.ConfirmationNotOnOrAfter = time.Time{}, time.Time{}, time.Now().Add(5*time.Minute)
		in.SAMLResponse = w.saml.Response(as)
		if _, err := w.p.ACS(c2Ctx(w.a, "", ""), in); err != nil {
			t.Fatalf("an assertion without condition times: %v", err)
		}
		// The same assertion answering a fresh request is a replay.
		in2, as2 := w.samlFlow(t, c2SAML)
		as.InResponseTo = as2.InResponseTo
		in2.SAMLResponse = w.saml.Response(as)
		_, err := w.p.ACS(c2Ctx(w.a, "", ""), in2)
		c2Code(t, "a replayed assertion", err, sso.SAMLReplay)
	})
}

// TestC2_SAMLDeprecatedAlgorithms: an RSA-SHA1 signature is accepted with a
// warning under the default policy and refused under DeprecatedReject.
func TestC2_SAMLDeprecatedAlgorithms(t *testing.T) {
	for _, c := range []struct {
		policy sso.DeprecatedPolicy
		ok     bool
	}{{sso.DeprecatedWarn, true}, {sso.DeprecatedReject, false}} {
		eachEngine(t, func(t *testing.T, e *env) {
			w := c2Build(t, e, sso.WithSAMLOptions(sso.SAMLOptions{OnDeprecated: c.policy}))
			w.register(t, w.samlRequest(t, c2SAML+string(c.policy)))
			in, as := w.samlFlow(t, c2SAML+string(c.policy))
			as.SHA1 = true
			in.SAMLResponse = w.saml.Response(as)
			_, err := w.p.ACS(c2Ctx(w.a, "", ""), in)
			if (err == nil) != c.ok {
				t.Fatalf("RSA-SHA1 under %s: %v", c.policy, err)
			}
		})
	}
}

// TestC2_SAMLSkipInResponseTo: with SkipInResponseTo the response is tied to
// the relay state only; the request ID it answers is not checked or spent.
func TestC2_SAMLSkipInResponseTo(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := c2Build(t, e, sso.WithSAMLOptions(sso.SAMLOptions{SkipInResponseTo: true}))
		w.register(t, w.samlRequest(t, c2SAML))
		in, as := w.samlFlow(t, c2SAML)
		as.InResponseTo = "_not-the-request"
		in.SAMLResponse = w.saml.Response(as)
		if _, err := w.p.ACS(c2Ctx(w.a, "", ""), in); err != nil {
			t.Fatalf("SkipInResponseTo: %v", err)
		}
	})
}

// TestC2_SAMLIdPInitiated: an unsolicited response is refused while the
// provider's domain is unproven, and an untrusted landing page configured
// for it falls back to the site root.
func TestC2_SAMLIdPInitiated(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		dns := &r31Resolver{txts: map[string][]string{}}
		w := c2Build(t, e, sso.WithDomainVerification(sso.DomainVerification{Resolver: dns}))
		in := w.samlRequest(t, c2SAML)
		in.SAMLConfig.AllowIdPInitiated, in.SAMLConfig.IdPInitiatedCallbackURL = true, "https://evil.example/landing"
		reg := w.register(t, in)
		as := w.saml.Valid(r31ACS, r31SP, "", c2Person)
		_, err := w.p.ACS(c2Ctx(w.a, "", ""), sso.ACSRequest{SAMLResponse: w.saml.Response(as), RelayState: c2SAML})
		c2Want(t, "IdP-initiated before the domain is proven", err, sso.ErrDomainUnverified)
		dns.txts[sso.DomainRecordName(sso.DefaultDomainTokenPrefix, c2SAML, r31Domain)] = []string{reg.DomainVerificationToken}
		if err := w.p.VerifyDomain(w.as(), c2SAML); err != nil {
			t.Fatal(err)
		}
		as = w.saml.Valid(r31ACS, r31SP, "", c2Person)
		res, err := w.p.ACS(c2Ctx(w.a, "", ""), sso.ACSRequest{SAMLResponse: w.saml.Response(as), RelayState: c2SAML})
		if err != nil || res.RedirectTo != "/" {
			t.Fatalf("an untrusted IdP-initiated landing: %+v %v", res, err)
		}
	})
}

// c2Engine is the GoSAML2 engine with AuthnRequest building failing.
type c2Engine struct{ sso.GoSAML2 }

var errC2Engine = errors.New("c2: engine failure")

func (c2Engine) AuthnRequestURL(sso.SPSettings, sso.IdPSettings, string, string) (string, error) {
	return "", errC2Engine
}

func (c2Engine) AuthnRequestPOST(sso.SPSettings, sso.IdPSettings, string, string) (sso.PostForm, error) {
	return sso.PostForm{}, errC2Engine
}

// TestC2_SAMLStartFailures: an engine that cannot build the AuthnRequest, on
// either binding, is the IdP failing, never a URL or a form; metadata is
// only for SAML providers.
func TestC2_SAMLStartFailures(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := c2Build(t, e, sso.WithSAMLEngine(c2Engine{}))
		w.register(t, w.samlRequest(t, c2SAML))
		post := w.samlRequest(t, "acme-post")
		post.SAMLConfig.SPMetadata.Binding = sso.AuthnBindingPOST
		w.register(t, post)
		for _, id := range []string{c2SAML, "acme-post"} {
			_, err := w.p.SignIn(c2Ctx(w.a, "", ""), sso.SignInRequest{ProviderID: id})
			c2Want(t, "engine failure on "+id, err, sso.ErrProviderFailed)
		}
		w.register(t, w.oidcRequest(c2OIDC))
		_, err := w.p.SPMetadata(w.as(), c2OIDC)
		c2Want(t, "metadata of an OIDC provider", err, sso.ErrProtocol)
		_, err = w.p.SPMetadata(w.as(), "nobody")
		c2Want(t, "metadata of no provider", err, sso.ErrProviderNotFound)
	})
}

// c2Msg describes one logout message from the IdP; zero fields take the
// value a correct message carries.
type c2Msg struct {
	kind, issuer, dest, nameID, index, inResponseTo, status string
	notOnOrAfter                                            time.Time
	param, sigAlg                                           string
	providerID                                              string
}

// slo builds m as the redirect binding carries it, signed by the IdP.
func (w *c2World) slo(t *testing.T, m c2Msg) sso.SLORequest {
	t.Helper()
	slo := testBaseURL + "/auth/sso/saml2/sp/slo"
	var idx []string
	if m.index != "" {
		idx = []string{m.index}
	}
	doc := sso.LogoutDocument(m.kind, "_idp"+auth.NewToken().Reveal(), firstNonEmpty(m.issuer, w.saml.EntityID), firstNonEmpty(m.dest, slo),
		m.nameID, "", idx, m.inResponseTo, firstNonEmpty(m.status, sso.StatusSuccess), w.a.Now())
	if !m.notOnOrAfter.IsZero() {
		doc.Root().CreateAttr("NotOnOrAfter", m.notOnOrAfter.UTC().Format(time.RFC3339))
	}
	param := m.param
	if param == "" {
		param = "SAMLRequest"
		if m.kind == sso.KindLogoutResponse {
			param = "SAMLResponse"
		}
	}
	u, err := sso.RedirectURL(slo, param, doc, "", w.saml.Signer(), firstNonEmpty(m.sigAlg, sso.AlgRSASHA256))
	if err != nil {
		t.Fatal(err)
	}
	pu, _ := url.Parse(u)
	q := pu.Query()
	return sso.SLORequest{SAMLRequest: q.Get("SAMLRequest"), SAMLResponse: q.Get("SAMLResponse"), SigAlg: q.Get("SigAlg"), Signature: q.Get("Signature"), ProviderID: m.providerID}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// pendingLogout signs in through SAML, starts an SP-initiated logout, and
// returns the LogoutRequest's ID.
func (w *c2World) pendingLogout(t *testing.T) string {
	t.Helper()
	res, err := w.samlSignIn(t, c2SAML)
	if err != nil {
		t.Fatal(err)
	}
	out, err := w.p.InitiateSLO(c2Ctx(w.a, res.Token, ""), sso.LogoutRequest{CallbackURL: "/bye"})
	if err != nil {
		t.Fatal(err)
	}
	pu, _ := url.Parse(out.URL)
	lr, err := sso.PeekLogout(sso.BindingMessage{Redirect: true, Param: "SAMLRequest", Value: pu.Query().Get("SAMLRequest")}, sso.DefaultMaxResponseSize)
	if err != nil {
		t.Fatal(err)
	}
	return lr.ID
}

// TestC2_SingleLogoutRefusals: every logout message that is not exactly
// what this IdP would send for this SP is refused, each with its answer;
// a request naming no live session still answers Success, as SAML asks.
func TestC2_SingleLogoutRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := c2Build(t, e, sso.WithSAMLOptions(sso.SAMLOptions{EnableSingleLogout: true, OnDeprecated: sso.DeprecatedReject}))
		w.register(t, w.samlRequest(t, c2SAML))
		w.register(t, w.oidcRequest(c2OIDC)) // passed over when finding the IdP by entity id
		ctx := c2Ctx(w.a, "", "")
		slo := func(m c2Msg) error { _, err := w.p.SLO(ctx, w.slo(t, m)); return err }

		_, err := w.p.SLO(ctx, sso.SLORequest{})
		c2Want(t, "neither message", err, sso.ErrInvalidLogoutRequest)
		_, err = w.p.SLO(ctx, sso.SLORequest{SAMLRequest: "x", SAMLResponse: "y"})
		c2Want(t, "both messages", err, sso.ErrInvalidLogoutRequest)
		_, err = w.p.SLO(ctx, sso.SLORequest{SAMLRequest: "%%%"})
		c2Code(t, "a request that is not base64", err, sso.SAMLInvalidEncoding)

		req := c2Msg{kind: sso.KindLogoutRequest, nameID: c2Person}
		bad := req
		bad.sigAlg = sso.AlgRSASHA1
		c2Want(t, "RSA-SHA1 under reject", slo(bad), sso.ErrSAMLInvalid)
		bad = req
		bad.kind, bad.param = sso.KindLogoutResponse, "SAMLRequest"
		c2Want(t, "a response sent as a request", slo(bad), sso.ErrInvalidLogoutRequest)
		bad = req
		bad.dest = testBaseURL + "/elsewhere"
		c2Code(t, "another destination", slo(bad), sso.SAMLDestinationMismatch)
		bad = req
		bad.notOnOrAfter = w.a.Now().Add(-time.Hour)
		c2Code(t, "an expired request", slo(bad), sso.SAMLExpired)
		bad = req
		bad.nameID = ""
		c2Want(t, "no NameID", slo(bad), sso.ErrInvalidLogoutRequest)
		bad = req
		bad.issuer = "https://idp.example.com/unknown"
		c2Want(t, "an issuer no provider has", slo(bad), sso.ErrProviderNotFound)
		bad.providerID = c2SAML
		c2Code(t, "another issuer for a named provider", slo(bad), sso.SAMLIssuerMismatch)
		bad = req
		bad.providerID = c2OIDC
		c2Want(t, "a request naming an OIDC provider", slo(bad), sso.ErrProviderNotFound)

		// No session index and no live session: nothing to end, and Success.
		out, err := w.p.SLO(ctx, w.slo(t, req))
		if err != nil || !strings.Contains(out.URL, r31IdPSLO+"?SAMLResponse=") {
			t.Fatalf("a request for no live session: %+v %v", out, err)
		}

		// Answers to an SP-initiated logout.
		resp := func(id string) c2Msg { return c2Msg{kind: sso.KindLogoutResponse, inResponseTo: id} }
		m := resp(w.pendingLogout(t))
		m.kind, m.param = sso.KindLogoutRequest, "SAMLResponse"
		c2Want(t, "a request sent as a response", slo(m), sso.ErrInvalidLogoutResponse)
		m = resp(w.pendingLogout(t))
		m.issuer = "https://idp.example.com/other"
		c2Code(t, "a response from another issuer", slo(m), sso.SAMLIssuerMismatch)
		m = resp(w.pendingLogout(t))
		m.dest = testBaseURL + "/elsewhere"
		c2Code(t, "a response to another destination", slo(m), sso.SAMLDestinationMismatch)
		m = resp(w.pendingLogout(t))
		m.status = "urn:oasis:names:tc:SAML:2.0:status:Requester"
		c2Want(t, "a failed logout at the IdP", slo(m), sso.ErrLogoutFailedAtIdP)
		m = resp(w.pendingLogout(t))
		m.providerID = c2OIDC
		c2Want(t, "a response at another provider's SLO URL", slo(m), sso.ErrInvalidLogoutResponse)
		c2Want(t, "a response to no pending request", slo(resp("_unknown")), sso.ErrInvalidLogoutResponse)

		// A logout with a callback this site does not trust is refused
		// before anything is ended.
		res, err := w.samlSignIn(t, c2SAML)
		if err != nil {
			t.Fatal(err)
		}
		_, err = w.p.InitiateSLO(c2Ctx(w.a, res.Token, ""), sso.LogoutRequest{CallbackURL: "https://evil.example/"})
		c2Want(t, "an untrusted logout callback", err, sso.ErrBadReturnTo)
		if _, err := w.a.Session(c2Ctx(w.a, res.Token, "")); err != nil {
			t.Fatalf("the refused logout ended the session: %v", err)
		}
	})
}

// TestC2_SingleLogoutAmbiguousAndUnsupported: an issuer two providers share
// names neither, and a provider whose IdP publishes no SLO endpoint cannot
// start or answer a logout.
func TestC2_SingleLogoutAmbiguousAndUnsupported(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := c2Build(t, e, sso.WithSAMLOptions(sso.SAMLOptions{EnableSingleLogout: true}))
		in := w.samlRequest(t, c2SAML)
		in.SAMLConfig.IdPMetadata.SingleLogoutService = nil
		w.register(t, in)
		res, err := w.samlSignIn(t, c2SAML)
		if err != nil {
			t.Fatal(err)
		}
		_, err = w.p.InitiateSLO(c2Ctx(w.a, res.Token, ""), sso.LogoutRequest{})
		c2Want(t, "SP-initiated logout without an IdP SLO URL", err, sso.ErrSLOUnsupported)
		res, err = w.samlSignIn(t, c2SAML)
		if err != nil {
			t.Fatal(err)
		}
		_, err = w.p.SLO(c2Ctx(w.a, "", ""), w.slo(t, c2Msg{kind: sso.KindLogoutRequest, nameID: c2Person}))
		c2Want(t, "IdP-initiated logout without an IdP SLO URL", err, sso.ErrSLOUnsupported)

		w.register(t, w.samlRequest(t, "acme-twin"))
		_, err = w.p.SLO(c2Ctx(w.a, "", ""), w.slo(t, c2Msg{kind: sso.KindLogoutRequest, nameID: c2Person}))
		c2Want(t, "an issuer two providers share", err, sso.ErrProviderNotFound)
	})
}

// TestC2_OIDCCallbackRefusals: a callback that does not complete the flow
// this browser started, at this provider, is refused before any token is
// redeemed; a failure at the IdP keeps its own answer.
func TestC2_OIDCCallbackRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := c2Build(t, e)
		w.register(t, w.oidcRequest(c2OIDC))
		bg := context.Background()
		cb := func(flow auth.Token, in sso.CallbackRequest) error {
			_, err := w.p.Callback(c2Ctx(w.a, "", flow), in)
			return err
		}
		c2Want(t, "an error from the IdP", cb("", sso.CallbackRequest{Error: "access_denied"}), sso.ErrProviderDenied)
		stray := auth.NewToken()
		c2Want(t, "a state that names no flow", cb(stray, sso.CallbackRequest{Code: "c", State: stray.Reveal()}), sso.ErrStateInvalid)
		for _, meta := range []string{"{", `{"p":"someone-else"}`} {
			st, err := w.a.IssueVerification(bg, sso.PurposeState, c2OIDC, time.Minute, meta)
			if err != nil {
				t.Fatal(err)
			}
			c2Want(t, "state meta "+meta, cb(st, sso.CallbackRequest{Code: "c", State: st.Reveal()}), sso.ErrStateInvalid)
		}
		// RFC 9207: an iss parameter naming another issuer is a mix-up. The
		// flow names an error page, which the refusal then uses.
		in, flow := w.oidcFlow(t, sso.SignInRequest{ProviderID: c2OIDC, ErrorCallbackURL: "/oops", NewUserCallbackURL: "/welcome"})
		in.Iss = "https://other-idp.example.com"
		c2Want(t, "another iss", cb(flow, in), sso.ErrStateInvalid)
		// A code the IdP does not know is the exchange failing.
		in, flow = w.oidcFlow(t, sso.SignInRequest{ProviderID: c2OIDC})
		in.Code = "not-a-code"
		c2Want(t, "an unknown code", cb(flow, in), sso.ErrTokenExchange)
		// The provider's iss parameter, with its trailing slash, passes; the
		// new user lands on NewUserCallbackURL.
		in, flow = w.oidcFlow(t, sso.SignInRequest{ProviderID: c2OIDC, NewUserCallbackURL: "/welcome"})
		in.Iss = w.oidc.Issuer() + "/"
		res, err := w.p.Callback(c2Ctx(w.a, "", flow), in)
		if err != nil || !res.Created || res.RedirectTo != "/welcome" {
			t.Fatalf("a correct iss: %+v %v", res, err)
		}
	})
}

// TestC2_OIDCSignInParameters: extra authorization parameters reach the
// IdP unless the flow owns them, untrusted landing pages are refused, and
// a protocol the provider does not offer is ErrProtocol.
func TestC2_OIDCSignInParameters(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := c2Build(t, e)
		w.register(t, w.oidcRequest(c2OIDC))
		w.register(t, w.samlRequest(t, c2SAML))
		ctx := c2Ctx(w.a, "", "")
		out, err := w.p.SignIn(ctx, sso.SignInRequest{ProviderID: c2OIDC, AdditionalParams: map[string]string{"prompt": "login"}})
		if err != nil || !strings.Contains(out.URL, "prompt=login") {
			t.Fatalf("an extra parameter: %+v %v", out, err)
		}
		_, err = w.p.SignIn(ctx, sso.SignInRequest{ProviderID: c2OIDC, AdditionalParams: map[string]string{"State": "x"}})
		c2Want(t, "a parameter the flow owns", err, sso.ErrBadParams)
		_, err = w.p.SignIn(ctx, sso.SignInRequest{ProviderID: c2SAML, Scopes: []string{"openid"}})
		c2Want(t, "scopes on a SAML sign-in", err, sso.ErrBadParams)
		for _, in := range []sso.SignInRequest{{ProviderID: c2OIDC, ErrorCallbackURL: "https://evil.example/"}, {ProviderID: c2OIDC, NewUserCallbackURL: "https://evil.example/"}} {
			_, err = w.p.SignIn(ctx, in)
			c2Want(t, "an untrusted landing page", err, sso.ErrBadReturnTo)
		}
		_, err = w.p.SignIn(ctx, sso.SignInRequest{ProviderID: c2OIDC, ProviderType: sso.ProtocolOIDC})
		if err != nil {
			t.Fatalf("an offered protocol: %v", err)
		}
		_, err = w.p.SignIn(ctx, sso.SignInRequest{ProviderID: c2OIDC, ProviderType: sso.ProtocolSAML})
		c2Want(t, "a protocol not offered", err, sso.ErrProtocol)
		_, err = w.p.SignIn(ctx, sso.SignInRequest{Email: "no-at-sign"})
		c2Want(t, "an email without a domain", err, sso.ErrProviderNotFound)
		_, err = w.p.SignIn(ctx, sso.SignInRequest{Domain: "   "})
		c2Want(t, "a blank domain", err, sso.ErrProviderNotFound)
		_, err = w.p.SignIn(ctx, sso.SignInRequest{OrganizationSlug: "acme"})
		c2Want(t, "an organization without WithOrganizations", err, sso.ErrProviderNotFound)
	})
}

// TestC2_OIDCRuntimeDiscoveryAndEndpoints: a default provider is discovered
// at its first sign-in (and a dead issuer fails that sign-in, not boot); a
// default provider with every endpoint written skips discovery and signs
// in with client_secret_basic; an endpoint at an untrusted origin is
// refused at registration.
func TestC2_OIDCRuntimeDiscoveryAndEndpoints(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		idp := ssotest.NewOIDC(t)
		dead := httptest.NewServer(http.NotFoundHandler())
		dead.Close()
		w := c2Build(t, e, sso.WithTrustedOrigins(idp.URL, dead.URL), sso.WithDefaultProviders(
			sso.Provider{ProviderID: "corp", Issuer: idp.Issuer(), Domain: "corp.test", OIDC: &sso.OIDCConfig{ClientID: idp.ClientID, ClientSecret: idp.ClientSecret}},
			sso.Provider{ProviderID: "gone", Issuer: dead.URL, Domain: "gone.test", OIDC: &sso.OIDCConfig{ClientID: "c", ClientSecret: "s"}},
			sso.Provider{ProviderID: "direct", Issuer: idp.Issuer(), Domain: "direct.test", OIDC: &sso.OIDCConfig{ClientID: idp.ClientID, ClientSecret: idp.ClientSecret,
				AuthorizationEndpoint: idp.URL + "/authorize", TokenEndpoint: idp.URL + "/token", JWKSEndpoint: idp.URL + "/jwks"}},
		))
		w.oidc = idp
		res, err := w.oidcSignIn(t, sso.SignInRequest{Email: "ada@corp.test"})
		if err != nil || !res.Created {
			t.Fatalf("a default provider discovered at sign-in: %+v %v", res, err)
		}
		_, err = w.p.SignIn(c2Ctx(w.a, "", ""), sso.SignInRequest{ProviderID: "gone"})
		var de *sso.DiscoveryError
		if !errors.As(err, &de) {
			t.Fatalf("a dead issuer: %v", err)
		}

		w.oidc.Person.Subject, w.oidc.Person.Email = "sub-2", "ada@direct.test"
		if _, err := w.oidcSignIn(t, sso.SignInRequest{ProviderID: "direct"}); err != nil {
			t.Fatalf("written endpoints, no discovery, basic authentication: %v", err)
		}
		in := w.oidcRequest("acme-bad-url")
		in.OIDCConfig.TokenEndpoint = "https://10.0.0.1/token"
		_, err = w.p.RegisterProvider(w.as(), in)
		if !errors.As(err, &de) || de.Code != sso.DiscoveryPrivateHost {
			t.Fatalf("an endpoint at a private address: %v", err)
		}
	})
}

// TestC2_OIDCUserInfo: userinfo adds the claims the ID token lacks (and
// never replaces one it has); an unreachable userinfo endpoint fails the
// sign-in as an incomplete exchange rather than signing in with less than
// the provider promised.
func TestC2_OIDCUserInfo(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var got sso.UserInfo
		w := c2Build(t, e, sso.WithProvisionUser(func(_ context.Context, _ *auth.Call, ev sso.ProvisionEvent) error { got = ev.Info; return nil }))
		in := w.oidcRequest(c2OIDC)
		in.OIDCConfig.Mapping.ExtraFields = map[string]string{"dept": "department"}
		w.register(t, in)
		cb, flow := w.oidcFlow(t, sso.SignInRequest{ProviderID: c2OIDC})
		w.oidc.Person.Extra = map[string]any{"department": "R&D", "name": "From userinfo"}
		if _, err := w.p.Callback(c2Ctx(w.a, "", flow), cb); err != nil {
			t.Fatal(err)
		}
		if got.Extra["dept"] != "R&D" || got.Name != "Ada" {
			t.Fatalf("userinfo merge: extra %v name %q", got.Extra, got.Name)
		}

		in = w.oidcRequest("acme-broken-userinfo")
		in.OIDCConfig.UserInfoEndpoint = w.oidc.URL + "/missing"
		w.register(t, in)
		_, err := w.oidcSignIn(t, sso.SignInRequest{ProviderID: "acme-broken-userinfo"})
		c2Want(t, "an unreachable userinfo endpoint", err, sso.ErrTokenExchange)
	})
}

// c2FailingOrgs is an organization system whose every call fails.
type c2FailingOrgs struct{}

var errC2Orgs = errors.New("c2: organizations unavailable")

func (c2FailingOrgs) Role(context.Context, string, string) (string, bool, error) {
	return "", false, errC2Orgs
}
func (c2FailingOrgs) BySlug(context.Context, string) (string, bool, error) {
	return "", false, errC2Orgs
}
func (c2FailingOrgs) AddMember(context.Context, string, string, string) error {
	return errC2Orgs
}

// TestC2_RegistrationRefusals: who may register what, and how many.
func TestC2_RegistrationRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := c2Build(t, e, sso.ProvidersLimit(0))
		_, err := w.p.RegisterProvider(w.as(), w.oidcRequest(c2OIDC))
		c2Want(t, "registration off", err, sso.ErrRegistrationOff)
	})
	eachEngine(t, func(t *testing.T, e *env) {
		var asked string
		w := c2Build(t, e, sso.WithProvidersLimit(func(_ context.Context, u auth.User) int { asked = u.ID; return 1 }),
			sso.ReserveProviderIDs("payroll"), sso.WithDomainVerification(sso.DomainVerification{Resolver: &r31Resolver{}}))
		w.register(t, w.oidcRequest(c2OIDC))
		if asked != w.uid {
			t.Fatalf("the limit was asked for %q", asked)
		}
		_, err := w.p.RegisterProvider(w.as(), w.oidcRequest("second"))
		c2Want(t, "over the limit", err, sso.ErrProvidersLimit)
		_, err = w.p.RegisterProvider(w.as(), w.oidcRequest("PAYROLL"))
		c2Want(t, "a reserved id", err, sso.ErrProviderIDReserved)
		_, err = w.p.RegisterProvider(w.as(), w.oidcRequest(strings.Repeat("x", 63)))
		c2Want(t, "an id too long for its DNS label", err, sso.ErrIdentifierTooLong)
	})
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := newTokensNative("alpha", "a-1")
		w := c2BuildWith(t, e, nil, []auth.Plugin{oauth.New(oauth.WithProviders(alpha))})
		_, err := w.p.RegisterProvider(w.as(), w.oidcRequest("alpha"))
		c2Want(t, "an id plugin/oauth already uses", err, sso.ErrProviderIDReserved)
	})
}

// TestC2_OrganizationManagement: an organization's provider is managed by
// its owners and admins only; a plain member is forbidden, a stranger is
// not a member, and a failing organization system fails the call.
func TestC2_OrganizationManagement(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		orgs := &r31Orgs{roles: map[string]string{}}
		w := c2Build(t, e, sso.WithOrganizations(orgs, sso.OrganizationProvisioning{}))
		in := w.oidcRequest(c2OIDC)
		in.OrganizationID = "org-1"
		_, err := w.p.RegisterProvider(w.as(), in)
		c2Want(t, "a stranger registers for an organization", err, sso.ErrNotMember)
		orgs.roles["org-1/"+w.uid] = sso.RoleMember
		_, err = w.p.RegisterProvider(w.as(), in)
		c2Want(t, "a plain member registers", err, sso.ErrForbidden)
		orgs.roles["org-1/"+w.uid] = sso.RoleAdmin
		w.register(t, in)
		if got, err := w.p.GetProvider(w.as(), c2OIDC); err != nil || got.OrganizationID != "org-1" {
			t.Fatalf("an admin reads the provider: %+v %v", got, err)
		}
		uid2, tok2 := identUser(t, w.a, "member@corp.test")
		orgs.roles["org-1/"+uid2] = sso.RoleMember
		member := c2Ctx(w.a, tok2, "")
		_, err = w.p.GetProvider(member, c2OIDC)
		c2Want(t, "a plain member reads it", err, sso.ErrForbidden)
		if l, err := w.p.ListProviders(member); err != nil || len(l.Providers) != 0 {
			t.Fatalf("a plain member's list: %+v %v", l, err)
		}
		if l, err := w.p.ListProviders(w.as()); err != nil || len(l.Providers) != 1 {
			t.Fatalf("an admin's list: %+v %v", l, err)
		}
		// Sign-in by organization slug.
		if _, err := w.p.SignIn(c2Ctx(w.a, "", ""), sso.SignInRequest{OrganizationSlug: "acme"}); err != nil {
			t.Fatalf("sign-in by slug: %v", err)
		}
		_, err = w.p.SignIn(c2Ctx(w.a, "", ""), sso.SignInRequest{OrganizationSlug: "nobody"})
		c2Want(t, "an unknown slug", err, sso.ErrProviderNotFound)
	})
	eachEngine(t, func(t *testing.T, e *env) {
		orgs := &r31Orgs{roles: map[string]string{}}
		w := c2Build(t, e, sso.WithOrganizations(orgs, sso.OrganizationProvisioning{}), sso.WithDefaultProviders(sso.Provider{ProviderID: "corp", Issuer: "https://corp.example.com",
			Domain: "corp.test", OrganizationID: "org-1", OIDC: &sso.OIDCConfig{ClientID: "c", ClientSecret: "s",
				AuthorizationEndpoint: "https://corp.example.com/a", TokenEndpoint: "https://corp.example.com/t", JWKSEndpoint: "https://corp.example.com/j"}}))
		out, err := w.p.SignIn(c2Ctx(w.a, "", ""), sso.SignInRequest{OrganizationSlug: "acme"})
		if err != nil || !strings.HasPrefix(out.URL, "https://corp.example.com/a") {
			t.Fatalf("an organization's default provider: %+v %v", out, err)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		orgs := &r31Orgs{roles: map[string]string{}}
		w := c2Build(t, e, sso.WithOrganizations(orgs, sso.OrganizationProvisioning{}))
		_, err := w.p.SignIn(c2Ctx(w.a, "", ""), sso.SignInRequest{OrganizationSlug: "acme"})
		c2Want(t, "an organization with no provider", err, sso.ErrProviderNotFound)
	})
	eachEngine(t, func(t *testing.T, e *env) {
		w := c2Build(t, e, sso.WithOrganizations(c2FailingOrgs{}, sso.OrganizationProvisioning{}))
		in := w.oidcRequest(c2OIDC)
		in.OrganizationID = "org-1"
		_, err := w.p.RegisterProvider(w.as(), in)
		c2Want(t, "a failing organization system at registration", err, errC2Orgs)
		_, err = w.p.SignIn(c2Ctx(w.a, "", ""), sso.SignInRequest{OrganizationSlug: "acme"})
		c2Want(t, "a failing organization system at sign-in", err, errC2Orgs)
	})
}

// TestC2_UpdateProvider: an update merges fields, keeps the stored secret
// when none is sent, re-checks the configuration, runs the guard, and
// refuses to repoint a provider accounts are linked to.
func TestC2_UpdateProvider(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var guard error
		var seen sso.MutationInput
		w := c2Build(t, e, sso.WithProviderFields(sso.ProviderField{Name: "tier"}, sso.ProviderField{Name: "plan"}, sso.ProviderField{Name: "internal", NoInput: true}),
			sso.WithMutationGuard(func(_ context.Context, _ *auth.Call, in sso.MutationInput) error { seen = in; return guard }))
		in := w.oidcRequest(c2OIDC)
		in.AdditionalFields = map[string]any{"tier": "silver"}
		w.register(t, in)

		up, err := w.p.UpdateProvider(w.as(), sso.UpdateRequest{ProviderID: c2OIDC, AdditionalFields: map[string]any{"plan": "pro"}})
		if err != nil || up.AdditionalFields["tier"] != "silver" || up.AdditionalFields["plan"] != "pro" {
			t.Fatalf("fields merge: %+v %v", up.AdditionalFields, err)
		}
		_, err = w.p.UpdateProvider(w.as(), sso.UpdateRequest{ProviderID: c2OIDC, AdditionalFields: map[string]any{"internal": "x"}})
		c2Want(t, "a NoInput field", err, sso.ErrFieldNotAllowed)
		bad := "https://elsewhere.example.com"
		_, err = w.p.UpdateProvider(w.as(), sso.UpdateRequest{ProviderID: c2OIDC, Issuer: &bad})
		var de *sso.DiscoveryError
		if !errors.As(err, &de) {
			t.Fatalf("an issuer that cannot be discovered: %v", err)
		}
		// A new client id with no secret keeps the stored secret.
		if _, err := w.p.UpdateProvider(w.as(), sso.UpdateRequest{ProviderID: c2OIDC, OIDCConfig: &sso.OIDCConfig{ClientID: w.oidc.ClientID}}); err != nil {
			t.Fatal(err)
		}
		if seen.Action != sso.MutationUpdate || seen.Next.OIDC == nil || seen.Next.OIDC.ClientSecret != w.oidc.ClientSecret {
			t.Fatalf("the guard did not see the kept secret: %+v", seen)
		}
		if _, err := w.oidcSignIn(t, sso.SignInRequest{ProviderID: c2OIDC}); err != nil {
			t.Fatalf("the kept secret does not sign in: %v", err)
		}
		// Now an account is linked: repointing is locked; a guard refusal
		// is ErrMutationRejected unless it is an answer of its own.
		_, err = w.p.UpdateProvider(w.as(), sso.UpdateRequest{ProviderID: c2OIDC, OIDCConfig: &sso.OIDCConfig{ClientID: "client-2"}})
		c2Want(t, "repointing a provider with linked accounts", err, sso.ErrBoundaryLocked)
		guard = errors.New("no changes on Fridays")
		_, err = w.p.UpdateProvider(w.as(), sso.UpdateRequest{ProviderID: c2OIDC, AdditionalFields: map[string]any{"plan": "free"}})
		c2Want(t, "a guard refusal", err, sso.ErrMutationRejected)
		guard = sso.ErrForbidden
		err = w.p.DeleteProvider(w.as(), c2OIDC)
		c2Want(t, "a guard's own answer", err, sso.ErrForbidden)

		w.register(t, w.samlRequest(t, c2SAML))
		cfg := w.samlConfig(t)
		cfg.PrivateKey = ""
		guard = nil
		up, err = w.p.UpdateProvider(w.as(), sso.UpdateRequest{ProviderID: c2SAML, SAMLConfig: cfg})
		if err != nil || up.SAML == nil {
			t.Fatalf("a SAML update without the key: %+v %v", up, err)
		}
		pr, err := w.p.ProviderByID(context.Background(), c2SAML)
		if err != nil || pr.SAML.PrivateKey == "" {
			t.Fatalf("the stored SAML key was dropped: %v", err)
		}
	})
}

// TestC2_ResolveRules: the sign-in resolution paths the round-31 tests do
// not reach.
func TestC2_ResolveRules(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var refuse error
		var linkTo string
		w := c2Build(t, e, sso.DefaultOverrideUserInfo(), sso.ProvisionUserOnEveryLogin(),
			sso.WithProvisionUser(func(context.Context, *auth.Call, sso.ProvisionEvent) error { return refuse }),
			sso.WithResolveUser(func(context.Context, *auth.Call, sso.ResolveInput) (sso.Decision, error) {
				if linkTo != "" {
					return sso.Decision{Action: sso.ResolveLink, UserID: linkTo}, nil
				}
				return sso.Decision{}, nil
			}))
		w.register(t, w.oidcRequest(c2OIDC))

		// An address the email plugin cannot read signs up without one.
		w.oidc.Person.Email = "not@an@address"
		res, err := w.oidcSignIn(t, sso.SignInRequest{ProviderID: c2OIDC})
		if err != nil || !res.Created {
			t.Fatalf("an unreadable address: %+v %v", res, err)
		}
		// Every sign-in provisions; a plain refusal is ErrUserRejected, an
		// answer of its own passes through.
		refuse = errors.New("suspended upstream")
		_, err = w.oidcSignIn(t, sso.SignInRequest{ProviderID: c2OIDC})
		c2Want(t, "a provisioning refusal", err, sso.ErrUserRejected)
		refuse = sso.ErrSignUpDisabled
		_, err = w.oidcSignIn(t, sso.SignInRequest{ProviderID: c2OIDC})
		c2Want(t, "a provisioning answer", err, sso.ErrSignUpDisabled)
		refuse = nil

		// DefaultOverrideUserInfo copies an https picture, drops any other,
		// and leaves a user with neither name nor picture as it is.
		w.oidc.Person = ssotest.Person{Subject: "sub-1", Name: "Ada Renamed", Extra: map[string]any{"picture": "https://img.example.com/a.png"}}
		res, err = w.oidcSignIn(t, sso.SignInRequest{ProviderID: c2OIDC})
		if err != nil || res.User.Name != "Ada Renamed" || res.User.Image != "https://img.example.com/a.png" {
			t.Fatalf("override: %+v %v", res.User, err)
		}
		w.oidc.Person = ssotest.Person{Subject: "sub-1", Extra: map[string]any{"picture": "http://img.example.com/a.png"}}
		res, err = w.oidcSignIn(t, sso.SignInRequest{ProviderID: c2OIDC})
		if err != nil || res.User.Name != "Ada Renamed" || res.User.Image != "https://img.example.com/a.png" {
			t.Fatalf("an empty override changed the user: %+v %v", res.User, err)
		}

		// A resolve decision to link to a user who does not exist fails.
		linkTo = "usr_missing"
		w.oidc.Person = ssotest.Person{Subject: "sub-9"}
		_, err = w.oidcSignIn(t, sso.SignInRequest{ProviderID: c2OIDC})
		c2Want(t, "a link to no user", err, auth.ErrUserNotFound)
	})
}

// TestC2_ProviderForDomain: under domain verification an unverified
// provider is still the answer when it is the only one, exact before
// parent, so its sign-in fails as unverified rather than not found.
func TestC2_ProviderForDomain(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := c2Build(t, e, sso.WithDomainVerification(sso.DomainVerification{Resolver: &r31Resolver{}}))
		w.register(t, w.oidcRequest(c2OIDC))
		ctx := context.Background()
		for _, d := range []string{r31Domain, "eng." + r31Domain} {
			pr, err := w.p.ProviderForDomain(ctx, d)
			if err != nil || pr.ProviderID != c2OIDC {
				t.Fatalf("%s: %+v %v", d, pr, err)
			}
		}
		_, err := w.p.SignIn(c2Ctx(w.a, "", ""), sso.SignInRequest{Email: "x@eng." + r31Domain})
		c2Want(t, "an unverified provider", err, sso.ErrDomainUnverified)
		if _, err := w.p.ProviderForDomain(ctx, "other.test"); !errors.Is(err, sso.ErrProviderNotFound) {
			t.Fatalf("an unknown domain: %v", err)
		}
	})
}

// c2Corrupt overwrites one column of a stored provider, as a bad restore or
// a hand edit would.
func c2Corrupt(t *testing.T, e *env, providerID, column, value string) {
	t.Helper()
	q := "UPDATE " + tbl("auth_sso_provider") + " SET " + column + " = ? WHERE provider_id = ?"
	if e.engine == auth.EnginePostgres {
		q = "UPDATE " + tbl("auth_sso_provider") + " SET " + column + " = $1 WHERE provider_id = $2"
	}
	if _, err := e.db.Exec(q, value, providerID); err != nil {
		t.Fatal(err)
	}
}

// TestC2_CorruptProviderRows: a stored provider whose JSON or sealed
// secret does not open is an error on every read — never a provider with
// its secret or key silently missing — and a SAML config whose keys or IdP
// settings do not parse fails each operation that needs them.
func TestC2_CorruptProviderRows(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := c2Build(t, e, sso.WithSAMLOptions(sso.SAMLOptions{EnableSingleLogout: true}))
		bg := context.Background()
		for _, c := range []struct{ column, value string }{
			{"fields", "{"},
			{"oidc_config", "{"},
			{"oidc_config", `{"clientId":"c","clientSecretSealed":"not-sealed"}`},
			{"saml_config", "{"},
			{"saml_config", `{"privateKeySealed":"not-sealed"}`},
		} {
			id := "acme-" + strings.ReplaceAll(c.column, "_", "-")
			if _, err := w.p.ProviderByID(bg, id); errors.Is(err, sso.ErrProviderNotFound) {
				w.register(t, w.oidcRequest(id))
			}
			c2Corrupt(t, e, id, c.column, c.value)
			if _, err := w.p.ProviderByID(bg, id); err == nil || errors.Is(err, sso.ErrProviderNotFound) {
				t.Errorf("%s = %s: %v", c.column, c.value, err)
			}
			if _, err := w.p.ListProviders(w.as()); err == nil {
				t.Errorf("a list over %s = %s answered", c.column, c.value)
			}
			if _, err := e.db.Exec("DELETE FROM " + tbl("auth_sso_provider")); err != nil {
				t.Fatal(err)
			}
		}

		// A SAML provider with a session, then its stored config broken
		// two ways: a key that is not a key, and IdP metadata that is not XML.
		w.register(t, w.samlRequest(t, c2SAML))
		res, err := w.samlSignIn(t, c2SAML)
		if err != nil {
			t.Fatal(err)
		}
		in, _ := w.samlFlow(t, c2SAML)
		pr, _ := w.p.ProviderByID(bg, c2SAML)
		badKey := *pr.SAML
		badKey.PrivateKey = "not a key"
		raw, _ := json.Marshal(badKey)
		c2Corrupt(t, e, c2SAML, "saml_config", string(raw))
		_, err = w.p.SignIn(c2Ctx(w.a, "", ""), sso.SignInRequest{ProviderID: c2SAML})
		c2Want(t, "sign-in with a broken key", err, sso.ErrBadProvider)
		_, err = w.p.ACS(c2Ctx(w.a, "", ""), in)
		c2Want(t, "ACS with a broken key", err, sso.ErrBadProvider)
		_, err = w.p.SPMetadata(w.as(), c2SAML)
		c2Want(t, "metadata with a broken key", err, sso.ErrBadProvider)
		_, err = w.p.SLO(c2Ctx(w.a, "", ""), w.slo(t, c2Msg{kind: sso.KindLogoutRequest, nameID: c2Person}))
		c2Want(t, "IdP logout with a broken key", err, sso.ErrBadProvider)
		_, err = w.p.InitiateSLO(c2Ctx(w.a, res.Token, ""), sso.LogoutRequest{})
		c2Want(t, "SP logout with a broken key", err, sso.ErrBadProvider)

		// A signature algorithm no hash backs (only a hand edit makes one):
		// both logout directions fail rather than send an unsigned message.
		badAlg := *pr.SAML
		badAlg.SignatureAlgorithm = "urn:c2:no-such-algorithm"
		raw, _ = json.Marshal(badAlg)
		c2Corrupt(t, e, c2SAML, "saml_config", string(raw))
		_, err = w.p.SLO(c2Ctx(w.a, "", ""), w.slo(t, c2Msg{kind: sso.KindLogoutRequest, nameID: c2Person}))
		if err == nil {
			t.Fatal("an IdP logout answered with no usable signature algorithm")
		}
		if _, err = w.p.InitiateSLO(c2Ctx(w.a, res.Token, ""), sso.LogoutRequest{}); err == nil {
			t.Fatal("an SP logout started with no usable signature algorithm")
		}

		res, err = func() (sso.CallbackResult, error) {
			raw, _ := json.Marshal(*pr.SAML)
			c2Corrupt(t, e, c2SAML, "saml_config", string(raw)) // the key unsealed in the clear, still readable
			return w.samlSignIn(t, c2SAML)
		}()
		if err != nil {
			t.Fatal(err)
		}
		in, _ = w.samlFlow(t, c2SAML)
		badIdP := *pr.SAML
		badIdP.IdPMetadata.Metadata, badIdP.AllowIdPInitiated = "<EntityDescriptor", true
		raw, _ = json.Marshal(badIdP)
		c2Corrupt(t, e, c2SAML, "saml_config", string(raw))
		_, err = w.p.SignIn(c2Ctx(w.a, "", ""), sso.SignInRequest{ProviderID: c2SAML})
		c2Want(t, "sign-in with broken IdP metadata", err, sso.ErrBadProvider)
		// The metadata is part of the provider's reference, so a flow begun
		// before the change is refused as repointed; an unsolicited
		// response, which has no flow, meets the broken metadata itself.
		_, err = w.p.ACS(c2Ctx(w.a, "", ""), in)
		c2Want(t, "ACS of a flow begun before the metadata broke", err, sso.ErrProviderChanged)
		as := w.saml.Valid(r31ACS, r31SP, "", c2Person)
		_, err = w.p.ACS(c2Ctx(w.a, "", ""), sso.ACSRequest{SAMLResponse: w.saml.Response(as), RelayState: c2SAML})
		c2Want(t, "IdP-initiated ACS with broken IdP metadata", err, sso.ErrBadProvider)
		_, err = w.p.SLO(c2Ctx(w.a, "", ""), w.slo(t, c2Msg{kind: sso.KindLogoutRequest, nameID: c2Person, providerID: c2SAML}))
		c2Want(t, "IdP logout with broken IdP metadata", err, sso.ErrBadProvider)
		_, err = w.p.InitiateSLO(c2Ctx(w.a, res.Token, ""), sso.LogoutRequest{})
		c2Want(t, "SP logout with broken IdP metadata", err, sso.ErrBadProvider)
	})
}

// TestC2_IDGeneratorFailures: an ID that cannot be made fails the
// registration or the sign-in that needed it, at every place an sso row is
// written.
func TestC2_IDGeneratorFailures(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		errIDs := errors.New("c2: no ids")
		var fail string
		gen := auth.WithIDs(func(prefix string) (string, error) {
			if prefix == fail {
				return "", errIDs
			}
			return prefix + "_" + strings.ToLower(auth.NewToken().Reveal()[:20]), nil
		})
		var linkTo string
		w := c2BuildWith(t, e, []auth.Option{gen}, nil, sso.TrustProviders(c2OIDC),
			sso.WithResolveUser(func(context.Context, *auth.Call, sso.ResolveInput) (sso.Decision, error) {
				if linkTo != "" {
					return sso.Decision{Action: sso.ResolveLink, UserID: linkTo}, nil
				}
				return sso.Decision{}, nil
			}))
		fail = "ssop"
		_, err := w.p.RegisterProvider(w.as(), w.oidcRequest(c2OIDC))
		c2Want(t, "registration", err, errIDs)
		fail = ""
		w.register(t, w.oidcRequest(c2OIDC))
		fail = "ssoa"
		_, err = w.oidcSignIn(t, sso.SignInRequest{ProviderID: c2OIDC})
		c2Want(t, "a first sign-in", err, errIDs)
		// Linking an existing verified address (trusted provider, its domain).
		uid, _ := identUser(t, w.a, c2Person)
		_, err = w.oidcSignIn(t, sso.SignInRequest{ProviderID: c2OIDC})
		c2Want(t, "linking by verified email", err, errIDs)
		// Linking by a resolve decision.
		linkTo = uid
		w.oidc.Person.Subject = "sub-linked"
		_, err = w.oidcSignIn(t, sso.SignInRequest{ProviderID: c2OIDC})
		c2Want(t, "linking by a resolve decision", err, errIDs)
		fail = ""
		if res, err := w.oidcSignIn(t, sso.SignInRequest{ProviderID: c2OIDC}); err != nil || res.User.ID != uid {
			t.Fatalf("the resolve link once ids work: %+v %v", res, err)
		}
	})
}

// TestC2_LinkRaceIsLinkedElsewhere: when a concurrent first sign-in links
// the same IdP account while this one is resolving, the second insert is
// ErrLinkedElsewhere, not a second account. The resolve hook plays the
// concurrent sign-in by completing one inside this one's transaction.
func TestC2_LinkRaceIsLinkedElsewhere(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var w *c2World
		var inner *sso.CallbackRequest
		var innerFlow auth.Token
		w = c2Build(t, e, sso.WithResolveUser(func(ctx context.Context, _ *auth.Call, _ sso.ResolveInput) (sso.Decision, error) {
			if inner != nil {
				cb := *inner
				inner = nil
				req := auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{Origin: testBaseURL}, Flow: innerFlow}
				if _, err := w.p.Callback(w.a.WithRequest(ctx, req), cb); err != nil {
					return sso.Decision{}, err
				}
			}
			return sso.Decision{}, nil
		}))
		w.register(t, w.oidcRequest(c2OIDC))
		w.oidc.Person.Email = "" // no address: both sign-ins would create a user
		first, flow1 := w.oidcFlow(t, sso.SignInRequest{ProviderID: c2OIDC})
		second, flow2 := w.oidcFlow(t, sso.SignInRequest{ProviderID: c2OIDC})
		inner, innerFlow = &second, flow2
		_, err := w.p.Callback(c2Ctx(w.a, "", flow1), first)
		c2Want(t, "the slower first sign-in", err, sso.ErrLinkedElsewhere)
		if n := r31Count(t, e, "auth_sso_account", ""); n != 0 {
			t.Fatalf("%d accounts after a rolled-back race", n)
		}
	})
}

// TestC2_PrivateKeyJWTFailures: private_key_jwt fails closed at each point
// the resolver's key is needed — a key of the wrong type, a key the
// assertion cannot use, and a resolver that fails mid-flow (at the
// exchange, at token verification, or on an IdP-initiated restart).
func TestC2_PrivateKeyJWTFailures(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		idp := ssotest.NewOIDC(t)
		p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		rsaKey, _, _ := ssotest.KeyPair(t, "client")
		var calls, failAt int
		var key crypto.Signer
		resolver := func(context.Context, sso.PrivateKeyRequest) (crypto.Signer, string, error) {
			calls++
			if calls == failAt {
				return nil, "", errors.New("c2: kms down")
			}
			return key, "kid-1", nil
		}
		def := func(id, alg string) sso.Provider {
			return sso.Provider{ProviderID: id, Issuer: idp.Issuer(), Domain: id + ".test", OIDC: &sso.OIDCConfig{ClientID: idp.ClientID,
				TokenEndpointAuthentication: oauth.PrivateKeyJWT, PrivateKeyAlgorithm: alg, AllowIdPInitiated: true,
				AuthorizationEndpoint: idp.URL + "/authorize", TokenEndpoint: idp.URL + "/token", JWKSEndpoint: idp.URL + "/jwks"}}
		}
		w := c2Build(t, e, sso.WithTrustedOrigins(idp.URL), sso.WithPrivateKeyResolver(resolver), sso.WithDefaultProviders(def("rs", "RS256"), def("any", "")))
		w.oidc = idp
		ctx := c2Ctx(w.a, "", "")

		key = p256
		_, err := w.p.SignIn(ctx, sso.SignInRequest{ProviderID: "rs"})
		c2Want(t, "an EC key for RS256", err, sso.ErrBadProvider)
		key = p384
		_, err = w.p.SignIn(ctx, sso.SignInRequest{ProviderID: "any"})
		c2Want(t, "a P-384 key the assertion cannot use", err, sso.ErrProviderFailed)

		key = rsaKey
		for _, at := range []int{2, 3} { // the callback resolves twice: the exchange, then the ID token check
			calls, failAt = 0, at
			cb, flow := w.oidcFlow(t, sso.SignInRequest{ProviderID: "rs"})
			_, err = w.p.Callback(c2Ctx(w.a, "", flow), cb)
			c2Want(t, fmt.Sprintf("the resolver failing at call %d", at), err, sso.ErrNoPrivateKey)
		}
		calls, failAt = 0, 1
		_, err = w.p.Callback(ctx, sso.CallbackRequest{Code: "planted", ProviderID: "rs"})
		c2Want(t, "an IdP-initiated restart with the resolver down", err, sso.ErrNoPrivateKey)
	})
}

// TestC2_PublicClientNeedsPKCE: a public client (no secret, no key) with
// PKCE turned off could never sign in, so it is refused when registered,
// not at its first sign-in.
func TestC2_PublicClientNeedsPKCE(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := c2Build(t, e)
		off := false
		in := w.oidcRequest(c2OIDC)
		in.OIDCConfig.ClientSecret, in.OIDCConfig.TokenEndpointAuthentication, in.OIDCConfig.PKCE = "", oauth.PublicClient, &off
		_, err := w.p.RegisterProvider(w.as(), in)
		c2Want(t, "a public client without PKCE", err, sso.ErrBadProvider)
	})
}

// TestC2_OIDCTokenWithoutSubject: an ID token with an empty sub names no
// one and signs no one in.
func TestC2_OIDCTokenWithoutSubject(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := c2Build(t, e)
		w.register(t, w.oidcRequest(c2OIDC))
		w.oidc.IDTokenClaims = func(c map[string]any) { c["sub"] = "" }
		if _, err := w.oidcSignIn(t, sso.SignInRequest{ProviderID: c2OIDC}); err == nil {
			t.Fatal("an ID token without a subject signed in")
		}
		if n := r31Count(t, e, "auth_user", ""); n != 1 {
			t.Fatalf("%d users", n)
		}
	})
}

// TestC2_ACSErrorPage: a SAML flow started with an error page lands there
// when its response is refused, and a signed assertion with no ID cannot be
// reserved against replay, so it is refused.
func TestC2_ACSErrorPage(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := c2Build(t, e)
		in := w.samlRequest(t, c2SAML)
		in.SAMLConfig.WantAssertionsSigned = false // the response's signature covers the assertion
		w.register(t, in)
		rw := &r31World{a: w.a, sso: w.p, web: newApp(t, w.a)}
		res := rw.web.post(t, "/auth/sso/sign-in", map[string]any{"providerId": c2SAML, "errorCallbackURL": "/oops"})
		var out sso.SignInResult
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("sign-in: %d %v", res.StatusCode, err)
		}
		res.Body.Close()
		reqID, _, relay := ssotest.AuthnRequest(t, out.URL)
		a := w.saml.Valid(r31ACS, r31SP, reqID, c2Person)
		a.ID, a.SignAssertion, a.SignResponse = "", false, true
		res = rw.acs(t, w.saml.Response(a), relay)
		loc := res.Header.Get("Location")
		res.Body.Close()
		if res.StatusCode != http.StatusFound || !strings.HasPrefix(loc, "/oops") {
			t.Fatalf("a refused response: %d %q", res.StatusCode, loc)
		}
		if n := r31Count(t, e, "auth_sso_account", ""); n != 0 {
			t.Fatalf("%d accounts", n)
		}
	})
}

// TestC2_SingleLogoutRecords: a deprecated logout signature is accepted
// with a warning under the default policy, and a session record that does
// not parse fails the sign-out or IdP logout that reads it rather than
// being skipped as "not a SAML session".
func TestC2_SingleLogoutRecords(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := c2Build(t, e, sso.WithSAMLOptions(sso.SAMLOptions{EnableSingleLogout: true}))
		w.register(t, w.samlRequest(t, c2SAML))
		ctx, bg := c2Ctx(w.a, "", ""), context.Background()
		if _, err := w.p.SLO(ctx, w.slo(t, c2Msg{kind: sso.KindLogoutRequest, nameID: c2Person, sigAlg: sso.AlgRSASHA1})); err != nil {
			t.Fatalf("an RSA-SHA1 logout under warn: %v", err)
		}
		sess, tok, err := w.a.CreateSession(bg, w.uid, auth.Client{})
		if err != nil {
			t.Fatal(err)
		}
		if err := w.a.IssueVerificationToken(bg, sso.PurposeSAMLSessionByID, c2SAML, auth.Token(sess.ID), time.Hour, "{"); err != nil {
			t.Fatal(err)
		}
		if err := w.a.SignOut(c2Ctx(w.a, tok, "")); err == nil {
			t.Fatal("a sign-out over an unreadable record answered")
		}
		ghost := auth.Token(c2SAML + "\x00ghost@acme.test\x00_ghost")
		if err := w.a.IssueVerificationToken(bg, sso.PurposeSAMLSession, c2SAML, ghost, time.Hour, "{"); err != nil {
			t.Fatal(err)
		}
		if _, err := w.p.SLO(ctx, w.slo(t, c2Msg{kind: sso.KindLogoutRequest, nameID: "ghost@acme.test", index: "_ghost"})); err == nil {
			t.Fatal("an IdP logout over an unreadable record answered")
		}
	})
}

// TestC2_MigrationsPerEngine: the account table's user index is inline on
// MySQL (which has no CREATE INDEX IF NOT EXISTS) and a separate statement
// elsewhere; an unknown engine is refused.
func TestC2_MigrationsPerEngine(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := c2Build(t, e)
		if _, err := w.p.TypedMigrations("oracle", auth.TypesFor("oracle")); err == nil {
			t.Fatal("an unknown engine got migrations")
		}
		for _, c := range []struct {
			engine string
			stmts  int
		}{{auth.EngineMySQL, 1}, {auth.EnginePostgres, 2}, {auth.EngineSQLite, 2}} {
			ms, err := w.p.TypedMigrations(c.engine, auth.TypesFor(c.engine))
			if err != nil || len(ms) != 3 || len(ms[1].Statements) != c.stmts {
				t.Fatalf("%s: %+v %v", c.engine, ms, err)
			}
			if c.engine == auth.EngineMySQL && !strings.Contains(ms[1].Statements[0], "INDEX ") {
				t.Fatalf("mysql account table has no inline index: %s", ms[1].Statements[0])
			}
		}
	})
}

// c2Orgs is an organization system whose calls fail on demand.
type c2Orgs struct {
	r31Orgs
	roleErr, pendingErr error
}

func (o *c2Orgs) Role(ctx context.Context, orgID, userID string) (string, bool, error) {
	if o.roleErr != nil {
		return "", false, o.roleErr
	}
	return o.r31Orgs.Role(ctx, orgID, userID)
}

func (o *c2Orgs) PendingInvitation(ctx context.Context, orgID, userID string) (bool, error) {
	if o.pendingErr != nil {
		return false, o.pendingErr
	}
	return o.r31Orgs.PendingInvitation(ctx, orgID, userID)
}

// TestC2_OrganizationAssignment: a verified address joins the one
// organization whose verified provider owns its domain, with the role the
// app computes; two such organizations is ambiguous; and every failure of
// the organization system or the role function is returned.
func TestC2_OrganizationAssignment(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		orgs := &c2Orgs{r31Orgs: r31Orgs{roles: map[string]string{}}}
		var roleErr error
		w := c2Build(t, e, sso.WithOrganizations(orgs, sso.OrganizationProvisioning{Role: func(_ context.Context, ev sso.ProvisionEvent) (string, error) {
			return "billing", roleErr
		}}), sso.WithDefaultProviders(sso.Provider{ProviderID: "corp", Issuer: "https://corp.example.com", Domain: r31Domain, OrganizationID: "org-1",
			OIDC: &sso.OIDCConfig{ClientID: "c", ClientSecret: "s", AuthorizationEndpoint: "https://corp.example.com/a", TokenEndpoint: "https://corp.example.com/t", JWKSEndpoint: "https://corp.example.com/j"}}))
		bg := context.Background()
		ev := oauth.ResolvedEvent{ProfileEvent: oauth.ProfileEvent{UserID: "u1", Profile: oauth.Profile{Email: c2Person, EmailVerified: true}}}
		roleErr = errors.New("c2: role service down")
		if _, err := w.p.AssignOAuth(bg, ev); !errors.Is(err, roleErr) {
			t.Fatalf("a failing role function: %v", err)
		}
		roleErr = nil
		orgs.pendingErr = errC2Orgs
		if _, err := w.p.AssignOAuth(bg, ev); !errors.Is(err, errC2Orgs) {
			t.Fatalf("a failing invitation check: %v", err)
		}
		orgs.pendingErr = nil
		if got, err := w.p.AssignOAuth(bg, ev); err != nil || got != sso.AssignAssigned || orgs.roles["org-1/u1"] != "billing" {
			t.Fatalf("an eligible OAuth sign-in: %s %v %v", got, err, orgs.roles)
		}
		orgs.roleErr = errC2Orgs
		if _, err := w.p.AssignByVerifiedDomain(bg, "u2", c2Person, true); !errors.Is(err, errC2Orgs) {
			t.Fatalf("a failing membership check: %v", err)
		}
		orgs.roleErr = nil
		// A second organization's verified provider for the same domain.
		orgs.roles["org-2/"+w.uid] = sso.RoleOwner
		in := w.oidcRequest(c2OIDC)
		in.OrganizationID = "org-2"
		w.register(t, in)
		if _, err := e.db.Exec("UPDATE " + tbl("auth_sso_provider") + " SET domain_verified = TRUE"); err != nil {
			t.Fatal(err)
		}
		if got, err := w.p.AssignByVerifiedDomain(bg, "u3", c2Person, true); err != nil || got != sso.AssignAmbiguous {
			t.Fatalf("two organizations claim the domain: %s %v", got, err)
		}
	})
}

// TestC2_ProviderFieldsWrites: Go code may set any declared field (NoInput ones
// included) but no undeclared one, never on a default provider, and a value
// that cannot be stored as JSON is an error at every write.
func TestC2_ProviderFieldsWrites(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := c2Build(t, e, sso.WithProviderFields(sso.ProviderField{Name: "tier"}, sso.ProviderField{Name: "internal", NoInput: true}),
			sso.WithDefaultProviders(sso.Provider{ProviderID: "corp", Issuer: "https://corp.example.com", Domain: "corp.test",
				OIDC: &sso.OIDCConfig{ClientID: "c", ClientSecret: "s", AuthorizationEndpoint: "https://corp.example.com/a", TokenEndpoint: "https://corp.example.com/t", JWKSEndpoint: "https://corp.example.com/j"}}))
		bg := context.Background()
		in := w.oidcRequest(c2OIDC)
		in.AdditionalFields = map[string]any{"tier": make(chan int)}
		if _, err := w.p.RegisterProvider(w.as(), in); err == nil {
			t.Fatal("an unstorable field value was registered")
		}
		in.AdditionalFields = map[string]any{"tier": "gold"}
		w.register(t, in)
		if _, err := w.p.UpdateProvider(w.as(), sso.UpdateRequest{ProviderID: c2OIDC, AdditionalFields: map[string]any{"tier": func() {}}}); err == nil {
			t.Fatal("an unstorable field value was updated")
		}
		if err := w.p.SetProviderFields(bg, c2OIDC, map[string]any{"internal": make(chan int)}); err == nil {
			t.Fatal("an unstorable field value was set")
		}
		c2Want(t, "an undeclared field", w.p.SetProviderFields(bg, c2OIDC, map[string]any{"other": 1}), sso.ErrBadProvider)
		c2Want(t, "a default provider", w.p.SetProviderFields(bg, "corp", map[string]any{"tier": "x"}), sso.ErrForbidden)
		c2Want(t, "no provider", w.p.SetProviderFields(bg, "nobody", map[string]any{"tier": "x"}), sso.ErrProviderNotFound)
		if err := w.p.SetProviderFields(bg, c2OIDC, map[string]any{"internal": "yes"}); err != nil {
			t.Fatal(err)
		}
		got, err := w.p.GetProvider(w.as(), c2OIDC)
		if err != nil || got.AdditionalFields["internal"] != "yes" || got.AdditionalFields["tier"] != "gold" {
			t.Fatalf("fields %+v %v", got.AdditionalFields, err)
		}
	})
}

// TestC2_DomainTokenLifecycle: a verified domain needs no token, and an
// expired one is replaced by a fresh token when asked again.
func TestC2_DomainTokenLifecycle(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		dns := &r31Resolver{txts: map[string][]string{}}
		w := c2Build(t, e, sso.WithDomainVerification(sso.DomainVerification{Resolver: dns}))
		reg := w.register(t, w.oidcRequest(c2OIDC))
		e.clock.Advance(sso.DefaultDomainTokenTTL + time.Minute)
		_, tok, err := w.a.CreateSession(context.Background(), w.uid, auth.Client{}) // the old session expired too
		if err != nil {
			t.Fatal(err)
		}
		w.admin = tok
		fresh, err := w.p.RequestDomainVerification(w.as(), c2OIDC)
		if err != nil || fresh.DomainVerificationToken == reg.DomainVerificationToken {
			t.Fatalf("an expired token was not replaced: %+v %v", fresh, err)
		}
		dns.txts[sso.DomainRecordName(sso.DefaultDomainTokenPrefix, c2OIDC, r31Domain)] = []string{fresh.DomainVerificationToken}
		if err := w.p.VerifyDomain(w.as(), c2OIDC); err != nil {
			t.Fatal(err)
		}
		_, err = w.p.RequestDomainVerification(w.as(), c2OIDC)
		c2Want(t, "a token for a verified domain", err, sso.ErrDomainVerified)
	})
}
