package integration

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/sso"
	"github.com/ubgo/auth/plugin/sso/ssotest"
)

// Round 31, second part: single logout, encrypted assertions, per-provider
// paths, domain-token expiry, provider fields, custom SP metadata and
// organization assignment.

const r31IdPSLO = "https://idp.example.com/slo"

// r31SAMLWorld signs one browser in through a SAML provider with SLO.
type r31SAMLWorld struct {
	*r31World
	idp     *ssotest.SAMLIdP
	spCert  *x509.Certificate
	reqSeen string
}

func r31SLOSetup(t *testing.T, e *env, opts ...sso.Option) *r31SAMLWorld {
	t.Helper()
	w := r31Setup(t, e, append([]sso.Option{sso.WithSAMLOptions(sso.SAMLOptions{EnableSingleLogout: true})}, opts...)...)
	idp := ssotest.NewSAMLIdP(t, "https://idp.example.com/acme")
	key, cert, certPEM := ssotest.KeyPair(t, "sp")
	w.registerSAML(t, idp, "acme-saml", map[string]any{
		"idpMetadata":   map[string]any{"entityID": idp.EntityID, "singleLogoutService": []map[string]any{{"Binding": sso.BindingRedirect, "Location": r31IdPSLO}}},
		"privateKey":    ssotest.KeyPEM(key),
		"spCertificate": certPEM,
	})
	return &r31SAMLWorld{r31World: w, idp: idp, spCert: cert}
}

// login signs the world's browser in and returns the assertion used.
func (w *r31SAMLWorld) login(t *testing.T) ssotest.Assertion {
	t.Helper()
	reqID, relay := w.samlStart(t, "acme-saml")
	a := w.idp.Valid(r31ACS, r31SP, reqID, "ada@"+r31Domain)
	res := w.acs(t, w.idp.Response(a), relay)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("acs: %d %s", res.StatusCode, readAll(t, res))
	}
	res.Body.Close()
	if st, _ := w.me(t); st != http.StatusOK {
		t.Fatalf("not signed in: %d", st)
	}
	return a
}

// idpMessage builds the redirect-binding query of an IdP logout message.
func (w *r31SAMLWorld) idpMessage(t *testing.T, kind, nameID, sessionIndex, inResponseTo string, signed bool) string {
	t.Helper()
	param := "SAMLRequest"
	if kind == sso.KindLogoutResponse {
		param = "SAMLResponse"
	}
	var idx []string
	if sessionIndex != "" {
		idx = []string{sessionIndex}
	}
	doc := sso.LogoutDocument(kind, "_idp"+auth.NewToken().Reveal(), w.idp.EntityID, testBaseURL+"/auth/sso/saml2/sp/slo", nameID, "", idx, inResponseTo, sso.StatusSuccess, time.Now())
	key := w.idp.Signer()
	if !signed {
		key = nil
	}
	u, err := sso.RedirectURL(testBaseURL+"/auth/sso/saml2/sp/slo", param, doc, "relay-x", key, sso.AlgRSASHA256)
	if err != nil {
		t.Fatal(err)
	}
	pu, _ := url.Parse(u)
	return pu.RawQuery
}

func TestR31_SAMLSingleLogoutSPInitiated(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r31SLOSetup(t, e)
		a := w.login(t)
		res := w.web.post(t, "/auth/sso/saml2/logout", map[string]any{"callbackURL": "/bye"})
		var out sso.LogoutResult
		_ = json.NewDecoder(res.Body).Decode(&out)
		res.Body.Close()
		if res.StatusCode != http.StatusOK || !strings.HasPrefix(out.URL, r31IdPSLO+"?SAMLRequest=") {
			t.Fatalf("logout: %d %+v", res.StatusCode, out)
		}
		if st, _ := w.me(t); st != http.StatusUnauthorized {
			t.Fatalf("still signed in after logout: %d", st)
		}
		pu, _ := url.Parse(out.URL)
		q := pu.Query()
		lr, err := sso.DecodeLogout(sso.BindingMessage{Redirect: true, Param: "SAMLRequest", Value: q.Get("SAMLRequest"), SigAlg: q.Get("SigAlg"), Signature: q.Get("Signature")},
			[]*x509.Certificate{w.spCert}, time.Now(), sso.DefaultMaxResponseSize)
		if err != nil || !lr.Signed || lr.NameID != "ada@"+r31Domain || len(lr.SessionIndexes) != 1 || lr.SessionIndexes[0] != "_s"+a.ID || lr.Destination != r31IdPSLO {
			t.Fatalf("LogoutRequest %+v %v", lr, err)
		}
		// An unsigned answer is refused; the signed one lands on the callback, once.
		if c := r31ErrCode(w.web.get(t, "/auth/sso/saml2/sp/slo?"+w.idpMessage(t, sso.KindLogoutResponse, "", "", lr.ID, false))); c != "sso.saml_invalid" {
			t.Fatalf("unsigned LogoutResponse: %s", c)
		}
		// The unsigned attempt spent the pending request: start again.
		w.login(t)
		res = w.web.post(t, "/auth/sso/saml2/logout", map[string]any{"callbackURL": "/bye"})
		_ = json.NewDecoder(res.Body).Decode(&out)
		res.Body.Close()
		pu, _ = url.Parse(out.URL)
		lr, _ = sso.PeekLogout(sso.BindingMessage{Redirect: true, Param: "SAMLRequest", Value: pu.Query().Get("SAMLRequest")}, sso.DefaultMaxResponseSize)
		answer := w.idpMessage(t, sso.KindLogoutResponse, "", "", lr.ID, true)
		res = w.web.get(t, "/auth/sso/saml2/sp/slo?"+answer)
		if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/bye" {
			t.Fatalf("LogoutResponse: %d %s %s", res.StatusCode, res.Header.Get("Location"), readAll(t, res))
		}
		res.Body.Close()
		if c := r31ErrCode(w.web.get(t, "/auth/sso/saml2/sp/slo?"+answer)); c != "sso.invalid_logout_response" {
			t.Fatalf("replayed LogoutResponse: %s", c)
		}
		// A session that did not start with SAML has nothing to log out.
		plain := w.user(t, "plain@corp.test")
		if st, out := w.call(t, plain, http.MethodPost, "/auth/sso/saml2/logout", map[string]any{}); st != http.StatusNotFound || r31Code(out) != "sso.saml_session_not_found" {
			t.Fatalf("non-SAML session: %d %v", st, out)
		}
	})
}

func TestR31_SAMLSingleLogoutIdPInitiated(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r31SLOSetup(t, e)
		a := w.login(t)
		// Unsigned, or signed by another key: refused, the session lives.
		if c := r31ErrCode(newApp(t, w.a).get(t, "/auth/sso/saml2/sp/slo?"+w.idpMessage(t, sso.KindLogoutRequest, "ada@"+r31Domain, "_s"+a.ID, "", false))); c != "sso.saml_invalid" {
			t.Fatalf("unsigned LogoutRequest: %s", c)
		}
		forger := ssotest.NewSAMLIdP(t, w.idp.EntityID)
		doc := sso.LogoutDocument(sso.KindLogoutRequest, "_f", w.idp.EntityID, "", "ada@"+r31Domain, "", []string{"_s" + a.ID}, "", "", time.Now())
		forged, _ := sso.RedirectURL("https://x/slo", "SAMLRequest", doc, "", forger.Signer(), sso.AlgRSASHA256)
		fu, _ := url.Parse(forged)
		if c := r31ErrCode(newApp(t, w.a).get(t, "/auth/sso/saml2/sp/slo?"+fu.RawQuery)); c != "sso.saml_invalid" {
			t.Fatalf("forged LogoutRequest: %s", c)
		}
		// Signed by the right key but naming another issuer, or another
		// SP's SLO endpoint: refused.
		for name, d := range map[string]struct{ issuer, dest string }{
			"issuer":      {"https://evil.example.com", ""},
			"destination": {w.idp.EntityID, "https://other-sp.example.com/slo"},
		} {
			doc := sso.LogoutDocument(sso.KindLogoutRequest, "_x", d.issuer, d.dest, "ada@"+r31Domain, "", []string{"_s" + a.ID}, "", "", time.Now())
			if d.dest == "" {
				doc.Root().RemoveAttr("Destination")
			}
			u, _ := sso.RedirectURL("https://x/slo", "SAMLRequest", doc, "", w.idp.Signer(), sso.AlgRSASHA256)
			pu, _ := url.Parse(u)
			if c := r31ErrCode(newApp(t, w.a).get(t, "/auth/sso/saml2/sp/slo?"+pu.RawQuery+"&providerId=acme-saml")); c != "sso.saml_invalid" {
				t.Fatalf("%s: %s", name, c)
			}
		}
		if st, _ := w.me(t); st != http.StatusOK {
			t.Fatalf("a refused logout ended the session: %d", st)
		}
		// The IdP's signed request ends it and is answered at the IdP.
		res := newApp(t, w.a).get(t, "/auth/sso/saml2/sp/slo?"+w.idpMessage(t, sso.KindLogoutRequest, "ada@"+r31Domain, "_s"+a.ID, "", true))
		loc := res.Header.Get("Location")
		res.Body.Close()
		if res.StatusCode != http.StatusFound || !strings.HasPrefix(loc, r31IdPSLO+"?SAMLResponse=") || !strings.Contains(loc, "RelayState=relay-x") {
			t.Fatalf("idp logout: %d %s", res.StatusCode, loc)
		}
		if st, _ := w.me(t); st != http.StatusUnauthorized {
			t.Fatalf("session survived the IdP's logout: %d", st)
		}
		// POST binding, enveloped signature.
		a = w.login(t)
		pd := sso.LogoutDocument(sso.KindLogoutRequest, "_p1", w.idp.EntityID, "", "ada@"+r31Domain, "", []string{"_s" + a.ID}, "", "", time.Now())
		pd.SetRoot(w.idp.Sign(pd.Root(), false))
		form := url.Values{"SAMLRequest": {ssotest.Encode(pd)}}
		req, _ := http.NewRequest(http.MethodPost, w.web.srv.URL+"/auth/sso/saml2/sp/slo", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://idp.example.com")
		pres, err := newApp(t, w.a).client.Do(req)
		if err != nil || pres.StatusCode != http.StatusFound {
			t.Fatalf("POST logout: %v %d", err, pres.StatusCode)
		}
		if st, _ := w.me(t); st != http.StatusUnauthorized {
			t.Fatalf("session survived POST logout: %d", st)
		}
		// Signing out locally forgets the SAML record.
		w.login(t)
		w.web.post(t, "/auth/sign-out", map[string]any{}).Body.Close()
		var n int
		if err := e.db.QueryRow("SELECT COUNT(*) FROM " + tbl("auth_verification") + " WHERE purpose = 'sso.saml_session_id' AND consumed_at IS NULL").Scan(&n); err != nil || n != 0 {
			t.Fatalf("%d open SAML session records after sign-out (%v)", n, err)
		}
	})
}

func TestR31_SAMLEncryptedAssertion(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r31Setup(t, e)
		idp := ssotest.NewSAMLIdP(t, "https://idp.example.com/acme")
		key, cert, certPEM := ssotest.KeyPair(t, "sp-enc")
		w.registerSAML(t, idp, "acme-saml", map[string]any{"decryptionKey": ssotest.KeyPEM(key), "decryptionCertificate": certPEM})
		reqID, relay := w.samlStart(t, "acme-saml")
		res := w.acs(t, idp.EncryptedResponse(idp.Valid(r31ACS, r31SP, reqID, "ada@"+r31Domain), cert, ssotest.EncAES256GCM), relay)
		if res.StatusCode != http.StatusFound {
			t.Fatalf("encrypted acs: %d %s", res.StatusCode, readAll(t, res))
		}
		res.Body.Close()
		// Encrypted to a key this provider does not hold: refused.
		_, other, _ := ssotest.KeyPair(t, "other")
		reqID, relay = w.samlStart(t, "acme-saml")
		if c := r31ErrCode(w.acs(t, idp.EncryptedResponse(idp.Valid(r31ACS, r31SP, reqID, "ada@"+r31Domain), other, ssotest.EncAES256GCM), relay)); c != "sso.saml_invalid" {
			t.Fatalf("foreign key: %s", c)
		}
		st, out := w.call(t, r31User{}, http.MethodGet, "/auth/sso/saml2/sp/metadata?providerId=acme-saml", nil)
		if md, _ := out["metadata"].(string); st != http.StatusOK || !strings.Contains(md, `use="encryption"`) {
			t.Fatalf("metadata without the encryption key: %v", out)
		}
	})
}

func TestR31_PerProviderPaths(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r31Setup(t, e, sso.PerProviderPaths())
		mux := http.NewServeMux()
		mux.Handle("/auth/", w.sso.ProviderPaths("/auth/sso", authhttp.Handler(w.a, authhttp.Prefix("/auth"))))
		mux.Handle("/app/me", authhttp.Middleware(w.a)(authhttp.RequireUser(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(rw).Encode(authhttp.MustUser(r))
		}))))
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		jar, _ := cookiejar.New(nil)
		w.web = &app{srv: srv, jar: jar, client: &http.Client{Jar: &secureJar{jar}, Transport: originTransport{},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}

		reg := w.registerOIDC(t, w.admin, "acme-okta", nil)
		if reg["redirectURI"] != testBaseURL+"/auth/sso/callback/acme-okta" {
			t.Fatalf("redirectURI %v", reg["redirectURI"])
		}
		res := w.web.post(t, "/auth/sso/sign-in", map[string]any{"providerId": "acme-okta"})
		var si sso.SignInResult
		_ = json.NewDecoder(res.Body).Decode(&si)
		res.Body.Close()
		q := w.idp.Authorize(t, si.URL)
		if c := r31ErrCode(w.web.get(t, "/auth/sso/callback/other?"+q.Encode())); c != "sso.state_invalid" {
			t.Fatalf("another provider's path: %s", c)
		}
		res = w.oidcSignIn2(t, "acme-okta")
		if res.StatusCode != http.StatusFound {
			t.Fatalf("per-provider callback: %d %s", res.StatusCode, readAll(t, res))
		}
		res.Body.Close()

		idp := ssotest.NewSAMLIdP(t, "https://idp.example.com/acme")
		acs := r31ACS + "/acme-saml"
		cfg := map[string]any{"entryPoint": idp.SSOURL, "cert": idp.CertPEM, "idpMetadata": map[string]any{"entityID": idp.EntityID}, "spMetadata": map[string]any{"entityID": r31SP}}
		st, out := w.call(t, w.admin, http.MethodPost, "/auth/sso/register", map[string]any{"providerId": "acme-saml", "issuer": r31SP, "domain": "saml.test", "samlConfig": cfg})
		if st != http.StatusOK || out["acsURL"] != acs {
			t.Fatalf("register: %d %v", st, out)
		}
		reqID, relay := w.samlStart2(t, "acme-saml", acs)
		form := url.Values{"SAMLResponse": {idp.Response(idp.Valid(acs, r31SP, reqID, "ada@saml.test"))}, "RelayState": {relay}}
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/auth/sso/saml2/sp/acs/acme-saml", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, err := w.web.client.Do(req)
		if err != nil || res.StatusCode != http.StatusFound {
			t.Fatalf("per-provider acs: %v %d %s", err, res.StatusCode, readAll(t, res))
		}
		res.Body.Close()
		// The raw XML metadata route.
		mres, _ := http.Get(srv.URL + "/auth/sso/saml2/sp/metadata?providerId=acme-saml")
		body, _ := io.ReadAll(mres.Body)
		mres.Body.Close()
		if mres.Header.Get("Content-Type") != "application/xml" || !strings.Contains(string(body), `Location="`+acs+`"`) {
			t.Fatalf("metadata %s %s", mres.Header.Get("Content-Type"), body)
		}
	})
}

// oidcSignIn2 is oidcSignIn through the per-provider callback path.
func (w *r31World) oidcSignIn2(t *testing.T, providerID string) *http.Response {
	t.Helper()
	res := w.web.post(t, "/auth/sso/sign-in", map[string]any{"providerId": providerID})
	var out sso.SignInResult
	_ = json.NewDecoder(res.Body).Decode(&out)
	res.Body.Close()
	q := w.idp.Authorize(t, out.URL)
	return w.web.get(t, "/auth/sso/callback/"+providerID+"?"+q.Encode())
}

// samlStart2 is samlStart for a provider with its own ACS URL.
func (w *r31World) samlStart2(t *testing.T, providerID, wantACS string) (string, string) {
	t.Helper()
	res := w.web.post(t, "/auth/sso/sign-in", map[string]any{"providerId": providerID})
	var out sso.SignInResult
	_ = json.NewDecoder(res.Body).Decode(&out)
	res.Body.Close()
	id, acs, relay := ssotest.AuthnRequest(t, out.URL)
	if acs != wantACS {
		t.Fatalf("AuthnRequest ACS %q", acs)
	}
	return id, relay
}

func TestR31_DomainTokenExpiry(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		dns := &r31Resolver{txts: map[string][]string{}}
		w := r31Setup(t, e, sso.WithDomainVerification(sso.DomainVerification{TokenPrefix: "ubgo", Resolver: dns}))
		tok := w.registerOIDC(t, w.admin, "acme-okta", nil)["domainVerificationToken"].(string)
		ask := func() string {
			st, out := w.call(t, w.admin, http.MethodPost, "/auth/sso/request-domain-verification", map[string]any{"providerId": "acme-okta"})
			if st != http.StatusOK {
				t.Fatalf("request: %d %v", st, out)
			}
			return out["domainVerificationToken"].(string)
		}
		if again := ask(); again != tok {
			t.Fatal("an active token was not reused")
		}
		dns.txts["_ubgo-acme-okta."+r31Domain] = []string{tok}
		e.clock.Advance(sso.DefaultDomainTokenTTL + time.Minute)
		_, fresh, err := w.a.CreateSession(context.Background(), w.admin.ID, auth.Client{}) // the first session is long gone
		if err != nil {
			t.Fatal(err)
		}
		w.admin.Token = fresh
		if st, out := w.call(t, w.admin, http.MethodPost, "/auth/sso/verify-domain", map[string]any{"providerId": "acme-okta"}); st != http.StatusNotFound || r31Code(out) != "sso.no_pending_verification" {
			t.Fatalf("expired: %d %v", st, out)
		}
		if again := ask(); again == tok {
			t.Fatal("an expired token was reissued")
		}
	})
}

func TestR31_ProviderFieldsAndSPMetadata(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r31Setup(t, e, sso.WithProviderFields(sso.ProviderField{Name: "plan", Required: true}, sso.ProviderField{Name: "internal", NoInput: true}))
		body := func(fields map[string]any) map[string]any {
			return map[string]any{"providerId": "f1", "issuer": w.idp.Issuer(), "domain": "f.test", "additionalFields": fields,
				"oidcConfig": map[string]any{"clientId": w.idp.ClientID, "clientSecret": w.idp.ClientSecret}}
		}
		for _, tc := range []struct {
			fields map[string]any
			code   string
		}{{map[string]any{}, "sso.bad_provider"}, {map[string]any{"plan": "x", "internal": 1}, "sso.field_not_allowed"}, {map[string]any{"plan": "x", "nope": 1}, "sso.bad_provider"}} {
			if st, out := w.call(t, w.admin, http.MethodPost, "/auth/sso/register", body(tc.fields)); st != http.StatusBadRequest || r31Code(out) != tc.code {
				t.Fatalf("%v: %d %v", tc.fields, st, out)
			}
		}
		if st, out := w.call(t, w.admin, http.MethodPost, "/auth/sso/register", body(map[string]any{"plan": "gold"})); st != http.StatusOK || out["additionalFields"].(map[string]any)["plan"] != "gold" {
			t.Fatalf("register: %d %v", st, out)
		}
		if err := w.sso.SetProviderFields(context.Background(), "f1", map[string]any{"internal": "set-by-go"}); err != nil {
			t.Fatal(err)
		}
		_, out := w.call(t, w.admin, http.MethodGet, "/auth/sso/get-provider?providerId=f1", nil)
		if f := out["additionalFields"].(map[string]any); f["internal"] != "set-by-go" || f["plan"] != "gold" {
			t.Fatalf("fields %v", f)
		}

		idp := ssotest.NewSAMLIdP(t, "https://idp.example.com/acme")
		md := func(acs string, signed bool) string {
			ws := "false"
			if signed {
				ws = "true"
			}
			return `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + r31SP + `"><SPSSODescriptor WantAssertionsSigned="` + ws + `" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><NameIDFormat>` + sso.NameIDPersistent + `</NameIDFormat><AssertionConsumerService Binding="` + sso.BindingPOST + `" Location="` + acs + `" index="1"/></SPSSODescriptor></EntityDescriptor>`
		}
		reg := func(id, metadata string) (int, map[string]any) {
			return w.call(t, w.admin, http.MethodPost, "/auth/sso/register", map[string]any{"providerId": id, "issuer": "https://ignored", "domain": "m.test", "additionalFields": map[string]any{"plan": "p"},
				"samlConfig": map[string]any{"entryPoint": idp.SSOURL, "cert": idp.CertPEM, "idpMetadata": map[string]any{"entityID": idp.EntityID}, "wantAssertionsSigned": true, "spMetadata": map[string]any{"metadata": metadata}}})
		}
		if st, out := reg("m1", md("https://elsewhere/acs", true)); st != http.StatusBadRequest || r31Code(out) != "sso.sp_metadata_mismatch" {
			t.Fatalf("foreign ACS: %d %v", st, out)
		}
		if st, out := reg("m2", md(r31ACS, false)); st != http.StatusBadRequest || r31Code(out) != "sso.sp_metadata_mismatch" {
			t.Fatalf("unsigned-assertion metadata: %d %v", st, out)
		}
		if st, out := reg("m3", md(r31ACS, true)); st != http.StatusOK || out["samlConfig"].(map[string]any)["spEntityId"] != r31SP {
			t.Fatalf("custom metadata: %d %v", st, out)
		}
		_, out = w.call(t, r31User{}, http.MethodGet, "/auth/sso/saml2/sp/metadata?providerId=m3", nil)
		if out["metadata"] != md(r31ACS, true) {
			t.Fatalf("custom metadata not served as given: %v", out["metadata"])
		}
	})
}

func TestR31_AssignByVerifiedDomain(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		orgs := &r31Orgs{roles: map[string]string{}}
		w := r31Setup(t, e, sso.WithOrganizations(orgs, sso.OrganizationProvisioning{}), sso.TrustProviders("x"),
			sso.WithDefaultProviders(sso.Provider{ProviderID: "code", Issuer: "https://idp", Domain: "acme.test", OrganizationID: "org-1",
				OIDC: &sso.OIDCConfig{ClientID: "c", ClientSecret: "s", AuthorizationEndpoint: "https://idp/a", TokenEndpoint: "https://idp/t", JWKSEndpoint: "https://idp/k"}}))
		ctx := context.Background()
		for _, tc := range []struct {
			email    string
			verified bool
			want     sso.Assignment
		}{
			{"bob@acme.test", false, sso.AssignUnverified},
			{"bob@other.test", true, sso.AssignNoTarget},
			{"bob@eng.acme.test", true, sso.AssignAssigned},
			{"bob@acme.test", true, sso.AssignAlreadyMember},
		} {
			got, err := w.sso.AssignByVerifiedDomain(ctx, "usr_bob", tc.email, tc.verified)
			if err != nil || got != tc.want {
				t.Fatalf("%s: %s %v", tc.email, got, err)
			}
		}
		if orgs.roles["org-1/usr_bob"] != sso.RoleMember {
			t.Fatalf("roles %v", orgs.roles)
		}
		orgs.pending = true
		if got, _ := w.sso.AssignByVerifiedDomain(ctx, "usr_carol", "carol@acme.test", true); got != sso.AssignInvitationPending {
			t.Fatalf("pending invitation: %s", got)
		}
	})
}

func TestR31_RenamedTableAndGoAPI(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		idp := ssotest.NewOIDC(t)
		p := sso.New(sso.WithTrustedOrigins(idp.URL), sso.RequireTrustedOrigins())
		a := e.newAuth(t, []auth.Option{auth.WithSecret(r31Secret), auth.RenameTable(sso.TableProvider, tablePrefix()+"app_sso_providers")}, e.emailPlugin(), p)
		ctx := context.Background()
		u, _ := a.CreateUser(ctx, auth.NewUser{Name: "admin"})
		_, tok, _ := a.CreateSession(ctx, u.ID, auth.Client{})
		rc := a.WithRequest(ctx, auth.Request{Transport: auth.TransportGo, Credential: auth.CredentialBearer, Token: tok})
		if _, err := p.RegisterProvider(rc, sso.RegisterRequest{ProviderID: "g1", Issuer: idp.Issuer(), Domain: "g.test",
			OIDCConfig: &sso.OIDCConfig{ClientID: idp.ClientID, ClientSecret: idp.ClientSecret}}); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := e.db.QueryRow("SELECT COUNT(*) FROM " + tablePrefix() + "app_sso_providers").Scan(&n); err != nil || n != 1 {
			t.Fatalf("renamed table: %d %v", n, err)
		}
		list, err := p.ListProviders(rc)
		if err != nil || len(list.Providers) != 1 {
			t.Fatalf("list %+v %v", list, err)
		}
		if _, err := p.RegisterProvider(rc, sso.RegisterRequest{ProviderID: "g2", Issuer: "https://login.example.com", Domain: "g.test",
			OIDCConfig: &sso.OIDCConfig{ClientID: "c", ClientSecret: "s"}}); err == nil || !strings.Contains(err.Error(), "untrusted") {
			t.Fatalf("an untrusted origin was registered: %v", err)
		}
		if _, err := p.ListProviders(a.WithRequest(ctx, auth.Request{Transport: auth.TransportGo})); err == nil {
			t.Fatal("a signed-out list answered")
		}
	})
}
