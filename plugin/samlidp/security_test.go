package samlidp_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/samlidp"
)

// responseXML decodes the SAMLResponse of the IdP's form page.
func responseXML(t *testing.T, p page) *etree.Element {
	t.Helper()
	for _, m := range formField.FindAllStringSubmatch(p.body, -1) {
		if m[1] != samlidp.ParamSAMLResponse {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(html.UnescapeString(m[2]))
		if err != nil {
			t.Fatal(err)
		}
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(raw); err != nil {
			t.Fatal(err)
		}
		return doc.Root()
	}
	t.Fatalf("no SAMLResponse in %d %s: %s", p.status, p.url, p.body)
	return nil
}

// An AuthnRequest from an issuer nobody registered is refused with a page,
// never answered at its ACS URL.
func TestRefuse_UnregisteredSP(t *testing.T) {
	w := newWorld(t, setup{})
	u, _ := w.authnRedirect(false, func(el *etree.Element) {
		el.FindElement("./Issuer").SetText("https://evil.example/sp")
	})
	wantRefused(t, w.get(u), samlidp.ErrUnknownSP)
}

// An AssertionConsumerServiceURL that is not registered exactly is refused:
// another host, another path, a prefix match and a trailing slash alike.
func TestRefuse_ACSNotInAllowlist(t *testing.T) {
	w := newWorld(t, setup{})
	for _, acs := range []string{
		"https://evil.example/acs", w.spSrv.URL + "/acs/", w.spSrv.URL + "/acs?x=1", w.spSrv.URL + "/ac", strings.ToUpper(w.spSrv.URL) + acsPath,
	} {
		u, _ := w.authnRedirect(false, func(el *etree.Element) { el.CreateAttr("AssertionConsumerServiceURL", acs) })
		wantRefused(t, w.get(u), samlidp.ErrACSNotRegistered)
	}
	// An index past the registered list is refused too, and an index with a
	// URL is malformed.
	u, _ := w.authnRedirect(false, func(el *etree.Element) {
		el.RemoveAttr("AssertionConsumerServiceURL")
		el.CreateAttr("AssertionConsumerServiceIndex", "1")
	})
	wantRefused(t, w.get(u), samlidp.ErrACSNotRegistered)
	u, _ = w.authnRedirect(false, func(el *etree.Element) { el.CreateAttr("AssertionConsumerServiceIndex", "0") })
	wantRefused(t, w.get(u), samlidp.ErrInvalidRequest)
}

// A request ID is answered once: the same AuthnRequest replayed is refused,
// and so is a used continue link.
func TestRefuse_ReplayedRequest(t *testing.T) {
	w := newWorld(t, setup{})
	u, id := w.authnRedirect(false, nil)
	r, ans := w.submit(w.get(u))
	checkAccepted(t, w, r, ans, id)
	wantRefused(t, w.get(u), samlidp.ErrRequestReplayed)

	var cont string
	for _, s := range w.seen {
		if strings.Contains(s, "/saml/continue") {
			cont = s
		}
	}
	if cont == "" {
		t.Fatal("never saw the continue URL")
	}
	wantRefused(t, w.get(cont), samlidp.ErrRequestNotFound)

	// The same ID with a fresh signature-free request (another IssueInstant)
	// is still the same request.
	w.env.Clock.Advance(time.Second)
	u2, _ := w.authnRedirect(false, func(el *etree.Element) { el.CreateAttr("ID", id) })
	wantRefused(t, w.get(u2), samlidp.ErrRequestReplayed)
}

// An AuthnRequest older than RequestMaxAge, or issued in the future past
// the clock skew, is refused.
func TestRefuse_ExpiredRequest(t *testing.T) {
	w := newWorld(t, setup{})
	u, _ := w.authnRedirect(false, nil)
	w.env.Clock.Advance(samlidp.DefaultRequestMaxAge + time.Second)
	wantRefused(t, w.get(u), samlidp.ErrRequestExpired)

	u, _ = w.authnRedirect(false, func(el *etree.Element) {
		el.CreateAttr("IssueInstant", w.env.Clock.Now().Add(samlidp.DefaultClockSkew+time.Second).Format(time.RFC3339))
	})
	wantRefused(t, w.get(u), samlidp.ErrRequestExpired)

	// Just inside both edges is accepted.
	u, _ = w.authnRedirect(false, func(el *etree.Element) {
		el.CreateAttr("IssueInstant", w.env.Clock.Now().Add(-samlidp.DefaultRequestMaxAge).Format(time.RFC3339Nano))
	})
	if p := w.get(u); !strings.Contains(p.body, samlidp.ParamSAMLResponse) {
		t.Fatalf("a request exactly RequestMaxAge old was refused: %d %s", p.status, p.body)
	}
}

// The assertion names the SP's entity ID as its only audience, the ACS URL
// as recipient and destination, and the request as InResponseTo; it is
// short-lived.
func TestAssertion_AudienceRecipientAndLifetime(t *testing.T) {
	w := newWorld(t, setup{})
	u, id := w.authnRedirect(false, nil)
	resp := responseXML(t, w.get(u))
	acs := w.spSrv.URL + acsPath
	if resp.SelectAttrValue("Destination", "") != acs || resp.SelectAttrValue("InResponseTo", "") != id {
		t.Fatalf("response Destination/InResponseTo: %q %q", resp.SelectAttrValue("Destination", ""), resp.SelectAttrValue("InResponseTo", ""))
	}
	auds := resp.FindElements("./Assertion/Conditions/AudienceRestriction/Audience")
	if len(auds) != 1 || auds[0].Text() != spEntityID {
		t.Fatalf("audiences: %d", len(auds))
	}
	scd := resp.FindElement("./Assertion/Subject/SubjectConfirmation/SubjectConfirmationData")
	if scd.SelectAttrValue("Recipient", "") != acs || scd.SelectAttrValue("InResponseTo", "") != id {
		t.Fatalf("SubjectConfirmationData: %v", scd.Attr)
	}
	exp, err := time.Parse(time.RFC3339, scd.SelectAttrValue("NotOnOrAfter", ""))
	if err != nil || !exp.Equal(w.env.Clock.Now().Truncate(time.Second).Add(samlidp.DefaultAssertionTTL)) {
		t.Fatalf("NotOnOrAfter %v, want now + %v", exp, samlidp.DefaultAssertionTTL)
	}
	if issuer := resp.FindElement("./Assertion/Issuer"); issuer.Text() != w.idp.IdPEntityID() {
		t.Fatalf("issuer %q", issuer.Text())
	}
}

// A signed-out browser is sent to the login page and never receives an
// assertion; from Go, Continue for an anonymous caller answers the login
// redirect and no form.
func TestAnonymous_SentToLoginNeverAsserted(t *testing.T) {
	w := newWorld(t, setup{})
	w.noLogin = true
	u, _ := w.authnRedirect(false, nil)
	p := w.get(u)
	if !strings.Contains(p.body, "login page") || strings.Contains(p.body, samlidp.ParamSAMLResponse) {
		t.Fatalf("anonymous browser got %d %s: %s", p.status, p.url, p.body)
	}
	lu, _ := url.Parse(p.url)
	ret := lu.Query().Get(samlidp.DefaultReturnParam)
	if lu.Path != loginPath || !strings.HasPrefix(ret, w.idp.SSOURL()[:len(w.idp.SSOURL())-len("/sso")]+"/continue?") {
		t.Fatalf("login URL %s", p.url)
	}
	// The return link, followed still signed out, sends to login again
	// under a new handle; the old handle is dead.
	again := w.get(ret)
	if !strings.Contains(again.body, "login page") {
		t.Fatalf("signed-out continue: %d %s", again.status, again.body)
	}
	wantRefused(t, w.get(ret), samlidp.ErrRequestNotFound)

	// The Go API: an anonymous caller gets a redirect, not a form.
	v, _ := w.authnPOST(false, nil)
	res, err := w.idp.SSO(w.env.Anonymous(context.Background()), samlidp.SSORequest{Binding: samlidp.BindingPOST, SAMLRequest: v})
	if err != nil {
		t.Fatal(err)
	}
	cu, _ := url.Parse(res.RedirectTo)
	res, err = w.idp.Continue(w.env.Anonymous(context.Background()), samlidp.ContinueRequest{Request: cu.Query().Get("request")})
	if err != nil || res.Form != nil || !strings.HasPrefix(res.RedirectTo, loginPath+"?") {
		t.Fatalf("anonymous Continue: %+v %v", res, err)
	}
}

// RequireSignedRequests refuses an unsigned request; a signature that does
// not cover what arrived, or one moved onto a wrapper element, is refused.
func TestRefuse_Signatures(t *testing.T) {
	w := newWorld(t, setup{spReg: func(sp *samlidp.ServiceProvider) { sp.RequireSignedRequests = true }})
	post := func(v string) page {
		return w.postForm(w.idp.SSOURL(), url.Values{samlidp.ParamSAMLRequest: {v}})
	}
	v, _ := w.authnPOST(false, nil)
	wantRefused(t, post(v), samlidp.ErrSignatureRequired)
	u, _ := w.authnRedirect(false, nil)
	wantRefused(t, w.get(u), samlidp.ErrSignatureRequired)

	// Tampered after signing: the ACS URL changed.
	v, _ = w.authnPOST(true, nil)
	raw, _ := base64.StdEncoding.DecodeString(v)
	tampered := strings.Replace(string(raw), `AssertionConsumerServiceURL="`+w.spSrv.URL, `AssertionConsumerServiceURL="https://evil.example`, 1)
	wantRefused(t, post(base64.StdEncoding.EncodeToString([]byte(tampered))), samlidp.ErrInvalidSignature)

	// Wrapping: an attacker's request carrying the SP's genuine signature,
	// whose reference names the original element.
	v, _ = w.authnPOST(true, nil)
	raw, _ = base64.StdEncoding.DecodeString(v)
	doc := etree.NewDocument()
	_ = doc.ReadFromBytes(raw)
	orig := doc.Root()
	evil := orig.Copy()
	evil.CreateAttr("ID", "_evil")
	evil.CreateAttr("AssertionConsumerServiceURL", "https://evil.example/acs")
	ext := evil.CreateElement("samlp:Extensions")
	ext.AddChild(orig)
	wd := etree.NewDocument()
	wd.SetRoot(evil)
	wb, _ := wd.WriteToBytes()
	wantRefused(t, post(base64.StdEncoding.EncodeToString(wb)), samlidp.ErrInvalidSignature)

	// A redirect signature over other parameters (the RelayState changed).
	u, _ = w.authnRedirect(true, nil)
	pu, _ := url.Parse(u)
	q := pu.Query()
	q.Set(samlidp.ParamRelayState, "other")
	pu.RawQuery = q.Encode()
	wantRefused(t, w.get(pu.String()), samlidp.ErrInvalidSignature)

	// A signature from a key the SP did not register.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	w.spKey = other
	u, _ = w.authnRedirect(true, nil)
	pu, _ = url.Parse(u)
	q = pu.Query()
	q.Set(samlidp.ParamSigAlg, "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
	pu.RawQuery = q.Encode()
	wantRefused(t, w.get(pu.String()), samlidp.ErrUnsupportedSigAlg)
}

// The request must be addressed to this IdP's SSO URL, ask for the POST
// binding, and a NameID format the SP is configured for.
func TestRefuse_DestinationBindingNameIDPolicy(t *testing.T) {
	w := newWorld(t, setup{})
	cases := []struct {
		edit func(el *etree.Element)
		want *auth.Error
	}{
		{func(el *etree.Element) { el.CreateAttr("Destination", "https://other-idp.example/sso") }, samlidp.ErrWrongDestination},
		{func(el *etree.Element) { el.CreateAttr("ProtocolBinding", samlidp.BindingRedirect) }, samlidp.ErrUnsupportedBinding},
		{func(el *etree.Element) { el.FindElement("./NameIDPolicy").CreateAttr("Format", samlidp.NameIDEmail) }, samlidp.ErrNameIDPolicy},
		{func(el *etree.Element) { el.CreateAttr("Version", "1.1") }, samlidp.ErrInvalidRequest},
		{func(el *etree.Element) { el.CreateAttr("ForceAuthn", "maybe") }, samlidp.ErrInvalidRequest},
		{func(el *etree.Element) { el.RemoveAttr("ID") }, samlidp.ErrInvalidRequest},
	}
	for _, c := range cases {
		u, _ := w.authnRedirect(false, c.edit)
		wantRefused(t, w.get(u), c.want)
	}
	wantRefused(t, w.get(w.idp.SSOURL()), samlidp.ErrMissingRequestParam)
	wantRefused(t, w.get(w.idp.SSOURL()+"?SAMLRequest=a&SAMLRequest=b"), samlidp.ErrInvalidRequest)
	wantRefused(t, w.get(w.idp.SSOURL()+"?SAMLRequest=%%%"), samlidp.ErrInvalidRequest)
	wantRefused(t, w.get(w.idp.SSOURL()+"?SAMLRequest=bm90IGRlZmxhdGVk"), samlidp.ErrInvalidRequest)
	long := strings.Repeat("r", samlidp.MaxRelayState+1)
	wantRefused(t, w.get(w.idp.SSOURL()+"?SAMLRequest=x&RelayState="+long), samlidp.ErrRelayStateTooLong)
}

// ForceAuthn with a session older than the request sends the browser to
// log in again with prompt=login.
func TestForceAuthn_ReauthenticatesAnOldSession(t *testing.T) {
	w := newWorld(t, setup{})
	u, id := w.authnRedirect(false, nil)
	r, ans := w.submit(w.get(u))
	checkAccepted(t, w, r, ans, id)
	w.env.Clock.Advance(time.Minute)
	u, id = w.authnRedirect(false, func(el *etree.Element) { el.CreateAttr("ForceAuthn", "true") })
	w.seen = nil
	r, ans = w.submit(w.get(u))
	checkAccepted(t, w, r, ans, id)
	if w.logins != 2 {
		t.Fatalf("ForceAuthn did not send the browser to log in: logins = %d", w.logins)
	}
	var prompted bool
	for _, s := range w.seen {
		su, _ := url.Parse(s)
		prompted = prompted || (su.Path == loginPath && su.Query().Get(samlidp.ParamPrompt) == samlidp.PromptLogin)
	}
	if !prompted {
		t.Fatalf("no prompt=login in %v", w.seen)
	}
}

// IsPassive for a signed-out browser answers NoPassive at the ACS URL
// rather than showing the login page.
func TestIsPassive_AnswersNoPassive(t *testing.T) {
	w := newWorld(t, setup{})
	u, id := w.authnRedirect(false, func(el *etree.Element) { el.CreateAttr("IsPassive", "true") })
	p := w.get(u)
	resp := responseXML(t, p)
	code := resp.FindElement("./Status/StatusCode")
	if code.SelectAttrValue("Value", "") != samlidp.StatusResponder || code.FindElement("./StatusCode").SelectAttrValue("Value", "") != samlidp.StatusNoPassive {
		t.Fatalf("status: %v", code.Attr)
	}
	if resp.SelectAttrValue("InResponseTo", "") != id || resp.FindElement("./Assertion") != nil || resp.FindElement("./Signature") == nil {
		t.Fatal("a NoPassive answer must be signed, carry InResponseTo and no assertion")
	}
	// gosaml2 reports a response without an assertion as an error, which
	// is how an SP learns the user is not signed in.
	if _, ans := w.submit(p); ans.status != http.StatusUnauthorized || !strings.Contains(ans.body, "missing Assertion") {
		t.Fatalf("SP answer: %d %s", ans.status, ans.body)
	}
	if w.logins != 0 {
		t.Fatal("IsPassive showed the login page")
	}
}

// IdP-initiated sign-on is off unless the SP allows it, needs a session,
// and refuses a cross-site form.
func TestIdPInitiated(t *testing.T) {
	w := newWorld(t, setup{})
	initURL := strings.TrimSuffix(w.idp.SSOURL(), "/sso") + "/initiate"
	form := url.Values{"sp": {spEntityID}, samlidp.ParamRelayState: {testRelay}}
	post := func(origin string) page {
		req, _ := http.NewRequest(http.MethodPost, initURL, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
		return w.do(req)
	}
	// Signed out.
	wantRefused(t, post(w.idpSrv.URL), auth.ErrSignedOut)
	u, _ := w.authnRedirect(false, nil)
	_, _ = w.submit(w.get(u)) // signs the browser in
	wantRefused(t, post(w.idpSrv.URL), samlidp.ErrIdPInitiatedOff)

	w2 := newWorld(t, setup{spReg: func(sp *samlidp.ServiceProvider) { sp.AllowIdPInitiated = true }})
	u, _ = w2.authnRedirect(false, nil)
	_, _ = w2.submit(w2.get(u))
	post2 := func(origin string) page {
		req, _ := http.NewRequest(http.MethodPost, initURL[:0]+strings.TrimSuffix(w2.idp.SSOURL(), "/sso")+"/initiate", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
		return w2.do(req)
	}
	wantRefused(t, post2("https://evil.example"), auth.ErrOriginNotTrusted)
	r, ans := w2.submit(post2(w2.idpSrv.URL))
	if ans.status != http.StatusOK || r.NameID != w2.user.ID || r.InResponseTo != "" || r.RelayState != testRelay {
		t.Fatalf("IdP-initiated: %d %+v %s", ans.status, r, ans.body)
	}
}

// The email NameID format needs a verified address; the Access seam can
// refuse a user.
func TestNameIDEmailAndAccess(t *testing.T) {
	w := newWorld(t, setup{spReg: func(sp *samlidp.ServiceProvider) { sp.NameIDFormat = samlidp.NameIDEmail }})
	w.sp.NameIdFormat = samlidp.NameIDEmail
	u, id := w.authnRedirect(false, nil)
	r, ans := w.submit(w.get(u))
	if ans.status != http.StatusOK || r.NameID != testEmail || r.InResponseTo != id {
		t.Fatalf("email NameID: %d %+v", ans.status, r)
	}
	// A user with no verified email cannot get one.
	w.user = w.env.CreateUser("No Mail")
	w.env.Clock.Advance(time.Second)
	w.browser.Jar, _ = newJar()
	u, _ = w.authnRedirect(false, nil)
	wantRefused(t, w.get(u), samlidp.ErrNameIDUnavailable)

	denied := errors.New("not in the finance group")
	w3 := newWorld(t, setup{opts: []samlidp.Option{samlidp.Access(func(context.Context, auth.User, samlidp.ServiceProvider) error { return denied })}})
	u, _ = w3.authnRedirect(false, nil)
	wantRefused(t, w3.get(u), samlidp.ErrAccessDenied)
}

// The metadata names the entity, the signing certificate and both SSO
// bindings.
func TestMetadata(t *testing.T) {
	w := newWorld(t, setup{opts: []samlidp.Option{samlidp.WantAuthnRequestsSigned()}})
	p := w.get(w.idp.MetadataURL())
	if p.status != http.StatusOK {
		t.Fatalf("metadata: %d", p.status)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(p.body); err != nil {
		t.Fatal(err)
	}
	ed := doc.Root()
	if ed.SelectAttrValue("entityID", "") != w.idp.IdPEntityID() {
		t.Fatalf("entityID %q", ed.SelectAttrValue("entityID", ""))
	}
	idp := ed.FindElement("./IDPSSODescriptor")
	if idp.SelectAttrValue("WantAuthnRequestsSigned", "") != "true" {
		t.Fatal("WantAuthnRequestsSigned missing")
	}
	certText := idp.FindElement("./KeyDescriptor/KeyInfo/X509Data/X509Certificate").Text()
	der, _ := base64.StdEncoding.DecodeString(certText)
	if _, err := x509.ParseCertificate(der); err != nil {
		t.Fatalf("certificate: %v", err)
	}
	locs := idp.FindElements("./SingleSignOnService")
	if len(locs) != 2 || locs[0].SelectAttrValue("Location", "") != w.idp.SSOURL() {
		t.Fatalf("SSO services: %d", len(locs))
	}
}
