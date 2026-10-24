package samlidp_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/samlidp"
	_ "modernc.org/sqlite" // registers the "sqlite" driver authtest opens
)

const (
	testEmail  = "ada@example.com"
	testRelay  = "relay-42"
	loginPath  = "/login"
	acsPath    = "/acs"
	spEntityID = "https://sp.example.test/metadata"
)

// keyPair is a fresh RSA key with a self-signed certificate valid around
// now.
func keyPair(t *testing.T, cn string, now time.Time) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// world is an IdP (the plugin on a real TLS server with a login page) and an
// SP (gosaml2 on a real HTTP server) on localhost, with a browser that keeps
// cookies.
type world struct {
	t       *testing.T
	env     *authtest.Env
	idp     *samlidp.Plugin
	idpSrv  *httptest.Server
	spSrv   *httptest.Server
	sp      *saml2.SAMLServiceProvider
	spKey   *rsa.PrivateKey
	spCert  *x509.Certificate
	user    auth.User
	browser *http.Client
	logins  int
	noLogin bool
	// seen is every URL the browser was redirected to, in order.
	seen []string
}

// setup configures one world; spReg edits the SP registration, opts add
// plugin options.
type setup struct {
	spReg func(sp *samlidp.ServiceProvider)
	opts  []samlidp.Option
	// faults, when set, fails a chosen database call (authtest.WithFaults).
	faults *authtest.Faults
	// extra are more plugins, after the IdP.
	extra []auth.Plugin
	// idpKey replaces the IdP's RSA key.
	idpKey func(t *testing.T, now time.Time) (crypto.Signer, *x509.Certificate)
}

func newWorld(t *testing.T, s setup) *world {
	t.Helper()
	w := &world{t: t}
	idpMux, spMux := http.NewServeMux(), http.NewServeMux()
	w.idpSrv = httptest.NewTLSServer(idpMux)
	t.Cleanup(w.idpSrv.Close)
	w.spSrv = httptest.NewServer(spMux)
	t.Cleanup(w.spSrv.Close)

	now := time.Now().UTC()
	var idpKey crypto.Signer
	idpKey, idpCert := keyPair(t, "idp", now)
	if s.idpKey != nil {
		idpKey, idpCert = s.idpKey(t, now)
	}
	w.spKey, w.spCert = keyPair(t, "sp", now)
	reg := samlidp.ServiceProvider{
		EntityID: spEntityID, ACSURLs: []string{w.spSrv.URL + acsPath},
		Certificates: []*x509.Certificate{w.spCert}, Attributes: samlidp.DefaultAttributes,
	}
	if s.spReg != nil {
		s.spReg(&reg)
	}
	opts := append([]samlidp.Option{
		samlidp.Issuer(w.idpSrv.URL), samlidp.LoginPage(loginPath),
		samlidp.SigningKey(idpKey, idpCert), samlidp.ServiceProviders(reg),
	}, s.opts...)
	w.idp = samlidp.New(opts...)
	envOpts := []authtest.Option{authtest.WithBaseURL(w.idpSrv.URL)}
	if s.faults != nil {
		envOpts = append(envOpts, authtest.WithFaults(s.faults))
	}
	w.env = authtest.New(t, append(envOpts, authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin {
		return append([]auth.Plugin{email.New(email.Login(), email.SignInWithCode(), email.WithMailer(e.Mail)), w.idp}, s.extra...)
	}))...)
	w.user = w.env.CreateUser("Ada Lovelace", authtest.Identity{Kind: email.KindEmail, Value: testEmail})

	idpMux.Handle("/saml/", w.idp.Handler())
	idpMux.HandleFunc(loginPath, w.login)
	spMux.HandleFunc(acsPath, w.acs)

	w.sp = &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL: w.idp.SSOURL(), IdentityProviderIssuer: w.idp.IdPEntityID(),
		ServiceProviderIssuer: spEntityID, AssertionConsumerServiceURL: w.spSrv.URL + acsPath, AudienceURI: spEntityID,
		IDPCertificateStore: &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{idpCert}},
		NameIdFormat:        samlidp.NameIDPersistent, AllowMissingAttributes: true,
	}
	_ = w.sp.SetSPSigningKeyStore(&saml2.KeyStore{Signer: w.spKey, Cert: w.spCert.Raw})

	jar, _ := cookiejar.New(nil)
	tr := w.idpSrv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: w.idpSrv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12}
	w.browser = &http.Client{Jar: jar, Transport: tr, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		w.seen = append(w.seen, req.URL.String())
		return nil
	}}
	return w
}

// login is the app's login page: it signs the test user in (as a real
// login form would after checking a password) and returns to return_to.
func (w *world) login(rw http.ResponseWriter, r *http.Request) {
	if w.noLogin {
		_, _ = io.WriteString(rw, "login page")
		return
	}
	rt := r.URL.Query().Get(samlidp.DefaultReturnParam)
	if !w.env.Auth.TrustsReturnURL(rt) {
		http.Error(rw, "bad return", http.StatusBadRequest)
		return
	}
	w.logins++
	http.SetCookie(rw, w.env.SignIn(w.user.ID).Cookie())
	http.Redirect(rw, r, rt, http.StatusSeeOther)
}

// acsResult is what the SP's ACS reports about a response it accepted.
type acsResult struct {
	NameID       string
	Email        string
	Name         string
	InResponseTo string
	RelayState   string
	Warnings     saml2.WarningInfo
	RespSigned   bool
	Status       string
}

// acs is the SP's assertion consumer service, entirely gosaml2.
func (w *world) acs(rw http.ResponseWriter, r *http.Request) {
	w.sp.Clock = dsig.NewFakeClockAt(w.env.Clock.Now())
	encoded := r.FormValue(samlidp.ParamSAMLResponse)
	resp, err := w.sp.ValidateEncodedResponse(encoded)
	if err != nil {
		http.Error(rw, "validate: "+err.Error(), http.StatusUnauthorized)
		return
	}
	out := acsResult{InResponseTo: resp.InResponseTo, RelayState: r.FormValue(samlidp.ParamRelayState), Status: resp.Status.StatusCode.Value}
	if out.Status == samlidp.StatusSuccess {
		info, err := w.sp.RetrieveAssertionInfo(encoded)
		if err != nil {
			http.Error(rw, "assertion: "+err.Error(), http.StatusUnauthorized)
			return
		}
		out.NameID, out.Email, out.Name = info.NameID, info.Values.Get("email"), info.Values.Get("name")
		out.Warnings, out.RespSigned = *info.WarningInfo, info.ResponseSignatureValidated
	}
	_ = json.NewEncoder(rw).Encode(out)
}

// authnRedirect builds an SP-initiated HTTP-Redirect URL with gosaml2 and
// returns it with the request's ID. edit, when set, changes the request
// before it is encoded (and signed, when sign is true).
func (w *world) authnRedirect(sign bool, edit func(el *etree.Element)) (string, string) {
	w.t.Helper()
	w.sp.Clock = dsig.NewFakeClockAt(w.env.Clock.Now())
	w.sp.SignAuthnRequests = sign
	doc, err := w.sp.BuildAuthRequestDocumentNoSig()
	if err != nil {
		w.t.Fatal(err)
	}
	if edit != nil {
		edit(doc.Root())
	}
	u, err := w.sp.BuildAuthURLRedirect(testRelay, doc)
	if err != nil {
		w.t.Fatal(err)
	}
	return u, doc.Root().SelectAttrValue("ID", "")
}

// authnPOST builds an SP-initiated HTTP-POST SAMLRequest value.
func (w *world) authnPOST(sign bool, edit func(el *etree.Element)) (string, string) {
	w.t.Helper()
	w.sp.Clock = dsig.NewFakeClockAt(w.env.Clock.Now())
	w.sp.SignAuthnRequests = sign
	doc, err := w.sp.BuildAuthRequestDocumentNoSig()
	if err != nil {
		w.t.Fatal(err)
	}
	if edit != nil {
		edit(doc.Root())
	}
	root := doc.Root()
	if sign {
		if root, err = w.sp.SignAuthnRequest(root); err != nil {
			w.t.Fatal(err)
		}
	}
	out := etree.NewDocument()
	out.SetRoot(root)
	b, _ := out.WriteToBytes()
	return base64.StdEncoding.EncodeToString(b), root.SelectAttrValue("ID", "")
}

var (
	formAction = regexp.MustCompile(`action="([^"]+)"`)
	formField  = regexp.MustCompile(`name="(SAMLResponse|RelayState)" value="([^"]*)"`)
)

// page is a final browser answer.
type page struct {
	status int
	url    string
	body   string
}

func (w *world) do(req *http.Request) page {
	w.t.Helper()
	res, err := w.browser.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return page{status: res.StatusCode, url: res.Request.URL.String(), body: string(b)}
}

func (w *world) get(u string) page {
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	return w.do(req)
}

func (w *world) postForm(u string, v url.Values) page {
	req, _ := http.NewRequest(http.MethodPost, u, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return w.do(req)
}

// submit posts the IdP's auto-submitting form to its action, as the
// browser's script would, and decodes the SP's answer.
func (w *world) submit(p page) (acsResult, page) {
	w.t.Helper()
	if p.status != http.StatusOK || !strings.Contains(p.body, samlidp.ParamSAMLResponse) {
		w.t.Fatalf("expected the response form, got %d at %s: %s", p.status, p.url, p.body)
	}
	action := html.UnescapeString(formAction.FindStringSubmatch(p.body)[1])
	v := url.Values{}
	for _, m := range formField.FindAllStringSubmatch(p.body, -1) {
		v.Set(m[1], html.UnescapeString(m[2]))
	}
	ans := w.postForm(action, v)
	var r acsResult
	if ans.status == http.StatusOK {
		_ = json.Unmarshal([]byte(ans.body), &r)
	}
	return r, ans
}

// wantRefused checks an IdP error page with the error's status and code.
func wantRefused(t *testing.T, p page, want *auth.Error) {
	t.Helper()
	if p.status != want.Status || !strings.Contains(p.body, want.Code) {
		t.Fatalf("want %d %s, got %d at %s: %s", want.Status, want.Code, p.status, p.url, p.body)
	}
	if strings.Contains(p.body, samlidp.ParamSAMLResponse) {
		t.Fatal("a refusal carried a SAMLResponse")
	}
}

// checkAccepted is what every successful sign-in must look like at the SP.
func checkAccepted(t *testing.T, w *world, r acsResult, ans page, reqID string) {
	t.Helper()
	if ans.status != http.StatusOK {
		t.Fatalf("SP refused the response: %d %s", ans.status, ans.body)
	}
	if r.NameID != w.user.ID || r.Email != testEmail || r.Name != "Ada Lovelace" {
		t.Fatalf("subject: %+v", r)
	}
	if r.InResponseTo != reqID || r.RelayState != testRelay {
		t.Fatalf("InResponseTo %q relay %q, want %q %q", r.InResponseTo, r.RelayState, reqID, testRelay)
	}
	if r.Warnings.NotInAudience || r.Warnings.InvalidTime || r.Warnings.OneTimeUse || r.Warnings.ProxyRestriction != nil {
		t.Fatalf("SP warnings: %+v", r.Warnings)
	}
	if !r.RespSigned {
		t.Fatal("the response envelope was not signed")
	}
}

// The full SP-initiated round trip over real HTTP, HTTP-Redirect binding: a
// signed-out browser is sent to the login page, comes back, and gosaml2
// accepts the signed response.
func TestRoundTrip_RedirectBinding(t *testing.T) {
	w := newWorld(t, setup{})
	u, id := w.authnRedirect(false, nil)
	r, ans := w.submit(w.get(u))
	checkAccepted(t, w, r, ans, id)
	if w.logins != 1 {
		t.Fatalf("logins = %d, want 1", w.logins)
	}
	// Signed in now: a second request goes straight through.
	u2, id2 := w.authnRedirect(false, nil)
	r, ans = w.submit(w.get(u2))
	checkAccepted(t, w, r, ans, id2)
	if w.logins != 1 {
		t.Fatalf("a signed-in browser was sent to log in again: logins = %d", w.logins)
	}
}

// The HTTP-POST binding with a request signed by the SP's registered key,
// which the SP requires.
func TestRoundTrip_SignedPOSTBinding(t *testing.T) {
	w := newWorld(t, setup{spReg: func(sp *samlidp.ServiceProvider) { sp.RequireSignedRequests = true }})
	v, id := w.authnPOST(true, nil)
	r, ans := w.submit(w.postForm(w.idp.SSOURL(), url.Values{samlidp.ParamSAMLRequest: {v}, samlidp.ParamRelayState: {testRelay}}))
	checkAccepted(t, w, r, ans, id)
}

// A redirect request with a query signature from the SP's key.
func TestRoundTrip_SignedRedirectBinding(t *testing.T) {
	w := newWorld(t, setup{opts: []samlidp.Option{samlidp.WantAuthnRequestsSigned()}})
	u, id := w.authnRedirect(true, nil)
	r, ans := w.submit(w.get(u))
	checkAccepted(t, w, r, ans, id)
}

// newJar is an empty cookie jar: a browser with no session.
func newJar() (http.CookieJar, error) { return cookiejar.New(nil) }

// An ECDSA IdP key signs with ECDSA-SHA256, which gosaml2 verifies.
func TestRoundTrip_ECDSAKey(t *testing.T) {
	w := newWorld(t, setup{idpKey: func(t *testing.T, now time.Time) (crypto.Signer, *x509.Certificate) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "idp-ec"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(der)
		return key, cert
	}})
	u, id := w.authnRedirect(false, nil)
	r, ans := w.submit(w.get(u))
	checkAccepted(t, w, r, ans, id)
}
