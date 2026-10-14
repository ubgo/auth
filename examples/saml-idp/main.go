// Command saml-idp makes this app a SAML 2.0 identity provider: another
// service (a SAML service provider such as a wiki, a ticketing tool or a
// vendor dashboard) sends its users here to sign in, and gets back a signed
// assertion naming them.
//
//	go run ./saml-idp       # serve the identity provider on :8081
//	go run ./saml-idp sp    # serve a demo service provider on :8082
//
// Open http://localhost:8082 to sign in to the demo SP through the IdP. The
// IdP's signing key comes from SAML_IDP_KEY and SAML_IDP_CERT (PEM files);
// without them every start signs with a new key, and an SP must load the
// metadata again.
package main

import (
	"cmp"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/beevik/etree"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/samlidp"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "saml-idp.db"
	// authPrefix is where the library's own routes are mounted.
	authPrefix = "/auth"
	// loginPath is the IdP's login page. A signed-out browser is sent here
	// with the continue URL in return_to.
	loginPath = "/login"
	// cmdSP is the subcommand that serves the demo service provider.
	cmdSP = "sp"
	// envKey and envCert name the PEM files of the IdP's signing key and
	// certificate.
	envKey  = "SAML_IDP_KEY"
	envCert = "SAML_IDP_CERT"
	// rsaBits is the size of a generated signing key.
	rsaBits = 2048
	// certLifetime is how long a generated certificate is valid.
	certLifetime = 365 * 24 * time.Hour
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
	// spACSPath and spMetadataPath are the demo SP's endpoints.
	spACSPath      = "/saml/acs"
	spMetadataPath = "/saml/metadata"
)

var (
	// port is the IdP's port: 8081, or $PORT.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// baseURL is the IdP's public URL: its endpoints live under it.
	baseURL = "http://localhost:" + port
	// spPort is the demo SP's port: 8082, or $SP_PORT.
	spPort = cmp.Or(os.Getenv("SP_PORT"), "8082")
	// spURL is the demo SP's public URL.
	spURL = "http://localhost:" + spPort
)

// sqlitePragmas are the settings every SQLite connection needs.
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

func main() {
	if len(os.Args) > 1 && os.Args[1] == cmdSP {
		// The SP is another program: it knows the IdP only by its metadata.
		sp, err := newServiceProvider(spURL, baseURL+samlidp.DefaultBasePath+"/metadata", http.DefaultClient)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("demo service provider on %s", spURL)
		srv := &http.Server{Addr: "localhost:" + spPort, Handler: spHandler(sp), ReadHeaderTimeout: readHeaderTimeout}
		log.Fatal(srv.ListenAndServe())
	}
	db, err := sql.Open("sqlite", "file:"+dbFile+"?"+sqlitePragmas)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	key, cert, err := signingKey(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	a, idp, err := newAuth(db, baseURL, key, cert, demoSP(spURL))
	if err != nil {
		log.Fatal(err) // a broken configuration fails here, not at the first sign-in
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}
	log.Printf("identity provider on %s, metadata at %s", baseURL, idp.MetadataURL())
	srv := &http.Server{Addr: "localhost:" + port, Handler: newHandler(a, idp), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// demoSP registers the demo service provider: its entity ID, the one ACS
// URL assertions may be posted to, and the attributes it receives. The
// NameID is the persistent default, the user's ID; the email attribute is
// released only once the address is verified. A real app loads its SPs from
// configuration or a table (WithServiceProviderStore).
//
//ds:def id=demosp-samlidp-example
func demoSP(base string) samlidp.ServiceProvider {
	return samlidp.ServiceProvider{
		EntityID:   base + spMetadataPath,
		ACSURLs:    []string{base + spACSPath},
		Attributes: samlidp.DefaultAttributes,
	}
}

// newAuth wires email and password sign-in and the identity provider.
//
//ds:def id=newauth-samlidp-example
func newAuth(db *sql.DB, base string, key crypto.Signer, cert *x509.Certificate, sps ...samlidp.ServiceProvider) (*auth.Auth, *samlidp.Plugin, error) {
	idp := samlidp.New(
		samlidp.Issuer(base),
		samlidp.LoginPage(loginPath),
		samlidp.SigningKey(key, cert),
		samlidp.ServiceProviders(sps...),
	)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(base),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(logMailer{})), password.New(), idp),
	)
	return a, idp, err
}

// newHandler mounts the library's routes, the IdP's endpoints and the
// login page.
//
//ds:def id=newhandler-samlidp-example
func newHandler(a *auth.Auth, idp *samlidp.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle(samlidp.DefaultBasePath+"/", idp.Handler())
	mux.Handle("GET "+loginPath, loginPage(a))
	return mux
}

// loginPageTemplate signs the user in with the password routes, then sends
// the browser back to the continue URL the IdP sent it here with. A real
// page offers every sign-in method the app has.
//
//ds:def id=loginpagetemplate-samlidp-example
var loginPageTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<meta charset="utf-8">
<title>Sign in</title>
<form id="f"><input name="identifier" type="email"> <input name="password" type="password"> <button>Sign in</button></form>
<pre id="out"></pre>
<script>
const back = {{.ReturnTo}};
document.getElementById("f").onsubmit = async (e) => {
  e.preventDefault();
  const body = Object.fromEntries(new FormData(e.target));
  const res = await fetch("{{.Prefix}}/password/sign-in", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
  if (res.ok) { location.href = back; return; }
  document.getElementById("out").textContent = (await res.json()).error.message;
};
</script>
`))

// loginPageData is what loginPageTemplate shows.
type loginPageData struct {
	// ReturnTo is the IdP's continue URL, checked against the trusted
	// origins before the page links to it.
	ReturnTo string
	// Prefix is where the library's routes are mounted.
	Prefix string
}

// loginPage serves loginPageTemplate. The return URL arrives in the query,
// so it is checked like any other redirect target.
func loginPage(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		back := r.URL.Query().Get(samlidp.DefaultReturnParam)
		if !a.TrustsReturnURL(back) {
			back = "/"
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := loginPageTemplate.Execute(w, loginPageData{ReturnTo: back, Prefix: authPrefix}); err != nil {
			log.Printf("login page: %v", err)
		}
	})
}

// signingKey reads the IdP's key and certificate from the PEM files getenv
// names, or generates both and says so: SPs that trusted a generated
// certificate stop accepting assertions when the process restarts.
func signingKey(getenv func(string) string) (crypto.Signer, *x509.Certificate, error) {
	kf, cf := getenv(envKey), getenv(envCert)
	if kf != "" || cf != "" {
		return loadKeyPair(kf, cf)
	}
	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "saml-idp example"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(certLifetime)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	log.Printf("%s and %s are not set: signing with a new key; SPs must load the metadata again after a restart", envKey, envCert)
	return key, cert, err
}

// loadKeyPair reads a PEM private key (PKCS#1 or PKCS#8) and certificate.
func loadKeyPair(keyFile, certFile string) (crypto.Signer, *x509.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("%s/%s: %w", envKey, envCert, err)
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("%s: not a signing key", envKey)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	return signer, cert, err
}

// newServiceProvider is the demo SP: gosaml2, configured from the IdP's
// metadata, which is all a real SP needs from you.
//
//ds:def id=newserviceprovider-samlidp-example
func newServiceProvider(base, metadataURL string, client *http.Client) (*saml2.SAMLServiceProvider, error) {
	res, err := client.Get(metadataURL)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	doc := etree.NewDocument()
	if _, err := doc.ReadFrom(io.LimitReader(res.Body, 1<<20)); err != nil {
		return nil, err
	}
	ed := doc.Root()
	certEl := ed.FindElement("./IDPSSODescriptor/KeyDescriptor/KeyInfo/X509Data/X509Certificate")
	ssoEl := ed.FindElement("./IDPSSODescriptor/SingleSignOnService[@Binding='" + samlidp.BindingRedirect + "']")
	if certEl == nil || ssoEl == nil {
		return nil, errors.New("metadata has no signing certificate or redirect SSO service")
	}
	der, err := base64.StdEncoding.DecodeString(certEl.Text())
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	sp := demoSP(base)
	return &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL: ssoEl.SelectAttrValue("Location", ""), IdentityProviderIssuer: ed.SelectAttrValue("entityID", ""),
		ServiceProviderIssuer: sp.EntityID, AssertionConsumerServiceURL: sp.ACSURLs[0], AudienceURI: sp.EntityID,
		IDPCertificateStore: &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}},
		NameIdFormat:        samlidp.NameIDPersistent, AllowMissingAttributes: true, Clock: dsig.NewRealClock(),
	}, nil
}

// spHandler serves the demo SP: / starts SP-initiated sign-in, the ACS
// checks the IdP's response and shows who signed in. A real SP would also
// check InResponseTo against the requests it sent, and start a session.
func spHandler(sp *saml2.SAMLServiceProvider) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		u, err := sp.BuildAuthURL("/")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, u, http.StatusFound)
	})
	mux.HandleFunc("POST "+spACSPath, func(w http.ResponseWriter, r *http.Request) {
		info, err := sp.RetrieveAssertionInfo(r.FormValue(samlidp.ParamSAMLResponse))
		if err != nil || info.WarningInfo.InvalidTime || info.WarningInfo.NotInAudience {
			http.Error(w, "assertion refused", http.StatusForbidden)
			return
		}
		fmt.Fprintf(w, "Signed in as %s (%s)\n", info.NameID, info.Values.Get("name"))
	})
	return mux
}

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
