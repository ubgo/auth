# SAML identity provider: let other services sign in with your app

You will have a SAML 2.0 identity provider (IdP) inside your app. A service provider (SP), such as a wiki, a ticketing tool or a vendor's dashboard, sends its users to you, they sign in with whatever sign-in methods your app has, and the SP receives a signed assertion naming them. It is the SAML sibling of the [OAuth provider](oauthprovider.md), and the mirror of [enterprise SSO](sso.md), which makes your app the service provider of someone else's IdP.

Use this plugin when a service your users need only speaks SAML (many enterprise tools do) and your app should be where they sign in. Don't use it to sign users into your own app with Okta or Entra ID (that is [SSO](sso.md)), or for an app that speaks OpenID Connect (that is the [OAuth provider](oauthprovider.md)).

## Before you start

- An app with a sign-in method, as in [your first app](../start/first-app.md): the login page signs the user in before the IdP answers.
- A signing key and its certificate: an RSA or ECDSA `crypto.Signer` (a key in memory, or a KMS or HSM handle) and the X.509 certificate SPs will trust.
- The module: `go get github.com/ubgo/auth/plugin/samlidp`. Its [README](../../plugin/samlidp/README.md) is the reference for every option, endpoint and error.
- The example this guide is built from, with a `main_test.go` that runs the whole round trip against a gosaml2 SP over real HTTP: [`examples/saml-idp`](../../examples/saml-idp/).

## Step 1 — Register the service providers

An SP is known by its entity ID, the Issuer of its requests and the only Audience of the assertions it receives. Its ACS URLs are the only places an assertion is ever posted: a request naming any other URL is refused, never answered. The example registers its demo SP with the default persistent NameID (the user's ID) and the default attributes (the verified email address and the name):

<!-- ds:block id=demosp-samlidp-example -->
**demoSP** · [`examples/saml-idp/main.go:127-133`](../../examples/saml-idp/main.go#L127-L133)

```go
func demoSP(base string) samlidp.ServiceProvider {
	return samlidp.ServiceProvider{
		EntityID:   base + spMetadataPath,
		ACSURLs:    []string{base + spACSPath},
		Attributes: samlidp.DefaultAttributes,
	}
}
```
<!-- /ds:block hash=6fba50 -->

Register SPs in code with `ServiceProviders`, or look them up at run time with `WithServiceProviderStore`, for an admin page that adds them; every SP a store answers is checked the same way `auth.New` checks static ones.

## Step 2 — Wire the provider

The provider needs the issuer (your app's public origin, https, or http on a loopback host while you develop), the login page and the signing key:

<!-- ds:block id=newauth-samlidp-example -->
**newAuth** · [`examples/saml-idp/main.go:138-151`](../../examples/saml-idp/main.go#L138-L151)

```go
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
```
<!-- /ds:block hash=d74ad9 -->

Then mount its handler under [`DefaultBasePath`](ds:block?id=samlidp-defaultbasepath-q4m8zt2k), beside the library's own routes and your login page:

<!-- ds:block id=newhandler-samlidp-example -->
**newHandler** · [`examples/saml-idp/main.go:157-163`](../../examples/saml-idp/main.go#L157-L163)

```go
func newHandler(a *auth.Auth, idp *samlidp.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle(samlidp.DefaultBasePath+"/", idp.Handler())
	mux.Handle("GET "+loginPath, loginPage(a))
	return mux
}
```
<!-- /ds:block hash=28435a -->

The SP administrator needs one thing from you: the metadata URL, `idp.MetadataURL()`. It carries the entity ID, the signing certificate and the single sign-on service in both bindings.

## Step 3 — The login page

A browser that is not signed in is sent to the login page with the continue URL in `return_to`. The page signs the user in and sends the browser back to that URL, after checking it with `TrustsReturnURL` like any other redirect target:

<!-- ds:block id=loginpagetemplate-samlidp-example -->
**loginPageTemplate** · [`examples/saml-idp/main.go:170-185`](../../examples/saml-idp/main.go#L170-L185)

```go
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
```
<!-- /ds:block hash=5eb2c8 -->

When the SP asked for `ForceAuthn` and the browser's session is older than the request, the login page also gets `prompt=login`: it must make the user authenticate again even though a session exists. A session still waiting for its second factor counts as signed out.

## Step 4 — What the SP receives

The continue step answers a page that posts the response to the ACS URL. The response and the assertion are both signed (an SP that refuses two signatures sets `UnsignedResponse`). The assertion names the SP's entity ID as its only audience, the ACS URL as recipient, the request's ID as `InResponseTo`, and expires after [`DefaultAssertionTTL`](ds:block?id=samlidp-defaultassertionttl-w7n3kp5x). The demo SP checks it with gosaml2:

<!-- ds:block id=newserviceprovider-samlidp-example -->
**newServiceProvider** · [`examples/saml-idp/main.go:252-283`](../../examples/saml-idp/main.go#L252-L283)

```go
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
```
<!-- /ds:block hash=ff18b7 -->

`Access` decides per user and SP whether an assertion is issued, which is where roles, groups or an organization's app assignments plug in; without it every signed-in user may sign in to every registered SP.

## What is refused

| Request | Answer |
|---|---|
| An issuer nobody registered | `samlidp.unknown_service_provider` |
| An ACS URL that is not registered exactly | `samlidp.acs_not_registered` |
| A request ID already answered | `samlidp.request_replayed` |
| An IssueInstant older than [`DefaultRequestMaxAge`](ds:block?id=samlidp-defaultrequestmaxage-h2v9qm4r), or ahead by more than [`DefaultClockSkew`](ds:block?id=samlidp-defaultclockskew-z5k8wn3t) | `samlidp.request_expired` |
| An unsigned request from an SP with `RequireSignedRequests` (or under `WantAuthnRequestsSigned`) | `samlidp.signature_required` |
| A signature that does not verify, or a wrapped one | `samlidp.invalid_signature` |
| A Destination other than this IdP's SSO URL | `samlidp.wrong_destination` |
| A continue link used twice, or older than [`DefaultLoginTTL`](ds:block?id=samlidp-defaultloginttl-p3x7mq9v) | `samlidp.request_not_found` |

Every refusal is shown to the user as a page and never posted to an SP. The endpoints are rate limited per IP by [`DefaultRateLimits`](ds:block?id=samlidp-defaultratelimits-b6t2qn8m).

## IdP-initiated sign-on

An SP with `AllowIdPInitiated` can be opened from your app: a form on your own page posts `sp` (and optionally `RelayState`) to `/saml/initiate`, and the user lands in the SP signed in. It needs the session and passes the origin check, so another site cannot trigger it. It is off by default because an unsolicited assertion has no request to bind it to.

## Not implemented yet

Single logout is deferred: the metadata advertises no SingleLogoutService, and an SP's logout does not end the session here. Encrypted assertions, signed metadata and the Artifact binding are not implemented either.
