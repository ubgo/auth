# SSO: sign a company's people in through their own identity provider

Enterprise single sign-on next to email and password. One OpenID Connect provider is configured in code from environment variables; any signed-in user can register more providers (OIDC or SAML) at run time, so a customer's admin connects their Okta, Entra ID or Google Workspace without a deploy. A person types their work email and the domain picks the provider.

## Run it

Create an OIDC application at the IdP with the redirect URI `http://localhost:8081/auth/sso/callback`, then:

```sh
cd examples
AUTH_SECRET=$(openssl rand -base64 32) SSO_ISSUER=https://acme.okta.com \
  SSO_CLIENT_ID=… SSO_CLIENT_SECRET=… SSO_DOMAIN=acme.com go run ./sso
```

| Variable | Meaning |
|---|---|
| `AUTH_SECRET` | Required, at least 32 bytes: each provider's client secret and SAML keys are sealed in the database with a key derived from it |
| `SSO_ISSUER`, `SSO_CLIENT_ID`, `SSO_CLIENT_SECRET`, `SSO_DOMAIN` | The provider in code; all four or none. `SSO_DOMAIN` takes a comma-separated list |
| `SSO_PROVIDER_ID` | Its id, `workforce` by default |
| `PORT` | 8081 by default |

Open `http://localhost:8081/`, type an address in `SSO_DOMAIN` and press the button. It creates `sso.db` (SQLite); mail is printed to the log. Run the tests with `go test ./sso`.

## Walkthrough

This transcript was captured with placeholder Google Workspace credentials (`SSO_ISSUER=https://accounts.google.com`, `SSO_DOMAIN=acme.com`), so it stops where the IdP takes over. The full round trip, OIDC and SAML, runs in the tests against `plugin/sso/ssotest`'s fake IdPs, below.

The server prints the redirect URI to register at the IdP:

```text
2026/10/07 17:26:30 provider workforce for acme.com: redirect URI http://localhost:8081/auth/sso/callback
2026/10/07 17:26:30 listening on http://localhost:8081
```

A work email starts the sign-in. The plugin fetched the issuer's discovery document, and answers the IdP's authorization URL with PKCE, a nonce and the address as `login_hint`, and binds the single-use state to this browser in the `__Host-auth_flow` cookie:

```sh
curl -s -c ada.txt -D - -X POST localhost:8081/auth/sso/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"email":"ada@acme.com","callbackURL":"/me"}'
```

```text
Set-Cookie: __Host-auth_flow=xGeW8nY5fmEl7B8nRc_psXk1psxf1U3B9GI0F0_iKhA; Path=/; Expires=Wed, 07 Oct 2026 12:06:30 GMT; HttpOnly; Secure; SameSite=Lax
{"url":"https://accounts.google.com/o/oauth2/v2/auth?client_id=1234-example.apps.googleusercontent.com&code_challenge=FoIEHqdwSShaEkmHPxLEI-UVPWs7JO0xX3h1H7QE_AM&code_challenge_method=S256&login_hint=ada%40acme.com&nonce=FoIEHqdwSShaEkmHPxLEI-UVPWs7JO0xX3h1H7QE_AM&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fauth%2Fsso%2Fcallback&response_type=code&scope=openid+email+profile+offline_access&state=xGeW8nY5fmEl7B8nRc_psXk1psxf1U3B9GI0F0_iKhA","redirect":true}
```

An address no provider serves is told so, and a callback whose state this browser did not start is refused:

```sh
curl -s -X POST localhost:8081/auth/sso/sign-in -H 'Origin: http://localhost:8081' -d '{"email":"eve@nowhere.com"}'
curl -s 'localhost:8081/auth/sso/callback?code=stolen&state=forged'
```

```json
{"error":{"code":"sso.provider_not_found","message":"No sign-in provider was found for this account."}}
{"error":{"code":"sso.state_invalid","message":"This sign-in link has expired. Start again."}}
```

Registering a provider needs a signed-in user. A customer's admin signs up and registers their SAML IdP: its SSO URL, its signing certificate (`idp.crt`, a PEM file) and its entity id. The answer is the sanitized provider with the ACS URL and the metadata URL to enter at the IdP:

```sh
curl -s -X POST localhost:8081/auth/sso/register -H 'Origin: http://localhost:8081' -d '{"providerId":"globex"}'
curl -s -c admin.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"admin@example.com","password":"correct horse battery staple"}'
jq -nc --rawfile cert idp.crt '{providerId:"globex",issuer:"http://localhost:8081/sp/globex",domain:"globex.com",
  samlConfig:{entryPoint:"https://idp.globex.com/sso",cert:$cert,wantAssertionsSigned:true,
  idpMetadata:{entityID:"https://idp.globex.com"},spMetadata:{entityID:"http://localhost:8081/sp/globex"}}}' > body.json
curl -s -b admin.txt -X POST localhost:8081/auth/sso/register -H 'Origin: http://localhost:8081' -d @body.json
```

```json
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"user":{"id":"usr_xatjokzecckapsfws45d5i2d","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"providerId":"globex","type":"saml","protocols":["saml"],"issuer":"http://localhost:8081/sp/globex","domain":"globex.com","domainVerified":false,"samlConfig":{"entryPoint":"https://idp.globex.com/sso","idpEntityId":"https://idp.globex.com","spEntityId":"http://localhost:8081/sp/globex","wantAssertionsSigned":true,"authnRequestsSigned":false,"certificatesCount":1},"acsURL":"http://localhost:8081/auth/sso/saml2/sp/acs","spMetadataURL":"http://localhost:8081/auth/sso/saml2/sp/metadata?providerId=globex"}
```

From then on a `globex.com` address goes to that IdP with a SAML AuthnRequest, and the SP metadata is there for the IdP admin to import:

```sh
curl -s -X POST localhost:8081/auth/sso/sign-in -H 'Origin: http://localhost:8081' -d '{"email":"bob@globex.com","callbackURL":"/me"}'
curl -s 'localhost:8081/auth/sso/saml2/sp/metadata?providerId=globex' | jq -r .metadata
```

```text
{"url":"https://idp.globex.com/sso?RelayState=wOE1rJzk6Yb3LCDWZnaBFF5hW-mB_FKlplCz7EisFmI&SAMLRequest=fJFda%2BowGMe%2FSsh9m7QHXwi2UPWcs6qbrdbhdjNijTaQJl2edNNvP3wZCBteP%2F83nt8AeK0alrSu0gvx3gpw6FArDex8iHBrNTMcJDDNawHMlWyZPM5Y6FPWWONMaRS%2Bsdx3cABhnTQao3Qc4bfOpOgcc7r5lxd29jeY13T9%2F1CthjtZTfq9l%2Bkon3rJmu7oMMfoWViQRkc49ClG2bV8KPVW6v393s1FBOyhKDIvmy8LjJLvLSOjoa2FXQr7IUuxWswiXDnXMEKUKbmqDDjWp%2F2A8NZVBMCQ03NCAg3hJWCUArQi1eC4dhEOadj1AurRXhEErNNlf%2BgrRmMBTmp%2B6rukAyNEbht%2Fr8xGHPzS1KdkHJ%2BJsHOkjX%2BfAQ25uAbkVnxl%2BcRrkY4zo2R5RIlS5nNkBXciws62ApN4QH5Cj78GAA%3D%3D","redirect":true}
<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://localhost:8081/sp/globex">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8081/auth/sso/saml2/sp/acs" index="1"></AssertionConsumerService>
  </SPSSODescriptor>
</EntityDescriptor>
```

The IdP posts its signed answer to the ACS URL; the plugin checks the signature, issuer, audience, destination, `InResponseTo` and timestamps, signs the person in and redirects to `/me`.

## The code

The provider in code comes from the environment. A provider in code counts as domain-verified, so a first sign-in may link to an existing user holding the same verified address in that domain:

<!-- ds:block id=sso-providerfromenv-7k3qw9mz -->
**providerFromEnv** · [`examples/sso/main.go:117-128`](main.go#L117-L128)

```go
func providerFromEnv(getenv func(string) string) (sso.Provider, bool) {
	iss, id, secret, domain := getenv(envSSOIssuer), getenv(envSSOClientID), getenv(envSSOSecret), getenv(envSSODomain)
	if iss == "" || id == "" || secret == "" || domain == "" {
		return sso.Provider{}, false
	}
	return sso.Provider{
		ProviderID: cmp.Or(getenv(envProviderID), defaultProvider),
		Issuer:     iss,
		Domain:     domain,
		OIDC:       &sso.OIDCConfig{ClientID: id, ClientSecret: secret},
	}, true
}
```
<!-- /ds:block hash=67d481 -->

The plugin goes next to email and password; `auth.WithSecret` is required because provider secrets are sealed at rest:

<!-- ds:block id=sso-newauth-4p8vx2nd -->
**newAuth** · [`examples/sso/main.go:136-147`](main.go#L136-L147)

```go
func newAuth(db *sql.DB, secret []byte, m email.Mailer, providers []sso.Provider, opts ...sso.Option) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			sso.New(append([]sso.Option{sso.WithDefaultProviders(providers...)}, opts...)...),
		),
	)
}
```
<!-- /ds:block hash=75be4b -->

`main_test.go` runs three things against `plugin/sso/ssotest`: the OIDC round trip from `SSO_*` variables (sign-in by work email, the IdP's consent, the callback, `/me`, and a second sign-in reaching the same account); a SAML provider registered over HTTP by a signed-in admin, then a person signing in through it with a signed assertion posted to the ACS; and the refusals above. The test passes `sso.WithTrustedOrigins` for the fake IdP, because the plugin's network guard refuses loopback and private addresses otherwise.

Limits of this example: registration is open to every signed-in user (`sso.ProvidersLimit` caps it at 10 each); a real product registers providers for an organization its admin owns (`sso.WithOrganizations`, see the [SSO guide](../../docs/plugins/sso.md)) and proves the domain with `sso.WithDomainVerification` before trusting it.

## What this used

- [`plugin/sso`](https://pkg.go.dev/github.com/ubgo/auth/plugin/sso): `New`, `WithDefaultProviders`, `WithTrustedOrigins`, `Provider`, `OIDCConfig`, `SAMLConfig`
- [`plugin/sso/ssotest`](https://pkg.go.dev/github.com/ubgo/auth/plugin/sso/ssotest): `NewOIDC`, `NewSAMLIdP`, `AuthnRequest`
- Related: [scim](../scim) (provisioning the same company's users), [oauth](../oauth) (a fixed list of social providers), [organizations](../organizations).
