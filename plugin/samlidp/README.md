# samlidp

`github.com/ubgo/auth/plugin/samlidp` makes the app a SAML 2.0 identity provider (IdP): other services, SAML service providers (SPs), send their users here to sign in and receive a signed assertion naming the user. It is the SAML sibling of [`plugin/oauthprovider`](../oauthprovider/README.md) and the mirror of [`plugin/sso`](../sso/README.md), which makes the app a service provider of someone else's IdP.

It is its own module, because it brings an XML-signature library ([goxmldsig](https://github.com/russellhaering/goxmldsig), the library `plugin/sso` already uses) that apps which are not an IdP should not inherit. It adds no table: pending requests and request-ID claims are verification rows.

The guide is [docs/plugins/samlidp.md](../../docs/plugins/samlidp.md); the runnable recipe is [examples/saml-idp](../../examples/saml-idp/).

## Wiring

```go
idp := samlidp.New(
    samlidp.Issuer("https://id.example.com"),
    samlidp.LoginPage("/login"),
    samlidp.SigningKey(key, cert), // RSA or ECDSA crypto.Signer, KMS handles included
    samlidp.ServiceProviders(samlidp.ServiceProvider{
        EntityID:   "https://wiki.example.com/saml/metadata",
        ACSURLs:    []string{"https://wiki.example.com/saml/acs"},
        Attributes: samlidp.DefaultAttributes,
    }),
)
a, err := auth.New(auth.WithDB(db, dialect), auth.WithBaseURL("https://id.example.com"), auth.WithPlugins(signIn, idp))
mux.Handle(samlidp.DefaultBasePath+"/", idp.Handler())
```

## Endpoints

| Path (under the issuer) | Method | What it does |
|---|---|---|
| `/saml/metadata` | GET, HEAD | IdP metadata: entity ID, signing certificate, NameID formats, SSO service in both bindings |
| `/saml/sso` | GET (HTTP-Redirect), POST (HTTP-POST) | Accepts an AuthnRequest, claims its ID, stores it and redirects to `/saml/continue` |
| `/saml/continue?request=…` | GET | Signed out: redirects to `LoginPage?return_to=<this URL>` under a new handle. Signed in: answers the auto-posting form with the signed response |
| `/saml/initiate` | POST (`sp`, `acs_url`, `RelayState`) | IdP-initiated sign-on, only to an SP with `AllowIdPInitiated`; needs the session and passes the origin check |

Each is a self-served operation (`samlidp.sso`, `samlidp.continue`, `samlidp.initiate`), so it runs the whole pipeline: rate limits (`DefaultRateLimits`, per IP), hooks and tracing. The Go API is `SSO`, `Continue`, `Initiate` and `Metadata`.

## Options

| Option | Default | Notes |
|---|---|---|
| `Issuer(url)` | required | https, or http on a loopback host |
| `LoginPage(url)` | required | same-site path or trusted origin; gets `return_to` and, for ForceAuthn, `prompt=login` |
| `SigningKey(signer, cert)` | required | key must match the certificate; RSA signs RSA-SHA256, ECDSA ECDSA-SHA256 |
| `ServiceProviders(sps...)` | | checked by `auth.New` |
| `WithServiceProviderStore(store)` | | looked up after the static list; each answer checked |
| `EntityID(id)` | metadata URL | |
| `BasePath(path)` | `/saml` | |
| `ReturnParam(name)` | `return_to` | |
| `AssertionTTL(d)` | 5 min | assertion and SubjectConfirmationData NotOnOrAfter |
| `RequestMaxAge(d)` | 5 min | oldest accepted IssueInstant |
| `ClockSkew(d)` | 1 min | future tolerance, and NotBefore set back |
| `LoginTTL(d)` | 15 min | how long a request waits for sign-in |
| `MaxMessageSize(n)` | 64 KiB | after base64 and inflate |
| `WantAuthnRequestsSigned()` | off | every SP must sign; advertised in metadata |
| `Access(fn)` | allow all | the authorization seam: may this user sign in to this SP |
| `WithRequestIDGuard(g)` | verification rows | needed when the verification store cannot refuse duplicates |
| `RateLimit(endpoint, limit, window)` | `DefaultRateLimits` | 0 removes a limit |

`ServiceProvider` fields: `EntityID`, `ACSURLs`, `Certificates`, `RequireSignedRequests`, `NameIDFormat` (persistent by default; email, transient, unspecified), `NameID` func, `Attributes` func (`DefaultAttributes` releases the verified email and the name), `AllowIdPInitiated`, `UnsignedResponse`.

## Error codes

`samlidp.invalid_request`, `unknown_service_provider`, `acs_not_registered`, `unsupported_binding`, `wrong_destination`, `request_expired`, `request_replayed`, `signature_required`, `invalid_signature`, `unsupported_signature_algorithm`, `invalid_name_id_policy`, `request_not_found`, `idp_initiated_disabled`, `name_id_unavailable`, `access_denied`, `relay_state_too_long`, `message_too_large`, `missing_request`. Every one is rendered as a page by `Handler` and never sent to an ACS URL. Configuration errors from `auth.New`: `ErrNoIssuer`, `ErrNoLoginPage`, `ErrNoSigningKey`, `ErrBadSP`, `ErrBadTTL`, `ErrBadBasePath`, `ErrNoExclusive`.

## Security rules, each pinned by a test

- An AuthnRequest from an unregistered issuer is refused; the SP is found by the unverified Issuer only to choose the certificates, and every field is then read from the verified element.
- `AssertionConsumerServiceURL` must equal a registered URL exactly; an index must be in range.
- The request ID is claimed once (`auth.ExclusiveVerificationStore`, checked by `Init`); IssueInstant must be within `RequestMaxAge` and `ClockSkew`; the continue handle is single use.
- A signed request must name this IdP's SSO URL as Destination; a POST signature is checked by goxmldsig (signature wrapping refused), a redirect signature over the raw query octets; SHA-1 is refused.
- Every response and assertion is signed; the assertion's only Audience is the SP's entity ID, Recipient and Destination the ACS URL, InResponseTo the request ID.
- A signed-out browser, or a session still waiting for its second factor, is sent to `LoginPage` and never gets an assertion; `IsPassive` answers `NoPassive` instead.

## Not implemented yet

Single logout (no SingleLogoutService in the metadata; an SP's logout does not end the IdP session), encrypted assertions, signed metadata, the Artifact binding and the SOAP ECP profile.
