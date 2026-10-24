# github.com/ubgo/auth/plugin/sso

Enterprise single sign-on: OpenID Connect and SAML 2.0 identity providers registered at run time, per organization or email domain. A customer's admin connects their Okta, Entra ID, Google Workspace, ADFS or Keycloak without a deploy; a person signs in by typing their work email, and the plugin routes them to their company's IdP.

## Install

```sh
go get github.com/ubgo/auth/plugin/sso
```

This is its own module (Go 1.25) because SAML needs an XML-signature library (`github.com/russellhaering/gosaml2` and `goxmldsig`, with `beevik/etree`) that no app without SAML should inherit. OpenID Connect runs on `plugin/oauth` from the core module.

## Wire it

```go
auth.New(
	auth.WithDB(db, sqlb.PostgresDialect{}),
	auth.WithBaseURL("https://app.example.com"),
	auth.WithSecret(secret), // required: provider secrets are sealed at rest
	auth.WithPlugins(
		email.New(email.Login()),
		sso.New(
			sso.WithDomainVerification(sso.DomainVerification{}),
			sso.WithOrganizations(orgAdapter{org}, sso.OrganizationProvisioning{}),
		),
	),
)
```

`auth.New` fails with `ErrKeyDerivation` without `auth.WithSecret`, and with `ErrNoCallbackURL` without `auth.WithBaseURL` (or `WithCallbackURL` and `WithACSURL`).

## Routes

Under the plugin mount (`/auth/sso` with `authhttp.Prefix("/auth")`):

| Route | Who | What |
|---|---|---|
| `POST /register` | signed in | Register an OIDC and/or SAML provider for yourself, or for an organization you own or administer |
| `GET /providers` | signed in | The providers you may manage, sanitized |
| `GET /get-provider?providerId=` | signed in | One of them |
| `POST /update-provider` | signed in | Change it; a domain change resets verification; an identity-boundary change is refused while accounts are linked |
| `POST /delete-provider` | signed in | Delete it and its linked accounts |
| `POST /sign-in` | public | Start SSO by `providerId`, `organizationSlug`, `domain` or `email`; answers `{url, redirect}` |
| `GET /callback` | public | The shared OIDC redirect URI (`?providerId=` for an IdP-initiated sign-in) |
| `GET /saml2/sp/metadata?providerId=` | public | SP metadata, as `{"metadata": "<xml>"}` |
| `POST /saml2/sp/acs` | public, cross-site form | The SAML assertion consumer service |
| `POST /request-domain-verification` | signed in | The DNS TXT token (with `WithDomainVerification`) |
| `POST /verify-domain` | signed in | Check the TXT record (with `WithDomainVerification`) |
| `POST /saml2/logout` | signed in | SP-initiated SAML single logout (with `SAMLOptions.EnableSingleLogout`) |
| `GET \| POST /saml2/sp/slo` | public (POST: cross-site form) | The SP's SLO endpoint: the IdP's LogoutRequest or LogoutResponse, redirect or POST binding |

By default the OIDC callback, the ACS and the SLO endpoint are shared by every provider: the provider travels in the OIDC state or the SAML RelayState, and an IdP-initiated SAML sign-in names it as its RelayState (Okta's "Default RelayState"). With `sso.PerProviderPaths()` every provider gets its own URLs (`/callback/<id>`, `/saml2/sp/acs/<id>`, `/saml2/sp/slo/<id>`); the core routes exact paths, so mount `p.ProviderPaths("/auth/sso", authhttp.Handler(a, authhttp.Prefix("/auth")))`, which rewrites those URLs onto the shared routes with the id as a second check, and also serves `GET /saml2/sp/metadata?providerId=` as raw `application/xml`.

## What it checks

OpenID Connect: authorization code with PKCE (S256), state bound to the browser by the flow cookie, the ID token's signature against the IdP's JWKS, its `iss`, `aud` (the client id), `exp`, `nonce` (the PKCE challenge) and `azp`, userinfo's `sub` equal to the token's, RFC 9207 `iss`. Discovery requires `issuer`, `authorization_endpoint`, `token_endpoint` and `jwks_uri`, refuses an issuer mismatch, and follows no redirect. A public client (`tokenEndpointAuthentication: "none"`) must keep PKCE on: registration refuses one without it, since no sign-in could complete.

SAML (`CheckAssertion`, `InspectResponse`): exactly one assertion anywhere in the document (the defence in depth against signature wrapping), a signature by one of the IdP's certificates over the Response or the Assertion (the Assertion's own with `WantAssertionsSigned`), issuer, destination, audience, bearer recipient, `InResponseTo` equal to the request this browser started (consumed once), `NotBefore`/`NotOnOrAfter` with `ClockSkew`, assertion-ID replay protection until expiry, no DTD, size limits, and the SHA-1 algorithm policy.

Encrypted assertions (`samlConfig.decryptionKey` + `decryptionCertificate`, or `privateKey` + `spCertificate`) are decrypted (RSA-OAEP or RSA-1.5 key transport, AES-GCM or AES-CBC data) and then pass every check above; the content must still be signed, an assertion encrypted to another key is refused, and the encryption algorithms follow the same allow-lists and SHA-1/RSA-1.5/3DES policy.

Single logout (`SAMLOptions.EnableSingleLogout`): an SP-initiated LogoutRequest is signed with the SP key when one is set; the IdP's LogoutRequest and LogoutResponse must be signed (`AllowUnsignedLogoutRequests`/`AllowUnsignedLogoutResponses` relax this), by the provider's certificate, with its issuer and, when present, this SP's SLO URL as Destination. A LogoutResponse must answer a pending request, once.

Network: every IdP call goes through a client that refuses redirects and refuses loopback, private, link-local (cloud metadata) and carrier-grade-NAT addresses at connect time, after DNS. `WithTrustedOrigins` lets an on-premises IdP through.

## Accounts and linking

`auth_sso_account` keys an IdP account on `(provider_id, subject)`: the OIDC `sub` or the SAML NameID. A first sign-in links to an existing user with the same email only when the provider is trusted (a default provider, a domain-verified one, or `TrustProviders`), the address is in one of the provider's domains, and the local identity is verified; otherwise it is refused with `sso.account_exists`. `WithResolveUser` decides first when the app knows better.

## Options

| Option | Effect |
|---|---|
| `WithDefaultProviders(...)` | Providers in code, treated as verified, never editable |
| `ProvidersLimit(n)` / `WithProvidersLimit(fn)` | Providers per user (default 10; 0 turns registration off) |
| `WithDomainVerification(DomainVerification{TokenPrefix, Resolver})` | DNS proof of each domain before sign-in |
| `WithOrganizations(o, OrganizationProvisioning{...})` | Org owner/admin checks, `organizationSlug` routing, joining on sign-in |
| `TrustEmailVerified()` | Take the IdP's `email_verified` |
| `TrustProviders(ids...)` | Link by verified email without domain verification |
| `DisableImplicitSignUp()` | Create users only when the sign-in sent `requestSignUp` |
| `DefaultOverrideUserInfo()` | Copy name and image at every sign-in |
| `WithProvisionUser(fn)`, `ProvisionUserOnEveryLogin()` | A hook inside the sign-in transaction |
| `WithResolveUser(fn)` | Link a first sign-in to a user the app names, or refuse it |
| `WithMutationGuard(fn)` | Refuse an update or delete |
| `WithPrivateKeyResolver(fn)` | `private_key_jwt` keys from an HSM or KMS |
| `WithSAMLOptions(SAMLOptions{...})` | IdP-initiated, request TTL, clock skew, required timestamps, algorithm policy, size limits |
| `WithSAMLEngine(e)` | Replace the XML-signature engine |
| `WithHTTPClient(hc)`, `WithTrustedOrigins(...)` | The IdP client and its SSRF escape hatch |
| `WithCallbackURL`, `WithACSURL`, `WithErrorURL`, `WithStateTTL`, `ReserveProviderIDs` | URLs and names |
| `PerProviderPaths()` + `p.ProviderPaths(mount, handler)` | One callback, ACS and SLO URL per provider |
| `samlConfig.spMetadata.binding: "post"` | AuthnRequest by HTTP-POST (sign-in answers a `form`); `digestAlgorithm` applies only to its signature and must match the signature hash |
| `RequireTrustedOrigins()` | Only IdP origins `WithTrustedOrigins` lists (`sso.discovery_untrusted_origin`) |
| `WithProviderFields(...)`, `p.SetProviderFields` | App-defined provider fields (`NoInput` ones settable from Go only) |
| `p.AssignByVerifiedDomain`, `p.OAuthAssignment()` | Join a verified domain's organization on a social sign-in (`oauth.OnResolved`) |

## Organizations

The plugin names no organization module. An adapter over `plugin/organization` (or any other) implements `sso.Organizations`: `Role(ctx, orgID, userID)`, `BySlug(ctx, slug)` and `AddMember(ctx, orgID, userID, role)`.

## Tables

`auth_sso_provider` (one row per provider; the OIDC client secret and SAML keys sealed with a key derived from `auth.WithSecret`; the pending domain token and its expiry; the provider fields as JSON) and `auth_sso_account`. `auth.RenameTable(sso.TableProvider, name)` renames a table. No foreign keys; `DeleteUser` removes a user's sso accounts, and a provider outlives the admin who registered it.

## Testing

`plugin/sso/ssotest` runs a fake OIDC provider (discovery, JWKS, a token endpoint that checks PKCE, userinfo) and a fake SAML IdP that signs responses, for an app's own tests.

## Go API

Every route is also a typed method that runs through the same pipeline: `RegisterProvider`, `SignIn`, `Callback`, `ACS`, `ListProviders`, `GetProvider`, `UpdateProvider`, `DeleteProvider`, `SPMetadata`, `RequestDomainVerification`, `VerifyDomain`, `InitiateSLO`, `SLO`. Helpers: `ProviderByID`, `ProviderForDomain`, `Accounts`, `Discover`, `DomainToken`, `DeriveIdPEntityID`, `DeriveSPPolicy`, `CheckAssertion`, `InspectResponse`, `DecodeLogout`.

## Not built

Passphrase-protected PEM keys (sealed at rest instead), a relay-state cookie (a cross-site form post never carries one), column renames, and the hosted onboarding dashboard. See [docs/plugins/sso.md](../../docs/plugins/sso.md).
