# Enterprise SSO (OIDC and SAML)

You will have enterprise single sign-on: a customer's admin connects their company's identity provider (Okta, Entra ID, Google Workspace, ADFS, Keycloak, OneLogin) from your settings page, over OpenID Connect or SAML 2.0, without a deploy; their people sign in by typing their work email and land at their own IdP; a person who signs in for the first time gets an account, and joins the customer's organization when you have one.

This is `plugin/sso`. For a fixed list of social providers (Google, GitHub), use [OAuth](oauth.md) instead; the two work side by side.

## Before you start

- `auth.WithSecret`: each provider's OIDC client secret and SAML private key are sealed in the database with a key derived from it, and `auth.New` refuses to start without one.
- `auth.WithBaseURL`: the OIDC redirect URI and the SAML ACS URL are built from it.
- An identifier plugin for email ([email](email.md)), so a person who signs in through SSO has an address on their account.
- Reference: [plugin/sso/README.md](../../plugin/sso/README.md) lists every option, route, table and error.
- Three examples, each with a test that runs it end to end against `plugin/sso/ssotest`'s fake identity providers, so no real IdP account is needed:
  - [`examples/sso`](../../examples/sso): an OIDC provider configured in code from environment variables, and a SAML provider a signed-in admin registers at run time (Steps 1 to 3).
  - [`examples/sso-domains`](../../examples/sso-domains): a provider registered for an organization, domain verification through DNS, people joining the organization on first sign-in, and SAML single logout in both directions (the sections from Organizations to single logout).
  - [`examples/import-sso`](../../examples/import-sso): moving SAML providers out of Supabase Auth with `RegisterProvider`.

## Step 1 — Wire the plugin

```sh
go get github.com/ubgo/auth/plugin/sso
```

Add `sso.New()` to the plugin list; everything else is optional. The `sso` example wires it beside email and passwords, with any providers known at deploy time:

<!-- ds:block id=sso-newauth-4p8vx2nd -->
**newAuth** · [`examples/sso/main.go:136-147`](../../examples/sso/main.go#L136-L147)

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

Providers you know when you deploy can live in code instead of rows. They are matched before any registered provider, count as domain-verified, and cannot be edited or shadowed through the API:

<!-- ds:block id=withdefaultproviders-qph6yfbg -->
**WithDefaultProviders** · [`plugin/sso/plugin.go:91-98`](../../plugin/sso/plugin.go#L91-L98)

```go
func WithDefaultProviders(ps ...Provider) Option {
	return func(p *Plugin) {
		for _, pr := range ps {
			pr.Default, pr.DomainVerified = true, true
			p.defaults = append(p.defaults, pr)
		}
	}
}
```
<!-- /ds:block hash=7d121c -->

The example builds its one provider in code from `SSO_*` variables, and builds none when one is missing, rather than a broken one:

<!-- ds:block id=sso-providerfromenv-7k3qw9mz -->
**providerFromEnv** · [`examples/sso/main.go:117-128`](../../examples/sso/main.go#L117-L128)

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

Check: `TestSSO_OIDCSignInByWorkEmail` in `examples/sso` configures the provider this way against a fake OIDC IdP and signs Ada in twice, reaching the same user.

## Step 2 — Register a provider

A signed-in user registers a provider for themselves, or for an organization they own or administer (`WithOrganizations`). The plugin checks the configuration before it stores anything: for OIDC it fetches the discovery document, requires `issuer`, `authorization_endpoint`, `token_endpoint` and `jwks_uri`, and refuses an issuer that does not match; every URL must be https and must not point at a private address.

```http
POST /auth/sso/register
{"providerId": "acme-okta", "issuer": "https://acme.okta.com", "domain": "acme.com",
 "oidcConfig": {"clientId": "0oa...", "clientSecret": "..."}}
```

The answer is the sanitized provider (no secret, the client id cut to its last four characters) with the `redirectURI` to enter at the IdP: `https://app.example.com/auth/sso/callback`. Every provider shares that one redirect URI; the provider travels in the state.

A SAML provider takes a `samlConfig` instead: the IdP's SSO URL (`entryPoint`), its signing certificate (`cert`, several PEM blocks for a rotation) and entity id (`idpMetadata.entityID`), or the IdP's metadata XML in `idpMetadata.metadata`. The answer carries the `acsURL` and `spMetadataURL` to enter at the IdP.

Check: `TestSSO_SAMLProviderRegisteredAtRunTime` in `examples/sso` registers a SAML IdP over HTTP and signs a person in through it, and `TestSSO_Refusals` shows that registering needs a signed-in user (`401 auth.signed_out`).

`GET /providers`, `GET /get-provider`, `POST /update-provider` and `POST /delete-provider` manage what the caller registered. Another user is refused with `403 sso.forbidden`. Once a person has signed in through a provider, its identity fields (issuer, endpoints, client id, entity ids, certificates) are locked (`409 sso.boundary_locked`): repointing a provider with linked accounts would hand them to a different IdP. `WithMutationGuard` refuses any other change you choose.

## Step 3 — Sign people in

```http
POST /auth/sso/sign-in
{"email": "ada@acme.com", "callbackURL": "/dashboard"}
```

The plugin picks the provider by `providerId`, then `organizationSlug`, then `domain`, then the domain of `email` (a provider for `acme.com` also serves `eng.acme.com`), answers `{"url": "...", "redirect": true}`, and sets the flow cookie. Send the browser to `url`. The callback (OIDC) or the ACS (SAML) signs the person in and redirects to `callbackURL`, or to `newUserCallbackURL` when the sign-in created the account.

<!-- ds:block id=signinrequest-u64snknb -->
**SignInRequest** · [`plugin/sso/signin.go:17-42`](../../plugin/sso/signin.go#L17-L42)

```go
type SignInRequest struct {
	Email            string `json:"email,omitempty"`
	OrganizationSlug string `json:"organizationSlug,omitempty"`
	ProviderID       string `json:"providerId,omitempty"`
	Domain           string `json:"domain,omitempty"`
	// CallbackURL is where to land after sign-in: a path on this site or a
	// trusted origin; "" is the site root.
	CallbackURL string `json:"callbackURL,omitempty"`
	// ErrorCallbackURL is where a failed sign-in lands, with the error code.
	ErrorCallbackURL string `json:"errorCallbackURL,omitempty"`
	// NewUserCallbackURL replaces CallbackURL when the sign-in created the
	// user.
	NewUserCallbackURL string `json:"newUserCallbackURL,omitempty"`
	// Scopes replace the provider's scopes for this sign-in (OIDC).
	Scopes []string `json:"scopes,omitempty"`
	// LoginHint is sent as login_hint (OIDC); Email is sent when it is "".
	LoginHint string `json:"loginHint,omitempty"`
	// AdditionalParams are added to the authorization URL (OIDC); a
	// parameter the flow sets itself is ErrBadParams.
	AdditionalParams map[string]string `json:"additionalParams,omitempty"`
	// RequestSignUp allows creating a user under DisableImplicitSignUp.
	RequestSignUp bool `json:"requestSignUp,omitempty"`
	// ProviderType picks the protocol of a provider that offers both;
	// empty is OIDC when offered.
	ProviderType Protocol `json:"providerType,omitempty"`
}
```
<!-- /ds:block hash=07c415 -->

Try it: both protocols, end to end, against `ssotest`'s fake IdPs:

```sh
cd examples
go test -v ./sso
```

```text
=== RUN   TestSSO_OIDCSignInByWorkEmail
2026/10/09 08:45:52 WARN auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance
--- PASS: TestSSO_OIDCSignInByWorkEmail (0.15s)
=== RUN   TestSSO_SAMLProviderRegisteredAtRunTime
2026/10/09 08:45:52 WARN auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance
--- PASS: TestSSO_SAMLProviderRegisteredAtRunTime (0.28s)
=== RUN   TestSSO_Refusals
2026/10/09 08:45:52 WARN auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance
--- PASS: TestSSO_Refusals (0.08s)
PASS
ok  	github.com/ubgo/auth/examples/sso	1.115s
```

With real values, `AUTH_SECRET=$(openssl rand -base64 32) SSO_ISSUER=https://acme.okta.com SSO_CLIENT_ID=… SSO_CLIENT_SECRET=… SSO_DOMAIN=acme.com go run ./sso` serves a page on `localhost:8081` that asks for a work email and sends the browser to the IdP.

## Who gets which account

A provider account is linked to a user in `auth_sso_account`, keyed on the provider and the IdP's subject (the OIDC `sub`, the SAML NameID). The first sign-in through a provider decides whose account it is, in this order: an account already linked to that subject signs its user in; a `WithResolveUser` decision to link names the user; an existing user with the same email is linked only when the provider is trusted (a default provider, a domain-verified one, or one `TrustProviders` names), the address is in one of the provider's domains, and the local address is verified, and otherwise the sign-in is refused with `409 sso.account_exists`; anyone else gets a new account ([the rule in code](ds:block?id=plugin-resolve-y5d3hvbs)).


So an IdP you have not verified can create new accounts but cannot take over an existing one. `TrustProviders` marks a provider trusted without DNS proof; `WithResolveUser` decides first when your app knows better (a directory lookup, an allow-list); `DisableImplicitSignUp` creates users only when the sign-in sent `requestSignUp: true`; `WithProvisionUser` runs your code inside the sign-in transaction.

## Organizations

The plugin names no organization module. Give it an adapter:

<!-- ds:block id=organizations-ad677n7w -->
**Organizations** · [`plugin/sso/hooks.go:105-114`](../../plugin/sso/hooks.go#L105-L114)

```go
type Organizations interface {
	// Role returns userID's role in orgID; ok is false when the user is not
	// a member.
	Role(ctx context.Context, orgID, userID string) (role string, ok bool, err error)
	// BySlug returns the id of the organization with slug; ok is false
	// when there is none.
	BySlug(ctx context.Context, slug string) (orgID string, ok bool, err error)
	// AddMember adds userID to orgID with role.
	AddMember(ctx context.Context, orgID, userID, role string) error
}
```
<!-- /ds:block hash=76dcf5 -->

With it, registering under an organization needs its owner or admin, `organizationSlug` routes a sign-in, and a person who signs in through an organization's provider joins it with `OrganizationProvisioning.DefaultRole` (default `member`) or the role your `Role` function returns.

The [`sso-domains`](../../examples/sso-domains) example answers the three questions from `plugin/organization`. The plugin is created once and passed both to `auth.WithPlugins` and to the adapter:

<!-- ds:block id=ssodomains-newauth-6p3kw8zn -->
**newAuth** · [`examples/sso-domains/main.go:96-113`](../../examples/sso-domains/main.go#L96-L113)

```go
func newAuth(db *sql.DB, secret []byte, m email.Mailer, resolver sso.TXTResolver) (*auth.Auth, error) {
	orgs := organization.New()
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			orgs,
			sso.New(
				sso.WithDomainVerification(sso.DomainVerification{Resolver: resolver}),
				sso.WithOrganizations(orgAdapter{orgs: orgs, db: db}, sso.OrganizationProvisioning{}),
				sso.WithSAMLOptions(sso.SAMLOptions{EnableSingleLogout: true}),
			),
		),
	)
}
```
<!-- /ds:block hash=85ec2d -->

`Role` maps the organization plugin's `ErrNotMember` to "not a member" rather than an error, so the sso plugin can answer the caller instead of failing:

<!-- ds:block id=ssodomains-role-5j8rv3kc -->
**orgAdapter.Role** · [`examples/sso-domains/main.go:128-137`](../../examples/sso-domains/main.go#L128-L137)

```go
func (o orgAdapter) Role(ctx context.Context, orgID, userID string) (string, bool, error) {
	role, err := o.orgs.RoleOf(ctx, orgID, userID)
	if errors.Is(err, organization.ErrNotMember) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return string(role), true, nil
}
```
<!-- /ds:block hash=3affb6 -->

`BySlug` reads the organization table with its typed columns, because reads are open to the app:

<!-- ds:block id=ssodomains-byslug-8k2nw5qr -->
**orgAdapter.BySlug** · [`examples/sso-domains/main.go:144-161`](../../examples/sso-domains/main.go#L144-L161)

```go
func (o orgAdapter) BySlug(ctx context.Context, slug string) (string, bool, error) {
	var id string
	q, err := sqlb.NewSelect(sqlb.SQLiteDialect{}).
		Columns(sqlb.Bind(organization.OrgID, &id)).
		From(organization.TableOrg).
		Where(sqlb.Eq(organization.OrgSlug, slug)).
		Build()
	if err != nil {
		return "", false, err
	}
	switch err := sqlb.One(ctx, o.db, q); {
	case errors.Is(err, sqlb.ErrNoRows):
		return "", false, nil
	case err != nil:
		return "", false, err
	}
	return id, true, nil
}
```
<!-- /ds:block hash=e7e206 -->

`AddMember` runs inside the sign-in's transaction, so a failure to join undoes the sign-in too:

<!-- ds:block id=ssodomains-addmember-2w6qt9ny -->
**orgAdapter.AddMember** · [`examples/sso-domains/main.go:168-170`](../../examples/sso-domains/main.go#L168-L170)

```go
func (o orgAdapter) AddMember(ctx context.Context, orgID, userID, role string) error {
	return o.orgs.AddMember(ctx, orgID, userID, organization.Role(role))
}
```
<!-- /ds:block hash=fbc2c2 -->

The owner registers the provider with `"organizationId"` set; a plain member of the organization gets `403 sso.forbidden`, and someone outside it `400 sso.not_member`. After Ada's first sign-in by her work email, the organization's members list holds her as `member`; signing in with `{"organizationSlug": "acme"}` reaches the same provider. Check: `TestSSODomains_VerifyJoinAndSingleLogout` and `TestSSODomains_OnlyTheOwnerOrAdminRegisters` in `examples/sso-domains`.

## Domain verification

Without verification any signed-in user can register a provider for any domain, and sign-ins by email domain may reach it. `WithDomainVerification` closes that: a provider cannot sign anyone in until the customer proves the domain.

<!-- ds:block id=domainverification-gbvt37je -->
**DomainVerification** · [`plugin/sso/domain.go:26-31`](../../plugin/sso/domain.go#L26-L31)

```go
type DomainVerification struct {
	// TokenPrefix names the record; empty is DefaultDomainTokenPrefix.
	TokenPrefix string
	// Resolver looks the record up; nil is net.DefaultResolver.
	Resolver TXTResolver
}
```
<!-- /ds:block hash=57e5e2 -->

Registration answers a `domainVerificationToken`, valid for a week (`sso.DefaultDomainTokenTTL`; asking again within the week returns the same token, after it a new one, and `verify-domain` with none pending is `404 sso.no_pending_verification`); the customer publishes it as a TXT record at `_<prefix>-<providerId>.<domain>` (the value may be the token or `_<prefix>-<providerId>=<token>`) and calls `POST /verify-domain`. Every listed domain must hold it. A domain change resets verification. A verified provider is trusted for linking. `sso.DomainRecordName(prefix, providerID, domain)` builds the record name, and `request-domain-verification` answers it as `recordName`, so your settings page can show the customer exactly what to publish.

The lookup goes through `DomainVerification.Resolver`, which is `net.DefaultResolver` unless you pass one: any type with `LookupTXT(ctx, name) ([]string, error)`. The `sso-domains` example passes nil in `main` and a fake in its test, where the record appears when the test publishes it. The flow in that test:

1. The owner registers the provider; the answer carries `domainVerificationToken` and `"domainVerified": false`.
2. Ada's sign-in by email is `401 sso.domain_unverified`.
3. `verify-domain` before the record exists is `502 sso.domain_not_proven`, logged at INFO with the name looked up, and changes nothing.
4. With the record published, `verify-domain` answers `{"ok":true}` and Ada signs in.

```sh
cd examples
go test -v ./sso-domains
```

```text
=== RUN   TestSSODomains_VerifyJoinAndSingleLogout
2026/10/09 08:45:54 WARN auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance
2026/10/09 08:45:55 INFO sso: domain record lookup failed provider=acme-saml domain=acme.test error="lookup _ubgo-auth-token-acme-saml.acme.test: no such host"
--- PASS: TestSSODomains_VerifyJoinAndSingleLogout (0.29s)
=== RUN   TestSSODomains_OnlyTheOwnerOrAdminRegisters
2026/10/09 08:45:55 WARN auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance
--- PASS: TestSSODomains_OnlyTheOwnerOrAdminRegisters (0.38s)
PASS
ok  	github.com/ubgo/auth/examples/sso-domains	1.304s
```

The INFO line is step 3: the record was not there yet.

## SAML: what is checked

Every SAML response passes these checks in order; each refusal is logged with its code (`SAML_AUDIENCE_MISMATCH`, …) and answered `400 sso.saml_invalid`, `sso.saml_replay` or `sso.saml_unsolicited`:

1. The decoded XML holds exactly one `Assertion` or `EncryptedAssertion` anywhere in the tree and no DTD. A signature-wrapping attack needs a second assertion, so it is refused here before any signature code runs.
2. The signature and digest algorithms are known, allowed (`SAMLOptions.AllowedSignatureAlgorithms`) and not SHA-1 under `OnDeprecated: reject`.
3. The signature verifies against one of the IdP's certificates, over the Response or the Assertion; only the content the signature covered is read.
4. The rules this package checks itself, so that replacing the XML-signature engine cannot drop one: exactly one assertion, signed itself under `wantAssertionsSigned`; the Response's and Assertion's issuer are the IdP's entity id; the Destination, when present, is the ACS URL; `InResponseTo` on the Response and on the bearer confirmation is the request this browser started (absent for an IdP-initiated sign-in); an `AudienceRestriction` exists and names the SP's audience; a bearer `SubjectConfirmation` names the ACS URL as its Recipient and has not expired; `NotBefore` has come and `NotOnOrAfter` has not passed, each with `SAMLOptions.ClockSkew` (5 minutes by default). The whole list is [CheckAssertion](ds:block?id=checkassertion-8evwc35n).


5. The AuthnRequest ID is consumed once, so a second response to the same request is refused.
6. The assertion's ID is reserved until it expires (plus the skew), so the same assertion is accepted once.

`spMetadata.binding: "post"` sends the AuthnRequest by HTTP-POST: sign-in then answers `{"redirect": false, "form": {"action", "SAMLRequest", "RelayState"}}` for the page to submit, with an enveloped signature under `authnRequestsSigned`. `digestAlgorithm` applies only there and must be the signature algorithm's hash; set anywhere else it is refused, not ignored.

An `EncryptedAssertion` is decrypted with the provider's `decryptionKey` (or `privateKey`) and then checked exactly like a plain one: it must still be signed, and one encrypted to another key is refused.

An unsolicited (IdP-initiated) response is refused unless `SAMLOptions.AllowIdPInitiated` or the provider's `allowIdpInitiated` is set; it must then name the provider as its RelayState and must not carry an `InResponseTo`.

## SAML single logout

Turn it on with `sso.WithSAMLOptions(sso.SAMLOptions{EnableSingleLogout: true})` and give the provider the IdP's SLO URL (`idpMetadata.singleLogoutService`, or it is read from the IdP metadata). Each SAML sign-in then records which app session belongs to which IdP NameID and SessionIndex.

- `POST /auth/sso/saml2/logout` (`{"callbackURL": "/bye"}`) ends the app session at once and answers the IdP URL carrying a LogoutRequest, signed with the SP key when the provider has one. The IdP's LogoutResponse comes back to `/auth/sso/saml2/sp/slo` and lands on `callbackURL`; it must answer that request, once.
- The IdP's own LogoutRequest at `/auth/sso/saml2/sp/slo` (redirect or POST binding) ends every app session with that NameID and SessionIndex and is answered with a LogoutResponse at the IdP.
- Incoming logout messages must be signed by the provider's certificate unless `AllowUnsignedLogoutRequests` / `AllowUnsignedLogoutResponses` say otherwise; accepting unsigned ones would let anyone who knows a NameID and SessionIndex sign that person out.
- Signing out of the app (`/auth/sign-out`) forgets the record.

`TestSSODomains_VerifyJoinAndSingleLogout` runs both directions against `ssotest`'s IdP, registered with `"idpMetadata": {"singleLogoutService": [{"Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", "Location": "https://idp.acme.test/slo"}]}`:

1. Ada calls `POST /auth/sso/saml2/logout` with `{"callbackURL": "/bye"}`. The answer's `url` starts with the IdP's SLO URL and carries a `SAMLRequest`; `/me` is already `401`. Decoded with `sso.PeekLogout`, the request names Ada's NameID and the SessionIndex of the assertion she signed in with.
2. The IdP's signed LogoutResponse to that request, at `/auth/sso/saml2/sp/slo`, redirects to `/bye`.
3. Ada signs in again. The IdP's own signed LogoutRequest for her NameID and SessionIndex, at the same SLO URL, ends that session and redirects to the IdP's SLO URL with a `SAMLResponse` and the IdP's `RelayState`.

The test builds the IdP's messages with `sso.LogoutDocument` and `sso.RedirectURL`, signed with the fake IdP's key, which is how a test of your own can play the IdP's side.

## One URL per provider

`sso.PerProviderPaths()` gives each provider its own redirect URI, ACS and SLO URL (`.../callback/acme-okta`). Mount `p.ProviderPaths("/auth/sso", authHandler)` in front of the auth handler: it maps those URLs onto the shared routes, refuses a callback or response that arrives at another provider's URL, and serves `GET /auth/sso/saml2/sp/metadata?providerId=` as raw XML for IdPs that import it by URL.

## SAML with Okta

1. In Okta, create a SAML 2.0 app. Single sign-on URL: the `acsURL` (`https://app.example.com/auth/sso/saml2/sp/acs`). Audience URI: the SP entity id you register (`spMetadata.entityID`, default the provider's `issuer`). Name ID format: Email Address. For IdP-initiated sign-in from the Okta dashboard, set Default RelayState to the provider id.
2. Download the IdP metadata, or copy the SSO URL, issuer and certificate.
3. Register: `{"providerId": "acme-okta", "issuer": "https://app.example.com/sp/acme", "domain": "acme.com", "samlConfig": {"entryPoint": "https://acme.okta.com/app/.../sso/saml", "cert": "-----BEGIN CERTIFICATE-----...", "idpMetadata": {"entityID": "http://www.okta.com/exk..."}, "wantAssertionsSigned": true}}`, or put the same `Provider` in `WithDefaultProviders`.
4. Sign in with `{"providerId": "acme-okta"}`, `{"email": "ada@acme.com"}` or `{"domain": "acme.com"}`.

## Test your setup without an IdP

`plugin/sso/ssotest` holds fake identity providers for tests; never use its keys outside tests.

- `ssotest.NewOIDC(t)` serves discovery, JWKS, authorize, token and userinfo on a local `httptest` server, stopped when the test ends. Set `idp.Person` (subject, email, verified, name), register `idp.Issuer()` with `idp.ClientID` and `idp.ClientSecret`, and pass `sso.WithTrustedOrigins(idp.URL)`, because the plugin's network guard refuses a loopback IdP otherwise. `idp.Authorize(t, url)` plays the person at the IdP and returns the callback query.
- `ssotest.NewSAMLIdP(t, entityID)` has a signing certificate (`CertPEM` for `SAMLConfig.Cert`) and an `SSOURL`. `ssotest.AuthnRequest(t, url)` decodes the sign-in redirect into the request id, ACS URL and relay state; `idp.Valid(acs, audience, requestID, nameID)` describes a correct assertion, which you change field by field to test a refusal; `idp.Response(a)` signs and encodes it for the ACS form.
- `ssotest.KeyPair(t, cn)` and `ssotest.KeyPEM(key)` make an SP key and certificate, for signed AuthnRequests, encrypted assertions and signed logout messages.

`examples/sso` uses the OIDC and SAML fakes, `examples/sso-domains` the SAML one with logout messages.

## Options you may want

| Situation | Option | What it changes |
|---|---|---|
| Providers known at deploy time | `sso.WithDefaultProviders(…)` | matched first, domain-verified, not editable through the API |
| Prove domain ownership before a provider signs anyone in | `sso.WithDomainVerification(sso.DomainVerification{TokenPrefix, Resolver})` | registration answers a token; sign-in waits for `verify-domain` |
| Providers that belong to organizations | `sso.WithOrganizations(adapter, sso.OrganizationProvisioning{DefaultRole, Role, Disabled})` | owner or admin registers; people join on sign-in |
| Single logout | `sso.WithSAMLOptions(sso.SAMLOptions{EnableSingleLogout: true})` | logout route, SLO endpoint, session records |
| IdP dashboard tiles | `SAMLOptions.AllowIdPInitiated` or the provider's `allowIdpInitiated` | unsolicited responses accepted, RelayState naming the provider |
| One redirect, ACS and SLO URL per provider | `sso.PerProviderPaths()` and `p.ProviderPaths(…)` | per-provider URLs |
| Trust a provider for linking without DNS | `sso.TrustProviders(ids…)` | existing users with a matching verified email are linked |
| Your own linking decision | `sso.WithResolveUser(fn)` | decides before the default rules |
| Create users only on request | `sso.DisableImplicitSignUp()` | a sign-in without `requestSignUp` is `403 sso.sign_up_disabled` |
| A loopback or private IdP in tests | `sso.WithTrustedOrigins(urls…)` | lets the network guard reach it |

## From TypeScript

The prebuilt [typed client](../client/README.md) has no `sso` factory: the plugin is its own module and is not among the plugins the prebuilt `client.ts` was generated with. A client your app generates with [`auth client ts`](../client/custom-plugins.md) has a `client.sso` namespace with the operations your configuration serves, named by the [usual rule](../client/plugins.md#step-4--how-a-method-gets-its-name): with the default options `signIn`, `callback`, `register`, `providers`, `getProvider`, `updateProvider`, `deleteProvider`, `samlAcs` and `samlMetadata` (checked against `examples/sso`); single logout and domain verification add theirs only when turned on.

What a page does with it:

- **Start a sign-in with `client.sso.signIn({ email })`** (or `organizationSlug`, `providerId`, `domain`), then navigate: the answer is `{ url, redirect }`, and for a SAML provider on the POST binding `redirect` is false and `form` holds the fields to post to `form.action` from an auto-submitting form. The page assigns `location` to `url` (or submits the form); it never fetches the identity provider. `callbackURL`, `newUserCallbackURL` and `errorCallbackURL` choose where the browser lands afterwards; with `errorCallbackURL` set, a failed sign-in lands there with the error code, and without it the callback answers the error itself.
- **`callback` and `samlAcs` are not for pages.** The identity provider sends the browser there; they exist on the client only because they are operations.
- **An admin page registers and edits providers** with `register`, `providers`, `getProvider`, `updateProvider` and `deleteProvider`, all signed-in operations checked against the caller's organization role on the server.

The error codes are the `sso.*` entries of the generated `AUTH_ERROR_CODES`. `signIn` itself answers `sso.provider_not_found` (no provider for that address or organization) or `sso.domain_unverified`; the failures after the identity provider (`sso.denied`, `sso.state_invalid`, `sso.sign_up_disabled`) arrive at the callback, in the browser, not as the `signIn` call's error; send `errorCallbackURL` so they land on a page of yours. The table is in [What can go wrong](#what-can-go-wrong).

Pitfalls:

- **Generate the client from the app that wires SSO.** The prebuilt client would compile without `client.sso` and every call would be a type error; a hand-written `fetch` loses the types and the error union.
- **A sign-in is a navigation.** The session cookie is set by the callback on your origin after the identity provider, never by the `signIn` call itself.

## What can go wrong


| Code | Status | When |
|---|---|---|
| `sso.provider_not_found` | 404 | No provider matched the sign-in |
| `sso.target_required` | 400 | The sign-in named no email, domain, organization or provider |
| `sso.domain_unverified` | 401 | Domain verification is on and the provider is not verified |
| `sso.state_invalid` | 400 | The flow expired, or the callback came from another browser |
| `sso.provider_changed` | 409 | The provider's identity fields changed during the flow |
| `sso.account_exists` | 409 | A user with this email exists and the provider may not link to it |
| `sso.sign_up_disabled` | 403 | `DisableImplicitSignUp` without `requestSignUp` |
| `sso.saml_invalid` / `sso.saml_replay` / `sso.saml_unsolicited` | 400 | A SAML response failed a check |
| `sso.provider_exists` / `sso.provider_id_reserved` | 422 | Registration with a taken or reserved provider id |
| `sso.boundary_locked` | 409 | An identity-field change while accounts are linked |
| `sso.discovery_*`, `sso.issuer_mismatch`, `sso.endpoint_redirect` | 400/502 | OIDC discovery refused the issuer (`sso.discovery_untrusted_origin` under `RequireTrustedOrigins`) |
| `sso.token_not_verified` / `sso.token_response_error` / `sso.token_response_not_found` / `sso.no_private_key_available` | 401 / 502 / 502 / 500 | The ID token or userinfo did not check out / the token endpoint refused / no id_token came back / the private_key_jwt resolver failed |
| `sso.no_pending_verification` | 404 | `verify-domain` with no unexpired token |
| `sso.domain_not_proven` | 502 | `verify-domain` found no TXT record holding the token; DNS can take a while, so ask again later |
| `sso.domain_verified` | 409 | The domain is already verified |
| `sso.forbidden` | 403 | Managing a provider registered by someone else, or registering for an organization as a plain member |
| `sso.not_member` | 400 | Registering for an organization the caller is not in |
| `sso.sp_metadata_mismatch` / `sso.field_not_allowed` | 400 | Custom SP metadata contradicts the config / a `NoInput` field in a body |
| `sso.saml_session_not_found`, `sso.idp_slo_unsupported`, `sso.invalid_logout_request`, `sso.invalid_logout_response`, `sso.logout_failed_at_idp` | 404/400/502 | Single logout |

## Not built yet

Passphrase-protected PEM keys (Go deprecates them; keys are sealed at rest instead), column renames, and a hosted onboarding dashboard.

## Next

- [Organizations](organization.md): the organization a provider belongs to, and the roles its people get.
- [SCIM](scim.md): let the same IdP create and deactivate the users before they sign in.
- [OAuth](oauth.md): a fixed list of social providers beside SSO.
