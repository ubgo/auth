# SSO for organizations: domain verification and single logout

A customer connects their SAML identity provider to their organization the way a B2B product needs it:

- the organization's owner registers the provider for the organization; a plain member cannot;
- nobody signs in through it until the customer proves they own the email domain with a DNS TXT record;
- the company's people join the organization as members on their first sign-in, by work email or by the organization's slug;
- signing out ends the session at the IdP too (SAML single logout), whether the app starts it or the IdP does.

The basics of SSO (an OIDC provider in code, a SAML provider registered at run time) are in [sso](../sso).

## Run it

```sh
cd examples
AUTH_SECRET=$(openssl rand -base64 32) go run ./sso-domains
```

It creates `sso-domains.db` (SQLite) and listens on `http://localhost:8081`, with domain verification against the real DNS. A real run needs a real IdP and a domain whose DNS you control, so the test is the walkthrough: it plays the IdP with `plugin/sso/ssotest` and the DNS with a fake resolver.

## Walkthrough

```sh
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

`TestSSODomains_VerifyJoinAndSingleLogout`, step by step:

1. The owner signs up, creates Acme, and registers Acme's SAML IdP with `POST /auth/sso/register`, naming the organization, the domain `acme.test` and the IdP's single logout URL. The answer carries a `domainVerificationToken` and `"domainVerified": false`.
2. Ada's sign-in by her work email is `401 sso.domain_unverified`.
3. `POST /auth/sso/verify-domain` before the record exists is `502 sso.domain_not_proven`; that is the INFO line above.
4. The test publishes the token at `_ubgo-auth-token-acme-saml.acme.test` (`sso.DomainRecordName`), and `verify-domain` succeeds.
5. Ada signs in: the AuthnRequest goes to the IdP, the IdP's signed assertion is posted to the ACS, and she lands on `/me`. The owner's members list now holds her as `member`.
6. Ada calls `POST /auth/sso/saml2/logout`. Her session ends at once, and the answer sends her browser to the IdP with a LogoutRequest naming her NameID and IdP session. The IdP's signed LogoutResponse lands her on `/bye`.
7. Ada signs in again, this time with `{"organizationSlug": "acme"}`. The IdP sends its own signed LogoutRequest; her session ends, and the IdP gets a LogoutResponse with its RelayState.

`TestSSODomains_OnlyTheOwnerOrAdminRegisters`: a plain member of Acme registering for it is `403 sso.forbidden`; someone outside it `400 sso.not_member`.

## The code

Domain verification, organizations and single logout are three options of `sso.New`. The resolver is nil in `main` (the real DNS) and a fake in the test:

<!-- ds:block id=ssodomains-newauth-6p3kw8zn -->
**newAuth** · [`examples/sso-domains/main.go:96-113`](main.go#L96-L113)

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

The sso plugin names no organization module; the app answers its three questions from `plugin/organization`. Finding an organization by slug reads the plugin's table with its typed columns, because reads are open to the app:

<!-- ds:block id=ssodomains-byslug-8k2nw5qr -->
**orgAdapter.BySlug** · [`examples/sso-domains/main.go:144-161`](main.go#L144-L161)

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

Limits of this example: one IdP and one domain. Logout messages must be signed by the IdP's certificate, which is the default; `SAMLOptions.AllowUnsignedLogoutRequests` relaxes it and lets anyone who knows a NameID and SessionIndex sign that person out.

## What this used

- [`plugin/sso`](https://pkg.go.dev/github.com/ubgo/auth/plugin/sso): `WithDomainVerification`, `WithOrganizations`, `WithSAMLOptions`, `DomainRecordName`, `LogoutDocument`, `RedirectURL`, `PeekLogout`
- [`plugin/sso/ssotest`](https://pkg.go.dev/github.com/ubgo/auth/plugin/sso/ssotest): `NewSAMLIdP`, `AuthnRequest`
- [`plugin/organization`](https://pkg.go.dev/github.com/ubgo/auth/plugin/organization): `RoleOf`, `AddMember`, the typed columns `OrgID` and `OrgSlug`
- Guide: [enterprise SSO](../../docs/plugins/sso.md). Related: [sso](../sso), [scim](../scim), [import-sso](../import-sso), [org-teams](../org-teams).
