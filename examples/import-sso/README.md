# Import SAML SSO providers from Supabase

The SSO step of a Supabase migration, after [import-users](../import-users): every SAML provider in `auth.sso_providers`, `auth.saml_providers` and `auth.sso_domains` becomes a [`plugin/sso`](../../plugin/sso) provider with the same IdP metadata, NameID format, attribute mapping and email domains. Each one goes through `RegisterProvider`, so it is checked exactly as a registration over HTTP would be, and its keys are sealed with your `AUTH_SECRET`.

## Run it

```sh
cd examples
AUTH_SECRET=… go run ./import-sso -providers sso_providers.csv -saml saml_providers.csv -domains sso_domains.csv \
  -sp-entity-id https://<ref>.supabase.co/auth/v1/sso/saml/metadata -owner <user id> -base-url https://app.example.com -db app.db
```

| Flag | Meaning |
|---|---|
| `-providers`, `-saml`, `-domains` | The three tables as CSV with headers (`\copy … to … csv header`) |
| `-sp-entity-id` | Supabase's SP entity id, kept as each provider's SP entity id, so the IdP admin changes only the ACS URL |
| `-owner` | An imported user who owns the providers (manages them over `/auth/sso/*-provider`); usually your administrator |
| `-base-url` | The app's public URL; each provider's ACS URL (`<base>/auth/sso/saml2/sp/acs`) is built from it |

`AUTH_SECRET` must be the one your app runs with. Run the tests with `go test ./import-sso`.

## Walkthrough

After `go run ./import-users -source supabase -file import-users/testdata/supabase-users.csv -identities import-users/testdata/supabase-identities.csv -factors import-users/testdata/supabase-factors.csv -db app.db`, with Ada (`0b1f1c1e-…-000000000001`) as owner:

```sh
AUTH_SECRET=example-secret-for-the-transcript-only-32b go run ./import-sso \
  -providers import-sso/testdata/sso_providers.csv -saml import-sso/testdata/saml_providers.csv -domains import-sso/testdata/sso_domains.csv \
  -sp-entity-id https://abcdefghijklmnop.supabase.co/auth/v1/sso/saml/metadata \
  -owner 0b1f1c1e-0000-4000-8000-000000000001 -base-url https://app.example.com -db app.db
```

```text
imported 1 provider(s), 1 failed
  ok     example-okta: example.com, example.org (IdP https://idp.example.com/saml)
  note   example-okta: department: kept the first of 2 attribute names (dept)
  FAILED supabase-5a1b2c3d-0000-4000-8000-00000000000b: no metadata_xml (metadata_url "https://login.globex.test/saml/metadata"): fetch the XML and put it in the CSV
```

A provider keeps its Supabase `resource_id` as its id when it has one (`example-okta`), else `supabase-<uuid>`. Supabase can store a metadata URL instead of the XML; the import never fetches anything, so download that XML into the CSV's `metadata_xml` column and run again.

## The code

Each row is registered by the owner. `RegisterProvider` is an operation of a signed-in user, so the import holds a session of the owner while it runs and deletes it afterwards:

<!-- ds:block id=importproviders-4c7mx2ra -->
**importProviders** · [`examples/import-sso/main.go:137-157`](main.go#L137-L157)

```go
func importProviders(ctx context.Context, a *auth.Auth, p *sso.Plugin, owner, spEntityID string, rows []samlRow) ([]result, error) {
	s, tok, err := a.CreateSession(ctx, owner, auth.Client{UserAgent: "import-sso"})
	if err != nil {
		return nil, fmt.Errorf("owner %s: %w", owner, err)
	}
	defer func() { _ = a.DeleteSession(context.Background(), owner, s.ID) }() // best effort; it expires anyway
	as := a.WithRequest(ctx, auth.Request{Transport: auth.TransportGo, Credential: auth.CredentialBearer, Token: tok})

	out := make([]result, 0, len(rows))
	for _, r := range rows {
		res := result{Row: r, ProviderID: providerIDFor(r)}
		cfg, notes, err := samlConfig(r, spEntityID)
		res.Notes = notes
		if err == nil {
			_, err = p.RegisterProvider(as, sso.RegisterRequest{ProviderID: res.ProviderID, Issuer: spEntityID, Domain: strings.Join(r.Domains, ","), SAMLConfig: cfg})
		}
		res.Err = err
		out = append(out, res)
	}
	return out, nil
}
```
<!-- /ds:block hash=cf40c5 -->

Supabase's attribute mapping (`{"keys": {"email": {"name": "mail"}}}`) becomes the plugin's `SAMLMapping`:

<!-- ds:block id=samlmapping-9t3pv6hd -->
**samlMapping** · [`examples/import-sso/main.go:203-240`](main.go#L203-L240)

```go
func samlMapping(raw string) (sso.SAMLMapping, []string, error) {
	var out sso.SAMLMapping
	var m supabaseMapping
	if raw == "" {
		return out, nil, nil
	}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return out, nil, fmt.Errorf("attribute_mapping: %w", err)
	}
	var notes []string
	keys := slices.Sorted(maps.Keys(m.Keys))
	for _, k := range keys {
		attr := m.Keys[k].Name
		if names := m.Keys[k].Names; attr == "" && len(names) > 0 {
			attr = names[0]
			if len(names) > 1 {
				notes = append(notes, fmt.Sprintf("%s: kept the first of %d attribute names (%s)", k, len(names), attr))
			}
		}
		switch {
		case attr == "":
		case k == "email":
			out.Email = attr
		case k == "name":
			out.Name = attr
		case k == "first_name" || k == "given_name":
			out.FirstName = attr
		case k == "last_name" || k == "family_name":
			out.LastName = attr
		default:
			if out.ExtraFields == nil {
				out.ExtraFields = map[string]string{}
			}
			out.ExtraFields[k] = attr
		}
	}
	return out, notes, nil
}
```
<!-- /ds:block hash=671122 -->

An imported provider is not domain-verified. So that a user imported with a verified address in its domain lands on that account at their first SSO sign-in instead of being refused with `sso.account_exists`, name the imported providers in `sso.TrustProviders(...)` in your app (Supabase trusted them already), or verify their domains with `sso.WithDomainVerification`. `main_test.go` runs that sign-in through `ssotest`'s SAML IdP and checks it reaches Ada's imported account, and that the same sign-in without `TrustProviders` is refused.

## What this used

- [`plugin/sso`](https://pkg.go.dev/github.com/ubgo/auth/plugin/sso): `RegisterProvider`, `SAMLConfig`, `SAMLMapping`, `TrustProviders`, `ProviderByID`
- [`github.com/ubgo/auth`](https://pkg.go.dev/github.com/ubgo/auth): `CreateSession`, `WithRequest`, `DeleteSession`
- Related: [import-users](../import-users), [sso](../sso), [Supabase guide](../../docs/migrating/supabase.md).
