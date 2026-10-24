# Import organizations and roles from Auth0 or Clerk

The second step of a migration, after [import-users](../import-users) has brought the users in with their ids kept: each organization with its members and their roles into [`plugin/organization`](../../plugin/organization), and, for Auth0, the tenant roles that mean "administrator" into [`plugin/admin`](../../plugin/admin). One transaction per organization: one that fails leaves nothing behind and is listed; the rest land.

## Run it

```sh
cd examples
go run ./import-orgs -source auth0 -file orgs.json -roles roles.json -admin-role Admin -db app.db
go run ./import-orgs -source clerk -file orgs.json -db app.db
```

Add `-dry-run` to print the plan without writing. Run the tests with `go test ./import-orgs`; they import the fixtures in `testdata/` into a database holding import-users' fixture users.

## Input

| Source | `-file` | `-roles` |
|---|---|---|
| Auth0 | A JSON array of `GET /api/v2/organizations`, each with the answer of `GET /api/v2/organizations/{id}/members?fields=user_id,roles` saved under `"members"` | A JSON array of `GET /api/v2/roles`, each with `GET /api/v2/roles/{id}/users` under `"users"` |
| Clerk | A JSON array of the `data` of `GET /v1/organizations`, each with the `data` of `GET /v1/organizations/{id}/memberships` under `"memberships"` | none: Clerk's app-wide roles live in your metadata |

The [Auth0](../../docs/migrating/auth0.md) and [Clerk](../../docs/migrating/clerk.md) migration guides give the commands that build these files.

## Walkthrough

After `go run ./import-users -source auth0 -file import-users/testdata/auth0.ndjson -db app.db` (three users imported, the duplicate `auth0|dup0001` failed), the dry run:

```sh
go run ./import-orgs -source auth0 -file import-orgs/testdata/auth0-orgs.json -roles import-orgs/testdata/auth0-roles.json -admin-role Admin -dry-run
```

```text
would import 2 organization(s)
  acme (org_W1a2B3c4D5e6F7g8): owner auth0|5f1a2b3c4d5e6f7a8b9c0d1e, 3 member(s)
    note auth0|blocked0001: role Billing Viewer has no equivalent; imported as member
  globex (org_H9i8J7k6L5m4N3o2): owner github|8675309, 2 member(s)
would set the admin role on 1 user(s)
```

The import. `globex` names `auth0|dup0001`, whose user import failed, so the whole organization is rolled back:

```sh
go run ./import-orgs -source auth0 -file import-orgs/testdata/auth0-orgs.json -roles import-orgs/testdata/auth0-roles.json -admin-role Admin -db app.db
```

```text
imported 1 organization(s), 1 failed
  note   acme: auth0|blocked0001: role Billing Viewer has no equivalent; imported as member
  FAILED globex: member auth0|dup0001: auth.user_not_found
set the admin role on 1 user(s), 0 failed
```

Clerk, after `go run ./import-users -source clerk -file import-users/testdata/clerk.csv -db clerk.db`:

```sh
go run ./import-orgs -source clerk -file import-orgs/testdata/clerk-orgs.json -db clerk.db
```

```text
imported 1 organization(s), 0 failed
  note   initech: user_2def is the owner (was admin): an organization starts with its creator as owner
  note   initech: user_2abc: role org:billing has no equivalent; imported as member
```

Fix the failed row (import the missing user, or drop the member from the file) and run again for that organization alone: one already imported fails on its slug (`organization.slug_taken`) and is not touched.

## The code

Each organization is created for its creator, who becomes the owner, and every other member is added with their mapped role; `CreateFor` and `AddMember` join the surrounding transaction:

<!-- ds:block id=importorgs-6v2kq9wd -->
**importOrgs** · [`examples/import-orgs/main.go:160-193`](main.go#L160-L193)

```go
func importOrgs(ctx context.Context, a *auth.Auth, orgs *organization.Plugin, source string, in []org) []orgResult {
	out := make([]orgResult, 0, len(in))
	for _, o := range in {
		res := orgResult{Org: o}
		creator := pickCreator(o)
		meta, _ := json.Marshal(importedFrom{Source: source, SourceID: o.SourceID}) // two strings always encode
		res.Err = a.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			created, err := orgs.CreateFor(ctx, creator, organization.CreateRequest{Name: o.Name, Slug: o.Slug, Metadata: meta})
			if err != nil {
				return fmt.Errorf("create: %w", err)
			}
			res.ID = created.ID
			for _, m := range o.Members {
				if m.UserID == creator {
					continue
				}
				if err := orgs.AddMember(ctx, created.ID, m.UserID, m.Role); err != nil {
					return fmt.Errorf("member %s: %w", m.UserID, err)
				}
			}
			return nil
		})
		for _, m := range o.Members {
			switch {
			case m.UserID == creator && m.Role != organization.RoleOwner:
				res.Notes = append(res.Notes, fmt.Sprintf("%s is the owner (was %s): an organization starts with its creator as owner", m.UserID, m.Role))
			case m.Note != "":
				res.Notes = append(res.Notes, m.UserID+": "+m.Note)
			}
		}
		out = append(out, res)
	}
	return out
}
```
<!-- /ds:block hash=616af1 -->

Auth0 has no built-in organization roles, so the mapping covers the names tenants usually create, compared ignoring case; Clerk's two built-in roles map directly:

<!-- ds:block id=auth0orgroles-8r4mv2xs -->
**auth0OrgRoles** · [`examples/import-orgs/sources.go:39-43`](sources.go#L39-L43)

```go
var auth0OrgRoles = map[string]organization.Role{
	"owner":  organization.RoleOwner,
	"admin":  organization.RoleAdmin,
	"member": organization.RoleMember,
}
```
<!-- /ds:block hash=b232ea -->

<!-- ds:block id=clerkorgroles-2w9dx6pb -->
**clerkOrgRoles** · [`examples/import-orgs/sources.go:134-137`](sources.go#L134-L137)

```go
var clerkOrgRoles = map[string]organization.Role{
	"org:admin":  organization.RoleAdmin,
	"org:member": organization.RoleMember,
}
```
<!-- /ds:block hash=2db320 -->

A tenant role named in `-admin-role` becomes the admin plugin's `admin` role; every other Auth0 role is your app's permission model and is not imported:

<!-- ds:block id=readauth0roles-5n7qc3wk -->
**readAuth0Roles** · [`examples/import-orgs/sources.go:97-112`](sources.go#L97-L112)

```go
func readAuth0Roles(r io.Reader, adminRoles []string) (map[string][]string, error) {
	var in []auth0TenantRole
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return nil, fmt.Errorf("auth0 roles: want an array of roles: %w", err)
	}
	out := map[string][]string{}
	for _, role := range in {
		if !slices.ContainsFunc(adminRoles, func(n string) bool { return strings.EqualFold(n, role.Name) }) {
			continue
		}
		for _, u := range role.Users {
			out[u.UserID] = []string{admin.RoleAdmin}
		}
	}
	return out, nil
}
```
<!-- /ds:block hash=445600 -->

<!-- ds:block id=importadminroles-3h8nw5tc -->
**importAdminRoles** · [`examples/import-orgs/main.go:215-223`](main.go#L215-L223)

```go
func importAdminRoles(ctx context.Context, ad *admin.Plugin, grants map[string][]string) []error {
	var errs []error
	for userID, roles := range grants {
		if err := ad.SetRoleFor(ctx, userID, roles...); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", userID, err))
		}
	}
	return errs
}
```
<!-- /ds:block hash=e210b5 -->

The organization plugin makes its own ids; the source's id is kept in each organization's metadata as `{"importedFrom": "auth0", "sourceId": "org_…"}`, so your own rows that referenced it can be re-pointed.

## What this used

- [`plugin/organization`](https://pkg.go.dev/github.com/ubgo/auth/plugin/organization): `CreateFor`, `AddMember`, `Role.Rank`
- [`plugin/admin`](https://pkg.go.dev/github.com/ubgo/auth/plugin/admin): `SetRoleFor`, `RoleAdmin`
- [`github.com/ubgo/auth`](https://pkg.go.dev/github.com/ubgo/auth): `Tx`
- Related: [import-users](../import-users), [import-sso](../import-sso), [organizations](../organizations).
