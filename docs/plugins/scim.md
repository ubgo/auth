# Provision users from an identity provider with SCIM

You will let a customer's identity provider (Okta, Microsoft Entra ID, Google Workspace, JumpCloud) create, update, deactivate and delete their users and groups in your app over SCIM 2.0, so a new hire can sign in on day one and a leaver loses access the moment IT disables them. This is better-auth's `scim` plugin.

Use it when you sell to organizations that manage people centrally. Pair it with single sign-on, so the provisioned users also sign in through the customer's IdP.

## Before you start

- An app with the email plugin wired, as in [your first app](../start/first-app.md): a provisioned user's primary email becomes an email identity.
- The module: `go get github.com/ubgo/auth/plugin/scim`. It depends on the core only.
- The reference for every attribute, path, option and error is the package's [README](../../plugin/scim/README.md).
- The example is [`examples/scim`](../../examples/scim): one connection, email and password sign-in, groups printed by a `GroupMapper`. `SCIM_TOKEN=$(openssl rand -hex 32) go run ./scim` in `examples/` serves it on `localhost:8081`; `go test ./scim` runs the joiner-and-leaver flow. The transcripts below come from that program.

## Step 1 — Wire the plugin and mount the handler

One [`Connection`](ds:block?id=scim-connection-4t8qm2wv) per customer tenant, with a bearer token you generate and hand to their admin. Store the token like any secret; the connection id scopes everything that tenant creates. The example reads the token from `SCIM_TOKEN` and refuses to start without it, so no token is ever written into the source:

<!-- ds:block id=scim-example-newscim-5r2wk8qp -->
**newSCIM** · [`examples/scim/main.go:113-119`](../../examples/scim/main.go#L113-L119)

```go
func newSCIM(token string, groups scim.GroupMapper) *scim.Plugin {
	return scim.New(
		scim.Connections(scim.Connection{ID: connectionID, Credentials: []scim.Credential{{ID: credentialID, Token: token}}}),
		scim.TrustEmails(),
		scim.WithGroupMapper(groups),
	)
}
```
<!-- /ds:block hash=5d8568 -->

Add the plugin to `auth.WithPlugins` beside the email plugin, and mount its handler next to the library's routes:

<!-- ds:block id=scim-example-newhandler-9m4tq7vx -->
**newHandler** · [`examples/scim/main.go:141-147`](../../examples/scim/main.go#L141-L147)

```go
func newHandler(a *auth.Auth, sp *scim.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle(scimPrefix+"/", http.StripPrefix(scimPrefix, sp.Handler()))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}
```
<!-- /ds:block hash=7879df -->

SCIM is a REST protocol with its own media type, verbs and error schema, so it is served by its own handler rather than as library operations:

<!-- ds:block id=scim-handler-2m6xv8qn -->
**Plugin.Handler** · [`plugin/scim/scim.go:550`](../../plugin/scim/scim.go#L550-L550)

```go
func (p *Plugin) Handler() http.Handler { return http.HandlerFunc(p.serve) }
```
<!-- /ds:block hash=90d140 -->

Run `a.Migrate(ctx)` once: the plugin owns three tables and adds `scim_deactivated_at` to `auth_user`. With many customers, keep their tokens in your own table and authenticate them with `scim.VerifyBearerToken(fn)`, which returns the `Principal` (connection id and scopes) for a token or `scim.ErrUnauthorized`.

Check: the public discovery document answers without a token, and everything else needs it (from the example's [walkthrough](../../examples/scim/README.md)):

```sh
curl -s localhost:8081/scim/v2/ServiceProviderConfig | jq -c '{patch,filter,bulk}'
curl -s -D - -o /dev/null localhost:8081/scim/v2/Users | grep -i '^HTTP\|^www-auth'
```

```text
{"patch":{"supported":true},"filter":{"maxResults":100,"supported":true},"bulk":{"maxOperations":0,"maxPayloadSize":0,"supported":false}}
HTTP/1.1 401 Unauthorized
Www-Authenticate: Bearer realm="SCIM"
```

`TestSCIM_TokenGuardsEverythingButDiscovery` in `examples/scim` proves the same.

## Step 2 — Point the identity provider at it

In the IdP's provisioning settings, set the tenant URL to `https://app.example.com/scim/v2` and the secret token to the connection's token. A request without it answers `401` with `WWW-Authenticate: Bearer realm="SCIM"`; a credential whose `Scopes` lack the needed `scim.users.*` or `scim.groups.*` answers `403`. The IdP then creates users like this:

```sh
curl -s -X POST https://app.example.com/scim/v2/Users -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/scim+json' \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"ada@acme.test","name":{"givenName":"Ada","familyName":"Lovelace"},"emails":[{"value":"ada@acme.test","type":"work","primary":true}]}'
```

The answer is the stored user with its `id` and `meta.location`, in this shape:

<!-- ds:block id=scim-user-3q9wk5mt -->
**User** · [`plugin/scim/user.go:21-41`](../../plugin/scim/user.go#L21-L41)

```go
type User struct {
	Schemas           []string        `json:"schemas"`
	ID                string          `json:"id,omitempty"`
	ExternalID        string          `json:"externalId,omitempty"`
	UserName          string          `json:"userName"`
	Name              *Name           `json:"name,omitempty"`
	DisplayName       string          `json:"displayName,omitempty"`
	Title             string          `json:"title,omitempty"`
	UserType          string          `json:"userType,omitempty"`
	PreferredLanguage string          `json:"preferredLanguage,omitempty"`
	Locale            string          `json:"locale,omitempty"`
	Timezone          string          `json:"timezone,omitempty"`
	Active            *bool           `json:"active,omitempty"`
	Emails            []MultiValue    `json:"emails,omitempty"`
	PhoneNumbers      []MultiValue    `json:"phoneNumbers,omitempty"`
	Addresses         []Address       `json:"addresses,omitempty"`
	Roles             []MultiValue    `json:"roles,omitempty"`
	Entitlements      []MultiValue    `json:"entitlements,omitempty"`
	Enterprise        *EnterpriseUser `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
	Meta              *Meta           `json:"meta,omitempty"`
}
```
<!-- /ds:block hash=5fe6c1 -->

Each new SCIM user gets a new library user with its primary email as an unverified identity. An address another account already holds answers `409 uniqueness`: the plugin never links by email, because an IdP can assert any address. To attach a SCIM user to an account that already exists, decide it yourself with `scim.ResolveUser(fn)`. Its `Resolution{UserID, Profile}` says whether the IdP then owns that account's profile: `scim.ProfilePreserve` (the default) never writes the account's name or email, `scim.ProfileManage` writes them now and on every update. An account has one profile source across all connections, so a second manager is `409 uniqueness` until the first SCIM user is deleted, which hands the profile over to the next `ProfileManage` link.

## Step 3 — Deactivation ends access

When the IdP sets `active` to `false` (Entra sends `"False"`, which is accepted), and every SCIM user linked to that library user is inactive, the user's sessions end and every later session lookup refuses them:

<!-- ds:block id=scim-sessionpredicates-5w9kq3nt -->
**Plugin.SessionPredicates** · [`plugin/scim/scim.go:490-492`](../../plugin/scim/scim.go#L490-L492)

```go
func (p *Plugin) SessionPredicates() []sqlb.Predicate {
	return []sqlb.Predicate{sqlb.IsNull(DeactivatedAt)}
}
```
<!-- /ds:block hash=e5a533 -->

In the example Ada is signed in when Entra deactivates her; her open session is refused at once, and so is her correct password:

```sh
curl -s -X PATCH localhost:8081/scim/v2/Users/scu_qrr557rximyx5gbayvjvksdh -H "Authorization: Bearer $SCIM_TOKEN" -H 'Content-Type: application/scim+json' \
  -d '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}' \
  | jq -c '{id, active, version: .meta.version}'
curl -s -b ada.txt localhost:8081/me
curl -s -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"ada@acme.com","password":"correct horse battery staple"}'
```

```json
{"id":"scu_qrr557rximyx5gbayvjvksdh","active":false,"version":"W/\"2\""}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"error":{"code":"scim.deactivated","message":"This account has been deactivated by your organization."}}
```

Check: `TestSCIM_JoinerAndLeaver` in `examples/scim`.

`active: true` restores access. Deleting the SCIM user keeps the library user deactivated, so a leaver's data stays for your records; `scim.DeleteUsers()` deletes the account instead.

## Step 4 — Follow groups into your own model

SCIM groups are stored per connection, but the core has no groups. Give the plugin a `GroupMapper` and it tells you, inside the same transaction, every group's full membership as library user ids after each change:

<!-- ds:block id=scim-groupmapper-7q4wn8kx -->
**GroupMapper** · [`plugin/scim/scim.go:361-364`](../../plugin/scim/scim.go#L361-L364)

```go
type GroupMapper interface {
	SyncGroup(ctx context.Context, g GroupState) error
	DeleteGroup(ctx context.Context, connectionID, groupID string) error
}
```
<!-- /ds:block hash=710420 -->

An error from the mapper fails the request and rolls it back, so the IdP retries. Map a group to an organization, a team or a role there; because you get the whole list each time, the implementation can simply replace what it had. To think in roles rather than groups, use `scim.ProjectRoles` instead: you map each group to role names, and the plugin tells you each user's full list of roles whenever it changes:

<!-- ds:block id=scim-roleprojection-6m3wq8kv -->
**RoleProjection** · [`plugin/scim/roles.go:61-70`](../../plugin/scim/roles.go#L61-L70)

```go
type RoleProjection struct {
	// Map returns the roles a group grants its members (projection.roles.map).
	Map func(ctx context.Context, g RoleSource) ([]string, error)
	// Exists, when set, keeps only roles the app knows
	// (projection.roles.exists); a refused role grants nothing.
	Exists func(ctx context.Context, connectionID, role string) (bool, error)
	// Reconcile receives each affected user's full state, idempotent, in the
	// request's transaction (projection.reconcileUser); an error rolls back.
	Reconcile func(ctx context.Context, u ProjectedUser) error
}
```
<!-- /ds:block hash=e485b3 -->

## Step 5 — Let customers connect their own IdP

With many customers, create connections at run time instead of in code: each customer's admin connects their own IdP from your settings page. Turn on `scim.ManagedConnections()`; the plugin then needs no connection in code. Managed tokens start with `scimt_` and are stored only as HMAC-SHA256 digests, keyed from `auth.WithSecret` (or `scim.CredentialHashSecret`), so the app needs a secret. [`examples/scim-connections`](../../examples/scim-connections) treats every organization as a customer:

<!-- ds:block id=scimconn-newscim-3w8kq5nv -->
**newSCIM** · [`examples/scim-connections/main.go:117-122`](../../examples/scim-connections/main.go#L117-L122)

```go
func newSCIM(groups scim.GroupMapper) *scim.Plugin {
	return scim.New(
		scim.ManagedConnections(),
		scim.WithGroupMapper(groups),
	)
}
```
<!-- /ds:block hash=95ab6a -->

The managed-connection API is Go only, so you put your own routes over it. Pass the customer's id (here the organization's) as the provisioning domain on every call: a connection is found only within its domain, so one customer naming another's connection id gets `scim.connection_not_found`. Guard the routes with your own admin check (the example asks for the organization's owner) and check the request's origin, because these are your routes, not the library's:

<!-- ds:block id=scimconn-newhandler-7d2xr4mh -->
**newHandler** · [`examples/scim-connections/main.go:153-176`](../../examples/scim-connections/main.go#L153-L176)

```go
func newHandler(a *auth.Auth, sp *scim.Plugin) (http.Handler, error) {
	orgs, err := auth.PluginOf[*organization.Plugin](a)
	if err != nil {
		return nil, err
	}
	mw := authhttp.Middleware(a)
	owner := func(h http.Handler) http.Handler {
		return mw(orgs.RequireRole(orgInPath, organization.RoleOwner)(h))
	}
	s := settings{a: a, sp: sp}
	base := "/orgs/{" + pathOrgParam + "}/scim/connections"
	conn := base + "/{" + pathConnParam + "}"
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle(scimPrefix+"/", http.StripPrefix(scimPrefix, sp.Handler()))
	mux.Handle("GET "+base, owner(http.HandlerFunc(s.list)))
	mux.Handle("POST "+base, owner(s.post(s.create)))
	mux.Handle("GET "+conn+"/events", owner(http.HandlerFunc(s.events)))
	mux.Handle("POST "+conn+"/rotate", owner(s.post(s.rotate)))
	mux.Handle("POST "+conn+"/credentials/{"+pathCredParam+"}/revoke", owner(s.post(s.revoke)))
	mux.Handle("POST "+conn+"/decommission", owner(s.post(s.decommission)))
	mux.Handle("/me", mw(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux, nil
}
```
<!-- /ds:block hash=ac2adf -->

Creating a connection ([`CreateManagedConnection`](ds:block?id=scim-plugin-createmanagedconnection-6t2wn9qk)) issues its first credential. The token is in this answer and never again. `CreationRequestID` (16 to 255 characters, chosen once per form) makes a retried click answer `409 scim.creation_request_conflict` instead of creating a second connection. Leaving `Scopes` empty grants every scope; pass `scim.ScopeUsersRead` and friends for a narrower token:

<!-- ds:block id=scimconn-create-5p9tn2wq -->
**settings.create** · [`examples/scim-connections/main.go:229-245`](../../examples/scim-connections/main.go#L229-L245)

```go
func (s settings) create(w http.ResponseWriter, r *http.Request) {
	var in createRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		authhttp.WriteError(w, auth.ErrBadRequest)
		return
	}
	out, err := s.sp.CreateManagedConnection(r.Context(), scim.CreateManagedRequest{
		CreationRequestID:    in.RequestID,
		ProvisioningDomainID: orgInPath(r),
		ActorID:              authhttp.MustUser(r).ID,
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, issued(out))
}
```
<!-- /ds:block hash=4796b8 -->

To change a token without downtime, rotate: a second credential is issued beside the active ones (at most [5](ds:block?id=scim-defaultmaxactivecredentials-4n9wq2xt) by default, `scim.MaxActiveCredentials(n)`), the customer pastes it into the IdP, then revokes the old one with `RevokeCredential`. `ManagedConnections(ctx, domain)` lists a customer's connections with their credentials (never a token), and `ConnectionEvents` is the audit trail: who created the connection and issued, rotated and revoked which credential.

<!-- ds:block id=scimconn-rotate-8h3mv6xz -->
**settings.rotate** · [`examples/scim-connections/main.go:252-259`](../../examples/scim-connections/main.go#L252-L259)

```go
func (s settings) rotate(w http.ResponseWriter, r *http.Request) {
	out, err := s.sp.RotateCredential(r.Context(), r.PathValue(pathConnParam), orgInPath(r), authhttp.MustUser(r).ID, nil, nil)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, issued(out))
}
```
<!-- /ds:block hash=1f75fb -->

Try it (the example's README has the full run):

```sh
cd examples
AUTH_SECRET=$(openssl rand -hex 32) go run ./scim-connections
curl -s -b alice.txt -X POST localhost:8081/orgs/org_et2i2wnniixzxmung3jz7t7h/scim/connections -H 'Origin: http://localhost:8081' -d '{"requestId":"settings-form-7f3a9c"}'
```

```json
{"connection":{"id":"scimc_lu7grwvhytpg2rdkrzpq2hzj","provisioningDomainId":"org_et2i2wnniixzxmung3jz7t7h","status":"active","createdAt":"2026-10-09T10:23:13.997941Z","createdBy":"usr_bviu7ezles3ah757fiq4nmx4","credentials":[{"id":"scimk_ak7pj4muk2llvf73c57t2zqm","status":"active","scopes":["scim.users.read","scim.users.write","scim.groups.read","scim.groups.write"],"createdAt":"2026-10-09T10:23:13.998057Z","createdBy":"usr_bviu7ezles3ah757fiq4nmx4"}]},"credentialId":"scimk_ak7pj4muk2llvf73c57t2zqm","token":"scimt_scimk_ak7pj4muk2llvf73c57t2zqm.y22m3r-vWcC9hiTEkSchDp48XOinQt11arrd1Gr5nRQ"}
```

Check: `TestConnections_CustomerConnectsTheirIdP` (the IdP provisions with the new token; a retried create, a member, another customer and a cross-site page are refused) and `TestConnections_RotateThenRevoke`:

<!-- ds:block id=scimconn-rotatetest-4n7vq2km -->
**TestConnections_RotateThenRevoke** · [`examples/scim-connections/main_test.go:186-215`](../../examples/scim-connections/main_test.go#L186-L215)

```go
func TestConnections_RotateThenRevoke(t *testing.T) {
	w := newWorld(t)
	acme := w.newCustomer(t, "Acme")
	first := w.connect(t, acme, "acme-create-0001-form")
	connPath := acme.connections() + "/" + first.Connection.ID

	var second issuedResponse
	acme.b.Post(connPath+"/rotate", nil).Expect(http.StatusCreated).Decode(&second)
	for _, tok := range []string{first.Token, second.Token} {
		if status := w.listUsers(t, tok); status != http.StatusOK {
			t.Fatalf("during the rotation a token answered %d", status)
		}
	}

	acme.b.Post(connPath+"/credentials/"+first.CredentialID+"/revoke", nil).Expect(http.StatusOK)
	if status := w.listUsers(t, first.Token); status != http.StatusUnauthorized {
		t.Fatalf("the revoked token answered %d", status)
	}
	if status := w.listUsers(t, second.Token); status != http.StatusOK {
		t.Fatalf("the new token answered %d", status)
	}
	if code := acme.b.Post(connPath+"/credentials/"+first.CredentialID+"/revoke", nil).Expect(http.StatusNotFound).ErrorCode(); code != scim.ErrCredentialNotFound.Code {
		t.Fatalf("revoking twice: %q", code)
	}

	want := []scim.EventKind{scim.EventConnectionCreated, scim.EventCredentialIssued, scim.EventCredentialRotated, scim.EventCredentialRevoked}
	if got := w.eventKinds(t, acme, connPath); !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}
```
<!-- /ds:block hash=f65fa9 -->

## Step 6 — Retire a connection

When a customer leaves or moves IdP, decommission its connection with [`DecommissionConnection`](ds:block?id=scim-plugin-decommissionconnection-2q8xv5mk). It is irreversible: its tokens stop at once (`401` "SCIM connection is decommissioned", for managed credentials too; one revoked earlier keeps answering "Invalid SCIM bearer token"), its SCIM users are made inactive in batches of 50, each in its own transaction, and each linked user with no other active source is deactivated and signed out (a user another connection still provisions stays active). Your `GroupMapper` is told the connection's groups are gone. The SCIM rows are kept for the record, and the event log ends with `connection.decommissioning` and `connection.decommissioned`.

<!-- ds:block id=scimconn-decommission-6r4yk8cs -->
**settings.decommission** · [`examples/scim-connections/main.go:310-321`](../../examples/scim-connections/main.go#L310-L321)

```go
func (s settings) decommission(w http.ResponseWriter, r *http.Request) {
	res, err := s.sp.DecommissionConnection(r.Context(), scim.DecommissionRequest{
		ConnectionID:         r.PathValue(pathConnParam),
		ProvisioningDomainID: orgInPath(r),
		ActorID:              authhttp.MustUser(r).ID,
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, decommissionResponse{Status: res.Status, ReconciledUsers: res.ReconciledUsers})
}
```
<!-- /ds:block hash=1e0caf -->

The example runs it to completion inside the request. For a large directory, pass `MaxBatches` so one call does bounded work, and call again from a worker until the status is `complete`; the cursor survives a crash, and a call on a finished connection answers `complete` again. Run one worker per connection at a time.

```sh
curl -s -b alice.txt -X POST localhost:8081/orgs/org_et2i2wnniixzxmung3jz7t7h/scim/connections/scimc_lu7grwvhytpg2rdkrzpq2hzj/decommission -H 'Origin: http://localhost:8081'
curl -s localhost:8081/scim/v2/Users -H 'Authorization: Bearer scimt_scimk_uskckjmgcgzv3z6eddacy26m._N_e0DjTnVmwok-89YL01UmnDqCtLzVnR050O9Dql4A'
```

```json
{"status":"complete","reconciledUsers":1}
{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"401","detail":"Invalid SCIM bearer token"}
```

Check: `TestConnections_DecommissionEndsAccess` signs the provisioned user in first, then finds the token refused, the session gone, the group deleted in the mapper, and a later rotation `409 scim.connection_decommissioned`.

## Options you may want

| Option | When |
|---|---|
| `scim.TrustEmails()` | The IdP verifies addresses in domains the customer owns, and provisioned users should sign in by email or receive recovery mail without verifying first. |
| `scim.ResolveUser(fn)` | Attach a new SCIM user to an existing account (an invited user who signed up already), on evidence you trust. |
| `scim.DeleteUsers()` | A SCIM delete should delete the account, not only deactivate it. |
| `scim.VerifyBearerToken(fn)` | Tokens live in your database, one per customer. |
| `Credential.Scopes`, `Credential.ExpiresAt` | A read-only audit token, or a token that expires. |

## From TypeScript

There is nothing for a frontend to call. SCIM is server-to-server: the identity provider talks to `scim.Handler` with its bearer token, and the plugin's one operation is the gate every SCIM request passes through inside that handler, which answers `auth.unknown_operation` to any other caller. The gate is a self-served operation (`auth.OpInfo.SelfServed`), so no transport mounts it and neither the prebuilt [typed client](../client/README.md) nor one generated from an app that wires the plugin has a `scim` method, and the OpenAPI document does not list it.

The settings page where a customer's admin connects their own identity provider (Step 5) calls your app's own routes over the Go-only managed-connection API, so its frontend uses your own fetch code or your own plugin ([Your own plugins](../client/custom-plugins.md) turns routes of your own into typed methods). What the people provisioned this way see is ordinary sign-in through [SSO](sso.md#from-typescript) or the other methods.

## What can go wrong

| Answer | When | Fix |
|---|---|---|
| `401` | No token, a wrong one, or an expired credential. | Check the IdP's secret token. |
| `403 scim.deactivated` on sign-in | The IdP deactivated the user (Step 3). | Expected; the IdP sets `active` back to restore access. |
| `403` | The credential lacks the scope. | Add the scope, or use another credential. |
| `409 uniqueness` | The `userName`, `externalId` or group `displayName` is taken in this connection, or the email belongs to another account. | Expected for a duplicate; for an email, link the accounts with `ResolveUser` if they are the same person. |
| `400 invalidFilter` | A filter outside `attribute eq "value"` joined by `and`. | IdPs use the supported subset; a custom client should too. |
| `400 mutability` | A PATCH touched `id`, `meta` or `schemas`, or removed `userName`. | Fix the client. |
| `400 noTarget` | A PATCH filter matched nothing (and could not create an entry). | Fix the path. |
| `415` | The body is not `application/scim+json` or `application/json`. | Set `Content-Type`. |
| `412` | An `If-Match` names an older version of the user. | Read the user again and retry with its `meta.version`. |
| `409` without `scimType` | Two writes to one user raced; this one lost and changed nothing. | Retry. |
| `409 scim.creation_request_conflict` | A create reused a `CreationRequestID` (Step 5). | Expected for a retry; a new form gets a new id. |
| `404 scim.connection_not_found` | The connection id is unknown, not managed, or belongs to another provisioning domain. | Pass the caller's own domain; never take it from the request body. |
| `409 scim.too_many_credentials` | A rotation would exceed the active credentials allowed (5 by default). | Revoke an old credential first, or raise `scim.MaxActiveCredentials`. |
| `404 scim.credential_not_found` | Revoking a credential that is already revoked or not this connection's. | Expected on a repeated revoke. |
| `409 scim.connection_decommissioned` | Rotating a retired connection (Step 6). | Create a new connection. |
| `auth: the secret must be at least 32 bytes` at start | `AUTH_SECRET` is unset or short; managed token digests are keyed from it. | Set a 32-byte secret (`openssl rand -hex 32`); changing it later invalidates every issued token. |
| `scim: managed connections are off` (a 500) | A managed-connection call without `scim.ManagedConnections()`. | Add the option. |
| `429` | More than [600](ds:block?id=scim-defaultrequestlimit-7w3qn8kv) requests a minute from one address or one connection. | Wait for `Retry-After`, or raise the limit with `auth.WithRateRules` on `scim.EndpointRequest`. |

Known limits:

- Lists are filtered in SQL for ids, names and external ids, but email filters and paging run in memory over the matching users: fine for directories of thousands. A page holds at most [100](ds:block?id=scim-maxpagesize-6k2wq9mv) resources, a group at most [1,000](ds:block?id=scim-maxgroupmembers-3n8xk5tq) members, and a user at most [65,535](ds:block?id=scim-maxresourcesize-9v4mz2kw) bytes serialized.
- A user deleted by the IdP and created again with the same `externalId` gets the same account back (a tombstone remembers it).
- After fixing a `GroupMapper`, `sp.ReconcileProjection(ctx, domain)` replays every group into it.

## Next

- [Organizations](organization.md): a target for a `GroupMapper`.
- [Enterprise SSO](sso.md): the provisioned users then sign in through the same IdP; [`examples/sso-domains`](../../examples/sso-domains) joins them to the customer's organization on first sign-in.
- [Sessions](../concepts/sessions.md): what ends when a user is deactivated.
- The package [README](../../plugin/scim/README.md) is the full reference.
