# scim

A SCIM 2.0 service provider ([RFC 7643](https://www.rfc-editor.org/rfc/rfc7643), [RFC 7644](https://www.rfc-editor.org/rfc/rfc7644)), better-auth's `scim` plugin: an identity provider such as Okta, Microsoft Entra ID, Google Workspace or JumpCloud creates, updates, deactivates and deletes users and groups by calling your app, so a leaver loses access the moment IT disables them.

It is its own module, `github.com/ubgo/auth/plugin/scim`, so an app without enterprise customers never compiles it. It needs the email plugin: a provisioned user's primary email becomes an email identity.

```go
sp := scim.New(
	scim.Connections(scim.Connection{ID: "acme", Credentials: []scim.Credential{{ID: "2026-10", Token: os.Getenv("SCIM_ACME_TOKEN")}}}),
	scim.WithGroupMapper(myOrgSync), // optional
)
a, err := auth.New(auth.WithDB(db, dialect), auth.WithBaseURL("https://app.example.com"),
	auth.WithPlugins(email.New(...), password.New(), sp))

mux.Handle("/scim/v2/", http.StripPrefix("/scim/v2", sp.Handler()))
```

Give the IdP the base URL `https://app.example.com/scim/v2` and the token.

## Endpoints

| Route | Scope | What it does |
|---|---|---|
| `POST /Users` | `scim.users.write` | Creates a SCIM user and a new library user (or links one, `ResolveUser`); 201 |
| `GET /Users` | `scim.users.read` | ListResponse with `filter`, `startIndex`, `count`, `attributes`, `excludedAttributes` |
| `GET /Users/{id}` | `scim.users.read` | One user; another connection's id is 404 |
| `PUT /Users/{id}` | `scim.users.write` | Replaces the user |
| `PATCH /Users/{id}` | `scim.users.write` | Ordered, atomic operations |
| `DELETE /Users/{id}` | `scim.users.write` | Deletes the SCIM user and its memberships; 204 |
| `POST /Groups`, `GET /Groups`, `GET`, `PUT`, `PATCH`, `DELETE /Groups/{id}` | `scim.groups.*` | The same for groups |
| `GET /ServiceProviderConfig`, `/Schemas`, `/Schemas/{id}`, `/ResourceTypes`, `/ResourceTypes/{id}` | public | Discovery: PATCH and filters yes; bulk, sort, ETags and password change no |

Every request passes the core's rate rules first, as the operation `scim.EndpointRequest` (`scim.request`, self-served: never mounted by a transport, and absent from the OpenAPI document and the generated TypeScript client): by default 600 a minute per IP and 600 a minute per connection, answered with 429 and `Retry-After`; replace them with `auth.WithRateRules(auth.RateRule{Match: scim.EndpointRequest, ...})`. A refused token is counted by its address, so guessing is limited too.

Every write to a user is conditional on the revision it read: `meta.version` is `W/"n"`, a PUT, PATCH or DELETE with `If-Match` naming an older revision answers 412, and a write that loses a race with another answers 409, rolling back everything it changed. ServiceProviderConfig advertises `etag` as supported.

Requests must be `application/scim+json` or `application/json`; every answer is `application/scim+json`, errors in SCIM's error schema with `scimType` (`invalidFilter`, `uniqueness`, `mutability`, `invalidSyntax`, `invalidPath`, `noTarget`, `invalidValue`, `tooMany`).

## Authentication

Each `Connection` is one IdP tenant and scopes every resource it creates: a connection never sees another's users or groups. A connection holds one or more `Credential`s (bearer tokens), so a token is rotated by adding the new credential, switching the IdP, then removing the old one. A credential's `Scopes` default to all four (`scim.users.read`, `scim.users.write`, `scim.groups.read`, `scim.groups.write`); `ExpiresAt` refuses it after a date. Tokens are compared in constant time over their SHA-256. `VerifyBearerToken(fn)` authenticates tokens the app stores itself (a per-customer token in its own table), asked only after every static credential missed; it returns a `Principal` or `scim.ErrUnauthorized`. A `Principal` with a blank or over-long connection id, an unknown scope, the managed connections' prefix, or the id of a connection given to `Connections` is refused (401), so a verifier can never speak for a configured connection. A missing or wrong token answers 401 with `WWW-Authenticate: Bearer realm="SCIM"`; a missing scope 403.

## Managed connections

`ManagedConnections(opts...)` lets the app create connections at run time, better-auth's managed mode, for a self-serve "connect your IdP" page: `CreateManagedConnection(ctx, CreateManagedRequest{CreationRequestID, ProvisioningDomainID, ActorID, Scopes, ExpiresAt})` returns the connection, its first credential and the raw token, once (a `CreationRequestID` of 16 to 255 characters is never reused: `scim.creation_request_conflict`). `ManagedConnections(ctx, domain)` lists a provisioning domain's connections newest first, `ManagedConnection(ctx, id, domain)` reads one (another tenant's is not found), `RotateCredential` adds an overlapping credential (at most `MaxActiveCredentials`, default 5), `RevokeCredential` revokes one, and `ConnectionEvents` returns the latest 100 events (`connection.created`, `credential.issued`, `credential.rotated`, `credential.revoked`, `connection.decommissioning`, `connection.decommissioned`). Tokens start with `scimt_`, are stored as HMAC-SHA256 digests (`CredentialHashSecret`, or a key derived from `auth.WithSecret`), carry their credential id, and never fall through to `VerifyBearerToken`. `last_used_at` is written at most every `LastUsedWriteInterval` (5 minutes).

Every connection, static, verified or managed, gets a row on its first request with its `ProvisioningDomainID` (default: the connection id), which cannot change afterwards (409).

## Decommissioning

`DecommissionConnection(ctx, DecommissionRequest{ConnectionID, ProvisioningDomainID, ActorID, MaxBatches})` retires a connection for good: its tokens answer 401 "SCIM connection is decommissioned" at once (static tokens, and managed credentials that were active, which are marked decommissioned; a credential revoked before keeps answering "Invalid SCIM bearer token"), its SCIM users are made inactive in batches of 50, each batch in its own transaction, and each linked library user is reconciled, so a user with no other active source is deactivated and signed out. At the end the `GroupMapper` is told every group is deleted. The SCIM rows are kept. `MaxBatches` bounds one call, which then answers `reconciling`; the next call resumes at the stored cursor. Run it from one worker.

## Users

Supported attributes: `userName` (required, unique per connection ignoring case), `externalId` (unique per connection), `name`, `displayName`, `title`, `userType`, `preferredLanguage`, `locale`, `timezone`, `active`, `emails` (up to 20), `phoneNumbers`, `addresses`, `roles`, `entitlements` (up to 10 each; one primary, distinct types), and the enterprise extension (`employeeNumber`, `costCenter`, `organization`, `division`, `department`, `manager`). A user is at most 65,535 bytes serialized. Entra's `"True"`/`"False"` strings for `active` and `primary` are accepted.

A new SCIM user gets a new library user named after `displayName` (or the formatted, or given and family name) with its primary email (the one marked primary, else the first `work`, else the first, else `userName` when it is an address) as an **unverified** email identity. The address must not be held by any identity already (409 `uniqueness`): the plugin never links by email, because an IdP can assert any address. `ResolveUser(fn)` links a new SCIM user to an existing library user instead, and a connection may hold one SCIM user per library user. The link's `Resolution.Profile` is better-auth's profile mode: `ProfilePreserve` (the default) leaves the linked user's name and email alone; `ProfileManage` makes the SCIM user that user's **profile source**, which writes the name and makes the IdP's address the primary email now (adopting the user's identity that already holds it, otherwise replacing the old primary email) and follows it on every PUT and PATCH. A library user has one profile source across every connection: a user the plugin created is managed by its creator, and a second `ProfileManage` link, or a tombstone revival while another source holds the profile, is 409 `uniqueness`. Deleting the source frees the profile for the next `ProfileManage` link (the hand-over). Another value is `ErrBadProfile` (500). `TrustEmails()` creates the address verified; use it only when the IdP verifies addresses in domains the customer owns. On PUT and PATCH the name follows, and a changed primary email replaces the identity with a new unverified one.

Deleting a SCIM user with an `externalId` leaves a tombstone; when the same connection creates a user with that `externalId` again, it gets the same library user (and its identity) back, reactivated, instead of a second account; if another source took the profile over meanwhile, the revival is 409.

`active: false` deactivates: when every SCIM user linked to a library user is inactive, the user's sessions end and the `scim_deactivated_at` column on `auth_user` refuses them until a connection sets `active: true` again: every later session lookup fails, and a new sign-in by any method is refused with `scim.deactivated` (403, `ErrDeactivated`) once the credential is proven, as admin refuses a banned user; a wrong credential still gets the ordinary answer, so the refusal tells a stranger nothing. Deleting the last SCIM user keeps the library user deactivated; `DeleteUsers()` deletes it instead. `ReconcileUser(fn)` is told the recomputed state (`UserID`, `Active`, `Sources`) inside the request's transaction, to mirror it into the app's own records. `p.ActiveUser(ctx, connectionID, externalID)` resolves the IdP's user id to the provisioned account while it is active, for an SSO sign-in that must never resolve by email (better-auth's `acquireActiveSCIMUserLink`).

## PATCH

`op` is `add`, `replace` or `remove` in any case (`replace` when missing); operations apply in order to a copy and the result is validated before anything is written, so a failing operation changes nothing. Paths: an attribute, `attr.sub`, `attr[type eq "work"]`, `attr[type eq "work"].sub`, `attr[primary eq true]…`, the core schema URN prefix, the enterprise URN and its attributes. A pathless `add`/`replace` takes an object of paths; inside the enterprise URN's object, `manager.value` names the sub-attribute as the path form does. A `replace` or `add` whose `type eq` filter matches nothing creates the entry (never primary), as Entra expects; other misses answer `noTarget`. `id`, `schemas`, `meta` and `manager.displayName` are read-only, and `userName` cannot be removed (`mutability`). `members` add skips values already present, `remove` with a value list removes those members, `members[value eq "…"]` removes one.

## Filters, paging, projection

`filter` is one to ten `attribute eq "value"` terms joined by `and`: users by `id`, `userName`, `externalId`, `emails.value`, `emails[type eq "work"].value`; groups by `id`, `displayName`, `externalId`. `userName`, emails and `displayName` compare ignoring case. Anything else is `invalidFilter`. `startIndex` is 1-based; `count` defaults to and is capped at 100. `attributes` or `excludedAttributes` (not both) project every answer, `id` and `schemas` always kept; giving both is `invalidValue` before anything is written, so a refused create leaves no user behind for the retry to collide with.

## Groups

`displayName` is required and unique per connection ignoring case, `externalId` unique; `members` are users of the same connection (type `User`; nested groups and other connections' users are refused), duplicates collapsed, at most 1,000. `AcceptEntraLegacyGroupSchema()` accepts Entra's legacy group schema marker once on `POST /Groups`. Groups map to nothing in the core: a `GroupMapper` receives `SyncGroup` with the group's full membership as library user ids after every change (including a member user's deletion), and `DeleteGroup`, inside the request's transaction, so an organization or role system follows the IdP. An error from it fails the request and the IdP retries. `ProjectRoles(RoleProjection{Map, Exists, Reconcile})` is better-auth's role projection: `Map` turns a group into roles, `Exists` drops roles the app does not know, one grant row per member and role is kept in `auth_scim_grant`, and `Reconcile` receives each affected user's full grant list and active state after every change, in the same transaction. `ReconcileProjection(ctx, domain)` replays every group of a provisioning domain's active connections into the mapper, 50 per transaction, after a mapper fix.

## Tables

`auth_scim_user` (`scu`), `auth_scim_group` (`scg`), `auth_scim_member` (`scm`), `auth_scim_tombstone` (`sct`), `auth_scim_grant` (`scx`), `auth_scim_connection` (`scn`), `auth_scim_credential` (`scr`) and `auth_scim_event` (`sce`), every row with its `connection_id`; unique keys are SHA-256 hashes of the compared forms so long values fit MySQL's key length. No foreign keys (ADR-0002): `UserTables` lists the `user_id` of `auth_scim_user`, `auth_scim_member`, `auth_scim_tombstone` and `auth_scim_grant`, so `DeleteUser` removes a user's SCIM rows. The plugin adds `scim_deactivated_at` to `auth_user`.

## Not built

nothing of better-auth's SCIM plugin beyond what it lists as unsupported itself. The Entra request shapes (capitalised ops, string booleans, a bare manager id, member add and remove by value list, the legacy group marker) are replayed by `TestSCIM_EntraValidatorSequence`; Microsoft's validator is a hosted tool run against a deployed, publicly reachable endpoint from an Entra tenant, so it is outside the library's test suite. Every list is filtered in SQL for `id`, `userName`, `externalId` and `displayName`, but email filters and paging run over the connection's matching users in memory, which suits directories of thousands, not millions.
