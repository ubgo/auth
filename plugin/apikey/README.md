# github.com/ubgo/auth/plugin/apikey

Gives users long-lived keys with scopes for scripts and integrations, sent as `Authorization: Bearer ubk_...` in place of a session, and checked by the app's own routes; each key can be renamed, paused, re-expired, labelled with metadata, rate-limited and given a usage quota.

## Install

```sh
go get github.com/ubgo/auth
```

The package is part of the core module `github.com/ubgo/auth` and adds no dependency beyond the core's own (`github.com/ubgo/sqlb`, `golang.org/x/crypto`).

## Wire it

From [examples/api-keys-and-jwt](../../examples/api-keys-and-jwt/main.go):

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
		apikey.New(apikey.Scopes("orders:read", "orders:write")),
	),
)

forKeys := func(scope string, h http.HandlerFunc) http.Handler {
	return authhttp.Middleware(a)(authhttp.RequireUser(authhttp.RequireScope(scope)(h)))
}
mux.Handle("/auth/", authhttp.Handler(a, authhttp.Prefix("/auth")))
mux.Handle("GET /api/orders", forKeys("orders:read", o.list))
```

The plugin needs a sign-in method (any plugin such as `password`): keys are created by a signed-in user. In app code, `auth.HasScope(ctx, scope)` and `auth.CurrentScopes(ctx)` read the key's scopes; `authhttp.RequireScope` answers 403 to a browser session or a key without the scope.

`auth.New` fails when:

| Condition | Error |
|---|---|
| Neither `Scopes` nor `WithPermissions` was passed | `ErrNoScopes`: "apikey: declare what a key may carry: scopes with apikey.Scopes, permissions with apikey.WithPermissions, or both" |
| A declared scope is empty or contains a space, tab or newline | `ErrBadScope`: "apikey: a scope is non-empty and contains no whitespace" |
| The prefix is shorter than 3 characters ([`minPrefixLength`](ds:block?id=minprefixlength-x27y46d2)) or does not end with `_` | `ErrBadPrefix`: "apikey: a prefix is at least three characters and ends with _" |
| `MaxKeys` or `NameLength` is below 1, `NameBounds` has a negative bound, a maximum below the minimum or a minimum with no maximum, `HintLength` is negative or above [`maxHintLength`](ds:block?id=maxhintlength-f3kq8wrn) (8), or `WithExpiry` has a negative field, a minimum above the maximum, or a default outside the bounds | `ErrBadLimits`: "apikey: limits are positive and the expiry default lies within its bounds" |
| `DefaultLimits` pairs `RateMax` without `RateWindow` or `RefillAmount` without `RefillInterval`, or holds a negative value | `ErrBadLimits` wrapping `ErrBadLimitsValue` |
| Another token resolver's prefix overlaps this one | `auth.ErrBadOperation` |

## Options

| Option | What it does | Default |
|---|---|---|
| `Scopes(scopes ...string)` | Every scope a key may carry; a request for another is refused | none (required unless `WithPermissions` is set) |
| `Prefix(prefix string)` | The start of every key, so secret scanners recognize a leaked one and the core routes it here | [`DefaultPrefix`](ds:block?id=defaultprefix-rgykkrgm) (`ubk_`) |
| `MaxKeys(n int)` | Keys one account may hold; the next create is `ErrTooMany` | `MaxKeysPerUser` (50) |
| `RequireName()` | A create without a name is `ErrNameRequired` | off: names are optional |
| `NameLength(runes int)` | Names longer than this are cut, not refused | 64 (`maxNameLength`) |
| `NameBounds(min, max int)` | A name shorter than `min` or longer than `max` runes is refused (`ErrBadName`) at create and rename, instead of being cut | off: names are cut to `NameLength` |
| `HintLength(n int)` | How many characters after the prefix the hint keeps, at most 8; 0 keeps the prefix alone | 4 ([`hintExtra`](ds:block?id=hintextra-tm73uvqy)) |
| `Generate(fn func() string)` | Replaces the random part of a new key (after the prefix) with `fn`'s result, for a particular alphabet or length; at least [22](ds:block?id=minsecretlength-t7mx2bqz) characters (128 bits) or the create fails with `ErrShortSecret` | `auth.NewToken`: 32 random bytes, base64url |
| `WithExpiry(Expiry{MinDays, MaxDays, DefaultDays})` | Bounds and defaults `expiresInDays`, and bounds `expiresIn` (seconds) measured in days: outside the bounds is `ErrExpiryOutOfRange`; with `MaxDays` set, "never" (0) is refused too; `DefaultDays` fills an empty request | no bounds, no default, 0 means never |
| `AllowMetadata()` | Create and update may store a JSON object of at most [`maxMetadataLength`](ds:block?id=maxmetadatalength-n7rc2hwq) (4096) bytes with each key, returned in `Key.Metadata` | off: metadata in a request is `ErrMetadataDisabled` |
| `DefaultLimits(Limits{...})` | The rate limit and quota every key made through the create operation gets; `CreateFor` and `SetLimits` set them per key from Go | none |
| [`Configuration(id, opts...)`](ds:block?id=configuration-x4kd8pwz) | A key configuration beside the default one (such as `live` with `Prefix("sk_live_")` and `test` with `Prefix("sk_test_")`): its own prefix, scopes, limits, expiry and name rules, sharing the one table through the `config_id` column. It starts from the plugin's options and applies `opts` on top (`Scopes` adds to the inherited list). An id is at most [32](ds:block?id=maxconfigidlength-h2rn6xwk) letters, digits, `_` or `-`, unique and not `default` (`ErrBadConfig`). Requests name it with `configId`; none means [`DefaultConfig`](ds:block?id=defaultconfig-q8wv3mzt) (`default`); an unknown one is `ErrUnknownConfig` (better-auth falls back to the default instead) | the default configuration only |
| [`AllowKeyPrefix(max)`](ds:block?id=allowkeyprefix-r7mw2kqd) | A create may send `prefix`, up to `max` letters, digits, `_` or `-` (0 means [32](ds:block?id=maxkeyprefixlength-c5tq9vbn)), placed after the configuration's prefix, which stays first because it routes the key | off: a `prefix` in a create is `ErrBadKeyPrefix` |
| [`DefaultScopes(scopes...)`](ds:block?id=defaultscopes-v3nb8xtp), `DefaultScopesFunc(fn)` | The scopes of a key created without a `scopes` field (an explicit empty list stays empty); the function form decides per user, and an undeclared scope it returns fails the create with `ErrUnknownScope` | none |
| [`PreCheck(fn)`](ds:block?id=precheck-k6zp4wnd) | `fn(ctx, key) bool` runs before the database lookup; false refuses the key like an unknown one. `fn` sees the whole key and must never log it | none |
| [`DeleteSpentKeys()`](ds:block?id=deletespentkeys-b9xq5mrv) | An expired key, or an exhausted key with no refill, is deleted when next presented (still refused the same way) | off: the row stays until `auth.Sweep` |
| [`DistinctErrors()`](ds:block?id=distincterrors-m3wt9xhv) (plugin-wide) | A refused key answers its own 401 code (`apikey.key_disabled`, `apikey.key_expired`, `apikey.invalid_owner`, `apikey.owner_blocked`; `apikey.invalid_key` from `Verify`). Risk: whoever holds a stolen key learns its state, and a refused key fails even a route that serves anonymous callers | off: all are `auth.signed_out` |
| [`RejectUnknownKeys()`](ds:block?id=apikey-rejectunknownkeys-p3r2kq7w) (plugin-wide) | A bearer token with a key prefix that is no live key answers `401 apikey.invalid_key` (better-auth's `INVALID_API_KEY`) on every route instead of passing through signed out; without `DistinctErrors` every refusal, a banned owner's included, is that same code. `auth.New` refuses it (`ErrPrefixNotDistinct`) unless every configuration's prefix holds a character outside base64url, such as `sk.live_`, so no core session token (base64url) can start with a prefix and be refused as a key. Cost: a bad key fails even a route that serves anonymous callers | off: an unknown key passes through to the sessions |
| [`WithCache(c, ttl)`](ds:block?id=withcache-p2hm6wtv) (plugin-wide) | Puts a [`Cache`](ds:block?id=cache-n5vq2xkr) (`NewMemoryCache()`, or any shared store) in front of the key lookup for `ttl` (0 is [1 minute](ds:block?id=defaultcachettl-w8kc3nzq), at most [15](ds:block?id=maxcachettl-j4rx7mbs)). Revoke, update and `SetLimits` drop the entry; limits still run as guarded writes. A key revoked on another instance with an in-process cache keeps working until its entry expires | no cache |
| [`OrganizationOwned()`](ds:block?id=organizationowned-b8rn3vqd) | The configuration's keys belong to an organization, not a user (better-auth's `references: "organization"`). A create names it with `organizationId`; create, list/get, update and revoke need the caller's organization role to grant `apiKey` `create`, `read`, `update` or `delete`, and the organization's creator role passes every one. The resource is [`ResourceAPIKey`](ds:block?id=resourceapikey-w4kq7rzn) (`apiKey`), and `Statements()` is its vocabulary to merge into the organization's access control. Such a key never signs anyone in: a bearer request with it is signed out (`apikey.organization_key` under `DistinctErrors`) before its counters move; the app checks it with `Verify`, which reports `Verification.OrganizationID`. Its prefix may not overlap a user-owned configuration's (`ErrBadConfig`), and it needs `WithOrganizations` (`ErrOrganizationsRequired` from `auth.New`) | off: keys belong to users |
| [`WithOrganizations(o)`](ds:block?id=withorganizations-j5tm2xcv) (plugin-wide) | How the plugin asks an organization about a member: `o.APIKeyPermission(ctx, orgID, userID, action) (member, allowed bool, err error)`. The core cannot import `plugin/organization` (its own module), so it asks through this interface: `*organization.Plugin` implements it, and an app with organizations of its own writes the method or uses `OrganizationsFunc` | none |
| [`WithPermissions(c)`](ds:block?id=withpermissions-y2hd6kfm) | A key may carry permissions, a resource-to-actions set (`apikey.Permissions`, better-auth's permission object) checked by the `apikey.PermissionChecker` `c` (`Check`, `Grants`; a failed `Check` is `ErrBadPermissions`). The built-in checker is `apikey.Vocabulary{"orders": {"read", "write"}}`; `accessapikey.New(ac)` from the `plugin/access` module uses an access control instead, and an app may plug in its own model. Set from Go only (`CreateRequest.Permissions`, which JSON never fills, `CreateFor`, `SetPermissions`), as better-auth makes them a server-only property; checked with `VerifyPermissions` or `Authorize`. A key whose stored permissions name something the checker no longer declares is refused every check (its stored permissions fail `Check`); called directly, `Vocabulary.Grants` ignores such a held entry and denies a check that names it. Scopes stay beside them | off: a permission on a key is `ErrPermissionsOff` |
| `DefaultPermissions(perms)`, `DefaultPermissionsFunc(fn)` | The permissions of a key created without any; the function form decides per owner (the user id, or the organization id of an organization key). `DefaultPermissions(nil)` inside a `Configuration` clears the inherited default | none |
| [`DeferUpdates()`](ds:block?id=deferupdates-y5gn3kdt) (plugin-wide) | The `last_used_at`/`updated_at` stamp and `DeleteSpentKeys`' delete run through the core's background runner after the check; the rate-limit and quota writes never do | off: done on the request |
| [`StampEveryUse()`](ds:block?id=stampeveryuse-p3tk8wqe) (plugin-wide) | Every use writes `last_used_at` and `updated_at` with a write guarded on the key's id, on the request (never deferred): a key deleted while its request was checked is refused like an unknown one and its cache entry dropped, even a key without limits; a failing write fails the request. better-auth's verify stamping `updatedAt` every call | `last_used_at` at most once a minute, a failure only logged, no write for a key without limits |

`Limits` is the per-key rate limit and quota: `RateMax` requests per `RateWindow` (a fixed window counted from the first request after the previous window ended), and `Remaining` uses (nil for unlimited) reset to `RefillAmount` every `RefillInterval` since the last refill or creation. `RateMax` pairs with `RateWindow` and `RefillAmount` with `RefillInterval`; windows and intervals are whole seconds; on the wire they are `rateWindowSeconds` and `refillIntervalSeconds`. The zero value is no limit, which every key made before migration `0002` has.

## Routes and Go API

Paths are under the mount prefix (`/auth` in the example). A Query is served as GET, a Mutation as POST.

| Route | Go API | Requirement | Rate limit |
|---|---|---|---|
| `POST /apikey/create` `{"configId","name","scopes","prefix","expiresInDays","expiresIn","metadata","organizationId"}` (`expiresIn` in seconds, better-auth's unit, or `expiresInDays`, not both) (`organizationId` only under an `OrganizationOwned` configuration, where it is required) | `(*Plugin).Create(ctx, CreateRequest) (CreateResult, error)` | FreshSignIn | none |
| `GET /apikey/list?configId=live&organizationId=org_…&limit=20&offset=40&sortBy=name&sort=desc` (each optional; `organizationId` lists that organization's keys, needing `apiKey` `read` there, and the caller's own list never shows an organization's keys) | `(*Plugin).List(ctx) ([]Key, error)` for the whole list oldest first; [`(*Plugin).ListKeys(ctx, ListRequest)`](ds:block?id=plugin-listkeys-c4vt9nzk) for a page: [`ListRequest`](ds:block?id=listrequest-h6wn3kqt) (`limit`, `offset`, `sortBy` one of `createdAt`, `name`, `lastUsedAt`, `expiresAt`, `sort` `asc` or `desc`) answers [`ListResult`](ds:block?id=listresult-m8pq4xrw) `{"keys","total","limit","offset"}`; a bad value is `ErrBadList` | SignedIn | none |
| `GET /apikey/get?id=key_…&configId=…` (`configId` optional; another configuration's key is `ErrNotFound`) | [`(*Plugin).Get(ctx, id) (Key, error)`](ds:block?id=plugin-get-r2mk7xqw); another user's key or an unknown id is `ErrNotFound` | SignedIn | none |
| `POST /apikey/revoke` `{"id","configId"}` | `(*Plugin).Revoke(ctx, id) error` | SignedIn | none |
| `POST /apikey/update` `{"id","configId","name","expiresInDays","expiresIn","disabled","metadata","scopes"}` (each optional; `scopes` replaces the key's scopes, an empty list clears them; the key's own configuration's rules apply) | `(*Plugin).Update(ctx, UpdateRequest) (Key, error)` | FreshSignIn | none |
| Go only | `(*Plugin).CreateFor(ctx, userID, CreateRequest, Limits)`: a key for any user, no session needed, metadata accepted without `AllowMetadata` | none (app code) | none |
| Go only | `(*Plugin).SetLimits(ctx, id, Limits)`: replaces a key's limits and resets its counters; a refillable quota with no `Remaining` starts at `RefillAmount` (here, in `CreateFor` and in `DefaultLimits`) | none (app code) | none |
| Go only | [`(*Plugin).Verify(ctx, secret, scopes...)`](ds:block?id=plugin-verify-w6nq8xkr): checks a key received outside the `Authorization` header (a webhook signature, a websocket message) through the core's own resolution, counting the use against its limits, and answers a [`Verification`](ds:block?id=verification-k9zr4wtm) `{Valid, Reason, Key, UserID, OrganizationID}` (`OrganizationID` set, `UserID` empty, for an organization-owned key); `Reason` is `auth.ErrSignedOut`, `auth.ErrRateLimited`, `ErrUsageExceeded` or `ErrScopeMissing` (or a `DistinctErrors` code), and the error return is only an infrastructure failure | none (app code) | none |
| Go only | [`(*Plugin).VerifyFor(ctx, configID, secret, scopes...)`](ds:block?id=plugin-verifyfor-n4dk7wqs): `Verify` for one configuration; a key of another is refused before its counters move, an unknown configuration is `Reason` `ErrUnknownConfig` | none (app code) | none |
| Go only | [`(*Plugin).VerifyPermissions(ctx, secret, perms)`](ds:block?id=plugin-verifypermissions-m2xb7rqc): `Verify` that also requires the key's permissions to grant every action of `perms` (`Reason` `ErrPermissionDenied` otherwise, including a key with none) | none (app code) | none |
| Go only | [`(*Plugin).Authorize(ctx, perms)`](ds:block?id=plugin-authorize-t5kd2wny): the current request's key must grant `perms`; `ErrPermissionDenied` otherwise or for a request made without a key. Guard a route with `authhttp.RequireFunc(func(r) error { return ak.Authorize(r.Context(), perms) })` | none (app code) | none |
| Go only | [`(*Plugin).SetPermissions(ctx, id, perms)`](ds:block?id=plugin-setpermissions-u6pn9wbt): replaces a key's permissions (nil clears them) and drops its cache entry | none (app code) | none |
| Go only | [`(*Plugin).DeleteOrganizationKeys(ctx, orgID)`](ds:block?id=plugin-deleteorganizationkeys-c9vf4hxs): deletes an organization's keys and their cache entries; call it from `organization.Hooks.AfterDeleteOrg`, since no foreign key does | none (app code) | none |
| Any app route, `Authorization: Bearer <key>` | `(*Plugin).ResolveToken(ctx, token)`, called by the core | none | none |

Update changes only the fields present (`ErrNoChanges` when none is); `expiresInDays` and `expiresIn` follow the create rules, `disabled: true` pauses the key (refused like an unknown one until `disabled: false`), and `metadata` replaces the object. On resolve, after the hash lookup and the expiry and disabled checks, the key's limits are enforced with guarded UPDATEs run outside the caller's transaction, so a burst never exceeds `RateMax` and `Remaining` never goes below zero; a refill is a compare-and-swap on `last_refill_at`, so one request resets the count and the others spend from it. The plugin is an `auth.Sweeper`: `auth.Sweep` (and `auth sweep` from authcli) deletes keys past their expiry, which were already refused on use. All four operations refuse a request made with a key (`auth.ErrAPIKeyRefused`): a script cannot mint, list or revoke keys, change the password or read the session list. List returns keys oldest first, and keys made in the same instant in id order, so every engine returns the same order. `CreateResult.Secret` is the key, shown this once. `ExpiresInDays` 0 means the key never expires, unless `WithExpiry` sets a default or a maximum. The name is cut to 64 runes ([`maxNameLength`](ds:block?id=maxnamelength-89a3u4k8)); repeated scopes are stored once, sorted. An account holds at most [`MaxKeysPerUser`](ds:block?id=maxkeysperuser-fkhrbvpa) (50) keys. `last_used_at` is written at most once per [`usedEvery`](ds:block?id=usedevery-h6p3zwfn) (1 minute) per key, or on every use under `StampEveryUse`.

## Tables and columns

The plugin owns `auth_api_key` ([`TableNameKey`](ds:block?id=tablenamekey-4q22c5ze), alias `ak`), created by migration `0001_api_key` (owner `apikey`):

| Column | Constant | Meaning |
|---|---|---|
| `id` | [`ColID`](ds:block?id=colid-wve5u4tk) | Primary key, `key_...` |
| `user_id` | [`ColUserID`](ds:block?id=coluserid-d85t7bwn) | Owner; deleted with the user by `a.DeleteUser` (declared in `UserTables`; no foreign key) |
| `name` | [`ColName`](ds:block?id=colname-buussu3v) | The owner's label |
| `hint` | [`ColHint`](ds:block?id=colhint-685gvhrx) | The prefix plus 4 characters ([`hintExtra`](ds:block?id=hintextra-tm73uvqy); `HintLength` changes it, 0 to 8), shown in lists; never enough to use |
| `key_hash` | [`ColKeyHash`](ds:block?id=colkeyhash-n9ne59xk) | SHA-256 of the key, UNIQUE; the key itself is never stored |
| `scopes` | [`ColScopes`](ds:block?id=colscopes-nuk5dts4) | Scopes joined by a space |
| `created_at` | [`ColCreatedAt`](ds:block?id=colcreatedat-kav6jpyq) | When created |
| `last_used_at` | [`ColLastUsedAt`](ds:block?id=collastusedat-5b23p9ng) | Last use, NULL until first use |
| `expires_at` | [`ColExpiresAt`](ds:block?id=colexpiresat-hf6aw2fc) | Expiry, NULL for never |
| `disabled_at` | [`ColDisabledAt`](ds:block?id=coldisabledat-y7kp3qvn) | When the owner paused the key; NULL while enabled (migration `0002_api_key_limits`) |
| `metadata` | [`ColMetadata`](ds:block?id=colmetadata-d4xw8mrt) | The owner's JSON object, NULL when none |
| `rate_max`, `rate_window_seconds` | [`ColRateMax`](ds:block?id=colratemax-b2nq6ksj), [`ColRateWindow`](ds:block?id=colratewindow-g9tc5lvz) | The per-key rate limit; 0 means none |
| `rate_count`, `rate_window_start` | [`ColRateCount`](ds:block?id=colratecount-m3fh7wpd), [`ColRateWindowStart`](ds:block?id=colratewindowstart-r6jd2bxn) | The current window's counter and start (NULL before the first request) |
| `remaining` | [`ColRemaining`](ds:block?id=colremaining-k8sv4czq) | Uses left; NULL means unlimited |
| `refill_amount`, `refill_interval_seconds`, `last_refill_at` | [`ColRefillAmount`](ds:block?id=colrefillamount-p5wm9tyh), [`ColRefillInterval`](ds:block?id=colrefillinterval-x2bk7nqs), [`ColLastRefillAt`](ds:block?id=collastrefillat-v4gz8mcj) | The refill rule and when it last ran (NULL means the clock started at `created_at`) |
| `config_id` | [`ColConfigID`](ds:block?id=colconfigid-f6np2qwd) | The key's configuration; `default` for rows made before migration `0003_api_key_config` |
| `prefix` | [`ColPrefix`](ds:block?id=colprefix-z3hk8vmt) | The key's full prefix in clear (the configuration's, then its own under `AllowKeyPrefix`); NULL before `0003` |
| `updated_at` | [`ColUpdatedAt`](ds:block?id=colupdatedat-u7cy4rbn) | When the key last changed: create, update, `SetLimits`, a counter write, or the once-a-minute use stamp; NULL before `0003` |
| `organization_id` | [`ColOrganizationID`](ds:block?id=colorganizationid-q3vx8nkt) | The owning organization of an organization-owned key, whose `user_id` is then `""`, so no user-side query and no `DeleteUser` ever reaches it; NULL for a user's key (migration `0004_api_key_org`) |
| `permissions` | [`ColPermissions`](ds:block?id=colpermissions-h7cw4mzp) | The key's permissions as a JSON object of resource to actions, NULL for none (`0004`) |

Index `auth_api_key_user_idx` on `user_id`, `auth_api_key_config_idx` on `config_id`, and `auth_api_key_org_idx` on `organization_id`. Typed columns are exported as `KeyID`, `KeyUserID`, and so on. These columns are not in the core's stable-column contract (`stability_test.go` covers `auth_user`, `auth_identity` and `auth_session` only), so treat them as readable but not frozen across minor versions.

## Errors

| Variable | Code | HTTP | When |
|---|---|---|---|
| `ErrUnknownScope` | `apikey.unknown_scope` | 400 | Create or update asked for a scope not declared with `Scopes` |
| `ErrTooMany` | `apikey.too_many` | 409 | The account already holds [`MaxKeysPerUser`](ds:block?id=maxkeysperuser-fkhrbvpa) keys (50) |
| `ErrNotFound` | `apikey.not_found` | 404 | Revoke, update or get of an unknown key or of another user's key (the same answer, so ids cannot be probed) |
| `ErrNameRequired` | `apikey.name_required` | 400 | `RequireName` is set and the name is blank |
| `ErrExpiryOutOfRange` | `apikey.expiry_out_of_range` | 400 | `expiresInDays` or `expiresIn` is negative, outside `WithExpiry`'s bounds (seconds compared as a duration of days), longer than a `time.Duration` holds (about 292 years), or 0 while `MaxDays` is set |
| `ErrExpiryConflict` | `apikey.expiry_conflict` | 400 | A create or update with both `expiresIn` and `expiresInDays` |
| `ErrNoChanges` | `apikey.no_changes` | 400 | An update with no field set |
| `ErrBadList` | `apikey.bad_list` | 400 | A list with a `limit` or `offset` that is not a non-negative integer, an unknown `sortBy` or `sort` |
| `ErrBadName` | `apikey.bad_name` | 400 | `NameBounds` is set and the name is outside them, at create or rename |
| `ErrScopeMissing` | `apikey.missing_scope` | 403 | `Verify` was asked for a scope the key lacks (Go only; never answered to a client by this plugin) |
| `ErrShortSecret` | none; answered over HTTP as `auth.internal` | 500 | `Generate` returned fewer than 22 characters; an app bug |
| `ErrMetadataDisabled` | `apikey.metadata_disabled` | 400 | Metadata in a create or update without `AllowMetadata` |
| `ErrBadMetadata` | `apikey.bad_metadata` | 400 | Metadata that is not a JSON object or is over 4096 bytes |
| `auth.ErrRateLimited` (via `auth.RateLimitedFor`) | `auth.rate_limited` | 429 | A request with a key past `RateMax` in the current window; `Retry-After` says when the window ends |
| `ErrUsageExceeded` | `apikey.usage_exceeded` | 429 | A request with a key whose `Remaining` is zero and no refill due |
| `ErrBadLimitsValue` | none | none | `CreateFor` or `SetLimits` with limits that break the pairing rules; wrapped in `ErrBadLimits` from `auth.New` for `DefaultLimits` |
| `ErrUnknownConfig` | `apikey.unknown_config` | 400 | A request (or `CreateFor`, `VerifyFor`) naming a configuration that does not exist |
| `ErrBadKeyPrefix` | `apikey.bad_prefix` | 400 | A create's `prefix` without `AllowKeyPrefix`, longer than its bound, or with other characters than letters, digits, `_` and `-` |
| `ErrInvalidKey` | `apikey.invalid_key` | 401 | `DistinctErrors`: `Verify` of an unknown key, one refused by `PreCheck`, or one of another configuration than `VerifyFor` named. `RejectUnknownKeys`: also a bearer token with the key prefix that is no live key, on every route (and every refusal, without `DistinctErrors`) |
| `ErrKeyDisabled` | `apikey.key_disabled` | 401 | `DistinctErrors` only: a paused key |
| `ErrKeyExpired` | `apikey.key_expired` | 401 | `DistinctErrors` only: a key past its expiry |
| `ErrKeyOwnerGone` | `apikey.invalid_owner` | 401 | `DistinctErrors` only: a key whose user no longer exists |
| `ErrOwnerBlocked` | `apikey.owner_blocked` | 401 | `DistinctErrors` only: a key whose user exists but may not sign in (banned, or refused by an app's `SessionChecker`); better-auth's `USER_BANNED` |
| `ErrOrganizationIDRequired` | `apikey.organization_id_required` | 400 | A create under an `OrganizationOwned` configuration without `organizationId` |
| `ErrNotOrganizationConfig` | `apikey.not_organization_config` | 400 | A create naming an organization under a configuration whose keys belong to users |
| `ErrNotOrganizationMember` | `apikey.not_organization_member` | 403 | A create or list naming an organization the caller is not a member of. Get, update and revoke of such an organization's key answer `ErrNotFound` instead, so a key id cannot be probed |
| `ErrOrganizationPermission` | `apikey.organization_permission` | 403 | A member whose role does not grant the `apiKey` action asked for |
| `ErrOrganizationKey` | `apikey.organization_key` | 401 | `DistinctErrors` only: an organization-owned key presented as a bearer credential |
| `ErrPermissionsOff` | `apikey.permissions_off` | 400 | Permissions on a key of a configuration without `WithPermissions` |
| `ErrBadPermissions` | `apikey.bad_permissions` | 400 | Permissions naming a resource or action `WithPermissions` does not declare; from `auth.New` for `DefaultPermissions` |
| `ErrPermissionDenied` | `apikey.permission_denied` | 403 | `VerifyPermissions` or `Authorize` asked for what the key's permissions do not grant (Go only) |
| `ErrNoScopes`, `ErrBadScope`, `ErrBadPrefix`, `ErrBadLimits`, `ErrBadConfig`, `ErrBadCacheTTL`, `ErrOrganizationsRequired` | none | none | Configuration, returned by `auth.New` |

By default an unknown, revoked, expired or disabled key, or one belonging to a banned user, is simply signed out: `auth.ErrSignedOut` (401) on routes that need a user. Under `DistinctErrors` the disabled, expired and ownerless cases answer their own code instead; an unknown key over HTTP still leaves the request signed out, because a session token may start with a key prefix by chance and is then looked up as a session. `RejectUnknownKeys` answers it `apikey.invalid_key` instead, once every prefix holds a character no session token has.

## Security notes

| Property | Pinned by |
|---|---|
| A key acts in app routes with its scopes, and every auth operation refuses it | `TestAPIKey_ActsInAppRoutesNotInAuthOperations` |
| A key sent in the session cookie is not trusted | `TestAPIKey_ActsInAppRoutesNotInAuthOperations` |
| Banning a user stops their keys; revoked and expired keys are refused | `TestAPIKey_ActsInAppRoutesNotInAuthOperations`, `TestTokensAPIKey_Lifecycle` |
| Another user's key cannot be revoked, and looks unknown | `TestTokensAPIKey_Lifecycle` |
| Overlapping token prefixes are refused at wiring | `TestNew_RefusesOverlappingTokenPrefixes` |
| A failed `last_used_at` write signs nobody out and is logged | `TestTokensAPIKey_RecordUseFailureIsOnlyLogged` |
| An Auth without a database reports `auth.ErrNoDatabase` instead of panicking | `TestNoDatabase_ReportsInsteadOfPanicking` |
| Only the key's SHA-256 and a short hint are stored: no column of `auth_api_key` holds the key or its random part | `TestTokensAPIKey_OnlyTheHashIsStored` |
| Every database failure on create, list, revoke and resolve reaches the caller | `TestTokensAPIKey_Faults` |
| A paused key is refused like an unknown one; another user's key cannot be updated | `TestTokensAPIKey_Update` |
| A burst of requests never exceeds `RateMax`, and `Remaining` never goes below zero, on Postgres and MySQL | `TestTokensAPIKey_LimitsHoldUnderConcurrency` |
| The window reopens, the quota refills once per interval, and a non-refilling key runs out | `TestTokensAPIKey_RateLimitAndQuota` |
| `Get` and the list page never show another user's key, and the total counts only the caller's | `TestTokensAPIKey_GetAndListPaging` |
| `Verify` refuses an unknown, foreign-prefix, disabled, rate-limited or exhausted key and a missing scope with the same reasons a bearer request gets, and counts the use | `TestTokensAPIKey_Verify` |
| New scopes take effect on the next request; a short `Generate` result mints nothing; a refillable quota starts full | `TestTokensAPIKey_ScopesNamesHintAndGenerator` |
| Every database failure on get, a list page, a scope update and `Verify` reaches the caller | `TestTokensAPIKey_Round3Faults` |
| Every database failure on update, `CreateFor`, `SetLimits` and each counter write reaches the caller | `TestTokensAPIKey_LimitFaults` |
| Configurations keep their own prefix, scopes, cap and limits in one table; `VerifyFor` refuses another configuration's key without spending its quota | `TestTokensAPIKey_Configurations` |
| `DistinctErrors` names each refusal on `Verify` and on the wire; without it every refusal stays `auth.signed_out` and an open route serves the caller anonymously | `TestTokensAPIKey_PreCheckAndDistinctErrors`, `TestTokensAPIKey_DefaultStaysSilent` |
| A cache hit spares the lookup, revoke and update drop the entry at once, the limits hold through stale cached counters, and a key deleted under a cached entry is refused rather than counted | `TestTokensAPIKey_Cache` |
| `DeleteSpentKeys` deletes only keys that can never work again; without it they stay listed | `TestTokensAPIKey_DeleteSpentKeys`, `TestTokensAPIKey_DefaultKeepsSpentKeys` |
| Every database failure on the round-6 paths reaches the caller, except the logged stamp and delete | `TestTokensAPIKey_Round6Faults` |

Limits, honestly: the database keeps a fast SHA-256 of the key rather than a slow password hash, which is safe because a key carries 256 random bits. The library carries scopes but never enforces them: each app route must check `auth.HasScope` or use `authhttp.RequireScope`. The key operations have no rate limit of their own; the per-account cap bounds creation. A per-key rate limit costs one or two UPDATEs per request on top of the lookup; a key with no limits writes nothing but the once-a-minute `last_used_at`. Organization-owned keys never act as a user: they are for `Verify`, as in better-auth. Permissions are checked only where the app calls `VerifyPermissions` or `Authorize`, exactly as scopes are checked only where it calls `auth.HasScope`. With `WithCache`, revocation is immediate only on the instance that revoked (or everywhere with a shared store); elsewhere it waits for the TTL.

## Example

- [examples/api-keys-and-jwt](../../examples/api-keys-and-jwt/): a scoped orders API called with keys.
- API reference: https://pkg.go.dev/github.com/ubgo/auth/plugin/apikey
