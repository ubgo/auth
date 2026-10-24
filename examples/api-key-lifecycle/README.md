# API key lifecycle: live and test keys, limits, verify, permissions

An orders API whose keys live a whole life. A person makes keys in settings under two configurations, `live` (`sk_live_…`) and `test` (`sk_test_…`, three requests a minute); lists them a page at a time; renames, pauses, resumes and revokes them. A provisioning job mints a key from Go with a monthly quota and permissions. A webhook receiver checks a key that arrived outside the `Authorization` header with `Verify`. A refund route asks for a permission, checked by a `plugin/access` control through the `accessapikey` adapter.

The guide is [docs/plugins/apikey.md](../../docs/plugins/apikey.md), Steps 5 to 10.

## Run it

```sh
cd examples
go run ./api-key-lifecycle
```

It creates `api-key-lifecycle.db` (SQLite) and listens on `http://localhost:8081`. Mail is printed to the log. Run the tests with `go test ./api-key-lifecycle`.

## Walkthrough

Sign up, then make a live key with metadata and a test key. The secret is shown once:

```sh
curl -s -c ck.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b ck.txt -X POST localhost:8081/auth/apikey/create -H 'Origin: http://localhost:8081' \
  -d '{"configId":"live","name":"importer","scopes":["orders:read"],"metadata":{"team":"ops"}}'
curl -s -b ck.txt -X POST localhost:8081/auth/apikey/create -H 'Origin: http://localhost:8081' \
  -d '{"configId":"test","name":"ci","scopes":["orders:read"]}'
```

```json
{"user":{"id":"usr_rynh7os2cbui6yk6c2w7cjwe","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"key":{"id":"key_3llc4pzb6c3qmkcy23bkjsa7","configId":"live","name":"importer","prefix":"sk_live_","hint":"sk_live_HkcH","scopes":["orders:read"],"createdAt":"2026-10-09T03:14:31.731803Z","lastUsedAt":null,"expiresAt":null,"disabled":false,"metadata":{"team":"ops"},"organizationId":"","permissions":null,"limits":{"rateMax":0,"rateWindowSeconds":0,"remaining":null,"refillAmount":0,"refillIntervalSeconds":0},"updatedAt":"2026-10-09T03:14:31.731803Z"},"secret":"sk_live_HkcH5tYQZaVpDembINb44tBK7o05mxwWidu6aDOYBxk"}
{"key":{"id":"key_batk7oaxxhtdk42f52p2k5mj","configId":"test","name":"ci","prefix":"sk_test_","hint":"sk_test_FXrZ","scopes":["orders:read"],"createdAt":"2026-10-09T03:14:31.742703Z","lastUsedAt":null,"expiresAt":null,"disabled":false,"metadata":null,"organizationId":"","permissions":null,"limits":{"rateMax":3,"rateWindowSeconds":60,"remaining":null,"refillAmount":0,"refillIntervalSeconds":0},"updatedAt":"2026-10-09T03:14:31.742703Z"},"secret":"sk_test_FXrZfoeJcn3oIbIFzQnRa6r5VSlMkW7eCIMhFWrZEic"}
```

The list pages and sorts; `total` counts every key:

```sh
curl -s -b ck.txt 'localhost:8081/auth/apikey/list?limit=1&sortBy=name'
```

```json
{"keys":[{"id":"key_batk7oaxxhtdk42f52p2k5mj","configId":"test","name":"ci","prefix":"sk_test_","hint":"sk_test_FXrZ","scopes":["orders:read"],"createdAt":"2026-10-09T03:14:31.742703Z","lastUsedAt":null,"expiresAt":null,"disabled":false,"metadata":null,"organizationId":"","permissions":null,"limits":{"rateMax":3,"rateWindowSeconds":60,"remaining":null,"refillAmount":0,"refillIntervalSeconds":0},"updatedAt":"2026-10-09T03:14:31.742703Z"}],"total":2,"limit":1,"offset":0}
```

The test key's fourth request in a minute is throttled:

```sh
for i in 1 2 3 4; do curl -s -i localhost:8081/api/orders -H "Authorization: Bearer $TEST_KEY" | grep -E '^HTTP|^Retry-After|^\{'; done
```

```text
HTTP/1.1 200 OK
{"userId":"usr_rynh7os2cbui6yk6c2w7cjwe","orders":[]}
HTTP/1.1 200 OK
{"userId":"usr_rynh7os2cbui6yk6c2w7cjwe","orders":[]}
HTTP/1.1 200 OK
{"userId":"usr_rynh7os2cbui6yk6c2w7cjwe","orders":[]}
HTTP/1.1 429 Too Many Requests
Retry-After: 60
{"error":{"code":"auth.rate_limited","message":"Too many attempts. Wait a moment and try again."}}
```

Pause the live key, and it is refused like an unknown one; resume it, and it works again:

```sh
curl -s -b ck.txt -X POST localhost:8081/auth/apikey/update -H 'Origin: http://localhost:8081' \
  -d '{"id":"key_3llc4pzb6c3qmkcy23bkjsa7","name":"importer (paused)","disabled":true}'
curl -s localhost:8081/api/orders -H "Authorization: Bearer $LIVE_KEY"
curl -s -b ck.txt -X POST localhost:8081/auth/apikey/update -H 'Origin: http://localhost:8081' \
  -d '{"id":"key_3llc4pzb6c3qmkcy23bkjsa7","disabled":false}' > /dev/null
curl -s localhost:8081/api/orders -H "Authorization: Bearer $LIVE_KEY"
```

```json
{"id":"key_3llc4pzb6c3qmkcy23bkjsa7","configId":"live","name":"importer (paused)","prefix":"sk_live_","hint":"sk_live_HkcH","scopes":["orders:read"],"createdAt":"2026-10-09T03:14:31.731803Z","lastUsedAt":null,"expiresAt":null,"disabled":true,"metadata":{"team":"ops"},"organizationId":"","permissions":null,"limits":{"rateMax":0,"rateWindowSeconds":0,"remaining":null,"refillAmount":0,"refillIntervalSeconds":0},"updatedAt":"2026-10-09T03:14:31.974177Z"}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"userId":"usr_rynh7os2cbui6yk6c2w7cjwe","orders":[]}
```

A key made in settings has no permissions, so the refund route refuses it; revoking ends it:

```sh
curl -s -X POST localhost:8081/api/refunds -H "Authorization: Bearer $LIVE_KEY"
curl -s -b ck.txt -X POST localhost:8081/auth/apikey/revoke -H 'Origin: http://localhost:8081' -d '{"id":"key_3llc4pzb6c3qmkcy23bkjsa7"}'
curl -s localhost:8081/api/orders -H "Authorization: Bearer $LIVE_KEY"
```

```json
{"error":{"code":"apikey.permission_denied","message":"This key does not allow this."}}
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

## What the tests prove

| Test | What it checks |
|---|---|
| `TestLifecycle_ListRenamePauseRevoke` | Live and test prefixes, metadata, an unknown `configId` refused, paging and filtering the list, pause and resume, revoke, a revoked key's `get` is 404 |
| `TestLifecycle_TestKeysAreThrottled` | A test key's request past three a minute is 429 with `Retry-After` |
| `TestLifecycle_ProvisionedKeyHasAQuota` | A key from `provisionKey` (`CreateFor`) with a quota of two answers `apikey.usage_exceeded` on the third use |
| `TestLifecycle_VerifyAKeyFromElsewhere` | `checkWebhookKey` returns the owner, `apikey.ErrScopeMissing` for a key without the scope, `auth.ErrSignedOut` for a revoked one |
| `TestLifecycle_PermissionsAndARemovedAction` | A provisioned key may refund, a settings key may not; after the app removes `refund` from its statements the old key is refused until `SetPermissions` gives it permissions from the new vocabulary, and an undeclared action is `apikey.ErrBadPermissions` |
