# JWT keys: rotation, a remote key set, RSA, and tokens without a session

An app whose JWT signing key changes every day by itself, and a second program, the report service, that verifies the app's tokens by fetching its key set over HTTP and follows each rotation without a deploy. The app also publishes an RSA key beside the rotating Ed25519 one and mints an RS256 token for a nightly job, with no session behind it, for a consumer that accepts RSA only.

The guide is [docs/plugins/jwt.md](../../docs/plugins/jwt.md), Steps 6, 8, 9 and 10; verifying elsewhere is [docs/integrations/other-services.md](../../docs/integrations/other-services.md).

## Run it

```sh
cd examples
go run ./jwt-keys
```

It creates `jwt-keys.db` (SQLite), serves the app on `http://localhost:8081` and the report service on `http://localhost:8082`, and logs the nightly job's token. Set `JWT_ROTATION_SEED` to 32 bytes, base64url without padding, so every instance and every restart derives the same keys; unset, a seed is made for the run and the log says so. The RSA key is generated at start; load yours from a secret store. Run the tests with `go test ./jwt-keys`.

```text
2026/10/09 08:44:50 JWT_ROTATION_SEED is not set: using a seed for this run only
2026/10/09 08:44:50 app listening on http://localhost:8081
2026/10/09 08:44:50 nightly job token (RS256, no session): eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjE1Nm56LVJSajlUbkpsWEcifQ.…
2026/10/09 08:44:50 report service listening on http://localhost:8082, keys from /auth/jwt/jwks
```

## Walkthrough

Sign up, take a token, and look at the key set: the rotating key first, the RSA key after it.

```sh
curl -s -c ck.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}' > /dev/null
curl -s -b ck.txt -X POST localhost:8081/auth/jwt/token -H 'Origin: http://localhost:8081'
curl -s localhost:8081/auth/jwt/jwks | python3 -c 'import json,sys; [print(k["kty"],k["alg"],k["kid"]) for k in json.load(sys.stdin)["keys"]]'
```

```text
{"token":"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6InNScWdKd3E5eHlja1l3X2wifQ.…","expiresAt":"2026-10-09T03:19:52.013248Z"}
OKP EdDSA sRqgJwq9xyckYw_l
RSA RS256 156nz-RRj9TnJlXG
```

The report service started with no key; its first request fetched the set. A session token names its session, the job token names none and carries its role:

```sh
curl -s localhost:8082/report -H "Authorization: Bearer $JWT"
curl -s localhost:8082/report -H "Authorization: Bearer $JOB_TOKEN"
curl -s localhost:8082/report
```

```json
{"subject":"usr_epa5gyhu4kmqbchbpnwnuhsn","sessionId":"ses_fecqp7ib3s5mydazgvljdaq3"}
{"subject":"job:nightly-export","sessionId":"","role":"worker"}
{"error":"no token"}
```

A rotation cannot be shown live without waiting a day; the tests move a clock instead.

## What the tests prove

| Test | What it checks |
|---|---|
| `TestRotation_TheReportServiceFollowsANewKey` | A token signed two minutes before midnight and one signed after carry different key ids; the report service refetches on the new id and accepts both, because the old key stays published for the grace period |
| `TestRotation_EveryInstanceDerivesTheSameKey` | Two instances on two databases, one seed: the same signing key, and a token from one verifies against the other's key set |
| `TestJobToken_RS256WithoutASession` | The job token's header says `RS256`, it names no session, carries `role`, and is refused once expired |
| `TestRotationSeed_FromTheEnvironment` | A set seed is used as given; a malformed one is refused |
