# User metadata: public, private and unsafe documents

Three JSON documents per user. A pretend checkout writes the plan to public metadata, where the front end reads it, and a billing id to private metadata, where it never can; the user keeps their own preferences in unsafe metadata with a merge patch; the session answer carries public and unsafe; an admin reads and patches all three through routes the admin plugin's roles decide.

## Run it

```sh
cd examples
go run ./user-metadata
```

It creates `user-metadata.db` (SQLite) and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./user-metadata`: they cover the flow below, the refusals (a user naming public or private, a patch that is not an object, a document over its bound, the per-user rate, a non-admin on the admin routes), and concurrent merges.

## Walkthrough

Alice signs up; her documents start empty. The checkout sets her plan, and she patches her own preferences, then removes one key with `null`:

```sh
O='Origin: http://localhost:8081'
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -b alice.txt localhost:8081/auth/metadata/get
curl -s -b alice.txt -X POST localhost:8081/checkout -H "$O"
curl -s -b alice.txt -X POST localhost:8081/auth/metadata/update -H "$O" -d '{"unsafe":{"theme":"dark","tour":{"step":2}}}'
curl -s -b alice.txt -X POST localhost:8081/auth/metadata/update -H "$O" -d '{"unsafe":{"theme":null,"tour":{"step":3}}}'
```

```json
{"user":{"id":"usr_6hcb627ubkg5orfl7jvflpcr","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"public":{},"unsafe":{}}
{"plan":"pro"}
{"public":{"plan":"pro"},"unsafe":{"theme":"dark","tour":{"step":2}}}
{"public":{"plan":"pro"},"unsafe":{"tour":{"step":3}}}
```

The session answer carries both documents she may see, and never the private one:

```sh
curl -s -b alice.txt localhost:8081/auth/session
```

```json
{"user":{"id":"usr_6hcb627ubkg5orfl7jvflpcr","name":"Alice","image":""},"expiresAt":"2026-10-20T12:33:48.660081Z","extras":{"public":{"plan":"pro"},"unsafe":{"tour":{"step":3}}}}
```

She cannot write public metadata, and the admin routes refuse her:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/metadata/update -H "$O" -d '{"public":{"plan":"enterprise"}}'
curl -s -b alice.txt "localhost:8081/auth/metadata/admin-get?userId=x"
```

```json
{"error":{"code":"auth.bad_request","message":"The request is not valid."}}
{"error":{"code":"metadata.forbidden","message":"You may not manage this user's metadata."}}
```

The guide is [docs/plugins/metadata.md](../../docs/plugins/metadata.md).
