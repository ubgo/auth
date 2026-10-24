# One app, many tenants: an address per tenant

One deployment serves many tenants from one database. The tenant is the first path segment (`/t/acme/…`), middleware puts it in the request context with `auth.WithScope`, and the email kind is unique per tenant, so `alice@example.com` has one account at Acme and another at Globex. The guide [Multi-tenancy](../../docs/concepts/multi-tenancy.md) explains it.

## Run it

```sh
cd examples
go run ./concepts-tenancy
```

It creates `concepts-tenancy.db` (SQLite), migrates it, and listens on `http://localhost:8081`. Run the tests with `go test ./concepts-tenancy`.

## Walkthrough

The unique index for the email kind is the scoped one:

```text
2026/10/01 10:27:29 migrated core/0001_core_tables
2026/10/01 10:27:29 migrated core/0003_session_lifetimes
2026/10/01 10:27:29 migrated email/0000_identity_unique_email_verified_scoped
2026/10/01 10:27:29 migrated email/0000_column_auth_user_primary_email
2026/10/01 10:27:29 migrated email/0000_column_auth_user_email_verified_at
2026/10/01 10:27:29 migrated password/0001_password
```

The same address signs up at two tenants and gets two users, each visible under its own tenant:

```sh
O='Origin: http://localhost:8081'
curl -s -c acme.txt -X POST localhost:8081/t/acme/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -c globex.txt -X POST localhost:8081/t/globex/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"a different password at globex"}'
curl -s -b acme.txt localhost:8081/t/acme/me
curl -s -b globex.txt localhost:8081/t/globex/me
```

```json
{"user":{"id":"usr_snvm4iv5sb2jrr4iu3zximq6","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"user":{"id":"usr_wmidytm5szqconbgbtelfn65","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"user":{"id":"usr_snvm4iv5sb2jrr4iu3zximq6","name":"","image":""},"tenant":"acme"}
{"user":{"id":"usr_wmidytm5szqconbgbtelfn65","name":"","image":""},"tenant":"globex"}
```

Globex's password does not open the Acme account, and a request with no tenant is refused before any lookup:

```sh
curl -s -X POST localhost:8081/t/acme/auth/password/sign-in -H "$O" -d '{"identifier":"alice@example.com","password":"a different password at globex"}'
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
```

```json
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"error":{"code":"auth.no_scope","message":"The request does not name a workspace."}}
```

In the database, each identity carries its tenant:

```sh
sqlite3 concepts-tenancy.db "select value, scope_id, user_id from auth_identity order by scope_id;"
```

```text
alice@example.com|acme|usr_snvm4iv5sb2jrr4iu3zximq6
alice@example.com|globex|usr_wmidytm5szqconbgbtelfn65
```

## What the tests pin

- One address at two tenants is two users, each with its own password and its own `scope_id`.
- A sign-in at one tenant with the other tenant's password is `password.invalid_credentials`.
- A scoped kind with no tenant in the context is `auth.no_scope`, over HTTP and from Go.
