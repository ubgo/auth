# Audit history: your own events, by type, from the table or a sink

A security log that each user can read for themselves. Alice signs up, mistypes her password once, signs in, and asks for a data export (an operation of the app's own). Her history at `/auth/audit/my-events` lists each event under its type, the export under a type name the app chose with `audit.Types`; the app's own security page lists her sign-ins with a Go query. Run with `-memory` and the same reads are served by a sink that implements `audit.Querier` instead of the `audit_event` table.

## Run it

```sh
cd examples
go run ./audit-history            # events in the audit_event table
go run ./audit-history -memory    # events kept in the process by memoryLog
```

It creates `audit-history.db` (SQLite) and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./audit-history`.

## Walkthrough

Alice signs up, fails one sign-in, signs in and requests an export:

```sh
O='Origin: http://localhost:8081'
P='"password":"correct horse battery staple"'
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d "{\"identifier\":\"alice@example.com\",$P,\"name\":\"Alice\"}"
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"alice@example.com","password":"not it"}'
curl -s -c alice.txt -b alice.txt -X POST localhost:8081/auth/password/sign-in -H "$O" -d "{\"identifier\":\"alice@example.com\",$P}"
curl -s -b alice.txt -X POST localhost:8081/auth/exports/request -H "$O"
```

```json
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"ok":true}
```

(The two successful sign-in answers are left out above.) Her history holds three events, newest first. The failed sign-in is not among them: it carries no user id, on purpose, so the row does not reveal whether the address has an account.

```sh
curl -s -b alice.txt localhost:8081/auth/audit/my-events
```

```json
{"events":[{"id":"aud_th3edawc522isvq2hu2zvwg3","at":"2026-10-09T03:11:05.423246Z","op":"exports.request","plugin":"exports","transport":"http","ok":true,"actorId":"usr_pu2cobh3ola7w3wlhnffo4qn","sessionId":"ses_qvbwigzehztfp43dfyfhzwc5","ip":"127.0.0.1","userAgent":"curl/8.7.1","severity":"info","type":"data_export_requested"},{"id":"aud_5iypir4bwu26ilerdwt4r7ai","at":"2026-10-09T03:11:05.411477Z","op":"password.sign-in","plugin":"password","transport":"http","ok":true,"actorId":"usr_pu2cobh3ola7w3wlhnffo4qn","sessionId":"ses_unnsczzet6uinju5badttrvy","identifier":"alice@example.com","ip":"127.0.0.1","userAgent":"curl/8.7.1","severity":"info","type":"user_signed_in"},{"id":"aud_ehdbhimxr6db7avhihcpt52v","at":"2026-10-09T03:11:05.240602Z","op":"password.sign-up","plugin":"password","transport":"http","ok":true,"actorId":"usr_pu2cobh3ola7w3wlhnffo4qn","sessionId":"ses_unnsczzet6uinju5badttrvy","identifier":"alice@example.com","ip":"127.0.0.1","userAgent":"curl/8.7.1","severity":"info","type":"user_signed_up"}],"total":3,"page":1,"limit":50}
```

Narrowed to the app's own type, and the app's security page, which asks `audit.Plugin.Events` for her sign-ins from Go:

```sh
curl -s -b alice.txt 'localhost:8081/auth/audit/my-events?type=data_export_requested'
curl -s -b alice.txt localhost:8081/security/sign-ins
```

```json
{"events":[{"id":"aud_th3edawc522isvq2hu2zvwg3","at":"2026-10-09T03:11:05.423246Z","op":"exports.request","plugin":"exports","transport":"http","ok":true,"actorId":"usr_pu2cobh3ola7w3wlhnffo4qn","sessionId":"ses_qvbwigzehztfp43dfyfhzwc5","ip":"127.0.0.1","userAgent":"curl/8.7.1","severity":"info","type":"data_export_requested"}],"total":1,"page":1,"limit":50}
{"events":[{"id":"aud_5iypir4bwu26ilerdwt4r7ai","at":"2026-10-09T03:11:05.411477Z","op":"password.sign-in","plugin":"password","transport":"http","ok":true,"actorId":"usr_pu2cobh3ola7w3wlhnffo4qn","sessionId":"ses_unnsczzet6uinju5badttrvy","identifier":"alice@example.com","ip":"127.0.0.1","userAgent":"curl/8.7.1","severity":"info","type":"user_signed_in"}],"total":1,"page":1,"limit":10}
```

With `-memory`, the same commands give the same shapes (other ids and times), served from `memoryLog.Events`.

## The code

- `newApp` passes `audit.Types` to map the app's operation `exports.request` to `data_export_requested`, and `audit.To(sink)` when a sink is given. Without `audit.Types` the event's type would be the operation id.
- `newExports` is the smallest plugin with an operation: any `Mutation` is recorded with no wiring.
- `signIns` calls `Events` with `UserID` and `Type: audit.TypeUserSignedIn`. `Events` has no authorization of its own, so scoping the query to the caller is the handler's job.
- `memoryLog` implements `audit.Sink` and `audit.Querier`. It shows the shape of a sink for a log service; it is not one, since a restart loses every event.

`main_test.go` runs the same history on the table and on `memoryLog`, counts the failed attempt by the address typed (`audit.Query{Identifier: …}`), checks that a second user sees none of Alice's events, and checks that a sink with no `Querier` makes every read answer `501 audit.no_query_backend`.

## What this used

- [`plugin/audit`](https://pkg.go.dev/github.com/ubgo/auth/plugin/audit): `New`, `Types`, `To`, `Sink`, `SinkFunc`, `Querier`, `Query`, `Page`, `Events`, `TypeUserSignedIn`, `ErrNoQueryBackend`
- [`auth`](https://pkg.go.dev/github.com/ubgo/auth): `Define`, `OpInfo`
- Guide: [docs/plugins/audit.md](../../docs/plugins/audit.md). Related: [admin-ops](../admin-ops) (admins reading the log at `GET /auth/admin/audit`).
