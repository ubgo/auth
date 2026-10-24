# Admin operations: grant, find, create, ban, impersonate, audit

The admin and audit plugins end to end. The first admin is made from a subcommand, then over HTTP an admin finds users, creates one, sets a user's password and address, ends a user's sessions, grants and removes admin rights, bans a user who then reads why at sign-in, acts as a user for support within limits the library enforces (at most an hour, visible to the user, unable to change anything that proves the user's identity) and comes back to their own session, and reads the audit log of all of it.

## Run it

```sh
cd examples
go run ./admin-ops                          # serve on localhost:8081
go run ./admin-ops grant alice@example.com  # make the first admin
go run ./admin-ops auth admin grant --email alice@example.com   # the same through authcli
echo "$PW" | go run ./admin-ops auth admin create --email root@example.com --name Root --password-stdin
```

It creates `admin-ops.db` (SQLite) and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./admin-ops`.

## Walkthrough

Alice signs up. The `grant` command refuses her until her address is verified, because admin rights for whoever typed an address first would be a takeover:

```sh
O='Origin: http://localhost:8081'
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H "$O" \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
go run ./admin-ops grant alice@example.com
curl -s -b alice.txt -X POST localhost:8081/auth/email/verify -H "$O" -d '{"token":"E7dg-fIBAeGJHCzp47QNRkP_mZ01I48tY3O0Bq87tv0"}'
go run ./admin-ops grant alice@example.com
```

```text
{"user":{"id":"usr_gejihnupfzjajqbl5xi6aguc","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
2026/10/01 10:49:12 find a verified alice@example.com: auth.identity_not_found
exit status 1
{"email":"alice@example.com"}
alice@example.com (usr_gejihnupfzjajqbl5xi6aguc) is an admin
```

Bob signs up and is refused the admin routes. Alice pages through users, finds Bob by his address (normalized, matched exactly) and sees that a fragment matches nothing:

```sh
curl -s -b bob.txt localhost:8081/auth/admin/users
curl -s -b alice.txt 'localhost:8081/auth/admin/users?limit=1'
curl -s -b alice.txt 'localhost:8081/auth/admin/users?query=Bob@Example.com'
curl -s -b alice.txt 'localhost:8081/auth/admin/users?query=bob'
curl -s -b alice.txt 'localhost:8081/auth/admin/user?userId=usr_u6zvrbzlaexjc5l3tfvcvpri'
```

```json
{"error":{"code":"admin.forbidden","message":"Only an administrator can do this."}}
{"users":[{"id":"usr_u6zvrbzlaexjc5l3tfvcvpri","name":"Bob","createdAt":"2026-10-01T05:19:13.766596Z","admin":false,"banned":false}],"total":2,"page":1,"limit":1}
{"users":[{"id":"usr_u6zvrbzlaexjc5l3tfvcvpri","name":"Bob","createdAt":"2026-10-01T05:19:13.766596Z","admin":false,"banned":false}],"total":1,"page":1,"limit":50}
{"users":[],"total":0,"page":1,"limit":50}
{"user":{"id":"usr_u6zvrbzlaexjc5l3tfvcvpri","name":"Bob","createdAt":"2026-10-01T05:19:13.766596Z","admin":false,"banned":false},"banReason":"","identities":[{"kind":"email","value":"bob@example.com","verified":false,"primary":false}],"sessions":1}
```

Revoking ends Bob's sessions without banning him; he signs in again:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/admin/revoke-sessions -H "$O" -d '{"userId":"usr_u6zvrbzlaexjc5l3tfvcvpri"}'
curl -s -b bob.txt localhost:8081/me
curl -s -c bob.txt -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"bob@example.com","password":"correct horse battery staple"}'
```

```json
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"user":{"id":"usr_u6zvrbzlaexjc5l3tfvcvpri","name":"Bob","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

Admin rights: the last admin cannot remove their own; an admin cannot be banned, so Alice grants Bob, fails to ban him, and removes his rights again:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/admin/set-admin -H "$O" -d '{"userId":"usr_gejihnupfzjajqbl5xi6aguc","admin":false}'
curl -s -b alice.txt -X POST localhost:8081/auth/admin/set-admin -H "$O" -d '{"userId":"usr_u6zvrbzlaexjc5l3tfvcvpri","admin":true}'
curl -s -b alice.txt -X POST localhost:8081/auth/admin/ban -H "$O" -d '{"userId":"usr_u6zvrbzlaexjc5l3tfvcvpri","reason":"spam"}'
curl -s -b alice.txt -X POST localhost:8081/auth/admin/set-admin -H "$O" -d '{"userId":"usr_u6zvrbzlaexjc5l3tfvcvpri","admin":false}'
```

```json
{"error":{"code":"admin.last_admin","message":"Keep at least one administrator."}}
{"ok":true}
{"error":{"code":"admin.admin_target","message":"Remove this user's admin rights first."}}
{"ok":true}
```

Impersonation. Alice cannot act as an admin, herself included. Acting as Bob she asks for 600 minutes and gets 60; the new session is saved here to its own cookie jar (in a browser it replaces hers). As Bob she sees his `/me`, cannot change his password, and cannot reach the admin routes. Bob's own session list shows the impersonation:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/admin/impersonate -H "$O" -d '{"userId":"usr_gejihnupfzjajqbl5xi6aguc"}'
curl -s -b alice.txt -c support.txt -X POST localhost:8081/auth/admin/impersonate -H "$O" -d '{"userId":"usr_u6zvrbzlaexjc5l3tfvcvpri","minutes":600}'
curl -s -b support.txt localhost:8081/me
curl -s -b support.txt -X POST localhost:8081/auth/password/change -H "$O" -d '{"current":"correct horse battery staple","new":"hijacked passphrase"}'
curl -s -b support.txt localhost:8081/auth/admin/users
curl -s -b bob.txt localhost:8081/auth/sessions
```

```json
{"error":{"code":"admin.admin_target","message":"Remove this user's admin rights first."}}
{"user":{"id":"usr_u6zvrbzlaexjc5l3tfvcvpri","name":"Bob","image":""},"expiresAt":"2026-10-01T06:19:14.498264Z"}
{"id":"usr_u6zvrbzlaexjc5l3tfvcvpri","name":"Bob"}
{"error":{"code":"auth.impersonation_refused","message":"This cannot be done while acting as another user."}}
{"error":{"code":"admin.forbidden","message":"Only an administrator can do this."}}
{"sessions":[{"id":"ses_q7ob3wylddxxr56flwoyrgy6","current":false,"impersonated":true,"ip":"127.0.0.1","userAgent":"curl/8.7.1","createdAt":"2026-10-01T05:19:14.498264Z","lastSeenAt":"2026-10-01T05:19:14.498264Z"},{"id":"ses_d4425bkp5eboi7zd6zh5qh4v","current":true,"impersonated":false,"ip":"127.0.0.1","userAgent":"curl/8.7.1","createdAt":"2026-10-01T05:19:14.254692Z","lastSeenAt":"2026-10-01T05:19:14.254692Z"}]}
```

Stopping ends the impersonation and gives Alice her own session back: `impersonate` rotated her token and kept the new one in the flow cookie (saved to `support.txt` along with the impersonation cookie), and `stop-impersonating` re-issues it. On an ordinary session the route is refused. The server log records both ends with both user ids:

```sh
curl -s -b support.txt -c support.txt -X POST localhost:8081/auth/admin/stop-impersonating -H "$O"
curl -s -b support.txt localhost:8081/me
curl -s -b bob.txt -X POST localhost:8081/auth/admin/stop-impersonating -H "$O"
```

```json
{"ok":true,"restored":true}
{"id":"usr_62pz2ve5aawqz6kowwdreijn","name":"Alice"}
{"error":{"code":"admin.not_impersonating","message":"This session is not an impersonation."}}
```

```text
2026/10/01 10:49:14 WARN admin: impersonation started admin=usr_gejihnupfzjajqbl5xi6aguc user=usr_u6zvrbzlaexjc5l3tfvcvpri expires=2026-10-01T06:19:14.498Z
2026/10/01 10:49:14 WARN admin: impersonation ended admin=usr_gejihnupfzjajqbl5xi6aguc user=usr_u6zvrbzlaexjc5l3tfvcvpri
```

Creating users and setting passwords and addresses go through the plugins that own them, so their rules apply (here the password plugin refuses a short password and the create leaves no user behind); Carol signs in at once. Setting Bob's password ends his session; an admin's password cannot be set:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/admin/create-user -H "$O" -d '{"name":"Carol","email":"carol@example.com","password":"short"}'
curl -s -b alice.txt -X POST localhost:8081/auth/admin/create-user -H "$O" -d '{"name":"Carol","email":"carol@example.com","verified":true,"password":"correct horse battery staple"}'
curl -s -c carol.txt -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"carol@example.com","password":"correct horse battery staple"}'
curl -s -b alice.txt -X POST localhost:8081/auth/admin/set-password -H "$O" -d '{"userId":"usr_bwvncybszuhpp4fx6bbudkky","password":"a brand new passphrase"}'
curl -s -b bob.txt localhost:8081/me
curl -s -b alice.txt -X POST localhost:8081/auth/admin/set-email -H "$O" -d '{"userId":"usr_bwvncybszuhpp4fx6bbudkky","email":"robert@example.com","verified":true}'
curl -s -b alice.txt -X POST localhost:8081/auth/admin/set-password -H "$O" -d '{"userId":"usr_62pz2ve5aawqz6kowwdreijn","password":"a brand new passphrase"}'
```

```json
{"error":{"code":"password.too_short","message":"Choose a longer password."}}
{"user":{"id":"usr_rbowbyjbsbaupkb3tdktw6kh","name":"Carol","image":""}}
{"user":{"id":"usr_rbowbyjbsbaupkb3tdktw6kh","name":"Carol","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"ok":true}
{"error":{"code":"admin.admin_target","message":"Remove this user's admin rights first."}}
```

A banned user reads the app's message at sign-in, but only with the right password; a wrong one gets the ordinary answer, so the ban is not visible to a stranger. The audit log keeps the ban (about Bob by id) and both attempts (by the address typed, which carries no user id so an attempt at an unknown address looks the same):

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/admin/ban -H "$O" -d '{"userId":"usr_bwvncybszuhpp4fx6bbudkky","reason":"chargeback"}'
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"bob@example.com","password":"correct horse battery staple"}'
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"bob@example.com","password":"not it"}'
curl -s -b alice.txt 'localhost:8081/auth/admin/audit?userId=usr_bwvncybszuhpp4fx6bbudkky&limit=1'
curl -s -b alice.txt 'localhost:8081/auth/admin/audit?identifier=bob@example.com&op=password.sign-in&limit=2'
```

```json
{"ok":true}
{"error":{"code":"admin.banned","message":"Your account is suspended: chargeback."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"events":[{"id":"aud_nzkhleucwrz5inncfozd5u5k","at":"2026-10-02T16:21:47.155807Z","op":"admin.ban","plugin":"admin","transport":"http","ok":true,"actorId":"usr_62pz2ve5aawqz6kowwdreijn","sessionId":"ses_xgmkseloqq6m5vrm74lm754n","subjectId":"usr_bwvncybszuhpp4fx6bbudkky","ip":"127.0.0.1","userAgent":"curl/8.7.1"}],"total":2,"page":1,"limit":1}
{"events":[{"id":"aud_rbtotdduvaxj7muc7kaeyvvp","at":"2026-10-02T16:21:47.333408Z","op":"password.sign-in","plugin":"password","transport":"http","ok":false,"code":"password.invalid_credentials","identifier":"bob@example.com","ip":"127.0.0.1","userAgent":"curl/8.7.1"},{"id":"aud_harnqxe27ocsy2vgoccpplrz","at":"2026-10-02T16:21:47.246891Z","op":"password.sign-in","plugin":"password","transport":"http","ok":false,"code":"admin.banned","identifier":"bob@example.com","ip":"127.0.0.1","userAgent":"curl/8.7.1"}],"total":2,"page":1,"limit":2}
```

## The code

`admin.New` takes the banned-user message as its one option here; who is an admin is a column on `auth_user`, and the plugin finds the password, email and audit plugins at `Init` by interface. The grant command resolves a verified address and calls `Grant`:

```go
idn, err := a.FindIdentity(ctx, email.KindEmail, address, true)
if err != nil {
	return "", fmt.Errorf("find a verified %s: %w", address, err)
}
return idn.UserID, ad.Grant(ctx, idn.UserID)
```

Every other operation is one of the plugin's routes under `/auth/admin/`: `users`, `user`, `create-user`, `set-password`, `set-email`, `ban`, `unban`, `revoke-sessions`, `set-admin`, `impersonate`, `stop-impersonating`, `audit`. All but `users`, `user`, `audit` and `stop-impersonating` need a fresh sign-in (a session under ten minutes old by default).

The `auth` word hands the rest of the command line to [`authcli`](../../authcli/README.md), whose `admin grant` does the same as the grant command and whose `admin create` makes the first admin outright (verified address, password from stdin, admin rights, one transaction), finding this plugin's `Grant` by interface; its transcript is in the [CLI guide](../../docs/integrations/cli.md#step-7--make-the-first-admin).

`main_test.go` runs four flows: grant, find, revoke and set-admin; impersonation, its limits and the way back; create, set password, the ban message and the audit log; and the `auth admin` commands.

## What this used

- [`plugin/admin`](https://pkg.go.dev/github.com/ubgo/auth/plugin/admin): `New`, `BannedMessage`, `Grant`, `UsersRequest`, `UserDetail`, `CreateUserRequest`, `ImpersonateRequest`, `ImpersonateResult`, `StopResult`, the errors
- [`plugin/audit`](https://pkg.go.dev/github.com/ubgo/auth/plugin/audit): `New`, `Page`, `Event`
- [`github.com/ubgo/auth`](https://pkg.go.dev/github.com/ubgo/auth): `FindIdentity`, `MaxImpersonationTTL`, `ErrImpersonationRefused`
- [`authcli`](https://pkg.go.dev/github.com/ubgo/auth/authcli): `Main`, `MainWithStdin`, `CmdAdmin`, `AdminGrant`, `AdminCreate`, `AdminResult`
- Related: [admin-plan](../admin-plan) (an admin page of the app's own joined to its tables, ban and unban), [quickstart](../quickstart).
