# Write a plugin: rows that expire, and effects

A signed-in user mints a short-lived ticket for a path of the app, and whoever holds the ticket is redirected there until it expires. The plugin in [`tickets/`](tickets/tickets.go) shows what a plugin with expiring rows needs beyond a table. The ticket is handed over through effects: a response header when minted, and a redirect when redeemed. The plugin writes no HTTP itself. It is also a `Sweeper`, so the app's sweep deletes the expired rows. The guides are [Operations](../../docs/extending/02-operations.md), Step 5, and [Tables and migrations](../../docs/extending/05-tables-and-migrations.md), Step 7.

## Run it

```sh
cd examples
go run ./plugin-sweeper              # serve on http://localhost:8081
go run ./plugin-sweeper auth sweep   # delete what has expired, then exit
```

Run the tests with `go test ./plugin-sweeper/...`. They move a test clock forward instead of waiting five minutes.

## Walkthrough

Sign up, then mint a ticket. The ticket arrives in the `Set-Download-Ticket` header, which `authhttp` also lists in `Access-Control-Expose-Headers`. The JSON body holds only the expiry, because clients log bodies:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -si -b cookies.txt -X POST localhost:8081/auth/tickets/mint -H 'Origin: http://localhost:8081' -d '{"target":"/files/report.txt"}'
```

```text
HTTP/1.1 200 OK
Access-Control-Expose-Headers: Set-Download-Ticket
Content-Type: application/json
Set-Download-Ticket: BizjqrBhICjExw_YM4SzDkKc67mqPAEtHME5QyBqORs

{"expiresAt":"2026-10-09T03:16:30.854131Z"}
```

Redeeming it answers the redirect the operation recorded:

```sh
curl -si 'localhost:8081/auth/tickets/redeem?ticket=BizjqrBhICjExw_YM4SzDkKc67mqPAEtHME5QyBqORs'
```

```text
HTTP/1.1 302 Found
Location: /files/report.txt
```

A target on another site is refused, so a ticket can never become an open redirect. A failed call applies none of its effects, so no ticket header is sent:

```sh
curl -si -b cookies.txt -X POST localhost:8081/auth/tickets/mint -H 'Origin: http://localhost:8081' -d '{"target":"https://evil.example/"}'
```

```text
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"error":{"code":"tickets.target_invalid","message":"The target must be a path on this site."}}
```

The sweep reports the plugin's count under its name, next to the core's tables. The ticket above is still within the default retention, so it is kept:

```sh
go run ./plugin-sweeper auth sweep
```

```text
core.auth_code	0
core.auth_session	0
core.auth_verification	0
tickets	0
```

## The code

`doMint` records the ticket with `c.Effects.Header(HeaderTicket, ticket.Reveal())`, and `doRedeem` records `c.Effects.Redirect(target)`. Over HTTP they become a header and a `302`. From a Go call they are read back with `auth.RequestEffects(ctx)`, which `TestTickets_GoCallRecordsTheSameEffects` does. The table stores the ticket's hash (`auth.HashToken`), so a leaked database opens nothing.

`Sweep` is one `DELETE … WHERE expires_at < cutoff` on an indexed column. `Auth.Sweep(ctx, retention)` passes now minus the retention, so a ticket stays a while after it stops opening. `doRedeem` checks the expiry itself, so an expired ticket is refused whether or not a sweep has run yet: how often the app sweeps changes storage, never behaviour.

`main_test.go` checks the header and the redirect, the refusal of three other-site targets, an expired ticket refused before the sweep, a sweep that deletes it and a second sweep that finds nothing, a retention that keeps a recently expired ticket, and the same effects from a Go call.

## What this used

- [`auth`](https://pkg.go.dev/github.com/ubgo/auth): `Sweeper`, `Auth.Sweep`, `Effects.Header`, `Effects.Redirect`, `RequestEffects`, `HashToken`, `NewToken`, `WithClock`
- [`authcli`](https://pkg.go.dev/github.com/ubgo/auth/authcli): `auth sweep`
- Related: [plugin-tables](../plugin-tables) is the table contract without expiry; [plugin-delivery](../plugin-delivery) sends codes; [plugin-hooks](../plugin-hooks) changes other plugins' operations.
