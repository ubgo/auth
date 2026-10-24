# Sign up and create a workspace in one transaction

Every new user gets a workspace, a row in the app's own table. If the workspace cannot be created, the user must not exist either, and no verification mail may go out. `a.Tx` gives the app one transaction that both its own writes and the library's writes join.

## Run it

```sh
cd examples
go run ./saas-workspace
```

It creates `saas-workspace.db` (SQLite), the library's tables and the app's `workspace` table, and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./saas-workspace`.

## Walkthrough

Alice signs up through the app's own route and gets a session and a workspace:

```sh
O='Origin: http://localhost:8081'
curl -s -c alice.txt -X POST localhost:8081/signup -H "$O" \
  -d '{"email":"alice@example.com","password":"correct horse battery staple","name":"Alice","workspace":"Acme"}'
curl -s -b alice.txt localhost:8081/workspaces
```

```json
{"user":{"id":"usr_ke4yfxv4xvpuqzzjdy5zcfmo","name":"Alice","image":""},"workspace":{"id":"ws_caqrskty6q4wjjioioogfzjp","name":"Acme"}}
{"workspaces":[{"id":"ws_caqrskty6q4wjjioioogfzjp","name":"Acme"}]}
```

The log shows her verification mail, sent after the commit:

```text
2026/09/29 13:48:18 mail to=alice@example.com subject="Verify your email address"
Open this link to verify your email address:

http://localhost:8081/verify-email?token=vZE1zj1ZHnOLeZkedFXBClxKeZzT1wWY3Y6nlgCQ3j4
```

Bob asks for the same workspace name. The library had already created his user and identity inside the transaction when the app's insert hit the unique index, so everything rolls back:

```sh
curl -si -c bob.txt -X POST localhost:8081/signup -H "$O" \
  -d '{"email":"bob@example.com","password":"correct horse battery staple","name":"Bob","workspace":"Acme"}'
curl -s -b bob.txt localhost:8081/workspaces
```

```text
HTTP/1.1 409 Conflict
Content-Type: application/json
Date: Thu, 01 Oct 2026 05:17:53 GMT
Content-Length: 97

{"error":{"code":"workspace.name_taken","message":"A workspace with this name already exists."}}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

No `Set-Cookie` on the 409: the session the library issued inside the transaction was rolled back with it, and its effect never reached the response. Effects of an operation inside an outer `a.Tx` are held until that transaction commits and dropped when it rolls back.

The app's sign-up checks the origin itself, because a sign-up carries no session cookie for the library's check to look at:

```sh
curl -s -X POST localhost:8081/signup -H 'Origin: https://evil.example' \
  -d '{"email":"eve@example.com","password":"correct horse battery staple","workspace":"Evil"}'
```

```json
{"error":{"code":"auth.origin_not_trusted","message":"This request came from a site that is not trusted."}}
```

The tables afterwards hold Alice alone, and the log holds no mail for Bob:

```sh
sqlite3 saas-workspace.db "select 'users', count(*) from auth_user; select 'identities', group_concat(value) from auth_identity; select * from workspace;"
```

```text
users|1
identities|alice@example.com
ws_caqrskty6q4wjjioioogfzjp|Acme|usr_ke4yfxv4xvpuqzzjdy5zcfmo
```

## The code

The library owns begin and commit. Library calls made with the `ctx` that `Tx` passes join the transaction; the app writes its row with `tx`:

```go
err := a.Tx(ctx, func(ctx context.Context, tx *sql.Tx) error {
	res, err := pw.SignUp(ctx, password.SignUpRequest{Identifier: in.Email, Password: in.Password, Name: in.Name})
	if err != nil {
		return err
	}
	id, err := a.NewID(workspaceIDPrefix)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, insertWorkspace, id, name, res.User.ID); err != nil {
		if auth.IsUniqueViolation(err) {
			return errWorkspaceTaken
		}
		return err
	}
	...
})
```

Owning the commit is how the library knows when to send the verify mail: after the commit, never for a rolled-back row. An app that handed in its own `*sql.Tx` could not tell it when.

The app's table holds the owner's user id with no foreign key; the library creates none, and the app's `User.BeforeDelete` hook removes a deleted owner's workspaces. Reading the auth tables is open to the app; only writes go through the library:

```sql
CREATE TABLE IF NOT EXISTS workspace (
	id       TEXT NOT NULL PRIMARY KEY,
	name     TEXT NOT NULL UNIQUE,
	owner_id TEXT NOT NULL
)
```

The app's errors are `auth.NewError` values, so `authhttp.WriteError` answers them in the same JSON shape as the library's own.

`main_test.go` proves the success path (one user, one workspace, one mail), the rollback (no user, no identity, no mail and no session cookie for Bob, and Bob can then sign up with another name), and the refusals.

## Limits

- **A crash between commit and send loses the mail.** Mail goes out after the commit, in the background. The user can ask for a new link with `POST /auth/email/resend`. An outbox table would close the gap; the library does not have one.
- The schema is SQLite's. On Postgres or MySQL use `auth.TypesFor(engine).Key` for the id columns and the engine's placeholder style.

## What this used

- [`github.com/ubgo/auth`](https://pkg.go.dev/github.com/ubgo/auth): `Tx`, `NewID`, `IsUniqueViolation`, `NewError`, `TrustsOrigin`
- [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password): `SignUp` from Go
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `Middleware`, `RequestOf`, `WriteError`
- Related: [custom-plugin](../custom-plugin) (a data hook in the same transaction), [organizations](../organizations) (workspaces as a library feature).
