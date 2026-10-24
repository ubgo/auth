# Usernames: handles beside email and password

Ada signs up with her address, claims the handle `Ada_Lovelace`, and from then on signs in with either. Anyone can ask whether a handle is free; `admin`, `pricing` and the rest of the reserved list can never be claimed; a rename frees the old handle at once.

## Run it

```sh
cd examples
go run ./username
```

It creates `username.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./username`.

## Walkthrough

Ada signs up and asks whether her handle is free, then claims it. The handle is stored lowercase; the spelling she typed is kept for display:

```sh
O='Origin: http://localhost:8081'
curl -s -c ada.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"ada@example.com","password":"correct horse battery staple"}'
curl -s 'localhost:8081/auth/username/available?username=Ada_Lovelace'
curl -s -b ada.txt -X POST localhost:8081/auth/username/set -H "$O" -d '{"username":"Ada_Lovelace"}'
curl -s -b ada.txt localhost:8081/me
```

```json
{"user":{"id":"usr_onk5awmdb3rucs3y4spihacn","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"available":true}
{"username":"ada_lovelace"}
{"id":"usr_onk5awmdb3rucs3y4spihacn","handle":"ada_lovelace","display":"Ada_Lovelace"}
```

The handle is taken now in any spelling. Reserved and malformed handles are refused:

```sh
curl -s 'localhost:8081/auth/username/available?username=ADA_LOVELACE'
curl -s 'localhost:8081/auth/username/available?username=pricing'
curl -s -b ada.txt -X POST localhost:8081/auth/username/set -H "$O" -d '{"username":"pricing"}'
curl -s -b ada.txt -X POST localhost:8081/auth/username/set -H "$O" -d '{"username":"1ada"}'
```

```json
{"available":false}
{"available":false}
{"error":{"code":"username.reserved","message":"This username is not available."}}
{"error":{"code":"auth.identifier_invalid","message":"This does not look right. Check it and try again."}}
```

The handle signs in with the same password, in any case:

```sh
curl -s -c ada2.txt -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"ADA_LOVELACE","password":"correct horse battery staple"}'
```

```json
{"user":{"id":"usr_onk5awmdb3rucs3y4spihacn","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

Bob cannot take it. Ada renames herself, and the old handle is free:

```sh
curl -s -c bob.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"bob@example.com","password":"correct horse battery staple"}'
curl -s -b bob.txt -X POST localhost:8081/auth/username/set -H "$O" -d '{"username":"ada_lovelace"}'
curl -s -b ada.txt -X POST localhost:8081/auth/username/set -H "$O" -d '{"username":"ada"}'
curl -s 'localhost:8081/auth/username/available?username=ada_lovelace'
curl -s -b ada.txt localhost:8081/me
```

```json
{"user":{"id":"usr_isxj6dge7gbgwqzjbg7ubsdz","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"error":{"code":"auth.identity_taken","message":"This is already in use by another account."}}
{"username":"ada"}
{"available":true}
{"id":"usr_onk5awmdb3rucs3y4spihacn","handle":"ada","display":"ada"}
```

The rows afterwards. A handle is a row of `auth_identity` like an address, stored verified and primary, with the typed spelling in `value_raw`:

```sh
sqlite3 username.db "select kind, value, value_raw, is_primary from auth_identity order by created_at;"
```

```text
email|ada@example.com|ada@example.com|0
email|bob@example.com|bob@example.com|0
username|ada|ada|1
```

## The code

The plugin line, with the app's own route names reserved on top of `username.DefaultReserved`:

```go
username.New(username.Login(), username.Reserved(reservedHandles...))
```

`Login()` is what lets the handle sign in; the password plugin's identifier field then takes an address or a handle, and the core tells them apart by shape. A handle cannot receive mail, so email with `Recover()` stays in the list: username and password alone fail in `auth.New` with `password: no identifier can recover an account; …`.

The handle lives in `auth_identity`, so the app's user struct has it as a nested field filled by a join in the same statement:

```go
type appUser struct {
	auth.User
	Handle username.Data
}

func (u *appUser) Bindings() []sqlb.Binding {
	return sqlb.Bindings(auth.UserBindings(&u.User), username.UserBindings(&u.Handle))
}

func (u *appUser) Joins() []sqlb.Join { return []sqlb.Join{username.UserJoin()} }
```

`a.LoadUser(ctx, id, &u)` fills both. `main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server: claim, show, sign in by handle, rename, and the three refusals.

## What this used

- [`plugin/username`](https://pkg.go.dev/github.com/ubgo/auth/plugin/username): `Login`, `Reserved`, `UserJoin`, `UserBindings`, `Data`
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email), [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password), [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp)
- Guide: [docs/plugins/username.md](../../docs/plugins/username.md). Related: [quickstart](../quickstart) is the app without handles.
