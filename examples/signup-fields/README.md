# Signup fields: fill the app's own columns at sign-up

The sign-up form sends more than an email and a password: here a company name, a seat count and a newsletter choice. The app declares those columns on `auth_user` with `auth.WithUserColumns`, lists the ones a stranger may set with `auth.WithSignUpFields`, and the library writes them in the same transaction as the new account. A fourth column, the billing plan, is declared but not listed, so no sign-up body can set it.

## Run it

```sh
cd examples
go run ./signup-fields
```

It creates `signup-fields.db` (SQLite) in the current directory, creates the tables (the app's four columns included), and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./signup-fields`.

## Walkthrough

Alice signs up with the extra fields in a `fields` object, each with its column's JSON type, and `/me` reads them back. The plan was not sent, so it has the column's default:

```sh
O='Origin: http://localhost:8081'
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple","fields":{"app_company":"Acme","app_seats":5,"app_newsletter":true}}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"user":{"id":"usr_3nkocadgsw5nl32c7d4mr7lo","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_3nkocadgsw5nl32c7d4mr7lo","company":"Acme","seats":5,"newsletter":true,"plan":"free"}
```

A column that is not listed, and a value with the wrong type, are both refused before any row is written, with one code that names neither, so a probe learns nothing about the schema:

```sh
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"bob@example.com","password":"correct horse battery staple","fields":{"app_plan":"enterprise"}}'
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"bob@example.com","password":"correct horse battery staple","fields":{"app_seats":"five"}}'
```

```json
{"error":{"code":"auth.field_invalid","message":"A field in this request cannot be set, or has the wrong type."}}
{"error":{"code":"auth.field_invalid","message":"A field in this request cannot be set, or has the wrong type."}}
```

The same columns may also sit at the top level of the body: `{"identifier":…,"password":…,"app_company":"Globex"}`.

## The code

The columns, each NOT NULL with a default so an account that skips a field still has a value:

```go
var appColumns = []auth.ColumnExtension{
	{Name: colCompany, Type: auth.ColumnText, Default: "''"},
	{Name: colSeats, Type: auth.ColumnInt, Default: "1"},
	{Name: colNewsletter, Type: auth.ColumnBool, Default: "false"},
	{Name: colPlan, Type: auth.ColumnText, Default: "'free'"},
}
```

And the two options. `auth.New` refuses a sign-up field that is not one of the app's columns, so a typo cannot open a core column such as `name` or a plugin's column to strangers:

```go
auth.WithUserColumns(appColumns...),
auth.WithSignUpFields(colCompany, colSeats, colNewsletter),
```

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server: the `fields` object and top-level fields both land, defaults fill what was not sent, and an unlisted column, a core column, a wrong type, `null` on a NOT NULL column, a column sent twice and an unknown top-level key are each refused with the address left free; `auth.New` refuses a core column as a sign-up field.

## What this used

- [`auth`](https://pkg.go.dev/github.com/ubgo/auth): `WithUserColumns`, `ColumnExtension`, `WithSignUpFields`, `LoadUserColumns`
- [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password), [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email), [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp)
- Guide: [docs/plugins/password.md](../../docs/plugins/password.md#extra-fields-at-sign-up). Related: [account-settings](../account-settings) lets the user edit such columns later with `WithProfileFields`.
