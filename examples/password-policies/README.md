# Password policies: length, classes, a company rule and breach checks

The quick start with rules on new passwords: at least 12 characters, three character classes, a rule of the app's own with its own error code, and a check against the Have I Been Pwned range API. The same rules apply at sign-up, at reset and at change; existing passwords are not re-checked.

## Run it

```sh
cd examples
go run ./password-policies
```

It creates `password-policies.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. The breach check calls the public range API: only the first five hex characters of the password's SHA-1 leave the machine. Run the tests with `go test ./password-policies`; they use a fake range API that knows one password.

## Walkthrough

Length is checked first, then each policy in order, then the breach check. Four refusals and one sign-up:

```sh
for pw in 'Short1!' 'alllowercaseletters' 'Acme Rocks 2026 Forever' 'Correct Horse Battery 42'; do
  curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
    -d "{\"identifier\":\"alice@example.com\",\"password\":\"$pw\",\"name\":\"Alice\"}"; echo
done
```

```json
{"error":{"code":"password.too_short","message":"Choose a longer password."}}
{"error":{"code":"password.weak","message":"Choose a stronger password."}}
{"error":{"code":"acme.password_company_name","message":"The password must not contain the company name."}}
{"user":{"id":"usr_i6ytahdkr35qrdg4m2uo6o3w","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

`password.weak` is the generic answer of `RequireClasses`; the company rule returned its own `*auth.Error`, so its code and message reached the client as is. The app's `/me` reports whether the user has a password, for a settings page that must choose between "set a password" and "change password":

```sh
curl -s -b cookies.txt localhost:8081/me
```

```json
{"id":"usr_i6ytahdkr35qrdg4m2uo6o3w","hasPassword":true}
```

Change applies the same rules to the new password. A short one, then one that appears in a known breach (this call went to the real range API):

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/password/change -H 'Origin: http://localhost:8081' -d '{"current":"Correct Horse Battery 42","new":"Tr0ub4dor&3"}'
curl -s -b cookies.txt -X POST localhost:8081/auth/password/change -H 'Origin: http://localhost:8081' -d '{"current":"Correct Horse Battery 42","new":"P@ssw0rd1234"}'
```

```json
{"error":{"code":"password.too_short","message":"Choose a longer password."}}
{"error":{"code":"password.breached","message":"This password has appeared in a data breach. Choose another one."}}
```

## The code

The rules are options of the password plugin. The breach checker is a parameter of `newAuth` so the test can pass a fake range API; `main` passes `hibp.New()`:

```go
password.New(
	password.MinLength(minLength),
	password.RequireClasses(classes),
	password.Policy(noCompanyName),
	password.CheckBreached(breaches),
),
```

A policy is a function of the new password in clear. Returning an `*auth.Error` keeps its code; any other error becomes `password.weak`:

```go
func noCompanyName(pw string) error {
	if strings.Contains(strings.ToLower(pw), forbidden) {
		return ErrCompanyName
	}
	return nil
}
```

When the range API cannot be reached the request fails with that error, because a check that silently passes is a check that never runs; `hibp.FailOpen()` is the named way to prefer availability.

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server with a fake range API: the four refusals in order, the sign-up that passes, `/me` reporting the password, and a change to a breached password refused while the current one keeps working.

## What this used

- [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password): `MinLength`, `RequireClasses`, `Policy`, `CheckBreached`, `HasPassword`
- [`plugin/password/hibp`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password/hibp): `New`, `WithBaseURL`, `WithHTTPClient`
- [`github.com/ubgo/auth`](https://pkg.go.dev/github.com/ubgo/auth): `auth.NewError`, `a.Plugins`
- Related: [quickstart](../quickstart) is this app without the rules; the [passwords guide](../../docs/plugins/password.md) walks through every password operation.
