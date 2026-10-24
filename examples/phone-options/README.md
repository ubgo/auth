# Phone options: replace a number, keep several, let the provider check codes

Three choices of the phone plugin on an email-and-password account, one per mode of the same app:

- the default: one number per account, replaced in one step with `change` and `confirm-change`, never a moment with no number;
- `PHONE_MODE=multiple`: `phone.Multiple()`, several numbers per account with one primary;
- `PHONE_MODE=provider`: `phone.WithVerifier`, the SMS provider's verification service (Twilio Verify and the like) makes, texts and checks the codes, so the library never sees them.

## Run it

```sh
cd examples
go run ./phone-options                     # one number, change in one step
PHONE_MODE=multiple go run ./phone-options # several numbers
PHONE_MODE=provider go run ./phone-options # the provider checks the codes
```

It creates `phone-options.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Mail and texts are printed to the log instead of sent. Delete the database file between modes, since each mode is a different product decision. Run the tests with `go test ./phone-options`.

Every walkthrough starts the same way: Alice signs up, adds a number and types the texted code.

```sh
O='Origin: http://localhost:8081'
curl -s -c c.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b c.txt -X POST localhost:8081/auth/phone/add -H "$O" -d '{"phone":"+14155550101"}'
curl -s -b c.txt -X POST localhost:8081/auth/phone/verify -H "$O" -d '{"phone":"+14155550101","code":"676649"}'
```

## Replace the number in one step (default mode)

`change` texts a code to the new number and changes nothing; `/me` still shows the old number. `confirm-change` makes the new number the verified one and removes the old one in the same transaction:

```sh
curl -s -b c.txt -X POST localhost:8081/auth/phone/change -H "$O" -d '{"phone":"+14155550102"}'
curl -s -b c.txt localhost:8081/me
curl -s -b c.txt -X POST localhost:8081/auth/phone/confirm-change -H "$O" -d '{"phone":"+14155550102","code":"996758"}'
curl -s -b c.txt localhost:8081/me
```

```json
{"ok":true}
{"id":"usr_eskq7bkxs3mwqa5j3iyuegdu","phone":"+14155550101"}
{"phone":"+14155550102"}
{"id":"usr_eskq7bkxs3mwqa5j3iyuegdu","phone":"+14155550102"}
```

```text
2026/10/09 15:52:17 sms to=+14155550101 "Your code is 676649. It expires in 10 minutes."
2026/10/09 15:52:17 sms to=+14155550102 "Your code is 996758. It expires in 10 minutes."
```

`change` needs a fresh sign-in; `confirm-change` needs the session only, since the code is the proof.

## Several numbers per account (`PHONE_MODE=multiple`)

A second number is added beside the first. It cannot become primary until it is verified, and verifying it does not take primary over; `make-primary` does:

```sh
curl -s -b c.txt -X POST localhost:8081/auth/phone/add -H "$O" -d '{"phone":"+14155550102"}'
curl -s -b c.txt -X POST localhost:8081/auth/phone/make-primary -H "$O" -d '{"phone":"+14155550102"}'
curl -s -b c.txt -X POST localhost:8081/auth/phone/verify -H "$O" -d '{"phone":"+14155550102","code":"372109"}'
curl -s -b c.txt localhost:8081/auth/phone/list
curl -s -b c.txt -X POST localhost:8081/auth/phone/make-primary -H "$O" -d '{"phone":"+14155550102"}'
curl -s -b c.txt localhost:8081/auth/phone/list
curl -s -b c.txt localhost:8081/me
```

```json
{"ok":true}
{"error":{"code":"auth.not_verified","message":"Verify this first."}}
{"ok":true}
{"numbers":[{"phone":"+14155550101","verified":true,"primary":true},{"phone":"+14155550102","verified":true,"primary":false}]}
{"ok":true}
{"numbers":[{"phone":"+14155550101","verified":true,"primary":false},{"phone":"+14155550102","verified":true,"primary":true}]}
{"id":"usr_qykbrbm75dvaafnbrhva2fhw","phone":"+14155550102"}
```

In the default mode the same second `add` is refused with `phone.has_number`, and `list` and `make-primary` do not exist.

## The provider checks the codes (`PHONE_MODE=provider`)

The same `add` and `verify`, but the text comes from the provider's service, with its own wording, lifetime and attempt count:

```text
2026/10/09 15:52:21 sms to=+14155550101 "Your verification code is 269145."
```

`fakeVerify` in `main.go` is an in-process stand-in shaped like Twilio Verify: `Send` opens a verification and texts its code, `Check` compares it and answers a wrong, expired or exhausted code with `phone.ErrCodeInvalid`. Replace it with your provider's client; any other error from `Check` fails the operation instead of refusing the user.

## The code

The mode picks the options:

```go
func phoneOptions(m mode, sms phone.SMSSender) ([]phone.Option, error) {
	switch m {
	case modeSingle:
		return nil, nil
	case modeMultiple:
		return []phone.Option{phone.Multiple()}, nil
	case modeProvider:
		return []phone.Option{phone.WithVerifier(newFakeVerify(sms))}, nil
	default:
		return nil, fmt.Errorf("%w: %q", errUnknownMode, m)
	}
}
```

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server, once per mode: change keeps the old number until confirm, a wrong code, and the old number free for another account afterwards; a second number, `make-primary` refused until verified, the list, and removing the primary promoting the other; no `list` route without `Multiple`; the provider's text, its attempt count refusing the right code after five wrong ones, and a change checked by the provider; and `auth.New` refusing `GenerateCode` beside `WithVerifier`.

## What this used

- [`plugin/phone`](https://pkg.go.dev/github.com/ubgo/auth/plugin/phone): `Change`, `ConfirmChange`, `Multiple`, `List`, `MakePrimary`, `WithVerifier`, `Verifier`, `ErrCodeInvalid`, `ErrGenerateWithVerifier`
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email), [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password), [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp)
- Guide: [docs/plugins/phone.md](../../docs/plugins/phone.md#replace-the-number-in-one-step). Related: [phone-account](../phone-account) adds and verifies one number.
