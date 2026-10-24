# Phone numbers as people type them

The [phone-only](../phone-only) app for people who type numbers the way they write them at home: "0412 345 678" in Australia, "+1 (650) 253-0000" from a visitor. [`contrib/phonenumbers`](https://pkg.go.dev/github.com/ubgo/auth/contrib/phonenumbers) reads them with libphonenumber's country rules, stores them as E.164, and refuses numbers that are the right length but in no range a carrier has assigned, before any text is sent.

## Run it

```sh
cd examples
go run ./phone-numbers
```

It creates `phone-numbers.db` (SQLite) and listens on `http://localhost:8081`. Texts are printed to the log; the code is in the log line. Run the tests with `go test ./phone-numbers`.

## Walkthrough

A code for a nationally typed number. The normalizer reads it as an Australian number and the text goes to the E.164 form:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/phone/send-code -H 'Origin: http://localhost:8081' -d '{"phone":"0412 345 678"}'
```

```json
{"ok":true}
```

```text
2026/10/01 10:47:50 sms to=+61412345678 "Your code is 297046. It expires in 10 minutes."
```

A number of the right length that no carrier has assigned, a real number from a country the app does not serve, and garbage are refused alike, and no text is sent for any of them:

```sh
curl -s -X POST localhost:8081/auth/phone/send-code -H 'Origin: http://localhost:8081' -d '{"phone":"0012 345 678"}'
curl -s -X POST localhost:8081/auth/phone/send-code -H 'Origin: http://localhost:8081' -d '{"phone":"+49 30 901820"}'
curl -s -X POST localhost:8081/auth/phone/send-code -H 'Origin: http://localhost:8081' -d '{"phone":"call me maybe"}'
```

```json
{"error":{"code":"auth.identifier_invalid","message":"This does not look right. Check it and try again."}}
{"error":{"code":"auth.identifier_invalid","message":"This does not look right. Check it and try again."}}
{"error":{"code":"auth.identifier_invalid","message":"This does not look right. Check it and try again."}}
```

The code signs the account in (the first time creates it); after signing out, the international form finds the same account:

```sh
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/phone/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"phone":"0412 345 678","code":"297046"}'
curl -s -b cookies.txt localhost:8081/me
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: http://localhost:8081'
curl -s -c cookies.txt -X POST localhost:8081/auth/phone/send-code -H 'Origin: http://localhost:8081' -d '{"phone":"+61 412 345 678"}'
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/phone/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"phone":"+61 412 345 678","code":"877385"}'
```

```json
{"user":{"id":"usr_x43dpt2piyln627wbjt3pgvb","name":"","image":""},"created":true,"secondFactorRequired":false}
{"id":"usr_x43dpt2piyln627wbjt3pgvb","phone":"+61412345678","phoneVerified":true}
{"ok":true}
{"ok":true}
{"user":{"id":"usr_x43dpt2piyln627wbjt3pgvb","name":"","image":""},"created":false,"secondFactorRequired":false}
```

## The code

The country-aware normalizer and validator replace the plugin's own, which accept only numbers typed with "+" and check nothing but the length; `AllowPrefixes` still applies on top:

```go
phone.New(phone.Login(), phone.Recover(), phone.SignInWithCode(), phone.WithSMS(sms),
	phone.WithNormalizer(phonenums.Normalizer(defaultRegion)),
	phone.WithValidator(phonenums.Validator()),
	phone.AllowPrefixes(allowedPrefixes...)),
```

`main_test.go` checks that the national and international forms of one number are one account, that a visitor's number is read by its own country code, and that an unassigned, a foreign and a garbage number are refused with only the one good number getting a text.

## What this used

- [`contrib/phonenumbers`](https://pkg.go.dev/github.com/ubgo/auth/contrib/phonenumbers) (`phonenums`): `Normalizer`, `Validator`
- [`plugin/phone`](https://pkg.go.dev/github.com/ubgo/auth/plugin/phone): `Login`, `Recover`, `SignInWithCode`, `WithSMS`, `WithNormalizer`, `WithValidator`, `AllowPrefixes`, `UserBindings`, `UserJoin`
- The guide is [docs/integrations/phone-numbers.md](../../docs/integrations/phone-numbers.md); the plugin alone is [phone-only](../phone-only).
