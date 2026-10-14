# Phone numbers as people type them

You will have a phone sign-in that accepts "0412 345 678" from an Australian and "+1 (650) 253-0000" from a visitor, stores both as E.164, finds the same account whichever way the number is typed, and refuses a number no carrier has assigned before any text is sent.

## Before you start

- [Phone](../plugins/phone.md): the plugin's own flow, sign-in with a code sent by SMS. This guide changes only how a typed number is read.
- The example is [`examples/phone-numbers`](../../examples/phone-numbers/main.go). `go run ./phone-numbers` in `examples/` serves it on `http://localhost:8081`; texts are printed to the log. `go test ./phone-numbers` runs its tests.
- `go get github.com/ubgo/auth/contrib/phonenumbers` (package `phonenums`). It is its own module because libphonenumber's country metadata is several megabytes that an app accepting only "+" numbers does not need. It brings `github.com/nyaruka/phonenumbers`.

## Step 1 — Know what the plugin does on its own

Without this module, `phone.Normalize` accepts only a number typed with "+" and its country code, strips spaces and punctuation, and `phone.Validate` checks the digit count against [`MinDigits`](ds:block?id=mindigits-s68ve98t) (7) and [`MaxDigits`](ds:block?id=maxdigits-9yc3z2gc) (15). It cannot tell whether a number exists, and it cannot guess a country: that is a product decision, which this module makes with a default region.

## Step 2 — Plug in the normalizer and the validator

`phonenums.Normalizer(defaultRegion)` reads a number with "+" by its own country code and one without as a number of `defaultRegion` (an ISO 3166 code), and returns E.164. `phonenums.Validator()` accepts only numbers the country's rules say can exist, which also refuses numbers of the right length in no assigned range. `phone.AllowPrefixes` still applies on top: the validator says a number can exist, the prefixes say you serve its country.

<!-- ds:block id=normalizer-nkw5gw3q -->
**Normalizer** · [`contrib/phonenumbers/phonenums.go:31-39`](../../contrib/phonenumbers/phonenums.go#L31-L39)

```go
func Normalizer(defaultRegion string) func(raw string) (string, error) {
	return func(raw string) (string, error) {
		n, err := phonenumbers.Parse(raw, defaultRegion)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrNotANumber, err)
		}
		return phonenumbers.Format(n, phonenumbers.E164), nil
	}
}
```
<!-- /ds:block hash=cbde4d -->

<!-- ds:block id=validator-t8sw739j -->
**Validator** · [`contrib/phonenumbers/phonenums.go:46-57`](../../contrib/phonenumbers/phonenums.go#L46-L57)

```go
func Validator() func(normalized string) error {
	return func(normalized string) error {
		n, err := phonenumbers.Parse(normalized, "")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrNotANumber, err)
		}
		if !phonenumbers.IsValidNumber(n) {
			return fmt.Errorf("%w: %s is not an assigned number", ErrNotANumber, normalized)
		}
		return nil
	}
}
```
<!-- /ds:block hash=899b7f -->

<!-- ds:block id=phonenumbers-newauth-y7kq3mdb -->
**newAuth** · [`examples/phone-numbers/main.go:108-119`](../../examples/phone-numbers/main.go#L108-L119)

```go
func newAuth(db *sql.DB, sms phone.SMSSender) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			phone.New(phone.Login(), phone.Recover(), phone.SignInWithCode(), phone.WithSMS(sms),
				phone.WithNormalizer(phonenums.Normalizer(defaultRegion)),
				phone.WithValidator(phonenums.Validator()),
				phone.AllowPrefixes(allowedPrefixes...)),
		),
	)
}
```
<!-- /ds:block hash=1cd1d0 -->

Check: `auth.New` fails with `phone: no SMS sender; pass phone.WithSMS` without an SMS sender, and with `auth: no sign-in method; add a plugin such as password or oauth` without `phone.SignInWithCode()`, before anything is served.

## Step 3 — Send a code to a nationally typed number

The frontend posts the number as typed. The normalizer turns `0412 345 678` into `+61412345678`, the validator accepts it, the prefix check passes, and the text goes to the E.164 number:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/phone/send-code -H 'Origin: http://localhost:8081' -d '{"phone":"0412 345 678"}'
```

```json
{"ok":true}
```

```text
2026/10/01 10:47:50 sms to=+61412345678 "Your code is 297046. It expires in 10 minutes."
```

Check: the log shows the text to `+61412345678`, not to the typed form. The same number typed as `+61 412 345 678`, `0412345678` or `(04) 1234 5678` is one identity, so one person cannot hold two accounts for one phone.

## Step 4 — Refuse what cannot be a number

A number in no assigned range, a real number from a country you do not serve, and plain garbage are all refused with `auth.identifier_invalid` before a text is sent. The module's own `ErrNotANumber` never reaches a client: the core replaces it with the stable code, so the answer does not say which rule refused the number.

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

Check: the log shows no text for any of them. Every text costs money, and bots requesting codes for premium numbers abroad (SMS pumping) is the attack these two checks and the rate limits ([`sendCodeLimit`](ds:block?id=sendcodelimit-9ruwtqm6), 3 per number per [10 minutes](ds:block?id=sendcodewindow-jsdvm8be); [`sendCodeIPLimit`](ds:block?id=sendcodeiplimit-u8vu8fht), 20 per IP) stand against.

## Step 5 — Sign in, with either form

The code from the text signs the account in (the first time creates it). After signing out, the international form finds the same account:

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

The second code, `877385`, came from the log line that followed the second send.

Check: `/me` shows the stored number as E.164, and `created` is `false` the second time.

## Options you may want

| Need | Do |
|---|---|
| A different home country | `phonenums.Normalizer("US")`, or read the region from the request's locale and build the plugin per tenant. |
| Only international input, but with the existence check | Keep `phone.Normalize` (no `WithNormalizer`) and add `phone.WithValidator(phonenums.Validator())`. |
| Show the number formatted on the profile page | Store stays E.164; format for display in the frontend, or with `phonenumbers.Format` in Go. |
| Serve more countries | Extend `phone.AllowPrefixes`; the validator already knows every country. |

## What can go wrong

| You see | Why | Fix |
|---|---|---|
| `auth.identifier_invalid` for a number you know is real | It is outside `AllowPrefixes`, or typed without "+" from a country other than the default region, so it was read as a number of that region and did not exist there. | Add the prefix, or tell users abroad to include their country code. |
| `auth.identifier_invalid` for a short code or a premium number | libphonenumber knows them as non-standard; the validator refuses anything that is not a normal subscriber number. | Expected; those cannot receive sign-in codes. |
| A user's old account is not found after you added the module | The account's number was stored with the plugin's plain normalizer; both produce E.164, so this happens only if the number was stored unnormalized by a custom normalizer before. | Normalize the stored values once with `phonenums.Normalizer` and the region. |
| `auth.rate_limited` on send-code | More than 3 codes for one number in 10 minutes, or 20 from one IP. | Wait for `Retry-After`. |
| `auth.New` fails with `phone: no SMS sender; pass phone.WithSMS` | No sender configured. | Pass `phone.WithSMS`. |

## Next

- [Phone](../plugins/phone.md) for the full flow: adding a second number, verification, codes as a second factor.
- [Rate limits](../concepts/rate-limits.md) for what else protects the SMS budget.
- The module's [README](../../contrib/phonenumbers/README.md) is the reference.
