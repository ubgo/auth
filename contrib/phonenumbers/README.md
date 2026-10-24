# github.com/ubgo/auth/contrib/phonenumbers

Lets users type phone numbers the way they write them at home, such as "0412 345 678" in Australia or "(555) 010-0100" in the US. It normalizes them to E.164 and refuses numbers in no assigned range, using libphonenumber's country rules.

## Install

```sh
go get github.com/ubgo/auth/contrib/phonenumbers
```

This is its own module because the country metadata is several megabytes that an app accepting only "+" numbers does not need. It brings `github.com/nyaruka/phonenumbers`. The package name is `phonenums`.

## Wire it

Plug it into the phone plugin. From `TestWithThePhonePlugin`:

```go
import phonenums "github.com/ubgo/auth/contrib/phonenumbers"

a, err := auth.New(auth.WithPlugins(
	phone.New(phone.Login(), phone.WithSMS(sms),
		phone.WithNormalizer(phonenums.Normalizer("AU")),
		phone.WithValidator(phonenums.Validator())),
))
// a.Normalize(phone.KindPhone, "0412 345 678") == "+61412345678"
```

Everything else about the phone plugin (sign-in with a code, `AllowPrefixes`, rate limits) is unchanged; see [examples/phone-only](../../examples/phone-only/).

## Options

| Function | What it does | Default |
|---|---|---|
| `Normalizer(defaultRegion)` | Returns a `phone.WithNormalizer` function. A number with "+" is read by its own country code; one without is read as a number of `defaultRegion`, an ISO 3166 code such as `"AU"`. The result is E.164. | none; the region is required |
| `Validator()` | Returns a `phone.WithValidator` function that accepts only numbers the country's rules say can exist. It also refuses numbers that have the right length but fall in no assigned range. | none |

Without them, the phone plugin's own `phone.Normalize` and `phone.Validate` accept only numbers typed with "+" and check the digit count against `phone.MinDigits` and `phone.MaxDigits`; they cannot tell whether a number exists.

## Tables and columns

None. The phone plugin stores the E.164 result in `auth_identity` as usual.

## Errors

| Error | When |
|---|---|
| `ErrNotANumber` | Input no country rule can read (`Normalizer`, `Validator`), or a number in no assigned range (`Validator`). The underlying reason is wrapped into the message. |

`ErrNotANumber` is a plain error rather than an `*auth.Error`. Inside the library the core replaces it with `auth.ErrIdentifierInvalid` (`a.Normalize` in store.go), so a client sees only `auth.identifier_invalid` (400).

## Security notes

| Property | Pinned by |
|---|---|
| National and international forms of one number normalize to the same E.164 value, so one person cannot hold two identities for the same number. | `TestNormalizer`, `TestWithThePhonePlugin` |
| A number of the right length in an unassigned range is refused, which cuts SMS spend on numbers nobody owns. | `TestValidator` |

Limit: `Validator` checks that a number can exist, not that anyone owns it. The code sent by SMS proves ownership.

## Example

- [examples/phone-only](../../examples/phone-only/): phone sign-in; add the two options above to its `phone.New`.
- https://pkg.go.dev/github.com/ubgo/auth/contrib/phonenumbers
