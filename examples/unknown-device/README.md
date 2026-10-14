# Tell users when a new device signs in

When someone signs in from a device the account has not been used from, the user gets a mail naming the device, the address and the time. The guide is the "Unknown-device sign-in notification" section of [docs/concepts/sessions.md](../../docs/concepts/sessions.md).

## Run it

```sh
cd examples
go run ./unknown-device
```

It creates `unknown-device.db` (SQLite) and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./unknown-device`.

## What it does

`auth.WithUnknownDeviceNotification()` is the only switch; it is off without it. A sign-in is from a known device when another session of the user, live or revoked, has the same user agent once version numbers are removed, so a browser update is not a new device. A user with no other session at all (their first sign-in) is not alarmed. The check and the mail run after the sign-in commits and in the background, so a slow or failing mail server never slows or fails a sign-in; a failure is logged. The user gets nothing if they have no verified address. `auth.WithDeviceRecognizer` replaces the rule with the app's own (a device cookie, a fingerprinting service, a table).

## What the test proves

`main_test.go` signs up from one browser and verifies the address, then: two sign-ins from that browser, one of them after an update, send nothing; the first sign-in from another browser sends one mail that names it; a second sign-in from that browser sends none.
