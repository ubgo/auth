# Two-factor manage: show codes again, turn it off, support resets or pauses

The "manage two-factor" page of an email-and-password app with an authenticator app as the second factor: read the QR code's URI back to add a second phone, show the recovery codes again, turn two-factor off, the two support-desk calls for a user who is locked out (`Unlock`) or lost both phone and recovery codes (`Reset`), and the admin plugin's routes over another user's factor: see it, pause it, switch it back on, reset it.

## Run it

```sh
cd examples
AUTH_SECRET=$(openssl rand -base64 32) STAFF_USER_IDS=usr_wcbhphu3hsy4jleaze3nemse go run ./two-factor-manage
```

It creates `two-factor-manage.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. `AUTH_SECRET` is required: the factor's secret and the sealed recovery codes use keys derived from it. `STAFF_USER_IDS` lists, comma-separated, the users allowed to call the support routes, who are also the admin plugin's admins; sign up a support account first, then restart with its id. Mail is printed to the log instead of sent. Run the tests with `go test ./two-factor-manage`.

## Walkthrough

Alice signs up, enrols an authenticator app and confirms it with her first code (computed from `secret`, as the app would). The answer is her recovery codes:

```sh
O='Origin: http://localhost:8081'
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b alice.txt -X POST localhost:8081/auth/twofactor/enroll -H "$O" -d '{}'
curl -s -b alice.txt -X POST localhost:8081/auth/twofactor/confirm -H "$O" -d '{"code":"929215"}'
```

```json
{"user":{"id":"usr_sxfcqpceelvwq5x7f5yiwyua","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"method":"totp","secret":"ZJ26R7X4HXPFH4VMAP6MWHYPMJ5GQCPC","url":"otpauth://totp/App:usr_sxfcqpceelvwq5x7f5yiwyua?digits=6&issuer=App&period=30&secret=ZJ26R7X4HXPFH4VMAP6MWHYPMJ5GQCPC","enabled":false}
{"codes":["LC3K-OVUI-2NFL-FIHK","VPYR-NK7J-WA2G-QJSS","3S67-VLE6-LD3D-DFWZ","OVUK-Y2GH-SMJO-T44K","IYD2-B647-6POQ-7KBX","67SW-WMOJ-PNML-I2Q7","GGWN-R7T4-MBHX-G3Q5","Z6JY-S3BT-ZIJ7-I7ER","MUZW-SIBT-I5OT-CXBN","4JJS-WP6W-ZCBI-VX64"]}
```

### Show the QR code and the recovery codes again

`ReadableTOTPURI()` adds `totp-uri`: on a fresh session and with her password, Alice reads the `otpauth://` URI back to draw the QR code for a second phone. `RecoveryCodeStorage(StoreEncrypted)` adds `recovery-codes/view`, which shows the unused codes again, in the order they were handed out:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/twofactor/totp-uri -H "$O" -d '{"password":"wrong"}'
curl -s -b alice.txt -X POST localhost:8081/auth/twofactor/totp-uri -H "$O" -d '{"password":"correct horse battery staple"}'
curl -s -b alice.txt -X POST localhost:8081/auth/twofactor/recovery-codes/view -H "$O" -d '{}'
```

```json
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"totpURI":"otpauth://totp/App:usr_sxfcqpceelvwq5x7f5yiwyua?digits=6&issuer=App&period=30&secret=ZJ26R7X4HXPFH4VMAP6MWHYPMJ5GQCPC"}
{"codes":["LC3K-OVUI-2NFL-FIHK","VPYR-NK7J-WA2G-QJSS","3S67-VLE6-LD3D-DFWZ","OVUK-Y2GH-SMJO-T44K","IYD2-B647-6POQ-7KBX","67SW-WMOJ-PNML-I2Q7","GGWN-R7T4-MBHX-G3Q5","Z6JY-S3BT-ZIJ7-I7ER","MUZW-SIBT-I5OT-CXBN","4JJS-WP6W-ZCBI-VX64"]}
```

Both are off by default for a reason: the URI is the secret itself, and sealed recovery codes mean a database leak together with the app secret gives every unused code.

### Locked out: support unlocks

Alice signs in again and types three wrong codes. The factor locks for 15 minutes, and even the right code is refused. Support, signed in as a staff user, unlocks her, and the right code works:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/sign-out -H "$O" -d '{}'
curl -s -b alice.txt -c alice.txt -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b alice.txt -X POST localhost:8081/auth/twofactor/verify -H "$O" -d '{"code":"000000"}'   # three times
curl -s -b alice.txt -X POST localhost:8081/auth/twofactor/verify -H "$O" -d '{"code":"524316"}'
curl -s -b staff.txt -X POST localhost:8081/support/two-factor/unlock -H "$O" -d '{"userId":"usr_sxfcqpceelvwq5x7f5yiwyua"}'
curl -s -b alice.txt -c alice.txt -X POST localhost:8081/auth/twofactor/verify -H "$O" -d '{"code":"524316"}'
```

```json
{"ok":true}
{"user":{"id":"usr_sxfcqpceelvwq5x7f5yiwyua","name":"","image":""},"verificationRequired":false,"secondFactorRequired":true}
{"error":{"code":"twofactor.code_invalid","message":"This code is not right."}}
{"error":{"code":"twofactor.locked","message":"Too many wrong codes. Wait and try again."}}
{"ok":true}
{"ok":true}
```

### Lost everything: support resets

`Reset` deletes the factor, every recovery code and every trusted device. Alice's next sign-in asks for the password only, and she can enrol again:

```sh
curl -s -b staff.txt -X POST localhost:8081/support/two-factor/reset -H "$O" -d '{"userId":"usr_sxfcqpceelvwq5x7f5yiwyua"}'
curl -s -b alice.txt -X POST localhost:8081/auth/sign-out -H "$O" -d '{}'
curl -s -b alice.txt -c alice.txt -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
```

```json
{"ok":true}
{"ok":true}
{"user":{"id":"usr_sxfcqpceelvwq5x7f5yiwyua","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

### Through the admin plugin: pause, switch back on, reset

The app also registers the admin plugin, with the `STAFF_USER_IDS` users as its admins (`admin.AdminIDs`), so support can manage Alice's factor over the library's own routes. Support reads the factor, then pauses it while her phone is in for repair: she signs in with the password alone. Switching it back on ends her sessions, and the recovery codes she kept still work. Support's own factor cannot be reset over HTTP, Alice's can, and Alice herself may not use the admin routes:

```sh
curl -s -b staff.txt "localhost:8081/auth/admin/two-factor?userId=usr_ck647t7m57ufbyrnlw63jks5"
curl -s -b staff.txt -X POST localhost:8081/auth/admin/disable-two-factor -H "$O" -d '{"userId":"usr_ck647t7m57ufbyrnlw63jks5"}'
curl -s -b alice.txt -c alice.txt -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b staff.txt -X POST localhost:8081/auth/admin/enable-two-factor -H "$O" -d '{"userId":"usr_ck647t7m57ufbyrnlw63jks5"}'
curl -s -b alice.txt localhost:8081/me
curl -s -b alice.txt -c alice.txt -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b alice.txt -c alice.txt -X POST localhost:8081/auth/twofactor/verify -H "$O" -d '{"code":"D3PA-CMFU-MUR6-IJCY"}'
curl -s -b staff.txt -X POST localhost:8081/auth/admin/reset-two-factor -H "$O" -d '{"userId":"usr_t2d43wn5qp45qd4awxdwqncr"}'
curl -s -b staff.txt -X POST localhost:8081/auth/admin/reset-two-factor -H "$O" -d '{"userId":"usr_ck647t7m57ufbyrnlw63jks5"}'
curl -s -b staff.txt "localhost:8081/auth/admin/two-factor?userId=usr_ck647t7m57ufbyrnlw63jks5"
curl -s -b alice.txt "localhost:8081/auth/admin/two-factor?userId=usr_ck647t7m57ufbyrnlw63jks5"
```

```json
{"enrolled":true,"enabled":true,"method":"totp"}
{"ok":true}
{"user":{"id":"usr_ck647t7m57ufbyrnlw63jks5","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"user":{"id":"usr_ck647t7m57ufbyrnlw63jks5","name":"","image":""},"verificationRequired":false,"secondFactorRequired":true}
{"ok":true}
{"error":{"code":"admin.admin_target","message":"Remove this user's admin rights first."}}
{"ok":true}
{"enrolled":false,"enabled":false,"method":""}
{"error":{"code":"admin.forbidden","message":"Only an administrator can do this."}}
```

### Turn it off

After enrolling again, Alice turns two-factor off herself. `disable` needs a fresh session and a current code (or an unused recovery code):

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/twofactor/disable -H "$O" -d '{"code":"589141"}'
curl -s -b alice.txt localhost:8081/me
curl -s -b alice.txt -X POST localhost:8081/auth/twofactor/disable -H "$O" -d '{"code":"589141"}'
```

```json
{"ok":true}
{"id":"usr_sxfcqpceelvwq5x7f5yiwyua","twoFactorEnabled":false}
{"error":{"code":"twofactor.not_enrolled","message":"Start two-factor setup first."}}
```

## The code

The plugin with both "show again" options and a lockout:

```go
tf := twofactor.New(
	twofactor.ReadableTOTPURI(),                             // POST /auth/twofactor/totp-uri
	twofactor.RecoveryCodeStorage(twofactor.StoreEncrypted), // POST /auth/twofactor/recovery-codes/view
	twofactor.Lockout(maxWrongCodes, lockFor),
)
```

The twofactor plugin itself serves no route over another user's factor, because who may act for another user is the app's rule. The app mounts `Reset` and `Unlock` behind its own staff check, `supportHandler(staff, tf.Reset)` and `supportHandler(staff, tf.Unlock)`, and registers `admin.New(admin.AdminIDs(staff...))`, whose `two-factor`, `disable-two-factor`, `enable-two-factor` and `reset-two-factor` routes ask the admin Authorizer instead (the built-in admin role holds `two-factor:get`, `disable`, `enable` and `reset`). A real app asks its roles or its authorizer instead of a list of ids.

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server: the URI read back matches the enrolled one, a wrong password is refused, the viewed codes match in the order they were handed out and lose the one used at sign-in; disable refuses a wrong code, turns the factor off, then answers `not_enrolled`; a lockout refuses the right code until staff unlock it, a non-staff user gets `403`, an unknown id gets `twofactor.not_enrolled`, and after a reset sign-in asks for the password only; through the admin routes a pause lets the password alone sign in, enable ends the session and a kept recovery code passes, an admin target is refused, a reset clears the factor and a non-admin gets `403`; and `newAuth` refuses to start without a secret.

## What this used

- [`plugin/twofactor`](https://pkg.go.dev/github.com/ubgo/auth/plugin/twofactor): `ReadableTOTPURI`, `TOTPURI`, `RecoveryCodeStorage`, `StoreEncrypted`, `ViewRecoveryCodes`, `Lockout`, `Disable`, `Reset`, `Unlock`, `DisableFor`, `EnableFor`, `FactorOf`, `TwoFactorColumns`
- [`plugin/admin`](https://pkg.go.dev/github.com/ubgo/auth/plugin/admin): `AdminIDs`, `TwoFactor`, `DisableTwoFactor`, `EnableTwoFactor`, `ResetTwoFactor`, `TwoFactorManager`
- [`auth`](https://pkg.go.dev/github.com/ubgo/auth): `WithSecret`; [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password), [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email), [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp)
- Guide: [docs/plugins/twofactor.md](../../docs/plugins/twofactor.md#step-6--turn-it-off). Related: [two-factor](../two-factor) enrols and signs in, [two-factor-options](../two-factor-options) has mailed codes, trusted devices and step-up.
