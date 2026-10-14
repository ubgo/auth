# Two-factor sign-in (TOTP, or codes by email or SMS)

You will have authenticator-app codes (Google Authenticator, 1Password, Authy and the rest) as a second step after any sign-in method the app has, with single-use recovery codes for a lost phone, a lockout against guessing, and a settings page that turns the factor on and off.

## Before you start

- [Passwords](password.md) or another way to sign in: the second factor sits after the first one, whatever it is (a password, a [magic link](magiclink.md), [OAuth](oauth.md), an [SMS code](phone.md)). No sign-in plugin knows this one exists.
- The example is [`examples/two-factor`](../../examples/two-factor/main.go): the quick start plus this plugin. `go run ./two-factor` in `examples/` starts it on `http://localhost:8081`; the transcripts below are from that program. The codes in them were computed from the secret by a 20-line RFC 6238 program, which is what an authenticator app does.
- A 32-byte key. TOTP secrets are sealed with AES-256 at rest; the example reads it as hex from `AUTH_TWO_FACTOR_KEY`. Keep it where you keep your other secrets: losing it disables every enrolled factor, and users then sign in with a recovery code.
- Reference: [plugin/twofactor/README.md](../../plugin/twofactor/README.md) lists every option, route, column and error.

## Step 1 — Wire the plugin

One more plugin in the list. The key is required; `Issuer` is the app name an authenticator app shows above the code, and `AccountLabel` the account name under it.

<!-- ds:block id=newauth-rby6vsmq -->
**newAuth** · [`examples/two-factor/main.go:129-139`](../../examples/two-factor/main.go#L129-L139)

```go
func newAuth(db *sql.DB, m email.Mailer, key []byte) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			twofactor.New(twofactor.WithEncryptionKey(key), twofactor.Issuer(appName), twofactor.AccountLabel(accountLabel)),
		),
	)
}
```
<!-- /ds:block hash=74a4b9 -->

The plugin is in the core module; `go get github.com/ubgo/auth` is all it needs. `auth.New` refuses it without a key of exactly 32 bytes, `auth.WithSecret` to derive one from, or a Sealer:

```text
twofactor: pass twofactor.WithEncryptionKey with a 32-byte key, or auth.WithSecret
```

When the key must stay in a key service (Vault transit, AWS KMS), seal through an [`auth.Sealer`](ds:block?id=core-sealer-4kw9vn2t) instead: [`twofactor.WithSealer(s)`](ds:block?id=twofactor-withsealer-7rq2mz4k) for this plugin, or `auth.WithSealer(s)` for every plugin that keeps secrets. TOTP secrets are sealed by the first of: `WithEncryptionKey`, `WithSealer`, `auth.WithSealer`, the key derived from `auth.WithSecret`; `StoreEncrypted` recovery codes by the first of `WithSealer`, `auth.WithSealer`, the derived key, so with a Sealer that mode no longer needs `auth.WithSecret`. Each value is sealed with the user id as additional data. A seal error fails the enrolment (no factor row is written) or the new set of recovery codes; an open error fails the check, never reads as an empty secret. Values sealed before the switch open only through a Sealer that can open them: moving existing users from the derived key to a KMS needs a Sealer that falls back to `auth.RingSealer` for the old values, or a re-enrolment. See [Security](../concepts/security.md#keys-in-a-kms-the-sealer).

The example turns the environment variable into a key, and refuses a malformed one instead of quietly using another, because a replaced key locks every enrolled user out:

<!-- ds:block id=sealkey-5cmce22d -->
**sealKey** · [`examples/two-factor/main.go:109-121`](../../examples/two-factor/main.go#L109-L121)

```go
func sealKey(hexKey string) ([]byte, error) {
	if hexKey == "" {
		log.Printf("WARN %s is not set: using a random key, so factors enrolled now stop working at the next start", envKey)
		key := make([]byte, auth.SealKeySize)
		_, err := rand.Read(key)
		return key, err
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) != auth.SealKeySize {
		return nil, fmt.Errorf("%s must be %d hex characters", envKey, 2*auth.SealKeySize)
	}
	return key, nil
}
```
<!-- /ds:block hash=987d3a -->

Check: `go run ./two-factor` prints `listening on http://localhost:8081`. Without the variable it also prints `WARN AUTH_TWO_FACTOR_KEY is not set: using a random key, so factors enrolled now stop working at the next start`, which is fine for a first run.

## Step 2 — Enrol

Enrolment is two calls from a signed-in user with a fresh session (created in the last [10 minutes](ds:block?id=defaultfreshwindow-5mt8jqw7)), so a laptop left open cannot have a factor added or removed by whoever sits down. `POST /auth/twofactor/enroll` mints a secret and returns it two ways: `url` for a QR code, `secret` as text to type into the app.

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b cookies.txt -X POST localhost:8081/auth/twofactor/enroll -H 'Origin: http://localhost:8081'
```

```json
{"user":{"id":"usr_fywmdzbrm35uf46lg5biymrj","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"secret":"HMIX4E2LHAZ4VFBEJDYCG2EPCQVIBWIL","url":"otpauth://totp/Acme:alice@example.com?digits=6&issuer=Acme&period=30&secret=HMIX4E2LHAZ4VFBEJDYCG2EPCQVIBWIL"}
```

The factor is still off: the plugin does not know the app scanned the code. `POST /auth/twofactor/confirm` with the first code from the app turns it on and returns the recovery codes. This is the only time they are shown (only their hashes are stored), so the page must tell the user to save them now. Confirming also signs out every other session of the user: they were created without the factor.

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/twofactor/confirm -H 'Origin: http://localhost:8081' -d '{"code":"325753"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"codes":["JRRP-QJEK-IWB7-PPLL","SAEO-UQ7E-ULF5-VQOX","FGFK-CSTA-VROW-LOSA","D7B4-CQNB-RAWQ-TALW","6TWJ-F3ZB-5OPK-K7CM","7R6L-CJD2-MLFY-TSV5","6WEQ-O3QM-LKAM-FADJ","LMDG-W3LJ-5HGW-XNBM","73PA-KYJD-XAJY-2TGB","I3HU-5UW5-OSDO-DLKI"]}
{"id":"usr_fywmdzbrm35uf46lg5biymrj","twoFactorEnabled":true}
```

The example's `/me` reads whether the factor is on from a column the plugin adds to `auth_user`, so a settings page learns it with the user row and no join:

<!-- ds:block id=mehandler-nwaa78nv -->
**meHandler** · [`examples/two-factor/main.go:179-190`](../../examples/two-factor/main.go#L179-L190)

```go
func meHandler(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := authhttp.MustUser(r)
		var cols twofactor.TwoFactorColumns
		if err := a.LoadUserColumns(r.Context(), u.ID, twofactor.Bindings(&cols)...); err != nil {
			authhttp.WriteError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, TwoFactorEnabled: cols.TwoFactorEnabled}) // a client that hung up cannot be told
	})
}
```
<!-- /ds:block hash=fbdcba -->

What the wrong order looks like: confirm before enroll, and enroll again once the factor is on. Enrolling twice before confirming is fine and replaces the secret, so a user who lost the QR code starts over.

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/twofactor/confirm -H 'Origin: http://localhost:8081' -d '{"code":"123456"}'
curl -s -b cookies.txt -X POST localhost:8081/auth/twofactor/enroll -H 'Origin: http://localhost:8081'
```

```json
{"error":{"code":"twofactor.not_enrolled","message":"Start two-factor setup first."}}
{"error":{"code":"twofactor.already_enabled","message":"Two-factor sign-in is already on."}}
```

From Go: `tf.Enroll(ctx)` returns `EnrollResult{Secret, URL}` and `tf.Confirm(ctx, code)` returns `RecoveryCodes{Codes}`. The context must carry the user's session (`a.WithRequest`), as `authhttp` and the adapters arrange.

## Step 3 — The sign-in step

Nothing changes in how the frontend signs a user in. The answer of the first step now says `secondFactorRequired: true`, and the session it set is pending: it signs nobody in. `/auth/session`, `RequireUser`, every signed-in route treat it as signed out, and only the verify operation can see it.

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"user":{"id":"usr_fywmdzbrm35uf46lg5biymrj","name":"","image":""},"verificationRequired":false,"secondFactorRequired":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

The frontend shows the code form and calls `POST /auth/twofactor/verify` with the pending session's cookie. A code works once, even inside its 30 seconds, so the code that confirmed enrolment is refused, and a code read over someone's shoulder cannot be replayed. The next one is accepted; the pending session is replaced by a full one with a new token (a token captured before the second step is worthless after it), and the app's page opens:

```sh
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/twofactor/verify -H 'Origin: http://localhost:8081' -d '{"code":"325753"}'
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/twofactor/verify -H 'Origin: http://localhost:8081' -d '{"code":"811988"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"error":{"code":"twofactor.code_invalid","message":"This code is not right."}}
{"ok":true}
{"id":"usr_fywmdzbrm35uf46lg5biymrj","twoFactorEnabled":true}
```

A pending session lives [10 minutes](ds:block?id=pendingsessionttl-p4sajtqx) by default (`auth.WithPendingSessionTTL(d)` changes it, see [Configuration](../concepts/configuration.md)); after that the user signs in again. Codes are accepted from [one step](ds:block?id=skew-v9xvtnr8) ([30 seconds](ds:block?id=step-xcvm8nc8)) before and after the server's clock, for a phone whose clock is a little off.

From Go, with the pending session's context:

<!-- ds:block id=plugin-verify-c25qunwp -->
**Plugin.Verify** · [`plugin/twofactor/twofactor.go:1168-1171`](../../plugin/twofactor/twofactor.go#L1168-L1171)

```go
func (p *Plugin) Verify(ctx context.Context, code string) error {
	_, err := p.verify.Call(ctx, CodeRequest{Code: code})
	return err
}
```
<!-- /ds:block hash=681b6d -->

The new token reaches the transport as an effect (`auth.RequestEffects(ctx)` lists an `EffectIssueSession`), which `authhttp` turns into the new cookie or `Set-Auth-Token` header; a Go caller that manages its own sessions reads it from there.

## Step 4 — Recovery codes

A user without their phone signs in with the password as usual and gives a recovery code where the app code would go. Dashes, spaces and case do not matter. Each code works once:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/twofactor/verify -H 'Origin: http://localhost:8081' -d '{"code":"JRRP-QJEK-IWB7-PPLL"}'
```

```json
{"user":{"id":"usr_fywmdzbrm35uf46lg5biymrj","name":"","image":""},"verificationRequired":false,"secondFactorRequired":true}
{"ok":true}
```

The same code on the next sign-in:

```json
{"error":{"code":"twofactor.code_invalid","message":"This code is not right."}}
```

There are [10](ds:block?id=defaultrecoverycodes-qp2yzv4v) by default (`twofactor.RecoveryCodeCount(n)` changes it), [16](ds:block?id=defaultrecoverycodelength-trh532bc) base32 characters each (80 bits; `twofactor.RecoveryCodeLength(n)` shortens or lengthens them, down to [8](ds:block?id=minrecoverycodelength-k2frj7m4)), stored as SHA-256 hashes. By default there is no "show me my codes again": only hashes exist. An app that wants better-auth's behaviour, codes the user can look at again, passes `twofactor.RecoveryCodeStorage(twofactor.StoreEncrypted)`; see [Showing recovery codes again](#showing-recovery-codes-again). A user who runs low asks for a new set with `POST /auth/twofactor/recovery-codes`, a fresh session and a current app code or an unused recovery code; the old set stops working the moment the new one is shown. From Go: `tf.RegenerateRecoveryCodes(ctx, code)`. An app that wants its own code format (words, a house pattern) passes `twofactor.RecoveryCodeGenerator(fn)`; the codes are returned as given and compared after trimming, upper-casing and removing dashes and spaces. A recovery code also works when the encryption key was lost or replaced, which is the only way in then.

## Step 5 — Lockout

[5](ds:block?id=maxfailures-dyu8kjqs) wrong codes, app codes or recovery codes, lock the factor for [15 minutes](ds:block?id=lockduration-mh4x5jpc), from any number of IPs; `twofactor.Lockout(maxFailures, d)` changes both. Every code-taking route (confirm, verify, disable, recovery-codes) also has a per-IP rule of [30](ds:block?id=codeiplimit-398tymcc) a minute, which bounds how fast one address can reach the database; the lockout is what stops guessing. A six-digit code accepts 3 of a million values per window, so the lock is what makes guessing hopeless, not a per-IP rule. While locked, even the right code and a valid recovery code are refused, on verify and on disable alike:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/twofactor/disable -H 'Origin: http://localhost:8081' -d '{"code":"000000"}'
```

```json
{"error":{"code":"twofactor.code_invalid","message":"This code is not right."}}
```

After four more of those, the right code and then a recovery code on a pending session:

```text
HTTP/1.1 429 Too Many Requests
{"error":{"code":"twofactor.locked","message":"Too many wrong codes. Wait and try again."}}
```

```json
{"error":{"code":"twofactor.locked","message":"Too many wrong codes. Wait and try again."}}
```

Check: `TestTwoFactorOptions_LockoutRefusesEvenTheRightCode` in [`examples/two-factor-options`](../../examples/two-factor-options/) runs this with `twofactor.Lockout(3, 15*time.Minute)`: three wrong codes, then the right one answers `twofactor.locked` (429).

Each lock is reported once to the [security event stream](../concepts/security-events.md) when a sink is registered: a `lockout` event (severity `warn`, outcome `blocked`) with the user, the operation, the number of wrong codes (`failures`) and the lock's length (`window`). The refusals while the lock lasts are not repeated into the stream, so a guessing run is one event per lock. `TestSecurityEvents_TwoFactorLockoutIsOneEventPerLock` in `integration/secgeo_test.go` pins it.

Wrong guesses are counted after the request's transaction ends, so the rollback of a failed request does not undo the count. A pending session that outlives the lock is gone when the lock ends; the user signs in again and gets a new one.

## Step 6 — Turn it off

`POST /auth/twofactor/disable` needs a fresh session and a current app code or an unused recovery code: the person turning the factor off must prove they could pass it. It deletes the factor and every recovery code, and sign-in is a full session again. This run used a second user whose factor was just confirmed, with the next step's code:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/twofactor/disable -H 'Origin: http://localhost:8081' -d '{"code":"336663"}'
curl -s -b cookies.txt localhost:8081/me
curl -s -b cookies.txt -X POST localhost:8081/auth/twofactor/disable -H 'Origin: http://localhost:8081' -d '{"code":"336663"}'
```

```json
{"ok":true}
{"id":"usr_zcpka4k4jmwfpj3su7wi3wmu","twoFactorEnabled":false}
{"error":{"code":"twofactor.not_enrolled","message":"Start two-factor setup first."}}
```

From Go: `tf.Disable(ctx, code)`.

### When support has to step in

Two Go calls cover the support desk, and neither has a route: who may act for another user is your rule, so put them behind your own staff check.

- [`tf.Reset(ctx, userID)`](ds:block?id=twofactor-reset-8kq3wv5n) turns the factor off for a user who lost both phone and recovery codes. It deletes every factor (further code factors and security keys included), every recovery code and every trusted device, and clears `two_factor_enabled`, in one transaction; the next sign-in asks for the first factor only, and the user can enrol again. It leaves sessions alone, so call `a.DeleteUserSessions` too if you suspect the account was taken.
- [`tf.Unlock(ctx, userID)`](ds:block?id=twofactor-unlock-4tn8xm2q) lifts a lockout before it expires and clears the count of wrong codes, once you have confirmed who is asking. The factor and recovery codes are untouched.

Both answer `twofactor.not_enrolled` for a user with no factor, so a mistyped id shows up.

[`examples/two-factor-manage`](../../examples/two-factor-manage/main.go) mounts both behind the app's own staff check, here a list of staff user ids; a real app asks its roles or its [authorizer](../extending/11-authorization.md):

<!-- ds:block id=two-factor-manage-support-6tq2wk9m -->
**supportHandler** · [`examples/two-factor-manage/main.go:185-204`](../../examples/two-factor-manage/main.go#L185-L204)

```go
func supportHandler(staff staffList, act func(ctx context.Context, userID string) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !staff[authhttp.MustUser(r).ID] {
			authhttp.WriteError(w, errNotStaff)
			return
		}
		var in supportRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.UserID == "" {
			authhttp.WriteError(w, auth.ErrBadRequest)
			return
		}
		if err := act(r.Context(), in.UserID); err != nil {
			// twofactor.not_enrolled for a user with no factor, so a
			// mistyped id shows up instead of passing silently.
			authhttp.WriteError(w, err)
			return
		}
		writeJSON(w, auth.Done{OK: true})
	})
}
```
<!-- /ds:block hash=80cbf4 -->

Alice typed three wrong codes, so her factor is locked and even the right code is refused; support unlocks her, and later resets the factor, after which her sign-in asks for the password only:

```sh
O='Origin: http://localhost:8081'
curl -s -b alice.txt -X POST localhost:8081/auth/twofactor/verify -H "$O" -d '{"code":"524316"}'
curl -s -b staff.txt -X POST localhost:8081/support/two-factor/unlock -H "$O" -d '{"userId":"usr_sxfcqpceelvwq5x7f5yiwyua"}'
curl -s -b alice.txt -c alice.txt -X POST localhost:8081/auth/twofactor/verify -H "$O" -d '{"code":"524316"}'
curl -s -b staff.txt -X POST localhost:8081/support/two-factor/reset -H "$O" -d '{"userId":"usr_sxfcqpceelvwq5x7f5yiwyua"}'
curl -s -b alice.txt -X POST localhost:8081/auth/sign-out -H "$O" -d '{}'
curl -s -b alice.txt -c alice.txt -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
```

```json
{"error":{"code":"twofactor.locked","message":"Too many wrong codes. Wait and try again."}}
{"ok":true}
{"ok":true}
{"ok":true}
{"ok":true}
{"user":{"id":"usr_sxfcqpceelvwq5x7f5yiwyua","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

Check: `TestTwoFactorManage_Support` in the example also refuses a non-staff caller (`403`) and answers `twofactor.not_enrolled` for an unknown id; `TestTwoFactorManage_Disable` refuses a wrong code at disable and signs in with a full session afterwards.

### Through the admin plugin: see, pause, switch back on, reset

With the [admin plugin](admin.md) registered too, an admin manages another user's factor over HTTP, with no handler of your own: `GET /auth/admin/two-factor?userId=` answers `{enrolled, enabled, method}`, and `POST /auth/admin/disable-two-factor`, `/enable-two-factor` and `/reset-two-factor` take `{userId}`. Admin finds this plugin by its methods (`FactorOf`, [`DisableFor`](ds:block?id=twofactor-disablefor-r5m2qk8w), [`EnableFor`](ds:block?id=twofactor-enablefor-h7w3nd6p), `Reset`), so neither imports the other, and asks its Authorizer for `two-factor:get`, `disable`, `enable` and `reset` first (the built-in admin role holds all four; a support role can be granted `two-factor:get` alone).

- **Disable** pauses the factor: sign-in stops asking, but the factor, its recovery codes and trusted devices stay, and the user's sessions are kept. To the user it reads as off (`status` answers `enabled: false`) and they may enrol a new factor, which replaces it. Use it when the phone is in for repair and will come back.
- **Enable** switches a paused factor back on and ends every session of the user, because sessions made during the pause never passed the factor; the old recovery codes work again. On a factor that is on it changes nothing.
- **Reset** is `tf.Reset`: the factor, codes and trusted devices go, and the user enrols again. Use it when the phone is gone.

Pause and reset refuse an admin's factor (`admin.admin_target`), so a stolen admin session cannot strip the other admins' protection; `ad.ResetTwoFactorFor(ctx, userID)` from Go accepts an admin, for the operator's recovery command, and is recorded in the audit log with no actor. The routes are audited like every admin mutation. [`examples/two-factor-manage`](../../examples/two-factor-manage/main.go) registers `admin.New(admin.AdminIDs(staff...))` beside its support routes.

Check: `TestTwoFactorManage_AdminRoutes` in the example pauses alice's factor (she signs in with the password alone), switches it back on (her session ends, a recovery code passes), refuses an admin target and resets it; alice herself gets `403 admin.forbidden`.

## Every option in one app

The sections that follow each turn on one choice. The example [`examples/two-factor-options`](../../examples/two-factor-options/) turns them all on at once, so its test proves they work together: mailed codes as the factor, remembered devices, a lockout after three wrong codes, step-up checks, and a policy that asks after every sign-in method, a mailed sign-in code included. The secret seals the factor's data with a derived key, so no separate `WithEncryptionKey` is needed:

<!-- ds:block id=newauth-tfo7op02 -->
**newAuth** · [`examples/two-factor-options/main.go:107-123`](../../examples/two-factor-options/main.go#L107-L123)

```go
func newAuth(db *sql.DB, secret []byte, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.SignInWithCode(), email.WithMailer(m)),
			password.New(),
			twofactor.New(
				twofactor.DeliveredCodes(),
				twofactor.TrustDevices(trustAge),
				twofactor.Lockout(maxWrongCodes, lockFor),
				twofactor.WithPolicy(signInPolicy),
			),
		),
	)
}
```
<!-- /ds:block hash=c6402e -->

<!-- ds:block id=twofactorsettings-tfo7op01 -->
**trustAge** · [`examples/two-factor-options/main.go:45-53`](../../examples/two-factor-options/main.go#L45-L53)

```go
const (
	// trustAge is how long a device the user trusted skips the factor.
	trustAge = 30 * 24 * time.Hour
	// maxWrongCodes wrong codes in a row lock the factor for lockFor.
	maxWrongCodes = 3
	// lockFor is how long a locked factor refuses every code, the right one
	// included.
	lockFor = 15 * time.Minute
)
```
<!-- /ds:block hash=802242 -->

<!-- ds:block id=signinpolicy-tfo7op03 -->
**signInPolicy** · [`examples/two-factor-options/main.go:133-135`](../../examples/two-factor-options/main.go#L133-L135)

```go
func signInPolicy(ctx context.Context, in twofactor.PolicyRequest) (bool, error) {
	return twofactor.AskEverySignIn(ctx, in)
}
```
<!-- /ds:block hash=77080f -->

A run, with the cookie jar `a.txt` as the user's laptop. Sign up, verify the address (a mailed code needs a verified channel), enrol the mailed code and confirm it with the first code:

```sh
O='Origin: http://localhost:8081'
curl -s -c a.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b a.txt -X POST localhost:8081/auth/email/verify -H "$O" -d '{"token":"NbeXesgGdukU1laSpSiJ4gjeI6hbwED9Q2kacrLf14Y"}'
curl -s -b a.txt -c a.txt -X POST localhost:8081/auth/twofactor/enroll -H "$O" -d '{"method":"delivered"}'
curl -s -b a.txt -c a.txt -X POST localhost:8081/auth/twofactor/confirm -H "$O" -d '{"code":"007639"}'
```

```json
{"user":{"id":"usr_ausgm32c7dwxdzqs355bi6dv","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"email":"alice@example.com"}
{"method":"delivered","enabled":false}
{"codes":["G2D2-YSZC-B6FS-ESA5","IRK7-OI3H-A6YF-3MLU","34KS-LEKN-RAFD-U66Q","T7FC-2YVX-UTHR-7QS4","GGYI-NLMQ-PS5D-7RLK","BXVI-TZEH-O55N-QIY7","2GIU-O5EV-JQGU-LCYR","JSJN-7ET3-KDTO-HKS5","6CJC-7EJ4-UOGO-RNKP","D7KK-GBGL-DRY7-OD6S"]}
```

Sign out and back in: the session is pending and `/me` sees nobody until the mailed code, sent with "remember this device":

```sh
curl -s -b a.txt -c a.txt -X POST localhost:8081/auth/sign-out -H "$O"
curl -s -b a.txt -c a.txt -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b a.txt localhost:8081/me
curl -s -b a.txt -c a.txt -X POST localhost:8081/auth/twofactor/send -H "$O"
curl -s -b a.txt -c a.txt -X POST localhost:8081/auth/twofactor/verify -H "$O" -d '{"code":"199135","trustDevice":true}'
```

```text
{"ok":true}
{"user":{"id":"usr_ausgm32c7dwxdzqs355bi6dv","name":"","image":""},"verificationRequired":false,"secondFactorRequired":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"ok":true}
2026/10/09 08:44:44 mail to=alice@example.com subject="Your sign-in code"
Your code is 199135. It expires in 5 minutes.
{"ok":true}
```

The next sign-in from the same browser skips the step, the device is listed, and a step-up check passes with a fresh code:

```sh
curl -s -b a.txt -c a.txt -X POST localhost:8081/auth/sign-out -H "$O"
curl -s -b a.txt -c a.txt -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b a.txt localhost:8081/auth/twofactor/devices
curl -s -b a.txt -c a.txt -X POST localhost:8081/auth/twofactor/send -H "$O"
curl -s -b a.txt -X POST localhost:8081/auth/twofactor/check -H "$O" -d '{"code":"120997"}'
```

```json
{"ok":true}
{"user":{"id":"usr_ausgm32c7dwxdzqs355bi6dv","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"devices":[{"id":"tfd_7zhoejduvuvm7ht3ta3fgzbs","userAgent":"curl/8.7.1","createdAt":"2026-10-09T03:14:44.548938Z","expiresAt":"2026-11-08T03:14:44.548938Z","lastUsedAt":"2026-10-09T03:14:44.676714Z","current":true}]}
{"ok":true}
{"ok":true}
```

A second browser (`p.txt`) signs in with a mailed sign-in code. The policy asks for the factor there too, and three wrong codes lock it, so even the right one is then refused:

```sh
curl -s -c p.txt -X POST localhost:8081/auth/email/send-code -H "$O" -d '{"email":"alice@example.com"}'
curl -s -b p.txt -c p.txt -X POST localhost:8081/auth/email/sign-in-code -H "$O" -d '{"email":"alice@example.com","code":"146869"}'
curl -s -b p.txt -c p.txt -X POST localhost:8081/auth/twofactor/send -H "$O"
for i in 1 2 3; do curl -s -b p.txt -X POST localhost:8081/auth/twofactor/verify -H "$O" -d '{"code":"000000"}'; done
curl -s -b p.txt -X POST localhost:8081/auth/twofactor/verify -H "$O" -d '{"code":"397638"}'
```

```json
{"ok":true}
{"user":{"id":"usr_ausgm32c7dwxdzqs355bi6dv","name":"","image":""},"created":false,"secondFactorRequired":true}
{"ok":true}
{"error":{"code":"twofactor.code_invalid","message":"This code is not right."}}
{"error":{"code":"twofactor.code_invalid","message":"This code is not right."}}
{"error":{"code":"twofactor.code_invalid","message":"This code is not right."}}
{"error":{"code":"twofactor.locked","message":"Too many wrong codes. Wait and try again."}}
```

Notice the trade-off this run makes visible: the sign-in code and the second-factor code both went to the same mailbox, so for a user whose factor is a mailed code, a mailed sign-in code followed by a mailed factor code proves the mailbox twice and nothing else. Prefer the authenticator app (`MethodTOTP`) for users who sign in by mailed code, or do not offer both. The default policy does not ask after a mailed sign-in code at all, which is the same trade-off made the other way.

## Codes by email or SMS

Some users will not install an authenticator app, and a product that insists loses them. With `twofactor.DeliveredCodes()` the plugin offers a second method, [`MethodDelivered`](ds:block?id=method-k3d8vq2m): the server mails or texts a one-time code to one of the user's verified identities at each sign-in. It is weaker than TOTP, because it trusts the mailbox or the phone network, which is why it is off by default and why the TOTP method stays available unless you pass `twofactor.WithoutTOTP()`. `tf.Methods()` lists what this configuration lets a user enrol, for the settings page.

Enrolment: `POST /auth/twofactor/enroll` with `{"method":"delivered"}` stores no secret and sends the first code at once, to the user's primary verified identity whose plugin can deliver (an [email](email.md) plugin with a `Mailer`, a [phone](phone.md) plugin with an `SMS` sender); the answer is `{"method":"delivered"}`. A user with no verified address or number cannot enrol this method (`twofactor.no_channel`). `POST /auth/twofactor/confirm` with that code turns the factor on and returns the recovery codes, as for TOTP.

Sign-in: the first step answers `secondFactorRequired: true` as before, and the client that offers both methods asks `GET /auth/twofactor/status` on the pending session, which answers `{"enabled":true,"method":"delivered","methods":["totp","delivered"],"trustDevices":false}`: the form to show, without probing send. The client then calls `POST /auth/twofactor/send` on the pending session, which mails or texts a fresh code (each call replaces the open one; [10 per 10 minutes](ds:block?id=sendiplimit-7qx3nm8w) per IP, and nothing while the factor is locked), and `POST /auth/twofactor/verify` with it. A delivered code works once and expires after `CodeTTL`; wrong guesses count towards the same lockout as TOTP codes, and recovery codes work as always. Send for a user whose factor is an authenticator app answers `twofactor.not_code_method`. A signed-in user calls the same send before disable or recovery-codes, which need a current code. From Go: `tf.EnrollWith(ctx, twofactor.EnrollRequest{Method: twofactor.MethodDelivered})`, `tf.Send(ctx)`, then `tf.Verify(ctx, code)`.

Check: `TestTwoFactorOptions_DeliveredCodeAndTrustedDevice` in [`examples/two-factor-options`](../../examples/two-factor-options/) enrols a mailed code and signs in with it.

The message goes out with the purpose [`twofactor.PurposeCode`](ds:block?id=purposecode-f9j2wt6x) and a default subject and text ("Your sign-in code", "Your code is 123456. It expires in 5 minutes."); an app's `email.Templates` or `phone.Templates` can handle the purpose to word it differently. Rows from before this method existed are authenticator-app factors: the `method` column the migration adds defaults to `totp`.

## Several factors, and security keys

A user may hold more than one second factor at once (an authenticator app, codes by email or SMS, and any number of security keys) and pick one at each sign-in. A security key here is a WebAuthn authenticator used after the first factor, never instead of it: a USB or NFC key, or the device's own Touch ID or Windows Hello. It needs the [passkey](passkey.md) plugin, which owns the WebAuthn protocol and stores the keys in a table of their own, so a security key never signs anyone in through passkey sign-in and a passkey never passes this step. The two plugins meet through one interface this plugin owns, [`twofactor.SecurityKeyStore`](ds:block?id=twofactor-securitykeystore-2hq7wn4c); [`passkey.(*Plugin).SecurityKeys`](ds:block?id=passkey-securitykeys-9wd3kq6n) returns one, and [`twofactor.WithSecurityKeys`](ds:block?id=twofactor-withsecuritykeys-6tn2vq8m) takes it:

<!-- ds:block id=sk-newauth-7qm2vd4w -->
**newAuth** · [`examples/two-factor-security-key/main.go:118-132`](../../examples/two-factor-security-key/main.go#L118-L132)

```go
func newAuth(db *sql.DB, m email.Mailer, secret []byte, extra ...auth.Option) (*auth.Auth, error) {
	pk := passkey.New(passkey.DisplayName(appName))
	opts := []auth.Option{
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			pk,
			twofactor.New(twofactor.Issuer(appName), twofactor.WithSecurityKeys(pk.SecurityKeys())),
		),
	}
	return auth.New(append(opts, extra...)...)
}
```
<!-- /ds:block hash=9e13da -->

The whole flow runs in [`examples/two-factor-security-key`](../../examples/two-factor-security-key/), whose test drives every route below through `authhttp.Handler` with a software authenticator making real WebAuthn signatures.

**Adding a factor.** A security key is added with `POST /auth/twofactor/security-key/register-begin` (fresh session; optional `authenticatorAttachment`: `platform` or `cross-platform`), which answers `{ceremony, options}` for `navigator.credentials.create`, then `POST /auth/twofactor/security-key/register-finish` with `{ceremony, credential, name}`. When the key is the user's first factor, two-factor sign-in is on from then and the answer carries the recovery codes, shown once, as `confirm` does. When a factor is already on, finish needs a `proof`: a current factor of the user (`{"method":"totp","code":"…"}`, a recovery code, or a security-key assertion), refused with `twofactor.proof_required` without it, because otherwise a stolen fresh session could plant a factor of its own. An authenticator app or delivered codes are added beside a factor that is on the same way: `enroll` with the new `method` and a `proof`, then `confirm` with the new method's first code, which answers `{"codes":[]}`: the recovery codes the user holds stay valid. One enrolment is in progress at a time.

**The challenge.** `GET /auth/twofactor/status` on the pending session lists the factors for the picker; `method` is still the first code factor, so an existing client sees nothing new:

```json
{"enabled":true,"method":"totp","methods":["totp","security_key"],"trustDevices":false,"factors":[{"method":"totp","primary":true,"createdAt":"…"},{"method":"security_key","id":"pks_…","name":"YubiKey","createdAt":"…","lastUsedAt":null}]}
```

The user picks one. A code goes to `verify` as before, with the method it is from: `{"method":"totp","code":"…"}`; without `method` the code is checked against the first code factor, which is the only one a user enrolled before factors could be combined has, so their sign-in is unchanged. A security key is `POST /auth/twofactor/security-key/challenge` (pending or signed-in session), which answers `{ceremony, options}` naming only that user's keys, then `verify` with `{"method":"security_key","securityKey":{"ceremony":"…","credential":{…}}}`. `check`, `disable`, `recovery-codes` and `reauthenticate` take the same `method` and `securityKey` fields. A recovery code passes with no method.

The challenge refuses, and the example's test proves each refusal by breaking the check behind it: a method the user does not have (`twofactor.factor_not_enrolled`, not counted, since no secret was tried); a signature from another private key, another user's genuine key, a replayed assertion (each ceremony works once) and a ceremony begun for another user (all `twofactor.security_key_invalid`, counted toward the same [lockout](#step-5--lockout) as wrong codes); and a key removed after its assertion was signed. A key's sign count that goes backwards is refused as a clone.

**Removing one factor.** `POST /auth/twofactor/remove-factor` (fresh session) with `{"method":"security_key","id":"pks_…","proof":{…}}`, or `{"method":"totp","proof":{…}}`, removes one factor after a proof (any current factor, the one being removed included, or a recovery code; the password too under `RequirePassword`). It answers `{"enabled":true}` while a factor is left; removing the last one turns two-factor off exactly as `disable` does, recovery codes included, and answers `{"enabled":false}`. `disable` still removes every factor at once, security keys included, as `tf.Reset` does for support.

From Go: `tf.SecurityKeyRegisterBegin`, `tf.SecurityKeyRegisterFinish`, `tf.SecurityKeyChallengeFor`, `tf.VerifyWith(ctx, twofactor.CodeRequest{Method: twofactor.MethodSecurityKey, SecurityKey: &resp})` and `tf.RemoveFactor`.

Where the rows live: the first factor stays in `auth_two_factor`, which also holds the lockout every factor shares; each further code factor is a row of [`auth_two_factor_method`](ds:block?id=tablenamemethod-8vq3kd7w), keyed by user and method; security keys are rows of the passkey plugin's [`auth_passkey_security_key`](ds:block?id=tablenamesecuritykey-4kt9wm2q). When the first factor is removed, the oldest further factor takes its place in `auth_two_factor`; a user whose factors are all security keys has a row there with `method` [`security_key`](ds:block?id=twofactor-methodsecuritykey-5mw8rq2k) and no secret. Users enrolled before this existed have the one row they always had, which is their one factor, so nothing is migrated.

## Requiring users to enrol

[`twofactor.RequireEnrolment(rule)`](ds:block?id=twofactor-requireenrolment-8mq4wk6t) makes a second factor mandatory for the users an [`EnrolmentRule`](ds:block?id=twofactor-enrolmentrule-3vk8qw2m) names: every user (`func(...) (bool, error) { return true, nil }`), admins only, or the members of an organization whose policy says so, which the rule looks up itself through the `*auth.Auth` it receives. A named user with no factor on signs in (or signs up) to a session with the core's `setup-mfa` [session task](../concepts/sessions.md) pending: `GET /auth/session` lists `"tasks":["setup-mfa"]`, the session reaches `status`, `enroll`, `confirm` and, with `WithSecurityKeys`, the security-key registration, and every other operation, the app's own `RequireUser` routes included, answers `auth.session_task_pending` (403). Turning a factor on (confirm, enroll under `SkipVerificationOnEnable`, or a first security key) replaces the session with an ordinary one under a new token, sent as a new cookie or `Set-Auth-Token`, and the old token stops working. A rule that returns an error requires enrolment. Without the option nothing changes.

Check: `TestRequireEnrolment_SessionWaitsForAFactor` in [`examples/two-factor-security-key`](../../examples/two-factor-security-key/) signs up under the rule, is refused `core.sessions` and `/me`, enrols by authenticator app (and a second user by security key), and checks the new token has no task while the old one is signed out.

## Remembering a device

The code step on every sign-in is the reason users turn two-factor off again. With `twofactor.TrustDevices(maxAge)` the code form can offer "remember this device": the client sends `{"code":"…","trustDevice":true}` to verify, and after the code passes the plugin stores a random device token's hash against the user and hands the token to the transport, which `authhttp` keeps in its own cookie (`__Host-auth_device`), apart from the session cookie, so it survives sign-out. The next password sign-in from that browser is a full session with no second step: `secondFactorRequired` is false. A sign-in from anywhere else, with no token or with another user's, still gets the step.

Trust has a fixed end: `maxAge` from the moment of verify (0 means thirty days, at most a year), never extended by use, so a stolen device cookie has a known expiry. It also ends early: `GET /auth/twofactor/devices` lists the user's trusted devices (user agent, created, expires, last used, and `current` for the one this request came from) and `POST /auth/twofactor/devices/forget` with `{"id":"…"}` or `{"all":true}` revokes them, which needs a fresh session; disabling the factor forgets them all; and a password change or reset forgets them too, because a device trusted before the response to a stolen account must not outlive it. When the device being forgotten is the current one, the transport drops its cookie. `auth sweep` deletes expired rows. From Go: `tf.VerifyWith(ctx, twofactor.CodeRequest{Code: code, TrustDevice: true})`, `tf.Devices(ctx)`, `tf.ForgetDevice(ctx, twofactor.ForgetDeviceRequest{All: true})`.

Without `TrustDevices` a verify that asks for trust is refused (`twofactor.trust_disabled`) before the code is spent, so a client that shows the checkbox learns the server will not honour it, and the device routes do not exist.

Check: `TestTwoFactorOptions_DeliveredCodeAndTrustedDevice` also checks that a second browser is still asked after the first was trusted, and that the device list marks the current one.

## Asking for the code again (step-up)

Before a sensitive action (changing payout details, exporting data) an app may want the signed-in user to type a code again. `POST /auth/twofactor/check` with `{"code":"…"}` on a signed-in session checks a current code or an unused recovery code and changes nothing else: no session is issued or replaced. It is better-auth's verify on an already signed-in session, with one difference on purpose: wrong codes here count towards the same [lockout](#step-5--lockout) as at sign-in, where better-auth's re-verify skips its lockout. A delivered-code user calls `send` first. From Go: `tf.CheckCode(ctx, code)`.

On the pending session, `POST /auth/twofactor/verify` with `{"code":"…","disableSession":true}` checks and spends the code and leaves the session pending (better-auth's `disableSession`, which it offers on `verify-backup-code`; here it applies to any code). Asking for `trustDevice` in the same call is refused (`twofactor.trust_needs_session`), since there is no sign-in to remember the device for. From Go: `tf.VerifyWith(ctx, twofactor.CodeRequest{Code: code, DisableSession: true})`.

Check: `TestTwoFactorOptions_StepUpCheck` in the example refuses a wrong code, passes the right one, and the session still answers `/me`.

## Re-authentication

A signed-in user who must prove themselves again for a `FreshSignIn` operation does it on the session they hold (see [Sessions](../concepts/sessions.md#prove-it-is-still-you-re-authentication)). The first step is a sign-in method's own, such as `POST /auth/password/reauthenticate`; the core then asks this plugin the sign-in question with `SignInAttempt.Reauthentication` set, so the [policy](#who-is-asked-for-the-code) decides exactly as at sign-in: `DefaultPolicy` asks after a password (`password.reauthenticate` is in `CredentialSignIns`) and after a passkey that did not verify the user, never from a remembered device. When it asks, the first step answers `{"fresh":false,"secondFactorRequired":true,"ticket":"…"}` and the session stays signed in and not fresh: cancelling here signs nobody out.

`POST /auth/twofactor/reauthenticate` with `{"code":"…","ticket":"…"}` finishes it: a current code or an unused recovery code, checked like the sign-in step with the same [lockout](#step-5--lockout), then the ticket, which is single use and only valid on the session it was issued to (`auth.reauthentication_ticket_invalid` otherwise). The answer is `{"fresh":true,"freshUntil":"…","secondFactorRequired":false}`; no session is issued or replaced. A delivered-code user calls `send` first. It is rate limited per IP like every code operation and [per account](ds:block?id=twofactor-reauthaccountlimit-3kd8wq5n). From Go: `tf.Reauthenticate(ctx, twofactor.ReauthenticateRequest{Code: code, Ticket: first.Ticket})`.

Unlike [`check`](#asking-for-the-code-again-step-up), which only answers whether a code is right, this step is what the library's `FreshSignIn` guards accept. A custom policy that wants to treat a re-authentication differently reads `PolicyRequest.Reauthentication`.

## Showing the QR code again

With `twofactor.ReadableTOTPURI()` the plugin adds `POST /auth/twofactor/totp-uri` (better-auth's `get-totp-uri`): a signed-in user adding a second phone, or whose setup page lost the QR code, reads the `otpauth://` URI back. It needs a fresh session and, for a user who has a password, the password in the body, checked by the password plugin with its own rate limit:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/twofactor/totp-uri -H 'Origin: http://localhost:8081' -d '{"password":"correct horse battery staple"}'
```

The answer is `{"totpURI":"otpauth://totp/…"}`, the field named as better-auth names it, with the issuer the user enrolled with. A wrong or missing password is `password.invalid_credentials`; a delivered-code factor is `twofactor.not_totp`. It is off by default because the URI is the secret: for a user with no password, a stolen fresh session is enough to clone their authenticator, silently. From Go: `tf.TOTPURI(ctx, twofactor.PasswordRequest{Password: pw})`.

[`examples/two-factor-manage`](../../examples/two-factor-manage/main.go) turns on both "show again" options, this one and [recovery codes](#showing-recovery-codes-again), and registers the admin plugin for [support's routes](#through-the-admin-plugin-see-pause-switch-back-on-reset):

<!-- ds:block id=two-factor-manage-newauth-8pk3vn6w -->
**newAuth** · [`examples/two-factor-manage/main.go:124-144`](../../examples/two-factor-manage/main.go#L124-L144)

```go
func newAuth(db *sql.DB, secret []byte, m email.Mailer, admins ...string) (*auth.Auth, *twofactor.Plugin, error) {
	tf := twofactor.New(
		twofactor.ReadableTOTPURI(),                             // POST /auth/twofactor/totp-uri
		twofactor.RecoveryCodeStorage(twofactor.StoreEncrypted), // POST /auth/twofactor/recovery-codes/view
		twofactor.Lockout(maxWrongCodes, lockFor),
	)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret), // seals the TOTP secret and the recovery codes
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			tf,
			// GET /auth/admin/two-factor, POST /auth/admin/disable-two-factor,
			// /enable-two-factor and /reset-two-factor.
			admin.New(admin.AdminIDs(admins...)),
		),
	)
	return a, tf, err
}
```
<!-- /ds:block hash=d96cfd -->

```sh
O='Origin: http://localhost:8081'
curl -s -b alice.txt -X POST localhost:8081/auth/twofactor/totp-uri -H "$O" -d '{"password":"wrong"}'
curl -s -b alice.txt -X POST localhost:8081/auth/twofactor/totp-uri -H "$O" -d '{"password":"correct horse battery staple"}'
curl -s -b alice.txt -X POST localhost:8081/auth/twofactor/recovery-codes/view -H "$O" -d '{}'
```

```json
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"totpURI":"otpauth://totp/App:usr_sxfcqpceelvwq5x7f5yiwyua?digits=6\u0026issuer=App\u0026period=30\u0026secret=ZJ26R7X4HXPFH4VMAP6MWHYPMJ5GQCPC"}
{"codes":["LC3K-OVUI-2NFL-FIHK","VPYR-NK7J-WA2G-QJSS","3S67-VLE6-LD3D-DFWZ","OVUK-Y2GH-SMJO-T44K","IYD2-B647-6POQ-7KBX","67SW-WMOJ-PNML-I2Q7","GGWN-R7T4-MBHX-G3Q5","Z6JY-S3BT-ZIJ7-I7ER","MUZW-SIBT-I5OT-CXBN","4JJS-WP6W-ZCBI-VX64"]}
```

Check: `TestTwoFactorManage_ShowAgain` compares the URI with the enrolled one and the viewed codes with the ones handed out, and sees a code used at sign-in drop out of the view.

## Showing recovery codes again

better-auth stores backup codes encrypted so `view-backup-codes` can show them; this plugin stores hashes. `twofactor.RecoveryCodeStorage(twofactor.StoreEncrypted)` offers better-auth's mode: each code also keeps a copy sealed with AES-256-GCM, bound to the user id, under a key derived from `auth.WithSecret` under the fixed label [`twofactor.KeyLabelRecoveryCodes`](ds:block?id=keylabelrecoverycodes-b6m2xq8t), so a secret rotation keeps them opening; with `twofactor.WithSealer` or `auth.WithSealer` the Sealer seals them instead. `auth.New` refuses it with neither a Sealer nor `auth.WithSecret`. `POST /auth/twofactor/recovery-codes/view` then answers the unused codes as they were handed out, in the order they were handed out (codes made before migration `0005_two_factor_recovery_seq` come back in a fixed order that may not be the original one), on a fresh session (and with the password under `RequirePassword`); a used code drops out and its sealed copy is cleared. Codes made before the switch have no sealed copy, so the view answers `twofactor.recovery_codes_hidden` until the user makes a new set. From Go: `tf.ViewRecoveryCodes(ctx, twofactor.PasswordRequest{})`. The risk it adds: a database leak together with the app secret gives every unused code, which hashed storage never would.

## Who is asked for the code

By default the plugin matches better-auth, whose `twoFactor` plugin hooks the password sign-ins only (`/sign-in/email`, `/sign-in/username`, `/sign-in/phone-number`). [`twofactor.DefaultPolicy`](ds:block?id=twofactor-defaultpolicy-4hn8wq3t) asks a user with a confirmed factor for the code after the operations in [`twofactor.CredentialSignIns`](ds:block?id=twofactor-credentialsignins-6pw2kq9m): `password.sign-in` (one operation for an email, a username or a phone number), `password.change-expired`, which signs in with a password too, and `password.reauthenticate`, the password [re-authentication](#re-authentication) of a signed-in session. It also asks after a direct `CreateSession` from Go, which cannot say how the user proved who they are. It also asks after a sign-in whose method reports it proved one factor (`SignInAttempt.SingleFactor`), which today is a passkey whose device skipped user verification; better-auth does not. It does not ask after OAuth, enterprise SSO, a magic link, a user-verified passkey, or a one-time code by email or SMS, and never from a [remembered device](#remembering-a-device). The consequence is better-auth's too: with one of those methods turned on, a user with a factor can sign in without it.

`twofactor.WithPolicy(fn)` replaces that rule. The policy is a `func(ctx, twofactor.PolicyRequest) (bool, error)`: true asks for the factor (a pending session), false signs the user in. The request carries the user id, the client (IP, user agent, origin), the sign-in operation (`Operation`, such as `password.sign-in` or `oauth.google-callback`) and its plugin (`Method`: `password`, `oauth`, `sso`, `magiclink`, `phone` …; empty for a direct `CreateSession` call from Go), and `DeviceTrusted`. It is asked only about a user who has a confirmed factor: a factor cannot be asked of someone who has none; making a user enrol is [`RequireEnrolment`](#requiring-users-to-enrol). An error asks for the factor, so a policy that cannot decide fails closed. `twofactor.DefaultPolicy` is the default rule, for a policy to fall back on.

To require the factor after OAuth, SSO and every other method too, use [`twofactor.AskEverySignIn`](ds:block?id=twofactor-askeverysignin-9tk3vn7w), which asks after every sign-in except from a remembered device (it was this plugin's default before it followed better-auth):

```go
tf := twofactor.New(twofactor.WithEncryptionKey(key), twofactor.WithPolicy(twofactor.AskEverySignIn))
```

Or keep better-auth's rule for most users and ask admins after every method:

```go
tf := twofactor.New(twofactor.WithEncryptionKey(key),
	twofactor.WithPolicy(func(ctx context.Context, in twofactor.PolicyRequest) (bool, error) {
		if isAdmin(ctx, in.UserID) {
			return twofactor.AskEverySignIn(ctx, in)
		}
		return twofactor.DefaultPolicy(ctx, in)
	}))
```

Check: `TestTwoFactorOptions_PolicyAsksAfterAMailedCode` in the example signs in by mailed code under the app's policy and gets a pending session, and checks that `DefaultPolicy` would not ask after that sign-in but does ask after a passkey that did not verify the user. The end-to-end run of that passkey rule is [`examples/passkey-first`](../../examples/passkey-first/); see [passkeys](passkey.md#a-passkey-that-did-not-verify-the-user).

Skipping after SSO is reasonable when the identity provider enforces its own second factor; skipping after a consumer OAuth provider, a magic link or an emailed code trusts that provider's or that mailbox's security with your second factor. The default follows better-auth; choose `AskEverySignIn` when your second factor must not depend on how the user signed in. The core passes the same sign-in description to any plugin that implements `auth.SecondFactorForSignIn` (see [Session rules](../extending/07-session-rules.md)); a plugin with only the older `SecondFactorRequired(ctx, userID)` keeps working unchanged.

## Options you may want

| You want | Do |
|---|---|
| The code after OAuth, SSO, magic links and one-time codes too, not only after a password | `twofactor.WithPolicy(twofactor.AskEverySignIn)`. See [Who is asked for the code](#who-is-asked-for-the-code). |
| A different rule for who is asked for the code (always ask admins, skip on a known network) | `twofactor.WithPolicy(fn)`. See [Who is asked for the code](#who-is-asked-for-the-code). |
| The app's name above the code | `twofactor.Issuer("Acme")`; the default is [`"App"`](ds:block?id=defaultissuer-enheudet). It is written into the authenticator app at enrolment, so renaming later relabels nothing already enrolled. |
| The user's email address under the code instead of their name or id | `twofactor.AccountLabel(fn)`. The plugin does not depend on the email plugin, so the callback looks the address up; it receives the core to do it with, and an empty result falls back to the user's name, then the id. |
| Fewer or more recovery codes | `twofactor.RecoveryCodeCount(n)`; applies at the next confirm or regenerate. |
| Users arriving with a TOTP secret from another system (Supabase `auth.mfa_factors.secret`, an otpauth URL's `secret`) | `tf.ImportTOTP(ctx, userID, secretBase32)` from the import: the secret is sealed and stored exactly as a confirmed enrolment stores it, and the user's next sign-in asks for the code their existing app already shows. No recovery codes are made, since nobody is there to be shown them; the user regenerates a set from settings. Refused: a secret that is not base32 or under 16 characters (`twofactor.secret_invalid`), a user already enrolled (`twofactor.already_enabled`), an unknown user. |
| Shorter or longer recovery codes | `twofactor.RecoveryCodeLength(n)` characters, at least `MinRecoveryCodeLength`. |
| Your own recovery code format | `twofactor.RecoveryCodeGenerator(func() []string)`. Empty or duplicate codes fail the confirm with `ErrBadRecoveryCodes`. |
| Eight-digit codes, or another step | `twofactor.WithDigits(twofactor.LongDigits)`, `twofactor.WithPeriod(d)` in whole seconds. Both are written into the authenticator app at enrolment: changing them later breaks every enrolled app, so decide before the first user enrols. |
| "Remember this browser for 30 days" | `twofactor.TrustDevices(0)` (0 is the [30-day](ds:block?id=defaulttrusteddeviceage-m2k7xn4q) default; at most [a year](ds:block?id=maxtrusteddeviceage-8gw3rz6p)). See [Remembering a device](#remembering-a-device). |
| More or less time to finish the code step | `auth.WithPendingSessionTTL(d)` on the core; the default is 10 minutes. |
| A different app name for one user's authenticator (one deployment, several brands) | `{"issuer":"Beta"}` at enroll (`twofactor.EnrollRequest{Issuer}`): better-auth's per-call issuer. Stored with the factor; at most [64](ds:block?id=maxissuerlength-r7u2kd9w) bytes, no colon, no control character (`twofactor.issuer_invalid`). |
| The factor on at enroll, with no first code | `twofactor.SkipVerificationOnEnable()`: better-auth's `skipVerificationOnEnable`. Enroll answers `"enabled":true` with the `recoveryCodes` and signs out the other sessions. Nothing proves the app holds the secret, so a user who mis-scanned the QR code needs a recovery code at the next sign-in; show the codes prominently. |
| The password asked for on enroll, disable and new recovery codes, as better-auth does | `twofactor.RequirePassword()`: a user with a password sends `"password"` with the request; a user without one (passkey or social sign-in) passes on the fresh session, which is better-auth's `allowPasswordless`. |
| A gentler or harsher lockout | `twofactor.Lockout(maxFailures, d)`. A six-digit code accepts 3 of a million values per step; raise `maxFailures` with care. |
| A second factor for users who will not install an authenticator app | `twofactor.DeliveredCodes()`: they enrol with `{"method":"delivered"}` and get a one-time code by email or SMS at each sign-in. See [Codes by email or SMS](#codes-by-email-or-sms). `twofactor.WithoutTOTP()` makes it the only method; `twofactor.CodeTTL(d)` sets how long a code works (default [5 minutes](ds:block?id=defaultcodettl-2wq9hz5r)). |
| "Is it on" in your own user struct | Embed `twofactor.TwoFactorColumns` and bind it with `Bindings`, or select the `two_factor_enabled` column of `auth_user`. See [Databases](../concepts/databases.md). |

<!-- ds:block id=labelfunc-tkkszqw2 -->
**LabelFunc** · [`plugin/twofactor/twofactor.go:506`](../../plugin/twofactor/twofactor.go#L506-L506)

```go
type LabelFunc func(ctx context.Context, a *auth.Auth, u auth.User) string
```
<!-- /ds:block hash=f5c716 -->

<!-- ds:block id=accountlabel-9pcn7s6s -->
**accountLabel** · [`examples/two-factor/main.go:147-158`](../../examples/two-factor/main.go#L147-L158)

```go
func accountLabel(ctx context.Context, a *auth.Auth, u auth.User) string {
	ids, err := a.Identities(ctx, u.ID)
	if err != nil {
		return u.ID
	}
	for _, id := range ids {
		if id.Kind == email.KindEmail {
			return id.Value
		}
	}
	return u.ID
}
```
<!-- /ds:block hash=56898c -->

<!-- ds:block id=bindings-hdjx6phm -->
**Bindings** · [`plugin/twofactor/twofactor.go:209-211`](../../plugin/twofactor/twofactor.go#L209-L211)

```go
func Bindings(c *TwoFactorColumns) []sqlb.Binding {
	return []sqlb.Binding{sqlb.Bind(Enabled, &c.TwoFactorEnabled)}
}
```
<!-- /ds:block hash=de5f8c -->

Combining with other plugins:

- Every sign-in method consults the plugin through the core. By default only a password sign-in yields a pending session for a user with the factor on; under `twofactor.WithPolicy(twofactor.AskEverySignIn)` a [magic link](magiclink.md), an [OAuth](oauth.md) sign-in and a [phone](phone.md) code do too. There is nothing to wire per method ([Who is asked for the code](#who-is-asked-for-the-code)).
- A [passkey](passkey.md) sign-in is a full session even with the factor on: user verification on the device (PIN or biometric) already makes it two factors. A passkey sign-in whose device did not verify the user (possible only under a lowered `passkey.AuthenticatorSelection`) proves possession only: it reaches the policy as `SignInAttempt.SingleFactor`, and `DefaultPolicy` asks for the factor after it.
- [Ready-made pages](../integrations/ready-made-pages.md) include the code form as the two-factor step of sign-in.
- For a factor that is not TOTP (a PIN, a hardware token, a push), the [Session rules](../extending/07-session-rules.md) guide shows the `SecondFactor` interface this plugin is built on.

## From TypeScript

Use this when the settings page that turns two-factor on and the code step after sign-in run in a browser or an app. The [typed client](../client/README.md) has every route of this guide on `client.twofactor`; list `twofactor()` in `plugins` with the sign-in plugins, because any sign-in can now answer `secondFactorRequired: true`.

The code step after sign-in, including `trustDevice` and a mailed code with `twofactor.send()`, is in [Flows › Second factor](../client/flows.md#second-factor-the-pending-session). Turning it on is two calls, as in Step 2; `enroll` needs a fresh session (re-authenticate as [password's From TypeScript](password.md#from-typescript) shows when it answers `auth.fresh_session_required`):

<!-- ds:block id=tsp-twofactor-enrol-7kq2wm5x -->
**turnOnAuthenticatorApp** · [`clients/ts/examples/plugin-twofactor.ts:15-25`](../../clients/ts/examples/plugin-twofactor.ts#L15-L25)

```typescript
export async function turnOnAuthenticatorApp(
  showQRCode: (otpauthURL: string, secret: string) => void,
  askForCode: () => Promise<string>,
): Promise<string[] | null> {
  const started = await auth.twofactor.enroll({ method: "totp" });
  if (started.error) return null; // auth.fresh_session_required, twofactor.already_enabled, ...
  showQRCode(started.data.url ?? "", started.data.secret ?? "");
  const confirmed = await auth.twofactor.confirm({ code: await askForCode() });
  if (confirmed.error) return null; // twofactor.code_invalid: ask again; the enrolment stays open
  return confirmed.data.codes ?? [];
}
```
<!-- /ds:block hash=cc233b -->

The settings page reads the state, and makes new recovery codes or forgets remembered devices:

<!-- ds:block id=tsp-twofactor-status-3wn8kx4q -->
**secondFactorSummary** · [`clients/ts/examples/plugin-twofactor.ts:29-33`](../../clients/ts/examples/plugin-twofactor.ts#L29-L33)

```typescript
export async function secondFactorSummary(): Promise<string> {
  const { data, error } = await auth.twofactor.status();
  if (error) return error.message;
  return data.enabled ? `On (${data.method ?? "totp"})` : `Off; available: ${(data.methods ?? []).join(", ")}`;
}
```
<!-- /ds:block hash=9c8153 -->

<!-- ds:block id=tsp-twofactor-recovery-9mx4qw2k -->
**newRecoveryCodes** · [`clients/ts/examples/plugin-twofactor.ts:38-41`](../../clients/ts/examples/plugin-twofactor.ts#L38-L41)

```typescript
export async function newRecoveryCodes(code: string): Promise<string[]> {
  const { data } = await auth.twofactor.recoveryCodes({ code });
  return data?.codes ?? [];
}
```
<!-- /ds:block hash=ca9744 -->

<!-- ds:block id=tsp-twofactor-devices-5kw2nq8v -->
**forgetOtherDevices** · [`clients/ts/examples/plugin-twofactor.ts:45-50`](../../clients/ts/examples/plugin-twofactor.ts#L45-L50)

```typescript
export async function forgetOtherDevices(): Promise<number> {
  const { data } = await auth.twofactor.devices();
  const others = (data?.devices ?? []).filter((d) => !d.current);
  for (const device of others) await auth.twofactor.forgetDevice({ id: device.id });
  return others.length;
}
```
<!-- /ds:block hash=428090 -->

<!-- ds:block id=tsp-twofactor-disable-2qx7mk9w -->
**turnOff** · [`clients/ts/examples/plugin-twofactor.ts:54-57`](../../clients/ts/examples/plugin-twofactor.ts#L54-L57)

```typescript
export async function turnOff(code: string): Promise<boolean> {
  const { error } = await auth.twofactor.disable({ code });
  return error === null;
}
```
<!-- /ds:block hash=3ce84d -->

The codes a frontend handles, explained in [What can go wrong](#what-can-go-wrong): `twofactor.code_invalid` (ask again; each wrong code counts toward the lock), `twofactor.locked` (show the wait), `twofactor.not_enrolled`, `twofactor.already_enabled`, `twofactor.not_code_method` (no "send me a code" button for an authenticator-app user), `twofactor.trust_disabled`, `auth.signed_out` from any other call while the session is pending, and `auth.fresh_session_required` on enroll, confirm, disable and the recovery-code calls.

Try it: `examples/ts-client-flows` enrols the mailed-code method, confirms it, signs in again to a pending session, gets `auth.signed_out` from `session()`, sends a code, is refused a wrong one and accepted the right one ([Flows › Try it](../client/flows.md#try-it)). The [React demo](../client/react.md) (`task demo`) runs the authenticator-app setup at `/two-factor/setup` and the challenge at `/two-factor`.

Pitfalls:

- **`twofactor.status` works on a pending session**, so the code step can ask which form to show (`method`, `methods`) before the user is signed in; every other signed-in call answers `auth.signed_out` until `verify` passes.
- **`confirm` signs out every other session of the user**, because they were created without the factor; a second tab or device has to sign in again.
- **The recovery codes are in `confirm`'s answer once.** Show them and ask the user to save them; by default no call shows them again (`viewRecoveryCodes` needs `RecoveryCodeStorage(StoreEncrypted)` on the server).
- **`url` is an `otpauth://` URL, not an image.** Draw the QR code in the page with a QR library; never send the URL to a third-party QR service, because it carries the secret.

Every method with its route and types: [TypeScript client reference › twofactor](../reference/ts-client.md#twofactor).

## What can go wrong

| Answer | Why | Fix |
|---|---|---|
| `twofactor.code_invalid` (400) | Wrong code, a code outside the one-step skew, a code already accepted, or a recovery code already used. | Let the user try again; show "codes work once" if they are retyping the last one. Each one counts toward the lock. |
| `twofactor.locked` (429) | 5 wrong codes in a row. | Wait 15 minutes. There is no operation to clear the lock early. |
| `twofactor.not_enrolled` (409) | Confirm before enroll, or disable, verify, send or recovery-codes for a user whose factor is not confirmed. | Call enroll first; or, for verify, the factor was turned off and the session should not be pending any more: sign in again. |
| `twofactor.method_invalid` (400) | Enroll named a method this configuration does not offer. | Offer only `tf.Methods()`; add `DeliveredCodes()` for codes by message. |
| `twofactor.no_channel` (409) | The user has no verified email address or phone number to send codes to. | Have them verify one first, or offer the authenticator app. |
| `twofactor.not_code_method` (409) | Send was called for an authenticator-app user. | Show the code form without a send button for `method: "totp"` users. |
| `twofactor.trust_disabled` (400) | Verify asked to remember the device, but the plugin has no `TrustDevices`. | Hide the checkbox, or turn the option on. The code was not spent. |
| `twofactor.device_not_found` (404) | Forget named a device that is not this user's. | Refresh the device list. |
| `twofactor.issuer_invalid` (400) | Enroll's issuer is longer than 64 bytes or holds a colon or a control character. | Send a plain product name, or none. |
| `twofactor.trust_needs_session` (400) | Verify asked for `trustDevice` and `disableSession` together. | Drop one; the code was not spent. |
| `twofactor.not_totp` (409) | Totp-uri for a delivered-code factor. | Only offer "show QR code" to `method: "totp"` users. |
| `twofactor.recovery_codes_hidden` (409) | View-recovery-codes for codes made before `StoreEncrypted` was on. | Have the user make a new set with recovery-codes. |
| `password.invalid_credentials` (401) on totp-uri, or on enroll, disable, recovery-codes and view under `RequirePassword` | Wrong or missing password for a user who has one. | Ask for the password again. |
| `twofactor.already_enabled` (409) | Enroll of a method the user already has on, or confirm with nothing waiting to be confirmed. | Offer disable or remove-factor, then enroll; to add a different method send it with a `proof`. |
| `auth.session_task_pending` (403) under `RequireEnrolment` | The session has `setup-mfa` pending: the user must enrol first. | Send the user to the enrolment page; `GET /auth/session` lists the task. |
| `twofactor.proof_required` (400) | Adding a factor (enroll, security-key-register-finish) while one is on, without a current factor in `proof`. | Ask for a code or a key first and send it as `proof`. |
| `twofactor.factor_not_enrolled` (400) | Verify, check or a proof named a method the user does not have, or a security-key challenge for a user with no key. | Offer only the factors `status` lists. |
| `twofactor.factor_not_found` (404) | Remove-factor named a key id that is not this user's, or a method they do not have. | Refresh the factor list. |
| `twofactor.security_key_invalid` (401) | The assertion did not verify: another key, another user's key, a spent or expired ceremony, a cloned key. Counted toward the lockout. | Start a new challenge and try again with a registered key. |
| `auth.signed_out` (401) on a signed-in route after sign-in | The session is pending. | Show the code form and call verify; only then is the user signed in. |
| `auth.fresh_session_required` (403) on enroll, confirm, disable, totp-uri or view-recovery-codes | The session is older than the fresh window. | Have the user sign in again, then retry. |
| `twofactor.secret_unreadable` (503), and the log says `twofactor: a sealed value does not open` with the user id | The stored secret does not open: the encryption key is not the one it was sealed with, or a `Sealer`'s key service is down. It is not counted as a wrong code. | Restore the key or the key service. If the key is gone, the user signs in with a recovery code (checked by hash, so it still works), and support resets the factor (`tf.Reset`, or the admin plugin's `reset-two-factor`) so they enrol again; there is no bulk reset. |
| A phone whose codes are always refused | Its clock is off by more than one step (30 seconds). | Have the user enable automatic time on the phone; the plugin accepts one step either way and no more, by design. |

Known limits, plainly: this plugin serves no route over another user's factor (`tf.Reset`, `tf.Unlock`, `tf.DisableFor`, `tf.EnableFor` are Go calls, see [When support has to step in](#when-support-has-to-step-in)), because who may act for another user is the app's rule; the [admin plugin](admin.md) serves pause, enable, reset and the read behind its Authorizer, and unlock stays a Go call. "Remember this browser" exists through `TrustDevices()` above. Codes by email or SMS are a second factor only through `DeliveredCodes()` above; the [phone plugin's](phone.md) own SMS code is a first factor.

## Next

- [Passkeys](passkey.md): one gesture instead of password and code.
- [Sessions](../concepts/sessions.md): what a pending session is and how the fresh window works.
- [Session rules](../extending/07-session-rules.md): build a second factor of your own.
- Reference: [plugin/twofactor/README.md](../../plugin/twofactor/README.md).
