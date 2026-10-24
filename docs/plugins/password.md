# Passwords

You will have sign-up and sign-in with a password, a forgotten-password flow that mails a reset link, a change-password form, rules for new passwords (length, character classes, a rule of your own) and a check against known breaches, through HTTP routes a frontend calls and through the Go API.

## Before you start

- [Your first app](../start/first-app.md) wires email and password; this guide goes through every password operation that app serves.
- The examples are [`examples/quickstart`](../../examples/quickstart/main.go) (the flows) and [`examples/password-policies`](../../examples/password-policies/main.go) (the rules). `go run ./quickstart` in `examples/` starts the first on `http://localhost:8081`; the transcripts below are from that program.
- The password plugin stores no identifier of its own. It asks the core "who has this identifier" and "where can this account be reached", so it needs at least one identifier plugin: [email](email.md), [phone](phone.md) or [username](username.md). A username-only app has no way to recover a password; see [Options you may want](#options-you-may-want).
- Reference: [plugin/password/README.md](../../plugin/password/README.md) lists every option, route, column and error.

## Step 1 — Wire the plugin

Add `password.New()` to the plugin list next to an identifier plugin that can sign in (`email.Login()`) and recover (`email.Recover()`). `auth.New` checks the combination: a password with no identifier to type, or none to send a reset link to, fails at start-up, not when the first user forgets a password.

<!-- ds:block id=newauth-smwje7vu -->
**newAuth** · [`examples/quickstart/main.go:99-108`](../../examples/quickstart/main.go#L99-L108)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
	)
}
```
<!-- /ds:block hash=6b7d2a -->

The plugin is its own module (`go get github.com/ubgo/auth/plugin/password`), because it brings `golang.org/x/crypto` for argon2id. Check: `go run ./quickstart` prints `listening on http://localhost:8081`. If it prints one of these instead, the plugin list is incomplete:

```text
password: no identifier can sign in; add one with Login(), for example email.New(email.Login())
password: no identifier can recover an account; add one with Recover(), for example email.New(email.Recover()), or pass password.WithoutRecovery()
password: reset links need auth.WithBaseURL or password.ResetLinks
```

## Step 2 — Sign up

`POST /auth/password/sign-up` takes the identifier, the password and an optional name. The identifier can be anything a wired identifier plugin accepts: an address here, a phone number or a username in another app. The session arrives as a cookie (or as a bearer token, see [SPA frontends](../integrations/spa-frontends.md)); the body never carries it.

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
```

```json
{"user":{"id":"usr_6h57utnyiaovn2aiblbubqx2","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

The email plugin mails a verification link at the same time (printed to the log by this example):

```text
2026/10/01 10:26:10 mail to=alice@example.com subject="Verify your email address"
Open this link to verify your email address:

http://localhost:8081/verify-email?token=UKaeGywG8RLU7CJEDtSW41_2pCYAUh0ar_ai8tTW35U

If you did not ask for this, ignore this email.
```

### Extra fields at sign-up

A sign-up may also fill columns your app added to `auth_user`, sent in a `fields` object. Declare the columns with `auth.WithUserColumns`, then list the ones a sign-up body may set with [`auth.WithSignUpFields`](ds:block?id=opt-withsignupfields-8mn3wq7k). This is from [`examples/signup-fields`](../../examples/signup-fields/main.go). The columns are NOT NULL with a default, so an account that skips a field still has a value; the plan is declared but not listed, because billing code sets it:

<!-- ds:block id=signup-fields-columns-p4w8kz2m -->
**appColumns** · [`examples/signup-fields/main.go:104-109`](../../examples/signup-fields/main.go#L104-L109)

```go
var appColumns = []auth.ColumnExtension{
	{Name: colCompany, Type: auth.ColumnText, Default: "''"},
	{Name: colSeats, Type: auth.ColumnInt, Default: "1"},
	{Name: colNewsletter, Type: auth.ColumnBool, Default: "false"},
	{Name: colPlan, Type: auth.ColumnText, Default: "'free'"},
}
```
<!-- /ds:block hash=c5510f -->

<!-- ds:block id=signup-fields-newauth-7mq2vx9k -->
**newAuth** · [`examples/signup-fields/main.go:116-129`](../../examples/signup-fields/main.go#L116-L129)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
		auth.WithUserColumns(appColumns...),
		// Only what a stranger may choose. colPlan grants something, so the
		// app's billing code writes it, never the sign-up form.
		auth.WithSignUpFields(colCompany, colSeats, colNewsletter),
	)
}
```
<!-- /ds:block hash=43f3c1 -->

A sign-up sends the fields, each with its column's JSON type, and the app's `/me` reads them back with `a.LoadUserColumns`:

```sh
O='Origin: http://localhost:8081'
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple","fields":{"app_company":"Acme","app_seats":5,"app_newsletter":true}}'
curl -s -b cookies.txt localhost:8081/me
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"bob@example.com","password":"correct horse battery staple","fields":{"app_plan":"enterprise"}}'
```

```json
{"user":{"id":"usr_3nkocadgsw5nl32c7d4mr7lo","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_3nkocadgsw5nl32c7d4mr7lo","company":"Acme","seats":5,"newsletter":true,"plan":"free"}
{"error":{"code":"auth.field_invalid","message":"A field in this request cannot be set, or has the wrong type."}}
```

Check: `TestSignupFields_Refusals` in the example refuses an unlisted column, a core column, a wrong type, `null` on a NOT NULL column, a column sent twice and an unknown top-level key, and the address is still free after each.

The same columns may also sit at the top level of the body: `{"identifier":…,"password":…,"app_company":"Globex"}` works too. A top-level key that is not a listed column is refused as any unknown key always was (`400 auth.bad_request`), and a column sent both at the top level and in `fields` is `400 auth.field_invalid`.

Each value must have its column's JSON type: a string for `text`, an integer for `int`, a boolean for `bool`, an RFC 3339 string for `timestamp`, and `null` only for a nullable column. A field that is not listed (including a core column such as `name`), or has the wrong type, is `400 auth.field_invalid` before any row is written. The values are written through the core's column writer in the sign-up transaction, never by raw SQL. List only what a stranger may choose: anything in `WithSignUpFields` is set by whoever signs up, so a column that grants something (a plan that is paid for, a role) belongs in your own code after the payment or the check. The same `fields` object works on `phone/sign-in` and `email/sign-in-code` for the account a code creates.

The optional `image` field sets the user's picture (`auth_user.image`), and `remember: false` makes the sign-up session end with the browser, exactly as on sign-in. Two fields of the answer matter to a frontend. `verificationRequired` is true when the identifier's plugin was given `RequireVerified()`: the account exists but no session was issued, and the next screen is "check your inbox". `secondFactorRequired` is true when the user has [two-factor](twofactor.md) on: the session is pending until the code is given.

<!-- ds:block id=signinresult-ucfp8fef -->
**SignInResult** · [`plugin/password/password.go:746-756`](../../plugin/password/password.go#L746-L756)

```go
type SignInResult struct {
	User auth.UserView `json:"user"`
	// VerificationRequired is true when sign-up created the account but the
	// identifier must be verified before the first sign-in; no session was
	// issued.
	VerificationRequired bool `json:"verificationRequired"`
	// SecondFactorRequired is true when the session is pending: the client
	// must pass the user's second factor before it signs anyone in.
	SecondFactorRequired bool       `json:"secondFactorRequired"`
	Token                auth.Token `json:"-"`
}
```
<!-- /ds:block hash=ce8005 -->

What a refused sign-up looks like. A short password and an identifier no plugin accepts:

```sh
curl -s -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' -d '{"identifier":"bob@example.com","password":"short"}'
curl -s -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' -d '{"identifier":"not an address","password":"correct horse battery staple"}'
```

```json
{"error":{"code":"password.too_short","message":"Choose a longer password."}}
{"error":{"code":"auth.identifier_invalid","message":"This does not look right. Check it and try again."}}
```

Signing up with an address that someone has already verified is not refused: that answer would tell anyone which addresses have accounts. The sign-up succeeds as a separate, unverified account that can never verify the address, and the owner is told:

```sh
curl -s -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' -d '{"identifier":"alice@example.com","password":"another passphrase here"}'
```

```json
{"user":{"id":"usr_lt6y3jvvtmfzvheaipgxt7qz","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

```text
2026/10/01 10:27:10 mail to=alice@example.com subject="Someone tried to sign up with your address"
Someone tried to create an account with this email address. You already have one.

If this was you, sign in instead. If it was not, you do not need to do anything.
```

From Go, the same operation is `pw.SignUp`. Inside `a.Tx` it joins the app's transaction, so the app can create its own rows in the same commit; this is from [`examples/saas-workspace`](../../examples/saas-workspace/main.go):

<!-- ds:block id=saas-signup-nw9pz4mq -->
**signup** · [`examples/saas-workspace/main.go:189-214`](../../examples/saas-workspace/main.go#L189-L214)

```go
func signup(ctx context.Context, a *auth.Auth, pw *password.Plugin, in signupRequest) (signupResponse, error) {
	name := strings.TrimSpace(in.Workspace)
	if name == "" {
		return signupResponse{}, errWorkspaceName
	}
	var out signupResponse
	err := a.Tx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		res, err := pw.SignUp(ctx, password.SignUpRequest{Identifier: in.Email, Password: in.Password, Name: in.Name})
		if err != nil {
			return err
		}
		id, err := a.NewID(workspaceIDPrefix)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, insertWorkspace, id, name, res.User.ID); err != nil {
			if auth.IsUniqueViolation(err) {
				return errWorkspaceTaken
			}
			return err
		}
		out = signupResponse{User: res.User, Workspace: Workspace{ID: id, Name: name}}
		return nil
	})
	return out, err
}
```
<!-- /ds:block hash=ee37ed -->

## Step 3 — Sign in

`POST /auth/password/sign-in` takes the identifier and the password. `remember` is the "remember me" box: leave it out (or send `true`) for a session that outlives the browser; send `false` for one that ends with it, which is a cookie without an expiry.

```sh
curl -si -c cookies.txt -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"a brand new passphrase","remember":false}'
```

```text
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: __Host-auth_session=-Mrh2hf_k3TlO_6NEKtW66Mtd5xhy4OunjZlf1VDVNc; Path=/; HttpOnly; Secure; SameSite=Lax
Date: Thu, 01 Oct 2026 04:57:09 GMT
Content-Length: 131

{"user":{"id":"usr_6h57utnyiaovn2aiblbubqx2","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

<!-- ds:block id=signinrequest-w2xepzbx -->
**SignInRequest** · [`plugin/password/password.go:728-734`](../../plugin/password/password.go#L728-L734)

```go
type SignInRequest struct {
	Identifier string `json:"identifier"`
	Password   Secret `json:"password"`
	// Remember is the "remember me" box. Nil means remember, the usual
	// default; false makes a transient session that ends with the browser.
	Remember *bool `json:"remember,omitempty"`
}
```
<!-- /ds:block hash=dd2132 -->

Every refusal is the same answer: an unknown identifier, a wrong password, an account that has no password (one created through a social provider), and a password over the maximum length. They also take the same time, because an unknown account is checked against a dummy hash made with the same cost. Only a caller who knows the password learns that the address still needs verifying (`auth.not_verified`, when the email plugin has `RequireVerified()`).

```sh
curl -s -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
```

```json
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
```

Guessing is bounded per account as well as per IP, so a guess spread over many addresses still stops at [5](ds:block?id=signinaccountlimit-yz756w5r) attempts in 15 minutes. The rule counts attempts, not failures; three sign-ins had already been made in this transcript, so the third one here is the sixth:

```sh
for i in 1 2 3; do curl -s -i -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"wrong wrong wrong"}' | grep -E '^HTTP|Retry-After|error'; done
```

```text
HTTP/1.1 401 Unauthorized
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
HTTP/1.1 401 Unauthorized
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
HTTP/1.1 429 Too Many Requests
Retry-After: 900
{"error":{"code":"auth.rate_limited","message":"Too many attempts. Wait a moment and try again."}}
```

The real owner is slowed too while someone guesses; that is the cost of stopping a distributed guess. See [Rate limits](../concepts/rate-limits.md) for the per-IP rules ([20](ds:block?id=signiniplimit-a4yqscxz) sign-ins a minute, [10](ds:block?id=signupiplimit-q4rubgct) sign-ups an hour) and for sharing counters between instances.

From Go:

<!-- ds:block id=plugin-signin-25e2758f -->
**Plugin.SignIn** · [`plugin/password/password.go:834-836`](../../plugin/password/password.go#L834-L836)

```go
func (p *Plugin) SignIn(ctx context.Context, in SignInRequest) (SignInResult, error) {
	return p.signIn.Call(ctx, in)
}
```
<!-- /ds:block hash=2f6ee7 -->

The context must come from `a.WithRequest` (what `authhttp` and the framework adapters do for you) so the operation knows the client for the session row and for the per-IP rule; a plain `context.Background()` works for a script and is simply not rate limited by IP. The result's `Token` is the raw session token for Go callers: it is never encoded into JSON.

## Step 4 — Forgot and reset

`POST /auth/password/forgot` takes the identifier and always answers the same, whether or not an account exists. The link goes only to a verified recovery identity of the account (an address with `email.Recover()`, a number with `phone.Recover()`), never to the value typed, so an unverified row someone else added cannot receive it, and an account with no verified recovery identity simply gets no mail.

```sh
curl -s -X POST localhost:8081/auth/password/forgot -H 'Origin: http://localhost:8081' -d '{"identifier":"alice@example.com"}'
curl -s -X POST localhost:8081/auth/password/forgot -H 'Origin: http://localhost:8081' -d '{"identifier":"nobody@example.com"}'
```

```json
{"status":"check_your_inbox"}
{"status":"check_your_inbox"}
```

```text
2026/10/01 10:26:27 mail to=alice@example.com subject="Reset your password"
Open this link to choose a new password:

http://localhost:8081/reset-password?token=HjGKG5mKjy99D0RXGvDP84BF3iA1S1Xy-YN8t_gC6bw

If you did not ask for this, ignore this email. Your password has not changed.
```

The link opens a page of your app at [`/reset-password`](ds:block?id=defaultresetpage-368asg23) with the token in the query. The page shows a new-password form and POSTs the token with the new password to `POST /auth/password/reset`; a link that performed the reset on GET would be spent by the mail scanners that prefetch links. The token works once and for [one hour](ds:block?id=defaultresetttl-2vkb6wb9). A reset applies the same rules as sign-up, spends every other open reset link, and signs out every session, because a reset is often the answer to a stolen account:

```sh
curl -s -X POST localhost:8081/auth/password/reset -H 'Origin: http://localhost:8081' -d '{"token":"HjGKG5mKjy99D0RXGvDP84BF3iA1S1Xy-YN8t_gC6bw","password":"short"}'
curl -s -X POST localhost:8081/auth/password/reset -H 'Origin: http://localhost:8081' -d '{"token":"HjGKG5mKjy99D0RXGvDP84BF3iA1S1Xy-YN8t_gC6bw","password":"a brand new passphrase"}'
curl -s -X POST localhost:8081/auth/password/reset -H 'Origin: http://localhost:8081' -d '{"token":"HjGKG5mKjy99D0RXGvDP84BF3iA1S1Xy-YN8t_gC6bw","password":"third passphrase!"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"error":{"code":"password.too_short","message":"Choose a longer password."}}
{"ok":true}
{"error":{"code":"auth.token_invalid","message":"This link or code is not valid any more."}}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

A refused reset (too short) did not spend the token, so the user can try again from the same link. From Go: `pw.Forgot(ctx, identifier)` and `pw.Reset(ctx, password.ResetRequest{Token, Password})`.

## Step 5 — Change

`POST /auth/password/change` takes the current password and the new one. It needs a fresh session (one created in the last [10 minutes](ds:block?id=defaultfreshwindow-5mt8jqw7); see [Sessions](../concepts/sessions.md)), or the answer is `auth.fresh_session_required` and the frontend asks for the password again through [re-authentication](#re-authentication)), so a laptop left open cannot have its password changed by whoever sits down. A change signs out every other session and spends every open reset link, so a reset link requested before the change cannot undo it.

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/password/change -H 'Origin: http://localhost:8081' -d '{"current":"not it","new":"next passphrase here"}'
curl -s -b cookies.txt -X POST localhost:8081/auth/password/change -H 'Origin: http://localhost:8081' -d '{"current":"a brand new passphrase","new":"next passphrase here"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"ok":true}
{"id":"usr_6h57utnyiaovn2aiblbubqx2","hello":"Alice"}
```

A user who has no password yet, because the account was created by a social sign-in or a magic link, sets the first one through the same route with `current` left empty. `HasPassword` tells a settings page which label to show:

<!-- ds:block id=plugin-haspassword-t7q6avak -->
**Plugin.HasPassword** · [`plugin/password/password.go:979-985`](../../plugin/password/password.go#L979-L985)

```go
func (p *Plugin) HasPassword(ctx context.Context, userID string) (bool, error) {
	_, err := p.load(ctx, userID)
	if errors.Is(err, sqlb.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
```
<!-- /ds:block hash=197b9b -->

<!-- ds:block id=mehandler-a3yb2ukz -->
**meHandler** · [`examples/password-policies/main.go:165-177`](../../examples/password-policies/main.go#L165-L177)

```go
func meHandler(a *auth.Auth) http.Handler {
	pw := passwordPlugin(a)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := authhttp.MustUser(r)
		has, err := pw.HasPassword(r.Context(), u.ID)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, HasPassword: has}) // a client that hung up cannot be told
	})
}
```
<!-- /ds:block hash=7861e7 -->

### Asking for the password again

`POST /auth/password/verify` takes `{"password": "…"}` and answers `{"ok": true}` when it is the signed-in user's password, for an app step that wants the password typed again before something sensitive (showing a recovery key, deleting the account). It changes nothing. A wrong password, an over-long one, or an account that has no password all answer `password.invalid_credentials`, with the same argon2 cost as sign-in, and the route is rate limited per IP like sign-in. From Go: `pw.Verify(ctx, password)`. For actions the library itself guards, the fresh-session rule (`auth.FreshSignIn`) is usually the better tool: it asks for a recent sign-in rather than a retyped password.

### Re-authentication

`POST /auth/password/reauthenticate` takes `{"password": "…"}` from a signed-in user and makes the session they hold fresh again for the `FreshSignIn` operations, without a new session or a new cookie (see [Sessions](../concepts/sessions.md#prove-it-is-still-you-re-authentication)). The password is checked exactly as `verify` checks it: same argon2 cost for a user without a password, same `password.invalid_credentials` for every refusal, and a refusal ends nothing. A user without a second factor gets `{"fresh":true,"freshUntil":"…","secondFactorRequired":false}`. A user whose second factor is due (a password proves one factor, so [`twofactor.DefaultPolicy`](twofactor.md#re-authentication) asks) gets `{"fresh":false,"secondFactorRequired":true,"ticket":"…"}`, and the client finishes at `POST /auth/twofactor/reauthenticate`. It is [rate limited](ds:block?id=password-reauthlimits-6wq3nx8p) per IP and per account like sign-in. From Go: `pw.Reauthenticate(ctx, password)`.

The difference from `verify`: verify only answers whether the password is right, which the app's own steps use; reauthenticate is what the library's own `FreshSignIn` guards accept.

### Setting a password from server code

`pw.SetPassword(ctx, userID, password)` sets or replaces a user's password with no current password and no session: a support flow for a locked-out user, an admin tool, an import. It has no HTTP route on purpose, because any client-reachable form of it is account takeover. The new password passes the same rules as sign-up, every open reset link is spent, and every session of the user is signed out, since whoever holds them may not be the person the password is being set for. An unknown user id is `auth.ErrUserNotFound`. It runs in one transaction, or joins the one in `ctx` (see [Transactions](../concepts/transactions.md)).

## Step 6 — Rules for new passwords

The defaults follow NIST SP 800-63B: at least [8](ds:block?id=defaultminlength-8nyr776x) characters, at most [256](ds:block?id=defaultmaxlength-zux6j6ma) bytes, no composition rule. The maximum is what bounds the argon2 work an anonymous request can cause; sign-in refuses a longer password before hashing. [`examples/password-policies`](../../examples/password-policies/main.go) adds the rules a product may have to have:

<!-- ds:block id=newauth-w7tbnaeb -->
**newAuth** · [`examples/password-policies/main.go:119-133`](../../examples/password-policies/main.go#L119-L133)

```go
func newAuth(db *sql.DB, m email.Mailer, breaches password.BreachChecker) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(
				password.MinLength(minLength),
				password.RequireClasses(classes),
				password.Policy(noCompanyName),
				password.CheckBreached(breaches),
			),
		),
	)
}
```
<!-- /ds:block hash=56a02b -->

Length is always checked first, then each `Policy` in the order given, then the breach check. A policy gets the new password in clear and returns `nil` to accept it; return your own `*auth.Error` to give the client a code it can show a message for, or any other error for the generic `password.weak`:

<!-- ds:block id=errcompanyname-e4xkw4bu -->
**ErrCompanyName** · [`examples/password-policies/main.go:90`](../../examples/password-policies/main.go#L90-L90)

```go
var ErrCompanyName = auth.NewError("acme.password_company_name", http.StatusBadRequest, "The password must not contain the company name.")
```
<!-- /ds:block hash=71cf23 -->

<!-- ds:block id=nocompanyname-uxgxwbsh -->
**noCompanyName** · [`examples/password-policies/main.go:140-145`](../../examples/password-policies/main.go#L140-L145)

```go
func noCompanyName(pw string) error {
	if strings.Contains(strings.ToLower(pw), forbidden) {
		return ErrCompanyName
	}
	return nil
}
```
<!-- /ds:block hash=134a90 -->

The same rules apply at sign-up, reset and change. Existing passwords are not re-checked: a user whose password predates a new rule still signs in, and meets the rule at their next change.

### Breached passwords

`CheckBreached` takes anything that answers "is this password known from a breach":

<!-- ds:block id=breachchecker-qa5hp5a3 -->
**BreachChecker** · [`plugin/password/password.go:213-215`](../../plugin/password/password.go#L213-L215)

```go
type BreachChecker interface {
	Breached(ctx context.Context, password string) (bool, error)
}
```
<!-- /ds:block hash=2db006 -->

Package `hibp` (in the same module) is a client of the Have I Been Pwned range API. Only the first five hex characters of the password's SHA-1 leave the process; the service answers every suffix it knows under that prefix and the match happens locally, so the service never learns the password or even whether it matched. Answers are padded, so their size does not hint at the prefix either. When the service cannot be reached the sign-up fails with that error, because a check that silently passes is a check that never runs; `hibp.FailOpen()` is the named way to prefer availability. `hibp.WithBaseURL` points it at a mirror, or at a test server, which is what the example's test does. `hibp.WithMessage("…")` words the refusal: the client still gets the code `password.breached` with status 400, and an `auth.WithMessages` catalogue entry for that code still wins in its locale. Your own checker can do the same by also implementing `password.BreachMessenger`.

When a check refuses a breached password, the plugin also emits one `password.compromised` event to the security stream (`auth.WithSecuritySink`), once per check call, at sign-up, password change, reset and admin set alike, and for any `BreachChecker`, not only `hibp`. It has severity warn and outcome blocked, names the operation, and carries no password, no hash prefix and no account (a sign-up has none yet), so a sink can ship it as it stands. With no sink registered it costs nothing.

### Spraying and credential stuffing

The per-IP and per-account rate rules stop one address hammering one account. They do not see an attack spread thin: one common password tried once against each of thousands of accounts from thousands of addresses (spraying), or leaked email-and-password pairs each tried once (stuffing). `password.GuardCredentialStuffing` guards against that, off by default:

```go
pw := password.New(password.GuardCredentialStuffing(password.StuffingPolicy{
	PasswordFailures: 10,               // one password failed on 10 sign-ins, any accounts, any IPs: refused (default 10)
	GlobalFailures:   500,              // 500 failed sign-ins in the window, all accounts: every sign-in refused (default off)
	Window:           15 * time.Minute, // counting window and refusal length (default 15 minutes)
}))
```

Every failed password sign-in, for an account that exists or not, is counted in the core's rate store under an HMAC of the password keyed from `auth.WithSecret` (the store never holds the password, nor a hash anyone can test guesses against without the secret), and with `GlobalFailures` under one global counter too. Before the password is checked, a sign-in whose password is over its limit, or any sign-in while the global count is over its limit, is refused with `429 auth.rate_limited` and a `Retry-After` of the window. Refusing before the check means the answer never tells a guesser whether a refused guess was right, and the counts only ever grow on failures, so a person typing their own password correctly is never counted. Crossing a limit logs a warning and, when a [security sink](../concepts/security-events.md) is registered, emits one `credential.stuffing` event (severity `alert`, attributes `scope` = `password` or `global`, `failures` and `window`, no password): once per window and scope, at the moment the count reaches the limit, not on each refusal that follows, with the outcome `blocked`, or `logged` under `LogOnly`. `LogOnly: true` counts and logs but refuses nothing, for tuning the numbers on real traffic first.

Risk, and why it is opt-in: everyone whose password is the sprayed one is refused for the window, the right password included, and the global rule refuses every user while an attack keeps the failures up, so it turns a stuffing run into an outage for its length. `auth.New` logs a warning at every start while the guard refuses. It needs `auth.WithSecret` (`auth.ErrNoSecret` at `auth.New`) and a rate store that can read a count without adding to it (`auth.RatePeeker`: the memory, database and storage stores and `contrib/redis` are); on another store `auth.New` fails with `auth.ErrRatePeekUnsupported` rather than run unguarded. Run more than one instance with a shared store, or each instance counts alone. A "challenge" action is not offered by this guard: over its limit it refuses, or only logs under `LogOnly`. To challenge a busy address instead of refusing it, give a rate rule the `auth.RateChallenge` action, answered by `plugin/captcha` or [`plugin/pow`](pow.md) ([rate limits, Step 5](../concepts/rate-limits.md#step-5--choose-what-a-rule-does-over-its-limit)).

## Step 7 — Run a password's lifecycle: reset by code, history, expiry

Three opt-in policies change what happens to a password after sign-up, for products a compliance regime or a customer's security questionnaire holds to them. The example [`examples/password-lifecycle`](../../examples/password-lifecycle/) turns all three on, with the spraying guard from the section above, and its test walks one password through them:

<!-- ds:block id=newauth-pwl7cy02 -->
**newAuth** · [`examples/password-lifecycle/main.go:110-126`](../../examples/password-lifecycle/main.go#L110-L126)

```go
func newAuth(db *sql.DB, secret []byte, m email.Mailer, now func() time.Time) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret),
		auth.WithClock(now),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(
				password.ResetByCode(),
				password.History(historySize),
				password.ExpireAfter(maxPasswordAge),
				password.GuardCredentialStuffing(password.StuffingPolicy{PasswordFailures: sprayFailures}),
			),
		),
	)
}
```
<!-- /ds:block hash=89da3a -->

<!-- ds:block id=lifecyclepolicy-pwl7cy01 -->
**historySize** · [`examples/password-lifecycle/main.go:45-56`](../../examples/password-lifecycle/main.go#L45-L56)

```go
const (
	// historySize is how many passwords a user cannot go back to, counting
	// the one in use.
	historySize = 3
	// maxPasswordAge is how long a password signs in before it must be
	// changed. NIST SP 800-63B advises against expiry; set it only when a
	// policy requires it.
	maxPasswordAge = 90 * 24 * time.Hour
	// sprayFailures is how many failed sign-ins with one password, across
	// every account and IP, refuse that password for the guard's window.
	sprayFailures = 5
)
```
<!-- /ds:block hash=73d302 -->

`auth.WithClock` is there only so the test can age a password by 90 days; `main` passes `time.Now`. `auth.WithSecret` is there for the spraying guard, which counts each failed password under a key derived from it.

### Reset by code instead of a link

`password.ResetByCode()` makes `forgot` mail (or text) a one-time code instead of a link, and replaces `POST /auth/password/reset` with `POST /auth/password/reset-code`, which takes the identifier, the code and the new password. Use it in a phone-first app, where a link in a text is awkward, or in a flow that keeps the person on one screen. No base URL or `ResetLinks` is needed. The code goes to an address or number the user verified, lives `ResetTTL`, and is spent after a few wrong guesses; an unknown identifier and a wrong, spent or expired code all answer `auth.code_invalid`, so the route tells nobody which accounts exist.

```sh
O='Origin: http://localhost:8081'
curl -s -X POST localhost:8081/auth/password/forgot -H "$O" -d '{"identifier":"alice@example.com"}'
curl -s -X POST localhost:8081/auth/password/reset-code -H "$O" -d '{"identifier":"alice@example.com","code":"584616","password":"third-long-password"}'
curl -s -X POST localhost:8081/auth/password/reset-code -H "$O" -d '{"identifier":"alice@example.com","code":"584616","password":"fourth-long-password"}'
```

```text
{"status":"check_your_inbox"}
2026/10/09 08:39:20 mail to=alice@example.com subject="Your password reset code"
Your password reset code is 584616.

If you did not ask for this, ignore this email. Your password has not changed.
{"ok":true}
{"error":{"code":"auth.code_invalid","message":"This code is not right, or it has expired."}}
```

From Go, `pw.ResetWithCode(ctx, password.ResetCodeRequest{Identifier: …, Code: …, Password: …})`. A reset signs out every session unless `KeepSessionsOnReset()`.

### Refuse a recent password

`password.History(n)` refuses a new password that matches the one in use or any of the n-1 before it, with `password.reused` (400). It applies to change, reset, reset-code, change-expired and `SetPassword`; sign-up and `ImportHash` have no earlier password. The earlier hashes live in `auth_password_history`, which the next `a.Migrate` creates once the option is set. n runs from 1 to [`MaxHistory`](ds:block?id=maxhistory-r25pwh01), because each remembered hash costs one argon2 check per change.

```sh
curl -s -b alice.txt -c alice.txt -X POST localhost:8081/auth/password/change -H "$O" -d '{"current":"first-long-password","new":"second-long-password"}'
curl -s -b alice.txt -c alice.txt -X POST localhost:8081/auth/password/change -H "$O" -d '{"current":"second-long-password","new":"first-long-password"}'
```

```json
{"ok":true}
{"error":{"code":"password.reused","message":"Choose a password you have not used recently."}}
```

`password.reused` is reached only by someone who already proved the account (a fresh session with the current password, a reset link or code), so it tells a stranger nothing. Turning `History` off later stops the writes and leaves the table; drop it if you want the hashes gone.

### Expire passwords

`password.ExpireAfter(d)` makes a password stop signing in d after it was set (by sign-up, change, reset, `SetPassword` or `ImportHash`). Sign-in with the right, expired password answers `password.expired` (403) and issues no session; a wrong password still answers `password.invalid_credentials`, so only the owner learns the password expired. The client then posts the identifier, the expired password and a new one to `POST /auth/password/change-expired` (`pw.ChangeExpired`), which refuses the same password again, changes it, signs out every other session and signs in. Sessions that already exist are not ended when a password expires; expiry is checked at sign-in only.

A live run cannot wait 90 days, so the example's test moves the clock instead. `TestPasswordLifecycle_HistoryResetAndExpiry` checks each answer in turn: `password.expired` for the right password, `password.invalid_credentials` for a wrong one, `password.reused` from change-expired with the same password, and a signed-in `/me` after change-expired with a new one. NIST SP 800-63B advises against forced periodic changes; set `ExpireAfter` only when a policy requires it.

### The spraying guard in the same run

With `PasswordFailures: 5`, five failed sign-ins with one password on five different accounts refuse that password for everyone, before it is checked:

```sh
for i in 0 1 2 3 4; do curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -d "{\"identifier\":\"user$i@example.com\",\"password\":\"Winter2026!\"}"; done
curl -si -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"alice@example.com","password":"Winter2026!"}'
```

```text
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
Retry-After: 900
Date: Fri, 09 Oct 2026 03:09:21 GMT
Content-Length: 94

{"error":{"code":"auth.rate_limited","message":"Too many attempts. Wait a moment and try again."}}
```

The server logs `WARN password: one password failed on many accounts (password spraying) failures=5 window=15m0s`. Check: `TestPasswordLifecycle_SprayedPasswordIsRefused` also signs in a second user with a password of their own while the sprayed one is refused.

## Bringing passwords from another stack

A product that moves to this library usually arrives with a user table and a column of hashes from somewhere else: bcrypt from Rails, Laravel or Spring, `pbkdf2_sha256$…` from Django, `hexsalt:hexkey` scrypt (16-byte salt, 64-byte key). Asking every user to reset on day one is the migration nobody wants, so the plugin verifies those formats and replaces them as users sign in.

1. Create the user (`auth.CreateUser` plus `CreateIdentity` for their address) and store the old hash string, unchanged, with `pw.ImportHash(ctx, userID, hash)`. It writes `auth_password` for you and refuses a string no configured verifier recognizes (`password.hash_unrecognized`), so a column copied from the wrong table fails at import time rather than at the user's first sign-in; a user who already has a password is refused too (`password.has_password`). Nothing writes the table by hand.
2. List a verifier per format: `password.New(password.AcceptLegacyHashes(password.Bcrypt(), password.DjangoPBKDF2(), password.Scrypt(password.BetterAuthScrypt)))`. The first verifier that recognizes a stored string decides; an argon2id string is always the plugin's own.
3. Nothing else. At the user's next successful sign-in the plugin verifies the old hash and, in the same transaction, stores an argon2id hash in its place; a wrong password changes nothing. Change and verify accept the old hash as the current password too.

Three things to know. A stored string that no verifier recognizes is a server error at sign-in, not `invalid_credentials`, so a column copied from the wrong table shows up in your logs rather than as users locked out. Until a user has signed in once, their sign-in costs the old algorithm's time while an unknown identifier costs argon2id's; that difference is inherent in verifying foreign hashes and ends with the re-hash. And `Scrypt` checks the password as typed, without NFKC normalization: where the old stack normalized to NFKC before hashing, the rare password whose NFKC form differs verifies only after a reset. Your own format goes behind the `Verifier` interface (`Recognizes` by shape, `Verify` in constant time, an error for a corrupt string); your own algorithm for new hashes behind `Hasher`, through `password.WithHasher`.

## Options you may want

| You want | Do |
|---|---|
| Refuse password spraying and credential stuffing spread over many IPs | `password.GuardCredentialStuffing(password.StuffingPolicy{...})`; see [Spraying and credential stuffing](#spraying-and-credential-stuffing) for the risk. |
| No password reset at all (a username-only app, or reset handled by support) | `password.WithoutRecovery()`. The forgot and reset routes do not exist, and `auth.New` no longer asks for a recovery identifier. |
| No self-service sign-up (accounts come from an invite, an admin or a social sign-in) | `password.WithoutSignUp()`. The sign-up route is 404 and its rate rules are gone; `pw.SetPassword` or another plugin creates the credential. The core's `auth.WithDisabledOperations(password.EndpointSignUp)` is the app-side way to the same end. |
| An account created at sign-up but no session until the user signs in | `password.SignUpWithoutSession()`. The result carries the user and no token. An identifier kind with `RequireVerified()` already behaves this way. |
| Your own reset page URL, or a deep link into a mobile app | `password.ResetLinks(func(t auth.Token) string { ... })`. The function builds the whole link from the token. |
| A reset page chosen per request | Send `"redirectTo"` with forgot (`pw.ForgotWith(ctx, password.ForgotRequest{Identifier, RedirectTo})`): a path of your site, or an http(s) URL on an origin in `auth.WithTrustedOrigins`. The link is that page with `?token=…` added. Anything else, a custom scheme or a loopback address included, answers `password.redirect_invalid` and sends nothing, so it is never an open redirect and a token never goes to an address another app can claim. |
| Sessions kept alive through a reset or a change | `password.KeepSessionsOnReset()` keeps every session after a reset; `password.KeepSessionsOnChange()` keeps the other sessions after a change unless the request sends `"revokeOtherSessions": true`. The risk is the reason they are off: someone who already stole a session keeps it after the owner resets or changes the password. Open reset links are spent and trusted devices forgotten either way. Without the change option, `revokeOtherSessions` is ignored, so a client cannot weaken the default. |
| A reset by code instead of a link (phone-first apps, or a flow that stays on one screen) | `password.ResetByCode()`: forgot sends a one-time code by text or mail, and `POST /auth/password/reset-code` takes `{"identifier":"…","code":"123456","password":"…"}` (`pw.ResetWithCode`). Unknown identifier, wrong, spent or expired code are all `auth.code_invalid`. The `/reset` route and the need for a base URL go away. See [Step 7](#reset-by-code-instead-of-a-link). |
| A username chosen at sign-up, in the same call as the email address | Wire the [username plugin](username.md) and send `"username"` in the sign-up body: the handle is claimed in the sign-up transaction, so a taken or reserved one fails the whole sign-up (`auth.identity_taken`, `username.reserved`) and leaves no account. Without the plugin the field is `password.no_usernames`. An app with its own handle scheme registers any plugin with `ClaimWithDisplay(ctx, userID, handle, display string) error` (`password.UsernameClaimer`) instead; its error fails the sign-up the same way. |
| A shorter or longer reset window | `password.ResetTTL(d)`; the default is [one hour](ds:block?id=defaultresetttl-2vkb6wb9). |
| A different hash cost | `password.Argon2(password.Argon2Params{Memory, Time, Threads})`. The default is 64 MiB, 3 passes, 2 lanes (OWASP). Existing hashes are re-hashed at the user's next successful sign-in, so changing the cost needs no migration. |
| Users imported from Rails, Laravel, Django or a scrypt-based stack, with their old hashes | `password.AcceptLegacyHashes(password.Bcrypt(), password.DjangoPBKDF2(), password.Scrypt(password.BetterAuthScrypt))`: copy the old hash strings into `auth_password` and each user signs in with their old password, which is re-hashed with argon2id in that same sign-in. Nobody resets. See [Bringing passwords from another stack](#bringing-passwords-from-another-stack). |
| Another hashing algorithm altogether (an HSM, a key-derivation service) | `password.WithHasher(h)` with your `Hasher`; list `password.Argon2id{Params: …}` in `AcceptLegacyHashes` if argon2id rows already exist. |
| Character classes | `password.RequireClasses(n)`: at least n of lowercase, uppercase, digits, everything else. |
| No going back to a recent password | `password.History(n)`: change, reset, change-expired and `SetPassword` refuse the current password and the n-1 before it with `password.reused`. The earlier hashes live in `auth_password_history`, which the next `a.Migrate` creates; n is at most 24, because each remembered hash costs one hash check per change. See [Refuse a recent password](#refuse-a-recent-password). |
| Passwords that expire | `password.ExpireAfter(d)`: once a password is d old, sign-in with it answers `password.expired` (403, and only to the right password) and issues no session. The client then posts `{"identifier","current","new"}` to `POST /auth/password/change-expired` (`pw.ChangeExpired`), which refuses the expired password itself, changes it, signs out every other session and signs in. NIST SP 800-63B advises against forced periodic changes, which is why it is off. See [Expire passwords](#expire-passwords). |
| Read who has a password | `pw.HasPassword(ctx, userID)`, or `SELECT` from `auth_password` (one row per user, keyed by `user_id`). The table is the plugin's to write; see [Databases](../concepts/databases.md). |

Combining with other plugins:

- [Two-factor](twofactor.md): nothing to wire on the password side. Sign-in returns `secondFactorRequired: true` and a pending session for a user with a factor on.
- [Magic links](magiclink.md) or [OAuth](oauth.md) alongside passwords: a user who signed up without a password sets one through change with an empty `current`; `HasPassword` tells the settings page which to offer.
- [Phone](phone.md) as the identifier: `phone.New(phone.Login(), phone.Recover(), ...)` and the reset link goes out as a text.
- [Ready-made pages](../integrations/ready-made-pages.md) serve the sign-in, sign-up, forgot, reset and change forms if you do not want to build them.

## From TypeScript

Use this when the sign-up, sign-in, forgot and change forms run in a browser, a mobile app or a Node program, rather than in Go templates. The [typed client](../client/README.md) calls the same routes as the curl lines above, checks every input at compile time, and resolves each call to `{ data, error }` instead of throwing. List the plugin next to the identifier plugin the server wires (`plugins: [email(), password()]`), and `twofactor()` too when the server has it, because a sign-in can then end pending.

Sign-up. The answer never says that an address is taken, so the form has three outcomes: a rule refused the password, the address must be verified first (`verificationRequired`, with `RequireVerified()`), or the user is signed in:

<!-- ds:block id=tsp-password-signup-4kw9qx2m -->
**signUp** · [`clients/ts/examples/plugin-password.ts:13-30`](../../clients/ts/examples/plugin-password.ts#L13-L30)

```typescript
export async function signUp(address: string, secret: string, name: string): Promise<string> {
  const { data, error } = await auth.password.signUp({ identifier: address, password: secret, name });
  if (error) {
    switch (error.code) {
      case "password.too_short":
      case "password.too_long":
      case "password.weak":
      case "password.breached":
        return `Choose another password: ${error.message}`;
      case "auth.identifier_invalid":
        return "Check the address.";
      default:
        return error.message;
    }
  }
  if (data.verificationRequired) return "Check your inbox to verify the address, then sign in.";
  return `Welcome, ${data.user.name}.`;
}
```
<!-- /ds:block hash=af0c11 -->

Sign-in. `secondFactorRequired` means the session is pending until [`twofactor.verify`](../client/flows.md#second-factor-the-pending-session) accepts a code; `error.retryAfter` carries the `Retry-After` seconds of a rate-limited answer:

<!-- ds:block id=tsp-password-signin-7mq3wk8n -->
**signIn** · [`clients/ts/examples/plugin-password.ts:34-49`](../../clients/ts/examples/plugin-password.ts#L34-L49)

```typescript
export async function signIn(address: string, secret: string): Promise<"signed-in" | "second-factor" | string> {
  const { data, error } = await auth.password.signIn({ identifier: address, password: secret });
  if (error) {
    switch (error.code) {
      case "password.invalid_credentials":
        return "The sign-in details are not right.";
      case "auth.not_verified":
        return "Verify your address first; we can send the link again.";
      case "auth.rate_limited":
        return `Too many attempts. Try again in ${error.retryAfter ?? 60} seconds.`;
      default:
        return error.message;
    }
  }
  return data.secondFactorRequired ? "second-factor" : "signed-in";
}
```
<!-- /ds:block hash=734837 -->

Changing the password needs a recent sign-in. When the session is older than the fresh window the call answers `auth.fresh_session_required`; the page proves the user on the session they already hold with `password.reauthenticate` (and `twofactor.reauthenticate` with the answered `ticket` when a second factor is due), then runs the change again. Signing in again would start a second session instead ([Re-authentication](#re-authentication)):

<!-- ds:block id=tsp-password-fresh-2nx8kq5w -->
**withFreshSession** · [`clients/ts/examples/plugin-password.ts:55-69`](../../clients/ts/examples/plugin-password.ts#L55-L69)

```typescript
export async function withFreshSession<T>(
  action: () => Promise<AuthResult<T>>,
  askForPassword: () => Promise<string>,
  askForCode: () => Promise<string>,
): Promise<AuthResult<T>> {
  const first = await action();
  if (first.error?.code !== "auth.fresh_session_required") return first;
  const proof = await auth.password.reauthenticate({ password: await askForPassword() });
  if (proof.error) return { data: null, error: proof.error };
  if (proof.data.secondFactorRequired) {
    const second = await auth.twofactor.reauthenticate({ code: await askForCode(), ticket: proof.data.ticket ?? "" });
    if (second.error) return { data: null, error: second.error };
  }
  return action();
}
```
<!-- /ds:block hash=497ad8 -->

<!-- ds:block id=tsp-password-change-6wq2mx9k -->
**changePassword** · [`clients/ts/examples/plugin-password.ts:74-81`](../../clients/ts/examples/plugin-password.ts#L74-L81)

```typescript
export async function changePassword(current: string, next: string, askForCode: () => Promise<string>): Promise<boolean> {
  const { error } = await withFreshSession(
    () => auth.password.change({ current, new: next }),
    async () => current,
    askForCode,
  );
  return error === null;
}
```
<!-- /ds:block hash=3937af -->

Forgot and reset are two calls from two pages, the form and the page the mailed link opens; they are in [Flows › Password reset](../client/flows.md#password-reset).

The codes a frontend handles, with the reasons and fixes in [What can go wrong](#what-can-go-wrong): `password.invalid_credentials` (one answer for a wrong password and an unknown account, never branch on which), `auth.not_verified`, `password.too_short`, `password.too_long`, `password.weak` and `password.breached` on a new password, `auth.identifier_invalid`, `auth.token_invalid` on a spent reset link, `auth.fresh_session_required` on change, `auth.rate_limited`.

Try it: `examples/ts-client-flows` runs sign-up, forgot, reset, a refused old password and sign-in with the new one from Node against a real server, and `examples/ts-client-bearer` runs sign-up, sign-in, `whoami` and sign-out as a CLI that keeps its token in a file; the commands and their output are in [Flows › Try it](../client/flows.md#try-it) and [Bearer and mobile › Try it](../client/bearer-and-mobile.md#try-it).

Pitfalls:

- **Reset signs nobody in.** `password.reset` answers `{ ok: true }` and, by default, ends every session of the user; the page sends the user to the sign-in form.
- **The prebuilt client has only the default routes.** `reset-code` (`ResetByCode()`) and `change-expired` (`ExpireAfter`) exist only on a server built with those options, so their methods are missing from the prebuilt `client.ts`; [generate the client from your app](../client/custom-plugins.md) to get them.
- **Re-authentication is rate limited like sign-in**, per account, so a script that confirms the password in a loop meets `auth.rate_limited`; within the fresh window one confirmation covers every guarded call.

Every method with its route and types: [TypeScript client reference › password](../reference/ts-client.md#password). Errors in general: [Errors](../client/errors.md).

## What can go wrong

| Answer | Why | Fix |
|---|---|---|
| `password.invalid_credentials` (401) | Wrong password, unknown identifier, no password on the account, over-long password at sign-in or verify, or wrong `current` at change. Deliberately one answer. | Show "the sign-in details are not right" and a link to forgot. Never branch on which it was: the server does not tell you. |
| `auth.not_verified` (409) at sign-in | The password was right, but the identifier's plugin has `RequireVerified()` and this one is not verified yet. | Offer "resend the verification mail" (`POST /auth/email/resend`). |
| `password.too_short`, `password.too_long`, `password.weak`, `password.breached` (400) | The new password failed a rule. | Show the message and let the user choose again. The reset token was not spent. |
| `auth.identifier_invalid` (400) at sign-up | No wired identifier plugin accepts the value. | Check the plugin list has the kind the user typed (an email plugin for addresses, a phone plugin with that country allowed). |
| `auth.token_invalid` (400) at reset | The link was used, expired, or is not one the server made. | Ask for a new link through forgot. |
| `auth.code_invalid` (400) at reset-code | Wrong, spent or expired code, or an identifier with no account; deliberately one answer. | Ask for a new code through forgot. |
| `password.redirect_invalid` (400) at forgot | `redirectTo` is not a path of your site or an http(s) URL on a trusted origin. | Add the origin with `auth.WithTrustedOrigins`, or send a path. |
| `password.no_usernames` (400) at sign-up | The body carried a username but the username plugin (or another `password.UsernameClaimer`) is not wired. | Wire `username.New(...)`, or drop the field. |
| `auth.fresh_session_required` (403) at change | The session was neither created nor re-authenticated within the fresh window. | `POST /auth/password/reauthenticate` with the password (and the second factor when it answers `secondFactorRequired`), then retry. |
| `auth.rate_limited` (429), `Retry-After` header | The per-IP or per-account rule tripped. | Show the wait. From Go, `auth.RetryAfter(err)` gives the duration. |
| The reset mail never arrives, but forgot answered `check_your_inbox` | The account has no verified recovery identity: the address was never verified, or the only identifier kind cannot recover. | Verify the address first; or give a plugin `Recover()`; or run with `WithoutRecovery()` and handle resets through support. |
| `auth.New` fails with `password: ...` | See Step 1. | Add the missing `Login()` / `Recover()` / base URL, or opt out by name. |

Known limits: there is no "password expiry" or history ("not one of your last five"); write a `Policy` for history if a product rule demands it, and expect pushback from NIST. Rate limits count per process unless you pass `auth.WithRateStore`; see [Rate limits](../concepts/rate-limits.md).

## Next

- [Two-factor](twofactor.md) adds an authenticator-app code on top of the password.
- [Passkeys](passkey.md) replace the password and the code with one gesture.
- [Security](../concepts/security.md) explains the origin check and enumeration safety this guide relied on.
- Reference: [plugin/password/README.md](../../plugin/password/README.md).
