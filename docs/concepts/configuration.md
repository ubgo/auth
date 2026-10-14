# Configuration

Every setting of the library is an option passed to `auth.New`. This page lists all of them, what each defaults to, and when to set it; the environment helper `auth.EnvOptions` reads the ones a deployment changes most.

## Before you start

- [Plugins and the pipeline](plugins-and-pipeline.md): `auth.New` validates the whole combination of options and plugins at once, so a bad setting is a failed start, not a failure on the first request.
- Options are functions, not a struct literal, on purpose: a literal would invite skipping `auth.New` and running an unvalidated instance. The resolved configuration is readable afterwards through `a.Config()`, as a copy.

The resolved settings are the [`auth.Config`](ds:block?id=core-config-vtej7aae) struct.

## Step 1 — The options every app sets

A database and its dialect, the public URL, and the plugins. The quick start sets exactly these:

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

| Option | What it sets | Default | Set it when |
| --- | --- | --- | --- |
| `auth.WithDB(db, dialect)` | The `*sql.DB` every statement runs on and the sqlb dialect that renders them (`sqlb.PostgresDialect{}`, `sqlb.MySQLDialect{}`, `sqlb.SQLiteDialect{}`). The app may use the same handle; `a.Tx` lets both write in one transaction. | none; without it every database call is `auth: no database configured; pass auth.WithDB` | always, except to only print the schema |
| `auth.WithDialect(dialect)` | Only the dialect, for building statements and migrations without a database. | Postgres | a tool that prints `MigrationSQL()` for an engine |
| `auth.WithDBAuto(db)` | `WithDB` with the dialect found by `auth.DetectDialect(ctx, db)`, as better-auth infers it from the pool you pass: by the driver's package first (pgx, lib/pq, go-sql-driver/mysql, modernc.org/sqlite, mattn/go-sqlite3, ncruces/go-sqlite3), at no cost, and for a driver it does not know by type (a tracing wrapper such as otelsql) by up to three probe queries inside `auth.New`, bounded by [five seconds](ds:block?id=core-detecttimeout-2wq8nd5k): `sqlite_version()` answers only on SQLite, `version()` names PostgreSQL only on Postgres, `@@version` answers only on MySQL and MariaDB. Anything else fails `auth.New` with `auth.ErrUnknownDialect`, never a guess. | none | you would rather not name the dialect; keep `WithDB` when `auth.New` must run no query |
| `auth.WithTablePrefix(prefix)` | The real name of every table, the core's and every plugin's, is `prefix` + its label (`billing_auth_user`), except a table `RenameTable` names. Every statement, every migration, every index and foreign key, the ledger, the schema check and `auth migrate orphans` use the real names; the Go constants (`auth.TableNameUser`) stay the labels, and `a.TableName(auth.TableUser)` gives the real name for SQL you write by hand. The prefix must be a plain identifier start; it is written verbatim. | none: the labels are the names | two apps, or two instances of one app, share one database or schema |
| `auth.RenameTable(table, name)` | One table's real name, used as given (no prefix). `table` is a declared table value — `auth.TableUser`, `auth.TableSession`, `apikey.TableKey`, any plugin's exported `Table…` — never a hand-built `sqlb.Table`: `auth.New` refuses a table that the core or a registered plugin does not declare (`auth.ErrUnknownTable`), two tables mapped to one name or a name another table already has (`auth.ErrTableNameConflict`), a name that is not a plain identifier or that makes a derived index name longer than 63 bytes (`auth.ErrBadTableName`), and, under renaming, a column named exactly like a table label. Decide before the first deploy: renaming a table that exists is an `ALTER TABLE … RENAME` you run yourself, because the ledger records what was created, not what it was called. | the label, or the prefixed label | a schema whose naming rules forbid `auth_`, or a table name your other tools expect |
| `auth.WithPlugins(p...)` | The plugins, in order. Calls accumulate, so a shared base list and a per-app list compose. | none; at least one sign-in method is required | always |
| `auth.WithBaseURL(url)` | The app's public URL. Its origin is trusted for cookie-authenticated mutations, and plugins build the links they mail from it. | empty: no origin is trusted and links are relative | always, in production |

<!-- ds:block id=opt-withdb-6nvjnp2w -->
**WithDB** · [`auth.go:460-467`](../../auth.go#L460-L467)

```go
func WithDB(db *sql.DB, d sqlb.Dialect) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithDB", d) {
			return
		}
		s.db, s.cfg.Dialect = db, d
	}
}
```
<!-- /ds:block hash=e383a8 -->

<!-- ds:block id=opt-withplugins-37cf99g2 -->
**WithPlugins** · [`auth.go:485-492`](../../auth.go#L485-L492)

```go
func WithPlugins(ps ...Plugin) Option {
	return func(s *settings) {
		if RefuseNilEach(&s.optErrs, "auth.WithPlugins", ps) {
			return
		}
		s.plugins = append(s.plugins, ps...)
	}
}
```
<!-- /ds:block hash=652572 -->

<!-- ds:block id=opt-withbaseurl-zkfj99z8 -->
**WithBaseURL** · [`auth.go:497`](../../auth.go#L497-L497)

```go
func WithBaseURL(u string) Option { return func(s *settings) { s.cfg.BaseURL = u } }
```
<!-- /ds:block hash=592126 -->

<!-- ds:block id=opt-withdialect-xuerha78 -->
**WithDialect** · [`auth.go:472-479`](../../auth.go#L472-L479)

```go
func WithDialect(d sqlb.Dialect) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithDialect", d) {
			return
		}
		s.cfg.Dialect = d
	}
}
```
<!-- /ds:block hash=2bebda -->

Check: `auth.New` returns no error, and `a.Config().BaseURL` is what you passed.

## Step 2 — Security settings

| Option | What it sets | Default | Set it when |
| --- | --- | --- | --- |
| `auth.WithAllowedHosts(hosts...)` | The hosts the deployment serves besides the base URL's, exact or `*.example.com`. A request on one of them gets `a.BaseURL(ctx)` = that host under the base URL's scheme, so the links plugins send point at the host the user is on, and each is a trusted origin without a second list. A request on any other host, or outside a request, gets the static base URL. The transport fills `Request.Host`. | only the base URL | preview deployments, a domain per customer |
| `auth.WithTrustedOrigins(origins...)` | More origins allowed to send cookie-authenticated mutations, as `scheme://host[:port]`, a custom scheme alone (`myapp://`), or a pattern: `*` and `?` in any label left of a fixed domain of [two labels or more](ds:block?id=core-minpatternsuffixlabels-2pw7xn4k). A first label that is `*` alone (`https://*.example.com`) spans one label or more; inside a label `*` is any run and `?` one character (`https://preview-*.example.com`, `https://app-?.example.com`), never crossing a dot. A pattern without a port matches any port. Each must be an absolute URL. | only the base URL's origin | an admin app or a second front end on another origin posts to the API with the session cookie; one front end per customer on your subdomains; a preview deployment per branch |
| `auth.WithTrustedOrigins("myapp://")`, `"com.example.app:/"` | A scheme-only entry names a native app's custom scheme. It is never an origin a browser sends (`TrustsOrigin` ignores it); it makes `a.TrustsReturnURL("myapp://signed-in")` true, so a flow may send the user back into the app. Any app on the device can register a scheme, so a return into one must carry nothing secret: the session travels as a bearer token in the response, never in the URL. | none | a mobile or desktop app finishes a browser flow by deep link |
| `auth.WithLoopbackReturn()` | A flow may send the browser back to `http://127.0.0.1:<any port>/…` or `http://[::1]:<any port>/…` (`TrustsReturnURL`), the return address of a native app that signs in through the system browser and listens on an ephemeral loopback port (RFC 8252 §7.3). Return URLs only: a loopback origin is never trusted for cookie-authenticated mutations, `localhost` by name is never accepted, and only `http`. | off: a loopback return needs its exact origin listed | a CLI or desktop app finishes a browser sign-in on a port it chose at run time |
| `auth.WithTrustedOriginFunc(fn)` | A function asked, per request, about an origin the list and the patterns did not accept. It must be fast and must answer `false` on its own failure. | none | the origins change while the process runs: one per tenant in a table, a preview deployment per branch |
| [`auth.WithFreshWindow(d)`](sessions.md#require-a-recent-sign-in-withfreshwindow) | How recent a sign-in or [re-authentication](sessions.md#prove-it-is-still-you-re-authentication) a `FreshSignIn` operation (change password, add a factor, remove an address) needs. Setting it to `auth.MaxSessionLifetime` turns freshness off: no session is older than that. | [ten minutes](ds:block?id=defaultfreshwindow-5mt8jqw7) | you want a shorter window; longer is rarely right |
| [`auth.WithDisabledOperations(ids...)`](#switch-an-operation-off-withdisabledoperations) | Operations switched off by id, such as `password.EndpointSignUp` for an app that creates accounts itself. A disabled operation has no route on any transport and its Go method returns `auth.ErrUnknownOperation`; an id nothing registered fails `auth.New`. Whole operations only: a plugin's rate rule cannot be removed. | none | a shipped operation must not be reachable in this deployment |
| [`auth.WithoutIPTracking()`](sessions.md#store-no-client-address-withoutiptracking) | Sessions record no client address; the session list shows none. `ByIP` rate rules still count. | addresses are stored | your privacy policy says so |
| `auth.WithAccountDeletion(d)` | Turns self-service deletion on. `POST /auth/account/delete` needs a fresh sign-in and deletes at once (`auth.AccountDeletion{}`); with `ConfirmByLink` it sends a link to the user's recovery channel instead, valid [an hour](ds:block?id=defaultdeleteaccountttl-9h3nxrwe) unless `LinkTTL` says otherwise and pointing at [`/account/delete`](ds:block?id=defaultdeleteaccountpage-6tz8vpqk) on the base URL unless `Link` builds it, and `POST /auth/account/delete/confirm` with the token deletes. | off: no deletion route, `a.DeleteAccount` answers `auth.ErrAccountDeletionOff` | you want users to delete their own account; with a provider-only sign-in base, with `ConfirmByLink` |
| `auth.WithDataHooks(h...)` | Data hooks of the app's own, run after every plugin's: `User.BeforeDelete` removes the app's rows that hold the user's id inside the deleting transaction, or refuses the deletion with an error. The library creates no foreign keys and no cascade (ADR-0002), so this hook is how the app's rows go with the user. `SessionEnded` runs once for every session that ends, with the reason; it reports and cannot refuse. | none | the app has tables that hold a user id, or a rule such as "the owner of a workspace cannot be deleted" |
| `auth.WithSecret(secret)` | One secret, at least [32](ds:block?id=minsecretsize-7wq2kx9m) bytes, from which every sealing key you did not pass explicitly is derived with HKDF-SHA256 under its own label: the stateless session key (`auth.WithStatelessSessions()` with no key), the snapshot cache key (`auth.NewSnapshotCache()` with no key) and a plugin's key when it asks `Config.DeriveKey`; a package with no `auth.New` behind it ([authgate](../integrations/login-gate.md)) derives the same keys from the same secrets with [`auth.DeriveSecretKeys`](ds:block?id=core-derivesecretkeys-4qv8nt2k). An explicit key still wins. To rotate, pass the new secret first and the old after it (`auth.WithSecret(new, old)`): keys from the first seal, keys from every secret open, so stateless tokens and sealed plugin values from before the rotation still open; drop the old secret once they have expired. A shorter or empty value fails `auth.New`: there is no development default. `AUTH_SECRET` sets it through `auth.EnvOptions`. | none: every key is passed where it is used | you want one value in the secret store instead of one per feature |
| [`auth.WithSealer(s)`](ds:block?id=opt-withsealer-2mt7rk5c) | An `auth.Sealer` (Vault transit, AWS KMS, Google Cloud KMS, an HSM) that seals every secret a plugin keeps at rest and was given no key of its own: the OAuth plugin's stored provider tokens and the two-factor plugin's TOTP secrets and encrypted recovery codes. A plugin's own key (`oauth.StoreTokensWith`, `twofactor.WithSealer`) still wins. Session tokens and the snapshot cache keep the in-memory ring. See [Security: the Sealer](security.md#keys-in-a-kms-the-sealer). | the key ring, through `auth.RingSealer` | keys must never sit in process memory |
| `auth.WithoutServerCallRateLimits()` | Direct Go calls (`TransportGo`) skip `ByIdentifier` rules too, so no Go call is counted at all: better-auth's rule that `auth.api` calls skip rate limiting. Calls through `authhttp` and every adapter are still counted. `auth.New` logs [a warning](ds:block?id=core-warnservercalllimitsoff-4nd8qw2k) at every start while it is on, because an app route that forwards a password to a Go call is then an unlimited guess channel. | Go calls are counted per account | every Go call site is a trusted job (an import, a seed, a back-office tool) |
| [`auth.WithFetchMetadata()`](security.md#refuse-cross-site-sign-ins-withfetchmetadata) | A mutation whose request says `Sec-Fetch-Site: cross-site` and whose `Origin` is not trusted is refused with `auth.origin_not_trusted` even without a cookie, so a form on another site cannot sign a victim into an attacker's account (login CSRF). Browsers send the header and no script can change it; a client that sends none is unaffected. The transport fills `Client.FetchSite`. | the header is not read | your front end is a browser and every cross-site caller you allow is a trusted origin |
| `auth.WithoutCSRFCheck()` | Turns the origin check off: a cookie-authenticated mutation from any origin is accepted, and `WithFetchMetadata`'s cross-site refusal with it. better-auth's `advanced.disableCSRFCheck`. It opens cross-site request forgery: any page the user visits can post to the auth routes with their cookie (sign them out, revoke sessions, unlink a provider, create an API key). `auth.New` logs [a warning](ds:block?id=core-warncsrfcheckoff-8vq3nk2w) at every start while it is on. The plugins' and `authui`'s own sign-in origin checks stay. | the check is on | never in production unless the app runs its own CSRF defence in front (a proxy that checks `Origin`, a synchronizer token); prefer `WithTrustedOrigins`, `WithTrustedOriginFunc` or bearer mode |
| `auth.WithoutOriginCheck()` | Turns return-URL validation off: `TrustsReturnURL` accepts any non-empty target without a line break or backslash (a Location-header guard, not a destination rule), so every `returnTo`, `errorTo`, `callbackURL` and `redirectTo` is taken as given. better-auth's `advanced.disableOriginCheck`. It opens an open redirect and, worse, token-bearing links to any host: a password-reset `redirectTo` or a magic-link callback on the attacker's site gets the victim's live token, which is account takeover on one click. `auth.New` logs [a warning](ds:block?id=core-warnorigincheckoff-3kd8wq5n) at every start while it is on. The CSRF origin check is untouched. | the check is on | never in production; every legitimate target is reachable with `WithTrustedOrigins` (including `myapp://` and `https://*.example.com`), `WithTrustedOriginFunc` or `WithLoopbackReturn` |
| `auth.WithUserColumns(cols...)` | Columns of your own on `auth_user`, declared like a plugin's (`auth.ColumnExtension`; `Table` may be left empty), migrated under the owner [`app`](ds:block?id=core-appname-3kq8vz2m), loaded with `LoadUser`, and written only through `auth.SetUserColumn(ctx, a, auth.AppName, …)`. The same checks as a plugin's apply, and a column a plugin also adds fails `auth.New`. | none | a plan, a locale or a flag belongs on the user row and no plugin owns it |
| `auth.WithSignUpFields(cols...)` | Lets a sign-up body's `fields` object (`auth.Fields`) set the listed `WithUserColumns` columns of the new account, better-auth's `user.additionalFields`: password sign-up, phone and email code sign-in. Each value must have its column's type (a JSON string for text, an integer for int, `true`/`false`, an RFC 3339 string for a timestamp, `null` for a nullable column), else `auth.field_invalid` before anything is written. A core or plugin column, or one the app did not declare, fails `auth.New`, so a role or a ban can never be set by a stranger. | none | a sign-up form collects a plan, a referral source or a locale |
| [`auth.WithProfileFields(cols...)`](sessions.md#let-users-edit-their-own-fields-withprofilefields) | Lets `POST /auth/profile` (`a.UpdateProfile`) set the listed app columns of the signed-in user's own row through `fields`, better-auth's `updateUser` with additional fields: same checks as the sign-up fields (a `WithUserColumns` column, the right type, else `auth.field_invalid` and nothing written). | name and image only | a bio, a time zone, a display preference the user edits themselves |
| `auth.WithOperationHooks(h...)` | Operation hooks of the app's own, checked and run like a plugin's: a `Before` on `auth.EndpointDeleteAccount` refuses self-service deletion while `a.DeleteUser` from an admin tool still works. A `Match` naming an unknown operation fails `auth.New`. | none | a policy on who may run an operation, or an audit line after one |
| `auth.WithErrorURL(url)` | The page a failed browser flow (an OAuth callback, a magic link) lands on when the flow names none of its own, with the code in the query (`?error=oauth.denied`), better-auth's `onAPIError.errorURL`. It must pass `TrustsReturnURL` (a same-site path or a URL on a trusted origin) or `auth.New` fails. `authhttp.ErrorPage` serves a page for it at `<prefix>/error`. See [Errors, step 4](errors.md#step-4--land-a-browser-on-an-error-page). | such failures answer JSON | your sign-in starts in a browser and a failure should land on a page |

<!-- ds:block id=opt-withloopbackreturn-6tn4wq8k -->
**WithLoopbackReturn** · [`returnurl.go:37`](../../returnurl.go#L37-L37)

```go
func WithLoopbackReturn() Option { return func(s *settings) { s.loopbackReturn = true } }
```
<!-- /ds:block hash=b7c70f -->

<!-- ds:block id=fetchsitecrosssite-8kq3wn2v -->
**FetchSiteCrossSite** · [`call.go:57`](../../call.go#L57-L57)

```go
"cross-site"
```
<!-- /ds:block hash=b56f49 -->

<!-- ds:block id=core-derivekey-6zp3rw8k -->
**Config.DeriveKey** · [`secret.go:99-105`](../../secret.go#L99-L105)

```go
func (c Config) DeriveKey(label string) ([]byte, error) {
	keys, err := c.DeriveKeys(label)
	if err != nil {
		return nil, err
	}
	return keys[0], nil
}
```
<!-- /ds:block hash=8cb1a9 -->

<!-- ds:block id=core-derivekeys-7xq4mn2b -->
**Config.DeriveKeys** · [`secret.go:113-115`](../../secret.go#L113-L115)

```go
func (c Config) DeriveKeys(label string) ([][]byte, error) {
	return DeriveSecretKeys(label, c.secrets...)
}
```
<!-- /ds:block hash=aa6af9 -->

<!-- ds:block id=core-derivesecretkeys-4qv8nt2k -->
**DeriveSecretKeys** · [`secret.go:128-149`](../../secret.go#L128-L149)

```go
func DeriveSecretKeys(label string, secrets ...[]byte) ([][]byte, error) {
	if len(secrets) == 0 {
		return nil, ErrNoSecret
	}
	if label == "" {
		return nil, fmt.Errorf("%w: DeriveKey needs a label", ErrBadOperation)
	}
	out := make([][]byte, 0, len(secrets))
	for i, secret := range secrets {
		if len(secret) < MinSecretSize {
			return nil, fmt.Errorf("%w: secret %d has %d bytes", ErrSecretTooShort, i, len(secret))
		}
		// hkdf.Key fails only for a length beyond 255 hashes; SealKeySize is
		// one, so the error cannot occur with a non-empty secret.
		key, err := hkdf.Key(sha256.New, secret, nil, keyLabelPrefix+label, SealKeySize)
		if err != nil {
			return nil, fmt.Errorf("auth: derive key %q: %w", label, err)
		}
		out = append(out, key)
	}
	return out, nil
}
```
<!-- /ds:block hash=853c16 -->

<!-- ds:block id=core-trustsreturnurl-9tk2mq4w -->
**Auth.TrustsReturnURL** · [`returnurl.go:83-109`](../../returnurl.go#L83-L109)

```go
func (a *Auth) TrustsReturnURL(target string) bool {
	if a.noOriginCheck {
		// WithoutOriginCheck: any destination, as better-auth's
		// disableOriginCheck. A line break or a backslash is still refused:
		// that guards the Location header against injection and URL
		// confusion, which is not a destination policy. See its comment for
		// the risk.
		return target != "" && !strings.ContainsAny(target, "\\\n\r")
	}
	if target == "" || strings.ContainsAny(target, "\\\n\r") {
		return false
	}
	if strings.HasPrefix(target, "/") {
		return !strings.HasPrefix(target, "//")
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" {
		return false
	}
	if _, ok := a.trustedSchemes[strings.ToLower(u.Scheme)]; ok {
		return true
	}
	if a.loopbackReturn && isLoopbackReturn(u) {
		return true
	}
	return u.Host != "" && a.TrustsOrigin(u.Scheme+"://"+u.Host)
}
```
<!-- /ds:block hash=14f065 -->

<!-- ds:block id=opt-withallowedhosts-7xk2mq9w -->
**WithAllowedHosts** · [`hosts.go:30-32`](../../hosts.go#L30-L32)

```go
func WithAllowedHosts(hosts ...string) Option {
	return func(s *settings) { s.allowedHosts = append(s.allowedHosts, hosts...) }
}
```
<!-- /ds:block hash=a52834 -->

<!-- ds:block id=core-baseurl-9qm4wx2t -->
**Auth.BaseURL** · [`hosts.go:102-107`](../../hosts.go#L102-L107)

```go
func (a *Auth) BaseURL(ctx context.Context) string {
	if st := stateFrom(ctx); st != nil && st.req.Host != "" && a.hostAllowed(st.req.Host) {
		return a.baseScheme() + "://" + strings.ToLower(st.req.Host)
	}
	return strings.TrimSuffix(a.cfg.BaseURL, "/")
}
```
<!-- /ds:block hash=b8092b -->

<!-- ds:block id=opt-withtrustedorigins-78h3s8tt -->
**WithTrustedOrigins** · [`auth.go:503-505`](../../auth.go#L503-L505)

```go
func WithTrustedOrigins(origins ...string) Option {
	return func(s *settings) { s.cfg.TrustedOrigins = append(s.cfg.TrustedOrigins, origins...) }
}
```
<!-- /ds:block hash=396633 -->

<!-- ds:block id=opt-withfreshwindow-9d7339p8 -->
**WithFreshWindow** · [`auth.go:512`](../../auth.go#L512-L512)

```go
func WithFreshWindow(d time.Duration) Option { return func(s *settings) { s.cfg.FreshWindow = d } }
```
<!-- /ds:block hash=5f3152 -->

<!-- ds:block id=opt-withdisabledoperations-4bkqa6ax -->
**WithDisabledOperations** · [`wire.go:145-147`](../../wire.go#L145-L147)

```go
func WithDisabledOperations(ids ...EndpointID) Option {
	return func(s *settings) { s.disabled = append(s.disabled, ids...) }
}
```
<!-- /ds:block hash=2f43c6 -->

<!-- ds:block id=opt-withoutiptracking-3f2vnmkt -->
**WithoutIPTracking** · [`observer.go:111`](../../observer.go#L111-L111)

```go
func WithoutIPTracking() Option { return func(s *settings) { s.noIPTracking = true } }
```
<!-- /ds:block hash=d809da -->

<!-- ds:block id=core-accountdeletion-7wq2xn5p -->
**AccountDeletion** · [`account.go:68-80`](../../account.go#L68-L80)

```go
type AccountDeletion struct {
	// ConfirmByLink makes /account/delete send a confirmation link rather
	// than delete; /account/delete/confirm then deletes. The user needs a
	// verified recovery identity, or the call answers ErrNoRecoveryChannel.
	ConfirmByLink bool
	// LinkTTL is how long the link works; zero means DefaultDeleteAccountTTL.
	LinkTTL time.Duration
	// Link builds the URL the message carries from the token. Nil means
	// BaseURL + DefaultDeleteAccountPage + "?token=…"; New refuses
	// ConfirmByLink with neither a Link nor a BaseURL, since no link could
	// be built.
	Link func(t Token) string
}
```
<!-- /ds:block hash=47b949 -->

<!-- ds:block id=opt-withaccountdeletion-3kd8rz2m -->
**WithAccountDeletion** · [`account.go:88-90`](../../account.go#L88-L90)

```go
func WithAccountDeletion(d AccountDeletion) Option {
	return func(s *settings) { s.accountDeletion, s.accountDeletionOn = d, true }
}
```
<!-- /ds:block hash=0cd036 -->

<!-- ds:block id=opt-withdatahooks-8pf4ym6n -->
**WithDataHooks** · [`account.go:104-106`](../../account.go#L104-L106)

```go
func WithDataHooks(h ...DataHooks) Option {
	return func(s *settings) { s.dataHooks = append(s.dataHooks, h...) }
}
```
<!-- /ds:block hash=aec246 -->

<!-- ds:block id=opt-withoperationhooks-5vn9qw3c -->
**WithOperationHooks** · [`account.go:116-118`](../../account.go#L116-L118)

```go
func WithOperationHooks(h ...OperationHook) Option {
	return func(s *settings) { s.opHooks = append(s.opHooks, h...) }
}
```
<!-- /ds:block hash=e16db4 -->

<!-- ds:block id=core-originfunc-5rj4fvun -->
**OriginFunc** · [`origins.go:43`](../../origins.go#L43-L43)

```go
type OriginFunc func(origin string) bool
```
<!-- /ds:block hash=27711e -->

<!-- ds:block id=opt-withtrustedoriginfunc-7j7xq3hq -->
**WithTrustedOriginFunc** · [`origins.go:55-62`](../../origins.go#L55-L62)

```go
func WithTrustedOriginFunc(fn OriginFunc) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithTrustedOriginFunc", fn) {
			return
		}
		s.originFunc = fn
	}
}
```
<!-- /ds:block hash=f23f42 -->

Check: a `POST` with the session cookie from an origin not in the list answers `403` with `auth.origin_not_trusted`. See [Security](security.md).

### Switch an operation off: WithDisabledOperations

Use this when a plugin ships an operation your product must not serve: an invite-only app creates accounts itself, so public sign-up has to go while sign-in stays. `auth.WithDisabledOperations(ids...)` takes operation ids, always through the plugin's `Endpoint…` constant. A disabled operation has no route on any transport and its Go method returns `auth.ErrUnknownOperation`; an id nothing registered (a typo such as `"password.signup"`) fails `auth.New` with `auth.ErrUnknownHookTarget`, so a misspelling cannot leave the operation served. Whole operations only: a plugin's rate rule cannot be removed this way.

`examples/core-options` turns password sign-up off, beside the other core switches on this page:

<!-- ds:block id=coreoptions-p4ag7zqk -->
**coreOptions** · [`examples/core-options/main.go:142-150`](../../examples/core-options/main.go#L142-L150)

```go
func coreOptions(db *sql.DB) []auth.Option {
	return []auth.Option{
		auth.WithDBAuto(db),
		auth.WithBaseURL(baseURL),
		auth.WithIDs(newUUIDv7),
		auth.WithDisabledOperations(password.EndpointSignUp),
		auth.WithFetchMetadata(),
	}
}
```
<!-- /ds:block hash=a02430 -->

With sign-up off, the app creates accounts in one transaction of its own:

<!-- ds:block id=ensureaccount-9xt4bm2q -->
**app.ensureAccount** · [`examples/core-options/main.go:230-245`](../../examples/core-options/main.go#L230-L245)

```go
func (p *app) ensureAccount(ctx context.Context, addr, secret string) error {
	err := p.auth.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		u, err := p.auth.CreateUser(ctx, auth.NewUser{})
		if err != nil {
			return err
		}
		if _, err := p.auth.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: addr, Verified: true, Primary: true}); err != nil {
			return err
		}
		return p.passwords.SetPassword(ctx, u.ID, password.Secret(secret))
	})
	if errors.Is(err, auth.ErrIdentityTaken) {
		return nil
	}
	return err
}
```
<!-- /ds:block hash=6fe300 -->

Try it:

```sh
curl -s -i -X POST localhost:8098/auth/password/sign-up -H 'Origin: http://localhost:8098' \
  -d '{"identifier":"bob@example.com","password":"another long password"}'
```

```text
HTTP/1.1 404 Not Found
{"error":{"code":"auth.unknown_operation","message":"Not found."}}
```

Check: `TestDisabledOperations` in `examples/core-options`: the route answers 404, `passwords.SignUp` from Go returns `auth.ErrUnknownOperation`, sign-in still works, and a misspelled id fails `auth.New`.

## Step 3 — Session settings

| Option | What it sets | Default | Set it when |
| --- | --- | --- | --- |
| [`auth.WithSessionArchive()`](sessions.md#keep-ended-sessions-withsessionarchive) | A revoked session's row is kept, marked with `revoked_at`, instead of deleted: sign-out, sign-out everywhere, revoking by id and a password reset leave an audit trail that `a.RevokedSessions(ctx, userID)` reads and `a.Sweep` removes after the retention. Lookups never see a revoked row. SQL store only. | revoked rows are deleted | support wants to see when each device was signed out |
| `auth.WithDeferredSessionRefresh()` | Reads never slide a session's expiry: `GET /auth/session`, a middleware lookup and every Query answer `needsRefresh: true` when the slide is due and leave it, and the client asks for it with `POST /auth/session/refresh` (`a.RefreshSession`), or any mutation slides as before. For reads served from a replica, or a GET that must be a pure read. | every lookup slides when due | your reads go to a replica, or you want GET to write nothing |
| [`auth.WithMultiSession(max)`](sessions.md#several-accounts-on-one-browser-withmultisession) | Several accounts signed in on one device, one active: `GET /auth/device-sessions` lists them, `POST /auth/device-sessions/switch` makes another the active one, `POST /auth/device-sessions/revoke` ends one, and sign-out ends every account on the device. A sign-in beyond `max` (0 means [five](ds:block?id=defaultmaxdevicesessions-7qk2nw4e)) is refused with `auth.too_many_device_sessions`. The transport holds the other tokens (authhttp: one cookie each). | off: one account per browser | your users switch between a work and a personal account |
| [`auth.WithSession(cfg)`](sessions.md#set-the-lifetimes-withsession) | The idle timeout, the hard lifetime, how often an active session's expiry is written, and the idle timeout of a "remember me unticked" session. | 7 days idle, 30 days at most, refreshed at most daily, [12 hours](ds:block?id=core-defaulttransientidle-7mhdjdth) transient | your product's rules differ |
| [`auth.WithTokenRotation(r)`](sessions.md#catch-a-copied-token-withtokenrotation) | A new session token on every sliding refresh; the replaced token keeps working for `Grace` (one minute by default, ten at most), and after that its use revokes the session for every holder and emits `session.token_reuse`. Needs a session store with the `SessionTokenRotator` upgrade (the SQL, memory and Redis stores have it); refused with stateless sessions. | off: a token lives as long as its session | a stolen cookie or bearer token must be noticed, not only expire |
| `auth.WithSessionPolicy(p)` | A lifetime per session, chosen at creation from who is signing in (browser or app); `auth.ByCredential(web, app)` is the common one. | every session gets `WithSession` | apps need longer sessions than browsers |
| `auth.WithSessionStore(s)` | Where sessions live. `auth.MirrorSessionStore(auth.SQLSessionStore(), copy)` keeps them in the database and a fast copy read first; the database stays authoritative and a copy that cannot end a session fails the sign-out. | the `auth_session` table | several instances without a shared database, a key-value store you already run, or Redis in front of the database |
| [`auth.WithSecondaryStorage(kv)`](sessions.md#keep-sessions-in-any-key-value-store-withsecondarystorage) | Sessions and rate-limit counters in one key-value store, better-auth's `secondaryStorage`: implement `auth.SecondaryStorage` (`Get`, `Set` with a TTL, `Delete`, an atomic `Increment` with first-set expiry) over Redis, Memcached or a cloud KV, or use contrib/redis `NewStorage` or `auth.NewMemoryStorage`. It is `WithSessionStore(auth.NewStorageSessionStore(kv))` plus `WithRateStore(auth.NewStorageRateStore(kv))`; each session expires with itself, and "sign out everywhere" advances a per-user generation with `Increment`, so a session is ended even when two instances raced on the user's session list. Users, identities and verification tokens stay in SQL, where a single-use token is spent in the operation's transaction. | the `auth_session` table and the rate store | you already run a key-value store and want sessions out of the database |
| [`auth.WithVerificationStore(s)`](#keep-verification-tokens-elsewhere-withverificationstore) | Where single-use verification tokens live (email and reset links, magic links, OAuth state, passkey ceremonies), better-auth's verification records in `secondaryStorage`. `auth.NewStorageVerificationStore(kv)` puts them in any key-value store with an atomic `GetAndDelete` (`auth.GetAndDeleter`), contrib/redis `NewVerificationStore` over Redis `GETDEL`, `auth.NewMemoryVerificationStore` in the process. Keys carry the SHA-256 of the token and of the identifier, never either. A store outside the database joins no transaction: a token spent by an operation that then fails stays spent (the user asks for a new link), and `a.Sweep` has nothing to delete because records expire by themselves. `ConsumeAll` and user deletion write a per-identifier cutoff instant that expires after [seven days](ds:block?id=core-minverificationcutoffttl-5kq8wn3d) or the longest token lifetime the store issued, whichever is longer, so it outlives every token it ends. A store that refuses a duplicate token (`auth.ExclusiveVerificationStore`: the SQL table, and the key-value store over storage with an atomic `SetIfAbsent`, as memory and contrib/redis have) is what plugin/oauth's ID-token replay guard needs; `auth.New` refuses another while an ID-token provider is configured, unless the app swaps or turns off that guard. Check a custom store with `verificationtest.Run`. | the `auth_verification` table | tokens should live where sessions already do, or the database should hold no short-lived rows |
| `auth.WithStatelessSessions(key)` | No store: the token carries the session, sealed with a 32-byte key. Excludes `WithSessionStore`. | off | you cannot or do not want to store sessions |
| `auth.WithSessionCache(c, ttl)` | A cache in front of the session lookup; `ttl` 0 means [a minute](ds:block?id=defaultsessioncachettl-8knzqpgz), more than [fifteen](ds:block?id=maxsessioncachettl-2sh2x4n6) is clamped. Client-held copies: `auth.NewSnapshotCache` (encrypted), `auth.NewCompactSessionCache` (signed, readable), `jwt.NewSessionCache` (signed JWT, readable). | no cache | the session lookup is the hot path |
| `auth.WithStatelessRefreshWithoutRead(interval)` | Stateless requests and refreshes use the user copy the token carries for `interval` after its last full read (0 means [five minutes](ds:block?id=defaultstatelessreadinterval-3kq8vz2m), more than [fifteen](ds:block?id=maxstatelessreadinterval-7wm2pq4x) is clamped): no query per request, and a ban or "sign out everywhere" waits up to `interval`. `FreshSignIn` operations always read. Needs `WithStatelessSessions`. | every request loads the user | stateless sessions and no database read on the hot path |
| `auth.WithSessionRevocations(list)` | A revocation list for stateless sessions: sign-out, revoking by id, ending a device account and the second-factor promotion list the session id, and every stateless lookup refuses it. `auth.NewMemorySessionRevocations()` or contrib/redis `NewSessionRevocations`. Needs `WithStatelessSessions`. | a stateless sign-out clears only the cookie | a stateless sign-out must end the token everywhere |
| [`auth.WithStatelessVersion(n)`](sessions.md#tune-stateless-sessions-withstatelessversion-withstatelessrefreshwithoutread-withdeferredsessionrefresh) | A number every stateless token carries and must match. Raising it signs everyone out without rotating the key. Needs `WithStatelessSessions`; negative is refused. | 0 | you want a global sign-out you can undo by lowering the number back before the tokens expire |
| `auth.WithPendingSessionTTL(d)` | How long a pending second-factor session lives after the first factor. Zero or less is refused. | [ten minutes](ds:block?id=pendingsessionttl-p4sajtqx) | a factor that takes longer, or a shorter window for a half-finished sign-in |
| [`auth.WithSessionExtras(fn)`](sessions.md#app-data-on-the-session-answer-withsessionextras) | App data added to `GET /session` and `a.Session(ctx)` as the `extras` field: roles, plan, whatever the front end needs with the session. A `nil` value or no function leaves the field out. | no field | the front end would otherwise make a second request after every session check |
| `auth.WithDeviceSessionExtras()` | The `WithSessionExtras` function also runs for each account on `GET /device-sessions`, with that account's session and user; its effects are discarded. Needs `WithMultiSession` and `WithSessionExtras`. | no `extras` on the device list | an account switcher shows each account's plan or avatar |
| `auth.SessionConfig.RefreshAfter = auth.NoSessionRefresh` | Stops the sliding expiry: a session ends `IdleTimeout` after creation however active the user. [`NoSessionRefresh`](ds:block?id=core-nosessionrefresh-6ht3cwz9) is a value no session can be seen after. | sliding, refreshed at most daily | sessions must end at a fixed time |
| `Session.Data` (no option) | JSON of your own on every session, typed in Go: `auth.SessionData[T](ctx)` reads it with no query, `auth.SetSessionData(ctx, a, v)` replaces it, a `Session.BeforeCreate` data hook sets what a session starts with. Every store keeps it, at most [2 KiB](ds:block?id=maxsessiondatasize-9wk3rq2d); `plugin/sessiondata` keeps the same data in a table instead. See [Sessions, step 7](sessions.md#step-7--app-data-on-the-session). | none | the front end or your handlers need something per session: the active workspace, the device, a flag resolved at sign-in |

<!-- ds:block id=core-sessionconfig-2hscd7v9 -->
**SessionConfig** · [`session.go:20-30`](../../session.go#L20-L30)

```go
type SessionConfig struct {
	IdleTimeout time.Duration
	MaxLifetime time.Duration
	// RefreshAfter limits how often an active session's expiry is written, so
	// the middleware does not write to the database on every request.
	RefreshAfter time.Duration
	// TransientIdleTimeout replaces IdleTimeout for a session made without
	// "remember me" (SessionOptions.Transient). Zero means
	// DefaultTransientIdleTimeout.
	TransientIdleTimeout time.Duration
}
```
<!-- /ds:block hash=8eed42 -->

<!-- ds:block id=core-defaultsessionconfig-nsrfps74 -->
**DefaultSessionConfig** · [`session.go:62-66`](../../session.go#L62-L66)

```go
var DefaultSessionConfig = SessionConfig{
	IdleTimeout:  7 * 24 * time.Hour,
	MaxLifetime:  30 * 24 * time.Hour,
	RefreshAfter: 24 * time.Hour,
}
```
<!-- /ds:block hash=a08020 -->

<!-- ds:block id=opt-withdeferredsessionrefresh-4qn7xm2k -->
**WithDeferredSessionRefresh** · [`session.go:1029`](../../session.go#L1029-L1029)

```go
func WithDeferredSessionRefresh() Option { return func(s *settings) { s.deferRefresh = true } }
```
<!-- /ds:block hash=fef13c -->

<!-- ds:block id=opt-withsessionarchive-5rk3nq8w -->
**WithSessionArchive** · [`sessionstore.go:111`](../../sessionstore.go#L111-L111)

```go
func WithSessionArchive() Option { return func(s *settings) { s.archive = true } }
```
<!-- /ds:block hash=4bae03 -->

<!-- ds:block id=opt-withmultisession-9wn4rt6k -->
**WithMultiSession** · [`multisession.go:50-52`](../../multisession.go#L50-L52)

```go
func WithMultiSession(max int) Option {
	return func(s *settings) { s.cfg.MultiSession = MultiSessionConfig{Enabled: true, Max: max} }
}
```
<!-- /ds:block hash=b22754 -->

<!-- ds:block id=core-multisessionconfig-3fx8vp2m -->
**MultiSessionConfig** · [`multisession.go:28-33`](../../multisession.go#L28-L33)

```go
type MultiSessionConfig struct {
	// Enabled is true when WithMultiSession was given.
	Enabled bool
	// Max is the most sessions one device may hold, the active one included.
	Max int
}
```
<!-- /ds:block hash=5122b6 -->

<!-- ds:block id=opt-withsession-3xdevfcb -->
**WithSession** · [`auth.go:520`](../../auth.go#L520-L520)

```go
func WithSession(c SessionConfig) Option { return func(s *settings) { s.cfg.Session = c } }
```
<!-- /ds:block hash=522505 -->

<!-- ds:block id=opt-withsessionpolicy-kpmqcqvd -->
**WithSessionPolicy** · [`lifetime.go:54-61`](../../lifetime.go#L54-L61)

```go
func WithSessionPolicy(p SessionPolicy) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithSessionPolicy", p) {
			return
		}
		s.policy = p
	}
}
```
<!-- /ds:block hash=269354 -->

<!-- ds:block id=opt-withsessionstore-55bdhhma -->
**WithSessionStore** · [`sessionstore.go:84-91`](../../sessionstore.go#L84-L91)

```go
func WithSessionStore(s SessionStore) Option {
	return func(st *settings) {
		if st.optErrs.RefuseNil("auth.WithSessionStore", s) {
			return
		}
		st.sessions = s
	}
}
```
<!-- /ds:block hash=32d51e -->

<!-- ds:block id=opt-withstatelesssessions-56w8hk96 -->
**WithStatelessSessions** · [`stateless.go:33-35`](../../stateless.go#L33-L35)

```go
func WithStatelessSessions(keys ...[]byte) Option {
	return func(s *settings) { s.stateless, s.statelessKeys = true, keys }
}
```
<!-- /ds:block hash=dd69dd -->

<!-- ds:block id=opt-withstatelessversion-2b8jt6kq -->
**WithStatelessVersion** · [`observer.go:180`](../../observer.go#L180-L180)

```go
func WithStatelessVersion(n int) Option { return func(s *settings) { s.statelessVersion = n } }
```
<!-- /ds:block hash=f01bff -->

<!-- ds:block id=opt-withpendingsessionttl-6ngzx4pw -->
**WithPendingSessionTTL** · [`auth.go:528-530`](../../auth.go#L528-L530)

```go
func WithPendingSessionTTL(d time.Duration) Option {
	return func(s *settings) { s.cfg.PendingSessionTTL = d }
}
```
<!-- /ds:block hash=a4b17f -->

<!-- ds:block id=opt-withsessionextras-9zxg2w8t -->
**WithSessionExtras** · [`observer.go:162-169`](../../observer.go#L162-L169)

```go
func WithSessionExtras(fn SessionExtras) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithSessionExtras", fn) {
			return
		}
		s.sessionExtras = fn
	}
}
```
<!-- /ds:block hash=eba785 -->

<!-- ds:block id=core-nosessionrefresh-6ht3cwz9 -->
**NoSessionRefresh** · [`session.go:38`](../../session.go#L38-L38)

```go
const NoSessionRefresh = MaxSessionLifetime
```
<!-- /ds:block hash=00c784 -->

<!-- ds:block id=opt-withsessioncache-3rwgvmug -->
**WithSessionCache** · [`sessioncache.go:66-73`](../../sessioncache.go#L66-L73)

```go
func WithSessionCache(c SessionCache, ttl time.Duration) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithSessionCache", c) {
			return
		}
		s.cache, s.cacheTTL = c, ttl
	}
}
```
<!-- /ds:block hash=00e5ff -->

Check: `auth.Sessions(ctx, userID)` shows each session's `ExpiresAt` and the lifetime it was created with. [Sessions](sessions.md) explains the modes.

### Keep verification tokens elsewhere: WithVerificationStore

Use this when single-use tokens (verification and reset links, magic links, OAuth state, passkey ceremonies) belong in a key-value store rather than `auth_verification`, typically because sessions already live there. [`auth.WithVerificationStore(s)`](ds:block?id=opt-withverificationstore-4hz8nq3v) takes an [`auth.VerificationStore`](ds:block?id=core-verificationstore-7mq2wk9d); [`auth.NewStorageVerificationStore(kv)`](ds:block?id=core-newstorageverificationstore-9dk4wq7n) puts them in any key-value store with an atomic get-and-delete, and [`auth.NewMemoryVerificationStore()`](ds:block?id=core-newmemoryverificationstore-3nw7kq2d) serves one process. The `auth_verification` table is still created. A store outside the database joins no transaction: a token spent by an operation that then fails stays spent (the user asks for a new link), and one issued by an operation that fails stays until it expires, although nobody received it, because delivery runs only after a commit.

A store of your own has one hard rule: a token is spent once, even under concurrent requests. `examples/delivery-outbox` writes a map-backed store whose `Consume` reads and deletes under one lock:

<!-- ds:block id=verification-store-consume-yt8ygtxx -->
**mapVerificationStore.Consume** · [`examples/delivery-outbox/main.go:279-290`](../../examples/delivery-outbox/main.go#L279-L290)

```go
func (s *mapVerificationStore) Consume(_ context.Context, purpose auth.Purpose, tokenHash []byte, now time.Time) (auth.Verification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := storeKey(purpose, tokenHash)
	v, ok := s.rows[key]
	if !ok || !v.ExpiresAt.After(now) {
		return auth.Verification{}, auth.ErrTokenInvalid
	}
	delete(s.rows, key)
	v.ConsumedAt = &now
	return v, nil
}
```
<!-- /ds:block hash=c4198e -->

Run `verificationtest.Run` against any store before using it. It checks the whole contract: of many concurrent `Consume` calls with one token exactly one wins; a wrong, spent, expired or wrong-purpose token is `auth.ErrTokenInvalid` alike, and a wrong-purpose attempt does not spend it; `ConsumeAll` and `DeleteIdentifiers` end exactly the tokens they name. The core's SQL and memory stores and contrib/redis run the same suite. The example's whole test is that one call.

Try it: the verification link mailed by that example verifies once, and the second use answers `auth.token_invalid`:

```json
{"email":"alice@example.com"}
{"error":{"code":"auth.token_invalid","message":"This link or code is not valid any more."}}
```

Check: `TestMapVerificationStore_Contract` runs `verificationtest.Run`; removing the delete from `Consume` fails it on the single-use cases.

## Step 4 — Rate limits

| Option | What it sets | Default | Set it when |
| --- | --- | --- | --- |
| `auth.WithRateStore(s)` | Where rate-limit counters live: `redis.New(client)` from `contrib/redis`, or your own `RateStore`. | in this process's memory, with a warning on the first counted call | more than one instance |
| `auth.WithDBRateStore()` | Counters in the auth database, table `auth_rate_limit`, which `Migrate` creates. Excludes `WithRateStore`. | off | more than one instance and no shared cache |
| `auth.WithRateLimit(limit, window)` | One blanket `ByIP` limit on every operation, counted per operation and per address, on top of the plugins' rules. A limit below one or a window of zero is refused. | off | a floor under routes nobody thought to limit, when nothing in front of the app limits them |
| `auth.WithRateRules(rules...)` | Your own rules. A rule for an operation a plugin limits replaces that plugin's rules for it; a rule for an operation with none adds the first. Validated like a plugin's: the operation must exist, `Limit` is one or more. A limit cannot be removed; `WithDisabledOperations` switches an operation off. | the plugins' rules | a shipped budget is too tight or too loose for your users |
| `auth.RateRule{Key: auth.ByFunc, KeyFunc: fn}` | A rule that counts by any key `fn` derives from the call (user, tenant, API key, device); the value is hashed like every other key and an error from `fn` fails the call. `auth.New` refuses a `ByFunc` rule without a `KeyFunc`. See [Rate limits](rate-limits.md). | `ByIP` and `ByIdentifier` only | a budget per user, per tenant or per API key |
| `auth.WithRateExempt(fn)` | A function asked once per call, before the input is decoded, whether the client is exempt from every `ByIP` rule, including `WithRateLimit`: a health checker, an internal range, a partner's gateway. `ByIdentifier` rules are never exempt, since they count guesses at one account from any address. It must be fast and answer `false` on its own failure. | nobody is exempt | an address of yours trips the limits and nothing in front of the app can be told about it |
| `auth.WithIPv6Prefix(bits)` | `ByIP` rules count an IPv6 address by its first `bits`, typically 64, so one subscriber's allocation is one counter. IPv4 is unaffected. Addresses are canonicalized in every case. Outside 1..[128](ds:block?id=core-ipv6prefixbits-5hz8nqkv) is refused. | the whole address | you see one client rotate through a /64 |

<!-- ds:block id=core-rateexemptfunc-9wk2tn5x -->
**RateExemptFunc** · [`ratelimit.go:161`](../../ratelimit.go#L161-L161)

```go
type RateExemptFunc func(ctx context.Context, c *Call) bool
```
<!-- /ds:block hash=42ec38 -->

<!-- ds:block id=opt-withratestore-8wytkptr -->
**WithRateStore** · [`auth.go:583-590`](../../auth.go#L583-L590)

```go
func WithRateStore(r RateStore) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithRateStore", r) {
			return
		}
		s.rateStore = r
	}
}
```
<!-- /ds:block hash=dd3888 -->

<!-- ds:block id=opt-withratelimit-6kq2mz4d -->
**WithRateLimit** · [`ratelimit.go:149-151`](../../ratelimit.go#L149-L151)

```go
func WithRateLimit(limit int, window time.Duration) Option {
	return func(s *settings) { s.globalRate = &RateRule{Key: ByIP, Limit: limit, Window: window} }
}
```
<!-- /ds:block hash=e851cc -->

<!-- ds:block id=opt-withraterules-3pxw7hgf -->
**WithRateRules** · [`ratelimit.go:137-139`](../../ratelimit.go#L137-L139)

```go
func WithRateRules(rules ...RateRule) Option {
	return func(s *settings) { s.appRules = append(s.appRules, rules...) }
}
```
<!-- /ds:block hash=5698af -->

<!-- ds:block id=opt-withipv6prefix-8cfh3b2a -->
**WithIPv6Prefix** · [`ratelimit.go:196`](../../ratelimit.go#L196-L196)

```go
func WithIPv6Prefix(bits int) Option { return func(s *settings) { s.ipv6Prefix = bits } }
```
<!-- /ds:block hash=1981b7 -->

<!-- ds:block id=opt-withdbratestore-9gffdmh4 -->
**WithDBRateStore** · [`ratestore_db.go:32`](../../ratestore_db.go#L32-L32)

```go
func WithDBRateStore() Option { return func(s *settings) { s.dbRateStore = true } }
```
<!-- /ds:block hash=a47e66 -->

Check: with two instances on one database, five wrong passwords spread across both lock the account on both (`examples/multi-instance`). See [Rate limits](rate-limits.md).

## Step 5 — Settings for tests and operators

| Option | What it sets | Default | Set it when |
| --- | --- | --- | --- |
| `auth.WithClock(now)` | The clock every expiry is measured by. | `time.Now` | tests that move time |
| [`auth.WithIDs(gen)`](#your-own-ids-withids) | The id generator for users, sessions, identities, codes; `prefix` is `usr`, `ses`, … and the result must be unique and opaque. | `auth.NewID`: `<prefix>_` and 24 random base32 characters | ids must follow a scheme of yours |
| [`auth.WithSQLTypes(engine, types)`](ds:block?id=opt-withsqltypes-8pz4qm2k) | Column spellings for one engine (`auth.EnginePostgres`, `auth.EngineMySQL`, `auth.EngineSQLite`), only the fields you set: `ID` types every generated id and id-referencing column (`"UUID"` with a UUID `WithIDs` gives native UUID keys), `Key`, `Text` and the rest widen or change others. Reaches every built-in plugin, which implement `auth.TypedMigrator`. See [Databases](databases.md). | `auth.TypesFor(engine)`; `ID` spelled as `Key`, so existing schemas are unchanged | native UUID keys, or a column wider than the default |
| [`auth.WithLogger(l)`](#where-the-library-logs-withlogger) | Where the core logs warnings and failed deliveries, as `*slog.Logger`; the transport's internal-error line takes `authhttp.Logger(l)`. | `slog.Default()` | you have a logger |
| `auth.WithObserver(o)` | An `Observer` that sees every call end: operation, plugin, transport, duration on the configured clock, and the error or nil. No input or output reaches it. `auth.ObserverFunc` adapts a function. | nothing is measured | metrics, tracing, error reporting |
| `auth.WithTracer(t)` | A `Tracer` that starts one span per call (`auth.operation <id>`) and one per `Before` and `After` hook inside it (`auth.hook before <id> <plugin or app>`), one per statement run through `Exec`/`One`/`Each` (`auth.db <verb> <table>`: the verb and the real table name, never the SQL) and one per `DataHooks` function (`auth.db_hook <stage> <model>`), better-auth's database and database-hook spans, each ended with its error (a `One` that finds no row is not one). `Start` returns the context the work runs in, so an adapter's spans nest. `contrib/otel` turns it into OpenTelemetry spans; the Observer is for metrics. | no spans | distributed tracing |
| `auth.WithMessages(catalogue)` | A `MessageCatalog` error messages are rendered from in the request's locale (`Client.Locale`, then `WithDefaultLocale`): `auth.Messages` is a map of locale, then code, then text, looked up as the exact tag then the base language, so it unmarshals from a JSON translation file and `docs/reference/error-codes.json` is the template; [`i18n.Messages()`](../../i18n/README.md) ships every code in 21 languages. A translated error also carries the English text as `originalMessage`. Codes and statuses never change; a locale or code the catalogue lacks gets the English text. Transports render through `auth.ErrorInfoFor(ctx, err)`. | English messages | your users read another language and your front end does not translate by code itself |
| `auth.WithBackground(run)` | How post-commit work (message delivery) leaves the request. The function gets the request's context without its cancellation and must return at once. | one goroutine per task | a runtime that ends with the response (`waitUntil`), or a worker pool |
| [`auth.WithDefaultLocale(tag)`](errors.md#pick-the-language-withdefaultlocale-and-withuserlocale) | The locale of a message whose request carried no language, as a BCP 47 tag. Templates by locale are picked with it. | none: the plugin's default template | most of your users share one language that is not the templates' default |
| [`auth.WithUserLocale(column)`](ds:block?id=opt-withuserlocale-6kq2wn8x) | A `WithUserColumns` text column holding the user's chosen locale; for a signed-in request it wins over `Accept-Language` and the locale cookie (better-auth's i18n `session` detection). Read once per request, only when a message needs it, after the session is resolved; an empty or malformed value is ignored. | the client's locale | users pick a language in settings and expect it on every device |
| `auth.WithCodeLength(digits)` | Digits in every one-time code, between [4 and 10](ds:block?id=codelengthbounds-7xq2mt5r). | [6](ds:block?id=defaultcodelength-3vn8hq2k) | your product wants longer codes |
| `auth.WithDefaultPageSize(n)` | The page size every list that reads it (`Config.PageSize`) answers when the caller asks for none, better-auth's `defaultFindManyLimit`. Only the default changes: each list keeps its own maximum. Negative is refused; 0 keeps each list's own default. | each list's own default | you want shorter (or longer, up to each list's cap) default pages everywhere |

<!-- ds:block id=core-observer-4c7sgyun -->
**Observer** · [`observer.go:36-38`](../../observer.go#L36-L38)

```go
type Observer interface {
	Operation(ctx context.Context, e OperationEvent)
}
```
<!-- /ds:block hash=1e8f1c -->

<!-- ds:block id=opt-withobserver-8mvzpdru -->
**WithObserver** · [`observer.go:50-57`](../../observer.go#L50-L57)

```go
func WithObserver(o Observer) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithObserver", o) {
			return
		}
		s.observer = o
	}
}
```
<!-- /ds:block hash=e29035 -->

<!-- ds:block id=core-operationevent-9qmvrxbe -->
**OperationEvent** · [`observer.go:16-24`](../../observer.go#L16-L24)

```go
type OperationEvent struct {
	Op        OpInfo
	Plugin    string
	Transport Transport
	// Duration is from the pipeline's first check to the result, measured on
	// the configured clock.
	Duration time.Duration
	Err      error
}
```
<!-- /ds:block hash=03a6a1 -->

<!-- ds:block id=core-backgroundfunc-6dfpk3re -->
**BackgroundFunc** · [`observer.go:66`](../../observer.go#L66-L66)

```go
type BackgroundFunc func(ctx context.Context, task func(context.Context))
```
<!-- /ds:block hash=0876ec -->

<!-- ds:block id=opt-withbackground-7zhq8n2w -->
**WithBackground** · [`observer.go:76-83`](../../observer.go#L76-L83)

```go
func WithBackground(run BackgroundFunc) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithBackground", run) {
			return
		}
		s.background = run
	}
}
```
<!-- /ds:block hash=97b3b1 -->

<!-- ds:block id=opt-withdefaultlocale-5wc4ae9h -->
**WithDefaultLocale** · [`observer.go:125`](../../observer.go#L125-L125)

```go
func WithDefaultLocale(tag string) Option { return func(s *settings) { s.defaultLocale = tag } }
```
<!-- /ds:block hash=fead7f -->

<!-- ds:block id=core-tracer-3pm9kw7v -->
**Tracer** · [`trace.go:98-100`](../../trace.go#L98-L100)

```go
type Tracer interface {
	Start(ctx context.Context, s SpanInfo) (context.Context, Span)
}
```
<!-- /ds:block hash=7b429e -->

<!-- ds:block id=core-spaninfo-4kt7mn2b -->
**SpanInfo** · [`trace.go:57-74`](../../trace.go#L57-L74)

```go
type SpanInfo struct {
	Kind      SpanKind
	Name      string
	Op        OpInfo
	Plugin    string
	Transport Transport
	Stage     HookStage
	Source    string
	// Route is the request path a middleware span wraps; empty otherwise.
	Route string
	// DBOperation and Table are set for database and data-hook spans: the
	// statement's verb ("select", "insert", "update", "delete", or "query"
	// for anything else) and the real table name it names first, or for a
	// data hook its stage ("before_create" …) and the core model ("user",
	// "identity", "session", "verification").
	DBOperation string
	Table       string
}
```
<!-- /ds:block hash=0b8283 -->

<!-- ds:block id=core-span-8vq2hx5n -->
**Span** · [`trace.go:82-84`](../../trace.go#L82-L84)

```go
type Span interface {
	End(err error)
}
```
<!-- /ds:block hash=5e8ec9 -->

<!-- ds:block id=core-spankind-6rn3wq8d -->
**SpanKind** · [`trace.go:11`](../../trace.go#L11-L11)

```go
type SpanKind string
```
<!-- /ds:block hash=b33622 -->

<!-- ds:block id=opt-withtracer-5xh2rq8m -->
**WithTracer** · [`trace.go:106-113`](../../trace.go#L106-L113)

```go
func WithTracer(t Tracer) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithTracer", t) {
			return
		}
		s.tracer = t
	}
}
```
<!-- /ds:block hash=19d685 -->

<!-- ds:block id=core-messagecatalog-7qf3bn2x -->
**MessageCatalog** · [`messages.go:23-25`](../../messages.go#L23-L25)

```go
type MessageCatalog interface {
	Message(locale, code string) (string, bool)
}
```
<!-- /ds:block hash=118215 -->

<!-- ds:block id=opt-withcodelength-9rp4wvmt -->
**WithCodeLength** · [`auth.go:540`](../../auth.go#L540-L540)

```go
func WithCodeLength(digits int) Option { return func(s *settings) { s.cfg.CodeLength = digits } }
```
<!-- /ds:block hash=1eea46 -->

<!-- ds:block id=opt-withclock-7jfkrht9 -->
**WithClock** · [`auth.go:545-552`](../../auth.go#L545-L552)

```go
func WithClock(now func() time.Time) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithClock", now) {
			return
		}
		s.clock = now
	}
}
```
<!-- /ds:block hash=bb63a1 -->

<!-- ds:block id=opt-withids-cwqcmudc -->
**WithIDs** · [`auth.go:558-565`](../../auth.go#L558-L565)

```go
func WithIDs(gen func(prefix string) (string, error)) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithIDs", gen) {
			return
		}
		s.ids = gen
	}
}
```
<!-- /ds:block hash=acd489 -->

Check: a test with `auth.WithClock(clock.Now)` that advances the clock past the idle timeout sees `auth.ErrSignedOut` without sleeping.

### Your own ids: WithIDs

Use this when your schema already uses UUIDs, ULIDs or another id format, so the auth tables join yours without a translation. [`auth.WithIDs(gen)`](ds:block?id=opt-withids-cwqcmudc) replaces the generator for every id the library makes: users, sessions, identities, codes. The core passes a short prefix (`usr`, `ses`, …) that the default `auth.NewID` puts in front of 24 random base32 characters; a generator may ignore it. The result must be unique and opaque, the library never parses it, and an error the generator returns fails the write that asked for the id.

<!-- ds:block id=newuuidv7-r8k2mw4t -->
**newUUIDv7** · [`examples/core-options/main.go:181-194`](../../examples/core-options/main.go#L181-L194)

```go
func newUUIDv7(_ string) (string, error) {
	var b [uuidSize]byte
	if _, err := rand.Read(b[uuidTimeBytes:]); err != nil {
		return "", fmt.Errorf("uuidv7: %w", err)
	}
	var ms [millisBytes]byte
	binary.BigEndian.PutUint64(ms[:], uint64(time.Now().UnixMilli()))
	copy(b[:uuidTimeBytes], ms[millisBytes-uuidTimeBytes:])
	b[uuidVersionByte] = uuidVersion7 | b[uuidVersionByte]&lowNibble
	b[uuidVariantByte] = uuidVariantRFC | b[uuidVariantByte]&lowSixBits
	h := hex.EncodeToString(b[:])
	// The text form groups the 32 hex digits 8-4-4-4-12.
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}
```
<!-- /ds:block hash=60b4fb -->

To store such ids in a native column type, pair the generator with [`auth.WithSQLTypes`](databases.md#column-types-per-engine-withsqltypes). Try it: the sign-in in `examples/core-options` answers with the generator's id:

```json
{"user":{"id":"01a11eb2-af40-7c96-b9d8-c359961a046c","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

Check: `TestIDs` in `examples/core-options` matches the ids in `auth_user`, `auth_identity` and `auth_session` against the UUIDv7 pattern, and checks that a failing generator fails `CreateUser` with its own error.

### Where the library logs: WithLogger

Use this to send the library's warnings and internal errors to your own logger instead of `slog.Default()`. `auth.WithLogger(l)` takes a `*slog.Logger`. The core logs, among others, a failed delivery (`auth: delivery failed`, with the kind and the purpose, never the message), and a warning at the first request when rate limits are counted per process. Two things it does not cover: the `auth operation failed` line for an internal error is written by the transport, so pass the same logger to `authhttp.Logger(l)`, and the observer and tracer below are separate options.

<!-- ds:block id=obs-newauth-z6v7v9tm -->
**newAuth** · [`examples/observability/main.go:130-142`](../../examples/observability/main.go#L130-L142)

```go
func newAuth(db *sql.DB, m email.Mailer, logger *slog.Logger, tp trace.TracerProvider, obs auth.Observer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
		auth.WithObserver(obs),
		auth.WithTracer(authotel.Tracer(tp)),
		auth.WithLogger(logger),
	)
}
```
<!-- /ds:block hash=74ab73 -->

<!-- ds:block id=obs-newhandler-b6bkmd6m -->
**newHandler** · [`examples/observability/main.go:150-154`](../../examples/observability/main.go#L150-L154)

```go
func newHandler(a *auth.Auth, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix), authhttp.Logger(logger)))
	return mux
}
```
<!-- /ds:block hash=1bae18 -->

Try it: in `examples/observability`, a sign-up whose mail the provider rejects still answers 200, and the logger records:

```text
{"level":"WARN","msg":"auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance"}
{"level":"ERROR","msg":"auth: delivery failed","kind":"email","purpose":"verify","error":"mail provider rejected the message"}
```

Check: `TestObservability` in `examples/observability` finds the delivery failure at ERROR in the logger's buffer and the password nowhere in it. [Production, step 8](../start/production.md#step-8--logging-and-monitoring) adds the observer and the tracer.

## Step 6 — Read the deployment's settings from the environment

`auth.EnvOptions` turns environment variables into options: the base URL, the secret (`AUTH_SECRET`, used as its characters, at least 32 of them; `openssl rand -base64 32` gives 44), the trusted origins, the fresh window and the three session durations. It takes the lookup function (`os.LookupEnv`) rather than reading the process environment itself, so a test passes a map. An unset variable leaves the default; a malformed one is an error naming it, so a typo fails the deploy instead of silently running with the default.

<!-- ds:block id=core-envvars-h63nyypk -->
**EnvBaseURL** · [`env.go:15`](../../env.go#L15-L15)

```go
"AUTH_BASE_URL"
```
<!-- /ds:block hash=36a07f -->

<!-- ds:block id=core-envoptions-ewjb2mvy lines=1-14 -->
**EnvOptions** · [`env.go:40-90`](../../env.go#L40-L90)

```go
func EnvOptions(lookup func(string) (string, bool)) ([]Option, error) {
	var opts []Option
	if v, ok := lookup(EnvBaseURL); ok && v != "" {
		opts = append(opts, WithBaseURL(v))
	}
	// A set but short secret is passed on, so New refuses it with
	// ErrSecretTooShort instead of silently running without one.
	if v, ok := lookup(EnvSecret); ok {
		opts = append(opts, WithSecret([]byte(v)))
	}
	if v, ok := lookup(EnvTrustedOrigins); ok && v != "" {
		var origins []string
		for _, o := range strings.Split(v, ",") {
			if o = strings.TrimSpace(o); o != "" {
```
<!-- /ds:block hash=b40c0b -->

```go
env, err := auth.EnvOptions(os.LookupEnv)
if err != nil {
	log.Fatal(err)
}
a, err := auth.New(append([]auth.Option{auth.WithDB(db, sqlb.PostgresDialect{}), auth.WithPlugins(/* … */)}, env...)...)
```

Durations use Go syntax: `AUTH_SESSION_IDLE=168h`, `AUTH_FRESH_WINDOW=5m`. `AUTH_TRUSTED_ORIGINS` is comma-separated. An `AUTH_SECRET` that is set but shorter than 32 characters, including empty, is passed on and fails `auth.New` with `auth.ErrSecretTooShort`, so a deployment never starts without the secret it meant to have.

Check: `AUTH_FRESH_WINDOW=soon` fails with `auth: AUTH_FRESH_WINDOW="soon" is not a positive duration such as 168h`.

## What can go wrong

- `auth: no database configured; pass auth.WithDB` — `WithDB` was not given and a call needed the database.
- `auth: no sign-in method; add a plugin such as password or oauth` — no plugin in the list signs anyone in.
- `auth: origin is not an absolute URL: "admin.example.com"` — a trusted origin without a scheme.
- `auth: operation description is not valid: WithRateStore and WithDBRateStore both set` — choose one counter store.
- `auth: operation description is not valid: WithStatelessSessions and WithSessionStore both set` — choose one session mode.
- `auth: operation description is not valid: stateless sessions: auth: seal key is 16 bytes, want 32` — the stateless key is `auth.SealKeySize` bytes.
- `auth: no database configured; pass auth.WithDB: WithDBRateStore needs WithDB` — the database rate store has nowhere to count.
- `auth: AUTH_SESSION_MAX="30d" is not a positive duration such as 168h` — Go durations have no `d`; write `720h`.
- `auth: origin is not an absolute URL: pattern "https://api.*" may use "*" and "?" only in labels left of a domain of 2 labels or more, with no path` — a wildcard must sit left of a domain you own: `https://*.example.com`, `https://preview-*.example.com`.
- `auth: hook names an operation that is not registered: WithDisabledOperations names "password.signup"` — a typo in a disabled id would leave the operation served; use the plugin's `Endpoint…` constant.
- `auth: operation description is not valid: WithStatelessVersion needs WithStatelessSessions` — the version rides in stateless tokens only.
- `auth: operation description is not valid: IPv6 prefix 129 is not in 1..128`, `code length 3 is not in 4..10`, `pending session TTL 0s is not positive` — each option's bounds.

## Next

- [Databases](databases.md): the engines, drivers and DSNs behind `WithDB`.
- [Sessions](sessions.md) and [Rate limits](rate-limits.md): what the session and counter options change.
