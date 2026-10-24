# Production

You will have the app from [your first app](first-app.md) ready to deploy: configured from the environment, with its keys in a secret store, its schema migrated by the deploy, expired rows swept on a schedule, real mail going out, and the checks that matter done once.

## Before you start

- [Your first app](first-app.md) running locally.
- The library ships no background workers, no key management and no mail provider. Each of those is one call or one interface for the app to make; this guide is the list.

## Step 1 — Configure from the environment

`auth.EnvOptions` turns environment variables into options. It takes the lookup function as a parameter (`os.LookupEnv`), so a test passes a map and nothing reads the process environment behind your back. An unset variable leaves the default; a malformed one is an error naming the variable, so a typo fails the deploy instead of running with the default.

<!-- ds:block id=envbaseurl-k7cmqg4h -->
**EnvBaseURL** · [`env.go:13-24`](../../env.go#L13-L24)

```go
const (
	//ds:def id=core-envvars-h63nyypk owner=@khanakia stability=stable
	EnvBaseURL        = "AUTH_BASE_URL"
	EnvTrustedOrigins = "AUTH_TRUSTED_ORIGINS" // comma-separated
	EnvFreshWindow    = "AUTH_FRESH_WINDOW"
	EnvSessionIdle    = "AUTH_SESSION_IDLE"
	EnvSessionMax     = "AUTH_SESSION_MAX"
	EnvSessionRefresh = "AUTH_SESSION_REFRESH"
	// EnvSecret is the WithSecret value, used as its bytes: any string of at
	// least MinSecretSize characters, such as `openssl rand -base64 32`.
	EnvSecret = "AUTH_SECRET"
)
```
<!-- /ds:block hash=0d932f -->

The [cli example](../../examples/cli/README.md) reads them through a lookup it is handed (`os.LookupEnv` in `main`, a map in its tests) and logs which variables are set, never their values, because `AUTH_SECRET` is one of them. Its `newAuth` appends these options after its own defaults, so a set variable wins and an unset one keeps the default:

<!-- ds:block id=cli-envoptions-9423x8e8 -->
**envOptions** · [`examples/cli/main.go:170-183`](../../examples/cli/main.go#L170-L183)

```go
func envOptions(lookup func(string) (string, bool)) ([]auth.Option, error) {
	opts, err := auth.EnvOptions(lookup)
	if err != nil {
		return nil, err
	}
	for _, name := range auth.EnvVars {
		state := "default"
		if _, ok := lookup(name); ok {
			state = "set"
		}
		log.Printf("config %s: %s", name, state) // never the value: AUTH_SECRET is one of them
	}
	return opts, nil
}
```
<!-- /ds:block hash=7a3365 -->

Durations use Go syntax (`168h`, `30m`). `AUTH_BASE_URL` is the one you must set: it is the origin browsers may `POST` from and the host every mailed link points at. `AUTH_TRUSTED_ORIGINS` is a comma-separated list of other origins that may send cookie-authenticated mutations, such as an admin app on another subdomain.

Try it: build the example and print the settled configuration with `auth info` (step 6 of the [command line guide](../integrations/cli.md)); the start-up log goes to stderr.

```sh
AUTH_BASE_URL=https://app.example.com AUTH_SESSION_IDLE=48h ./myapp auth info 2>/dev/null | head -6
```

```text
version              (devel)
engine               sqlite
base url             https://app.example.com
trusted origins      0
fresh window         10m0s
session              idle 48h0m0s, max 720h0m0s, refresh after 24h0m0s
```

A malformed value stops the binary before it does anything else:

```sh
AUTH_SESSION_IDLE=7d ./myapp auth info; echo "exit $?"
```

```text
2026/10/09 16:05:30 auth: AUTH_SESSION_IDLE="7d" is not a positive duration such as 168h
exit 1
```

Check: `TestCLI_ConfigFromEnvironment` in `examples/cli` sets the variables through a map, reads them back from `auth info --json`, and expects the error that names the variable.

## Step 2 — Keys and secrets

Several plugins seal or sign with a key. Each key comes from your secret store, as hex or base64 in an environment variable, and the app refuses a malformed one rather than falling back to a random key: a random key would silently lock every user out of that feature at the next restart.

| Plugin | Option | Key | What a lost or rotated key does |
|---|---|---|---|
| `twofactor` | `twofactor.WithEncryptionKey(key)` | 32 bytes (`auth.SealKeySize`) | Every enrolled factor stops verifying; users must enrol again. |
| `oauth` with `oauth.StoreTokens(key)` | sealed provider tokens | 32 bytes | Stored provider tokens become unreadable; users link again. |
| `jwt` | `jwt.WithSigningKey(key)` | an Ed25519 private key (or an RSA or ECDSA key for `RS256`/`ES256`/`ES384`/`ES512`, and `jwt.RSAKey` for `PS256` and the other RSA algorithms); `jwt.PreviousKeys(...)` keeps old public keys verifiable during rotation | Tokens signed with the old key stop verifying unless its public key is in `PreviousKeys`. |
| `auth.WithStatelessSessions(key)` | stateless sessions | 32 bytes | Everyone is signed out: this is the global logout switch. |
| `auth.NewSnapshotCache(key)` | the session snapshot cache | 32 bytes | Every client's cached copy is ignored and looked up again; harmless. |

One secret instead of one key per feature: `auth.WithSecret(secret)` (or `AUTH_SECRET` through `auth.EnvOptions`) derives every key you did not pass with HKDF-SHA256 under a label of its own, so `auth.WithStatelessSessions()` and `auth.NewSnapshotCache()` need no argument and a plugin that takes an optional key asks `Config.DeriveKey`. The secret is at least [32](ds:block?id=minsecretsize-7wq2kx9m) bytes and has no default: an unset or short value fails `auth.New`. To rotate it, pass the new secret first and the old one after it, `auth.WithSecret(new, old)` (the environment variable holds one value, so an app that rotates through the environment reads a second variable for the previous one and passes both): keys derived from the first seal, keys derived from every secret open, so nobody is signed out of a stateless session and every sealed plugin value still opens; drop the old secret once what it sealed has expired. Labels are fixed constants (`auth.KeyLabelStatelessSessions`, `auth.KeyLabelSnapshotCache`, `auth.KeyLabelTwoFactor`, `auth.KeyLabelOAuthTokens`), never built from input, so no caller can choose a key.

<!-- ds:block id=opt-withsecret-4ht8vn2q -->
**WithSecret** · [`secret.go:83-85`](../../secret.go#L83-L85)

```go
func WithSecret(current []byte, previous ...[]byte) Option {
	return func(s *settings) { s.cfg.secrets, s.secretSet = append([][]byte{current}, previous...), true }
}
```
<!-- /ds:block hash=89c422 -->

The two-factor example reads its key like this; the same shape fits every 32-byte key:

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

And the JWT example its Ed25519 seed:

<!-- ds:block id=signingkey-jmtjdh92 -->
**signingKey** · [`examples/api-keys-and-jwt/main.go:155-169`](../../examples/api-keys-and-jwt/main.go#L155-L169)

```go
func signingKey(getenv func(string) string) (ed25519.PrivateKey, error) {
	if s := getenv(envSigningKey); s != "" {
		seed, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s must be %d bytes, base64url without padding", envSigningKey, ed25519.SeedSize)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	log.Printf("%s is not set: signing with a new key; tokens stop verifying when the process restarts", envSigningKey)
	return key, nil
}
```
<!-- /ds:block hash=2a7275 -->

OAuth client ids and secrets are configuration, not keys, but come from the same store; register only the providers whose variables are set:

<!-- ds:block id=providersfromenv-tyx5rn7w -->
**providersFromEnv** · [`examples/oauth/main.go:122-134`](../../examples/oauth/main.go#L122-L134)

```go
func providersFromEnv(getenv func(string) string) []oauth.Provider {
	var out []oauth.Provider
	if id, secret := getenv(envGitHubID), getenv(envGitHubSecret); id != "" && secret != "" {
		out = append(out, oauth.GitHub(id, secret))
	}
	if id, secret := getenv(envGoogleID), getenv(envGoogleSecret); id != "" && secret != "" {
		out = append(out, oauth.Google(id, secret))
	}
	if iss, id, secret := getenv(envOIDCIssuer), getenv(envOIDCID), getenv(envOIDCSecret); iss != "" && id != "" && secret != "" {
		out = append(out, oauth.OIDC(oidcProviderName, iss, id, secret))
	}
	return out
}
```
<!-- /ds:block hash=c5d0f5 -->

Check: start the app with each key variable unset in turn; the ones above warn or refuse, never start silently with a fresh key in production. Generate keys with `openssl rand -hex 32`.

## Step 3 — Migrate from the deploy, not from the server

`a.Migrate` is idempotent and safe for one process. With several instances, let the deploy job run the migrations once and have each server refuse to start against an old schema. `authcli` gives your binary the commands; your `main` routes a word of its choosing to it:

<!-- ds:block id=command-5hg2hb73 -->
**command** · [`examples/cli/main.go:112-117`](../../examples/cli/main.go#L112-L117)

```go
func command(ctx context.Context, a *auth.Auth, args []string, stdout, stderr io.Writer) (code int, handled bool) {
	if len(args) == 0 || args[0] != authCommand {
		return authcli.ExitOK, false
	}
	return authcli.Main(ctx, a, args[1:], stdout, stderr), true
}
```
<!-- /ds:block hash=9befd6 -->

<!-- ds:block id=usage-9kra29g4 -->
**usage** · [`authcli/authcli.go:85-115`](../../authcli/authcli.go#L85-L115)

```go
`usage: auth sweep [--retention 168h] delete expired sessions, tokens and plugin rows;
                                     with WithDeliveryOutbox, send the outbox's due messages
       auth maintain [--dry-run]   run the plugins' scheduled jobs (mail to dormant accounts,
                                     deletion of the ones that never answered);
                                     --dry-run counts them and changes nothing
       auth migrate [--dry-run]    apply pending migrations
       auth migrate sql              print every migration as SQL, change nothing
       auth migrate status           list migrations and whether each is applied
       auth migrate orphans          list tables, columns and owners no plugin claims now
       auth migrate check            fail unless the database holds every table, column and migration the code needs
       auth generate                 the same as auth migrate sql
       auth info [--json]            print the wiring: version, engine, plugins, routes, lifetimes
       auth secret [--value]         print AUTH_SECRET=<a fresh random secret> (--value: the value alone)
       auth client ts --out dir      write the typed TypeScript client of this app's routes into dir
       auth admin grant --email x    make the owner of a verified address an admin
       auth admin create --email x [--name y] [--password-stdin]
                                     create a user with a verified address and admin rights
                                     (--json prints the result as JSON, --dry-run changes nothing)

examples:
  myapp auth migrate status
  myapp auth migrate --dry-run
  myapp auth migrate check && myapp serve
  myapp auth migrate sql > schema.sql
  myapp auth info --json
  myapp auth secret --value | gopass insert -f myapp/auth-secret
  myapp auth client ts --out web/src/auth
  myapp auth admin grant --email alice@example.com
  echo "$ADMIN_PASSWORD" | myapp auth admin create --email root@example.com --name Root --password-stdin
  myapp auth admin create --email root@example.com --dry-run --json
`
```
<!-- /ds:block hash=be83bd -->

The server then checks the schema before it listens:

<!-- ds:block id=requiremigrated-nmbrfr8y -->
**requireMigrated** · [`examples/cli/main.go:128-139`](../../examples/cli/main.go#L128-L139)

```go
func requireMigrated(ctx context.Context, a *auth.Auth) error {
	states, err := a.MigrationStatus(ctx)
	if err != nil {
		return err
	}
	for _, s := range states {
		if !s.Applied || s.Changed {
			return errPending
		}
	}
	return nil
}
```
<!-- /ds:block hash=c6bc69 -->

A deploy runs `myapp auth migrate --dry-run` to see what would change, `myapp auth migrate sql > schema.sql` when a DBA applies DDL by hand, and `myapp auth migrate` to apply. `myapp auth migrate orphans` lists tables and columns whose plugin is no longer wired, which is what to drop after removing a plugin. Exit codes: 0 ok, 1 failed, 2 usage.

Check: from a clean database, `myapp auth migrate status` lists every migration as pending; after `migrate`, as applied; and the server starts only then. [Migrations and maintenance](../concepts/migrations-and-maintenance.md) covers upgrades.

## Step 4 — Sweep on a schedule

Expired sessions, spent and expired verification tokens, finished rate-limit windows and each plugin's own expired rows (SMS codes, OAuth states) stay until something deletes them. Nothing in the library runs by itself, so schedule `myapp auth sweep` (or call `a.Sweep(ctx, retention)`) from cron, a Kubernetes CronJob or your scheduler, every hour or every day. It is idempotent and safe to run from several instances at once. Spent tokens are kept for `--retention`, [7 days](ds:block?id=defaultsweepretention-shqfpbr3) by default, so support can still see that a reset link was used and when.

```sh
myapp auth sweep                     # every table, default retention
myapp auth sweep --retention 720h    # keep spent tokens 30 days
```

Check: the command prints what it deleted per table; a sweep on a quiet system deletes nothing and exits 0.

A plugin with a scheduled job of its own, such as [`plugin/stale`](../plugins/stale.md)'s mail to dormant accounts or [`plugin/webhook`](../plugins/webhook.md)'s retries, runs from `myapp auth maintain` (or `a.Maintain(ctx, auth.MaintainOptions{})`). It is a separate command because it can send mail and delete accounts: schedule it daily after the sweep (every minute or so when `plugin/webhook` is wired, since its retries wait for it), and try `myapp auth maintain --dry-run` first, which prints the same counters and changes nothing.

## Step 5 — Cookies, HTTPS and domains

The session cookie is `__Host-auth_session`: `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain`. Browsers refuse a `__Host-` cookie unless all of that holds, so no other host, not even a sibling subdomain, can set or read it. The price is HTTPS everywhere except `http://localhost`, which browsers treat as secure for development.

To share the session across subdomains (`app.example.com` and `admin.example.com`), pass `authhttp.CookieDomain("example.com")` to `Handler`, `Middleware` and every adapter alike; the cookies then use the `__Secure-` prefix. Every subdomain can then read the session, including one that serves user content, so use it only when every subdomain is yours.

<!-- ds:block id=authhttp-cookiedomain-emmfkgm8 -->
**CookieDomain** · [`authhttp/authhttp.go:304`](../../authhttp/authhttp.go#L304-L304)

```go
func CookieDomain(domain string) Option { return func(c *config) { c.cookieDomain = domain } }
```
<!-- /ds:block hash=4cfcaf -->

Behind a proxy, the client IP the rate limits count is the connection's remote address. The library does not trust `X-Forwarded-For` by default, because any client could then pick its own IP and escape per-IP limits; wrap the request and set `RemoteAddr` from the header only when your proxy is the one setting it.

Check: `curl -si` against the deployed URL shows `Set-Cookie: __Host-auth_session=…; Path=/; HttpOnly; Secure; SameSite=Lax`, and a `POST` with an `Origin` of another site answers `403 auth.origin_not_trusted`.

## Step 6 — More than one instance

Sessions live in the database, so a cookie from one instance works on another with nothing to configure. Rate limits do not: each process counts in memory by default and logs `WARN auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance`. Two choices:

<!-- ds:block id=ratestore-7z8zumcj -->
**rateStore** · [`examples/multi-instance/main.go:136-147`](../../examples/multi-instance/main.go#L136-L147)

```go
func rateStore(redisAddr string) (auth.Option, error) {
	if redisAddr == "" {
		log.Printf("rate limits: counted in the database table %s", auth.TableNameRateLimit)
		return auth.WithDBRateStore(), nil
	}
	client := redis.NewClient(&redis.Options{Addr: redisAddr})
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("redis at %s does not answer: %w", redisAddr, err)
	}
	log.Printf("rate limits: counted in Redis at %s", redisAddr)
	return auth.WithRateStore(redisrate.New(client)), nil
}
```
<!-- /ds:block hash=b1815c -->

`auth.WithDBRateStore()` counts in the `auth_rate_limit` table, which the sweep cleans; `contrib/redis` counts in Redis. [examples/multi-instance](../../examples/multi-instance) proves five wrong passwords spread over two instances lock the account on both.

Check: with two instances behind the load balancer, five wrong passwords get `429 auth.rate_limited` on the sixth whichever instance answers.

## Step 7 — Real mail and SMS

The library sends through interfaces the app implements: `email.Mailer` (`Send(ctx, email.Mail) error`), `phone.SMSSender` (`Send(ctx, to, text string) error`), and whatever your own identifier plugins define. A send runs after the transaction commits, in the background, with a [30-second](ds:block?id=core-deliverytimeout-m93qwbsg) timeout; a failure is logged with the kind and purpose, never returned to the user, because "forgot password" must take the same time whether or not an account exists.

Three things a production mailer does: sends from a domain with SPF, DKIM and DMARC so verification mail is not spam; returns an error when the provider refuses, so the failure reaches the log; and does not retry forever, because the user can ask for a new link with `POST /auth/email/resend`. Set `email.Templates` or `email.TemplatesByLocale` for your own wording; the defaults are short English.

Check: sign up on the deployed app and receive the verification mail within a few seconds; the log shows no `auth: delivery failed` line.

A message lost to a provider outage or a deploy that killed the process is only logged by default. Turn on [`auth.WithDeliveryOutbox`](../concepts/identifiers-and-verification.md#survive-a-crash-or-a-failing-mailer-withdeliveryoutbox) and schedule `a.SendOutbox` (or `myapp auth sweep`) to retry it, and use [`auth.WithBackground`](../concepts/identifiers-and-verification.md#run-deliveries-on-your-own-workers-withbackground) on a serverless platform that freezes the process after the response.

## Step 8 — Logging and monitoring

`auth.WithLogger(*slog.Logger)` sets where the core logs: a failed delivery (`auth: delivery failed`, with the kind and the purpose), a failed outbox write, and the start-up and first-request warnings. The `auth operation failed` line for an internal error, with the operation id and the error, is written by the transport, so give `authhttp.Logger(l)` the same logger (the gin, echo and fiber adapters take the same `authhttp` options); both default to `slog.Default()`. Internal errors never reach a response (`500 auth.internal` carries no detail), and secrets are redacted in every format: a token, a password or a code prints as `[redacted]` even in a logged request struct.

<!-- ds:block id=opt-withlogger-pbykcub2 -->
**WithLogger** · [`auth.go:570-577`](../../auth.go#L570-L577)

```go
func WithLogger(l *slog.Logger) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithLogger", l) {
			return
		}
		s.logger = l
	}
}
```
<!-- /ds:block hash=0e1c5f -->

`examples/observability` wires the logger, an observer and OpenTelemetry tracing in one place, and passes the logger to the transport too:

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

### Feed a SIEM: the security event stream

Use this for alerting on attacks rather than counting calls. `auth.WithSecuritySink(sink, auth.SecurityQueue{})` hands every rate-limit excess (once per window), credential-stuffing crossing, two-factor lockout and geo refusal to your own log drain or SIEM client as a typed `auth.SecurityEvent`, in batches, on the sink's own goroutine, so a slow sink never delays a sign-in; `auth.WithSecurityLog(auth.SecurityQueue{})` writes the same events as log lines. A full queue drops new events and counts them in `a.SecurityStats()`, so export `Dropped` with your metrics. See [Security events](../concepts/security-events.md).

### Count outcomes: WithObserver

Use this for metrics: calls per operation, errors by code, latency. [`auth.WithObserver(o)`](ds:block?id=opt-withobserver-8mvzpdru) calls `o.Operation` once at the end of every call, through every transport, with an [`auth.OperationEvent`](ds:block?id=core-operationevent-9qmvrxbe): the operation, the plugin, the transport, the duration and the error. It never sees the request or the answer, so nothing secret can reach a metric. The outcome worth counting is the error's code, never its text:

<!-- ds:block id=obs-observer-operation-m8pbc5rb -->
**callLog.Operation** · [`examples/observability/main.go:180-190`](../../examples/observability/main.go#L180-L190)

```go
func (l *callLog) Operation(ctx context.Context, e auth.OperationEvent) {
	rec := callRecord{Op: e.Op.ID, Plugin: e.Plugin, Outcome: authotel.OutcomeOK}
	if e.Err != nil {
		rec.Outcome = auth.ErrorOf(e.Err).Code
	}
	l.mu.Lock()
	l.calls = append(l.calls, rec)
	l.mu.Unlock()
	l.logger.InfoContext(ctx, "auth call", "op", string(rec.Op), "plugin", rec.Plugin,
		"transport", string(e.Transport), "outcome", rec.Outcome, "duration", e.Duration.String())
}
```
<!-- /ds:block hash=c82dcd -->

`authotel.Observer(mp)` from contrib/otel is the same thing as an OpenTelemetry counter and duration histogram.

### Trace every call: WithTracer and contrib/otel

Use this when you already run distributed tracing and want each auth call as a span under the request's. [`auth.WithTracer(t)`](ds:block?id=opt-withtracer-5xh2rq8m) starts a span per call, per hook, per data hook and per statement the core runs (`auth.db <verb> <table>`, never the SQL or its arguments). The core knows nothing about OpenTelemetry; `authotel.Tracer(tp)` from [contrib/otel](../../contrib/otel/README.md), its own module, gives the spans their OpenTelemetry shape, and `authotel.Options(tp, mp)` returns both options at once. Wrap `authhttp.Handler` with `otelhttp.NewHandler` so the operation span is a child of the request's. The example builds a plain SDK provider and logs each span as it ends; a real app plugs in its exporter:

<!-- ds:block id=obs-tracer-provider-8emg4nk3 -->
**newTracerProvider** · [`examples/observability/main.go:205-207`](../../examples/observability/main.go#L205-L207)

```go
func newTracerProvider(p sdktrace.SpanProcessor) *sdktrace.TracerProvider {
	return sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(p))
}
```
<!-- /ds:block hash=7a2a4c -->

Try it: a wrong password, then the right one. The refused call's span has status `Error` with the code as its description, the observer records the same code, and the logger reports a verification mail the provider rejected (lines trimmed of their time):

```text
{"level":"INFO","msg":"span","name":"auth.db select auth_password","status":"Unset","description":"","duration":"28.583µs"}
{"level":"INFO","msg":"span","name":"auth.operation password.sign-in","status":"Error","description":"password.invalid_credentials","duration":"77.857625ms"}
{"level":"INFO","msg":"auth call","op":"password.sign-in","plugin":"password","transport":"http","outcome":"password.invalid_credentials","duration":"77.896ms"}
{"level":"INFO","msg":"span","name":"auth.db insert auth_session","status":"Unset","description":"","duration":"51.458µs"}
{"level":"INFO","msg":"auth call","op":"password.sign-in","plugin":"password","transport":"http","outcome":"ok","duration":"77.091ms"}
{"level":"ERROR","msg":"auth: delivery failed","kind":"email","purpose":"verify","error":"mail provider rejected the message"}
```

The two sign-ins take the same time on purpose: a wrong password costs one hash, like a right one.

What to watch: the count of `auth.rate_limited` answers (an attack or a broken client), `auth: delivery failed` lines (the mail provider), `500 auth.internal` answers (the database), and the duration of the sweep. Every operation runs through one pipeline, so one HTTP middleware of yours timing requests by path covers all of them.

Check: `TestObservability` in `examples/observability` asserts the observer's outcomes in order, two `auth.operation password.sign-in` spans with the first in `Error`, the session insert as a child of the good sign-in's span, the delivery failure at ERROR, and the password nowhere in the log. By hand: point the mailer at a closed port and find the `auth: delivery failed` line with `kind=email purpose=verify`.

## Step 9 — The security checklist

Each line is something the library does not do for you, or does only if you let it.

- HTTPS everywhere; the cookie will not work otherwise.
- `AUTH_BASE_URL` is the URL the browser shows. Every other origin that posts with the cookie is in `AUTH_TRUSTED_ORIGINS`, and nothing else is.
- Keys come from a secret store and are not in the image, the repository or the log.
- `myapp auth migrate` runs from the deploy; servers refuse an old schema.
- `myapp auth sweep` runs on a schedule.
- `myapp auth maintain` runs on a schedule when a plugin has a job (`plugin/stale`, `plugin/webhook`), after a `--dry-run` was read.
- Refusals reach someone who reads them: a security sink, or at least `auth.WithSecurityLog`.
- A shared rate store when there is more than one instance.
- Password policy decided: `password.MinLength`, `password.RequireClasses`, and `password.CheckBreached(hibp.New())` to refuse passwords found in breaches.
- `email.RequireVerified()` if an unverified address must not sign in.
- Two-factor offered (`plugin/twofactor`) or passkeys (`plugin/passkey`) where the accounts are worth it.
- Your own tables never write to `auth_*` tables; reads and joins are fine.
- A `Content-Security-Policy` and the other response headers on your pages; the library sets none.
- The `WARN` lines at start-up are read, not ignored.

## What can go wrong

| Symptom | Fix |
|---|---|
| `auth: AUTH_SESSION_IDLE="7d" is not a positive duration such as 168h` | Durations are Go syntax: hours at most (`168h`). |
| Users signed out after every deploy | Sessions are in the database, so this is a key: stateless sessions or the snapshot cache with a key generated at start-up. Set the key from the secret store. |
| `429 auth.rate_limited` from one instance but not another | In-memory rate store. Pass `auth.WithDBRateStore()` or the Redis store to every instance. |
| `auth migrations are pending; run "auth migrate" first` (the example's own message) | The deploy did not run `myapp auth migrate`. |
| `auth: delivery failed kind=email purpose=verify error=…` | The mailer returned an error; the user exists and can ask for a new link with `POST /auth/email/resend`. |
| Mail links point at `http://localhost:8081` | `AUTH_BASE_URL` is unset in production. |

## Next

- [Configuration](../concepts/configuration.md): every option, with its default.
- [Migrations and maintenance](../concepts/migrations-and-maintenance.md), [security](../concepts/security.md), [rate limits](../concepts/rate-limits.md).
- [Troubleshooting](../reference/troubleshooting.md) when something answers an error you did not expect.
- [examples/observability](../../examples/observability) and [examples/delivery-outbox](../../examples/delivery-outbox): logging, metrics and tracing, and mail that survives a failing provider, end to end.
