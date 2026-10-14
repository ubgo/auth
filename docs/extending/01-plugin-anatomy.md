# Plugin anatomy

You will have a plugin of your own, registered with `auth.New`, that the core wires, checks and refuses like the plugins the library ships with.

## Before you start

- A Go module that imports `github.com/ubgo/auth` and `github.com/ubgo/sqlb`, with an app running the quick start (`examples/quickstart`).
- The two example plugins these guides are built on: [`examples/plugin-tables/devices`](../../examples/plugin-tables/devices/devices.go) owns a table, [`examples/plugin-hooks/guard`](../../examples/plugin-hooks/guard/guard.go) hooks other plugins. Both use only exported API; `go test ./...` in `examples/` runs them.
- No knowledge of the core's internals is needed: a plugin sees the core through `*auth.Auth` and nothing else.

## Step 1 — Name the plugin

A plugin is any value with a `Name()` method. The name is the route prefix (`/auth/<name>/…`) and the owner of every migration the plugin ships, so it is stable for ever: renaming a plugin orphans its recorded migrations in every deployment.

<!-- ds:block id=core-plugin-ccn7kdrp -->
**Plugin** · [`plugin.go:21-23`](../../plugin.go#L21-L23)

```go
type Plugin interface {
	Name() string
}
```
<!-- /ds:block hash=2a3f09 -->

Keep the name a constant next to everything else the plugin registers, and return it from `Name`:

<!-- ds:block id=devices-name-zcbgc7tj -->
**Plugin.Name** · [`examples/plugin-tables/devices/devices.go:167`](../../examples/plugin-tables/devices/devices.go#L167-L167)

```go
func (p *Plugin) Name() string { return PluginName }
```
<!-- /ds:block hash=9fd92c -->

Check: the name matches `^[a-z][a-z0-9_]{0,30}$` (`auth.KindNamePattern`) and is not `core`. `auth.New` refuses anything else before it looks at the rest of the plugin.

## Step 2 — Choose the capabilities

Everything beyond `Name` is an optional interface the core type-asserts for. An absent capability is simply absent, instead of an empty method that looks the same as a forgotten one in a review. The compiler can check the ones you mean to implement; a typo in a method signature then fails the build instead of silently dropping the capability:

<!-- ds:block id=devices-interfaces-hk26c8qn -->
**_** · [`examples/plugin-tables/devices/devices.go:139-146`](../../examples/plugin-tables/devices/devices.go#L139-L146)

```go
var (
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.TableOwner        = (*Plugin)(nil)
	_ auth.TypedMigrator     = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.RateLimiter       = (*Plugin)(nil)
)
```
<!-- /ds:block hash=d2adb8 -->

The interfaces, by what they let a plugin do. Each one has its own guide.

| Interface | A plugin that implements it | Guide |
| --- | --- | --- |
| `auth.Initializer` | receives the core handle once, during `auth.New` | this one |
| `auth.Validator` | checks its own configuration and the rest of the setup | this one |
| `auth.Dependent` | names plugins that must also be registered | this one |
| `auth.OperationProvider` | serves operations: routes, GraphQL fields, Go methods | [Operations](02-operations.md) |
| `auth.RateLimiter` | declares rate limits for its operations | [Operations](02-operations.md) |
| `auth.OperationHooker` | runs before and after other plugins' operations | [Hooks](03-hooks.md) |
| `auth.DataHooker` | runs around writes to the core tables | [Hooks](03-hooks.md) |
| `auth.ColumnExtender` | adds columns to `auth_user` | [Hooks](03-hooks.md) |
| `auth.TableOwner`, `auth.TypedMigrator` (or the older `auth.Migrator`), `auth.Sweeper` | owns tables of its own | [Tables and migrations](05-tables-and-migrations.md) |
| `auth.SessionChecker`, `auth.SecondFactor` | adds conditions to every session, or a second step to sign-in | [Session rules](07-session-rules.md) |
| `auth.IdentifierProvider`, `auth.Deliverer`, `auth.SignInMethod` | registers an identifier kind (email, phone, handle), delivers messages to it, signs users in | [Identifiers and delivery](06-identifiers-and-delivery.md), with [`examples/plugin-delivery`](../../examples/plugin-delivery) |
| `auth.TokenResolver`, `auth.OriginTruster`, `auth.CredentialCounter`, `auth.Closer` | owns bearer tokens with a prefix, trusts extra origins, counts ways into an account, releases resources at shutdown | the shipped `plugin/apikey` and `plugin/oauth` are the reference |

## Step 3 — Take the core handle in Init

`Init` runs once, during `auth.New`, after every plugin's `Validate`. Keep the `*auth.Auth` it hands you: every statement, every lookup and every session a plugin makes goes through it.

<!-- ds:block id=core-initializer-uv2s5atr -->
**Initializer** · [`plugin.go:28-30`](../../plugin.go#L28-L30)

```go
type Initializer interface {
	Init(*Auth) error
}
```
<!-- /ds:block hash=cb2dd0 -->

<!-- ds:block id=devices-init-g27d2ft4 -->
**Plugin.Init** · [`examples/plugin-tables/devices/devices.go:172-175`](../../examples/plugin-tables/devices/devices.go#L172-L175)

```go
func (p *Plugin) Init(a *auth.Auth) error {
	p.a = a
	return nil
}
```
<!-- /ds:block hash=9f1f67 -->

Check: nothing in `Init` touches the database. `auth.New` does not migrate, and an app may build its `Auth` only to print the schema.

## Step 4 — Refuse a configuration nobody could use, in Validate

`Validate` runs in `auth.New` with a read-only copy of the resolved configuration. Return an error for anything that would make every call fail later: a missing key, a limit of zero, a required identifier kind that no plugin registers. A refused start is cheap; the same mistake found by the first user is a support ticket.

<!-- ds:block id=core-validator-mrnuqybj -->
**Validator** · [`plugin.go:35-37`](../../plugin.go#L35-L37)

```go
type Validator interface {
	Validate(*Config) error
}
```
<!-- /ds:block hash=ffe24e -->

<!-- ds:block id=devices-validate-qx9nrmgv -->
**Plugin.Validate** · [`examples/plugin-tables/devices/devices.go:181-186`](../../examples/plugin-tables/devices/devices.go#L181-L186)

```go
func (p *Plugin) Validate(*auth.Config) error {
	if p.max < 1 {
		return ErrBadMax
	}
	return nil
}
```
<!-- /ds:block hash=89efba -->

Check: `auth.New` wraps the error with the plugin's name, `auth: plugin "devices": devices: the device limit must be at least 1`, and `errors.Is` still finds your sentinel through the wrap.

An option that takes a func or an interface cannot return an error, so it records a nil in an `auth.OptionErrors` field instead: start the closure with `if p.optErrs.RefuseNil("devices.OnLimit", fn) { return }` (`auth.RefuseNilEach(&p.optErrs, name, list)` for a variadic one), and give the plugin `func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }`. `auth.New` calls `OptionErr` on every plugin before anything else and refuses to start with `auth.ErrNilOption` naming the option, so a nil never reaches the first request as a panic. The library's own options do this, and `TestGuard_OptionsRefuseNil` fails when one does not.

## Step 5 — Name what you depend on, in Requires

A plugin that hooks another plugin's operations, or reads its columns, needs that plugin in the list. Say so; `auth.New` then refuses a list without it instead of wiring a hook that never runs.

<!-- ds:block id=core-dependent-c92t3h3e -->
**Dependent** · [`plugin.go:42-44`](../../plugin.go#L42-L44)

```go
type Dependent interface {
	Requires() []string
}
```
<!-- /ds:block hash=e0a1c3 -->

<!-- ds:block id=guard-requires-sr5wkkdp -->
**Plugin.Requires** · [`examples/plugin-hooks/guard/guard.go:129`](../../examples/plugin-hooks/guard/guard.go#L129-L129)

```go
func (p *Plugin) Requires() []string { return []string{password.PluginName, email.PluginName} }
```
<!-- /ds:block hash=02ef7e -->

Check: build the `Auth` without the dependency once; the error is `auth: plugin dependency not registered: "guard" requires "password"`.

## Step 6 — Build it with a constructor, and register it last

Declare operations in a constructor, so the plugin value is complete before `auth.New` sees it, and take options the way the shipped plugins do. Register your plugin after the ones it depends on: plugins run in list order, and so do their hooks and migrations.

<!-- ds:block id=devices-new-ebt28tw6 -->
**New** · [`examples/plugin-tables/devices/devices.go:153-162`](../../examples/plugin-tables/devices/devices.go#L153-L162)

```go
func New(opts ...Option) *Plugin {
	p := &Plugin{max: DefaultMax}
	for _, o := range opts {
		o(p)
	}
	p.add = auth.Define(auth.OpInfo{ID: EndpointAdd, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/add"}, p.doAdd)
	p.list = auth.Define(auth.OpInfo{ID: EndpointList, Kind: auth.Query, Require: auth.SignedIn, Path: "/list"}, p.doList)
	p.remove = auth.Define(auth.OpInfo{ID: EndpointRemove, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/remove"}, p.doRemove)
	return p
}
```
<!-- /ds:block hash=0a1d9f -->

<!-- ds:block id=hooks-newauth-9mq2x3bt -->
**newAuth** · [`examples/plugin-hooks/main.go:109-124`](../../examples/plugin-hooks/main.go#L109-L124)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, *countingCache, error) {
	g := guard.New(blockedDomains...)
	cache := newCountingCache(auth.NewMemorySessionCache(cacheEntries))
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			g,
		),
		auth.WithSessionPolicy(g.SessionPolicy()),
		auth.WithSessionCache(cache, cacheTTL),
	)
	return a, cache, err
}
```
<!-- /ds:block hash=e55d3d -->

Check: `auth.New` returns no error, and the start-up log lists your migrations after the core's. From a test, `auth.PluginOf[*devices.Plugin](a)` returns the wired plugin, or `auth.ErrPluginNotRegistered`.

## How auth.New wires and refuses

`auth.New` runs these checks in order and stops at the first failure, so a start either works completely or not at all:

1. Option errors: every core option's, then each plugin's and each store's `OptionErr` (`auth.OptionChecker`). `auth: an option was given nil; leave the option out to keep its default: devices.OnLimit(nil)`.
2. Plugin names: unique, matching the pattern, not `core`. `auth: duplicate plugin name`.
3. Dependencies: every `Requires` name is in the list. `auth: plugin dependency not registered`.
4. Identifier kinds: coherent, one owner per kind, deliverable when they recover. `auth: two plugins register one identifier kind`, `auth: identifier kind is not valid`.
5. Table aliases: no two owners for one alias, none of the core's. `auth: table alias conflicts with a registered alias`.
6. Column extensions: one owner per column, a default for every `NOT NULL` column. `auth: two owners for one column`.
7. At least one plugin reports `SignsIn() == true`. `auth: no sign-in method; add a plugin such as password or oauth`.
8. Each plugin's `Validate`, then each plugin's `Init`.
9. Token prefixes, session checks, operations and hooks: ids and routes unique, every hook aimed at a registered operation. `auth: two operations share an id or a route`, `auth: hook names an operation that is not registered`, `auth: a session check can use only auth_session and auth_user`.
10. Trusted origins: each one an absolute URL. `auth: origin is not an absolute URL`.

## What can go wrong

- `auth: operation description is not valid: plugin name "Bad-Name" must match ^[a-z][a-z0-9_]{0,30}$` — the name has an upper-case letter, a dash or is too long.
- `auth: duplicate plugin name: a plugin may not be named "core"` — `core` is the owner of the core's own operations and migrations.
- `auth: plugin dependency not registered: "guard" requires "password"` — register the dependency, before the plugin that needs it.
- `auth: plugin "devices": devices: the device limit must be at least 1` — your own `Validate` error, wrapped with the plugin's name.
- `auth: plugin "x" init: …` — your own `Init` error, wrapped the same way.
- `auth: plugin not registered` — `auth.PluginOf` found no plugin of that type; it was not in `auth.WithPlugins`.
- A capability that never runs and no error — the method's signature does not match the interface, so the type assertion fails silently. Add the `var _ auth.X = (*Plugin)(nil)` line and the compiler will say so.

## Next

- [Operations](02-operations.md): the feature itself, served to every transport from one definition.
- [Hooks](03-hooks.md): changing what other plugins do without touching them.
