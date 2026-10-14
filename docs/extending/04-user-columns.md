# Add columns to the user table

You will have a plugin that adds a column to `auth_user`, fills it when a user is created, and an app that reads it as a flat field of its own user struct, all in one query.

## Before you start

- A plugin with a `Name()` method, wired into `auth.New` ([plugin anatomy](01-plugin-anatomy.md)). This guide builds on [examples/custom-plugin](../../examples/custom-plugin), a referral-code plugin whose code is quoted below.
- The rule this guide works within: reads are open, writes are closed. An app may `SELECT` and `JOIN` the auth tables freely, but no row of a core table is written except through the library, and a plugin writes its own column through one function, `auth.SetUserColumn`.
- The column must be small: a flag, a timestamp, a short string or a number (`auth.ColumnBool`, `auth.ColumnTimestamp`, `auth.ColumnText`, `auth.ColumnInt`). Anything larger belongs in a table of the plugin's own ([tables and migrations](05-tables-and-migrations.md)).

## Step 1 — Declare the column as a typed expression

The column is declared once as an `sqlb.Expr[T]`, so every query that names it carries its Go type: comparing it to the wrong type is a compile error, and the scan target is checked too. The type is `*string` because the column is nullable, and nullable means pointer.

<!-- ds:block id=code-zcb8fwrm -->
**Code** · [`examples/custom-plugin/referral/referral.go:33`](../../examples/custom-plugin/referral/referral.go#L33-L33)

```go
var Code = sqlb.Col[*string](auth.TableUser, ColCode)
```
<!-- /ds:block hash=b47c92 -->

Check: the name is also used by the migration, so pick it with the plugin's name in it (`referral_code`, not `code`); two plugins cannot both add a column with one name, and a bare name is how that happens.

## Step 2 — Tell the core about the column

`Columns()` is the optional interface `auth.ColumnExtender`. The core writes the migration for every engine, with the right type spelling for each, and records it under the plugin's name; the plugin writes no DDL. Only `auth_user` can be extended, because it is the one row every request loads.

<!-- ds:block id=plugin-columns-2szmrbsf -->
**Plugin.Columns** · [`examples/custom-plugin/referral/referral.go:91-93`](../../examples/custom-plugin/referral/referral.go#L91-L93)

```go
func (p *Plugin) Columns() []auth.ColumnExtension {
	return []auth.ColumnExtension{{Table: auth.TableNameUser, Name: ColCode, Type: auth.ColumnText, Nullable: true, Unique: true}}
}
```
<!-- /ds:block hash=e3959e -->

A `NOT NULL` column needs a `Default`, so rows created before the plugin was added can be filled. `Unique: true` adds a unique index.

An app with no plugin to write adds its own columns the same way with `auth.WithUserColumns(cols...)`: the same `ColumnExtension` (`Table` may be left empty), the same checks, migrated under the owner [`app`](ds:block?id=core-appname-3kq8vz2m), and written through `auth.SetUserColumn(ctx, a, auth.AppName, userID, col, value)`. A column a plugin also adds fails `auth.New`, and no plugin may be named `app`.

<!-- ds:block id=opt-withusercolumns-7mt4wq9k -->
**WithUserColumns** · [`columns.go:75-77`](../../columns.go#L75-L77)

```go
func WithUserColumns(cols ...ColumnExtension) Option {
	return func(s *settings) { s.userColumns = append(s.userColumns, cols...) }
}
```
<!-- /ds:block hash=7e625d -->

Check: `a.MigrationSQL()` now contains the plugin's part. For SQLite the example's test reads it back:

<!-- ds:block id=testreferral-migrationiswrittenbythecore-kz5natn3 -->
**TestReferral_MigrationIsWrittenByTheCore** · [`examples/custom-plugin/main_test.go:117-131`](../../examples/custom-plugin/main_test.go#L117-L131)

```go
func TestReferral_MigrationIsWrittenByTheCore(t *testing.T) {
	a := newTestAuth(t)
	ddl, err := a.MigrationSQL()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ALTER TABLE auth_user ADD COLUMN referral_code",
		"CREATE UNIQUE INDEX auth_user_referral_code_key ON auth_user (referral_code)",
	} {
		if !strings.Contains(ddl, want) {
			t.Fatalf("migration SQL lacks %q:\n%s", want, ddl)
		}
	}
}
```
<!-- /ds:block hash=1313ee -->

What the database holds after `a.Migrate` (from the example's README, run on SQLite):

```text
CREATE UNIQUE INDEX auth_user_referral_code_key ON auth_user (referral_code)
referral|0000_column_auth_user_referral_code
```

## Step 3 — Write the column through SetUserColumn

A plugin fills its column in a data hook ([hooks](03-hooks.md)). `AfterCreate` on the user table runs inside the transaction that creates the user, so a user never exists without the value, and a failure anywhere in that transaction rolls the user back too. `auth.SetUserColumn` is the one sanctioned write to a core table: it refuses a column the plugin did not add, and a source test in the library (`TestGuard_PluginsNeverWriteCoreTables`) keeps the library's own plugins on it.

<!-- ds:block id=plugin-datahooks-fejs8nh6 -->
**Plugin.DataHooks** · [`examples/custom-plugin/referral/referral.go:99-112`](../../examples/custom-plugin/referral/referral.go#L99-L112)

```go
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{User: auth.TableHooks[auth.User]{
		AfterCreate: func(ctx context.Context, _ sqlb.DBTX, u *auth.User) error {
			code, err := newCode()
			if err != nil {
				return err
			}
			// ctx carries the sign-up's transaction. SetUserColumn is the one
			// sanctioned write to a core table, and it refuses a column this
			// plugin did not add.
			return auth.SetUserColumn(ctx, p.a, PluginName, u.ID, Code, &code)
		},
	}}
}
```
<!-- /ds:block hash=29be22 -->

The `ctx` the hook receives carries the transaction; pass it on, or the write escapes the rollback.

Check: a sign-up that fails after the hook ran leaves no user and no code. The example proves it with a second plugin that refuses the identity row:

<!-- ds:block id=testreferral-failedsignupleavesnocode-wtf7tuzk -->
**TestReferral_FailedSignUpLeavesNoCode** · [`examples/custom-plugin/main_test.go:83-111`](../../examples/custom-plugin/main_test.go#L83-L111)

```go
func TestReferral_FailedSignUpLeavesNoCode(t *testing.T) {
	a, err := auth.New(
		auth.WithDB(openTestDB(t), sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(discard))), password.New(), referral.New(), refuser{address: bobEmail}),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	b := newBrowser(t, newHandler(a))
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	post[errorAnswer](t, newBrowser(t, newHandler(a)), "/auth/password/sign-up", fields{"identifier": bobEmail, "password": testPassword}, http.StatusInternalServerError)

	var users, codes int64
	q, err := a.Select().Columns(sqlb.Bind(sqlb.Count(), &users), sqlb.Bind(sqlb.CountOf(referral.Code), &codes)).From(auth.TableUser).Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlb.One(context.Background(), a.DB(), q); err != nil {
		t.Fatal(err)
	}
	if users != 1 || codes != 1 {
		t.Fatalf("%d users and %d codes after the failed sign-up, want 1 and 1", users, codes)
	}
}
```
<!-- /ds:block hash=f45f6e -->

## Step 4 — Give the app a struct for the column

The app's user struct is composed from each plugin's columns struct. The convention the library follows (its ADR-0001, "struct shape follows the schema"): a column on `auth_user` is a flat field, and anything reached by a join is a nested struct. A plugin exports its columns struct and a `Bindings` function that pairs each column with its scan target.

<!-- ds:block id=referralcolumns-aefg6jvc -->
**ReferralColumns** · [`examples/custom-plugin/referral/referral.go:39-41`](../../examples/custom-plugin/referral/referral.go#L39-L41)

```go
type ReferralColumns struct {
	ReferralCode *string
}
```
<!-- /ds:block hash=3c501e -->

<!-- ds:block id=bindings-rjc6nqd2 -->
**Bindings** · [`examples/custom-plugin/referral/referral.go:46-48`](../../examples/custom-plugin/referral/referral.go#L46-L48)

```go
func Bindings(c *ReferralColumns) []sqlb.Binding {
	return []sqlb.Binding{sqlb.Bind(Code, &c.ReferralCode)}
}
```
<!-- /ds:block hash=aed739 -->

## Step 5 — Read the column in the plugin

Inside an operation ([operations](02-operations.md)) the plugin needs only its own column, so it reads it with `LoadUserColumns`, which takes any bindings:

<!-- ds:block id=plugin-docode-854s72jz -->
**Plugin.doCode** · [`examples/custom-plugin/referral/referral.go:125-134`](../../examples/custom-plugin/referral/referral.go#L125-L134)

```go
func (p *Plugin) doCode(ctx context.Context, c *auth.Call, _ struct{}) (CodeResult, error) {
	var cols ReferralColumns
	if err := p.a.LoadUserColumns(ctx, c.User.ID, Bindings(&cols)...); err != nil {
		return CodeResult{}, err
	}
	if cols.ReferralCode == nil {
		return CodeResult{}, nil // a user from before the plugin was added
	}
	return CodeResult{Code: *cols.ReferralCode}, nil
}
```
<!-- /ds:block hash=ebe04b -->

Check: a user created before the plugin was added has a `nil` pointer here; decide what the operation answers for them.

## Step 6 — Compose the app's user and load it in one query

The app embeds `auth.User`, each plugin's columns struct, and anything of its own, and makes the result an `auth.Scannable` by giving it a `Bindings` method. `a.LoadUser` then fills it in one statement.

<!-- ds:block id=appuser-yeztggtk -->
**appUser** · [`examples/custom-plugin/main.go:121-125`](../../examples/custom-plugin/main.go#L121-L125)

```go
type appUser struct {
	auth.User
	email.EmailColumns
	referral.ReferralColumns
}
```
<!-- /ds:block hash=e7875a -->

<!-- ds:block id=appuser-bindings-rwjrxxbw -->
**appUser.Bindings** · [`examples/custom-plugin/main.go:130-132`](../../examples/custom-plugin/main.go#L130-L132)

```go
func (u *appUser) Bindings() []sqlb.Binding {
	return sqlb.Bindings(auth.UserBindings(&u.User), email.Bindings(&u.EmailColumns), referral.Bindings(&u.ReferralColumns))
}
```
<!-- /ds:block hash=e65fd4 -->

<!-- ds:block id=mehandler-brfx2pez -->
**meHandler** · [`examples/custom-plugin/main.go:145-155`](../../examples/custom-plugin/main.go#L145-L155)

```go
func meHandler(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var u appUser
		if err := a.LoadUser(r.Context(), authhttp.MustUser(r).ID, &u); err != nil {
			authhttp.WriteError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, PrimaryEmail: u.PrimaryEmail, ReferralCode: u.ReferralCode}) // a client that hung up cannot be told
	})
}
```
<!-- /ds:block hash=0135e6 -->

Check: `GET /me` returns the email plugin's `primary_email` and the referral code together, with one query behind it.

## Step 7 — When the data is not on auth_user: a nested struct and a join

Phone numbers live in `auth_identity`, not on `auth_user`, so the phone plugin's part of the composite user is a nested struct filled through a `LEFT JOIN`. The struct implements the optional `auth.Joiner` interface, and `a.LoadUser` adds the joins to the same statement. This is the shape to copy when your plugin's data lives in a table of its own.

<!-- ds:block id=appuser-dtrcdfrt -->
**appUser** · [`examples/phone-only/main.go:120-123`](../../examples/phone-only/main.go#L120-L123)

```go
type appUser struct {
	auth.User
	Phone phone.Data
}
```
<!-- /ds:block hash=1928c6 -->

<!-- ds:block id=appuser-bindings-r6fpbeqm -->
**appUser.Bindings** · [`examples/phone-only/main.go:128-130`](../../examples/phone-only/main.go#L128-L130)

```go
func (u *appUser) Bindings() []sqlb.Binding {
	return sqlb.Bindings(auth.UserBindings(&u.User), phone.UserBindings(&u.Phone))
}
```
<!-- /ds:block hash=dc2e09 -->

<!-- ds:block id=appuser-joins-zpjfxhmt -->
**appUser.Joins** · [`examples/phone-only/main.go:135`](../../examples/phone-only/main.go#L135-L135)

```go
func (u *appUser) Joins() []sqlb.Join { return []sqlb.Join{phone.UserJoin()} }
```
<!-- /ds:block hash=e37f18 -->

Check: a user with no phone still loads; `u.Phone.Exists()` is false and `u.Phone.Number` is empty, because the join is `LEFT`.

## What can go wrong

Every one of these is returned by `auth.New`, so a broken plugin fails at start-up with the plugin named, never in a request.

| Error | When |
|---|---|
| `auth: two owners for one column: plugin "x" extends "auth_session"; only auth_user is extendable` | `Table` is not `auth.TableNameUser`. |
| `auth: two owners for one column: column name "Code" must match ^[a-z][a-z0-9_]{0,30}$` | The name has an uppercase letter, a dash, or is too long. |
| `auth: two owners for one column: column "x" has unknown type "varchar"` | `Type` is not one of `auth.ColumnTypeValues`. |
| `auth: two owners for one column: column "x" is NOT NULL with no default, so existing rows cannot be filled` | `Nullable: false` with an empty `Default`. |
| `auth: two owners for one column: column "auth_user"."referral_code" is added by "referral" and by plugin "growth"` | Two plugins add one column name. The example's test `TestReferral_TwoOwnersOfAColumnFailAtStartUp` triggers it. |

At run time:

| Error | When |
|---|---|
| `auth: plugin writes a column it does not own: "growth" writes "referral_code"` | `SetUserColumn` was called with a plugin name that did not add the column. It is a programming error in the plugin, not a user-facing one. |
| `auth.user_not_found` (404, "Not found.") | `LoadUser` or `LoadUserColumns` for an id that no longer exists. |

## Next

- [Tables and migrations](05-tables-and-migrations.md): give a plugin a table of its own when a column is not enough.
- [Testing a plugin](09-testing-plugins.md): the test that proves a failed transaction leaves no column value.
- [examples/custom-plugin](../../examples/custom-plugin), the whole program with its transcript; [examples/admin-plan](../../examples/admin-plan), the app's own tables joined to `auth_user` with typed columns.
