# ent: your own tables beside the library's

You will have an app that uses ent for its own tables, opened on the same database the library uses, writing an ent row in the same transaction as a library call, and reading `auth_user` from the app side with typed handles next to ent queries.

## Before you start

- [Databases](../concepts/databases.md) and [Transactions](../concepts/transactions.md): the library owns its tables and migrates them itself, and `a.Tx` is the one transaction the app's writes join.
- The example is [`examples/ent-alongside`](../../examples/ent-alongside/main.go), with a generated ent client for one app table (`Note`). Its tests run on SQLite and prove the rollback; run them with `go test ./ent-alongside` from `examples`.
- There is no `contrib/ent` module and no ent schema for an auth table. ent describes your tables; the library describes its own, and the two never share a schema, a migration or a generated type.
- `examples/go.mod` pins `entgo.io/ent v0.14.5`, whose `go` directive (1.23) fits the module's `go 1.25.0`.

## Step 1 — Open ent on the library's database

Pass the same `*sql.DB` to `auth.WithDB` and to ent. They then share one connection pool, one set of limits and one place the database is closed. Use ent's name for the engine (`dialect.SQLite`, `dialect.Postgres`, `dialect.MySQL`), which is not always the `database/sql` driver name:

<!-- ds:block id=entalong-open-4kd2m7qx -->
**openEnt** · [`examples/ent-alongside/main.go:101-103`](../../examples/ent-alongside/main.go#L101-L103)

```go
func openEnt(db *sql.DB) *ent.Client {
	return ent.NewClient(ent.Driver(entsql.OpenDB(entDialect, db)))
}
```
<!-- /ds:block hash=83b552 -->

Check: `client.Note.Query().Count(ctx)` answers on the same file the library migrated.

## Step 2 — Migrate each side with its own tool

The library creates its tables with `a.Migrate`; ent creates the app's tables with `client.Schema.Create`. ent's schema holds no auth table, so its migration has nothing to alter in them, and the library's ledger knows nothing about yours. Run the library first so a foreign key from your table to `auth_user` could resolve (the example uses none, as every app table beside the library does). On SQLite, ent's migrator needs foreign keys on (`_pragma=foreign_keys(1)`).

Keeping auth tables out of ent's schema is what makes a plain `Schema.Create` safe: it only ever sees your tables.

## Step 3 — Share one transaction

`a.Tx` hands the callback a plain `*sql.Tx`, and ent can run on it: build a driver from `entsql.Conn{ExecQuerier: tx}` and give that to a client. Every statement through that client runs on the library's transaction, and every library call made with the callback's `ctx` joins the same one:

<!-- ds:block id=entalong-txclient-9wr3hcvb -->
**txClient** · [`examples/ent-alongside/main.go:123-125`](../../examples/ent-alongside/main.go#L123-L125)

```go
func txClient(tx *sql.Tx) *ent.Client {
	return ent.NewClient(ent.Driver(entsql.NewDriver(entDialect, entsql.Conn{ExecQuerier: tx})))
}
```
<!-- /ds:block hash=280148 -->

<!-- ds:block id=entalong-create-m5tn8zpe -->
**createUserWithNote** · [`examples/ent-alongside/main.go:132-148`](../../examples/ent-alongside/main.go#L132-L148)

```go
func createUserWithNote(ctx context.Context, a *auth.Auth, name, body string, fail bool) (auth.User, error) {
	var u auth.User
	err := a.Tx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		if u, err = a.CreateUser(ctx, auth.NewUser{Name: name}); err != nil {
			return err
		}
		if _, err = txClient(tx).Note.Create().SetUserID(u.ID).SetBody(body).Save(ctx); err != nil {
			return err
		}
		if fail {
			return errRollback
		}
		return nil
	})
	return u, err
}
```
<!-- /ds:block hash=7ba35d -->

If the callback returns an error, the user, the identity and the ent row all roll back, and no mail queued by the library goes out. The example's test forces a failure after both writes and checks that neither row exists; it was broken on purpose (ent writing through the database instead of the transaction) and fails with `database is locked`, so it does catch the mistake.

Two rules follow from this:

- **Write through the returned client directly.** Do not call `.Tx(ctx)` on it: that would begin a second transaction inside the library's. Do not use ent's own `client.Tx` for a write that must commit with a library call, because then the library's `a.Tx` and ent's are two transactions and cannot commit as one; the library owns begin and commit by design (see [Transactions](../concepts/transactions.md), step 1).
- **Send nothing from inside the callback.** Use `a.AfterCommit` for work that must wait for the commit, as in the transactions page.

## Step 4 — Read auth tables with handles, not strings

An app may read the auth tables freely; it must not write them. Read `auth_user` with the library's exported sqlb column handles, and your own tables with ent:

<!-- ds:block id=entalong-list-c2vj6ahs -->
**listUsersWithNotes** · [`examples/ent-alongside/main.go:163-187`](../../examples/ent-alongside/main.go#L163-L187)

```go
func listUsersWithNotes(ctx context.Context, a *auth.Auth, client *ent.Client) ([]UserRow, error) {
	var row UserRow
	q, err := a.Select().
		Columns(sqlb.Bind(auth.UserID, &row.ID), sqlb.Bind(auth.UserName, &row.Name)).
		From(auth.TableUser).
		Order(sqlb.OrderBy(auth.UserCreatedAt, sqlb.SortAsc), sqlb.OrderBy(auth.UserID, sqlb.SortAsc)).
		Build()
	if err != nil {
		return nil, err
	}
	var out []UserRow
	if err := sqlb.Each(ctx, a.DB(), q, func() error {
		out = append(out, row) // the targets are reused for every row
		return nil
	}); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Notes, err = client.Note.Query().Where(note.UserID(out[i].ID)).All(ctx)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
```
<!-- /ds:block hash=6e5dee -->

Check: running the example prints `usr_… Alice notes=1`. The handles (`auth.UserID`, `auth.UserName`) are typed, so comparing a column to the wrong Go type does not compile.

## What can go wrong

| You see | Why | Fix |
|---|---|---|
| `database is locked` on SQLite inside the callback | ent wrote through the database (`openEnt(db)`) while the library's transaction held the writer. | Write through `txClient(tx)`. |
| `foreign_keys pragma is off` from `Schema.Create` | ent's SQLite migrator requires foreign keys. | Add `_pragma=foreign_keys(1)` to the DSN. |
| The ent row survives a failed sign-up | The row was written with a client opened on the database, not on `tx`. | Build the client from `tx` inside the callback. |
| ent generates a type for `auth_user` | Its schema describes an auth table. | Delete that schema. Read the table with sqlb handles. |

## Next

- [Transactions](../concepts/transactions.md) for what the library does inside `a.Tx`.
- [Databases](../concepts/databases.md) for reading auth tables and the stable columns.
