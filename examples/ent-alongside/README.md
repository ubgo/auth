# Use ent alongside auth

An app that keeps its own tables in ent and lets the library keep its tables. Both open on the same `*sql.DB`: ent through `entsql.OpenDB`, the library through `auth.WithDB`. Inside `a.Tx` the callback gets a plain `*sql.Tx`; ent runs on it through `entsql.NewDriver(..., entsql.Conn{ExecQuerier: tx})`, and `a.CreateUser` called with the callback's `ctx` joins the same transaction, so the new user and the app's ent row commit or roll back together. Reading `auth_user` from the app side goes through the library's sqlb handles (`auth.UserID`, `auth.UserName`), never a raw SQL string, so a renamed column keeps working and a removed one fails the build. The library migrates its own tables and ent migrates only the app's. The full walk-through is [docs/integrations/ent.md](../../docs/integrations/ent.md).

## Run it

```sh
cd examples
go run ./ent-alongside
```

It uses SQLite with `_pragma=foreign_keys(1)` in the DSN, which ent's SQLite migrator requires. Run the tests with `go test ./ent-alongside`; the rollback test forces a failure after both writes and checks that neither the user nor the note exists.

## Regenerate the ent code

```sh
cd examples/ent-alongside
go generate ./ent
```
