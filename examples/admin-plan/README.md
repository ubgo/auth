# An admin page with each user's plan

An admin table of users with their plan and project count, newest first, in one query. The plan and the projects are the app's own tables; the query joins them to `auth_user` with typed columns on both sides. Banning and unbanning are the admin plugin's routes.

## Run it

```sh
cd examples
go run ./admin-plan                          # serve on localhost:8081
go run ./admin-plan grant alice@example.com  # make the first admin
```

It creates `admin-plan.db` (SQLite), the library's tables and the app's `app_plan` and `app_project`, and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./admin-plan`.

## Walkthrough

Alice signs up and verifies her address (the token comes from the mailed link in the log). The first admin has to come from code, so the program has a `grant` command; it accepts only a verified address:

```sh
go run ./admin-plan grant alice@example.com
```

```text
alice@example.com (usr_gg6whrqi66ncvdquttddz2kn) is an admin
```

Bob signs up and verifies too, picks a plan and creates two projects. Plans are a closed set:

```sh
O='Origin: http://localhost:8081'
curl -s -b bob.txt -X POST localhost:8081/plan -H "$O" -d '{"plan":"pro"}'
curl -s -b bob.txt -X POST localhost:8081/projects -H "$O"
curl -s -b bob.txt -X POST localhost:8081/projects -H "$O"
curl -s -b bob.txt -X POST localhost:8081/plan -H "$O" -d '{"plan":"platinum"}'
```

```json
{"plan":"pro"}
{"id":"prj_whswcdqheh7jc4y67cafz7e2"}
{"id":"prj_duazd5tluwtk7nhi2xwivjfw"}
{"error":{"code":"plan.unknown","message":"There is no such plan."}}
```

Carol signs up and does nothing else. Bob is not an admin:

```sh
curl -s -b bob.txt localhost:8081/admin/users
```

```json
{"error":{"code":"admin.forbidden","message":"Only an administrator can do this."}}
```

Alice is. Carol's `email` is null because only a verified primary address is copied to `auth_user`:

```sh
curl -s -b alice.txt localhost:8081/admin/users
```

```json
{"users":[{"id":"usr_vt4fymu6ndfuowopmm3mgqpc","email":null,"createdAt":"2026-09-29T08:21:02.739974Z","banned":false,"plan":null,"projects":0},{"id":"usr_tldnrp5dzgjvjs3alrynvgtm","email":"bob@example.com","createdAt":"2026-09-29T08:21:02.284849Z","banned":false,"plan":"pro","projects":2},{"id":"usr_gg6whrqi66ncvdquttddz2kn","email":"alice@example.com","createdAt":"2026-09-29T08:21:01.767564Z","banned":false,"plan":null,"projects":0}],"page":1,"limit":50}
```

Pages:

```sh
curl -s -b alice.txt 'localhost:8081/admin/users?page=2&limit=2'
```

```json
{"users":[{"id":"usr_gg6whrqi66ncvdquttddz2kn","email":"alice@example.com","createdAt":"2026-09-29T08:21:01.767564Z","banned":false,"plan":null,"projects":0}],"page":2,"limit":2}
```

Alice bans Bob through the admin plugin. His session stops working at once, because the plugin adds "not banned" to every session lookup, and the app's list shows the ban from the plugin's column:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/admin/ban -H "$O" -d '{"userId":"usr_tldnrp5dzgjvjs3alrynvgtm","reason":"chargeback"}'
curl -s -b bob.txt localhost:8081/auth/session
curl -s -b alice.txt 'localhost:8081/admin/users?limit=2'
curl -s -b alice.txt -X POST localhost:8081/auth/admin/unban -H "$O" -d '{"userId":"usr_tldnrp5dzgjvjs3alrynvgtm"}'
```

```json
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"users":[{"id":"usr_vt4fymu6ndfuowopmm3mgqpc","email":null,"createdAt":"2026-09-29T08:21:02.739974Z","banned":false,"plan":null,"projects":0},{"id":"usr_tldnrp5dzgjvjs3alrynvgtm","email":"bob@example.com","createdAt":"2026-09-29T08:21:02.284849Z","banned":true,"plan":"pro","projects":2}],"page":1,"limit":2}
{"ok":true}
```

## The code

The app declares its tables as typed columns, the same way the library and its plugins declare theirs:

```go
var (
	TablePlan    = sqlb.Table{Name: "app_plan", Alias: "pl"}
	PlanUserID   = sqlb.Col[string](TablePlan, "user_id")
	PlanName     = sqlb.Col[Plan](TablePlan, "plan")
	TableProject = sqlb.Table{Name: "app_project", Alias: "pj"}
	ProjectID    = sqlb.Col[string](TableProject, "id")
	ProjectOwner = sqlb.Col[string](TableProject, "owner_id")
)
```

The query mixes the core's columns (`auth.UserID`), the email plugin's (`email.PrimaryEmail`), the admin plugin's (`admin.BannedAt`) and the app's. Each binding pairs a column with a Go destination of the same type, so a mismatch is a compile error:

```go
plan := sqlb.Nullable(PlanName) // null for a user without a plan row
a.Select().
	Columns(
		sqlb.Bind(auth.UserID, &dst.row.ID),
		sqlb.Bind(email.PrimaryEmail, &dst.row.Email),
		sqlb.Bind(auth.UserCreatedAt, &dst.row.CreatedAt),
		sqlb.Bind(admin.BannedAt, &dst.bannedAt),
		sqlb.Bind(plan, &dst.row.Plan),
		sqlb.Bind(sqlb.CountOf(ProjectID), &dst.row.Projects),
	).
	From(auth.TableUser).
	Join(
		sqlb.Join{Type: sqlb.JoinLeft, Table: TablePlan, On: []sqlb.Predicate{sqlb.EqExpr(PlanUserID, auth.UserID)}},
		sqlb.Join{Type: sqlb.JoinLeft, Table: TableProject, On: []sqlb.Predicate{sqlb.EqExpr(ProjectOwner, auth.UserID)}},
	).
	GroupBy(auth.UserID, email.PrimaryEmail, auth.UserCreatedAt, admin.BannedAt, plan).
	Order(sqlb.OrderBy(auth.UserCreatedAt, sqlb.SortDesc), sqlb.OrderBy(auth.UserID, sqlb.SortAsc)).
	Limit(limit).
	Offset((page - 1) * limit)
```

The SQL it builds on SQLite (`go test -v -run UsersQuery ./admin-plan`):

```sql
SELECT "u"."id", "u"."primary_email", "u"."created_at", "u"."admin_banned_at", "pl"."plan", count("pj"."id") FROM "auth_user" AS "u" LEFT JOIN "app_plan" AS "pl" ON ("pl"."user_id" = "u"."id") LEFT JOIN "app_project" AS "pj" ON ("pj"."owner_id" = "u"."id") GROUP BY "u"."id", "u"."primary_email", "u"."created_at", "u"."admin_banned_at", "pl"."plan" ORDER BY "u"."created_at" DESC, "u"."id" ASC LIMIT ? OFFSET ?
```

The admin check is the app's own rule as middleware; it reads the admin plugin's column like any other column of the user:

```go
mux.Handle("GET /admin/users", signedIn(authhttp.RequireFunc(requireAdmin(a))(adminUsersHandler(a))))
```

Reading and joining the auth tables is open to the app. Writing them is not: the ban goes through the plugin's route, which also ends Bob's sessions and refuses to ban another admin.

`main_test.go` checks every row of the list, the second page, the refusals (unverified grant, non-admin, unknown plan, `page=0`) and the ban round trip.

## Limits

- Only the columns [stability_test.go](../../stability_test.go) lists are a stable contract, and `auth_user.primary_email` and `auth_user.admin_banned_at` are not among them yet: plugin columns may change between versions. Using the plugins' typed columns (`email.PrimaryEmail`, `admin.BannedAt`) instead of strings turns such a change into a compile error rather than a runtime one.
- The admin plugin's own `GET /auth/admin/users` lists users without app data; this page is the app's, because only the app knows what a plan is.
- The app schema is SQLite's; on Postgres or MySQL use `auth.TypesFor(engine).Key` for the id columns.

## What this used

- [`github.com/ubgo/sqlb`](https://pkg.go.dev/github.com/ubgo/sqlb): `Col`, `Bind`, `Join`, `Nullable`, `CountOf`, `OrderBy`, `Each`
- [`plugin/admin`](https://pkg.go.dev/github.com/ubgo/auth/plugin/admin): `Grant`, `BannedAt`, `AdminColumns`, the ban and unban routes
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email): `PrimaryEmail`; [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `RequireFunc`
- Related: [custom-plugin](../custom-plugin) (adding a column of your own), [cli](../cli) (commands in the app's own binary).
