# Integration tests

The end-to-end suite: it runs the library against real databases and proves what unit tests cannot, that each engine accepts the SQL, that values come back exactly as written, and that SQLite, Postgres and MySQL give the same answers. Most of the library's behaviour is tested here.

It is a separate Go module, so the three database drivers it needs never reach the go.mod of an app that imports `github.com/ubgo/auth`.

## Run it

```sh
task integration    # SQLite only; part of task check
task test:engines   # SQLite, Postgres and MySQL, race detector on
task cover          # coverage of every library package, this suite and the unit tests merged
```

SQLite always runs. Postgres and MySQL run when their DSN is set, and a run without one says so on stderr instead of passing quietly:

| Variable | Engine | What `task test:engines` uses |
|---|---|---|
| `AUTH_TEST_PG_DSN` | Postgres | the host Postgres, database `auth_test`, created by `task engines:pg` |
| `AUTH_TEST_MYSQL_DSN` | MySQL 8 | compose.yml's throwaway `mysql` profile on 127.0.0.1:33070, started by `task engines:mysql` and removed after `task test:engines` |

Each test starts from empty tables. Two runs against the same Postgres or MySQL database at once drop each other's tables, so give a parallel run its own database.

## Write a test

`harness_test.go` has what a test needs:

- `eachEngine(t, func(t *testing.T, e *env) {…})` runs the body once per reachable engine, on an empty database.
- `e.newAuth(t, opts, plugins...)` builds and migrates an `*auth.Auth` on that database, with the test clock and an in-memory rate store.
- `e.emailPlugin()`, `e.passwordPlugin()` and `e.phonePlugin()` are the common plugins wired to fakes; `e.mail` and `e.sms` record what was sent (`LastToken`, `LastCode`), and `e.clock.Advance` moves time.
- `request(a, token)` and `anon(a)` give a context that looks like a browser request, signed in or not.

A test file per area keeps helpers apart: name it after the area, and prefix its helpers with the area's name so they never collide inside the one `integration` package.

## Database failures

`faultdb_test.go` holds a database driver that fails on demand. `sweepFaults(t, setup)` runs an operation once per database call it makes, each time on a fresh SQLite database with a different call failing, and asserts that every failure reaches the caller as an error:

```go
func TestFaults_PasswordSignIn(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		pw := e.passwordPlugin()
		a := e.newAuth(t, nil, e.emailPlugin(), pw)
		// set-up runs with faults off
		return func(context.Context) error {
			_, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: "alice@example.com", Password: "correct horse battery"})
			return err
		}
	})
}
```

A failure that an operation swallows on purpose (a best-effort "last used" write, say) is named in the call as an allowed step, so the exception is written down at the test rather than hidden.

## Helper commands

| Command | What it does |
|---|---|
| [`cmd/covmerge`](cmd/covmerge) | Merges coverage profiles and prints coverage per package; a block counts as covered when any run executed it. `task cover` uses it |
| [`cmd/mdwrap`](cmd/mdwrap) | Fails on hard-wrapped prose in any Markdown file of the repository; `task docs:wrap`, part of `task check` |
| [`cmd/featref`](cmd/featref) | Writes `docs/reference/features.md`, the feature index, from its rows: each guide cell resolved from the page's real headings, each example cell written only when the row's expression matches that example's code; `task docs:features`, and `task docs:features:check` in `task check` fails on a stale page or a row that no longer holds |
