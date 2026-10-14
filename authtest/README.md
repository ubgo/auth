# authtest

The test harness for an app that embeds the library. One call builds the library on a fresh database, with recorders where the plugins send mail and texts, a clock the test moves, and a signed-in session in every form a request can carry. It is part of the core module and imports no database driver: the test imports its own, and the harness opens the database by driver name.

```go
import (
    "github.com/ubgo/auth/authtest"
    _ "modernc.org/sqlite"
)

func newEnv(t *testing.T) *authtest.Env {
    return authtest.New(t, authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin {
        return []auth.Plugin{
            email.New(email.Login(), email.Recover(), email.WithMailer(e.Mail)),
            password.New(password.Argon2(password.Argon2Params{Memory: 64, Time: 1, Threads: 1})),
        }
    }))
}
```

The guide is [Test your app](../docs/start/testing.md); the recipe is [examples/app-tests](../examples/app-tests).

## What you get

| Piece | What it does |
|---|---|
| `authtest.New(t, opts...)` | Opens SQLite in memory (one shared-cache database per `Env`), wires the plugins and options over a frozen clock and a memory rate store, migrates, and closes everything in `t.Cleanup`. Any failure fails the test |
| `authtest.WithPlugins(fn)` | The plugin list, as a function of the `Env` so the plugins take `e.Mail` and `e.SMS`. Required |
| `authtest.WithOptions(opts...)` | More `auth.Option`s, after the harness's own |
| `authtest.WithDB(db, dialect)` | Run on an open Postgres or MySQL instead of SQLite |
| `authtest.WithSQLite(driver, dsn)` | Another SQLite driver or a file |
| `authtest.WithBaseURL(u)` | Replace `authtest.BaseURL` (`https://app.example.test`) |
| `e.CreateUser(name, ids...)` | A user with verified, primary identities, through the real core API |
| `e.NewUser(name, ids...)` | A [`UserFixture`](ds:block?id=authtest-userfixture-9kd2wq7m) built in memory and not saved, as better-auth's `ctx.test.createUser` returns one: its final id from the `Auth`'s generator, [`DefaultUserName`](ds:block?id=authtest-defaultusername-4hq8zn2w) when `name` is empty, the `Env` clock as `CreatedAt`, and the identities. Edit it, refer to its id, then save it. Nothing is checked until then |
| `e.SaveUser(f)` | Writes a fixture through the real core API (`CreateUser` with its id, then each identity as verified and primary), so every hook and uniqueness rule runs; returns the stored `auth.User` |
| `e.DeleteUser(id)` | Deletes the user through `a.DeleteUser`, its identities, sessions and plugin rows with it, as better-auth's `deleteUser` |
| `e.SignIn(userID)` | A `Session`: `Cookie()`, `Authorization()`, `Apply(req)`, `ApplyBearer(req)`, `Context(ctx)`, `BearerContext(ctx)`; a user with a second factor gets a pending session, as a sign-in plugin would create |
| `e.Anonymous(ctx)` | A signed-out browser request from the app's origin |
| `e.Browser(handler)` | A TLS test server with a cookie jar sending the app's `Origin`: `Post(path, body)`, `Get(path)`, `Do(req)`, `SetSession(s)`, `Cookie(name)`; redirects are not followed |
| `Response` | `Expect(status)`, `Decode(&v)`, `ErrorCode()`, plus `Status`, `Header`, `Body` |
| `e.Mail` | An `email.Mailer` that records: `Sent()`, `To(addr)`, `Last(addr)`, `LastLink(addr)`, `LastToken(addr)`, `LastCode(addr)`, `Reset()`. Every reader waits for deliveries in flight |
| `e.SMS` | A `phone.SMSSender` that records: `To(number)`, `LastCode(number)`, `Reset()` |
| `e.Clock` | `Now()`, `Advance(d)`, `Set(t)`; starts at the real time, rounded to microseconds |
| [`authtest.WithFaults(f)`](ds:block?id=authtest-withfaults-5rm9xc2p) | Runs the `Env`'s SQLite through a fault counter ([`authtest.Faults`](ds:block?id=authtest-faults-8kv3qd7n), from `authtest.NewFaults()`), kept as `e.Faults`; disarmed until `f.Arm(n)` makes the n-th database call (exec, query, prepare, begin, commit) fail with [`authtest.ErrFault`](ds:block?id=authtest-errfault-3wq8mz5k), and `f.Disarm()` reports whether it was reached |
| `authtest.SweepFaults(t, fresh, setup, swallowOK...)` | [Runs an operation](ds:block?id=authtest-sweepfaults-2pz7wk4d) once per database call it makes, each on a fresh `Env` from `fresh` with a different call failing, and fails the test when a faulted run returns no error, or when no run finishes within [`authtest.MaxFaultSteps`](ds:block?id=authtest-maxfaultsteps-6tn2hv9q) calls: the proof that a plugin surfaces every database failure. `swallowOK` names the steps where swallowing is documented. `f.Connector(base)` and `authtest.DSNConnector(driver, dsn)` wrap any other `database/sql` driver the same way |

## Rules it follows

- A request body that carries a password is a map, not the library's request type: `password.Secret` (an `auth.Token`) encodes as `"[redacted]"` on purpose, so marshalling `password.SignInRequest` would send that text. A request type that carries a link or poll token (`invite.TokenRequest`, `email.TokenRequest`, `emailchallenge.StartOrToken`) uses `auth.WireToken`, which encodes as its value, so it can be posted as it is.
- The browser is TLS because the session cookie is `__Host-` and `Secure`, and a cookie jar keeps such a cookie only for an `https` URL.
- The clock starts at the real time: an HTTP client judges cookie expiries against the real clock and would drop every cookie from a clock in the past.
- `SignIn` goes through `auth.CreateSession`, so a user who must pass a second factor gets a pending session, exactly as after a password sign-in. A test of the whole sign-in flow calls the plugin's operation through the browser instead.
