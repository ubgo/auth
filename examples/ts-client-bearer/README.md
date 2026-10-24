# The TypeScript client without a browser

Two Node programs using the typed client from [`clients/ts`](../../clients/ts/) where no browser keeps the session cookie for them. `web/cli.ts` is a command-line program in bearer mode: its `TokenStore` is a file, so it stays signed in from one run to the next, and its custom `fetch` names the program and times out. `web/server.ts` is server-side code for a browser (the shape of a server-rendering or backend-for-frontend app): it forwards the browser's `Cookie` header on a client made for that one request. The guide is [docs/client/bearer-and-mobile.md](../../docs/client/bearer-and-mobile.md).

## Layout

| Path | What it is |
|---|---|
| `main.go` | The server: email and password under `/auth`. Bearer mode needs no server option; the client asks for it per request with the `Auth-Token-Mode` header |
| `web/cli.ts` | `sign-up`, `sign-in`, `whoami`, `sign-out`; the token in `.auth-token` (or `$AUTH_TOKEN_FILE`), written with mode `0600` and deleted on sign-out; exit 0 done, 1 refused, 2 wrong command line |
| `web/server.ts` | `GET /` answers `hello <name>` for the browser whose cookie it forwarded, or 401 `signed out` |
| `web/node.d.ts` | The few Node APIs the two programs call, so `tsc` checks them with no npm install. With `@types/node` installed, delete it |
| `main_test.go` | Runs each CLI command as its own process and checks its output, exit code and the token file; signs in like a browser and asks `server.ts` for its page with that cookie, without one and after sign-out |

## Run it

From `examples/`, start the server in one terminal:

```sh
PORT=8111 go run ./ts-client-bearer
```

### A CLI that stays signed in

In another terminal, with Node 22.18 or later. Each line is a new process; only the file carries the session from one to the next.

```sh
export AUTH_URL=http://localhost:8111
node ts-client-bearer/web/cli.ts sign-up ada@example.com "correct horse battery staple" Ada
ls -l .auth-token
node ts-client-bearer/web/cli.ts whoami
node ts-client-bearer/web/cli.ts sign-out
node ts-client-bearer/web/cli.ts whoami
node ts-client-bearer/web/cli.ts sign-in ada@example.com wrong
```

```text
signed up and signed in as Ada; token saved
-rw-------@ 1 khanakia  staff  43 Oct 12 15:11 .auth-token
Ada (token read from .auth-token)
signed out; token file removed
not signed in (auth.signed_out)
The sign-in details are not right. (password.invalid_credentials)
```

The last two exit with status 1, so a script can test `whoami` before doing anything else. The token is a credential: whoever reads the file is signed in as Ada until it is signed out or expires, which is why it is written owner-only.

### A server forwarding the browser's cookie

With the API still running, start the Node server and sign in the way a browser does (curl keeps the cookie in a jar and sends the page's Origin). The cookie is for `localhost`, so the page is asked for on `localhost` too, as a browser would:

```sh
AUTH_URL=http://localhost:8111 PORT=8112 node ts-client-bearer/web/server.ts &
curl -s -c jar -H 'Origin: http://localhost:8111' -H 'Content-Type: application/json' \
  -d '{"identifier":"bea@example.com","password":"correct horse battery staple","name":"Bea"}' \
  http://localhost:8111/auth/password/sign-up
curl -si -b jar http://localhost:8112/ | sed -n '1p;$p'
curl -si http://localhost:8112/ | sed -n '1p;$p'
```

```text
listening on http://127.0.0.1:8112
{"user":{"id":"usr_olp75ohvtels5x7nf4hivg7v","name":"Bea","image":""},"verificationRequired":false,"secondFactorRequired":false}
HTTP/1.1 200 OK
hello Bea
HTTP/1.1 401 Unauthorized
signed out
```

The forwarding works for reads. A mutation sent with a cookie must also carry an Origin the API trusts, which server-side code does not have, so server code that changes something calls the Go API in-process or uses bearer mode.

The database is `ts-client-bearer.db` (SQLite) in the current directory.

## Checked by

- `go test ./ts-client-bearer`: `TestCLI_TheTokenSurvivesARestart` (eight CLI runs, each a new process: output, exit code, the file's presence and its `0600` mode) and `TestServer_ForwardsTheBrowsersCookie` (200 with the cookie, 401 without, 401 with the same cookie after sign-out). Both fail, never skip, when Node is missing or older than 22.18.
- `task ts:check` in the repository root: `tsc` under `strict` over `web/`.
