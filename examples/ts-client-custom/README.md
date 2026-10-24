# Your own plugin in a typed TypeScript client

An app with a plugin of its own, `nickname` (two operations and an error code), and a TypeScript frontend that calls it through a client the app generated from its own operation list with `auth client ts`. The prebuilt client in [`clients/ts`](../../clients/ts/) cannot do this: it knows only the library's plugins. The guide that walks through it is [docs/client/custom-plugins.md](../../docs/client/custom-plugins.md).

## Layout

| Path | What it is |
|---|---|
| `nickname/nickname.go` | The plugin: `nickname.set` (POST) and `nickname.get` (GET), a column on `auth_user`, the code `nickname.too_long` |
| `main.go` | Wires email, password and nickname; routes `auth ...` to `authcli.Main`; a `go:generate` directive that writes the client |
| `main_test.go` | The plugin over HTTP end to end, and the freshness check: `auth client ts` into a temporary folder must equal `web/src/auth` |
| `web/src/auth/` | The five generated files, committed. Never edit them |
| `web/src/app-auth.ts` | The app's client, with `nickname()` beside `email()` and `password()` |
| `web/src/nickname-form.ts` | Frontend code calling `client.nickname.set` and `.get`, switching on `nickname.too_long` |
| `web/demo.ts` | Runs the frontend code from Node, in bearer mode, against a running server |

## Run it

From `examples/`:

```sh
go run ./ts-client-custom auth client ts --out ts-client-custom/web/src/auth   # or: go generate ./ts-client-custom
go test ./ts-client-custom
tsc -p ts-client-custom/web
```

```text
ts-client-custom/web/src/auth/client.ts
ts-client-custom/web/src/auth/error-codes.ts
ts-client-custom/web/src/auth/index.ts
ts-client-custom/web/src/auth/runtime.ts
```

Then the server, and the frontend code against it from Node 22.18 or later (the first release that runs a `.ts` file without a flag):

```sh
PORT=8096 go run ./ts-client-custom
AUTH_URL=http://localhost:8096/auth node ts-client-custom/web/demo.ts
```

```text
password.signUp: user usr_b552aiqvalhgvmk4ilupe7w2
nickname before: null
saveNickname("Ada"): { saved: 'Ada' }
saveNickname(40 letters): { error: 'That nickname is too long.' }
nickname after: Ada
nickname signed out: null
```

The user id differs on every run; every other line is the same. The database is `ts-client-custom.db` (SQLite) in the current directory. Writing the client opens no database.

## Checked by

- `go test ./ts-client-custom`: `TestNickname_TheClientsCallsWork` (the calls over HTTP) and `TestClient_GeneratedCopyIsCurrent` (fails when the Go side changed and nobody regenerated).
- `task ts:check` in the repository root: `tsc` under `strict` over `web/`.
- `web/demo.ts` itself is run by hand only (the transcript above); the Go test makes the same calls over HTTP. For client code that a test runs with Node, see [ts-client-flows](../ts-client-flows/) and [ts-client-bearer](../ts-client-bearer/).
