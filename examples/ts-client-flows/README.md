# Every mailed flow from TypeScript

The typed TypeScript client from [`clients/ts`](../../clients/ts/) running the flows beyond a plain sign-in, from Node in bearer mode: email verification, a password reset, a magic link, sign out everywhere, a second factor by mailed code, re-authenticating the current session and an organization. The server keeps mail in an in-memory inbox at `/dev/mail`, so the script reads each link or code the way a person reads their mailbox, then posts the token the way the page the link opens would. The guide is [docs/client/flows.md](../../docs/client/flows.md).

## Layout

| Path | What it is |
|---|---|
| `main.go` | The server: email (login, recovery), password, magic link, a second factor by mailed code (`twofactor.DeliveredCodes`, `WithoutTOTP`) and organizations, under `/auth` |
| `devmail.go` | Example only: an `email.Mailer` that keeps every message, and `GET /dev/mail?to=…`, which answers each message's subject, first link and first six-digit code. A real app sends mail and never serves it |
| `web/flows.ts` | The client calls, one block per flow, printing one fixed line per call and failing on the first unexpected answer |
| `web/tsconfig.json` | `strict` type check of the script; the expected error codes are typed `AuthErrorCode`, so a misspelt code does not compile |
| `main_test.go` | Starts the server on a random port, runs `node web/flows.ts` against it and compares every printed line |

## Run it

From `examples/`, in one terminal:

```sh
PORT=8110 go run ./ts-client-flows
```

In another, with Node 22.18 or later (it runs the `.ts` file directly):

```sh
AUTH_URL=http://localhost:8110 node ts-client-flows/web/flows.ts
```

```text
email verification
  ok   password.signUp: signed in as Ada
       mail: "Verify your email address"
  ok   email.verify: address verified
  err  email.verify (same link again): auth.token_invalid
password reset
  ok   password.forgot: check_your_inbox
       mail: "Reset your password"
  ok   password.reset
  err  password.signIn (old password): password.invalid_credentials
  ok   password.signIn (new password): signed in as Ada
magic link
  ok   magiclink.send
       mail: "Your sign-in link"
  ok   magiclink.signIn: signed in as Ada
  err  magiclink.signIn (same link again): auth.token_invalid
sign out everywhere
  ok   session (laptop): Ada
  ok   session (phone): Ada
  ok   signOutAll (from the phone)
  err  session (laptop): auth.signed_out
  err  session (phone): auth.signed_out
second factor by mailed code
  ok   password.signIn: secondFactorRequired=false
  ok   twofactor.enroll: method=delivered enabled=false
       mail: "Your sign-in code"
  ok   twofactor.confirm: 10 recovery codes
  ok   signOut
  ok   password.signIn: secondFactorRequired=true
  err  session (pending): auth.signed_out
  ok   twofactor.send
       mail: "Your sign-in code"
  err  twofactor.verify (wrong code): twofactor.code_invalid
  ok   twofactor.verify
  ok   session: Ada
re-authentication on the current session
  err  password.reauthenticate (wrong password): password.invalid_credentials
  ok   password.reauthenticate: fresh=false secondFactorRequired=true
  ok   twofactor.send
       mail: "Your sign-in code"
  ok   twofactor.reauthenticate: fresh=true
  ok   sessions (the same one, now fresh): same id: true
organizations
  ok   organization.create: Acme
  ok   organization.invite
       mail: "You are invited to join an organization"
  ok   organization.list: Acme (owner)
  ok   organization.setActive: active: Acme
flows: every step answered as expected
```

Each run uses new addresses, so it can run again against the same database. The database is `ts-client-flows.db` (SQLite) in the current directory.

## What each block shows

- **Email verification.** Sign-up mails a link; the page it opens posts `?token=` to `email.verify`. A link works once: the second post is `auth.token_invalid`, which the page shows as "this link has expired".
- **Password reset.** `password.forgot` answers `check_your_inbox` whether or not the address has an account. The reset link's token and the new password go to `password.reset`; the old password stops working.
- **Magic link.** A second client (the phone) asks for a link and signs in with its token, once.
- **Sign out everywhere.** Each client is one device with its own token store. `signOutAll` from the phone ends the laptop's session too.
- **Second factor.** Enrolling the mailed-code method sends a first code that `twofactor.confirm` checks; it answers the recovery codes. From then on a sign-in answers `secondFactorRequired: true` and the session is pending (signed out to every other call) until `twofactor.send` mails a code and `twofactor.verify` accepts it. A wrong code is `twofactor.code_invalid`.
- **Re-authentication.** A change that needs a recent sign-in (`password.change`, `twofactor.disable`, account deletion) answers `auth.fresh_session_required` once the session is older than the fresh window; `password.reauthenticate` makes the session the user already has fresh again, with no new session or token. Ada has a second factor, so the password alone answers `fresh: false` with `secondFactorRequired: true` and a `ticket`; `twofactor.send` mails a code, and `twofactor.reauthenticate({ code, ticket })` finishes it. The session list then shows the same session id as before.
- **Organizations.** Create one, invite a colleague (who gets a mail), list your organizations with your role, make one active.

## Checked by

- `go test ./ts-client-flows`: `TestFlows_TheScriptRunsEveryFlow` runs the script with Node and compares the whole output above. It fails, never skips, when Node is missing or older than 22.18.
- `task ts:check` in the repository root: `tsc` under `strict` over `web/`.
