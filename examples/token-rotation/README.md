# Token rotation: catch a copied session token

`auth.WithTokenRotation` gives a session a new token every time its expiry slides, and treats the token it replaced as stolen when it comes back after a short grace window: the session is revoked for every holder and the security stream hears `session.token_reuse`. Inside the window the old token still works, so requests and tabs that were in flight are not signed out. Whichever of the user and a thief presents the replaced token later ends the session for both, as SuperTokens' refresh-token rotation does. The guide is the [token rotation section of Sessions](../../docs/concepts/sessions.md#catch-a-copied-token-withtokenrotation).

Here the expiry slides at most once a minute (`RefreshAfter`), so an active user's token changes about once a minute, the grace window is one minute, and the security sink prints each event to the log.

## Run it

```sh
cd examples
go run ./token-rotation
```

It creates `token-rotation.db` (SQLite) and listens on `http://localhost:8081` (`PORT` moves it). Run the tests with `go test ./token-rotation`; they move a test clock instead of waiting.

## What happens

1. Sign up or sign in: the client holds token A.
2. A minute later, the next request slides the expiry and the answer carries token B (a new session cookie, or `Set-Auth-Token` in bearer mode).
3. For the next minute A and B both work.
4. After that, a request with A revokes the session: A and B are both answered `401 auth.signed_out`, and the log shows `security session.token_reuse severity=alert`.

A browser keeps the newest cookie by itself and never notices. A client that lost the answer carrying B (a dropped connection) is signed out once the grace passes; that is the price of the detection.

## What the tests check

- `TestBearer_RotationAndReuse`: no rotation before `RefreshAfter`, a new token after it, both tokens working inside the grace, both refused after the replaced one is reused, and one `alert` event naming the session.
- `TestCookie_RotationKeepsTheBrowserSignedIn`: three rotations through the session cookie with no event, and a copy of the first cookie refused.
- `TestWithoutRotation_NothingChanges`: the same app without the option keeps one token, which works an hour later, and emits nothing.
