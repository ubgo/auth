# Guest sessions

You will let a visitor use the app before they have said who they are: a cart, a trial, a draft, kept under a guest session. When the guest signs up or signs in, by any method, your hook moves their data to the real account inside the same transaction, and the guest row is deleted. A guest is an ordinary user with no identifier, so your tables that reference a user work for a guest unchanged.

Use this plugin for trial-before-sign-up and cart hand-over, where asking for an address first costs you the visitor.

## Before you start

- An app with at least one real sign-in method wired, as in [your first app](../start/first-app.md): the guest must have something to become.
- The example program this guide is built from, with a `main_test.go` that drives the same steps and a `README.md` with the same transcript: [`examples/guest-sessions`](../../examples/guest-sessions/).
- The reference for every option, route and error is the package's [README](../../plugin/anonymous/README.md).

## Step 1 — Wire the plugin with your link hook

The example wires email, passwords and guests. `OnLink` is the one line the app adds:

<!-- ds:block id=newauth-7g3nq8wx -->
**newAuth** · [`examples/guest-sessions/main.go:115-126`](../../examples/guest-sessions/main.go#L115-L126)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			anonymous.New(anonymous.OnLink(moveCart)),
		),
		auth.WithDataHooks(auth.DataHooks{User: auth.TableHooks[auth.User]{BeforeDelete: deleteCart}}),
	)
}
```
<!-- /ds:block hash=accd89 -->

The hook receives the guest and the account, and the transaction the sign-in runs in. It moves the app's rows; the plugin deletes the guest right after it returns. An error fails the sign-in and leaves the guest as it was, so a cart is never lost half way:

<!-- ds:block id=movecart-2p9xr5kt -->
**moveCart** · [`examples/guest-sessions/main.go:133-136`](../../examples/guest-sessions/main.go#L133-L136)

```go
func moveCart(ctx context.Context, tx sqlb.DBTX, guest, user auth.User) error {
	_, err := tx.ExecContext(ctx, "UPDATE app_cart_item SET user_id = ? WHERE user_id = ?", user.ID, guest.ID)
	return err
}
```
<!-- /ds:block hash=31e662 -->

<!-- ds:block id=linkfunc-5r8nq3vd -->
**LinkFunc** · [`plugin/anonymous/anonymous.go:99`](../../plugin/anonymous/anonymous.go#L99-L99)

```go
type LinkFunc func(ctx context.Context, tx sqlb.DBTX, guest, user auth.User) error
```
<!-- /ds:block hash=2b52b8 -->

The cart table is an ordinary app table holding a user id, with no foreign key (the library creates none); the app's `User.BeforeDelete` hook removes a deleted user's cart, which is why the move has to run first:

<!-- ds:block id=cartschema-4m8kt2vz -->
**cartSchema** · [`examples/guest-sessions/main.go:72-75`](../../examples/guest-sessions/main.go#L72-L75)

```go
`CREATE TABLE IF NOT EXISTS app_cart_item (
	user_id TEXT NOT NULL,
	item TEXT NOT NULL
)`
```
<!-- /ds:block hash=15522e -->

The plugin adds one column to `auth_user`, [`is_anonymous`](ds:block?id=colisanonymous-7h2kq9mw), through its own migration; `a.Migrate` creates it with everything else.

Check: `go run ./guest-sessions` prints `listening on http://localhost:8081`, and `GET /cart` answers `401` to a visitor with no session.

## Step 2 — Start a guest session

`sign-in` takes no identifier. It creates a user named [`Guest`](ds:block?id=defaultname-m3xc8t4e) (`WithName` changes how the name is made) and starts a session:

```sh
O='Origin: http://localhost:8081'
curl -s -c cookies.txt -X POST localhost:8081/auth/anonymous/sign-in -H "$O" -d '{}'
```

```json
{"user":{"id":"usr_jvptwzit6fqupar25t5yklu5","name":"Guest","image":""}}
```

The cart handler asks only for a signed-in user (`authhttp.RequireUser`), so it works for the guest:

```sh
curl -s -b cookies.txt -X POST localhost:8081/cart -H "$O" -d '{"item":"lamp"}'
curl -s -b cookies.txt -X POST localhost:8081/cart -H "$O" -d '{"item":"chair"}'
```

```json
{"userId":"usr_jvptwzit6fqupar25t5yklu5","items":["lamp"]}
{"userId":"usr_jvptwzit6fqupar25t5yklu5","items":["lamp","chair"]}
```

From Go:

<!-- ds:block id=plugin-signin-6t3hk9ua -->
**Plugin.SignIn** · [`plugin/anonymous/anonymous.go:338-340`](../../plugin/anonymous/anonymous.go#L338-L340)

```go
func (p *Plugin) SignIn(ctx context.Context) (SignInResult, error) {
	return p.signIn.Call(ctx, SignInRequest{})
}
```
<!-- /ds:block hash=0ec594 -->

<!-- ds:block id=signinresult-4q7zd2vx -->
**SignInResult** · [`plugin/anonymous/anonymous.go:329-332`](../../plugin/anonymous/anonymous.go#L329-L332)

```go
type SignInResult struct {
	User  auth.UserView `json:"user"`
	Token auth.Token    `json:"-"`
}
```
<!-- /ds:block hash=ea6074 -->

Check: a guest asking for another guest session is refused, so a page that reloads cannot pile up guest rows. Guest creation is limited to [10](ds:block?id=signiniplimit-9v4bq2zp) per IP per [hour](ds:block?id=signinipwindow-2k7xw8rt) (`WithSignInLimit`):

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/anonymous/sign-in -H "$O" -d '{}'
```

```json
{"error":{"code":"anonymous.already","message":"You already have a guest session."}}
```

## Step 3 — The guest signs up, and the cart follows

The sign-up runs with the guest's cookie. Every sign-in method ends by creating a session, and that is where the plugin's hook runs: the request's user is the guest, the new session's user is the account. Your `OnLink` moves the cart, the guest is deleted, and the new session replaces the cookie:

```sh
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H "$O" \
  -d '{"identifier":"alice@example.com","password":"correct horse battery","name":"Alice"}'
curl -s -b cookies.txt localhost:8081/cart
```

```json
{"user":{"id":"usr_uaheceq3wu6wxfh4hsayj2sd","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"userId":"usr_uaheceq3wu6wxfh4hsayj2sd","items":["lamp","chair"]}
```

The same happens when a guest signs in to an existing account: with a password, a magic link, an emailed or texted code, a social provider, a passkey, or a method you add later. Nothing links for a session of the same user, for an admin's impersonation, or for a request that carries no guest.

Check: `a.User(ctx, guestID)` answers `auth.user_not_found` once the link ran, and [`an.IsAnonymous(ctx, userID)`](ds:block?id=plugin-isanonymous-8w2nt6kp) answers false for the account.

## Options you may want

| Option | Use it when |
|---|---|
| `anonymous.KeepUsers()` | Guest rows have value of their own. The guest stays after linking, and the `delete` route is not registered. |
| `anonymous.WithName(fn)` | Guests need distinct names ("Visitor 4812"). |
| `anonymous.SweepStale()` | Guests who never signed up should go away: `a.Sweep` deletes guests older than the retention whose every session has expired. Off by default, because deleting a user runs your `BeforeDelete` hook over its rows. |
| `anonymous.WithSignInLimit(n, window)` | Another limit on guest creation per IP. |

A guest may delete their own account with `POST /anonymous/delete`; a real account is refused:

<!-- ds:block id=plugin-delete-3n8vq5yc -->
**Plugin.Delete** · [`plugin/anonymous/anonymous.go:346-349`](../../plugin/anonymous/anonymous.go#L346-L349)

```go
func (p *Plugin) Delete(ctx context.Context) error {
	_, err := p.remove.Call(ctx, struct{}{})
	return err
}
```
<!-- /ds:block hash=9c8757 -->

A guest who adds and verifies an address or number of their own stops being a guest: the flag clears, and a later sign-in to another account no longer links them away. That is the other way out of guest status, for an app whose settings page lets a guest add an email.

## From TypeScript

Use this when a browser or app page lets a visitor start before signing up: a cart, a draft, a trial. The [typed client](../client/README.md) has the two routes as `client.anonymous.signIn` and `client.anonymous.delete`; list `anonymous()` in `plugins` with the sign-up methods the guest will use later.

Start a guest session, then sign up in the same browser. Nothing else is called: the sign-up's session creation runs the server's `OnLink`, which moves the guest's data and deletes the guest:

<!-- ds:block id=tsp-anonymous-guest-4nq8wk2x -->
**guestThenAccount** · [`clients/ts/examples/plugin-signin.ts:27-33`](../../clients/ts/examples/plugin-signin.ts#L27-L33)

```typescript
export async function guestThenAccount(address: string, secret: string): Promise<string | null> {
  const guest = await auth.anonymous.signIn();
  if (guest.error && guest.error.code !== "anonymous.already") return null;
  // ... the guest fills a cart ...
  const account = await auth.password.signUp({ identifier: address, password: secret });
  return account.data?.user.id ?? null;
}
```
<!-- /ds:block hash=26b2bd -->

A guest who leaves can delete the guest account:

<!-- ds:block id=tsp-anonymous-leave-7wm3qk9n -->
**leaveAsGuest** · [`clients/ts/examples/plugin-signin.ts:38-41`](../../clients/ts/examples/plugin-signin.ts#L38-L41)

```typescript
export async function leaveAsGuest(): Promise<boolean> {
  const { error } = await auth.anonymous.delete();
  return error === null;
}
```
<!-- /ds:block hash=620d59 -->

The codes a frontend handles: `anonymous.already` when the browser already has a guest session (keep using it; a page that calls `signIn` on every load meets this), `anonymous.not_anonymous` from `delete` on a real account, `auth.rate_limited` (guest creation is limited per IP). The rest is in [What can go wrong](#what-can-go-wrong).

There is no runnable TypeScript example for guests yet; the blocks above are type-checked by `task ts:check`, and Steps 2 and 3 show the same calls with curl.

Pitfalls:

- **The upgrade must happen in the browser that holds the guest session.** The link runs because the sign-up request carries the guest's cookie (or bearer token); a sign-up from another device starts a fresh account and the guest's data stays behind.
- **Call `signIn` once, not on every page load.** Read `client.session()` first; a guest is signed in like anyone else, with the name `Guest` by default.

Every method with its route and types: [TypeScript client reference › anonymous](../reference/ts-client.md#anonymous).

## What can go wrong

| Error | When | Fix |
|---|---|---|
| `anonymous.already` (409, "You already have a guest session.") | A guest called `sign-in` again. | Use the session you have; the client should not ask twice. |
| `anonymous.not_anonymous` (403, "This is not a guest account.") | A real account called `delete`. | Account deletion for real users is the app's own feature (`a.DeleteUser`). |
| `auth.rate_limited` (429) | More than 10 guests from one IP in an hour. | Wait, or raise `WithSignInLimit` behind a shared NAT. |
| The sign-in fails with your own error | `OnLink` returned it. | The guest is untouched; fix the move and let the user try again. |
| The cart is gone after sign-up | No `OnLink`, and the app's `BeforeDelete` hook deleted the guest's cart with the guest. | Add `OnLink`, or `KeepUsers()`. |

Known limits:

- A guest session is a cookie: whoever holds the device holds the cart.
- The link runs on session creation. A sign-in that issues no session (a sign-up that still needs verification) links nothing yet; the link runs when the person signs in afterwards from the same guest session.

## Next

- [Sessions](../concepts/sessions.md): what a guest session is, and the "remember me" choice `sign-in` accepts.
- [Hooks](../extending/03-hooks.md): the data hook mechanism this plugin is built on.
- The package [README](../../plugin/anonymous/README.md) is the full reference; the Go reference is on [pkg.go.dev](https://pkg.go.dev/github.com/ubgo/auth/plugin/anonymous).
