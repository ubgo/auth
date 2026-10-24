# Invites: invite-only sign-up with usage tracking

You will have invite codes for users: a signed-in user creates a public invite (a link with a number of uses) or a private one (mailed to one address, used once), every use is recorded with who used it and when, and, if you want, sign-up refuses anyone without a valid invite. The role an invite carries reaches your code inside the sign-up's own transaction, so a refused sign-up leaves nothing behind. It is the Go port of [better-invite](https://github.com/better-invite/better-invite).

Use this plugin for a closed beta, an internal tool, a community that grows by word of mouth, or any app where an existing member vouches for a new one. Invitations to an organization are a different feature, in [organizations](organization.md): they add an existing or new user to one organization, while this plugin decides who may have an account at all.

## Before you start

- An app with sign-in, as in [your first app](../start/first-app.md), and `plugin/email` with a mailer: `auth.New` refuses the plugin without one (`invite.ErrNoEmail`), because a private invite is mailed, unless you pass `invite.PublicOnly()`.
- The example program this guide is built from, with a `main_test.go` that drives the same steps and a `README.md` with the same transcript: [`examples/invite-only`](../../examples/invite-only/). `go run ./invite-only` in `examples/` serves it on `localhost:8081`.
- What the plugin stores: `auth_invite` (one row per invite, its token as a hash, its uses and its state) and `auth_invite_use` (one row per user per invite). Deleting a user removes the invites they created and their uses.
- What it does not do: grant anything. An invite can carry a role, which the plugin hands to your `OnAccepted` callback inside the same transaction; applying it (`admin.SetRole`, an organization membership, a row in your own table) is your code.
- The reference for every option, route and error is the package's [README](../../plugin/invite/README.md).

## Step 1 — Wire the plugin

The example makes the app invite-only and gives each invite a role from its own `app_member` table. `Required` refuses a sign-up made by a client (any public operation) with `403 invite.required`; `CanCreate` decides who may create which invite; `OnAccepted` applies the role:

<!-- ds:block id=newapp-aq3mycn4 -->
**newApp** · [`examples/invite-only/main.go:141-155`](../../examples/invite-only/main.go#L141-L155)

```go
func newApp(db *sql.DB, m email.Mailer) (*app, error) {
	x := &app{db: db, password: password.New()}
	x.invites = invite.New(
		invite.Required(),
		invite.CanCreate(x.canCreate),
		invite.OnAccepted(x.onAccepted),
	)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), x.password, x.invites),
	)
	x.auth = a
	return x, err
}
```
<!-- /ds:block hash=387409 -->

Without `CanCreate`, every signed-in user may create an invite with no role, and an invite with any role is refused. The example lets every member invite, and only the owner give a role, from a fixed set:

<!-- ds:block id=app-cancreate-9sdhf92a -->
**app.canCreate** · [`examples/invite-only/main.go:162-177`](../../examples/invite-only/main.go#L162-L177)

```go
func (x *app) canCreate(ctx context.Context, inviter auth.User, in invite.Request) error {
	if in.Role == "" {
		return nil
	}
	if !grantable[Role(in.Role)] {
		return invite.ErrForbidden
	}
	role, err := x.roleOf(ctx, inviter.ID)
	if err != nil {
		return err
	}
	if role != RoleOwner {
		return invite.ErrForbidden
	}
	return nil
}
```
<!-- /ds:block hash=2f88f2 -->

`OnAccepted` runs inside the transaction that records the use. Write on `a.Conn(ctx)`, which is that transaction; a write on your plain `*sql.DB` would survive a rollback of the sign-up. Return an error and the use and the sign-up are undone together:

<!-- ds:block id=app-onaccepted-k24c93ra -->
**app.onAccepted** · [`examples/invite-only/main.go:185-195`](../../examples/invite-only/main.go#L185-L195)

```go
func (x *app) onAccepted(ctx context.Context, acc invite.Accepted) error {
	conn, err := x.auth.Conn(ctx)
	if err != nil {
		return err
	}
	role := cmp.Or(Role(acc.Role), RoleMember)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO app_member (user_id, role, invited_by) VALUES (?, ?, ?) ON CONFLICT (user_id) DO NOTHING`,
		acc.UserID, string(role), acc.CreatedBy)
	return err
}
```
<!-- /ds:block hash=be2dec -->

Check: [`TestInviteOnly_SignUpNeedsAnInvite`](../../examples/invite-only/main_test.go) refuses a sign-up with no invite before any invite exists.

## Step 2 — Create the first account from Go

`Required` refuses only a client's sign-up. Users your app creates from Go are never refused, so `auth admin create`, imports and a start-up seed keep working. An invite-only app needs one such account, or nobody can ever create the first invite. The example seeds its owner in one transaction, so a second start finds the address taken and creates nothing:

<!-- ds:block id=app-seedowner-jwm9s54q -->
**app.seedOwner** · [`examples/invite-only/main.go:212-227`](../../examples/invite-only/main.go#L212-L227)

```go
func (x *app) seedOwner(ctx context.Context) error {
	return x.auth.Tx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		u, err := x.auth.CreateUser(ctx, auth.NewUser{Name: ownerName})
		if err != nil {
			return err
		}
		if _, err := x.auth.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: ownerEmail, Verified: true, Primary: true}); err != nil {
			return err
		}
		if err := x.password.SetPassword(ctx, u.ID, password.Secret(ownerPassword)); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO app_member (user_id, role) VALUES (?, ?)`, u.ID, string(RoleOwner))
		return err
	})
}
```
<!-- /ds:block hash=5ff45d -->

Check: `TestInviteOnly_SeedOwnerTwice`.

## Step 3 — Create an invite

`POST /auth/invite/create` as a signed-in user (`Create` from Go):

| Body | Result |
|---|---|
| `{}` or `{"maxUses":5,"expiresIn":86400}` | A public invite: the answer carries `url` once, for the creator to share. `maxUses` 0 is unlimited; `expiresIn` is seconds, at most 30 days |
| `{"email":"bob@example.com"}` | A private invite: mailed to that address (purpose `invite.user`), single use; the link is never in the answer |
| `{"role":"member"}` | Allowed only when `CanCreate` returns nil; without `CanCreate`, `403 invite.forbidden` |

```sh
O='Origin: http://localhost:8081'
curl -s -c ada.txt -X POST localhost:8081/auth/password/sign-in -H "$O" \
  -d '{"identifier":"ada@example.com","password":"correct horse battery staple"}'
curl -s -b ada.txt -X POST localhost:8081/auth/invite/create -H "$O" -d '{"role":"member","maxUses":1}'
curl -s -b ada.txt -X POST localhost:8081/auth/invite/create -H "$O" -d '{"email":"carol@example.com","role":"editor"}'
```

```json
{"id":"inv_slyp46ncrvuprz4pqstj5t46","token":"TGTVkfbjtALzDmzQ6Pla2pJeVaQd98UY4CjepjqDwZE","url":"http://localhost:8081/invite?token=TGTVkfbjtALzDmzQ6Pla2pJeVaQd98UY4CjepjqDwZE","expiresAt":"2026-10-09T04:10:12.383614Z"}
{"id":"inv_wqbbnicusiq4bwnxda6burg6","expiresAt":"2026-10-09T04:10:12.662795Z"}
```

Share the `url`, or the `token` for a client that builds its own link; `Created.Token` is an `auth.WireToken`, so it encodes as its value in JSON and still prints `[redacted]` in a log. The private invite went by mail:

```text
2026/10/09 08:40:12 mail to=carol@example.com subject="You are invited"
Ada invited you. Open this link to accept:
http://localhost:8081/invite?token=Mby6_eVTxV0es_zNBFht5o98XiUEkeYPA8UKyWBj0KI
```

## Step 4 — Accept it

The link opens `DefaultPage` (`/invite?token=…`, or your own with `Links`). The page calls `GET /auth/invite/get?token=…` to show the invite (`status`, `expiresAt`, `role`, `inviterName` unless `HideInviter`, `private`), then `POST /auth/invite/activate {"token":"…"}`:

- signed in: the invite is used now, and the answer is `{"action":"accepted"}`;
- signed out: the invite waits in the cookie `__Host-auth_invite` for ten minutes (`WithCookieTTL`, never past the invite's own expiry), and the answer is `{"action":"sign_in_required"}`.

The example mounts the page beside the library's routes:

<!-- ds:block id=app-handler-ppk4r4z7 -->
**app.handler** · [`examples/invite-only/main.go:233-239`](../../examples/invite-only/main.go#L233-L239)

```go
func (x *app) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(x.auth, authhttp.Prefix(authPrefix)))
	mux.HandleFunc("GET "+invite.DefaultPage, invitePage)
	mux.Handle("GET /me", authhttp.Middleware(x.auth)(authhttp.RequireUser(http.HandlerFunc(x.me))))
	return mux
}
```
<!-- /ds:block hash=40e562 -->

<!-- ds:block id=invitepagehtml-2kr6tty7 -->
**invitePageHTML** · [`examples/invite-only/main.go:246-265`](../../examples/invite-only/main.go#L246-L265)

```go
const invitePageHTML = `<!doctype html>
<meta charset="utf-8">
<title>Invitation</title>
<pre id="out"></pre>
<button id="go">Accept</button>
<script>
const token = new URLSearchParams(location.search).get("token");
const out = document.getElementById("out");
fetch("` + authPrefix + `/invite/get?token=" + encodeURIComponent(token))
  .then(r => r.json()).then(v => { out.textContent = v.error ? v.error.message : (v.inviterName || "Someone") + " invited you."; });
document.getElementById("go").onclick = async () => {
  const res = await fetch("` + authPrefix + `/invite/activate", {
    method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({token}),
  });
  const v = await res.json();
  if (!res.ok) { out.textContent = v.error.message; return; }
  location.href = v.action === "accepted" ? "/me" : "/sign-up";
};
</script>
`
```
<!-- /ds:block hash=c15c65 -->

```sh
T=TGTVkfbjtALzDmzQ6Pla2pJeVaQd98UY4CjepjqDwZE
curl -s "localhost:8081/auth/invite/get?token=$T"
curl -s -c bob.txt -b bob.txt -X POST localhost:8081/auth/invite/activate -H "$O" -d "{\"token\":\"$T\"}"
curl -s -c bob.txt -b bob.txt -X POST localhost:8081/auth/password/sign-up -H "$O" \
  -d '{"identifier":"bob@example.com","password":"another horse battery staple","name":"Bob"}'
curl -s -b bob.txt localhost:8081/me
```

```json
{"status":"pending","expiresAt":"2026-10-09T04:10:12.383614Z","role":"member","inviterName":"Ada","private":false}
{"action":"sign_in_required"}
{"user":{"id":"usr_fzpehukpvdtw4m3hikejaxvf","name":"Bob","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_fzpehukpvdtw4m3hikejaxvf","name":"Bob","role":"member"}
```

The sign-up spends the invite, whatever the method, because a data hook on user creation reads the [`Invite-Token`](ds:block?id=inviteheader-b6pq8rb7) header or the cookie. An OAuth sign-up's callback carries the cookie too. A bad invite refuses the sign-up, so nobody ends up with an account nobody invited. The same hook on session creation lets an existing user who signs in with an invite in the cookie or header use it; there an invalid invite is ignored rather than refusing the sign-in:

<!-- ds:block id=plugin-datahooks-8kkfp2xr -->
**Plugin.DataHooks** · [`plugin/invite/invite.go:395-418`](../../plugin/invite/invite.go#L395-L418)

```go
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{
		User: auth.TableHooks[auth.User]{AfterCreate: func(ctx context.Context, _ sqlb.DBTX, u *auth.User) error {
			tok := requestToken(ctx)
			if tok == "" {
				if p.required && clientSignUp(ctx) {
					return ErrRequired
				}
				return nil
			}
			return p.use(ctx, tok, u.ID, true)
		}},
		Session: auth.TableHooks[auth.Session]{AfterCreate: func(ctx context.Context, _ sqlb.DBTX, s *auth.Session) error {
			tok := requestToken(ctx)
			if tok == "" {
				return nil
			}
			if err := p.use(ctx, tok, s.UserID, false); err != nil && !errors.Is(err, ErrInvalid) {
				return err
			}
			return nil
		}},
	}
}
```
<!-- /ds:block hash=b38a5f -->

Each use is one guarded update: the invite must still be pending, unexpired and have uses left, so two sign-ups racing for the last use cannot both get it, and one user uses one invite once:

<!-- ds:block id=plugin-use-cza5uksu -->
**Plugin.use** · [`plugin/invite/invite.go:512-548`](../../plugin/invite/invite.go#L512-L548)

```go
func (p *Plugin) use(ctx context.Context, tok auth.Token, userID string, newAccount bool) error {
	r, ok, err := p.find(ctx, tok)
	if err != nil {
		return err
	}
	now := p.core.Now()
	if !ok || !r.open(now) {
		return ErrInvalid
	}
	if used, err := p.usedBy(ctx, r.id, userID); err != nil || used {
		return cmp.Or(err, error(ErrInvalid))
	}
	d := p.core.Dialect()
	n, err := p.core.Exec(ctx, sqlb.NewUpdate(d).Table(TableInvite).
		Set(sqlb.SetExpr(InviteUses, sqlb.Add(InviteUses, sqlb.Param[int64](1)))).
		Where(sqlb.Eq(InviteID, r.id), sqlb.Eq(InviteStatus, StatusPending), sqlb.Greater(InviteExpiresAt, now), usesLeft))
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrInvalid
	}
	if r.maxUses > 0 && r.uses+1 >= r.maxUses {
		if _, err := p.core.Exec(ctx, sqlb.NewUpdate(d).Table(TableInvite).Set(sqlb.Set(InviteStatus, StatusUsed)).
			Where(sqlb.Eq(InviteID, r.id), sqlb.Eq(InviteStatus, StatusPending))); err != nil {
			return err
		}
	}
	if _, err := p.core.Exec(ctx, sqlb.NewInsert(d).Into(TableUse).Row(
		sqlb.Set(UseInviteID, r.id), sqlb.Set(UseUserID, userID), sqlb.Set(UseAt, now))); err != nil {
		return fmt.Errorf("invite: record use: %w", err)
	}
	if p.onAccepted != nil {
		return p.onAccepted(ctx, Accepted{InviteID: r.id, UserID: userID, CreatedBy: r.createdBy, Role: r.role, NewAccount: newAccount})
	}
	return nil
}
```
<!-- /ds:block hash=e757fe -->

A later sign-up with the spent link is refused, and rolled back, so the address stays free:

```sh
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -H "Invite-Token: $T" \
  -d '{"identifier":"dave@example.com","password":"another horse battery staple","name":"Dave"}'
```

```json
{"error":{"code":"invite.invalid","message":"This invitation is not valid or has expired."}}
```

Check: [TestP3CommunityInvite_PrivateRoleCookie](ds:block?id=testp3communityinvite-privaterolecookie-gfqv25w5) runs a private invite with a role through the cookie on SQLite, Postgres and MySQL; `TestInviteOnly_SignUpNeedsAnInvite` runs the flow above over HTTPS.

## Step 5 — Manage invites

| Route | Go method | Who |
|---|---|---|
| `GET /auth/invite/list` | `List` | The creator: their invites, newest first, with `uses`, `maxUses` and `status`, never a token |
| `POST /auth/invite/cancel {"id"}` | `Cancel` | The creator; another user's invite answers like an unknown id |
| `POST /auth/invite/reject {"token"}` | `Reject` | The account that owns a private invite's address |

```sh
curl -s -b ada.txt localhost:8081/auth/invite/list
```

```json
{"invites":[{"id":"inv_wqbbnicusiq4bwnxda6burg6","email":"carol@example.com","role":"editor","maxUses":1,"uses":0,"status":"pending","expiresAt":"2026-10-09T04:10:12.662795Z","createdAt":"2026-10-09T03:10:12.662795Z"},{"id":"inv_slyp46ncrvuprz4pqstj5t46","role":"member","maxUses":1,"uses":1,"status":"used","expiresAt":"2026-10-09T04:10:12.383614Z","createdAt":"2026-10-09T03:10:12.383614Z"}],"total":2}
```

A canceled invite stops working at once: `get` and `activate` answer `invite.invalid`.

## Options you may want

| Situation | Option | What it changes |
|---|---|---|
| Nobody joins without an invite | `Required()` | A client's sign-up needs a valid invite; Go-side creation is never refused. Default off |
| Only some users may invite, or give roles | `CanCreate(fn)` | Decides who may create which invite; required for any role. Default: every signed-in user, no role |
| The invite stands for a role, a plan or a membership | `OnAccepted(fn)` | Runs in the use's transaction with the role; an error undoes the use and the sign-up |
| Invites should live longer or shorter | `WithTTL(d)` | An invite's default life, at most 30 days. Default one hour |
| Visitors take long to sign up | `WithCookieTTL(d)` | How long an activated invite waits in the cookie. Default ten minutes |
| The inviter's name must stay private | `HideInviter()` | Leaves the name out of `get` and the mail |
| Your accept page is not `/invite` | `Links(fn)` | Builds the invite link from the token |
| The app has no email plugin, or invites must never be mailed | `PublicOnly()` | Turns private invites off: a create naming an `email` is `403 invite.forbidden`, and `auth.New` no longer needs a plugin that delivers email |

## From TypeScript

Use this when the "invite someone" button and the page the invitation link opens run in a browser or an app. The [typed client](../client/README.md) has every route of this guide on `client.invite`; list `invite()` in `plugins`.

A signed-in user creates a shareable link (a private invite with `email` is mailed instead, and its answer has no `url`):

<!-- ds:block id=tsp-invite-create-8mk3wq7x -->
**shareableInvite** · [`clients/ts/examples/plugin-headers.ts:108-112`](../../clients/ts/examples/plugin-headers.ts#L108-L112)

```typescript
export async function shareableInvite(): Promise<string | null> {
  const { data, error } = await auth.invite.create({ maxUses: 5, expiresIn: 7 * 24 * 3600 });
  if (error) return null; // invite.forbidden when the server's CanCreate refuses
  return data.url ?? null;
}
```
<!-- /ds:block hash=1c47e4 -->

The page the link opens shows the invite, then activates it. Signed in, the invite is used at once; signed out, it waits in a cookie, so the page sends the visitor to sign up or sign in in the same browser:

<!-- ds:block id=tsp-invite-page-5kw2xn9q -->
**onInvitePage** · [`clients/ts/examples/plugin-headers.ts:118-125`](../../clients/ts/examples/plugin-headers.ts#L118-L125)

```typescript
export async function onInvitePage(): Promise<"accepted" | "sign-in-or-sign-up" | "invalid"> {
  const token = new URLSearchParams(location.search).get("token") ?? "";
  const shown = await auth.invite.get({ token });
  if (shown.error || shown.data.status !== "pending") return "invalid";
  const { data, error } = await auth.invite.activate({ token });
  if (error) return "invalid";
  return data.action === "accepted" ? "accepted" : "sign-in-or-sign-up";
}
```
<!-- /ds:block hash=de0687 -->

`list` and `cancel` manage the creator's invites, and `reject` lets the owner of a private invite's address refuse it.

The codes a frontend handles, explained in [What can go wrong](#what-can-go-wrong): `invite.invalid` (unknown, used, cancelled or expired), `invite.required` from a sign-up under `Required()` without an invite, `invite.forbidden` from `create` when the server's `CanCreate` refuses, `auth.rate_limited`.

There is no runnable TypeScript example for invites; the blocks above are type-checked by `task ts:check`, and Steps 3 and 4 show the same calls with curl and the example's own page.

Pitfalls:

- **The cookie lasts ten minutes** (never past the invite's expiry). A visitor who takes longer to sign up, or signs up in another browser, signs up without the invite; under `Required()` that sign-up is refused. A client without cookies sends the token in the `Invite-Token` header of the sign-up call instead, through the per-call `headers` option.
- **`url` is in `create`'s answer once.** The list never shows a token, so show or copy the link right away.

Every method with its route and types: [TypeScript client reference › invite](../reference/ts-client.md#invite).

## What can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| `403 invite.required` for every sign-up, and no account exists yet | `Required()` with no first account | Create the first account from Go, as in Step 2 |
| `auth.New` fails with `invite: private invites mail an address, so the email plugin must be wired (or pass invite.PublicOnly)` | `ErrNoEmail`: no plugin delivers email, and a private invite is mailed | Wire `plugin/email` with a mailer, or pass `invite.PublicOnly()` |
| `403 invite.forbidden` | `CanCreate` refused, the request has a `role` and no `CanCreate` is wired, or it names an `email` under `PublicOnly()` | Pass `CanCreate`; return nil for the roles the inviter may give; drop `email` or `PublicOnly()` |
| `400 invite.invalid` | Unknown, expired, used up, canceled or rejected token, all answered alike so a guesser learns nothing | Show one "this invitation is not valid" message; the creator makes a new invite |
| The role was not applied, or applied after a refused sign-up | `OnAccepted` wrote on the `*sql.DB` instead of `a.Conn(ctx)` | Write on `a.Conn(ctx)`; return an error to undo the sign-up |
| A visitor activated the invite, then the sign-up says `invite.required` | The cookie expired (`WithCookieTTL`), or the sign-up ran on another host so the `__Host-` cookie was not sent | Open the link again, or send the token in the `Invite-Token` header |
| `400 auth.bad_request` from `create` | `expiresIn` negative or over 30 days, or `maxUses` negative | Keep both in range |
| `429` from `get`, `activate` or `create` | `get` and `activate` allow 30 calls per IP per minute; `create` 20 per IP per hour | Wait for the window to pass; the limits count per IP, across every instance only when they share an `auth.WithRateStore` |

## Differences from better-invite

The token is the proof for a private invite too, as in better-invite: whoever holds the mailed link may use it, which is how an invite to a work address can create an account under another. better-invite's six-character code tokens are not offered, because a short code looked up by its hash can be guessed; every token here has 256 bits.

## Next

- [Organizations](organization.md): invitations into one organization, with roles that live in the organization.
- [Admin](admin.md): `admin.SetRole` for an app that keeps roles on the user.
- [Referrals](referral.md): record who brought whom without closing sign-up.
- [Hooks](../extending/03-hooks.md): the data hooks this plugin is built on.
