# Invite-only sign-up with roles

An app nobody can join without an invite. The owner is created from Go at start-up; every other account comes from an invite link. The owner shares a one-use link or mails a private invite to one address, and the role the invite carries lands in the app's own `app_member` table in the same transaction as the sign-up, so a refused sign-up leaves no member row and no account.

## Run it

```sh
cd examples
go run ./invite-only
```

It creates `invite-only.db` (SQLite), creates the owner `ada@example.com` with the password `correct horse battery staple`, and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./invite-only`.

## Walkthrough

A sign-up with no invite is refused:

```sh
O='Origin: http://localhost:8081'
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" \
  -d '{"identifier":"bob@example.com","password":"another horse battery staple","name":"Bob"}'
```

```json
{"error":{"code":"invite.required","message":"An invitation is required to sign up."}}
```

Ada signs in and creates a member link that works once. Share the `url`, or the `token` for a client that builds its own link.

```sh
curl -s -c ada.txt -X POST localhost:8081/auth/password/sign-in -H "$O" \
  -d '{"identifier":"ada@example.com","password":"correct horse battery staple"}'
curl -s -b ada.txt -X POST localhost:8081/auth/invite/create -H "$O" -d '{"role":"member","maxUses":1}'
```

```json
{"id":"inv_slyp46ncrvuprz4pqstj5t46","token":"TGTVkfbjtALzDmzQ6Pla2pJeVaQd98UY4CjepjqDwZE","url":"http://localhost:8081/invite?token=TGTVkfbjtALzDmzQ6Pla2pJeVaQd98UY4CjepjqDwZE","expiresAt":"2026-10-09T04:10:12.383614Z"}
```

Bob opens the link signed out. The page shows the invite, then activates it, which parks the token in the `__Host-auth_invite` cookie; his sign-up carries the cookie and spends the invite, and `/me` shows the role:

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

Dave brings the spent link in the `Invite-Token` header. The sign-up is refused and rolled back, so `dave@example.com` has no account:

```sh
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -H "Invite-Token: $T" \
  -d '{"identifier":"dave@example.com","password":"another horse battery staple","name":"Dave"}'
```

```json
{"error":{"code":"invite.invalid","message":"This invitation is not valid or has expired."}}
```

A private invite goes by mail and never appears in the answer. Bob, a member, may invite people but may not hand out a role:

```sh
curl -s -b ada.txt -X POST localhost:8081/auth/invite/create -H "$O" -d '{"email":"carol@example.com","role":"editor"}'
curl -s -b bob.txt -X POST localhost:8081/auth/invite/create -H "$O" -d '{"role":"editor"}'
```

```json
{"id":"inv_wqbbnicusiq4bwnxda6burg6","expiresAt":"2026-10-09T04:10:12.662795Z"}
{"error":{"code":"invite.forbidden","message":"You cannot create this invitation."}}
```

The server log shows the mail:

```text
2026/10/09 08:40:12 mail to=carol@example.com subject="You are invited"
Ada invited you. Open this link to accept:
http://localhost:8081/invite?token=Mby6_eVTxV0es_zNBFht5o98XiUEkeYPA8UKyWBj0KI
```

Ada lists her invites: the used link and the pending private one, with use counts and never a token:

```sh
curl -s -b ada.txt localhost:8081/auth/invite/list
```

```json
{"invites":[{"id":"inv_wqbbnicusiq4bwnxda6burg6","email":"carol@example.com","role":"editor","maxUses":1,"uses":0,"status":"pending","expiresAt":"2026-10-09T04:10:12.662795Z","createdAt":"2026-10-09T03:10:12.662795Z"},{"id":"inv_slyp46ncrvuprz4pqstj5t46","role":"member","maxUses":1,"uses":1,"status":"used","expiresAt":"2026-10-09T04:10:12.383614Z","createdAt":"2026-10-09T03:10:12.383614Z"}],"total":2}
```

## The code

- `newApp` wires `invite.Required()`, `invite.CanCreate` and `invite.OnAccepted`. `Required` refuses only a client's sign-up, so `seedOwner` creates the first account from Go (user, verified address, password and owner row in one `a.Tx`).
- `canCreate` lets any member create an invite with no role and only the owner one with a role from the `grantable` set; the owner role is never handed out by a link.
- `onAccepted` writes the role on `a.Conn(ctx)`, the transaction that records the use. A write on the plain `*sql.DB` would survive a rollback of the sign-up.
- `invitePageHTML` is the page the link opens: it shows the invite from `/auth/invite/get` and activates it on a click.

`main_test.go` drives all of the above over HTTPS, plus the private invite's mail link, a canceled invite and a second start-up that must not create a second owner.

Limits of this example: one role per member, and a member who uses a second invite keeps the first role.

## What this used

- [`plugin/invite`](https://pkg.go.dev/github.com/ubgo/auth/plugin/invite): `New`, `Required`, `CanCreate`, `OnAccepted`, `Request`, `Accepted`, `ErrForbidden`, `InviteHeader`, `DefaultPage`
- [`auth`](https://pkg.go.dev/github.com/ubgo/auth): `Tx`, `Conn`, `CreateUser`, `CreateIdentity`
- [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password): `SetPassword`
- Guide: [docs/plugins/invite.md](../../docs/plugins/invite.md). Related: [organizations](../organizations) (invitations to an organization are a different feature).
