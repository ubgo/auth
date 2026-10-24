# LDAP sign-in

You will have people sign in with the username and password their organization already gives them, checked against an LDAP directory (OpenLDAP, Active Directory, FreeIPA, lldap, 389-DS). The app stores no password: the directory is the source of truth for it, so a password change or a disabled account takes effect at the next sign-in. The first sign-in links the directory account to a user, or creates one from the entry's attributes.

Use this plugin for an internal tool, a staff portal or any app whose users already live in a directory. It is not single sign-on: the user types the directory password into your page, which is the trade for not running an identity provider. For SAML or OIDC against an identity provider, see [SSO](sso.md).

## Before you start

- An app with sign-in, as in [your first app](../start/first-app.md), and the [email plugin](email.md) if you want a directory account to find the user who signed up another way by address.
- The example program this guide is built from, with a `main_test.go` that drives the same steps and a `README.md` with the same transcript: [`examples/ldap-sign-in`](../../examples/ldap-sign-in/). `go run ./ldap-sign-in` in `examples/` serves it on `localhost:8081` with a one-user demo directory, so no server is needed to try it.
- The plugin is its own module, `github.com/ubgo/auth/plugin/ldap`, because it depends on go-ldap: an app without LDAP never compiles it. `go get github.com/ubgo/auth/plugin/ldap`.
- What it stores: `auth_ldap_account`, one row per directory account, linked to one user. It stores no password and no copy of the entry.
- The reference for every option, route and error is the package's [README](../../plugin/ldap/README.md).

## Step 1 — Point the plugin at a directory

The plugin reaches the directory only through the `Directory` interface: given a username and password, it answers the user's entry or `ldap.ErrInvalidCredentials`. The module ships `ldap.NewClient`, a go-ldap client that connects, binds a service account, searches for the user, binds as the user and closes. TLS is required: `NewClient` refuses a plain `ldap://` URL unless you set `StartTLS`, and `ldaps://` is TLS from the start:

<!-- ds:block id=ldap-example-newdirectory-5r8w2k6n -->
**newDirectory** · [`examples/ldap-sign-in/main.go:93-104`](../../examples/ldap-sign-in/main.go#L93-L104)

```go
func newDirectory() (ldap.Directory, error) {
	if os.Getenv("LDAP_URL") == "" {
		return demoDirectory(), nil
	}
	return ldap.NewClient(ldap.Config{
		URL:          os.Getenv("LDAP_URL"),
		StartTLS:     os.Getenv("LDAP_START_TLS") == "true",
		BindDN:       os.Getenv("LDAP_BIND_DN"),
		BindPassword: os.Getenv("LDAP_BIND_PASSWORD"),
		BaseDN:       os.Getenv("LDAP_BASE_DN"),
	})
}
```
<!-- /ds:block hash=a53a06 -->

Put access rules in the user filter, not in code: `(&(uid={username})(memberOf=cn=staff,ou=groups,dc=example,dc=com))` lets only staff sign in, and everyone else gets the same answer as a wrong password.

Then register the plugin. `MapAttributes` names the attribute that identifies the entry for good. The default is the DN, which changes when an entry is renamed or moved, so set `entryUUID` (OpenLDAP, lldap), `objectGUID` (Active Directory) or `ipaUniqueID` (FreeIPA):

<!-- ds:block id=ldap-example-plugins-7m3q9x2v -->
**plugins** · [`examples/ldap-sign-in/main.go:113-118`](../../examples/ldap-sign-in/main.go#L113-L118)

```go
func plugins(dir ldap.Directory, opts ...ldap.Option) []auth.Plugin {
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
		ldap.New(append([]ldap.Option{ldap.WithDirectory(dir), ldap.MapAttributes(ldap.AttributeMap{Subject: "entryUUID"})}, opts...)...),
	}
}
```
<!-- /ds:block hash=997710 -->

`auth.New` refuses the plugin without a directory (`ldap.ErrNoDirectory`), and every option refuses a nil argument by name.

## Step 2 — Sign in

`POST /auth/ldap/sign-in {"username","password"}`, or `Plugin.SignIn` from Go. The first sign-in links the entry to a user by this rule, in order:

1. An entry already linked is its user's.
2. An entry whose email matches a **verified** identity links to that user. This is what lets a person who signed up with a password and later signs in through the directory keep one account. `UntrustedEmail()` turns it off: the match is then refused with `ldap.account_exists`, and a new user's address is stored unverified.
3. Otherwise a user is created from the entry's name and email, verified. `NoSignUp()` refuses this with `ldap.sign_up_disabled`, for an app where the directory only signs in people who already have an account.

The test pins the first sign-in and the second:

<!-- ds:block id=ldap-example-test-signin-2p8x4m6k -->
**TestLDAP_FirstSignInCreatesThenSignsIn** · [`examples/ldap-sign-in/main_test.go:40-61`](../../examples/ldap-sign-in/main_test.go#L40-L61)

```go
func TestLDAP_FirstSignInCreatesThenSignsIn(t *testing.T) {
	e, b := newWorld(t, demoDirectory())
	var first ldap.SignInResult
	signIn(b, adaUser, adaPass).Expect(http.StatusOK).Decode(&first)
	if !first.Created || first.User.Name != "Ada Lovelace" {
		t.Fatalf("first sign-in = %+v", first)
	}
	var who meResponse
	b.Get("/me").Expect(http.StatusOK).Decode(&who)
	if who.ID != first.User.ID {
		t.Fatalf("/me = %+v", who)
	}
	owner, err := e.Auth.FindIdentity(t.Context(), email.KindEmail, adaMail, true)
	if err != nil || owner.UserID != first.User.ID {
		t.Fatalf("the directory's address must be the new user's, verified: %+v %v", owner, err)
	}
	var again ldap.SignInResult
	signIn(b, adaUser, adaPass).Expect(http.StatusOK).Decode(&again)
	if again.Created || again.User.ID != first.User.ID {
		t.Fatalf("second sign-in = %+v", again)
	}
}
```
<!-- /ds:block hash=86d887 -->

```sh
O='Origin: http://localhost:8081'
curl -s -c ada.txt -X POST localhost:8081/auth/ldap/sign-in -H "$O" -d '{"username":"ada","password":"correct horse battery staple"}'
curl -s -b ada.txt localhost:8081/me
curl -s -c ada.txt -X POST localhost:8081/auth/ldap/sign-in -H "$O" -d '{"username":"ada","password":"correct horse battery staple"}'
```

The first sign-in creates the user, `/me` shows the session works, and the second signs in to the same user:

```json
{"user":{"id":"usr_5gswpamxpgwbmsr5hetomdk3","name":"Ada Lovelace","image":""},"created":true,"linked":false,"secondFactorRequired":false}
{"id":"usr_5gswpamxpgwbmsr5hetomdk3","name":"Ada Lovelace"}
{"user":{"id":"usr_5gswpamxpgwbmsr5hetomdk3","name":"Ada Lovelace","image":""},"created":false,"linked":false,"secondFactorRequired":false}
```

A directory password is one factor: a user with [two-factor](twofactor.md) gets a pending session and `secondFactorRequired: true`, as with a password.

## Step 3 — Know what a stranger learns

An unknown username and a wrong password answer the same error, `ldap.credentials_invalid`, with the same body and after the same work: the `Directory` contract requires it, and `Client` keeps it by binding a decoy entry for an unknown user so both paths cost one search and one bind. An empty password, an oversized username (256 bytes) or password (1024 bytes) and a NUL byte are refused before the directory sees them: an empty password is an anonymous bind in LDAP, and anonymous binds succeed.

```sh
curl -s -X POST localhost:8081/auth/ldap/sign-in -H "$O" -d '{"username":"ada","password":"wrong"}'
curl -s -X POST localhost:8081/auth/ldap/sign-in -H "$O" -d '{"username":"grace","password":"wrong"}'
```

```json
{"error":{"code":"ldap.credentials_invalid","message":"The username or password is incorrect."}}
{"error":{"code":"ldap.credentials_invalid","message":"The username or password is incorrect."}}
```

A directory that cannot be reached answers `503 ldap.directory_unavailable`, which says nothing about the user, and the cause is logged. A username that matches several entries is logged and answered as a wrong password: make the filter specific.

Sign-in is limited to 20 attempts per address per minute and, lower, 5 per username per 15 minutes. The per-username budget is low on purpose: a directory locks accounts on its own count, often at 5 to 10, so an attacker guessing at your endpoint would otherwise lock real people out of every system that uses the directory.

## Step 4 — Shape the profile

| Situation | Option | What it changes |
|---|---|---|
| The entry's id, address or name live in other attributes | `MapAttributes(AttributeMap{Subject, Email, Name, Image})` | Which attributes the profile is read from; email defaults to `mail`, name to `cn`, subject to the DN |
| The profile needs code (a group decides a role, a value is split) | `MapProfile(fn)` | `fn(Entry) (Profile, error)` replaces the attribute map; an error refuses the sign-in with `ldap.profile_refused` |
| The directory is not the organization's own record | `UntrustedEmail()` | Its addresses never link to an existing user and are stored unverified |
| Only people who already have an account may sign in | `NoSignUp()` | Never creates a user |
| A pooled client, Active Directory through another library, or a fake | `WithDirectory(d)` | Any `Directory` |

## From TypeScript

Use this when the sign-in form for directory accounts runs in a browser or an app. The [typed client](../client/README.md) has the one route as `client.ldap.signIn`; list `ldap()` in `plugins`, and `twofactor()` too when the server has it.

<!-- ds:block id=tsp-ldap-signin-2kx9mw5q -->
**signInWithDirectory** · [`clients/ts/examples/plugin-signin.ts:46-57`](../../clients/ts/examples/plugin-signin.ts#L46-L57)

```typescript
export async function signInWithDirectory(user: string, secret: string): Promise<string> {
  const { data, error } = await auth.ldap.signIn({ username: user, password: secret });
  if (!error) return data.secondFactorRequired ? "second-factor" : `Signed in as ${data.user.name}`;
  switch (error.code) {
    case "ldap.credentials_invalid":
      return "The user name or password is not right.";
    case "ldap.directory_unavailable":
      return "The directory cannot be reached. Try again later.";
    default:
      return error.message;
  }
}
```
<!-- /ds:block hash=7866f3 -->

The answer says whether this sign-in created the account (`created`) or attached the entry to an existing user with the same verified address (`linked`), so a first-time page can greet a new user. The codes a frontend handles, explained in [What can go wrong](#what-can-go-wrong): `ldap.credentials_invalid` (one answer for a wrong password and an unknown user), `ldap.directory_unavailable` (the directory is down; try later, not a wrong password), `ldap.account_exists` under `UntrustedEmail()`, `ldap.sign_up_disabled` under `NoSignUp()`, `ldap.sign_in_conflict` (two first sign-ins at once; try again), `auth.rate_limited`.

There is no runnable TypeScript example for directory sign-in; the block is type-checked by `task ts:check`, and Step 2 shows the same call with curl against the example's one-user demo directory.

Pitfalls:

- **The field is the directory's user name, not an address**: the form label should say what your directory expects (`uid`, `sAMAccountName`).
- **Never fall back to another method on `ldap.directory_unavailable`** with the same password; show the outage.

Every method with its route and types: [TypeScript client reference › ldap](../reference/ts-client.md#ldap).

## What can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| `ldap: ldap:// without StartTLS sends passwords in clear text` from `NewClient` | A plain URL | Use `ldaps://`, set `StartTLS`, or `AllowInsecure` for a server on the same machine in a test |
| `503 ldap.directory_unavailable` | The server is down, a certificate does not verify, or the service account's password expired | Read the log line; for a private CA put it in `Config.TLS.RootCAs`, never `InsecureSkipVerify` outside a test |
| Every sign-in is `ldap.credentials_invalid` | The user filter finds nobody, or `BaseDN` is wrong | Run the filter with `ldapsearch`; the answer is deliberately the same as a wrong password |
| `409 ldap.account_exists` | `UntrustedEmail` is on and a user holds the address | Sign in to that account first, or drop the option if the directory is trusted |
| A renamed user signs in as a new user | `Subject` is the DN | Set `MapAttributes` to `entryUUID`, `objectGUID` or `ipaUniqueID`; links made on the DN stay until re-linked |
| `409 ldap.sign_in_conflict` | Two first sign-ins of one entry raced | Try again; the loser lost the unique row, nothing was created twice |

## Test against a real directory

The module's unit and example tests use a fake `Directory`. `task test:ldap` also runs `Client` against a real lldap server over LDAPS in a throwaway container with a certificate made for the run, and removes both afterwards. It is opt-in and not part of `task check`.

## Next

- [Two-factor](twofactor.md): a second step after the directory password.
- [Admin](admin.md): ban or impersonate a directory user like any other.
- [Organizations](organization.md): map a directory group to a role with `MapProfile` and your own table.
