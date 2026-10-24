# github.com/ubgo/auth/plugin/ldap

Sign-in with a username and password checked against an LDAP directory. The guide is [docs/plugins/ldap.md](../../docs/plugins/ldap.md).

## Install

```sh
go get github.com/ubgo/auth/plugin/ldap
```

A separate module: it depends on `github.com/go-ldap/ldap/v3`, so an app without a directory never compiles it.

## What it does

- `POST /auth/ldap/sign-in {username, password}` checks the pair with a `Directory` and signs the user in; the plugin stores no password.
- The default `Directory`, `NewClient(Config)`, uses go-ldap: service-account bind, search with an escaped filter, bind as the user. TLS is required (`ldaps://`, or `ldap://` with `StartTLS`); `AllowInsecure` exists for a local test server only.
- The first sign-in links the entry to the user holding its verified email, or creates a user. Links live in `auth_ldap_account`, keyed by `Subject`, so a renamed entry reaches the same user.
- An unknown user and a wrong password are the same error after the same work (a decoy bind); an empty password never reaches the directory.
- Limits: 20 sign-ins per address per minute, 5 per username per 15 minutes, below a typical directory lockout threshold.

## Options

`WithDirectory(d)`, `MapAttributes(AttributeMap)`, `MapProfile(fn)`, `NoSignUp()`, `UntrustedEmail()`. Every option refuses a nil argument by name.

## Errors

`ldap.credentials_invalid` (401), `ldap.directory_unavailable` (503), `ldap.account_exists` (409), `ldap.sign_up_disabled` (403), `ldap.profile_refused` (403), `ldap.sign_in_conflict` (409). `ErrNoDirectory` is returned by `auth.New`.

## Tests

Unit tests in this module against a fake connection and `Directory`; the flows in [examples/ldap-sign-in](../../examples/ldap-sign-in/); `task test:ldap` (opt-in) against a throwaway lldap container.
