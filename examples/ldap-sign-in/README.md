# Sign in with a directory username and password

People sign in with the username and password their organization gives them. The app stores no password: an LDAP directory checks it. The first sign-in links the directory account to the user holding its email address, or creates a user from the entry. The guide is [docs/plugins/ldap.md](../../docs/plugins/ldap.md).

## Run it

```sh
cd examples
go run ./ldap-sign-in
```

It creates `ldap-sign-in.db` (SQLite) and listens on `http://localhost:8081`. Without `LDAP_URL` it uses a one-user demo directory (`ada` / `correct horse battery staple`), so nothing else needs to run. Against a real directory:

```sh
LDAP_URL=ldaps://ldap.example.com LDAP_BASE_DN=ou=people,dc=example,dc=com \
LDAP_BIND_DN=cn=svc,dc=example,dc=com LDAP_BIND_PASSWORD=… go run ./ldap-sign-in
```

`ldap://` needs `LDAP_START_TLS=true`: the client refuses to send a password in clear text. Run the tests with `go test ./ldap-sign-in`.

## Walkthrough

The first sign-in creates the user from the entry, `/me` shows the session works, and the second sign-in is the same user:

```sh
O='Origin: http://localhost:8081'
curl -s -c ada.txt -X POST localhost:8081/auth/ldap/sign-in -H "$O" -d '{"username":"ada","password":"correct horse battery staple"}'
curl -s -b ada.txt localhost:8081/me
curl -s -c ada.txt -X POST localhost:8081/auth/ldap/sign-in -H "$O" -d '{"username":"ada","password":"correct horse battery staple"}'
```

```json
{"user":{"id":"usr_5gswpamxpgwbmsr5hetomdk3","name":"Ada Lovelace","image":""},"created":true,"linked":false,"secondFactorRequired":false}
{"id":"usr_5gswpamxpgwbmsr5hetomdk3","name":"Ada Lovelace"}
{"user":{"id":"usr_5gswpamxpgwbmsr5hetomdk3","name":"Ada Lovelace","image":""},"created":false,"linked":false,"secondFactorRequired":false}
```

A wrong password and an unknown username get the same answer:

```sh
curl -s -X POST localhost:8081/auth/ldap/sign-in -H "$O" -d '{"username":"ada","password":"wrong"}'
curl -s -X POST localhost:8081/auth/ldap/sign-in -H "$O" -d '{"username":"grace","password":"wrong"}'
```

```json
{"error":{"code":"ldap.credentials_invalid","message":"The username or password is incorrect."}}
{"error":{"code":"ldap.credentials_invalid","message":"The username or password is incorrect."}}
```

## What the tests prove

`main_test.go` drives the same app with an in-memory directory: first sign-in creates, the second reuses; an unknown user and a wrong password answer byte-identical bodies; a person with a verified account at the entry's address gets that account, not a second one; `UntrustedEmail` never links and `NoSignUp` creates nobody; a renamed entry keeps its user; a profile the app refuses is refused; an unreachable directory answers 503; and sign-in is limited per username.
