# Organization domains: join by a verified work address

An organization claims its email domain. Alice adds `acme.com` to Acme and proves Acme owns it; from then on, anyone whose `acme.com` address becomes verified is enrolled the way the domain says: an invitation, a suggestion they can ask to act on, or membership outright. An address nobody has verified enrolls no one, a domain nobody has proved enrolls no one, and a proved domain belongs to one organization only.

## Run it

```sh
cd examples
go run ./org-domains
```

It creates `org-domains.db` (SQLite) and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./org-domains`.

## Walkthrough

Alice signs up as `alice@acme.com`, verifies the address with the token from the mailed link, and creates Acme. The example sets `TrustVerifiedEmail`, so her verified address at the domain proves it when she adds it; without that, `verify-domain` looks for the TXT record `add-domain` answers.

```sh
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@acme.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -b alice.txt -X POST localhost:8081/auth/email/verify -H 'Origin: http://localhost:8081' -d '{"token":"…"}'
curl -s -b alice.txt -X POST localhost:8081/auth/organization/create -H 'Origin: http://localhost:8081' \
  -d '{"name":"Acme","slug":"acme"}'
curl -s -b alice.txt -X POST localhost:8081/auth/organization/add-domain -H 'Origin: http://localhost:8081' \
  -d '{"orgId":"org_2ms64etgftxzv7ummx3vlsqe","domain":"acme.com","enrollmentMode":"automatic_join","role":"member"}'
```

```json
{"id":"odom_sky2r55agi7eqwzzlxe3jqv2","orgId":"org_2ms64etgftxzv7ummx3vlsqe","domain":"acme.com","enrollmentMode":"automatic_join","role":"member","verified":true,"verifiedAt":"2026-10-13T12:40:09.662605Z","recordName":"_auth-verification.acme.com","recordValue":"auth-domain-verification=svIv7ocaELO3T1vfV7dyC8X6MkHaJ2cZf3YDLfI94CU","createdAt":"2026-10-13T12:40:09.662482Z"}
```

A public mail domain is refused:

```json
{"error":{"code":"organization.public_domain","message":"This is a public email domain and cannot belong to an organization."}}
```

Bob signs up as `bob@acme.com`. `GET /auth/organization/list` is `{"orgs":[]}` until he verifies the address, and lists Acme with the role `member` right after.

## What the tests prove

`TestDomains_AutoJoinOnlyAfterVerification` proves a domain with a fake DNS zone and checks that an unproved domain enrolls nobody, an unverified address joins only once verified, a second organization can neither prove nor add a proved domain, a member cannot add or remove a domain, a stranger gets 404, and a domain cannot grant the owner role. `TestDomains_SuggestionAndInvitation` runs suggestion mode (ask, approve, reject, never suggested again) and invitation mode (a pending invitation, accepted).

Guide: [Organizations › Step 16](../../docs/plugins/organization.md#step-16--verified-domains).
