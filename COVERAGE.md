# Test coverage

Measured by `task cover`, which runs the unit tests of every module and the integration suite (real SQLite, with `-coverpkg` over every library package), then merges the profiles with [integration/cmd/covmerge](integration/cmd/covmerge): a block counts as covered when any run executed it. The merged profile is `.cover/merged.profile`; `task cover COVER_MIN=99` fails below a floor.

The integration suite is where most behaviour is proven, because an auth library's behaviour lives in what the database accepts and returns. Measuring only the unit tests reads about 40% for the core and is wrong in the direction that sends people to rewrite tests that already exist.

| Package | Coverage | Missed statements |
|---|---:|---:|
| `github.com/ubgo/auth` (core) | 99.6% | 19 |
| `authcli`, `authhttp`, `i18n` | 100% | 0 |
| `authui` | 99.7% | 1 |
| `authgate` | 99.7% | 1 |
| `authtest` | 98.4% | 5 |
| `sessiontest` | 98.4% | 4 |
| `verificationtest` | 85.1% | 17 |
| `contrib/gin`, `echo`, `fiber`, `gqlgen`, `otel`, `phonenumbers`, `goth`, `redis` | 100% | 0 |
| `plugin/access/accessapikey` | 95.0% | 1 |
| `plugin/access` (with `accessadmin`), `anonymous`, `captcha`, `pow`, `stale`, `magiclink`, `phone`, `sessiondata`, `terms`, `username`, `password/hibp` | 100% | 0 |
| `plugin/admin` | 100% | 0 |
| `plugin/apikey` | 99.9% | 1 |
| `plugin/audit` | 100% | 0 |
| `plugin/email` | 100% | 0 |
| `plugin/handoff` | 98.3% | 2 |
| `plugin/jwt` | 99.7% | 2 |
| `plugin/lastlogin` | 97.6% | 2 |
| `plugin/oauth` | 99.5% | 11 |
| `plugin/oauth/oauthtest` | 96.8% | 10 |
| `plugin/organization` | 99.7% | 5 |
| `plugin/organization/orgtest` | 100% | 0 |
| `plugin/passkey` | 98.7% | 9 |
| `plugin/password` | 99.3% | 5 |
| `plugin/twofactor` | 99.9% | 1 |
| `plugin/emailchallenge` | 98.7% | 3 |
| `plugin/invite` | 98.7% | 3 |
| `plugin/referral` | 99.2% | 2 |
| `plugin/oauthproxy` | 100% | 0 |
| `plugin/oauthproxy/oauthpopup` | 100% | 0 |
| `plugin/deviceauth` | 99.5% | 2 |
| `plugin/deviceauth/oauthdevice` | 100% | 0 |
| `plugin/scim` | 99.9% | 1 |
| `plugin/agentauth/agentclient` | 98.7% | 3 |
| `plugin/oauthprovider` | 99.5% | 21 |
| `plugin/agentauth` | 99.6% | 11 |
| `plugin/sso/ssotest` | 95.2% | 12 |
| `plugin/sso` | 99.3% | 13 |
| `plugin/ldap` | 100% | 0 |
| `plugin/metadata`, `plugin/jwt/jwtpreset`, `plugin/organization/orgjwt`, `plugin/samlidp`, `plugin/webhook` (with `signature`) | 100% | 0 |
| `plugin/siwe` (with `siwetest`) | 100% | 0 |
| **Total** (`task cover`, 2026-10-13, after auth batch 5: session tasks and token rotation, several second factors and security keys, organization domains, metadata, jwt templates, webhooks, the SAML identity provider; the batch's examples count through `-coverpkg` like ldap's and siwe's) | **99.5%** | **167** |

`plugin/ldap` and `plugin/siwe` need a database and a driver their modules do not carry, so `task cover` counts them through the tests of `examples/ldap-sign-in` and `examples/siwe-sign-in`, which run every typed method once per database call with that call failing.

`contrib/redis` counts only when a Redis is reachable (`task cover` points it at 127.0.0.1:7012); without one its test skips loudly and the package reads 0%.

## The statements not covered, and why

Measured 2026-10-07, after `task cover` was extended to `plugin/sso`, `plugin/oauthprovider` and `plugin/agentauth` (it had left them out, and the earlier 99.3% had not listed `scim`, `deviceauth` or `oauthproxy`). The table below explains the 96 statements of the earlier measurement. Every one is an error check the code keeps because ignoring an error is worse than an untested branch, or a defensive branch no current caller reaches, and no test can reach them without replacing a standard-library or third-party function or racing two requests in the same instant; each is listed with the reason.

| Where | The check | Why no test reaches it |
|---|---|---|
| `stateless.go`, `sessioncache.go` and their four callers in `session.go`, `sessiondata.go` and `reauth.go` (6) | `json.Marshal` of the sealed session and the cache snapshot, and each caller's check of it | fixed structs of strings, times, booleans and already-validated JSON (`AppData`) cannot fail to encode |
| `authgate/authgate.go` `New` | the `auth.NewKeyRing` error | it fails only for a key that is not `auth.SealKeySize` bytes, and `auth.DeriveSecretKeys` returns exactly that size |
| `plugin/oauth/oauth.go` `Start` | `json.Marshal` of the flow metadata | a struct of five strings cannot fail to encode |
| `plugin/oauth/apple.go` `appleSecret.sign` (2), `secret` (1) | `json.Marshal` of the assertion's header and claims, and the caller's check of them | fixed maps of strings and integers always encode |
| `plugin/oauth/assertion.go` `assertionSigner.assertion` (2), `signCompact` (2) | `json.Marshal` of the client assertion's header and claims; `ecdsa.Sign` and `crypto.Signer.Sign` failing | fixed maps of strings and integers always encode; the two signers fail only when the system's random source fails, which since Go 1.24 crashes the program instead |
| `authui/authui.go` `DefaultTemplates` | the `fs.Sub` error | `fs.Sub` fails only for an invalid path, and the path is the constant `templatesDir`, which `TestTemplates_DefaultsParse` reads through |
| `plugin/access/accessapikey/accessapikey.go` `Checker.Grants` | the `NewRole` error | `declared` passes only resources and actions the statements declare, which `NewRole` accepts; the check stays so a future change fails closed rather than granting through a zero role |
| `plugin/apikey/org.go` `encodePermissions` | `json.Marshal` of the normalized permissions | the value is a `map[string][]string`, which `encoding/json` cannot fail to encode; the check stays because ignoring an error is worse than an untested branch |
| `plugin/jwt/signer.go` `keyFor` | the `hkdf.Key` error | it fails only for an output longer than the hash allows, and the Ed25519 seed is 32 bytes |
| `plugin/jwt/alg.go` `verifySignature` | the final `return false` after the key-type switch | `AlgOf` at the top accepts only the four key types the switch handles (Ed25519, RSA, an `RSAPublicKey`, ECDSA); Go needs a return after it |
| `plugin/passkey/passkey.go` `BeginRegistration` (register and sign-up), `BeginDiscoverableLogin` (3) | the WebAuthn library's own errors | they fail only when the system's random source fails |
| `plugin/handoff/handoff.go` `NewVerifier` | `crypto/rand.Read` error | it fails only when the system's random source fails, which since Go 1.24 crashes the program instead |
| `plugin/handoff/handoff.go` `doVerify` | the token's user no longer exists | `DeleteUser` removes every token filed under the user (ADR-0002), so a live hand-off token never outlives its user; kept as the same answer as a spent token |
| `plugin/passkey/passkey.go` sign-up finish | `DetectKind` failing on an identifier that passed at begin | the identifier kinds are fixed at `auth.New`, so they cannot change between the begin and the finish of one process |
| `plugin/twofactor/devices.go` trust | `NewID` error | as above |
| `plugin/password/password.go` sign-up | a `PluginOf` error other than "not registered" | `PluginOf` returns no other error today |
| `plugin/organization/active.go` set-active, active; `teams.go` set-active-team, `activeTeam` (4) | the caller's `session()` failing (no session row: an API key) | the pipeline refuses an API key at these operations before they run (`TestC4_Org_APIKeyHasNoActiveOrganization`; list-team-members, which reads the active team, is `SignedIn` like them); `session()` itself is unit-tested as the second layer |
| `plugin/deviceauth/deviceauth.go` redeem, decide (2) | the conditional delete or update matching no row after the code was read | reached only when two polls or two decisions race for one code in the same instant; the condition is what makes the race safe |
| `plugin/scim/users.go` `reconcile` | no SCIM user left for a reconcile that is not a deletion | every non-deleting caller (replace, decommission) keeps the SCIM row it reconciles, so only a concurrent DELETE of that row in the same instant reaches it |
| `plugin/email/email.go` `replacedAddress` | the primary-address pick | `replaceAtOnce` runs only while the user has no verified address, and the core never marks an unverified address primary (`NewIdentity.Primary` requires `Verified`), so the list it scans has no primary row; the branch stays because the rule lives in the core, not in this plugin |
| `plugin/password/password.go` sign-up | a `Deliver` error other than "no deliverer" | the core's `Deliver` returns no other error today |
| `secret.go` `Config.DeriveKey` | the `hkdf.Key` error | it fails only for an output longer than the hash allows, and `SealKeySize` is one hash |
| `secret.go` `derivedOrGiven` | a `DeriveKey` error other than `ErrNoSecret` | the labels it passes are constants, so only the `hkdf.Key` error above could reach it |
| `multisession.go` `deviceSessions` | the request state being nil | every caller is a `SignedIn` operation, which the pipeline refuses without a request |
| `schemacheck.go` `CheckSchema` | the `Migrations` error after `MigrationStatus` succeeded | `MigrationStatus` has just called `Migrations` for the same configuration |
| `plugin/oauth/oauthtest` `Run`, `newServer` (3) | starting the fake server: `ecdsa.GenerateKey` and `PublicKey.ECDH` failing, and `Run`'s check of it | P-256 key generation fails only when the system's random source fails, which since Go 1.24 crashes the program instead, and a freshly generated P-256 key always converts |
| `plugin/oauth/oauthtest` `follow` (2) | the authorization request failing in transport, and the server's `Location` not parsing | the request goes to the kit's own running `httptest` server, and that server builds the `Location` from a redirect URI it has already checked |
| `plugin/oauth/oauthtest/server.go` `token`, `idToken` (4) | signing the ID token: `json.Marshal` of the claims and `ecdsa.Sign` failing, and the token endpoint's check of it | a map of strings, integers and booleans always encodes, and signing fails only when the random source fails |
| `authtest/browser.go` `Browser` | `cookiejar.New(nil)` and `url.Parse` of the test server's URL failing | the jar's error is documented always nil, and `httptest` produces a valid URL |
| `authtest/browser.go` `Browser` (third) | the `CheckRedirect` function that stops at the first redirect | every test reads the redirect itself; none follows one through this client yet |
| `authtest/faults.go` `dsnConnector.Driver`, `faultConnector.Driver` (2) | the `driver.Connector` interface's `Driver` method | `database/sql` calls it only from `sql.DB.Driver`, which neither the suite nor the core calls |
| `authtest/faults.go` `faultConn.BeginTx` | the wrapped driver failing to begin after the fault step passed | SQLite, the only driver the fault suite wraps, does not fail a `BEGIN` |
| `sessiontest/cache.go` (4), `verificationtest/verificationtest.go` (17) | the contract suites' `t.Fatalf` and `t.Errorf` reports | they run only when the implementation under test breaks the contract; every shipped store passes, which is the point |
| `code.go` `IssueCodeWith` | `ringOf` failing for the derived reuse keys | `ringOf` refuses only a key that is not `SealKeySize` bytes, and `DeriveKeys` returns exactly that size |
| `outbox.go` `enqueue` | `a.conn` failing | it fails only without a database, which `auth.New` refuses before any delivery |
| `outbox.go` `SendOutbox` | zero rows claimed | reached only when two senders race for the same row in the same instant |
| `signupfields.go` `fieldAssignment` | a column type outside the five sign-up field types | `collectColumns` refuses any other type at `auth.New`; the branch fails closed should one be added without a decoder |
| `signupfields.go` `SplitBody` | `json.Marshal` of the request's own keys | a map of `json.RawMessage` values that `json.Unmarshal` has just produced always encodes |
| `signupfields.go` `jsonNames` | an embedded pointer-to-struct in a request type | no request type embeds a pointer; the branch keeps the walk right for one that does |
| `verificationstore.go` `storageVerificationStore.Insert` | `json.Marshal` of the stored verification | a struct of strings and times always encodes |
| `plugin/lastlogin/lastlogin.go` `doClear` | `Effects.SetCookie` failing | it refuses only an invalid cookie name, and `New` has already checked the name |
| `plugin/passkey/passkey.go` `doLoginBegin` | `BeginLogin` failing for a signed-in user's own credentials | as `BeginDiscoverableLogin` above, it fails only when the system's random source fails |
| `plugin/passkey/presence.go` `BeginPresence` | `BeginLogin` failing for the user's own credentials | as `BeginDiscoverableLogin` above, it fails only when the system's random source fails |
| `plugin/passkey/reauth.go` `doReauthBegin` | `BeginLogin` failing for the signed-in user's own credentials | as `BeginDiscoverableLogin` above, it fails only when the system's random source fails |
| `plugin/passkey/policy.go` `provenModel` (2) | the attestation object and the AAGUID failing to parse | both were parsed and verified by go-webauthn before the model policy runs, so a credential reaching the policy always parses (`x5cChain`'s own refusals are unit-tested) |
| `plugin/password/policy.go` `remember`, `doChangeExpired` (2) | `NewID` and `Hasher.Hash` failing | both fail only when the system's random source fails, which since Go 1.24 crashes the program instead |
| `plugin/sso/oidc.go` `oauthProvider`, `resolve.go` `complete` (2) | `oauth.ValidateProvider` refusing the built provider; an empty subject at the end of a sign-in | registration already refuses every configuration `ValidateProvider` would (a public client without PKCE since 2026-10-07), and both protocols refuse an empty subject earlier (plugin/oauth's ID-token check, `verifySAML`); both stay as the last line before a session is issued |
| `plugin/sso/plugin.go` `Validate` | the `auth.NewKeyRing` error | it fails only for a key that is not `auth.SealKeySize` bytes, and `DeriveKeys` returns exactly that size |
| `plugin/sso/slo.go` `recordSAMLSession` | a session whose expiry is not after now | the record is written right after `CreateSession`, on the same clock, so a new session always has time left |
| `plugin/sso/saml.go` `SPMetadataXML` and its callers `doMetadata`, `serveMetadata` (4) | `xml.MarshalIndent` of the metadata | a fixed struct of strings, booleans and an integer always encodes; the error stays in the exported signature |
| `plugin/sso/gosaml2.go` `AuthnRequestURL`, `AuthnRequestPOST`, `VerifyResponse` (3) | gosaml2's unsigned AuthnRequest build failing; an `EncryptedAssertion` left undecrypted | in gosaml2 v0.12.0 the unsigned build has no error path, and a response whose assertion does not decrypt fails inside the library; both stay because the library's signatures allow it |
| `plugin/sso/logoutxml.go` `parseLogout` | `xml.Unmarshal` of the element etree just serialized | etree read it with a strict `encoding/xml` decoder and writes it back escaped; kept because the bytes started as an attacker's |
| `plugin/sso/discovery.go` `guardedClient` | `net.SplitHostPort` failing in the dialer's `Control` | the net package always passes `host:port` |
| `plugin/sso/ssotest` `NewOIDC`, `KeyPair`, `sign`, `signer`, `Sign`, `Encode`, `Encrypt` (12) | RSA key generation, certificate creation, signing, AES and RSA-OAEP failing, and etree failing to write to memory | each fails only when the system's random source fails, which since Go 1.24 crashes the program, or on a key the kit generated itself |
| `plugin/agentauth/session.go` `sessionUser` | the agent's or host's user no longer existing | DeleteUser removes the user's hosts and every agent of them or acting for the user (the plugin's `DataHooks`), so no agent or host is left naming a deleted user |
| `plugin/agentauth/execute.go` `doRequestCapability` | a pending grant given by someone other than the host's owner | a host's owner is set once and never changes, and a pending grant's `granted_by` is that owner |
| `plugin/agentauth/execute.go` `doApprove` (4) | deleting a pending grant a live active grant already covers | a request is pending only when no live grant covers it, and every approval resolves every pending grant; only two requests racing in the same instant leave one |
| `plugin/agentauth/execute.go` `activatePendingAgent`, `presence.go` `needsPresence` (2) | a pending agent whose host is gone | hosts are deleted only by DeleteUser, together with all their agents |
| `plugin/agentauth/store.go` `loadHost` | an empty id or kid | every caller checks the JWT's `iss` or passes a stored, non-empty host id first |
| `plugin/agentauth/handler.go` `VerifyAgentRequest` | `authhttp.Begin` failing | the request is stripped of its Authorization header and cookies first, so Begin has no credential to resolve and cannot fail |
| `plugin/agentauth/jws.go` `spendJTI` | the unique violation of a jti inserted twice | the count read just before refuses a replay; only two requests with one jti racing reach the insert's own refusal |
| `plugin/agentauth/agentclient` `NewKey`, `Connect`, `sign` (3) | Ed25519 key generation failing, and encoding the claims | key generation fails only when the system's random source fails, which since Go 1.24 crashes the program; the claims are strings, numbers and a `PublicKey` |
| `plugin/oauthprovider/cimd.go` `fetchPublicLimit` (9), shared by the CIMD and `jwks_uri` fetchers, and `jwksuri.go` `fetchPublicJWKS`'s final return (its checks are `checkJWKSResponse`, unit-tested) | the dial to a public address and the response read after it, `net.SplitHostPort` failing in the dialer, and `http.NewRequestWithContext` failing | reaching a public address needs the internet, which the hermetic suite never uses (every refusal before the dial is tested, an unresolvable host included); the net package always passes `host:port`; the request is built from an https URL that already parsed and a live context |
| `plugin/oauthprovider/jwksuri.go` `clientKeySet`, `assertion.go` `verifyAssertion` | a stored inline key set that no longer parses, and the claims of an assertion that just verified failing to decode | key sets pass `parseClientJWKS` at registration, update and in `TrustedClients`, and only the provider writes the client table; a JWS that verified has three parts and a JSON payload |
| `plugin/oauthprovider` `TokenResponse.MarshalJSON`, `Introspection.MarshalJSON`, `Metadata.MarshalJSON` (3) | `json.Unmarshal` of the bytes `json.Marshal` just produced | the input is the encoder's own output |
| `plugin/oauthprovider/token.go` `atHash` | a signing algorithm with no hash | the key set is built by the jwt plugin, which publishes only `jwt.AlgValues` algorithms, and `jwt.HashOf` has a hash for each; the check stays because a zero hash would panic in `Hash.New` |
| `plugin/oauthprovider/oauthprovider.go` `checkSignerIssuer` | decoding the probe token the jwt plugin just signed | a token the plugin signs has three parts and a JSON payload; a signer that fails is tested (`TestOAuthProvider_SignerOutage`) |
| `plugin/oauthprovider/token.go` `doUserInfo`, `pairwise.go` `subjectForClient` (2) | the token's user or client gone after the token verified | DeleteUser and DeleteClient remove the token rows in the same transaction, and a trusted client removed from configuration fails `active` first; only a deletion racing the request reaches them, and both answer invalid_token |
| `plugin/invite/invite.go` `use`, `doReject`; `plugin/emailchallenge/emailchallenge.go` `complete` (3) | the guarded update or delete matching no row after the invite or challenge was read | each write repeats the read's conditions (pending, unexpired, uses left, the status read), so only a second request spending the same invite or challenge in the same instant reaches it; no app hook runs between the read and the write. The guard is what makes that race safe, and breaking all three layers of the invite's max-uses check is caught |
| `plugin/invite/invite.go` `doActivate`; `plugin/emailchallenge/emailchallenge.go` `doStart`, `complete`; `plugin/referral/referral.go` `doRemember` (4) | `Effects.SetCookie` failing | `SetCookie` fails only on a name `auth.CheckCookieName` refuses, and each plugin sets its one constant name, which it accepts (`TestP3Cover2_PluginCookieNamesAreValid`) |
| `plugin/referral/referral.go` `markStep` | `json.Marshal` of the step's metadata | the value is a `map[string]string`, which `encoding/json` cannot fail to encode |
| `plugin/oauthprovider/registry.go` `LinkClient` | the unique violation of a link inserted twice | `linked`, read just before, answers alreadyLinked; only two links of one pair racing reach the insert's own refusal |
| `ownership.go` `RequireOwnerRow` (3) | the owner-keyed read missing a row that `RequireOwner`'s read then finds owned by the caller | only a write landing between the two reads of one call, which nothing inside the call makes; the branch answers not-found rather than return unfilled columns |
| `plugin/oauth/oauth.go` `issueState`, `Init`, `withErrorCode` (3) | `json.Marshal` of the sealed flow state; `auth.NewKeyRing` of the derived state keys; `url.Parse` of the error page | a struct of strings, an integer and bytes always encodes; `DeriveKeys` returns keys of exactly `auth.SealKeySize`; the page already passed `TrustsReturnURL`, which parsed it |
| `plugin/agentauth/lifecycle.go` `doEnrollHost` | the conditional update matching no row after the pending host was read | only a second enrollment racing between the read and the update; no hook runs between them |
| `plugin/password/stuffing.go` `init` | the `DeriveKeys` error | `validate` derives the same key at `auth.New`, which refuses before any `Init` runs |
| `plugin/organization/messagedata.go` `primaryEmail` | verified addresses of which none is primary | the email plugin makes the first verified address primary (`promoteIfNone`), so a user with a verified address always has a primary one |

Reachable, and not yet covered by any test: **none** (2026-10-08). The 14 statements the 2026-10-07 modules left open (oauthproxy 3, audit 1, apikey 8, scim 1, organization 1), with the three listed rows a test can reach after all (apikey `doUpdate`, the organization invitation close, the SCIM managed `bind`), are tested by `integration/p3_cover_test.go`, `plugin/oauthproxy/relay_p3cover_test.go` and `plugin/scim/mount_p3cover_test.go`: a row that vanishes between a plugin's read and its write is produced through a hook the app owns (the API-key membership check, `BeforeCancelInvitation`), which runs inside the operation's transaction, instead of racing two requests. The one left, `encodePermissions`'s `json.Marshal`, is in the table above with its reason. The 2026-10-08 additions (the admin filters and all-sessions list, organization resend and the platform API, API-key `StampEveryUse`, the deviceauth client, SCIM profile authority, email address checks, and the new `emailchallenge`, `invite` and `referral` plugins) are tested by their own suites and `integration/p3_cover2_test.go` (database faults on the API-key stamp, the resend, the platform list, the active-team read and the SCIM managed claim; a cache that cannot drop an entry; the app's hooks refusing a claim), and the 8 statements of the new plugins no test can reach are in the table above. The full `task cover` of 2026-10-08 then found 19 more statements open in the core, `plugin/password` and `plugin/organization`; `integration/f1_cover_test.go` and the root `p2_test.go` test the reachable ones (rate stores failing under the credential-stuffing guard and in `RateHit`/`RatePeek`, a garbled storage counter, the database store's read, the user-locale read, the profile-field write and `RequireOwnerRow`'s read faulted, message data that does not encode or decode at enqueue and at send, a leading `*` origin glob with nothing to take, and `orgtest` with a failing id generator), and the unreachable ones are the last five rows of the table above. The package rows above are that `task cover` run.

## What coverage does not measure

A covered line proves it ran, not that its answer is right. The properties that matter for an auth library are pinned separately: source guards over the syntax tree (constant-time comparison, plugins never writing core tables, one password hash on every sign-in path), a timing test, a fault-injecting database driver that fails every database call of an operation in turn (`sweepFaults`), the negative type check (`task typecheck`), and the integration suite on Postgres and MySQL as well as SQLite (`task test:engines`).
