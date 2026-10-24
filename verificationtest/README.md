# verificationtest

The conformance suite for an `auth.VerificationStore`, the store single-use verification tokens live in (email and reset links, magic links, OAuth state, passkey ceremonies). A custom store proves itself with one call instead of finding out in production that a reset link worked twice.

```go
func TestMyStore(t *testing.T) {
	verificationtest.Run(t, func(t *testing.T) auth.VerificationStore {
		return mystore.New(freshKeyspace(t))
	})
}
```

`open` is called once per case, so each case must start empty: a store on a shared server returns a store with a fresh key prefix, and a store on the shared `auth_verification` table deletes the rows of `verificationtest.PurposeA` and `PurposeB` first (the cases reuse token hashes, which the table keeps unique).

The rules it checks: `Consume` returns what `Insert` saved, once; a wrong purpose is refused and spends nothing; a token at or after its expiry is refused; [`Racers`](verificationtest.go) concurrent `Consume` calls on one token spend it exactly once; `ConsumeAll` ends one purpose for one identifier and no other, and not a token issued after it; `DeleteIdentifiers` ends every purpose of the identifiers it names; `Sweep` never removes a live token; and a store that promises exclusive inserts (`auth.ExclusiveVerificationStore` reporting true) refuses a duplicate hash with `auth.ErrTokenExists`, and of `Racers` concurrent inserts of one hash stores exactly one. The suite's own tests run each rule against a store that breaks it, so every case is seen to fail.

The core's SQL store (on SQLite, Postgres and MySQL in `integration/`), `auth.NewMemoryVerificationStore`, `auth.NewStorageVerificationStore` and contrib/redis `NewVerificationStore` all run it. It imports only the standard library and the core.
