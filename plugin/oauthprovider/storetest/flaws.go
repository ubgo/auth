package storetest

// flaw is a rule a MemoryStore breaks on purpose. The suite's own tests set
// one per store and check the case that pins the rule fails: a guard nobody
// has seen fail is only a claim. NewMemoryStore never sets one.
type flaw int

// The rules a flawed MemoryStore can break, each pinned by a case of the
// suite.
const (
	flawNone flaw = iota
	// flawDropsField loses SecretEncrypted on read.
	flawDropsField
	// flawInsertOverwrites accepts a taken client id.
	flawInsertOverwrites
	// flawUpdateWholeRecord writes every field, not the named ones.
	flawUpdateWholeRecord
	// flawUpdateNonAtomic reads, waits and writes a client back.
	flawUpdateNonAtomic
	// flawDeleteClientKeepsTokens leaves a deleted client's tokens.
	flawDeleteClientKeepsTokens
	// flawRedeemReusable lets a code be redeemed again.
	flawRedeemReusable
	// flawRedeemNonAtomic checks and spends a code in two steps.
	flawRedeemNonAtomic
	// flawBurnDoesNothing never spends a refused code.
	flawBurnDoesNothing
	// flawDeleteCodesIgnoresRedeemed deletes spent codes too.
	flawDeleteCodesIgnoresRedeemed
	// flawRotateNonAtomic checks and rotates in two steps.
	flawRotateNonAtomic
	// flawRotateRevoked rotates a revoked refresh token.
	flawRotateRevoked
	// flawRotateStale answers a reuse with the record before its rotation.
	flawRotateStale
	// flawRevokeFirstOnly revokes one token of a family.
	flawRevokeFirstOnly
	// flawRevokeRecounts counts tokens revoked before.
	flawRevokeRecounts
	// flawEmptyFilterAccepted revokes every token for an empty filter.
	flawEmptyFilterAccepted
	// flawRevokeAccessEndsAll revokes the refresh token with the access one.
	flawRevokeAccessEndsAll
	// flawConsentMerges widens a consent instead of replacing it.
	flawConsentMerges
	// flawSweepsRefreshable deletes tokens whose refresh token still lives.
	flawSweepsRefreshable
	// flawDeleteUserTooBroad deletes other users' consents.
	flawDeleteUserTooBroad
	// flawRestoreRevoked puts back the rotation of a revoked refresh token.
	flawRestoreRevoked
)
