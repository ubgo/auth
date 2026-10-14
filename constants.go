package auth

// Rule: NO BARE STRINGS for any value with a closed set of choices. Table
// names, column names, id prefixes and purposes appear in the schema, the
// queries, the migrations and the plugins; a divergence between two of them is
// a query that compiles and fails at run time. Naming them makes it a compile
// error.

// Physical table names owned by the core.
//
// Every table the library owns is prefixed "auth_". The prefix is load-bearing:
// a migration tool that diffs the whole database (Atlas) proposes to drop
// tables no schema declares, so a consumer excludes "auth_*" in one glob that
// keeps working as plugins add tables.
const (
	TableNameUser         = "auth_user"
	TableNameIdentity     = "auth_identity"
	TableNameSession      = "auth_session"
	TableNameVerification = "auth_verification"
	// TableNameMigrations is the migration ledger. It is written only by the
	// sqlb ledger.
	//ds:def id=tablenamemigrations-xra38puh owner=@khanakia stability=stable
	TableNameMigrations = "auth_migrations"
)

// Table aliases reserved by the core. A plugin must not reuse one; New rejects
// a collision. Aliases live on the table, not the statement, so a plugin in
// another module can write an ON clause against a core column at package level.
const (
	TableAliasUser         = "u"
	TableAliasIdentity     = "i"
	TableAliasSession      = "s"
	TableAliasVerification = "v"
)

// ReservedAliases is the canonical list of aliases the core occupies.
var ReservedAliases = []string{TableAliasUser, TableAliasIdentity, TableAliasSession, TableAliasVerification, TableAliasCode}

// Column names on auth_user. The core owns exactly these; a plugin adds its
// own through ColumnExtender.
const (
	ColUserID        = "id"
	ColUserName      = "name"
	ColUserImage     = "image"
	ColUserCreatedAt = "created_at"
	ColUserUpdatedAt = "updated_at"
	// ColUserSessionsValidAfter is the instant before which no session of
	// the user is accepted: DeleteUserSessions (sign out everywhere) sets it,
	// which is what ends stateless sessions, and cached ones once their
	// entry expires. NULL until the first such call.
	ColUserSessionsValidAfter = "sessions_valid_after"
)

// CoreUserColumns is every column the core owns on auth_user, so New can refuse
// a plugin that declares one of them as its own.
//
//ds:def id=core-coreusercolumns-x6whdeje owner=@khanakia stability=stable
var CoreUserColumns = []string{ColUserID, ColUserName, ColUserImage, ColUserCreatedAt, ColUserUpdatedAt, ColUserSessionsValidAfter}

// Column names on auth_identity.
const (
	ColIdentityID         = "id"
	ColIdentityUserID     = "user_id"
	ColIdentityKind       = "kind"
	ColIdentityValue      = "value"
	ColIdentityValueRaw   = "value_raw"
	ColIdentityVerifiedAt = "verified_at"
	ColIdentityIsPrimary  = "is_primary"
	ColIdentityScopeID    = "scope_id"
	ColIdentityCreatedAt  = "created_at"
)

// Column names on auth_session.
const (
	ColSessionID         = "id"
	ColSessionUserID     = "user_id"
	ColSessionTokenHash  = "token_hash"
	ColSessionExpiresAt  = "expires_at"
	ColSessionLastSeenAt = "last_seen_at"
	ColSessionIP         = "ip"
	ColSessionUserAgent  = "user_agent"
	ColSessionCreatedAt  = "created_at"
	// ColSessionFactorPending marks a session waiting for a second factor.
	ColSessionFactorPending = "second_factor_pending"
	// ColSessionImpersonator is the admin behind an impersonation session.
	ColSessionImpersonator = "impersonated_by"
	// ColSessionTransient marks a session made without "remember me".
	ColSessionTransient = "transient"
	// ColSessionIdleSeconds, ColSessionRefreshSeconds and ColSessionMaxExpiresAt
	// are the lifetime chosen for the session when it was created (see
	// WithSessionPolicy), so a sliding refresh uses the session's own values.
	// 0 and NULL, as on rows from before the columns existed, mean the
	// SessionConfig defaults.
	ColSessionIdleSeconds    = "idle_seconds"
	ColSessionRefreshSeconds = "refresh_seconds"
	ColSessionMaxExpiresAt   = "max_expires_at"
	// ColSessionRevokedAt is when the session was ended before its expiry,
	// under WithSessionArchive, which keeps the row as an audit trail
	// instead of deleting it. NULL for a live session, and always NULL
	// without the option, whose sign-out deletes the row as before.
	ColSessionRevokedAt = "revoked_at"
	// ColSessionData is the app's JSON for the session (Session.Data), the
	// engine's document type; NULL for none, and always NULL on rows from
	// before the column existed.
	ColSessionData = "data"
	// ColSessionReauthenticatedAt is when the user last re-authenticated on
	// the session (Session.ReauthenticatedAt); NULL when never, and always
	// NULL on rows from before the column existed.
	ColSessionReauthenticatedAt = "reauthenticated_at"
	// ColSessionTasks is the session tasks still to complete
	// (Session.Tasks), their ids joined by commas; '' for none, and on rows
	// from before the column existed.
	ColSessionTasks = "pending_tasks"
	// ColSessionPreviousTokenHash is the hash of the token the session had
	// before its last rotation under WithTokenRotation, and
	// ColSessionPreviousValidUntil the end of that token's grace window;
	// both NULL until a rotation, and always NULL without the option.
	ColSessionPreviousTokenHash  = "previous_token_hash"
	ColSessionPreviousValidUntil = "previous_valid_until"
)

// Column names on auth_verification.
const (
	ColVerificationID         = "id"
	ColVerificationIdentifier = "identifier"
	ColVerificationPurpose    = "purpose"
	ColVerificationTokenHash  = "token_hash"
	ColVerificationExpiresAt  = "expires_at"
	ColVerificationConsumedAt = "consumed_at"
	ColVerificationMeta       = "meta"
	ColVerificationCreatedAt  = "created_at"
)

// Id prefixes. A prefixed id tells a reader of a log line or a support ticket
// what kind of row it names without a lookup.
const (
	IDPrefixUser         = "usr"
	IDPrefixIdentity     = "idn"
	IDPrefixSession      = "ses"
	IDPrefixVerification = "ver"
)

// IdentifierKindName is the discriminator stored in auth_identity.kind, such as
// "email" or "phone".
//
// The core defines no kinds of its own: identifier plugins register them. It is
// a named type rather than a string so a kind cannot be confused with an
// identifier's value, which is also a string and appears beside it in almost
// every signature.
type IdentifierKindName string

// Purpose names what a verification token or a delivered message is for, as
// "<plugin>.<name>", such as "email.verify" or "password.reset".
//
// The purpose is part of every token lookup, so a verify token can never be
// used as a reset token.
type Purpose string
