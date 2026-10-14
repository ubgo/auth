package auth

import (
	"time"

	"github.com/ubgo/sqlb"
)

// Tables owned by the core. Package-level values, because a plugin in another
// module declares its joins against them before any statement exists.
//
// TableCode, TableRateLimit and TableMigrations exist so an app can name
// those tables in RenameTable and Auth.TableName like any other; the core
// writes them through its own generators and nothing joins them.
var (
	TableUser         = sqlb.Table{Name: TableNameUser, Alias: TableAliasUser}
	TableIdentity     = sqlb.Table{Name: TableNameIdentity, Alias: TableAliasIdentity}
	TableSession      = sqlb.Table{Name: TableNameSession, Alias: TableAliasSession}
	TableVerification = sqlb.Table{Name: TableNameVerification, Alias: TableAliasVerification}
	TableCode         = sqlb.Table{Name: TableNameCode, Alias: TableAliasCode}
	TableRateLimit    = sqlb.Table{Name: TableNameRateLimit}
	TableMigrations   = sqlb.Table{Name: TableNameMigrations}
)

// Typed columns on auth_user.
//
// The Go type of each column is what makes every predicate and binding built
// on it checkable: comparing UserCreatedAt with a string does not compile.
// Nullable columns are pointer types, so null is visible in the type system.
var (
	UserID        = sqlb.Col[string](TableUser, ColUserID)
	UserName      = sqlb.Col[string](TableUser, ColUserName)
	UserImage     = sqlb.Col[string](TableUser, ColUserImage)
	UserCreatedAt = sqlb.Col[time.Time](TableUser, ColUserCreatedAt)
	UserUpdatedAt = sqlb.Col[time.Time](TableUser, ColUserUpdatedAt)
	// UserSessionsValidAfter is nil until the user first signed out
	// everywhere.
	UserSessionsValidAfter = sqlb.Col[*time.Time](TableUser, ColUserSessionsValidAfter)
)

// Typed columns on auth_identity.
var (
	IdentityID         = sqlb.Col[string](TableIdentity, ColIdentityID)
	IdentityUserID     = sqlb.Col[string](TableIdentity, ColIdentityUserID)
	IdentityKind       = sqlb.Col[IdentifierKindName](TableIdentity, ColIdentityKind)
	IdentityValue      = sqlb.Col[string](TableIdentity, ColIdentityValue)
	IdentityValueRaw   = sqlb.Col[string](TableIdentity, ColIdentityValueRaw)
	IdentityVerifiedAt = sqlb.Col[*time.Time](TableIdentity, ColIdentityVerifiedAt)
	IdentityIsPrimary  = sqlb.Col[bool](TableIdentity, ColIdentityIsPrimary)
	IdentityScopeID    = sqlb.Col[*string](TableIdentity, ColIdentityScopeID)
	IdentityCreatedAt  = sqlb.Col[time.Time](TableIdentity, ColIdentityCreatedAt)
)

// Typed columns on auth_session.
var (
	SessionID            = sqlb.Col[string](TableSession, ColSessionID)
	SessionUserID        = sqlb.Col[string](TableSession, ColSessionUserID)
	SessionTokenHash     = sqlb.Col[[]byte](TableSession, ColSessionTokenHash)
	SessionExpiresAt     = sqlb.Col[time.Time](TableSession, ColSessionExpiresAt)
	SessionLastSeenAt    = sqlb.Col[time.Time](TableSession, ColSessionLastSeenAt)
	SessionIP            = sqlb.Col[string](TableSession, ColSessionIP)
	SessionUserAgent     = sqlb.Col[string](TableSession, ColSessionUserAgent)
	SessionCreatedAt     = sqlb.Col[time.Time](TableSession, ColSessionCreatedAt)
	SessionFactorPending = sqlb.Col[bool](TableSession, ColSessionFactorPending)
	SessionImpersonator  = sqlb.Col[*string](TableSession, ColSessionImpersonator)
	SessionTransient     = sqlb.Col[bool](TableSession, ColSessionTransient)
	// The session's own lifetime; see ColSessionIdleSeconds.
	SessionIdleSeconds    = sqlb.Col[int64](TableSession, ColSessionIdleSeconds)
	SessionRefreshSeconds = sqlb.Col[int64](TableSession, ColSessionRefreshSeconds)
	SessionMaxExpiresAt   = sqlb.Col[*time.Time](TableSession, ColSessionMaxExpiresAt)
	// SessionRevokedAt is nil for a live session; see ColSessionRevokedAt.
	SessionRevokedAt = sqlb.Col[*time.Time](TableSession, ColSessionRevokedAt)
	// SessionAppData is the app's JSON for the session; see Session.Data.
	SessionAppData = sqlb.Col[AppData](TableSession, ColSessionData)
	// SessionReauthenticatedAt is nil until a re-authentication; see
	// Session.ReauthenticatedAt.
	SessionReauthenticatedAt = sqlb.Col[*time.Time](TableSession, ColSessionReauthenticatedAt)
	// SessionPendingTasks is the pending session tasks; see Session.Tasks.
	SessionPendingTasks = sqlb.Col[SessionTasks](TableSession, ColSessionTasks)
	// SessionPreviousTokenHash and SessionPreviousValidUntil are the token
	// a WithTokenRotation rotation replaced and the end of its grace
	// window. They are never bound into a Session: the hash is a lookup
	// key only, like SessionTokenHash.
	SessionPreviousTokenHash  = sqlb.Col[[]byte](TableSession, ColSessionPreviousTokenHash)
	SessionPreviousValidUntil = sqlb.Col[*time.Time](TableSession, ColSessionPreviousValidUntil)
)

// Typed columns on auth_verification.
var (
	VerificationID         = sqlb.Col[string](TableVerification, ColVerificationID)
	VerificationIdentifier = sqlb.Col[string](TableVerification, ColVerificationIdentifier)
	VerificationPurpose    = sqlb.Col[Purpose](TableVerification, ColVerificationPurpose)
	VerificationTokenHash  = sqlb.Col[[]byte](TableVerification, ColVerificationTokenHash)
	VerificationExpiresAt  = sqlb.Col[time.Time](TableVerification, ColVerificationExpiresAt)
	VerificationConsumedAt = sqlb.Col[*time.Time](TableVerification, ColVerificationConsumedAt)
	VerificationMeta       = sqlb.Col[string](TableVerification, ColVerificationMeta)
	VerificationCreatedAt  = sqlb.Col[time.Time](TableVerification, ColVerificationCreatedAt)
)

// UserBindings binds every core user column to dst.
//
// A function rather than a shared slice because each binding holds a pointer
// into dst: a package-level slice would be shared mutable state between
// concurrent queries.
//
//ds:def id=core-userbindings-cw7gf4c3 owner=@khanakia stability=stable
func UserBindings(dst *User) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(UserID, &dst.ID),
		sqlb.Bind(UserName, &dst.Name),
		sqlb.Bind(UserImage, &dst.Image),
		sqlb.Bind(UserCreatedAt, &dst.CreatedAt),
		sqlb.Bind(UserUpdatedAt, &dst.UpdatedAt),
		sqlb.Bind(UserSessionsValidAfter, &dst.SessionsValidAfter),
	}
}

// IdentityBindings binds every identity column to dst.
func IdentityBindings(dst *Identity) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(IdentityID, &dst.ID),
		sqlb.Bind(IdentityUserID, &dst.UserID),
		sqlb.Bind(IdentityKind, &dst.Kind),
		sqlb.Bind(IdentityValue, &dst.Value),
		sqlb.Bind(IdentityValueRaw, &dst.ValueRaw),
		sqlb.Bind(IdentityVerifiedAt, &dst.VerifiedAt),
		sqlb.Bind(IdentityIsPrimary, &dst.IsPrimary),
		sqlb.Bind(IdentityScopeID, &dst.ScopeID),
		sqlb.Bind(IdentityCreatedAt, &dst.CreatedAt),
	}
}

// SessionBindings binds a session to dst. The token hash is absent on purpose:
// a session is looked up by its hash and never selected with it, so the secret
// stays off every result set, logged ones included.
func SessionBindings(dst *Session) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(SessionID, &dst.ID),
		sqlb.Bind(SessionUserID, &dst.UserID),
		sqlb.Bind(SessionExpiresAt, &dst.ExpiresAt),
		sqlb.Bind(SessionLastSeenAt, &dst.LastSeenAt),
		sqlb.Bind(SessionIP, &dst.IP),
		sqlb.Bind(SessionUserAgent, &dst.UserAgent),
		sqlb.Bind(SessionCreatedAt, &dst.CreatedAt),
		sqlb.Bind(SessionFactorPending, &dst.SecondFactorPending),
		sqlb.Bind(SessionImpersonator, &dst.ImpersonatedBy),
		sqlb.Bind(SessionTransient, &dst.Transient),
		sqlb.Bind(SessionIdleSeconds, &dst.IdleSeconds),
		sqlb.Bind(SessionRefreshSeconds, &dst.RefreshSeconds),
		sqlb.Bind(SessionMaxExpiresAt, &dst.MaxExpiresAt),
		sqlb.Bind(SessionRevokedAt, &dst.RevokedAt),
		sqlb.Bind(SessionAppData, &dst.Data),
		sqlb.Bind(SessionReauthenticatedAt, &dst.ReauthenticatedAt),
		sqlb.Bind(SessionPendingTasks, &dst.Tasks),
	}
}

// VerificationBindings binds a verification row to dst, without its hash.
func VerificationBindings(dst *Verification) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(VerificationID, &dst.ID),
		sqlb.Bind(VerificationIdentifier, &dst.Identifier),
		sqlb.Bind(VerificationPurpose, &dst.Purpose),
		sqlb.Bind(VerificationExpiresAt, &dst.ExpiresAt),
		sqlb.Bind(VerificationConsumedAt, &dst.ConsumedAt),
		sqlb.Bind(VerificationMeta, &dst.Meta),
		sqlb.Bind(VerificationCreatedAt, &dst.CreatedAt),
	}
}

// VerifiedIdentity restricts identity rows to those whose ownership is proven.
// It is the one definition of the rule, so a plugin that matches an identity to
// a person cannot write a weaker version of it by accident.
func VerifiedIdentity() sqlb.Predicate { return sqlb.IsNotNull(IdentityVerifiedAt) }
