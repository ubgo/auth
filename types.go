package auth

import "time"

// User is the core identity record: the minimum any sign-in needs.
//
// Why it is this thin: every column here is a column every consuming app
// carries forever, whether it uses email, phones, handles or only Google.
// An email address is not here, because an app that signs in with a phone has
// none; the email plugin adds its own columns to auth_user. The test for adding
// a field is whether an app with no plugins but one sign-in method would be
// wrong without it.
//
//ds:def id=core-user-dxupgphj owner=@khanakia stability=stable
type User struct {
	// ID is the stable public identifier, and the foreign-key target for plugin
	// tables and app tables alike. It is opaque: nothing may parse it.
	ID string

	// Name and Image are display fields, set at sign-up or imported from a
	// social provider. Both may be empty.
	Name  string
	Image string

	CreatedAt time.Time
	UpdatedAt time.Time

	// SessionsValidAfter is set by DeleteUserSessions with no exception
	// ("sign out everywhere"): a session created before it is refused in
	// every session mode, which is what revokes stateless sessions, whose
	// tokens the server never stored. Nil until the first such call.
	SessionsValidAfter *time.Time
}

// Identity is one way of naming a user: an email address, a phone number, a
// handle. Social accounts are not identities; the oauth plugin keeps them in
// its own table, because a provider asserts them rather than the user.
//
//ds:def id=core-identity-r63skmf9 owner=@khanakia stability=stable
type Identity struct {
	ID     string
	UserID string

	// Kind selects which registered kind's rules apply: its normalizer, its
	// uniqueness, whether it can sign in or recover.
	Kind IdentifierKindName

	// Value is the normalized form, and the only form any lookup, comparison or
	// index uses. It is compared exactly, never through SQL lower(): the
	// normalizer is the one folding rule, and a second one in SQL would differ
	// between engines.
	Value string

	// ValueRaw is what the user typed, kept to show it back. Never compared.
	ValueRaw string

	// VerifiedAt is nil until the user proved control of Value.
	//
	// The most security-critical nullable in the schema. Any flow that treats
	// an unverified identity as proof of ownership — matching an invitation,
	// linking a social account, joining by domain — is an account takeover,
	// and the published advisories in comparable libraries are all that one
	// mistake. Match identities to people only through VerifiedIdentities.
	VerifiedAt *time.Time

	// IsPrimary marks the one identity per kind that the kind's plugin copies
	// onto the user row. Only a verified identity can be primary.
	IsPrimary bool

	// ScopeID confines uniqueness to one tenant. Nil means the value is unique
	// across the deployment.
	ScopeID *string

	CreatedAt time.Time
}

// Verified reports whether the identity has been proven.
func (i Identity) Verified() bool { return i.VerifiedAt != nil }

// Session is a signed-in session. Its raw token is never in this struct or in
// the database; only its hash is stored.
//
//ds:def id=core-session-vv6smfng owner=@khanakia stability=stable
type Session struct {
	ID         string
	UserID     string
	ExpiresAt  time.Time
	LastSeenAt time.Time

	// IP and UserAgent are for the "your sessions" list only. Both come from
	// the client, so nothing may use them to decide anything.
	IP        string
	UserAgent string

	CreatedAt time.Time

	// SecondFactorPending is true for a session whose user must still pass a
	// second factor. Such a session signs nobody in: CurrentUser and the
	// SignedIn requirement ignore it, and only PendingSecondFactor operations
	// see it. PromoteSession replaces it with a full one.
	SecondFactorPending bool

	// Tasks are the session tasks still to complete (SessionTasker), empty
	// for an ordinary session. While any is pending the session reaches only
	// the operations its tasks allow, and CurrentUser reports nobody;
	// CompleteSessionTask replaces it with one without the task.
	Tasks SessionTasks

	// ImpersonatedBy is the id of the admin acting as this user, or nil for
	// the user's own session. It is on the row, so the user's session list
	// shows it and nothing can hide that someone else was signed in as them.
	ImpersonatedBy *string

	// APIKeyID is set when the request was made with an API key rather than
	// a session; such a Session is built for the request and has no row. It
	// signs the user in for the app's routes, and every auth operation that
	// needs a person refuses it.
	APIKeyID string

	// Transient is true for a session made without "remember me": it lives
	// SessionConfig.TransientIdleTimeout at most, and its cookie has no
	// expiry, so closing the browser ends it.
	Transient bool

	// IdleSeconds, RefreshSeconds and MaxExpiresAt are the lifetime chosen
	// for this session when it was created (WithSessionPolicy), which a
	// sliding refresh keeps using: a year-long app session must not shrink
	// to the web default on its first refresh. 0 and nil mean the
	// SessionConfig defaults, as for rows from before the columns existed;
	// Lifetime resolves them.
	IdleSeconds    int64
	RefreshSeconds int64
	MaxExpiresAt   *time.Time

	// RevokedAt is when the session was ended before its expiry, kept under
	// WithSessionArchive as an audit trail; nil for a live session. A
	// revoked session is never found by a lookup or a list, only by
	// RevokedSessions.
	RevokedAt *time.Time

	// ReauthenticatedAt is when the user last proved who they are on this
	// session without signing in again (Auth.Reauthenticate), or nil when
	// they never did; FreshAt is the later of it and CreatedAt, which is what
	// a FreshSignIn operation checks. It never moves the expiry.
	ReauthenticatedAt *time.Time

	// Data is JSON the app attached to this session, or nil: the active
	// workspace, a device name, a flag resolved at sign-in. Every store
	// keeps it with the session, so a request reads it with no query
	// (SessionData); SetSessionData replaces it, a Session.BeforeCreate
	// hook sets what a session starts with (EncodeSessionData). It
	// survives refresh, token rotation and the second-factor promotion,
	// and ends with the session. At most MaxSessionDataSize bytes.
	Data AppData
}

// Verification is a single-use token row: a verify link, a reset link, an
// OAuth state. The raw token is never stored.
//
//ds:def id=core-verification-rxkcq64t owner=@khanakia stability=stable
type Verification struct {
	ID string

	// Identifier names what the token is about. Which id it holds depends on
	// Purpose, and each purpose's owner documents it: an identity id for an
	// email verification, a user id for a password reset, a provider name for
	// an OAuth state.
	Identifier string

	Purpose    Purpose
	ExpiresAt  time.Time
	ConsumedAt *time.Time

	// Meta is free text owned by the purpose's plugin, such as an OAuth PKCE
	// verifier. Empty for most purposes.
	Meta string

	CreatedAt time.Time
}
