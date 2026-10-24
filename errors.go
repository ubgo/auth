package auth

import (
	"errors"
	"net/http"
)

// Wiring errors, returned by New. Each is a deployment that would be broken in
// a way nobody notices until a user is stuck, so it is refused at start-up.
var (
	ErrDuplicatePlugin    = errors.New("auth: duplicate plugin name")
	ErrMissingDependency  = errors.New("auth: plugin dependency not registered")
	ErrAliasConflict      = errors.New("auth: table alias conflicts with a registered alias")
	ErrNonUniqueLogin     = errors.New("auth: a sign-in or recovery identifier must be unique")
	ErrNoNormalizer       = errors.New("auth: identifier kind has no normalizer")
	ErrBadIdentifier      = errors.New("auth: identifier kind is not valid")
	ErrDuplicateKind      = errors.New("auth: two plugins register one identifier kind")
	ErrNoDeliverer        = errors.New("auth: the identifier kind's plugin cannot deliver messages")
	ErrNoSignInMethod     = errors.New("auth: no sign-in method; add a plugin such as password or oauth")
	ErrColumnConflict     = errors.New("auth: two owners for one column")
	ErrDuplicateOperation = errors.New("auth: two operations share an id or a route")
	ErrBadOperation       = errors.New("auth: operation description is not valid")
	ErrUnknownHookTarget  = errors.New("auth: hook names an operation that is not registered")
	ErrBadOrigin          = errors.New("auth: origin is not an absolute URL")
	ErrBadSessionCheck    = errors.New("auth: a session check can use only auth_session and auth_user")

	// ErrNilOption: an option that takes a func or an interface was given
	// nil, which would otherwise panic at the first request that calls it.
	// The error names the option; leave it out to keep its default.
	ErrNilOption = errors.New("auth: an option was given nil; leave the option out to keep its default")

	// ErrBadSessionConfig: a WithSession duration is negative. A zero field
	// takes DefaultSessionConfig's value instead.
	ErrBadSessionConfig = errors.New("auth: a session duration is negative")

	// ErrNoDatabase is returned when the database is needed and New was given
	// none. It is never mapped to "signed out": a missing database hidden
	// behind a sign-out looks like a working system that forgets everyone.
	ErrNoDatabase = errors.New("auth: no database configured; pass auth.WithDB")

	// ErrPluginNotRegistered is returned by PluginOf for a plugin that is not
	// in the list.
	ErrPluginNotRegistered = errors.New("auth: plugin not registered")

	// ErrNoVerificationSender is returned by SendVerification for a kind
	// whose plugin is no VerificationSender.
	ErrNoVerificationSender = errors.New("auth: the identifier's plugin cannot send a verification")
)

// Errors the core returns to callers. Each is safe to show; see Error.
var (
	// ErrUserNotFound: no user has this id.
	ErrUserNotFound = NewError("auth.user_not_found", http.StatusNotFound, "Not found.")

	// ErrIdentityNotFound covers a missing identity and an unverified one
	// asked for as verified. The two share one error so the difference cannot
	// be used to learn which addresses exist.
	ErrIdentityNotFound = NewError("auth.identity_not_found", http.StatusNotFound, "Not found.")

	// ErrIdentityTaken: the unique index refused the value, because another
	// account already has it verified (or at all, for kinds unique over every
	// row).
	ErrIdentityTaken = NewError("auth.identity_taken", http.StatusConflict, "This is already in use by another account.")

	// ErrIdentifierInvalid: the value is malformed for every kind that could
	// have taken it. It describes the input, not any account, so it is safe.
	ErrIdentifierInvalid = NewError("auth.identifier_invalid", http.StatusBadRequest, "This does not look right. Check it and try again.")

	// ErrTokenInvalid covers a wrong, used, expired and wrong-purpose token
	// alike.
	ErrTokenInvalid = NewError("auth.token_invalid", http.StatusBadRequest, "This link or code is not valid any more.")

	// ErrLastSignInMethod: removing this would leave the account with no way
	// in.
	ErrLastSignInMethod = NewError("auth.last_sign_in_method", http.StatusConflict, "Add another way to sign in before you remove this one.")

	// ErrNotVerified: the operation needs a verified identity.
	ErrNotVerified = NewError("auth.not_verified", http.StatusConflict, "Verify this first.")

	// ErrNoRecoveryChannel: the user has no verified identity that can
	// receive a recovery message. Callers that must not reveal this (forgot
	// password) swallow it.
	ErrNoRecoveryChannel = NewError("auth.no_recovery_channel", http.StatusConflict, "This account has no verified way to receive a message.")

	// ErrRateLimited: a rate rule refused the call.
	ErrRateLimited = NewError("auth.rate_limited", http.StatusTooManyRequests, "Too many attempts. Wait a moment and try again.")

	// ErrChallengeRequired: a RateChallenge rule is over its limit and the
	// call carried no proof. The client solves the challenge (a captcha:
	// plugin/captcha's token header) and sends the call again with it. 428
	// Precondition Required, because waiting does not help and a proof does.
	ErrChallengeRequired = NewError("auth.challenge_required", http.StatusPreconditionRequired, "Complete the challenge and try again.")
)
