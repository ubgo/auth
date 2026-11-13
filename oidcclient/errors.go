package oidcclient

import "errors"

// Errors a caller may branch on with errors.Is. Every other failure is
// wrapped with its cause for the log and answered as a refusal: the package
// never turns an unexpected error into a "yes".
var (
	// ErrInvalidConfig is returned by New for a Config or an option that
	// cannot be used safely: a missing field, an http issuer or app URL on a
	// non-loopback host, conflicting options, a cookie name the browser
	// would reject. The wrapped text names the field.
	ErrInvalidConfig = errors.New("oidcclient: invalid configuration")

	// ErrNilOption is recorded by an option given a nil func, interface or
	// pointer, so New fails at start-up naming the option instead of the
	// first request panicking on it.
	ErrNilOption = errors.New("oidcclient: nil option value")

	// ErrNoSession is what a SessionStore's Load answers for a cookie value
	// that names no live session (deleted, expired, revoked by back-channel
	// logout). The middleware treats it as "not signed in", never as a
	// failure.
	ErrNoSession = errors.New("oidcclient: no session")

	// ErrAccessDenied is the refusal a UserMapper or an Authorizer returns
	// (or wraps) to say "this person may not use the app". It is answered
	// with the no-access response. Any other error refuses too, but is
	// answered and logged as a failure, so an outage of the app's own user
	// database is not shown to the person as a permanent "no".
	ErrAccessDenied = errors.New("oidcclient: access denied")

	// ErrProviderUnavailable marks a failure to get any answer from the login
	// server: a network error, a timeout, a 5xx, an unreadable body. Only an
	// error wrapping it starts the outage grace (WithOutageGrace); a
	// Rechecker that fails for another reason refuses at once. A custom
	// Rechecker wraps it when, and only when, the server could not be asked.
	ErrProviderUnavailable = errors.New("oidcclient: login server unavailable")

	// ErrProviderRefused is the login server answering "no": invalid_grant
	// on a refresh, 401 from userinfo, a token endpoint that refuses the
	// client. It ends the session; it never starts the outage grace.
	ErrProviderRefused = errors.New("oidcclient: login server refused")

	// ErrBackchannelUnsupported is answered by the back-channel logout route
	// when the SessionStore cannot find sessions by subject or provider
	// session (it does not implement SessionRevoker), so the login server's
	// log shows why its logout token did nothing. The default cookie store
	// is one such store; NewMemoryStore is not.
	ErrBackchannelUnsupported = errors.New("oidcclient: session store cannot revoke by subject or sid")

	// ErrSessionTooLarge is a session whose sealed form does not fit the
	// cookie store's limit (a few cookies of 4 KB each). Sign-in is refused
	// rather than writing a cookie the browser would drop silently; a
	// UserMapper that keeps fewer Claims, or a server-side store, fixes it.
	ErrSessionTooLarge = errors.New("oidcclient: session too large for the cookie store")

	// ErrSealedCorrupt is what a Sealer's Open answers (or wraps) for a value
	// that does not open: tampered, sealed under another cookie name, or
	// sealed with a key no longer in the ring. It reads as "no session".
	ErrSealedCorrupt = errors.New("oidcclient: sealed value does not open")
)
