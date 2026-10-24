package auth

import (
	"sync"
	"time"
)

// EffectKind names what an operation asks the transport to do after it
// succeeds.
type EffectKind string

// The effects an operation can record.
//
// Why effects exist at all: an operation such as sign-in must end with a
// cookie, but an operation that writes an HTTP header could not run from a
// CLI, a job or a GraphQL resolver that has no response writer. So the
// operation records what it wants, and each transport decides what that means
// for its protocol — a Set-Cookie header, a token field, a returned URL.
const (
	EffectIssueSession EffectKind = "issue_session"
	EffectClearSession EffectKind = "clear_session"
	EffectRedirect     EffectKind = "redirect"
	// EffectBindFlow ties a multi-step flow, such as an OAuth sign-in, to
	// this client, so a flow started by one browser cannot be finished in
	// another. That is the defence against login CSRF, where an attacker gets
	// a victim signed in to the attacker's account.
	EffectBindFlow EffectKind = "bind_flow"
	// EffectCacheSession hands the client a value to send back as
	// Request.CachedSession, so its next requests skip the session lookup
	// (the snapshot SessionCache). EffectClearCache removes it: the session
	// ended on this device, and a copy that kept answering for it would
	// undo the sign-out for as long as it lived.
	EffectCacheSession EffectKind = "cache_session"
	EffectClearCache   EffectKind = "clear_cache"
	// EffectForgetDeviceSession asks the transport to drop one token from
	// the device's set of signed-in accounts (WithMultiSession): the
	// account was signed out on this device, or its token stopped opening.
	// An issue-session effect for a token the device already holds is the
	// opposite: that account becomes the active one.
	EffectForgetDeviceSession EffectKind = "forget_device_session"
	// EffectRememberDevice hands the client a device token to send back as
	// Request.Device until ExpiresAt, for a second-factor plugin's
	// "remember this browser"; an empty Token forgets it.
	EffectRememberDevice EffectKind = "remember_device"
	// EffectHeader hands the client a value in a response header of the
	// plugin's choosing, such as the jwt plugin's Set-Auth-JWT on the session
	// read. A plugin owns its header name; the transport also lists it in
	// Access-Control-Expose-Headers, because a header a cross-origin script
	// cannot read is a header that was never sent as far as it can tell.
	EffectHeader EffectKind = "header"
	// EffectCookie hands the client a plugin cookie (Effects.SetCookie):
	// the transport names it beside its own cookies and gives it their
	// fixed attributes; the plugin chooses only the name, the value and
	// the expiry.
	EffectCookie EffectKind = "cookie"
)

// EffectKindValues is the canonical iteration order over effect kinds, so a
// transport can check at test time that it handles every one of them.
var EffectKindValues = []EffectKind{EffectIssueSession, EffectClearSession, EffectRedirect, EffectBindFlow, EffectCacheSession, EffectClearCache, EffectForgetDeviceSession, EffectRememberDevice, EffectHeader, EffectCookie}

// Effect is one recorded effect.
//
// Which fields are set depends on Kind, and each transport must read only the
// fields of the kind it is handling:
//
//   - EffectIssueSession: Token (the raw session token), ExpiresAt,
//     Transient (the cookie must have no expiry, so it ends with the browser)
//     and Replaces (the token replaces the request's own, for the same
//     sign-in, rather than signing in another account).
//   - EffectClearSession: no fields.
//   - EffectRedirect: URL.
//   - EffectBindFlow: Token and ExpiresAt; an empty Token removes the binding.
//   - EffectCacheSession: Value (opaque, not a secret on its own but tied to
//     the session token) and ExpiresAt, when the value stops being used.
//   - EffectClearCache: no fields.
//   - EffectForgetDeviceSession: Token (the one to drop from the device's
//     set).
//   - EffectRememberDevice: Token and ExpiresAt; an empty Token removes the
//     device token.
//   - EffectHeader: Name (the header) and Value.
//   - EffectCookie: Name (the plugin cookie, CheckCookieName), Value and
//     ExpiresAt; a zero ExpiresAt deletes the cookie.
//
//ds:def id=core-effect-t9y8u9f5 owner=@khanakia stability=stable
type Effect struct {
	Kind      EffectKind
	Token     Token
	ExpiresAt time.Time
	URL       string
	Transient bool
	Value     string
	// UserID and SessionID name the session an EffectIssueSession is for,
	// set by IssueSessionOf; IssueSession leaves them empty. Transports do
	// not need them; an audit hook reading RequestEffects does, since a
	// public sign-in's Call has no User.
	UserID    string
	SessionID string
	// Name is the response header an EffectHeader sets, or the plugin
	// cookie an EffectCookie sets.
	Name string
	// Replaces is set on an EffectIssueSession whose token takes the place
	// of the one the request presented, for the same sign-in: a refresh
	// that changed the token (WithTokenRotation, a resealed stateless
	// token), a second-factor promotion, a completed session task. A
	// multi-session transport then drops the old token instead of keeping
	// it as another account on the device, where it would come back as a
	// replaced token and, under WithTokenRotation, revoke the session.
	Replaces bool
}

// Effects collects the effects of one call, or of one request.
//
// It is safe for concurrent use, because a GraphQL request resolves several
// fields at once and each field's operation adds to the same request's set.
type Effects struct {
	mu   sync.Mutex
	list []Effect
}

// IssueSession asks the transport to hand a new session token to the client.
func (e *Effects) IssueSession(t Token, expiresAt time.Time) {
	e.add(Effect{Kind: EffectIssueSession, Token: t, ExpiresAt: expiresAt})
}

// IssueSessionOf hands a session's token to the client with the session's own
// expiry and "remember me" choice. Prefer it to IssueSession, which always
// asks for a persistent cookie.
func (e *Effects) IssueSessionOf(s Session, t Token) {
	e.add(Effect{Kind: EffectIssueSession, Token: t, ExpiresAt: s.ExpiresAt, Transient: s.Transient, UserID: s.UserID, SessionID: s.ID})
}

// ReplaceSessionOf is IssueSessionOf for a token that replaces the
// request's own for the same sign-in; see Effect.Replaces.
func (e *Effects) ReplaceSessionOf(s Session, t Token) {
	e.add(Effect{Kind: EffectIssueSession, Token: t, ExpiresAt: s.ExpiresAt, Transient: s.Transient, UserID: s.UserID, SessionID: s.ID, Replaces: true})
}

// ClearSession asks the transport to remove the client's session token.
func (e *Effects) ClearSession() { e.add(Effect{Kind: EffectClearSession}) }

// Redirect asks the transport to send the client to url. HTTP transports
// answer with a 302; others return the URL.
func (e *Effects) Redirect(url string) { e.add(Effect{Kind: EffectRedirect, URL: url}) }

// BindFlow asks the transport to remember t for this client until expiresAt,
// and to present it as Request.Flow on later requests. An empty t forgets it.
func (e *Effects) BindFlow(t Token, expiresAt time.Time) {
	e.add(Effect{Kind: EffectBindFlow, Token: t, ExpiresAt: expiresAt})
}

// CacheSession hands the client v to send back as Request.CachedSession
// until expiresAt.
func (e *Effects) CacheSession(v string, expiresAt time.Time) {
	e.add(Effect{Kind: EffectCacheSession, Value: v, ExpiresAt: expiresAt})
}

// ClearCache asks the transport to forget the client's cached session value.
func (e *Effects) ClearCache() { e.add(Effect{Kind: EffectClearCache}) }

// RememberDevice asks the transport to keep t as the client's device token
// until expiresAt and present it as Request.Device on later requests; an
// empty t forgets it. See EffectRememberDevice.
func (e *Effects) RememberDevice(t Token, expiresAt time.Time) {
	e.add(Effect{Kind: EffectRememberDevice, Token: t, ExpiresAt: expiresAt})
}

// Header asks the transport to send value in the response header name and
// to let a cross-origin script read it; see EffectHeader. A transport with no
// headers (a CLI, a job) ignores it, and a Go caller reads it from
// RequestEffects.
func (e *Effects) Header(name, value string) {
	e.add(Effect{Kind: EffectHeader, Name: name, Value: value})
}

// ForgetDeviceSession asks the transport to drop t from the device's set of
// signed-in accounts; see EffectForgetDeviceSession.
func (e *Effects) ForgetDeviceSession(t Token) {
	e.add(Effect{Kind: EffectForgetDeviceSession, Token: t})
}

// List returns a copy of the effects in the order they were recorded.
func (e *Effects) List() []Effect {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Effect, len(e.list))
	copy(out, e.list)
	return out
}

func (e *Effects) add(ef Effect) {
	e.mu.Lock()
	e.list = append(e.list, ef)
	e.mu.Unlock()
}

// merge moves the effects of a finished call into the request's set. The
// pipeline calls it only when the call succeeded, which is how a failed
// operation ends up applying no effect at all.
func (e *Effects) merge(from *Effects) {
	for _, ef := range from.List() {
		e.add(ef)
	}
}
