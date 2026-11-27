package oidcclient

import (
	"context"
	"net/http"
)

// SessionStart is what a SessionStartHook decides from: the session about to
// be saved (its ID is final, so the app can key its own rows by it), the
// verified Identity it came from, and the callback request (for the client
// address or user agent of an audit row).
type SessionStart struct {
	Session  Session
	Identity Identity
	Request  *http.Request
}

// SessionStartHook runs at every sign-in, after the UserMapper and before
// the session is saved: the seam to record a session in the app's own
// database, cap concurrent sessions, or refuse a sign-in on a rule the
// UserMapper cannot see (it does not know the session). An error refuses the
// sign-in and no session is written: ErrAccessDenied answers "no access",
// any other error "failed".
type SessionStartHook func(ctx context.Context, in SessionStart) error

// EndReason is why this package ended a session, for a SessionEndHook.
type EndReason string

const (
	// EndLogout: the person signed out through the logout route.
	EndLogout EndReason = "logout"
	// EndIdleExpired: a request came after LastSeenAt + Idle.
	EndIdleExpired EndReason = "idle_expired"
	// EndAbsoluteExpired: a request came after CreatedAt + Absolute.
	EndAbsoluteExpired EndReason = "absolute_expired"
	// EndRecheckRefused: a re-check did not keep the session: the login
	// server said no, a hook refused, or the session could not be saved
	// after its tokens rotated. SessionEnd.Err says which.
	EndRecheckRefused EndReason = "recheck_refused"
	// EndReplaced: a new sign-in in the same browser replaced it.
	EndReplaced EndReason = "replaced"
	// EndBackchannel: a back-channel logout token ended the sessions of
	// SessionEnd.Target (SessionEnd.Count of them).
	EndBackchannel EndReason = "backchannel_logout"
)

// EndReasonValues is every EndReason.
var EndReasonValues = []EndReason{EndLogout, EndIdleExpired, EndAbsoluteExpired, EndRecheckRefused, EndReplaced, EndBackchannel}

// SessionEnd is one session (or, for a back-channel logout, one set of
// sessions) this package ended.
type SessionEnd struct {
	Reason EndReason
	// Session is the session that ended; nil for EndBackchannel, where the
	// store ends the matching rows itself and the package never sees them.
	Session *Session
	// Target and Count are set for EndBackchannel: whom the logout token
	// named and how many sessions the store ended.
	Target *LogoutTarget
	Count  int
	// Err is the cause for EndRecheckRefused, for the log.
	Err error
	// Request is the request that ended it (for a re-check, the first of the
	// requests that shared it).
	Request *http.Request
}

// SessionEndHook is told whenever this package ends a session: the seam to
// delete the app's own per-session rows, caches or downstream tokens. The
// session is already ended when it runs, so it cannot keep it; it runs in
// the request path, so slow work belongs on the app's own goroutine. A
// session a server-side store expires by its own TTL, without a request, is
// not reported.
type SessionEndHook func(ctx context.Context, in SessionEnd)

// RefreshFailure is one re-check that did not keep the session.
type RefreshFailure struct {
	Session Session
	// Err is why: the login server's "no", a hook's error, a store failure,
	// or (Outage true) the server not answering.
	Err error
	// Outage is true when the login server could not be reached: the
	// session is kept and the outage grace applies. False means the session
	// ends (a SessionEndHook then hears EndRecheckRefused).
	Outage bool
}

// RefreshFailedHook is told once per re-check that did not keep the session
// (re-checks are single-flight, so concurrent requests produce one call). It
// cannot change the outcome: the re-check is the authority. It is the seam
// to alert on a run of outages or to clean up after a removal.
type RefreshFailedHook func(ctx context.Context, in RefreshFailure)

// LogoutMode is how far a sign-out reaches.
type LogoutMode string

const (
	// LogoutAtServer ends the app's session and sends the browser to the
	// login server's end-session endpoint (RP-Initiated Logout), so the
	// person is signed out there too; straight to the post-logout path when
	// the server publishes none. The default.
	LogoutAtServer LogoutMode = "server"
	// LogoutAppOnly ends the app's session only and lands on the post-logout
	// path; the login server's own session stays, so the next sign-in may
	// not ask for a password.
	LogoutAppOnly LogoutMode = "app"
)

// LogoutModeValues is every LogoutMode.
var LogoutModeValues = []LogoutMode{LogoutAtServer, LogoutAppOnly}

// LogoutRequest is what a LogoutPolicy decides from: the sign-out request
// (a form field such as "everywhere=1" is the app's to read) and the session
// it ends, nil when the request carried none.
type LogoutRequest struct {
	Request *http.Request
	Session *Session
}

// LogoutPolicy picks how far one sign-out reaches. Whatever it returns, the
// app's session ends and its refresh token is revoked; a value that is not a
// LogoutMode is read as LogoutAtServer, the more complete sign-out.
type LogoutPolicy func(in LogoutRequest) LogoutMode

// LogoutAlways is the LogoutPolicy that answers mode for every sign-out.
// The default is LogoutAlways(LogoutAtServer).
func LogoutAlways(mode LogoutMode) LogoutPolicy {
	return func(LogoutRequest) LogoutMode { return mode }
}

// endSession tells the SessionEndHook, when there is one.
func (c *Client) endSession(ctx context.Context, e SessionEnd) {
	if c.set.onEnd != nil {
		c.set.onEnd(ctx, e)
	}
}

// refreshFailed tells the RefreshFailedHook, when there is one.
func (c *Client) refreshFailed(ctx context.Context, f RefreshFailure) {
	if c.set.onRefreshFailed != nil {
		c.set.onRefreshFailed(ctx, f)
	}
}
