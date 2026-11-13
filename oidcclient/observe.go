package oidcclient

import (
	"context"
	"time"
)

// EventKind names what happened.
type EventKind string

const (
	// EventLogin: a callback completed and a session was written.
	EventLogin EventKind = "login"
	// EventRefresh: a re-check said yes (tokens rotated or not).
	EventRefresh EventKind = "refresh"
	// EventGrace: the login server could not be reached and the last "yes"
	// was used, within the outage grace. A run of these is an outage.
	EventGrace EventKind = "grace"
	// EventRefuse: a request or a callback was refused; Reason says why.
	EventRefuse EventKind = "refuse"
	// EventLogout: the person signed out through the logout route.
	EventLogout EventKind = "logout"
	// EventBackchannelLogout: a logout token ended Count sessions.
	EventBackchannelLogout EventKind = "backchannel_logout"
	// EventRevokeFailed: sign-out could not revoke the session's refresh
	// token at the login server (Err says why: an error, or a server that
	// publishes no revocation endpoint). It comes just before the
	// EventLogout of the same sign-out, which still happened; a copy of
	// the cookie saved before it can keep refreshing until the server
	// refuses that token, so a run of these deserves an alert. A kind of
	// its own (rather than Err on EventLogout) lets an observer alert on
	// it without inspecting every logout, and matches the TypeScript
	// client's "revoke_failed".
	EventRevokeFailed EventKind = "revoke_failed"
)

// EventKindValues is every EventKind.
var EventKindValues = []EventKind{EventLogin, EventRefresh, EventGrace, EventRefuse, EventLogout, EventBackchannelLogout, EventRevokeFailed}

// Event is one thing an Observer is told. Fields that do not apply to the
// Kind are zero.
type Event struct {
	Kind EventKind
	At   time.Time
	// SessionID and Subject identify the session, when there is one.
	SessionID string
	Subject   string
	// Reason is set for EventRefuse.
	Reason Reason
	// Count is the sessions a back-channel logout ended.
	Count int
	// Err is the cause of a refusal, a grace or a failed revocation
	// (EventRevokeFailed), for the log.
	Err error
}

// Observer is told about logins, re-checks, refusals and logouts: the seam
// for metrics, audit logs and alerts. It cannot change a decision; it is
// called after the decision, synchronously, so it must return quickly and
// hand slow work to its own goroutine.
type Observer interface {
	Observe(ctx context.Context, e Event)
}

// ObserverFunc adapts a function to Observer.
type ObserverFunc func(ctx context.Context, e Event)

// Observe calls f.
func (f ObserverFunc) Observe(ctx context.Context, e Event) { f(ctx, e) }
