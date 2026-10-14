package auth

import (
	"context"
	"time"
)

// SessionLifetime is how long one session lives: Idle slides with use,
// Max is the hard stop from creation, and RefreshAfter bounds how often the
// sliding expiry is written. A zero or negative field means the SessionConfig
// default for that field.
//
//ds:def id=core-sessionlifetime-dd9t2x6a owner=@khanakia stability=stable
type SessionLifetime struct {
	Idle         time.Duration
	Max          time.Duration
	RefreshAfter time.Duration
}

// MaxSessionLifetime caps SessionLifetime.Max. A session that could live
// longer than about a year is a credential that never expires, whatever the
// policy meant; 400 days is the ceiling browsers apply to cookies too.
//
//ds:def id=maxsessionlifetime-pmz4mcbj owner=@khanakia stability=stable
const MaxSessionLifetime = 400 * 24 * time.Hour

// SessionPolicyInput is what a session policy sees when a session is created.
//
//ds:def id=core-sessionpolicyinput-tp7tav9x owner=@khanakia stability=stable
type SessionPolicyInput struct {
	UserID string
	// Credential is how the client presents its token: CredentialCookie for
	// a browser, CredentialBearer for an app, CredentialNone for a Go call
	// with no request in ctx. A request that asked for bearer delivery
	// (Request.Delivery) reports CredentialBearer here too: at sign-in the
	// app has no token yet, and it is the app's lifetime it needs.
	Credential Credential
	Client     Client
	// Transient is "remember me" unticked.
	Transient bool
}

// SessionPolicy chooses a session's lifetime at creation, per client. The
// choice is stored with the session, so every later refresh honours it.
//
//ds:def id=core-sessionpolicy-wghqdf3p owner=@khanakia stability=stable
type SessionPolicy func(ctx context.Context, in SessionPolicyInput) SessionLifetime

// WithSessionPolicy sets the per-client lifetime policy. Without one every
// session gets SessionConfig. Pending second-factor sessions and impersonation
// sessions keep their fixed lifetimes whatever the policy says.
//
//ds:def id=opt-withsessionpolicy-kpmqcqvd owner=@khanakia stability=stable
func WithSessionPolicy(p SessionPolicy) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithSessionPolicy", p) {
			return
		}
		s.policy = p
	}
}

// ByCredential is the common policy: one lifetime for browsers (cookie) and
// one for apps (bearer), such as thirty days and a year. A Go call with no
// request gets the cookie lifetime, the shorter of the two in practice.
//
//ds:def id=core-bycredential-f4r97d2a owner=@khanakia stability=stable
func ByCredential(cookie, bearer SessionLifetime) SessionPolicy {
	return func(_ context.Context, in SessionPolicyInput) SessionLifetime {
		if in.Credential == CredentialBearer {
			return bearer
		}
		return cookie
	}
}

// lifetimeFor resolves the lifetime of a new session: the policy's answer,
// with each zero or negative field replaced by the configured default and Max
// capped at MaxSessionLifetime.
func (a *Auth) lifetimeFor(ctx context.Context, userID string, client Client, transient bool) SessionLifetime {
	var lt SessionLifetime
	if a.policy != nil {
		in := SessionPolicyInput{UserID: userID, Credential: CredentialNone, Client: client, Transient: transient}
		if st := stateFrom(ctx); st != nil {
			in.Credential = st.req.Credential
			if st.req.Delivery == DeliveryBearer {
				in.Credential = CredentialBearer
			}
		}
		lt = a.policy(ctx, in)
	}
	return a.cfg.Session.fill(lt, transient)
}

// fill replaces every zero or negative field of lt with c's default for it,
// and caps Max at MaxSessionLifetime.
func (c SessionConfig) fill(lt SessionLifetime, transient bool) SessionLifetime {
	if lt.Idle <= 0 {
		lt.Idle = c.IdleTimeout
		if transient {
			lt.Idle = c.TransientIdleTimeout
			if lt.Idle <= 0 {
				lt.Idle = DefaultTransientIdleTimeout
			}
		}
	}
	if lt.Max <= 0 {
		lt.Max = c.MaxLifetime
	}
	if lt.Max > MaxSessionLifetime {
		lt.Max = MaxSessionLifetime
	}
	if lt.RefreshAfter <= 0 {
		lt.RefreshAfter = c.RefreshAfter
	}
	return lt
}

// Lifetime returns the lifetime the session was created with, falling back
// to c for a session from before lifetimes were stored (zero columns).
func (s Session) Lifetime(c SessionConfig) SessionLifetime {
	lt := SessionLifetime{
		Idle:         time.Duration(s.IdleSeconds) * time.Second,
		RefreshAfter: time.Duration(s.RefreshSeconds) * time.Second,
	}
	if s.MaxExpiresAt != nil {
		lt.Max = s.MaxExpiresAt.Sub(s.CreatedAt)
	}
	return c.fill(lt, s.Transient)
}

// expiryAt is the expiry the session gets when it is seen at now: its idle
// timeout from now, never past its hard stop.
func (s Session) expiryAt(c SessionConfig, now time.Time) time.Time {
	lt := s.Lifetime(c)
	exp := now.Add(lt.Idle)
	if limit := s.CreatedAt.Add(lt.Max); exp.After(limit) {
		return limit
	}
	return exp
}
