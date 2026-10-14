package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Multi-session: several accounts signed in on one device, one of them
// active. The core knows the device's other tokens from the request
// (Request.DeviceTokens), lists and switches between them, and asks the
// transport to add or forget one through effects; the transport owns how the
// set is held (authhttp: one cookie per token).

// DefaultMaxDeviceSessions caps the accounts one device may hold at once
// when WithMultiSession is on. Five is what a person switching between a
// work and a personal account and a couple of shared ones needs; every extra
// token is one more cookie on every request.
//
//ds:def id=defaultmaxdevicesessions-7qk2nw4e owner=@khanakia stability=stable
const DefaultMaxDeviceSessions = 5

// MultiSessionConfig is the WithMultiSession setting as Config reports it.
//
//ds:def id=core-multisessionconfig-3fx8vp2m owner=@khanakia stability=stable
type MultiSessionConfig struct {
	// Enabled is true when WithMultiSession was given.
	Enabled bool
	// Max is the most sessions one device may hold, the active one included.
	Max int
}

// WithMultiSession lets one device hold several signed-in accounts and
// switch between them, as a browser does between a work and a personal
// account. max is the most sessions a device may hold, the active one
// included; 0 means DefaultMaxDeviceSessions, less than 0 is refused by New.
// A sign-in that would exceed it is refused with ErrTooManyDeviceSessions
// and creates nothing, so the user signs one account out first.
//
// It adds three operations, GET /device-sessions, POST
// /device-sessions/switch and POST /device-sessions/revoke, and changes
// sign-out: with several accounts on the device, POST /sign-out ends every
// one of them, because "sign out" on a shared computer must leave nothing
// behind; one account is ended with /device-sessions/revoke. Without the
// option nothing changes.
//
//ds:def id=opt-withmultisession-9wn4rt6k owner=@khanakia stability=stable
func WithMultiSession(max int) Option {
	return func(s *settings) { s.cfg.MultiSession = MultiSessionConfig{Enabled: true, Max: max} }
}

// ErrTooManyDeviceSessions refuses a sign-in on a device that already holds
// MultiSessionConfig.Max accounts.
var ErrTooManyDeviceSessions = NewError("auth.too_many_device_sessions", http.StatusConflict, "Too many accounts are signed in on this device. Sign one out first.")

// ErrDeviceSessionNotFound refuses a switch or a revoke naming a session the
// device does not hold. One answer whether the id is unknown, expired or
// another device's, so nothing is learnt from the difference.
var ErrDeviceSessionNotFound = NewError("auth.device_session_not_found", http.StatusNotFound, "That account is not signed in on this device.")

// Multi-session operation ids.
const (
	EndpointDeviceSessions      EndpointID = "core.device-sessions"
	EndpointSwitchDeviceSession EndpointID = "core.device-sessions-switch"
	EndpointRevokeDeviceSession EndpointID = "core.device-sessions-revoke"
	deviceSessionsPath                     = "/device-sessions"
	switchDeviceSessionPath                = deviceSessionsPath + "/switch"
	revokeDeviceSessionPath                = deviceSessionsPath + "/revoke"
)

// DeviceSessionView is one account signed in on the device.
type DeviceSessionView struct {
	// ID is the session id, what switch and revoke take.
	ID   string   `json:"id"`
	User UserView `json:"user"`
	// Active is true for the session the device is using now.
	Active    bool      `json:"active"`
	ExpiresAt time.Time `json:"expiresAt"`
	// Extras is what the WithSessionExtras function computed for this
	// session, under WithDeviceSessionExtras; absent otherwise. It is any
	// because SessionExtras returns the app's own JSON-encodable shape, which
	// the library never reads, only encodes.
	Extras any `json:"extras,omitempty"`
}

// DeviceSessionsResult is the output of core.device-sessions: the active
// session first, then the others in the order the device holds them.
type DeviceSessionsResult struct {
	Sessions []DeviceSessionView `json:"sessions"`
}

// DeviceSessionRequest names a session the device holds, for switch and
// revoke.
type DeviceSessionRequest struct {
	ID string `json:"id"`
}

// resolveMultiSession settles the setting at New.
func (a *Auth) resolveMultiSession() error {
	ms := &a.cfg.MultiSession
	if !ms.Enabled {
		return nil
	}
	if ms.Max < 0 {
		return fmt.Errorf("%w: auth.WithMultiSession: multi-session maximum %d is negative", ErrBadOperation, ms.Max)
	}
	if ms.Max == 0 {
		ms.Max = DefaultMaxDeviceSessions
	}
	return nil
}

// deviceSession is one of the device's tokens, resolved.
type deviceSession struct {
	token Token
	s     Session
	u     User
}

// deviceSessions resolves the request's other tokens, dropping the active
// one when the device sent it twice. A token that no longer opens — ended
// on another device, expired, or a pending second factor nobody finished —
// is reported to the transport with a forget effect, so the device stops
// sending it. A store failure is returned: it must be a 500, not a device
// quietly losing an account.
func (a *Auth) deviceSessions(ctx context.Context, c *Call) ([]deviceSession, error) {
	st := stateFrom(ctx)
	// Without the option the device's other tokens mean nothing, whatever a
	// transport helper read from the cookies: the core is the guard that
	// cannot be bypassed.
	if st == nil || !a.cfg.MultiSession.Enabled {
		return nil, nil
	}
	var out []deviceSession
	seen := map[Token]bool{st.req.Token: true}
	for _, tok := range st.req.DeviceTokens {
		if tok == "" || seen[tok] {
			continue
		}
		seen[tok] = true
		s, u, _, err := a.resolveSession(ctx, tok)
		switch {
		case err == nil && !s.SecondFactorPending:
			out = append(out, deviceSession{token: tok, s: *s, u: *u})
		case err == nil || errors.Is(err, ErrSignedOut):
			c.Effects.ForgetDeviceSession(tok)
		default:
			return nil, err
		}
	}
	return out, nil
}

// checkDeviceCap refuses a call that issued a new session on a device that
// already holds the maximum. It runs inside the call's transaction, after the
// operation, so the refused session is rolled back with it. The count is
// what the device sent plus the active session plus the new one; a switch
// reissues a token the device already holds, which is not a new session and
// is left alone by excluding tokens the device sent.
func (a *Auth) checkDeviceCap(c *Call) error {
	if !a.cfg.MultiSession.Enabled {
		return nil
	}
	st := stateFrom(c.ctx)
	if st == nil {
		return nil
	}
	held := map[Token]bool{}
	if st.req.Token != "" {
		held[st.req.Token] = true
	}
	for _, tok := range st.req.DeviceTokens {
		if tok != "" {
			held[tok] = true
		}
	}
	fresh := 0
	for _, ef := range c.Effects.List() {
		// A replacement (a promotion, a completed session task) takes the
		// place of a token the device holds: not a new account.
		if ef.Kind == EffectIssueSession && !ef.Replaces && !held[ef.Token] {
			fresh++
		}
	}
	if fresh > 0 && len(held)+fresh > a.cfg.MultiSession.Max {
		return ErrTooManyDeviceSessions
	}
	return nil
}

// WithDeviceSessionExtras runs the WithSessionExtras function for every
// session of the device list too (GET /device-sessions,
// Auth.DeviceSessions), as better-auth's shouldMutateListDeviceSessionsEndpoint
// does, so an account switcher shows each account's plan or avatar without a
// request per account. For each listed session the function gets a copy of
// the call whose Session and User are that session's, and whose Effects are
// discarded: listing must not issue a cookie or a redirect on another
// account's behalf. One call per listed session, at most
// MultiSessionConfig.Max. New refuses it without WithMultiSession and
// WithSessionExtras.
//
//ds:def id=opt-withdevicesessionextras-3vb7nq5k owner=@khanakia stability=stable
func WithDeviceSessionExtras() Option { return func(s *settings) { s.deviceExtras = true } }

// listDeviceSessions is the body of core.device-sessions.
func (a *Auth) listDeviceSessions(ctx context.Context, c *Call) (DeviceSessionsResult, error) {
	others, err := a.deviceSessions(ctx, c)
	if err != nil {
		return DeviceSessionsResult{}, err
	}
	active := DeviceSessionView{ID: c.Session.ID, User: ViewOf(*c.User), Active: true, ExpiresAt: c.Session.ExpiresAt}
	if active.Extras, err = a.deviceExtrasFor(ctx, c, *c.Session, *c.User); err != nil {
		return DeviceSessionsResult{}, err
	}
	out := DeviceSessionsResult{Sessions: []DeviceSessionView{active}}
	for _, d := range others {
		v := DeviceSessionView{ID: d.s.ID, User: ViewOf(d.u), ExpiresAt: d.s.ExpiresAt}
		if v.Extras, err = a.deviceExtrasFor(ctx, c, d.s, d.u); err != nil {
			return DeviceSessionsResult{}, err
		}
		out.Sessions = append(out.Sessions, v)
	}
	return out, nil
}

// deviceExtrasFor runs the session extras for one listed session, under
// WithDeviceSessionExtras, on a copy of the call carrying that session and a
// throwaway Effects; nil without the option.
func (a *Auth) deviceExtrasFor(ctx context.Context, c *Call, s Session, u User) (any, error) {
	if !a.deviceExtras {
		return nil, nil
	}
	cc := *c
	cc.Session, cc.User, cc.Effects = &s, &u, &Effects{}
	return a.sessionExtras(ctx, &cc)
}

// switchDeviceSession is the body of core.device-sessions-switch: the named
// session's token is issued again, which makes it the device's active one;
// the transport keeps the previous active token in the device's set. The
// active session is accepted too and changes nothing.
func (a *Auth) switchDeviceSession(ctx context.Context, c *Call, in DeviceSessionRequest) (Done, error) {
	if in.ID == c.Session.ID {
		return Done{OK: true}, nil
	}
	others, err := a.deviceSessions(ctx, c)
	if err != nil {
		return Done{}, err
	}
	for _, d := range others {
		if d.s.ID == in.ID {
			c.Effects.IssueSessionOf(d.s, d.token)
			return Done{OK: true}, nil
		}
	}
	return Done{}, ErrDeviceSessionNotFound
}

// revokeDeviceSession is the body of core.device-sessions-revoke: it ends one
// of the device's other sessions and asks the transport to forget its token.
// The active session is ended with sign-out, not here, because ending it
// leaves the device with no active account and the transport must pick one.
func (a *Auth) revokeDeviceSession(ctx context.Context, c *Call, in DeviceSessionRequest) (Done, error) {
	others, err := a.deviceSessions(ctx, c)
	if err != nil {
		return Done{}, err
	}
	for _, d := range others {
		if d.s.ID != in.ID {
			continue
		}
		if err := a.endDeviceSession(ctx, d); err != nil {
			return Done{}, err
		}
		c.Effects.ForgetDeviceSession(d.token)
		return Done{OK: true}, nil
	}
	return Done{}, ErrDeviceSessionNotFound
}

// endDeviceSession deletes one of the device's other sessions and drops it
// from the cache. In stateless mode there is no row and no cache entry to
// end: the forget effect ends it on this device, and under
// WithSessionRevocations its id goes on the list so it ends everywhere.
func (a *Auth) endDeviceSession(ctx context.Context, d deviceSession) error {
	if a.stateless != nil {
		return a.revokeStateless(ctx, d.s)
	}
	if err := a.EndSession(ctx, d.s.UserID, d.s.ID, SessionEndRevoked); err != nil {
		return err
	}
	if a.cache != nil {
		if err := a.cache.Drop(ctx, CacheKey{TokenHash: HashToken(d.token)}); err != nil {
			return fmt.Errorf("auth: session cache: %w", err)
		}
	}
	return nil
}

// signOutDevice ends every other account on the device, for sign-out under
// WithMultiSession; the caller ends the active session itself.
func (a *Auth) signOutDevice(ctx context.Context, c *Call) error {
	if !a.cfg.MultiSession.Enabled {
		return nil
	}
	others, err := a.deviceSessions(ctx, c)
	if err != nil {
		return err
	}
	for _, d := range others {
		if err := a.endDeviceSession(ctx, d); err != nil {
			return err
		}
		c.Effects.ForgetDeviceSession(d.token)
	}
	return nil
}

// DeviceSessions lists the accounts signed in on the device of the request
// in ctx, through the same operation GET /device-sessions runs.
func (a *Auth) DeviceSessions(ctx context.Context) (DeviceSessionsResult, error) {
	return a.core.deviceSessions.Call(ctx, struct{}{})
}

// SwitchDeviceSession makes session id the device's active account.
func (a *Auth) SwitchDeviceSession(ctx context.Context, id string) error {
	_, err := a.core.switchDevice.Call(ctx, DeviceSessionRequest{ID: id})
	return err
}

// RevokeDeviceSession ends one of the device's other accounts.
func (a *Auth) RevokeDeviceSession(ctx context.Context, id string) error {
	_, err := a.core.revokeDevice.Call(ctx, DeviceSessionRequest{ID: id})
	return err
}
