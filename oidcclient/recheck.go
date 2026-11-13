package oidcclient

import (
	"context"
	"time"
)

// RecheckRequest is one re-check of a session whose last "yes" is older
// than the recheck interval.
type RecheckRequest struct {
	Session  Session
	Provider *Provider
}

// RecheckResult is a Rechecker's answer. Its zero value is Deny.
type RecheckResult struct {
	// Decision is Allow when the login server still accepts the session.
	Decision Decision
	// Refreshed carries new tokens (and a new Identity, which the UserMapper
	// sees as MapRefresh) when the check rotated them; nil otherwise. Only
	// Provider.Refresh makes one.
	Refreshed *Refreshed
}

// Rechecker asks the login server whether a session still stands. The
// package calls it at most once per recheck interval per session, and at
// most once at a time per session in this process: concurrent requests of
// one session wait for the same call (single-flight), so two tabs never
// spend one refresh token twice from here.
//
// It fails closed: only (Allow, nil) keeps the session. Deny ends it and
// the person signs in again (the login server then decides). An error
// wrapping ErrProviderUnavailable keeps the last "yes" for the outage
// grace; any other error ends the session as Deny does.
type Rechecker interface {
	Recheck(ctx context.Context, in RecheckRequest) (RecheckResult, error)
}

// RecheckerFunc adapts a function to Rechecker.
type RecheckerFunc func(ctx context.Context, in RecheckRequest) (RecheckResult, error)

// Recheck calls f.
func (f RecheckerFunc) Recheck(ctx context.Context, in RecheckRequest) (RecheckResult, error) {
	return f(ctx, in)
}

// RecheckByRefresh is the default Rechecker: redeem the session's refresh
// token. A server that re-asks its access rule on every refresh (ubgo/auth's
// provider does) refuses a removed person within one recheck interval. A
// session without a refresh token (the server granted none: ask for
// offline_access, or Google's access_type=offline through WithAuthParams)
// is refused at its first re-check, which New cannot know in advance and
// the log says.
func RecheckByRefresh() Rechecker {
	return RecheckerFunc(func(ctx context.Context, in RecheckRequest) (RecheckResult, error) {
		rf, err := in.Provider.Refresh(ctx, RefreshRequest{RefreshToken: in.Session.Tokens.RefreshToken, Subject: in.Session.User.Subject})
		if err != nil {
			return RecheckResult{}, err
		}
		return RecheckResult{Decision: Allow, Refreshed: rf}, nil
	})
}

// RecheckByIntrospection asks the introspection endpoint about the
// session's refresh token (its access token when it has none) and allows
// while it is active. Nothing is rotated, so a server whose refresh token
// rotation is costly is asked without it; whether a removed person shows as
// inactive depends on the server revoking their tokens (ubgo/auth's
// operator revoke does).
func RecheckByIntrospection() Rechecker {
	return RecheckerFunc(func(ctx context.Context, in RecheckRequest) (RecheckResult, error) {
		req := IntrospectRequest{Token: in.Session.Tokens.RefreshToken, Hint: HintRefreshToken}
		if req.Token.IsZero() {
			req = IntrospectRequest{Token: in.Session.Tokens.AccessToken, Hint: HintAccessToken}
		}
		got, err := in.Provider.Introspect(ctx, req)
		if err != nil {
			return RecheckResult{}, err
		}
		// An active token of another person or another client is not this
		// session's: a server answering for the wrong token says no.
		if !got.Active || (got.Subject != "" && got.Subject != in.Session.User.Subject) ||
			(got.ClientID != "" && got.ClientID != in.Provider.c.cfg.ClientID) {
			return RecheckResult{Decision: Deny}, nil
		}
		return RecheckResult{Decision: Allow}, nil
	})
}

// RecheckByUserInfo calls the userinfo endpoint with the session's access
// token, refreshing it first when it has expired, and allows on a 200 for
// the same subject. It suits a server whose userinfo, not its token
// endpoint, applies the access rule.
func RecheckByUserInfo() Rechecker {
	return RecheckerFunc(func(ctx context.Context, in RecheckRequest) (RecheckResult, error) {
		var out RecheckResult
		access := in.Session.Tokens.AccessToken
		exp := in.Session.Tokens.AccessExpiresAt
		if !exp.IsZero() && !in.Provider.c.set.now().Before(exp.Add(-tokenLeeway)) && !in.Session.Tokens.RefreshToken.IsZero() {
			rf, err := in.Provider.Refresh(ctx, RefreshRequest{RefreshToken: in.Session.Tokens.RefreshToken, Subject: in.Session.User.Subject})
			if err != nil {
				return RecheckResult{}, err
			}
			out.Refreshed, access = rf, rf.Tokens().AccessToken
		}
		if _, err := in.Provider.UserInfo(ctx, access, in.Session.User.Subject); err != nil {
			return RecheckResult{}, err
		}
		out.Decision = Allow
		return out, nil
	})
}

// RecheckBackchannelOnly never calls the login server: the session stands
// until the server's back-channel logout token ends it (or a lifetime
// does). New refuses it unless the SessionStore implements SessionRevoker,
// because with a stateless cookie nothing could ever end the session. It
// trusts delivery that the specification makes best effort with no retry,
// so prefer a periodic re-check where removal must be certain.
func RecheckBackchannelOnly() Rechecker { return backchannelOnly{} }

// backchannelOnly is RecheckBackchannelOnly; New recognises its type.
type backchannelOnly struct{}

func (backchannelOnly) Recheck(context.Context, RecheckRequest) (RecheckResult, error) {
	return RecheckResult{Decision: Allow}, nil
}

// Re-check timing defaults.
const (
	// DefaultRecheckInterval is how long the login server's last "yes"
	// stands: a person removed at the server is refused by the app within
	// this long, even with a saved cookie.
	//ds:def id=defaultrecheckinterval-vekfr6zh owner=@khanakia stability=stable
	DefaultRecheckInterval = time.Minute
	// RecheckEveryRequest, given to WithRecheckInterval, asks the login
	// server on every request: strict, and one round trip per request.
	RecheckEveryRequest time.Duration = 0
	// DefaultOutageGrace is how long the last "yes" still stands while the
	// login server cannot be reached, counted from Session.CheckedAt. After
	// it, requests are answered "unavailable" (the session is kept, so the
	// person is back the moment the server answers).
	//ds:def id=defaultoutagegrace-asgxt3qs owner=@khanakia stability=stable
	DefaultOutageGrace = 5 * time.Minute
	// NoOutageGrace, given to WithOutageGrace, refuses as soon as the login
	// server cannot be reached.
	NoOutageGrace time.Duration = 0
)
