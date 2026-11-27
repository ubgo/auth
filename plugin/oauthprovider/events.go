package oauthprovider

import (
	"context"
	"slices"
	"time"

	"github.com/ubgo/auth"
)

// TokenEventKind says what a TokenEvent reports.
type TokenEventKind string

// Token event kinds.
const (
	// TokenEventIssued: a token response was issued (a code exchange, a
	// refresh, client credentials, an extension grant, IssueTokens).
	TokenEventIssued TokenEventKind = "issued"
	// TokenEventRevoked: tokens were revoked; Reason says why.
	TokenEventRevoked TokenEventKind = "revoked"
)

// TokenEventKindValues lists every TokenEventKind.
var TokenEventKindValues = []TokenEventKind{TokenEventIssued, TokenEventRevoked}

// RevokeReason says why tokens were revoked.
type RevokeReason string

// Revoke reasons.
const (
	// RevokeReasonClientRequest: the client revoked a token (RFC 7009).
	RevokeReasonClientRequest RevokeReason = "client_request"
	// RevokeReasonReuse: a rotated refresh token was presented again outside
	// RefreshReuseInterval, or a spent code again, so the family was
	// revoked. The usual cause is a stolen token; the security stream gets
	// auth.SecurityTokenReplay too.
	RevokeReasonReuse RevokeReason = "reuse"
	// RevokeReasonRefused: a request presented the token or code but failed
	// one of its bindings (another client, a wrong redirect URI or PKCE
	// verifier, an expired token, a user that is gone, a DPoP proof of
	// another key, MaxAuthAge), which spends the family as reuse does.
	RevokeReasonRefused RevokeReason = "refused"
	// RevokeReasonSessionEnded: the session the tokens were issued on ended
	// (sign-out, RP-initiated logout, an admin); AccessOnly when the
	// refresh token outlives it under offline_access.
	RevokeReasonSessionEnded RevokeReason = "session_ended"
	// RevokeReasonConsentRevoked: the user withdrew their consent.
	RevokeReasonConsentRevoked RevokeReason = "consent_revoked"
	// RevokeReasonAdmin: the app's own code revoked them
	// (RevokeUserForClient, RevokeUserFamily).
	RevokeReasonAdmin RevokeReason = "admin"
)

// RevokeReasonValues lists every RevokeReason.
var RevokeReasonValues = []RevokeReason{RevokeReasonClientRequest, RevokeReasonReuse, RevokeReasonRefused, RevokeReasonSessionEnded, RevokeReasonConsentRevoked, RevokeReasonAdmin}

// TokenEvent is one issuance or revocation. It never carries a token, only
// what identifies it. Fields a kind does not know are empty: a revocation
// of every token one user holds at one client names no family or token, and
// one of a family names no token.
type TokenEvent struct {
	Kind TokenEventKind
	// Reason is why, for TokenEventRevoked.
	Reason RevokeReason
	// GrantType is the grant that issued, for TokenEventIssued.
	GrantType string
	ClientID  string
	// UserID is "" for a client's own token (client_credentials).
	UserID    string
	SessionID string
	// Family groups every token issued from one code (or one
	// client_credentials or extension grant) through its refreshes.
	Family string
	// TokenID is the token row (the token_id claim of a JWT access token).
	TokenID  string
	Scopes   []string
	Resource string
	// AccessExpiresAt is the access token's expiry; RefreshExpiresAt the
	// refresh token's, zero when none was issued (TokenEventIssued).
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
	// AccessOnly is a revocation that ended the access token and left the
	// refresh token (RevokeAccessTokenOnly, or a session end under
	// offline_access).
	AccessOnly bool
}

// TokenEventFunc receives token events.
type TokenEventFunc func(ctx context.Context, e TokenEvent)

// OnTokenEvent installs a TokenEventFunc: the hook for an app that mirrors
// issuance and revocation somewhere (a cache of revoked JWT access tokens,
// an audit trail, metrics, a webhook). It observes and cannot refuse: what
// may be issued is ClientAccess's and TokenResponseFields' to decide, and a
// core auth.Hook on EndpointToken, EndpointRevoke or EndpointEndSession can
// refuse those operations before they run.
//
// What stays true: an issuance is reported once its transaction commits,
// never for one rolled back; a revocation is reported after its write,
// including the ones that run after a refused request's rollback (reuse,
// refused); fn runs on the goroutine that committed (the request's,
// usually), so it must be quick, and a panic in it is recovered and logged,
// never reaching the client.
//
//ds:def id=oauthprovider-ontokenevent-kzgnhsu3 owner=@khanakia stability=stable
func OnTokenEvent(fn TokenEventFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.OnTokenEvent", fn) {
			return
		}
		p.tokenEvents = fn
	}
}

// emitToken reports e once the transaction in ctx commits (at once outside
// one).
func (p *Plugin) emitToken(ctx context.Context, e TokenEvent) {
	if p.tokenEvents == nil {
		return
	}
	p.core.AfterCommit(ctx, func(ctx context.Context) {
		p.safeHook("OnTokenEvent", func() { p.tokenEvents(ctx, e) })
	})
}

// issuedEvent is the TokenEventIssued of an issuance stored as row id.
func issuedEvent(is issuance, id string, access time.Time, refresh *time.Time) TokenEvent {
	e := TokenEvent{Kind: TokenEventIssued, GrantType: is.grantType, ClientID: is.client.c.ClientID, UserID: is.userID, SessionID: is.sessionID,
		Family: is.family, TokenID: id, Scopes: slices.Clone(is.scopes), Resource: is.resource, AccessExpiresAt: access}
	if refresh != nil {
		e.RefreshExpiresAt = *refresh
	}
	return e
}

// Attribute keys of the auth.SecurityTokenReplay events this plugin emits.
const (
	// AttrClientID names the client the replayed grant was issued to.
	AttrClientID = "client_id"
	// AttrGrantKind is what was replayed: GrantRefreshToken or
	// GrantAuthorizationCode.
	AttrGrantKind = "grant_kind"
)

// callKey carries the token request's call, so a replay found deep in a
// grant is reported with the call's address and operation.
type callKey struct{}

// withCall stores c in ctx for reportReplay.
func withCall(ctx context.Context, c *auth.Call) context.Context {
	if c == nil {
		return ctx
	}
	return context.WithValue(ctx, callKey{}, c)
}

// reportReplay emits auth.SecurityTokenReplay for a spent code or rotated
// refresh token presented again: SeverityAlert, Outcome blocked, as the
// core reports a replayed session token. Without a security sink it does
// nothing.
func (p *Plugin) reportReplay(ctx context.Context, kind, clientID, userID string) {
	e := auth.SecurityEvent{Kind: auth.SecurityTokenReplay, Severity: auth.SeverityAlert, Outcome: auth.RateOutcomeBlocked,
		Op: EndpointToken, Plugin: PluginName, UserID: userID, Attrs: map[string]string{AttrClientID: clientID, AttrGrantKind: kind}}
	if c, ok := ctx.Value(callKey{}).(*auth.Call); ok {
		p.core.EmitSecurityOf(c, e)
		return
	}
	p.core.EmitSecurity(e)
}
