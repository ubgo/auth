package oauthprovider

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/ubgo/auth"
)

// The revoke of one token family: one sign-in of one user at one client
// (the code's tokens and every rotation of its refresh token), from the
// operator's or the app's side, with no signed-in user. It is what a "your
// sessions" page needs to end one session of one app while the user's other
// sessions there, on other devices, go on; RevokeUserForClient ends them all.
// Like RevokeUserForClient it is a plain Go method, not an operation: the
// caller decides who may end which family (a page that lists the signed-in
// user's own families passes that user's id, so another user's family is
// ErrTokenFamilyNotFound).

// ErrTokenFamilyNotFound is a family the user holds no token in: unknown, or
// another user's. The two are not told apart, so a caller cannot probe
// another user's family ids.
var ErrTokenFamilyNotFound = auth.NewError("oauthprovider.family_not_found", http.StatusNotFound, "Not found.")

// RevokeFamilyRequest names the family and the user it must belong to.
type RevokeFamilyRequest struct {
	// UserID is the user the family must belong to.
	UserID string
	// Family is the family id (the token rows' family column).
	Family string
}

// RevokeUserFamily revokes every token of one family of one user, in one
// transaction: the access tokens and the refresh token stop (introspection
// answers inactive, a refresh is invalid_grant, inside RefreshReuseInterval
// too). When the family's client has a backchannel_logout_uri and the family
// still held a live token, the client is sent one logout token for the
// family's session (sub and sid; sub alone for a family issued on no session,
// unless the client set backchannel_logout_session_required), after the
// commit, not retried, as for RevokeUserForClient. The result counts the
// revoked rows (Tokens) and the notices (LogoutNotices); Codes and Consent
// stay zero: a family's code is already redeemed, and the consent covers the
// user's other families too.
//
// A second call returns all zero. A family that is not the user's is
// ErrTokenFamilyNotFound; any database error rolls the revoke back.
func (p *Plugin) RevokeUserFamily(ctx context.Context, in RevokeFamilyRequest) (RevokeUserResult, error) {
	var res RevokeUserResult
	if in.UserID == "" || in.Family == "" {
		return res, ErrTokenFamilyNotFound
	}
	err := p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		toks, err := p.store.Tokens(ctx, TokenFilter{Family: in.Family, UserID: in.UserID})
		if err != nil {
			return err
		}
		if len(toks) == 0 {
			return ErrTokenFamilyNotFound
		}
		// Every row of a family shares its client and session.
		clientID, sid, live := toks[0].ClientID, deref(toks[0].SessionID), 0
		for _, t := range toks {
			if t.RevokedAt == nil {
				live++
			}
		}
		if live == 0 {
			return nil
		}
		var targets []logoutTarget
		c, err := p.loadClient(ctx, clientID)
		switch {
		case errors.Is(err, ErrClientNotFound):
			// A deleted client has nobody to notify.
		case err != nil:
			return err
		case c.disabledAt == nil && deref(c.backchannel) != "" && (sid != "" || !c.c.BackchannelLogoutSessionRequired):
			targets = append(targets, logoutTarget{client: c, sessionID: sid, userID: in.UserID})
		}
		if res.Tokens, err = p.store.RevokeTokens(ctx, TokenFilter{Family: in.Family, UserID: in.UserID}, p.core.Now()); err != nil {
			return err
		}
		if res.Tokens > 0 {
			p.emitToken(ctx, TokenEvent{Kind: TokenEventRevoked, Reason: RevokeReasonAdmin, ClientID: clientID, UserID: in.UserID, SessionID: sid, Family: in.Family})
		}
		res.LogoutNotices = len(targets)
		if len(targets) > 0 {
			p.core.AfterCommit(ctx, func(ctx context.Context) {
				p.core.RunInBackground(ctx, func(ctx context.Context) { p.deliverLogoutTokens(ctx, targets) })
			})
		}
		return nil
	})
	if err != nil {
		return RevokeUserResult{}, err
	}
	return res, nil
}
