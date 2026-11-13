package oidcclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

// OpenID Connect Back-Channel Logout 1.0, matching what ubgo/auth's
// plugin/oauthprovider sends (plugin/oauthprovider/backchannel.go): a form
// POST of logout_token, a JWT with iss, sub and/or sid, aud the client id,
// iat, exp two minutes later, jti, and the back-channel logout event.
const (
	// backchannelEvent is the member of the events claim that makes a JWT
	// a logout token (section 2.4).
	backchannelEvent = "http://schemas.openid.net/event/backchannel-logout"
	// paramLogoutToken is the form field the token arrives in.
	paramLogoutToken = "logout_token"
	// logoutTokenMaxAge is the oldest iat accepted. The provider gives its
	// logout tokens two minutes; an older one is a replay or a delivery so
	// late that acting on it surprises more than it protects.
	logoutTokenMaxAge = 2 * time.Minute
	// maxLogoutFormBytes bounds the form; a logout token is about 1 KB.
	maxLogoutFormBytes = 64 << 10
	// maxReplayEntries bounds the jti memory. Only the issuer can mint a
	// token that verifies, and each is remembered only until it expires,
	// so a full cache means a misbehaving issuer; it then refuses.
	maxReplayEntries = 10000
)

// Back-channel error codes (section 2.8 allows error and
// error_description on a 400).
const (
	backchannelInvalidRequest = "invalid_request"
	backchannelNotSupported   = "not_supported"
	backchannelServerError    = "server_error"
	backchannelUnavailable    = "temporarily_unavailable"
)

// replayCache remembers the jti of every logout token accepted until it
// expires, so one token ends sessions once. It is per Client and per
// process: a second instance accepting the same token once more ends the
// same sessions again, which is harmless.
type replayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// remember records jti until until and reports whether it was new. A full
// cache is purged of expired entries first; if it is still full the token
// is refused (fail closed).
func (rc *replayCache) remember(jti string, until, now time.Time) bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.seen == nil {
		rc.seen = map[string]time.Time{}
	}
	if t, ok := rc.seen[jti]; ok && now.Before(t) {
		return false
	}
	if len(rc.seen) >= maxReplayEntries {
		for k, t := range rc.seen {
			if !now.Before(t) {
				delete(rc.seen, k)
			}
		}
		if len(rc.seen) >= maxReplayEntries {
			return false
		}
	}
	rc.seen[jti] = until
	return true
}

// forget drops jti, after the store failed to act on its token, so a
// retried delivery is not refused as a replay.
func (rc *replayCache) forget(jti string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	delete(rc.seen, jti)
}

// logoutToken is a verified logout token: who to sign out, and its jti
// with how long to remember it.
type logoutToken struct {
	target LogoutTarget
	jti    string
	until  time.Time
}

// verifyLogoutToken checks a logout token (section 2.6): signature under
// an allowed algorithm, iss exactly the issuer, aud the client, azp the
// client when present, iat present and recent, exp when present not
// passed, the back-channel logout event as a JSON object, sub or sid, a
// jti, and no nonce (which an ID token would carry: it keeps an ID token
// from being replayed as a logout token).
func (c *Client) verifyLogoutToken(ctx context.Context, raw string) (logoutToken, error) {
	meta, err := c.provider.Metadata(ctx)
	if err != nil {
		return logoutToken{}, err
	}
	v, err := c.provider.verifyJWS(ctx, meta.JWKSURI, raw)
	if err != nil {
		return logoutToken{}, err
	}
	var rc registeredClaims
	if err := json.Unmarshal(v.payload, &rc); err != nil {
		return logoutToken{}, invalid("claims: %v", err)
	}
	if err := c.provider.checkCommon(rc, meta.Issuer, false); err != nil {
		return logoutToken{}, err
	}
	now := c.set.now()
	var event map[string]json.RawMessage
	switch {
	case now.Sub(rc.IssuedAt.time()) > logoutTokenMaxAge+tokenLeeway:
		return logoutToken{}, invalid("issued too long ago")
	case rc.Events == nil || json.Unmarshal(rc.Events[backchannelEvent], &event) != nil || event == nil:
		return logoutToken{}, invalid("no back-channel logout event")
	case rc.Nonce != nil:
		return logoutToken{}, invalid("a logout token carries no nonce")
	case rc.Subject == "" && rc.SessionID == "":
		return logoutToken{}, invalid("neither sub nor sid")
	case rc.TokenID == "":
		return logoutToken{}, invalid("no jti")
	}
	until := rc.IssuedAt.time().Add(logoutTokenMaxAge)
	if exp := rc.ExpiresAt.time(); exp.After(until) {
		until = exp
	}
	return logoutToken{
		target: LogoutTarget{Issuer: rc.Issuer, Subject: rc.Subject, ProviderSessionID: rc.SessionID},
		jti:    rc.TokenID, until: until.Add(tokenLeeway),
	}, nil
}

// backchannelError is section 2.8's error answer.
func backchannelError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set(headerContentType, mediaTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(oauthError{Code: code, Description: description}) // a server that hung up cannot be told
}

// serveBackchannel implements BackchannelHandler.
func (c *Client) serveBackchannel(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodPost) {
		return
	}
	noStore(w)
	ctx := r.Context()
	rev, ok := c.set.store.(SessionRevoker)
	if !ok {
		c.set.logger.WarnContext(ctx, "oidcclient: back-channel logout received", "error", ErrBackchannelUnsupported)
		backchannelError(w, http.StatusNotImplemented, backchannelNotSupported, ErrBackchannelUnsupported.Error())
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLogoutFormBytes)
	if err := r.ParseForm(); err != nil || r.PostForm.Get(paramLogoutToken) == "" {
		backchannelError(w, http.StatusBadRequest, backchannelInvalidRequest, "a logout_token form field is required")
		return
	}
	lt, err := c.verifyLogoutToken(ctx, r.PostForm.Get(paramLogoutToken))
	if err != nil {
		c.set.logger.WarnContext(ctx, "oidcclient: back-channel logout token refused", "error", err)
		if errors.Is(err, ErrProviderUnavailable) {
			backchannelError(w, http.StatusServiceUnavailable, backchannelUnavailable, "the login server's keys could not be read")
			return
		}
		backchannelError(w, http.StatusBadRequest, backchannelInvalidRequest, "the logout token was not accepted")
		return
	}
	if !c.replay.remember(lt.jti, lt.until, c.set.now()) {
		c.set.logger.WarnContext(ctx, "oidcclient: back-channel logout token replayed")
		backchannelError(w, http.StatusBadRequest, backchannelInvalidRequest, "the logout token was already used")
		return
	}
	n, err := rev.RevokeSessions(ctx, lt.target)
	if err != nil {
		c.replay.forget(lt.jti)
		c.set.logger.ErrorContext(ctx, "oidcclient: back-channel logout", "error", err)
		backchannelError(w, http.StatusInternalServerError, backchannelServerError, "the sessions could not be ended")
		return
	}
	c.observe(ctx, Event{Kind: EventBackchannelLogout, Subject: lt.target.Subject, Count: n})
	w.WriteHeader(http.StatusOK)
}
