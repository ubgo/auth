package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ubgo/auth"
)

// This file holds two better-auth parities of round 6 (2026-10-06): server
// context carried across the provider redirect (addOAuthServerContext), and
// the opt-in route that hands a signed-in browser its own provider access
// token (getAccessToken from the client).

// ServerContextFunc returns server-set values to carry across one OAuth flow,
// better-auth's addOAuthServerContext: a tenant id the request resolved, a
// plan the server chose. It runs at every start and id-token sign-in, with
// the provider's name; what it returns is stored with the state, where no
// client can set or change it, and handed back in CallbackResult.ServerContext
// and ProfileEvent.ServerContext. An error refuses the start: an *auth.Error
// is answered as it is, any other error as a server error.
//
//ds:def id=servercontextfunc-k2nw8xqt owner=@khanakia stability=stable
type ServerContextFunc func(ctx context.Context, c *auth.Call, provider string) (map[string]string, error)

// WithServerContext adds a ServerContextFunc; several run in order, and a
// later one's key replaces an earlier one's. Unlike StartRequest.Data, which
// the client chooses and the app must validate, these values come from the
// server and need no check at the callback.
//
//ds:def id=withservercontext-r8kq3wnx owner=@khanakia stability=stable
func WithServerContext(fn ServerContextFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauth.WithServerContext", fn) {
			return
		}
		p.serverContext = append(p.serverContext, fn)
	}
}

// maxServerContextLength bounds the JSON of the server context: it shares
// the state row's 4096-character meta column with the flow's own fields and
// the client's Data (maxFlowDataLength).
//
//ds:def id=maxservercontextlength-w4xk9nqt owner=@khanakia stability=stable
const maxServerContextLength = 1024

// ErrServerContextTooLong is a server context whose JSON exceeds
// maxServerContextLength: a programming error of the app's function, so it
// is a plain error (a 500), not a client answer.
var ErrServerContextTooLong = errors.New("oauth: WithServerContext values exceed 1024 characters as JSON")

// runServerContext runs the WithServerContext functions and merges their
// values; nil when none is configured or none returned anything.
func (p *Plugin) runServerContext(ctx context.Context, c *auth.Call, provider string) (map[string]string, error) {
	var out map[string]string
	for _, fn := range p.serverContext {
		vals, err := fn(ctx, c, provider)
		if err != nil {
			return nil, err
		}
		for k, v := range vals {
			if out == nil {
				out = map[string]string{}
			}
			out[k] = v
		}
	}
	if out == nil {
		return nil, nil
	}
	// Marshalling a map[string]string cannot fail: every key and value is a
	// string, which JSON encodes whatever its bytes.
	raw, _ := json.Marshal(out)
	if len(raw) > maxServerContextLength {
		return nil, fmt.Errorf("%w: %d", ErrServerContextTooLong, len(raw))
	}
	return out, nil
}

// EndpointAccessToken is the ExposeAccessTokens route, POST /access-token.
//
//ds:def id=endpointaccesstoken-t6nq2xkw owner=@khanakia stability=stable
const EndpointAccessToken auth.EndpointID = "oauth.access_token"

// pathAccessToken is EndpointAccessToken's route.
const pathAccessToken = "/access-token"

// The access-token route's rate limit per client IP. A page reads the token
// once and caches it until accessTokenExpiresAt; a burst of reads is a script
// harvesting tokens, or a loop that would refresh at the provider each time.
// Thirty a minute is far above a page's own use.
const (
	//ds:def id=accesstokeniplimit-x4wn8kqt owner=@khanakia stability=stable
	accessTokenIPLimit = 30
	//ds:def id=accesstokenipwindow-m7qk2xwn owner=@khanakia stability=stable
	accessTokenIPWindow = time.Minute
)

// ErrExposeNeedsStoreTokens is ExposeAccessTokens without StoreTokens: the
// route would only ever answer ErrNoTokens.
var ErrExposeNeedsStoreTokens = errors.New("oauth: ExposeAccessTokens needs StoreTokens")

// ExposeAccessTokens adds POST /access-token {"provider"}: the signed-in
// user's own access token at that provider, refreshed when it is within
// RefreshMargin of expiring, with its expiry, granted scopes and ID token.
// better-auth's getAccessToken from the client, for a browser or mobile app
// that calls the provider's API itself (Google Drive from the page). Off by
// default, because it moves a bearer credential for another service into the
// browser: any script that runs on the app's origin (one XSS) can then read
// it and call the provider as the user until it expires. The refresh token
// is never sent; the route needs a signed-in session and the origin check,
// and requires StoreTokens (ErrExposeNeedsStoreTokens).
//
//ds:def id=exposeaccesstokens-m3xw8nqk owner=@khanakia stability=stable
func ExposeAccessTokens() Option { return func(p *Plugin) { p.exposeTokens = true } }

// AccessTokenRequest names the provider whose token the signed-in user wants.
type AccessTokenRequest struct {
	Provider string `json:"provider"`
}

// AccessTokenResult is the signed-in user's provider token, without the
// refresh token, which stays on the server.
//
//ds:def id=accesstokenresult-c8kw3xnt owner=@khanakia stability=stable
type AccessTokenResult struct {
	// AccessToken is revealed on purpose: delivering it is this route's
	// job (ExposeAccessTokens).
	AccessToken string `json:"accessToken"`
	// ExpiresAt is when AccessToken expires; nil when the provider did not
	// say.
	ExpiresAt *time.Time `json:"accessTokenExpiresAt"`
	// Scopes are the scopes the provider said it granted.
	Scopes []string `json:"scopes"`
	// IDToken is the OpenID Connect ID token of the last exchange, "" when
	// the provider issued none.
	IDToken string `json:"idToken,omitempty"`
}

// doAccessToken answers the signed-in user's token at in.Provider through
// Tokens, which refreshes it when due; a provider the user never linked, or
// one with no stored token, is ErrNoTokens.
func (p *Plugin) doAccessToken(ctx context.Context, c *auth.Call, in AccessTokenRequest) (AccessTokenResult, error) {
	if p.provider(in.Provider) == nil {
		return AccessTokenResult{}, ErrNoTokens
	}
	ts, err := p.Tokens(ctx, c.User.ID, in.Provider)
	if err != nil {
		return AccessTokenResult{}, err
	}
	out := AccessTokenResult{AccessToken: ts.AccessToken.Reveal(), Scopes: strings.Fields(ts.Scope), IDToken: ts.IDToken.Reveal()}
	if !ts.ExpiresAt.IsZero() {
		exp := ts.ExpiresAt
		out.ExpiresAt = &exp
	}
	return out, nil
}
