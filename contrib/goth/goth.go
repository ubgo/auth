// Package authgoth adapts any github.com/markbates/goth provider into an
// oauth.Provider, so an app that already configures its sign-in through goth
// (or needs one of goth's 70-odd providers the oauth plugin has no preset
// for) keeps that configuration and gets everything else from plugin/oauth:
// the state, the flow cookie, account linking, the verified-email rules,
// rate limits and hooks.
//
// The adapter only translates. It never sees a session, a cookie or a user
// row; the plugin stores what it always stores, the provider name and the
// subject, so swapping the adapter for a built-in provider (or back) keeps
// every linked account.
//
// What goth cannot do, and the adapter therefore does not claim:
//
//   - PKCE. goth's BeginAuth takes no code challenge, so the authorization
//     URL carries none and the code is protected by the state alone. The
//     adapter passes oauthtest with the NoPKCE option, which says so.
//   - Verified email, unless goth reports it: an address counts as verified
//     only when goth's RawData carries the OpenID Connect email_verified
//     claim as true (goth's openidConnect, and providers whose user API
//     returns that claim). Everything else is unverified, so it never links
//     to an existing account on the address alone.
//   - The plugin's redirect URI and HTTP client. goth fixes the callback URL
//     and the HTTP client when the goth provider is built, so build it with
//     the plugin's callback URL (BaseURL + "/auth/oauth/<name>/callback");
//     Exchange refuses a mismatch with an error that names both. The
//     context is checked before the exchange starts, but goth's own calls
//     do not take it.
//   - Per-flow session state. The plugin keeps none of goth's session
//     between the start and the callback, so a goth provider whose session
//     carries a secret of its own (OAuth 1.0a request tokens, twitterv2's
//     PKCE verifier) cannot be wrapped; plain OAuth 2.0 authorization-code
//     providers, whose session holds only the URL, can.
package authgoth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/markbates/goth"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

// claimEmailVerified is the OpenID Connect claim (Core section 5.1) the
// adapter reads as goth's verdict on the address. goth.User has no verified
// field, so this claim in RawData is the only report there is.
const claimEmailVerified = "email_verified"

// paramCode and paramRedirectURI are the authorization response's code and
// the authorization request's redirect URI (RFC 6749 section 4.1).
const (
	paramCode        = "code"
	paramRedirectURI = "redirect_uri"
)

// Wrap adapts gp. Its Name is the plugin's route segment and the stored
// provider name, so it must match auth.KindNamePattern: goth's own names
// ("openid-connect", "corp-oidc") do not, so rename it first with
// gp.SetName("corp"). No goth type crosses the returned value.
//
//ds:def id=authgoth-wrap-m7tq3xnv owner=@khanakia stability=stable
func Wrap(gp goth.Provider) oauth.Provider { return &provider{gp: gp} }

// provider is the adapter; it holds nothing but the goth provider, so it is
// as safe for concurrent flows as the goth provider is.
type provider struct{ gp goth.Provider }

// Name returns the goth provider's name.
func (p *provider) Name() string { return p.gp.Name() }

// Discover checks that goth can begin a flow, before the plugin writes any
// state for it: a goth provider that cannot build its authorization URL
// fails the start as oauth.ErrProviderFailed rather than redirecting the
// browser nowhere.
func (p *provider) Discover(context.Context, *http.Client) error {
	_, err := p.begin("")
	return err
}

// AuthCodeURL is goth's authorization URL for state. The challenge is not
// sent (goth's BeginAuth takes none), and the redirect URI is the one the
// goth provider was built with; Exchange refuses a mismatch. It returns ""
// only when goth fails between Discover and this call.
func (p *provider) AuthCodeURL(state, _, _ string) string {
	u, err := p.begin(state)
	if err != nil {
		return ""
	}
	return u.String()
}

// begin starts a goth flow for state and returns its authorization URL.
func (p *provider) begin(state string) (*url.URL, error) {
	sess, err := p.gp.BeginAuth(state)
	if err != nil {
		return nil, fmt.Errorf("%w: goth %q: begin: %v", oauth.ErrExchange, p.gp.Name(), err)
	}
	raw, err := sess.GetAuthURL()
	if err != nil {
		return nil, fmt.Errorf("%w: goth %q: authorization URL: %v", oauth.ErrExchange, p.gp.Name(), err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: goth %q: authorization URL %q: %v", oauth.ErrExchange, p.gp.Name(), raw, err)
	}
	return u, nil
}

// Exchange trades the code through goth (Authorize, then FetchUser) and
// translates the goth user into a profile. The verifier is unused: no
// challenge was sent.
func (p *provider) Exchange(ctx context.Context, _ *http.Client, code, _, redirectURI string) (oauth.Profile, error) {
	if err := ctx.Err(); err != nil {
		return oauth.Profile{}, fmt.Errorf("%w: %v", oauth.ErrExchange, err)
	}
	// A fresh session: the plugin carried none across the redirect, and an
	// OAuth 2.0 goth session holds nothing the exchange needs but the code.
	sess, err := p.gp.BeginAuth("")
	if err != nil {
		return oauth.Profile{}, fmt.Errorf("%w: goth %q: begin: %v", oauth.ErrExchange, p.gp.Name(), err)
	}
	if raw, err := sess.GetAuthURL(); err == nil {
		if u, err := url.Parse(raw); err == nil {
			if got := u.Query().Get(paramRedirectURI); got != "" && got != redirectURI {
				return oauth.Profile{}, fmt.Errorf("%w: goth %q redirects to %q but the plugin's callback is %q: build the goth provider with the plugin's callback URL", oauth.ErrExchange, p.gp.Name(), got, redirectURI)
			}
		}
	}
	if _, err := sess.Authorize(p.gp, url.Values{paramCode: {code}}); err != nil {
		return oauth.Profile{}, fmt.Errorf("%w: goth %q: authorize: %v", oauth.ErrExchange, p.gp.Name(), err)
	}
	u, err := p.gp.FetchUser(sess)
	if err != nil {
		return oauth.Profile{}, fmt.Errorf("%w: goth %q: fetch user: %v", oauth.ErrExchange, p.gp.Name(), err)
	}
	if u.UserID == "" {
		return oauth.Profile{}, fmt.Errorf("%w: goth %q: profile has no subject", oauth.ErrExchange, p.gp.Name())
	}
	return profileOf(u), nil
}

// profileOf translates a goth user. The email is verified only when goth
// reported the email_verified claim as true; the raw data becomes Claims so
// a ValidateProfile hook reads provider-specific fields as it does for a
// built-in provider.
func profileOf(u goth.User) oauth.Profile {
	return oauth.Profile{
		Subject:       u.UserID,
		Email:         u.Email,
		EmailVerified: u.Email != "" && verified(u.RawData[claimEmailVerified]),
		Name:          firstOf(u.Name, strings.TrimSpace(u.FirstName+" "+u.LastName), u.NickName),
		Image:         u.AvatarURL,
		Tokens: oauth.TokenSet{
			AccessToken:  auth.Token(u.AccessToken),
			RefreshToken: auth.Token(u.RefreshToken),
			IDToken:      auth.Token(u.IDToken),
			ExpiresAt:    u.ExpiresAt,
		},
		Claims: claimsOf(u.RawData),
	}
}

// verified reads an email_verified claim: JSON true, or the string "true"
// that some issuers (Slack, LinkedIn) send. Anything else, absence
// included, is unverified.
func verified(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return b == "true"
	}
	return false
}

// claimsOf re-encodes goth's decoded RawData as raw claims. goth decoded it
// from JSON, so every value encodes again; one that would not is left out
// rather than failing the sign-in over a field nobody asked for.
func claimsOf(raw map[string]any) map[string]json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]json.RawMessage, len(raw))
	for k, v := range raw {
		if b, err := json.Marshal(v); err == nil {
			out[k] = b
		}
	}
	return out
}

// firstOf returns the first non-empty value.
func firstOf(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
