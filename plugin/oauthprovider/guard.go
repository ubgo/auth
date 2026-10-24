package oauthprovider

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth/plugin/jwt"
)

// ResourceGuard protects a resource server that runs apart from the
// provider (an MCP server in another process): it needs no database and no
// Plugin. A JWT access token (typ at+jwt) is verified against the provider's
// keys, issuer and this resource's audience; an opaque one, when IntrospectURL
// is set, by RFC 7662 introspection. The required scopes are then checked, and
// refusals carry the RFC 6750 / RFC 9728 challenge.
type ResourceGuard struct {
	// Issuer and Audience are what a JWT access token must name: the
	// provider and this resource. Both required.
	Issuer   string
	Audience string
	// Keys resolves key ids, usually jwt.NewRemoteKeys(<issuer>/oauth2/jwks,
	// nil).Lookup.
	Keys func(kid string) (crypto.PublicKey, bool)
	// IntrospectURL, ClientID and ClientSecret verify opaque tokens by
	// introspection (client_secret_basic); empty refuses opaque tokens.
	IntrospectURL, ClientID, ClientSecret string
	// Force introspects every token, JWTs too: a revoked JWT is refused at once
	// rather than at its expiry. It needs IntrospectURL.
	Force bool
	// AllowMissingAudience accepts an introspected token that names no
	// audience: a token issued without a resource. Off, such a token is
	// refused, since nothing says it was meant for this resource.
	AllowMissingAudience bool
	// ChallengeScopes are the scopes a 401 challenge names; nil names
	// Scopes.
	ChallengeScopes []string
	// HTTPClient makes the introspection request; nil is a client with a
	// 5-second timeout.
	HTTPClient *http.Client
	// Scopes must all be granted; ScopeSatisfied replaces the exact match.
	Scopes         []string
	ScopeSatisfied func(granted []string, required string) bool
	// ResourceMetadataURL is named in challenges; JSONRPC answers in the
	// MCP JSON-RPC error envelope.
	ResourceMetadataURL string
	JSONRPC             bool
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// GuardedToken is what ResourceGuard verified, in the request context
// (GuardedTokenFrom).
type GuardedToken struct {
	Subject  string
	ClientID string
	Scopes   []string
	Claims   map[string]json.RawMessage
}

type guardKey struct{}

// GuardedTokenFrom returns the token ResourceGuard verified.
func GuardedTokenFrom(ctx context.Context) (GuardedToken, bool) {
	t, ok := ctx.Value(guardKey{}).(GuardedToken)
	return t, ok
}

// introspectTimeout bounds a remote introspection.
const introspectTimeout = 5 * time.Second

// Middleware guards next.
func (g ResourceGuard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, raw, _ := strings.Cut(strings.TrimSpace(r.Header.Get(headerAuthorization)), " ")
		if !strings.EqualFold(scheme, schemeBearer) || strings.TrimSpace(raw) == "" {
			g.challenge(w, nil, nil)
			return
		}
		t, err := g.verify(r.Context(), strings.TrimSpace(raw))
		if err != nil {
			g.challenge(w, ErrInvalidToken, nil)
			return
		}
		var missing []string
		for _, s := range g.Scopes {
			if !g.satisfied(t.Scopes, s) {
				missing = append(missing, s)
			}
		}
		if len(missing) > 0 {
			g.challenge(w, ErrInsufficientScope, missing)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), guardKey{}, t)))
	})
}

func (g ResourceGuard) satisfied(granted []string, required string) bool {
	if g.ScopeSatisfied != nil {
		return g.ScopeSatisfied(slices.Clone(granted), required)
	}
	return slices.Contains(granted, required)
}

// errNotVerifiable is a token neither the keys nor introspection can
// check.
var errNotVerifiable = errors.New("oauthprovider: token not verifiable")

// verify checks a JWT access token offline, or an opaque one remotely. A
// DPoP-bound token (cnf.jkt) is refused: the guard checks no proofs.
func (g ResourceGuard) verify(ctx context.Context, token string) (GuardedToken, error) {
	if g.Force && g.IntrospectURL != "" {
		return g.introspect(ctx, token)
	}
	if strings.Count(token, ".") == 2 && g.Keys != nil {
		v := jwt.Verifier{Lookup: g.Keys, Issuer: g.Issuer, Audience: g.Audience, Now: g.Now, Types: []string{AccessTokenType}}
		c, err := v.Verify(token)
		if err != nil {
			return GuardedToken{}, err
		}
		if _, bound := c.Extra[claimConfirm]; bound {
			return GuardedToken{}, errNotVerifiable
		}
		var scope, client string
		_ = json.Unmarshal(c.Extra[claimScope], &scope)
		_ = json.Unmarshal(c.Extra[claimClientID], &client)
		return GuardedToken{Subject: c.Subject, ClientID: client, Scopes: strings.Fields(scope), Claims: c.Extra}, nil
	}
	if g.IntrospectURL == "" {
		return GuardedToken{}, errNotVerifiable
	}
	return g.introspect(ctx, token)
}

// introspect asks the provider about an opaque token: it must be active,
// and, when it names an audience, name this resource.
func (g ResourceGuard) introspect(ctx context.Context, token string) (GuardedToken, error) {
	hc := g.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: introspectTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.IntrospectURL, strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		return GuardedToken{}, err
	}
	req.Header.Set(headerContentType, contentTypeForm)
	req.SetBasicAuth(url.QueryEscape(g.ClientID), url.QueryEscape(g.ClientSecret))
	res, err := hc.Do(req)
	if err != nil {
		return GuardedToken{}, err
	}
	defer res.Body.Close()
	var in struct {
		Active   bool            `json:"active"`
		Scope    string          `json:"scope"`
		ClientID string          `json:"client_id"`
		Subject  string          `json:"sub"`
		Audience json.RawMessage `json:"aud"`
		Cnf      *Confirmation   `json:"cnf"`
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, maxFormBytes))
	if err != nil || res.StatusCode != http.StatusOK || json.Unmarshal(b, &in) != nil || !in.Active || in.Cnf != nil {
		return GuardedToken{}, errNotVerifiable
	}
	switch {
	case len(in.Audience) == 0 || string(in.Audience) == "null":
		if !g.AllowMissingAudience {
			return GuardedToken{}, errNotVerifiable
		}
	case !audienceHas(in.Audience, g.Audience):
		return GuardedToken{}, errNotVerifiable
	}
	return GuardedToken{Subject: in.Subject, ClientID: in.ClientID, Scopes: strings.Fields(in.Scope)}, nil
}

// challenge writes the guard's refusal, as RequireToken does.
func (g ResourceGuard) challenge(w http.ResponseWriter, err error, missing []string) {
	writeChallenge(w, RequireOptions{Scopes: g.Scopes, JSONRPC: g.JSONRPC, ChallengeScopes: g.ChallengeScopes}, g.ResourceMetadataURL, err, missing)
}

// WriteInsufficientScope answers a request a RequireToken route found to
// need more scopes once it looked at the arguments: 403 insufficient_scope
// naming the missing scopes, with the route's challenge.
func (p *Plugin) WriteInsufficientScope(w http.ResponseWriter, o RequireOptions, missing ...string) {
	p.challenge(w, o, ErrInsufficientScope, missing)
}

// ProtectedResourceMetadata builds an RFC 9728 document for a resource
// served apart from the provider: the user scopes (openid, profile, email,
// offline_access) are not a resource's and are refused (ErrBadScopes).
func ProtectedResourceMetadata(resource string, authorizationServers, scopes []string) (ResourceMetadata, error) {
	for _, s := range scopes {
		if slices.Contains(userScopes, s) {
			return ResourceMetadata{}, ErrBadScopes
		}
	}
	return ResourceMetadata{Resource: resource, AuthorizationServers: slices.Clone(authorizationServers), BearerMethodsSupported: []string{"header"}, ScopesSupported: slices.Clone(scopes)}, nil
}
