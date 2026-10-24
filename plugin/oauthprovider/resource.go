package oauthprovider

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// WellKnownProtectedResource is the RFC 9728 protected resource metadata
// document, served before the resource's path.
const WellKnownProtectedResource = "/.well-known/oauth-protected-resource"

// JSON-RPC error envelope of an MCP challenge.
const (
	jsonRPCVersion = "2.0"
	// jsonRPCServerError is the JSON-RPC 2.0 implementation-defined server
	// error MCP servers answer an unauthenticated call with.
	jsonRPCServerError = -32000
)

// ProtectedResource declares a resource server this provider issues tokens
// for, such as an MCP server: its canonical URL (RFC 8707 / 9728: https, or
// http on loopback, with no query or fragment) and the scopes it accepts.
// Handler then serves its RFC 9728 metadata, which MCP clients read to find
// the authorization server.
func ProtectedResource(resource string, scopes ...string) Option {
	return func(p *Plugin) { p.resources = append(p.resources, resourceSpec{url: resource, scopes: scopes}) }
}

type resourceSpec struct {
	url    string
	scopes []string
}

// ResourceMetadata is the RFC 9728 document.
type ResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	// DPoPSigningAlgValuesSupported are the DPoP proof algorithms the
	// provider's resources accept (RFC 9728 section 2); a separate
	// resource server sets its own.
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`
}

// ResourceMetadataFor builds the document for a declared resource; false
// when it was not declared with ProtectedResource. User scopes (openid,
// profile, email, offline_access) are never advertised: they are the
// provider's, not the resource's.
func (p *Plugin) ResourceMetadataFor(resource string) (ResourceMetadata, bool) {
	for _, r := range p.resources {
		if r.url != resource {
			continue
		}
		m := ResourceMetadata{Resource: r.url, AuthorizationServers: []string{p.issuer}, BearerMethodsSupported: []string{"header"}, DPoPSigningAlgValuesSupported: slices.Clone(p.dpopAlgs)}
		for _, s := range r.scopes {
			if !slices.Contains(userScopes, s) {
				m.ScopesSupported = append(m.ScopesSupported, s)
			}
		}
		return m, true
	}
	return ResourceMetadata{}, false
}

// resourceMetadataURL is where a resource's metadata is served: the
// well-known prefix inserted before the resource's path (RFC 9728 section
// 3.1).
func resourceMetadataURL(resource string) string {
	u, _ := url.Parse(resource) // checked by Validate
	return u.Scheme + "://" + u.Host + WellKnownProtectedResource + strings.TrimSuffix(u.Path, "/")
}

// serveResourceMetadata answers the metadata of the resource whose
// well-known path was requested; false when none matches.
func (p *Plugin) serveResourceMetadata(w http.ResponseWriter, r *http.Request) bool {
	for _, res := range p.resources {
		u, _ := url.Parse(resourceMetadataURL(res.url))
		if u.Path != r.URL.Path {
			continue
		}
		if p.allow(w, r, true, http.MethodGet, http.MethodHead) {
			m, _ := p.ResourceMetadataFor(res.url)
			writeJSON(w, http.StatusOK, m)
		}
		return true
	}
	return false
}

// validResource is validIssuer's rule for a resource URL.
func validResource(raw string) bool { return validIssuer(raw) }

// RequireOptions configures RequireToken.
type RequireOptions struct {
	// Resource is the protected resource this route belongs to: only tokens
	// issued for it (RFC 8707 resource, the JWT's aud) are accepted, and its
	// metadata URL is named in every challenge (RFC 9728 section 5.1).
	// Optional; without it any of this provider's access tokens is accepted.
	Resource string
	// Scopes must all be on the token; a missing one is 403
	// insufficient_scope naming every missing scope.
	Scopes []string
	// ScopeSatisfied replaces the exact scope match: given the token's scopes
	// and one required scope, it says whether the requirement is met (a
	// hierarchy, a wildcard).
	ScopeSatisfied func(granted []string, required string) bool
	// JSONRPC answers a refusal in the JSON-RPC 2.0 error envelope MCP
	// clients expect, {"jsonrpc":"2.0","error":{"code":-32000,...},"id":null},
	// with the same status and WWW-Authenticate challenge.
	JSONRPC bool
	// ChallengeScopes are the scopes a 401 challenge names; nil names Scopes. A
	// 403 always names the missing ones.
	ChallengeScopes []string
}

type tokenKey struct{}

// TokenFrom returns the access token RequireToken verified for this
// request.
func TokenFrom(ctx context.Context) (AccessToken, bool) {
	t, ok := ctx.Value(tokenKey{}).(AccessToken)
	return t, ok
}

// RequireToken guards a resource server route, such as an MCP endpoint: it
// verifies the bearer access token (VerifyAccessToken) and the required
// scopes, and puts the token in the context (TokenFrom). A missing or bad
// token is 401 and a missing scope 403, each with the WWW-Authenticate
// Bearer challenge of RFC 6750 and RFC 9728 (resource_metadata, scope).
func (p *Plugin) RequireToken(o RequireOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pt, ok := presented(r, requestURL(r))
			if !ok {
				p.challenge(w, o, nil, nil)
				return
			}
			t, err := p.VerifyPresentedToken(r.Context(), pt)
			if err != nil {
				p.logInternal(err)
				p.challenge(w, o, err, nil)
				return
			}
			// Audience binding (RFC 8707): a route of a resource accepts only
			// tokens issued for it, so a token a client got for another API
			// cannot be replayed here.
			if o.Resource != "" && !t.HasResource(o.Resource) {
				p.challenge(w, o, ErrInvalidToken, nil)
				return
			}
			var missing []string
			for _, s := range o.Scopes {
				ok := t.HasScope(s)
				if o.ScopeSatisfied != nil {
					ok = o.ScopeSatisfied(slices.Clone(t.Scopes), s)
				}
				if !ok {
					missing = append(missing, s)
				}
			}
			if len(missing) > 0 {
				p.challenge(w, o, ErrInsufficientScope, missing)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tokenKey{}, t)))
		})
	}
}

// challenge answers a refused resource request on a RequireToken route.
func (p *Plugin) challenge(w http.ResponseWriter, o RequireOptions, err error, missing []string) {
	meta := ""
	if o.Resource != "" {
		meta = resourceMetadataURL(o.Resource)
	}
	writeChallenge(w, o, meta, err, missing)
}

// writeChallenge writes a refusal: err nil is "no token", a bare challenge
// with no error code, as RFC 6750 section 3.1 requires; otherwise the
// error's code and status, the scopes (the missing ones on 403), and the
// resource metadata URL (RFC 9728 section 5.1), in the JSON-RPC envelope
// when asked.
func writeChallenge(w http.ResponseWriter, o RequireOptions, metaURL string, err error, missing []string) {
	parts := []string{}
	status := http.StatusUnauthorized
	code := ""
	if err != nil {
		code = rfcCode(err)
		status = statusOf(err)
		parts = append(parts, `error="`+code+`"`)
	}
	scopes := missing
	if scopes == nil {
		scopes = o.Scopes
		if o.ChallengeScopes != nil {
			scopes = o.ChallengeScopes
		}
	}
	if len(scopes) > 0 {
		parts = append(parts, `scope="`+strings.Join(scopes, listSeparator)+`"`)
	}
	if metaURL != "" {
		parts = append(parts, `resource_metadata="`+metaURL+`"`)
	}
	h := schemeBearer
	if len(parts) > 0 {
		h += " " + strings.Join(parts, ", ")
	}
	w.Header().Set(headerWWWAuth, h)
	msg := "Authentication required."
	if err != nil {
		msg = errorMessage(err)
	}
	if o.JSONRPC {
		writeJSON(w, status, jsonRPCError{JSONRPC: jsonRPCVersion, Error: jsonRPCErrorBody{Code: jsonRPCServerError, Message: msg}})
		return
	}
	if code == "" {
		w.WriteHeader(status)
		return
	}
	writeJSON(w, status, errorBody{Error: code, Description: msg})
}

// jsonRPCError is the JSON-RPC 2.0 error response; ID is always null,
// because the refused request was never read.
type jsonRPCError struct {
	JSONRPC string           `json:"jsonrpc"`
	Error   jsonRPCErrorBody `json:"error"`
	ID      *int             `json:"id"`
}

type jsonRPCErrorBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
