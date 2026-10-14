package jwt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/ubgo/auth"
)

// Route and header constants.
const (
	// DefaultJWKSPath is where the key set is served under the plugin's
	// prefix (GET <mount>/jwt/jwks) unless JWKSPath moves it.
	//ds:def id=defaultjwkspath-t3vk9q2w owner=@khanakia stability=stable
	DefaultJWKSPath = "/jwks"
	// tokenPath is the token route; JWKSPath may not take it, nor
	// templatePath.
	tokenPath = "/token"
	// SetJWTHeader is the response header IssueOnSession puts a fresh token
	// in on the session read, better-auth's set-auth-jwt. The transport also
	// lists it in Access-Control-Expose-Headers, so a script on another
	// origin can read it.
	//ds:def id=setjwtheader-p6xr2m4c owner=@khanakia stability=stable
	SetJWTHeader = "Set-Auth-JWT"
	// pathParentSegment is what JWKSPath may never contain, so a path can
	// never climb out of the plugin's prefix once a proxy normalises it.
	pathParentSegment = ".."
	// pathUnreserved is every character a JWKSPath may hold besides "/":
	// RFC 3986's unreserved set, so the path needs no escaping anywhere.
	pathUnreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	// pathSeparator separates the segments of a path.
	pathSeparator = "/"
	// schemeHTTPS is the scheme RemoteJWKS needs, and schemeHTTP the one it
	// allows for a loopback host only, for development.
	schemeHTTPS = "https"
	schemeHTTP  = "http"
	// hostLocalhost is the loopback name RemoteJWKS allows over http.
	hostLocalhost = "localhost"
)

// Route and remote key-set errors, returned by auth.New.
var (
	// ErrJWKSPath is a JWKSPath that does not start with "/", is "/" alone,
	// contains "..", "//" or a character outside RFC 3986's unreserved set,
	// or is the token or template route's path.
	ErrJWKSPath = errors.New(`jwt: JWKSPath must start with "/", hold only letters, digits and "-._~/", contain no ".." or "//", and not be "/token" or "/template"`)
	// ErrRemoteJWKS is a RemoteJWKS URL that is not an absolute https URL
	// (http is allowed for a loopback host), or carries a fragment or user
	// information.
	ErrRemoteJWKS = errors.New("jwt: RemoteJWKS needs an absolute https URL (http only for a loopback host)")
)

// JWKSPath moves the key-set route from DefaultJWKSPath to path, under the
// plugin's prefix: JWKSPath("/.well-known/jwks.json") serves GET
// <mount>/jwt/.well-known/jwks.json, and the old path answers 404.
// better-auth's jwks.jwksPath; the same rules apply (it starts with "/" and
// has no ".."), plus the characters a route may hold here (ErrJWKSPath).
//
//ds:def id=jwkspath-c7n4wq8z owner=@khanakia stability=stable
func JWKSPath(path string) Option { return func(p *Plugin) { p.jwksPath = path } }

// RemoteJWKS says the key set is published somewhere else, such as a KMS's
// own JWKS endpoint or a CDN: the local key-set route is not served (404),
// and JWKSURL returns rawURL for the app to hand to its verifiers
// (jwt.NewRemoteKeys(url, nil) in Go, createRemoteJWKSet in jose, the "JWKS
// URI" field of an API gateway). better-auth's jwks.remoteUrl, which it
// advertises in its OpenID discovery document; this library has no
// discovery document, and no token carries the URL (no "jku" header): a
// verifier that followed a URL named by the token it is verifying would let
// the token choose its own keys. The keys at rawURL must include every key
// the plugin's Signer publishes, or the tokens will not verify; the session
// cache keeps verifying against the plugin's own keys either way.
//
//ds:def id=remotejwks-r2k8vm5d owner=@khanakia stability=stable
func RemoteJWKS(rawURL string) Option { return func(p *Plugin) { p.remoteJWKS = rawURL } }

// IssueOnSession makes the session read (GET <mount>/session, Auth.Session,
// every transport) also mint a token and hand it to the client in the
// SetJWTHeader response header: better-auth's set-auth-jwt, which it sends
// unless disableSettingJwtHeader. Off by default here, because a token in
// every session read is a bearer credential handed out on every page load
// whether the client wants one or not. The token is exactly the one POST
// <mount>/jwt/token returns at that instant (the same claims, TTL, signer
// and audience), there is none when the caller is signed out (the session
// read answers 401), and a failure to mint fails the session read, as a
// failing after-hook does in better-auth. A Go caller reads it with
// SessionJWT(ctx) after calling Auth.Session.
//
//ds:def id=issueonsession-h5q9wz3b owner=@khanakia stability=stable
func IssueOnSession() Option { return func(p *Plugin) { p.issueOnSession = true } }

// JWKSURL is where verifiers fetch the key set when it is published
// elsewhere: the RemoteJWKS URL, or "" when the plugin serves it itself, at
// JWKSRoute under the app's mount prefix.
func (p *Plugin) JWKSURL() string { return p.remoteJWKS }

// JWKSRoute is the key-set route under the app's mount prefix ("/jwt/jwks"
// by default, the JWKSPath otherwise), or "" when RemoteJWKS publishes the
// keys elsewhere and the route is not served.
func (p *Plugin) JWKSRoute() string {
	if p.remoteJWKS != "" {
		return ""
	}
	return p.jwks.Route()
}

// OperationHooks adds, under IssueOnSession, the after-hook on the session
// read that mints the header token; nothing otherwise.
func (p *Plugin) OperationHooks() []auth.OperationHook {
	if !p.issueOnSession {
		return nil
	}
	return []auth.OperationHook{{
		Match: []auth.EndpointID{auth.EndpointSession},
		After: func(ctx context.Context, c *auth.Call, _ any) error {
			res, err := p.mint(ctx, c)
			if err != nil {
				return err
			}
			c.Effects.Header(SetJWTHeader, res.Token)
			return nil
		},
	}}
}

// SessionJWT returns the token IssueOnSession handed out during the request
// in ctx, for a Go caller of Auth.Session, which has no response headers to
// read; false when there is none (the option is off, the caller is signed
// out, or the session was not read).
func SessionJWT(ctx context.Context) (string, bool) {
	for _, e := range auth.RequestEffects(ctx) {
		if e.Kind == auth.EffectHeader && e.Name == SetJWTHeader {
			return e.Value, true
		}
	}
	return "", false
}

// validateRoutes checks JWKSPath and RemoteJWKS for Validate.
func (p *Plugin) validateRoutes() error {
	if err := validJWKSPath(p.jwksPath); err != nil {
		return err
	}
	if p.remoteJWKS == "" {
		return nil
	}
	return validRemoteJWKS(p.remoteJWKS)
}

// validJWKSPath applies better-auth's rules (starts with "/", no "..") and
// this library's route rules: unreserved characters only, no empty segment,
// and not the token route.
func validJWKSPath(path string) error {
	if len(path) < 2 || !strings.HasPrefix(path, pathSeparator) || strings.Contains(path, pathParentSegment) ||
		strings.Contains(path, pathSeparator+pathSeparator) || path == tokenPath || path == templatePath {
		return fmt.Errorf("%w: %q", ErrJWKSPath, path)
	}
	for _, r := range path {
		if !strings.ContainsRune(pathUnreserved+pathSeparator, r) {
			return fmt.Errorf("%w: %q", ErrJWKSPath, path)
		}
	}
	return nil
}

// validRemoteJWKS needs an absolute https URL with a host and no fragment or
// user information; http is allowed only for a loopback host, because a key
// set fetched in clear text lets anyone on the path substitute keys.
func validRemoteJWKS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("%w: %q", ErrRemoteJWKS, raw)
	}
	switch u.Scheme {
	case schemeHTTPS:
		return nil
	case schemeHTTP:
		host := u.Hostname()
		if ip := net.ParseIP(host); host == hostLocalhost || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrRemoteJWKS, raw)
}
