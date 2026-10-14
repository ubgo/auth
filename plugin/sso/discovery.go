package sso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

// discoveryPath is where an OpenID Connect issuer publishes its endpoints.
const discoveryPath = "/.well-known/openid-configuration"

// maxDocumentBytes bounds a discovery document or userinfo answer.
const maxDocumentBytes = 1 << 20

// DiscoveryCode names why discovery failed; each is better-auth's code.
type DiscoveryCode string

const (
	DiscoveryIssuerMismatch   DiscoveryCode = "issuer_mismatch"
	DiscoveryIncomplete       DiscoveryCode = "discovery_incomplete"
	DiscoveryNotFound         DiscoveryCode = "discovery_not_found"
	DiscoveryTimeout          DiscoveryCode = "discovery_timeout"
	DiscoveryInvalidURL       DiscoveryCode = "discovery_invalid_url"
	DiscoveryPrivateHost      DiscoveryCode = "discovery_private_host"
	DiscoveryInvalidJSON      DiscoveryCode = "discovery_invalid_json"
	DiscoveryRedirect         DiscoveryCode = "oidc_endpoint_redirect"
	DiscoveryUnsupportedAuth  DiscoveryCode = "unsupported_token_auth_method"
	DiscoveryUnexpectedFailed DiscoveryCode = "discovery_unexpected_error"
	DiscoveryUntrustedOrigin  DiscoveryCode = "discovery_untrusted_origin"
)

// DiscoveryCodeValues is every DiscoveryCode.
var DiscoveryCodeValues = []DiscoveryCode{DiscoveryIssuerMismatch, DiscoveryIncomplete, DiscoveryNotFound, DiscoveryTimeout,
	DiscoveryInvalidURL, DiscoveryPrivateHost, DiscoveryInvalidJSON, DiscoveryRedirect, DiscoveryUnsupportedAuth, DiscoveryUnexpectedFailed, DiscoveryUntrustedOrigin}

// discoveryErrors are the answers of each code, permanent like every code.
var discoveryErrors = map[DiscoveryCode]*auth.Error{
	DiscoveryIssuerMismatch:   auth.NewError("sso.issuer_mismatch", http.StatusBadRequest, "The provider's discovery document names another issuer."),
	DiscoveryIncomplete:       auth.NewError("sso.discovery_incomplete", http.StatusBadRequest, "The provider's discovery document lacks a required endpoint."),
	DiscoveryNotFound:         auth.NewError("sso.discovery_not_found", http.StatusBadRequest, "The provider's discovery document was not found."),
	DiscoveryTimeout:          auth.NewError("sso.discovery_timeout", http.StatusBadGateway, "The provider did not answer in time."),
	DiscoveryInvalidURL:       auth.NewError("sso.discovery_invalid_url", http.StatusBadRequest, "A provider URL is not valid; it must be https."),
	DiscoveryPrivateHost:      auth.NewError("sso.discovery_private_host", http.StatusBadRequest, "A provider URL points at a private address."),
	DiscoveryInvalidJSON:      auth.NewError("sso.discovery_invalid_json", http.StatusBadRequest, "The provider's discovery document is not valid JSON."),
	DiscoveryRedirect:         auth.NewError("sso.endpoint_redirect", http.StatusBadRequest, "A provider endpoint answered with a redirect."),
	DiscoveryUnsupportedAuth:  auth.NewError("sso.unsupported_token_auth", http.StatusBadRequest, "The provider supports no token authentication method this app can use."),
	DiscoveryUnexpectedFailed: auth.NewError("sso.discovery_failed", http.StatusBadGateway, "The provider's discovery document could not be read."),
	DiscoveryUntrustedOrigin:  auth.NewError("sso.discovery_untrusted_origin", http.StatusBadRequest, "A provider URL is not on this app's list of trusted identity providers."),
}

// DiscoveryError is a failed discovery: the code, and the cause for logs.
type DiscoveryError struct {
	Code DiscoveryCode
	Err  error
}

func (e *DiscoveryError) Error() string { return fmt.Sprintf("sso: discovery %s: %v", e.Code, e.Err) }

// Unwrap returns the answer for the code, so errors.Is(err, the *auth.Error)
// holds and the transport answers it.
func (e *DiscoveryError) Unwrap() []error { return []error{discoveryErrors[e.Code], e.Err} }

func discoveryErr(code DiscoveryCode, format string, args ...any) error {
	return &DiscoveryError{Code: code, Err: fmt.Errorf(format, args...)}
}

// DiscoveryDocument is the part of an OpenID Connect discovery document the
// plugin reads.
type DiscoveryDocument struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
}

// DiscoveryURL is where the document of cfg is read: DiscoveryEndpoint, or
// issuer + /.well-known/openid-configuration.
func DiscoveryURL(issuer string, cfg OIDCConfig) string {
	if cfg.DiscoveryEndpoint != "" {
		return cfg.DiscoveryEndpoint
	}
	return strings.TrimSuffix(issuer, "/") + discoveryPath
}

// NeedsRuntimeDiscovery reports whether an endpoint the flow needs is
// missing, so discovery runs again at sign-in.
func NeedsRuntimeDiscovery(cfg OIDCConfig) bool {
	return cfg.AuthorizationEndpoint == "" || cfg.TokenEndpoint == "" || cfg.JWKSEndpoint == ""
}

// Discover fills cfg's empty endpoints and token authentication from
// issuer's discovery document; values already set win. The document must
// name issuer exactly (trailing slash aside) and list the authorization,
// token and JWKS endpoints; relative endpoint paths are resolved against
// the issuer. With SkipDiscovery nothing is fetched and a missing endpoint
// is DiscoveryIncomplete.
func (p *Plugin) Discover(ctx context.Context, issuer string, cfg *OIDCConfig) error {
	if cfg.SkipDiscovery {
		if NeedsRuntimeDiscovery(*cfg) {
			return discoveryErr(DiscoveryIncomplete, "skipDiscovery needs authorization, token and JWKS endpoints")
		}
		if cfg.TokenEndpointAuthentication == "" {
			cfg.TokenEndpointAuthentication = oauth.ClientSecretBasic
		}
		return nil
	}
	u := DiscoveryURL(issuer, *cfg)
	if err := p.checkURL(u); err != nil {
		return err
	}
	doc, err := p.FetchDiscoveryDocument(ctx, u)
	if err != nil {
		return err
	}
	if err := ValidateDiscoveryDocument(doc, issuer); err != nil {
		return err
	}
	for _, f := range []struct {
		dst *string
		v   string
	}{{&cfg.AuthorizationEndpoint, doc.AuthorizationEndpoint}, {&cfg.TokenEndpoint, doc.TokenEndpoint},
		{&cfg.UserInfoEndpoint, doc.UserinfoEndpoint}, {&cfg.JWKSEndpoint, doc.JWKSURI}} {
		if *f.dst != "" || f.v == "" {
			continue
		}
		abs, err := NormalizeEndpoint(issuer, f.v)
		if err != nil {
			return discoveryErr(DiscoveryInvalidURL, "%v", err)
		}
		if err := p.checkURL(abs); err != nil {
			return err
		}
		*f.dst = abs
	}
	if cfg.DiscoveryEndpoint == "" {
		cfg.DiscoveryEndpoint = u
	}
	if cfg.TokenEndpointAuthentication == "" {
		m, err := SelectTokenAuth(doc.TokenAuthMethods)
		if err != nil {
			return err
		}
		cfg.TokenEndpointAuthentication = m
	}
	return nil
}

// ValidateDiscoveryDocument checks a document against the configured
// issuer: the same issuer (trailing slash aside), and the authorization,
// token and JWKS endpoints present.
func ValidateDiscoveryDocument(doc DiscoveryDocument, issuer string) error {
	if strings.TrimSuffix(doc.Issuer, "/") != strings.TrimSuffix(issuer, "/") {
		return discoveryErr(DiscoveryIssuerMismatch, "document issuer %q, want %q", doc.Issuer, issuer)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return discoveryErr(DiscoveryIncomplete, "document lacks authorization_endpoint, token_endpoint or jwks_uri")
	}
	return nil
}

// SelectTokenAuth picks the token-endpoint authentication from the methods a
// discovery document lists: client_secret_basic, then client_secret_post,
// then private_key_jwt; an empty list means client_secret_basic, the
// specification's default. A list naming none of the three is
// DiscoveryUnsupportedAuth.
func SelectTokenAuth(methods []string) (oauth.TokenAuth, error) {
	if len(methods) == 0 {
		return oauth.ClientSecretBasic, nil
	}
	for _, m := range []oauth.TokenAuth{oauth.ClientSecretBasic, oauth.ClientSecretPost, oauth.PrivateKeyJWT} {
		if slices.Contains(methods, string(m)) {
			return m, nil
		}
	}
	return "", discoveryErr(DiscoveryUnsupportedAuth, "methods %q", methods)
}

// NormalizeEndpoint resolves a discovered endpoint against the issuer: an
// absolute URL is kept, a path is joined to the issuer's origin and path
// ("/oauth/token" under "https://idp/tenant" is "https://idp/tenant/oauth/token").
func NormalizeEndpoint(issuer, endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("endpoint %q: %w", endpoint, err)
	}
	if u.IsAbs() {
		return endpoint, nil
	}
	base, err := url.Parse(strings.TrimSuffix(issuer, "/"))
	if err != nil || !base.IsAbs() {
		return "", fmt.Errorf("issuer %q is not an absolute URL", issuer)
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/" + strings.TrimPrefix(u.Path, "/")
	base.RawQuery = u.RawQuery
	return base.String(), nil
}

// fetchDiscovery GETs and decodes the document.
func (p *Plugin) FetchDiscoveryDocument(ctx context.Context, u string) (DiscoveryDocument, error) {
	var doc DiscoveryDocument
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return doc, discoveryErr(DiscoveryInvalidURL, "%v", err)
	}
	req.Header.Set("Accept", "application/json")
	res, err := p.hc.Do(req)
	if err != nil {
		return doc, classifyFetchError(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxDocumentBytes))
	if err != nil {
		return doc, discoveryErr(DiscoveryUnexpectedFailed, "%v", err)
	}
	switch {
	case res.StatusCode == http.StatusNotFound:
		return doc, discoveryErr(DiscoveryNotFound, "%s answered 404", u)
	case res.StatusCode/100 == 3:
		return doc, discoveryErr(DiscoveryRedirect, "%s answered %d", u, res.StatusCode)
	case res.StatusCode/100 != 2:
		return doc, discoveryErr(DiscoveryUnexpectedFailed, "%s answered %d", u, res.StatusCode)
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return doc, discoveryErr(DiscoveryInvalidJSON, "%v", err)
	}
	return doc, nil
}

// classifyFetchError maps a transport error onto its discovery code.
func classifyFetchError(err error) error {
	var ne net.Error
	switch {
	case errors.Is(err, errPrivateHost):
		return discoveryErr(DiscoveryPrivateHost, "%v", err)
	case errors.Is(err, errRedirect):
		return discoveryErr(DiscoveryRedirect, "%v", err)
	case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, context.DeadlineExceeded):
		return discoveryErr(DiscoveryTimeout, "%v", err)
	}
	return discoveryErr(DiscoveryUnexpectedFailed, "%v", err)
}

// checkURL refuses a provider URL that is not https (a trusted origin may
// be http), and one whose literal host is a private address. A host name
// is checked again when the guarded client connects.
func (p *Plugin) checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return discoveryErr(DiscoveryInvalidURL, "%q is not an absolute URL", raw)
	}
	if p.trustedOrigin(u) {
		return nil
	}
	if p.onlyTrusted {
		return discoveryErr(DiscoveryUntrustedOrigin, "%q", raw)
	}
	if u.Scheme != "https" {
		return discoveryErr(DiscoveryInvalidURL, "%q is not https", raw)
	}
	if ip, err := netip.ParseAddr(strings.Trim(u.Hostname(), "[]")); err == nil && !PublicAddr(ip) {
		return discoveryErr(DiscoveryPrivateHost, "%q", raw)
	}
	return nil
}

// trustedOrigin reports whether u's origin is a WithTrustedOrigins entry.
func (p *Plugin) trustedOrigin(u *url.URL) bool {
	origin := u.Scheme + "://" + u.Host
	return slices.ContainsFunc(p.trusted, func(t string) bool { return strings.EqualFold(strings.TrimSuffix(t, "/"), origin) })
}

// errPrivateHost and errRedirect are what the guarded client refuses.
var (
	errPrivateHost = errors.New("sso: refusing to connect to a private address")
	errRedirect    = errors.New("sso: provider endpoints must not redirect")
)

// cgnat is the carrier-grade NAT range, private in practice.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// PublicAddr reports whether ip is publicly routable: not loopback,
// private (RFC 1918, fc00::/7), link-local (169.254.0.0/16, which holds
// the cloud metadata address, and fe80::/10), carrier-grade NAT,
// multicast or unspecified.
func PublicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() &&
		!ip.IsInterfaceLocalMulticast() && !ip.IsMulticast() && !ip.IsUnspecified() && !cgnat.Contains(ip)
}

// guardedClient is the default IdP client: no redirects, no proxy, and a
// dialer that refuses a private address after DNS resolution, so a name
// that resolves to 169.254.169.254 or flips to 127.0.0.1 between a check
// and the connect is refused at the connect. trusted origins skip the
// address check.
func guardedClient(timeout time.Duration, trusted []string) *http.Client {
	trustedHosts := map[string]bool{}
	for _, t := range trusted {
		if u, err := url.Parse(t); err == nil {
			port := u.Port()
			if port == "" {
				port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
			}
			trustedHosts[strings.ToLower(net.JoinHostPort(u.Hostname(), port))] = true
		}
	}
	guarded := &net.Dialer{Timeout: timeout, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !PublicAddr(ip) {
			return fmt.Errorf("%w: %s", errPrivateHost, host)
		}
		return nil
	}}
	plain := &net.Dialer{Timeout: timeout}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if trustedHosts[strings.ToLower(addr)] {
			return plain.DialContext(ctx, network, addr)
		}
		return guarded.DialContext(ctx, network, addr)
	}
	return &http.Client{Timeout: timeout, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect }}
}
