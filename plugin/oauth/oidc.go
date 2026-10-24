package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ubgo/auth"
)

// discoveryPath is where an OpenID Connect issuer publishes its endpoints.
const discoveryPath = "/.well-known/openid-configuration"

// Discoverer is a provider that must look up its endpoints before its first
// flow. The plugin calls Discover at every start; an implementation caches.
//
//ds:def id=discoverer-rc677yzv owner=@khanakia stability=stable
type Discoverer interface {
	Discover(ctx context.Context, hc *http.Client) error
}

// OIDCProvider is any OpenID Connect issuer, configured from its discovery
// document: Okta, Auth0, Keycloak, Entra ID, Zitadel. The profile comes from
// the userinfo endpoint with the access token, which the specification makes
// authoritative, so no ID-token signature check is needed on this path.
//
// It discovers lazily at the first flow and caches the result on the value; a
// failed discovery is retried at the next flow rather than kept.
type OIDCProvider struct {
	ID           string
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	// TokenAuth, AuthParams, TokenParams, RefreshParams, OptionalScopes,
	// OptionalParams, TokenLifetime and ClientAssertion mean what they mean on OAuth2; they
	// are copied onto the discovered endpoints.
	TokenAuth       TokenAuth
	AuthParams      url.Values
	TokenParams     url.Values
	RefreshParams   url.Values
	OptionalScopes  []string
	OptionalParams  []string
	TokenLifetime   time.Duration
	ClientAssertion func(ctx context.Context, tokenURL string) (string, error)
	// SubjectClaim is the userinfo claim taken as the account's subject
	// instead of sub, for an issuer whose stable identifier is another claim
	// (Entra ID's oid, which survives a tenant's app re-registration where
	// sub does not). Empty is sub.
	SubjectClaim string
	// RevokeURL overrides the discovery document's revocation_endpoint;
	// empty takes the discovered one, and unlink revokes stored tokens there.
	RevokeURL string
	// IDToken configures ID-token sign-in. JWKSURL and Issuers are filled
	// from the discovery document (jwks_uri and the configured issuer) when
	// left empty, so an OIDC provider accepts ID tokens with no extra field;
	// Audiences, ProfileFromToken and RequireNonce are copied as given.
	IDToken IDTokenConfig
	// EndSessionURL overrides the discovery document's end_session_endpoint;
	// empty takes the discovered one.
	EndSessionURL string
	// Headers means what it means on OAuth2: added to every token, refresh
	// and revocation request at the discovered endpoints.
	Headers http.Header
	// DiscoveryHeaders are added to the discovery request, for an issuer
	// behind a gateway that wants a header on it; Authorization is ignored,
	// since a discovery document is public and takes no credential.
	DiscoveryHeaders http.Header
	// GetToken means what it means on OAuth2: it replaces the code exchange
	// at the discovered token endpoint.
	GetToken func(ctx context.Context, code, verifier, redirectURI string) (TokenSet, error)
	// DisplayName is the provider's name for people, as on OAuth2; the
	// presets set it, and empty falls back to ID.
	DisplayName string
	// Fallback are static endpoints used ONLY while the discovery document
	// cannot be fetched (a transport error, a status other than 2xx, a body
	// that is not JSON), so an issuer whose discovery is down still signs
	// people in. A document that arrives but names another issuer or lacks
	// an endpoint is still refused: the issuer answered, and what it said is
	// wrong. Each use is logged at Warn on Logger, and discovery is tried
	// again after discoveryRetryInterval. The zero value has no fallback: a
	// failed discovery fails that flow with ErrProviderFailed, as before.
	Fallback Endpoints
	// Logger receives the fallback warning; nil is slog.Default(). The oauth
	// plugin sets it to the core's logger when it is nil.
	Logger *slog.Logger

	mu    sync.Mutex
	oauth *OAuth2
	// fallback is the provider built from Fallback, kept (with its key
	// cache) across uses; fallbackUntil is when discovery is tried again.
	fallback      *OAuth2
	fallbackUntil time.Time
	// now is the clock of the ID-token verifier and of the fallback
	// window, set by tests.
	now func() time.Time
}

// Endpoints are an OpenID Connect issuer's endpoints written down by hand,
// for OIDCProvider.Fallback. AuthURL, TokenURL and UserInfoURL are required
// once any field is set (ErrFallbackIncomplete); the others are optional,
// as in a discovery document.
//
//ds:def id=oidc-endpoints-r6tw2nqk owner=@khanakia stability=stable
type Endpoints struct {
	AuthURL     string
	TokenURL    string
	UserInfoURL string
	// JWKSURL is the key set, for ID tokens; empty accepts none while the
	// fallback is in use.
	JWKSURL       string
	EndSessionURL string
	RevokeURL     string
	// IssParameterSupported is the discovery flag of RFC 9207: set it when
	// the issuer sends iss on every authorization response, so the callback
	// keeps checking it while the fallback is in use.
	IssParameterSupported bool
}

// Enabled reports whether any endpoint is set.
func (e Endpoints) Enabled() bool { return e != (Endpoints{}) }

// ErrFallbackIncomplete is a configuration error: an OIDCProvider.Fallback
// with some endpoint set but no AuthURL, TokenURL or UserInfoURL, which
// could not sign anyone in.
var ErrFallbackIncomplete = errors.New("oauth: an OIDC Fallback needs AuthURL, TokenURL and UserInfoURL")

// discoveryRetryInterval is how long a fallback is used before discovery is
// tried again: long enough that a down issuer does not cost every flow a
// discovery timeout, short enough that a recovered one is back within the
// minute.
//
//ds:def id=discoveryretryinterval-k7xq3wnt owner=@khanakia stability=stable
const discoveryRetryInterval = time.Minute

// errDiscoveryUnreachable marks a discovery document that could not be
// fetched or parsed, the only failure the fallback covers.
var errDiscoveryUnreachable = errors.New("oauth: discovery document unreachable")

// OIDC builds a provider for issuer. name is the route segment and the stored
// provider name, such as "okta".
//
//ds:def id=oidc-eb7uu7dy owner=@khanakia stability=stable
func OIDC(name, issuer, clientID, clientSecret string) *OIDCProvider {
	return &OIDCProvider{ID: name, Issuer: strings.TrimSuffix(issuer, "/"), ClientID: clientID, ClientSecret: clientSecret,
		Scopes: openIDScopes()}
}

// discoveryDoc is the part of the discovery document the provider reads.
type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	// IssParameterSupported is RFC 9207's discovery flag: the issuer puts
	// iss in every authorization response, so the callback may require it.
	IssParameterSupported bool `json:"authorization_response_iss_parameter_supported"`
}

// Name returns ID, the route segment and stored provider name.
func (o *OIDCProvider) Name() string { return o.ID }

// Label returns DisplayName, or ID when it is empty.
func (o *OIDCProvider) Label() string { return firstOf(o.DisplayName, o.ID) }

// withDisplayName sets a preset's DisplayName.
func withDisplayName(o *OIDCProvider, name string) *OIDCProvider {
	o.DisplayName = name
	return o
}

// Discover reads the discovery document once. It refuses a document whose
// issuer is not the configured one, the check the specification requires so a
// redirected discovery URL cannot hand the flow to another issuer.
func (o *OIDCProvider) Discover(ctx context.Context, hc *http.Client) error {
	_, err := o.discover(ctx, hc)
	return err
}

// discover returns the discovered endpoints, reading the document on first
// use. Returning them, rather than having callers read o.oauth afterwards,
// means no caller can observe "discovered successfully but not configured".
// While the document is unreachable and a Fallback is set, the fallback
// endpoints are returned instead, for discoveryRetryInterval at a time.
func (o *OIDCProvider) discover(ctx context.Context, hc *http.Client) (*OAuth2, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.oauth != nil {
		return o.oauth, nil
	}
	now := o.clock()
	if o.fallback != nil && now.Before(o.fallbackUntil) {
		return o.fallback, nil
	}
	doc, err := o.fetchDiscovery(ctx, hc)
	switch {
	case err == nil:
		o.oauth = o.build(doc)
		return o.oauth, nil
	case errors.Is(err, errDiscoveryUnreachable) && o.Fallback.Enabled():
		o.logger().Warn("oauth: discovery unreachable, using the fallback endpoints", "provider", o.ID, "issuer", o.Issuer, "error", err)
		if o.fallback == nil {
			f := o.Fallback
			o.fallback = o.build(discoveryDoc{
				Issuer: o.Issuer, AuthorizationEndpoint: f.AuthURL, TokenEndpoint: f.TokenURL, UserinfoEndpoint: f.UserInfoURL,
				JWKSURI: f.JWKSURL, EndSessionEndpoint: f.EndSessionURL, RevocationEndpoint: f.RevokeURL, IssParameterSupported: f.IssParameterSupported,
			})
		}
		o.fallbackUntil = now.Add(discoveryRetryInterval)
		return o.fallback, nil
	}
	return nil, err
}

// fetchDiscovery reads and checks the discovery document. A transport
// error, a status other than 2xx or a body that is not JSON is
// errDiscoveryUnreachable; a document naming another issuer or lacking an
// endpoint is ErrExchange, which no fallback covers.
func (o *OIDCProvider) fetchDiscovery(ctx context.Context, hc *http.Client) (discoveryDoc, error) {
	var doc discoveryDoc
	body, status, err := getDocument(ctx, hc, o.Issuer+discoveryPath, o.DiscoveryHeaders)
	switch {
	case err != nil:
		return doc, fmt.Errorf("%w: %w", errDiscoveryUnreachable, err)
	case status/100 != 2:
		return doc, fmt.Errorf("%w: %w: %s answered %d", errDiscoveryUnreachable, ErrExchange, o.Issuer, status)
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return doc, fmt.Errorf("%w: %w: %v", errDiscoveryUnreachable, ErrExchange, err)
	}
	if strings.TrimSuffix(doc.Issuer, "/") != o.Issuer {
		return doc, fmt.Errorf("%w: discovery issuer %q, want %q", ErrExchange, doc.Issuer, o.Issuer)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.UserinfoEndpoint == "" {
		return doc, fmt.Errorf("%w: discovery document lacks an endpoint", ErrExchange)
	}
	return doc, nil
}

// getDocument GETs a public JSON document with extra headers (Authorization
// ignored: a public document takes no credential) and returns the body, at
// most maxProviderBody bytes, with the status, which the caller judges.
func getDocument(ctx context.Context, hc *http.Client, u string, hdr http.Header) (json.RawMessage, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: request %v", ErrExchange, err)
	}
	req.Header.Set(headerAccept, contentTypeJSON)
	for k, vs := range hdr {
		if !strings.EqualFold(k, headerAuthorization) {
			req.Header[http.CanonicalHeaderKey(k)] = vs
		}
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrExchange, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxProviderBody))
	_, _ = io.Copy(io.Discard, res.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrExchange, err)
	}
	return body, res.StatusCode, nil
}

// build turns a discovery document, or the Fallback written as one, into
// the provider every flow runs on.
func (o *OIDCProvider) build(doc discoveryDoc) *OAuth2 {
	idc := o.IDToken
	if idc.JWKSURL == "" {
		idc.JWKSURL = doc.JWKSURI
	}
	if len(idc.Issuers) == 0 {
		idc.Issuers = []string{o.Issuer}
	}
	iss := ""
	if doc.IssParameterSupported {
		iss = o.Issuer
	}
	return &OAuth2{
		ID: o.ID, DisplayName: o.DisplayName, ClientID: o.ClientID, ClientSecret: o.ClientSecret, Scopes: o.Scopes,
		AuthURL: doc.AuthorizationEndpoint, TokenURL: doc.TokenEndpoint,
		FetchProfile: UserInfoProfile(doc.UserinfoEndpoint, o.SubjectClaim),
		TokenAuth:    o.TokenAuth, AuthParams: o.AuthParams, TokenParams: o.TokenParams, RefreshParams: o.RefreshParams,
		OptionalScopes: o.OptionalScopes, OptionalParams: o.OptionalParams, TokenLifetime: o.TokenLifetime, ClientAssertion: o.ClientAssertion,
		IDToken: idc, EndSessionURL: firstOf(o.EndSessionURL, doc.EndSessionEndpoint), RevokeURL: firstOf(o.RevokeURL, doc.RevocationEndpoint),
		AuthorizationIssuer: iss, Headers: o.Headers, GetToken: o.GetToken, now: o.now,
	}
}

// clock is the test clock when set, else the wall clock.
func (o *OIDCProvider) clock() time.Time {
	if o.now != nil {
		return o.now()
	}
	return time.Now()
}

// logger is Logger, or slog.Default when none was set.
func (o *OIDCProvider) logger() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return slog.Default()
}

// current is the provider flows run on now: the discovered one, else the
// fallback in use, else nil (before the first discovery).
func (o *OIDCProvider) current() *OAuth2 {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.oauth != nil {
		return o.oauth
	}
	return o.fallback
}

// ExpectedIssuer returns the iss the callback must carry: the configured
// issuer when the discovery document says it is sent, "" otherwise or before
// discovery (the plugin discovers at start, before any callback).
func (o *OIDCProvider) ExpectedIssuer() string {
	c := o.current()
	if c == nil {
		return ""
	}
	return c.AuthorizationIssuer
}

// FetchProfileWith reads the userinfo endpoint with the tokens' access token.
func (o *OIDCProvider) FetchProfileWith(ctx context.Context, hc *http.Client, ts TokenSet) (Profile, error) {
	c, err := o.discover(ctx, hc)
	if err != nil {
		return Profile{}, err
	}
	return c.FetchProfileWith(ctx, hc, ts)
}

// Revoke revokes the tokens at the discovered revocation_endpoint; nothing
// when the issuer publishes none.
func (o *OIDCProvider) Revoke(ctx context.Context, hc *http.Client, ts TokenSet) error {
	c, err := o.discover(ctx, hc)
	if err != nil {
		return err
	}
	return c.Revoke(ctx, hc, ts)
}

// AuthCodeURL builds the authorization URL from the discovered endpoint. It
// returns "" before discovery; the plugin always discovers first.
func (o *OIDCProvider) AuthCodeURL(state, challenge, redirectURI string) string {
	return o.AuthCodeURLWithParams(state, challenge, redirectURI, RequestParams{})
}

// AuthCodeURLWithParams is AuthCodeURL with the request's parameters.
func (o *OIDCProvider) AuthCodeURLWithParams(state, challenge, redirectURI string, rp RequestParams) string {
	c := o.current()
	if c == nil {
		return ""
	}
	return c.AuthCodeURLWithParams(state, challenge, redirectURI, rp)
}

// OptionalScopeList returns OptionalScopes.
func (o *OIDCProvider) OptionalScopeList() []string { return o.OptionalScopes }

// OptionalParamList returns OptionalParams.
func (o *OIDCProvider) OptionalParamList() []string { return o.OptionalParams }

// Refresh runs the refresh grant at the discovered token endpoint.
func (o *OIDCProvider) Refresh(ctx context.Context, hc *http.Client, refreshToken auth.Token) (TokenSet, error) {
	c, err := o.discover(ctx, hc)
	if err != nil {
		return TokenSet{}, err
	}
	return c.Refresh(ctx, hc, refreshToken)
}

// EndSession returns the issuer's end_session_endpoint, discovering first;
// "" when the issuer publishes none.
func (o *OIDCProvider) EndSession(ctx context.Context, hc *http.Client) (string, error) {
	c, err := o.discover(ctx, hc)
	if err != nil {
		return "", err
	}
	return c.EndSessionURL, nil
}

// Exchange trades the code for the profile through the discovered endpoints.
func (o *OIDCProvider) Exchange(ctx context.Context, hc *http.Client, code, verifier, redirectURI string) (Profile, error) {
	c, err := o.discover(ctx, hc)
	if err != nil {
		return Profile{}, err
	}
	return c.Exchange(ctx, hc, code, verifier, redirectURI)
}
