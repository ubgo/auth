package oidcclient

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// ProviderMetadata is the part of the login server's discovery document
// (OpenID Connect Discovery 1.0, RFC 8414) the package reads, under the
// member names the server publishes. It is fetched from
// Issuer/.well-known/openid-configuration on first use and cached, or given
// once with WithDiscovery for a server without discovery or a test.
//
// Whichever way it arrives, Issuer must equal Config.Issuer (a trailing
// slash aside) and every endpoint must be https (http on a loopback host),
// or sign-in fails: a document naming another issuer is the mix-up attack.
type ProviderMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserInfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
	// EndSessionEndpoint is RP-Initiated Logout's; without one (Google),
	// sign-out ends the app's session only.
	EndSessionEndpoint    string `json:"end_session_endpoint,omitempty"`
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint    string `json:"revocation_endpoint,omitempty"`
	// CodeChallengeMethodsSupported, when listed, must include S256; S256 is
	// sent whether listed or not (some servers support PKCE without saying).
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
	// IDTokenSigningAlgValuesSupported is informational: the accepted
	// algorithms are the package's fixed set, whatever the server lists.
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
	// IssParameterSupported (RFC 9207) makes the callback require an iss
	// parameter equal to the issuer; without it an iss sent is still checked.
	IssParameterSupported             bool `json:"authorization_response_iss_parameter_supported,omitempty"`
	BackchannelLogoutSupported        bool `json:"backchannel_logout_supported,omitempty"`
	BackchannelLogoutSessionSupported bool `json:"backchannel_logout_session_supported,omitempty"`
}

// ClientAuthRequest is a token, introspection or revocation request about
// to be sent, for a ClientAuth to authenticate. Endpoint is the URL it goes
// to (the audience of a private_key_jwt assertion); Form and Header are
// sent as they are after Authenticate returns.
type ClientAuthRequest struct {
	Endpoint string
	Form     url.Values
	Header   http.Header
}

// ClientAuth authenticates the client at the login server's endpoints. The
// default is client_secret_basic with Config.ClientSecret; WithClientAuth
// sets another: ClientSecretPost, PublicClient, or the app's own for
// private_key_jwt or a KMS-held key. mTLS needs no ClientAuth: it is the
// HTTP client's certificate (WithHTTPClient) with PublicClient.
type ClientAuth interface {
	Authenticate(ctx context.Context, req ClientAuthRequest) error
}

// ClientAuthFunc adapts a function to ClientAuth.
type ClientAuthFunc func(ctx context.Context, req ClientAuthRequest) error

// Authenticate calls f.
func (f ClientAuthFunc) Authenticate(ctx context.Context, req ClientAuthRequest) error {
	return f(ctx, req)
}

// ClientSecretBasic sends the client id and secret as HTTP Basic (RFC 6749
// section 2.3.1), each form-encoded first as the RFC requires. It is what a
// non-empty Config.ClientSecret means.
func ClientSecretBasic(clientID string, secret Secret) ClientAuth {
	return ClientAuthFunc(func(_ context.Context, req ClientAuthRequest) error {
		cred := url.QueryEscape(clientID) + ":" + url.QueryEscape(secret.Reveal())
		req.Header.Set(headerAuthorization, schemeBasic+base64.StdEncoding.EncodeToString([]byte(cred)))
		return nil
	})
}

// ClientSecretPost sends the client id and secret in the form body, for a
// server that does not accept Basic.
func ClientSecretPost(clientID string, secret Secret) ClientAuth {
	return ClientAuthFunc(func(_ context.Context, req ClientAuthRequest) error {
		req.Form.Set(paramClientID, clientID)
		req.Form.Set(paramClientSecret, secret.Reveal())
		return nil
	})
}

// PublicClient sends only the client id: a client with no secret, which
// PKCE alone protects, or one authenticated by mTLS. It is explicit, so an
// empty ClientSecret is never mistaken for a public client.
func PublicClient(clientID string) ClientAuth {
	return ClientAuthFunc(func(_ context.Context, req ClientAuthRequest) error {
		req.Form.Set(paramClientID, clientID)
		return nil
	})
}

// Provider calls the login server as this client: the discovery document,
// the token, introspection and userinfo endpoints, each with the client's
// ClientAuth and HTTP client. The package's own flows use it, a Rechecker
// gets it, and Client.Provider returns it for anything else.
//
// Every method applies the floors itself (an ID token from a refresh is
// verified and must name the session's iss and sub), and classifies every
// failure: ErrProviderRefused for the server's "no",
// ErrProviderUnavailable for no answer.
type Provider struct {
	c *Client
	// meta guards the discovery document: fetched once, kept for the
	// Client's life (the key set, which does rotate, has its own cache).
	metaMu       sync.Mutex
	meta         *ProviderMetadata
	metaErr      error
	metaFailedAt time.Time
	jwks         jwksCache
}

// discoveryRetry is how long a failed discovery is answered from memory
// before the next request tries again, so an outage of the login server
// is not multiplied by every request of every person.
const discoveryRetry = time.Minute

// wellKnownOpenID is the discovery document's path under the issuer
// (OpenID Connect Discovery 1.0 section 4).
const wellKnownOpenID = "/.well-known/openid-configuration"

// pkceS256 is the only PKCE method the package sends (RFC 7636 section 4.2).
const pkceS256 = "S256"

// Metadata returns the discovery document, fetching it on the first call
// and again, at most once a minute, after a failure. A failure is
// ErrProviderUnavailable (no answer) or ErrInvalidConfig (a document that
// names another issuer, or an endpoint that is not https).
func (p *Provider) Metadata(ctx context.Context) (ProviderMetadata, error) {
	p.metaMu.Lock()
	defer p.metaMu.Unlock()
	if p.meta != nil {
		return *p.meta, nil
	}
	now := p.c.set.now()
	if p.metaErr != nil && now.Sub(p.metaFailedAt) < discoveryRetry {
		return ProviderMetadata{}, p.metaErr
	}
	m, err := p.fetchMetadata(ctx)
	if err != nil {
		p.metaErr, p.metaFailedAt = err, now
		return ProviderMetadata{}, err
	}
	p.meta, p.metaErr = &m, nil
	p.warnNoRevocation(m)
	return m, nil
}

// warnNoRevocation logs, once per discovery document, that the server
// publishes no revocation endpoint: sign-out then cannot revoke the
// session's refresh token, and under the stateless CookieStore a cookie
// copy saved before sign-out keeps working until its refresh is refused.
func (p *Provider) warnNoRevocation(m ProviderMetadata) {
	if m.RevocationEndpoint == "" {
		p.c.set.logger.Warn("oidcclient: the login server publishes no revocation_endpoint; logout cannot revoke the refresh token, " +
			"so with the cookie store a saved cookie copy keeps working until the server refuses its refresh")
	}
}

// revokeRefreshToken revokes a refresh token at the revocation endpoint
// (RFC 7009) with the client's ClientAuth. A server without the endpoint
// is errNoRevocation; RFC 7009 answers 200 even for a token it does not
// know, so any 200 is success.
func (p *Provider) revokeRefreshToken(ctx context.Context, token Secret) error {
	meta, err := p.Metadata(ctx)
	if err != nil {
		return err
	}
	if meta.RevocationEndpoint == "" {
		return errNoRevocation
	}
	_, err = p.postAuthenticated(ctx, meta.RevocationEndpoint, url.Values{paramToken: {token.Reveal()}, paramTokenTypeHint: {string(HintRefreshToken)}})
	return err
}

// errNoRevocation is a logout at a server that publishes no revocation
// endpoint; warnNoRevocation has already said so at discovery.
var errNoRevocation = errors.New("oidcclient: the login server publishes no revocation_endpoint")

// fetchMetadata reads and checks the discovery document.
func (p *Provider) fetchMetadata(ctx context.Context) (ProviderMetadata, error) {
	u := strings.TrimSuffix(p.c.cfg.Issuer, "/") + wellKnownOpenID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ProviderMetadata{}, fmt.Errorf("%w: discovery URL: %w", ErrInvalidConfig, err)
	}
	req.Header.Set(headerAccept, mediaTypeJSON)
	body, err := p.send(req)
	if err != nil {
		if errors.Is(err, ErrProviderRefused) {
			// A 404 or 403 on discovery says nothing about any person; the
			// server is unusable until it serves the document.
			return ProviderMetadata{}, fmt.Errorf("%w: %w", ErrProviderUnavailable, err)
		}
		return ProviderMetadata{}, err
	}
	var m ProviderMetadata
	if err := decodeJSON(u, body, &m); err != nil {
		return ProviderMetadata{}, err
	}
	if err := m.validate(p.c.cfg.Issuer); err != nil {
		return ProviderMetadata{}, err
	}
	return m, nil
}

// validate holds a discovery document, fetched or given, to the floors:
// the configured issuer (a trailing slash aside), the endpoints sign-in
// needs, every endpoint https (http on a loopback host), and S256 among the
// PKCE methods when the server lists any.
func (m ProviderMetadata) validate(issuer string) error {
	var errs error
	if strings.TrimSuffix(m.Issuer, "/") != strings.TrimSuffix(issuer, "/") {
		errs = errors.Join(errs, fmt.Errorf("%w: discovery issuer %q is not Config.Issuer %q", ErrInvalidConfig, m.Issuer, issuer))
	}
	for _, e := range []struct {
		name, value string
		required    bool
	}{
		{"authorization_endpoint", m.AuthorizationEndpoint, true}, {"token_endpoint", m.TokenEndpoint, true},
		{"jwks_uri", m.JWKSURI, true}, {"userinfo_endpoint", m.UserInfoEndpoint, false},
		{"end_session_endpoint", m.EndSessionEndpoint, false}, {"introspection_endpoint", m.IntrospectionEndpoint, false},
		{"revocation_endpoint", m.RevocationEndpoint, false},
	} {
		if e.value == "" && !e.required {
			continue
		}
		if err := checkEndpoint(e.name, e.value); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	if len(m.CodeChallengeMethodsSupported) > 0 && !slices.Contains(m.CodeChallengeMethodsSupported, pkceS256) {
		errs = errors.Join(errs, fmt.Errorf("%w: the server does not support PKCE S256", ErrInvalidConfig))
	}
	return errs
}

// checkEndpoint checks a discovered endpoint: absolute, https or http on a
// loopback host, no user info or fragment. A query is allowed (an
// authorization endpoint may carry one).
func checkEndpoint(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%w: %s %q is not an absolute URL", ErrInvalidConfig, name, raw)
	}
	if u.Scheme == schemeHTTPS || (u.Scheme == schemeHTTP && isLoopbackHost(u.Hostname())) {
		return nil
	}
	return fmt.Errorf("%w: %s %q must be https (http only on a loopback host)", ErrInvalidConfig, name, raw)
}

// OAuth parameter names the package sends (RFC 6749, RFC 7636, RFC 7662).
const (
	paramGrantType     = "grant_type"
	paramCode          = "code"
	paramRedirectURI   = "redirect_uri"
	paramCodeVerifier  = "code_verifier"
	paramRefreshToken  = "refresh_token"
	paramClientID      = "client_id"
	paramClientSecret  = "client_secret"
	paramToken         = "token"
	paramTokenTypeHint = "token_type_hint"
	grantAuthCode      = "authorization_code"
	grantRefresh       = "refresh_token"
)

// tokenResponse is the token endpoint's answer (RFC 6749 section 5.1,
// OpenID Connect Core section 3.1.3.3), in the member names
// plugin/oauthprovider's TokenResponse writes.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

// postAuthenticated POSTs form to endpoint with the client's ClientAuth
// and returns the 200 body.
func (p *Provider) postAuthenticated(ctx context.Context, endpoint string, form url.Values) ([]byte, error) {
	header := http.Header{}
	if err := p.c.set.clientAuth.Authenticate(ctx, ClientAuthRequest{Endpoint: endpoint, Form: form, Header: header}); err != nil {
		// The app's own authenticator failed (a KMS that did not sign): no
		// request was sent, so this is not the server's "no".
		return nil, fmt.Errorf("oidcclient: client authentication: %w", err)
	}
	body := form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidConfig, endpoint, err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set(headerContentType, mediaTypeForm)
	req.Header.Set(headerAccept, mediaTypeJSON)
	return p.send(req)
}

// tokenGrant runs one grant at the token endpoint and returns its answer,
// with the token type checked: a token this package would send as Bearer
// must have been issued as one.
func (p *Provider) tokenGrant(ctx context.Context, form url.Values) (tokenResponse, error) {
	meta, err := p.Metadata(ctx)
	if err != nil {
		return tokenResponse{}, err
	}
	body, err := p.postAuthenticated(ctx, meta.TokenEndpoint, form)
	if err != nil {
		return tokenResponse{}, err
	}
	var tr tokenResponse
	if err := decodeJSON(meta.TokenEndpoint, body, &tr); err != nil {
		return tokenResponse{}, err
	}
	if tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, tokenTypeBearer) {
		return tokenResponse{}, fmt.Errorf("%w: token answer without a Bearer access token (token_type %q)", ErrProviderUnavailable, tr.TokenType)
	}
	return tr, nil
}

// tokensOf turns a token answer into Tokens, the access expiry computed on
// the Client's clock.
func (p *Provider) tokensOf(tr tokenResponse) Tokens {
	t := Tokens{AccessToken: Secret(tr.AccessToken), RefreshToken: Secret(tr.RefreshToken), IDToken: Secret(tr.IDToken), Scope: tr.Scope}
	if tr.ExpiresIn > 0 {
		t.AccessExpiresAt = p.c.set.now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return t
}

// exchange redeems an authorization code with its PKCE verifier and
// verifies the ID token the answer must carry against the flow's nonce.
func (p *Provider) exchange(ctx context.Context, code, verifier, nonce string) (Tokens, Identity, error) {
	tr, err := p.tokenGrant(ctx, url.Values{
		paramGrantType: {grantAuthCode}, paramCode: {code}, paramRedirectURI: {p.c.redirectURI()}, paramCodeVerifier: {verifier},
	})
	if err != nil {
		return Tokens{}, Identity{}, err
	}
	if tr.IDToken == "" {
		return Tokens{}, Identity{}, invalid("the token answer carries no id_token (is the openid scope granted?)")
	}
	tok := p.tokensOf(tr)
	id, err := p.verifyIDToken(ctx, tr.IDToken, idTokenCheck{nonce: nonce, accessToken: tok.AccessToken})
	if err != nil {
		return Tokens{}, Identity{}, err
	}
	return tok, id, nil
}

// RefreshRequest is a refresh-token grant for one session.
type RefreshRequest struct {
	RefreshToken Secret
	// Subject is the session's sub, required: an ID token in the answer
	// must name it, so a refresh can never switch the session to another
	// person. Empty is ErrInvalidConfig.
	Subject string
}

// Refresh redeems a refresh token. The answer's ID token, when there is
// one, is verified as at sign-in (except the nonce, which a refresh does
// not carry) and must name in.Subject. invalid_grant is ErrProviderRefused.
func (p *Provider) Refresh(ctx context.Context, in RefreshRequest) (*Refreshed, error) {
	if in.RefreshToken.IsZero() {
		return nil, fmt.Errorf("%w: the session has no refresh token (request offline_access, or Google's access_type=offline)", ErrProviderRefused)
	}
	if in.Subject == "" {
		return nil, fmt.Errorf("%w: RefreshRequest.Subject is empty", ErrInvalidConfig)
	}
	tr, err := p.tokenGrant(ctx, url.Values{paramGrantType: {grantRefresh}, paramRefreshToken: {in.RefreshToken.Reveal()}})
	if err != nil {
		return nil, err
	}
	tok := p.tokensOf(tr)
	if tok.RefreshToken.IsZero() {
		tok.RefreshToken = in.RefreshToken
	}
	out := &Refreshed{tokens: tok}
	if tr.IDToken != "" {
		id, err := p.verifyIDToken(ctx, tr.IDToken, idTokenCheck{subject: in.Subject, accessToken: tok.AccessToken})
		if err != nil {
			return nil, err
		}
		out.identity = &id
	}
	return out, nil
}

// Refreshed is a successful refresh: the new tokens and, when the server
// issued a new ID token, the Identity it verified. Its fields are
// unexported so that only Provider.Refresh makes one: a Rechecker can hand
// the package new tokens only by actually refreshing them, never by
// building a value with an unverified ID token.
type Refreshed struct {
	tokens   Tokens
	identity *Identity
}

// Tokens returns the new tokens. A refresh token the server did not rotate
// is the previous one, carried over.
func (r *Refreshed) Tokens() Tokens { return r.tokens }

// Identity returns the verified Identity of the new ID token, or nil when
// the answer had none.
func (r *Refreshed) Identity() *Identity { return r.identity }

// TokenTypeHint is RFC 7009's token_type_hint.
type TokenTypeHint string

const (
	HintRefreshToken TokenTypeHint = "refresh_token"
	HintAccessToken  TokenTypeHint = "access_token"
)

// TokenTypeHintValues is every TokenTypeHint.
var TokenTypeHintValues = []TokenTypeHint{HintRefreshToken, HintAccessToken}

// IntrospectRequest is an RFC 7662 introspection.
type IntrospectRequest struct {
	Token Secret
	Hint  TokenTypeHint
}

// Introspection is the introspection endpoint's answer (RFC 7662 section
// 2.2), under the member names ubgo/auth's provider and others send.
// Active false is the server's "no", not an error.
type Introspection struct {
	Active    bool      `json:"active"`
	Subject   string    `json:"sub,omitempty"`
	ClientID  string    `json:"client_id,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	TokenType string    `json:"token_type,omitempty"`
	Issuer    string    `json:"iss,omitempty"`
	Audience  []string  `json:"-"`
	ExpiresAt time.Time `json:"-"`
	IssuedAt  time.Time `json:"-"`
	// Claims are every member of the answer, the ones above included.
	Claims Claims `json:"-"`
}

// Introspect asks the introspection endpoint about a token. A server
// without one is ErrInvalidConfig at the first call (New cannot know before
// discovery).
func (p *Provider) Introspect(ctx context.Context, in IntrospectRequest) (Introspection, error) {
	meta, err := p.Metadata(ctx)
	if err != nil {
		return Introspection{}, err
	}
	if meta.IntrospectionEndpoint == "" {
		return Introspection{}, fmt.Errorf("%w: the login server publishes no introspection_endpoint", ErrInvalidConfig)
	}
	form := url.Values{paramToken: {in.Token.Reveal()}}
	if in.Hint != "" {
		form.Set(paramTokenTypeHint, string(in.Hint))
	}
	body, err := p.postAuthenticated(ctx, meta.IntrospectionEndpoint, form)
	if err != nil {
		return Introspection{}, err
	}
	var out Introspection
	if err := decodeJSON(meta.IntrospectionEndpoint, body, &out); err != nil {
		return Introspection{}, err
	}
	var times struct {
		Audience  audience    `json:"aud"`
		ExpiresAt numericDate `json:"exp"`
		IssuedAt  numericDate `json:"iat"`
	}
	if err := decodeJSON(meta.IntrospectionEndpoint, body, &out.Claims); err != nil {
		return Introspection{}, err
	}
	if err := decodeJSON(meta.IntrospectionEndpoint, body, &times); err != nil {
		return Introspection{}, err
	}
	out.Audience, out.ExpiresAt, out.IssuedAt = times.Audience, times.ExpiresAt.time(), times.IssuedAt.time()
	return out, nil
}

// UserInfo calls the userinfo endpoint with an access token. 401 is
// ErrProviderRefused. The answer's sub must equal subject, or it is refused
// (OpenID Connect Core section 5.3.2).
func (p *Provider) UserInfo(ctx context.Context, accessToken Secret, subject string) (Claims, error) {
	meta, err := p.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	if meta.UserInfoEndpoint == "" {
		return nil, fmt.Errorf("%w: the login server publishes no userinfo_endpoint", ErrInvalidConfig)
	}
	if subject == "" {
		return nil, fmt.Errorf("%w: UserInfo needs the subject to match", ErrInvalidConfig)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meta.UserInfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: userinfo_endpoint: %w", ErrInvalidConfig, err)
	}
	req.Header.Set(headerAuthorization, schemeBearer+accessToken.Reveal())
	req.Header.Set(headerAccept, mediaTypeJSON)
	body, err := p.send(req)
	if err != nil {
		return nil, err
	}
	var claims Claims
	if err := decodeJSON(meta.UserInfoEndpoint, body, &claims); err != nil {
		return nil, err
	}
	if sub, _ := claims.String(ClaimSubject); sub != subject {
		return nil, fmt.Errorf("%w: userinfo names another subject", ErrProviderRefused)
	}
	return claims, nil
}
