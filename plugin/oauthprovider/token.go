package oauthprovider

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/sqlb"
)

// Token response and claim names.
const (
	tokenTypeBearer = "Bearer"
	// tokenIDPrefix starts every auth_oauth_token id.
	tokenIDPrefix = "oat"
	// familyPrefix starts the family of a client_credentials token, which
	// has no code.
	familyPrefix = "oaf"

	claimIssuer        = "iss"
	claimSubject       = "sub"
	claimAudience      = "aud"
	claimExpires       = "exp"
	claimIssuedAt      = "iat"
	claimNonce         = "nonce"
	claimAuthTime      = "auth_time"
	claimAZP           = "azp"
	claimName          = "name"
	claimPicture       = "picture"
	claimEmail         = "email"
	claimEmailVerified = "email_verified"
	claimGivenName     = "given_name"
	claimFamilyName    = "family_name"
	claimAtHash        = "at_hash"
	claimClientID      = "client_id"
	claimScope         = "scope"

	// Token type hints (RFC 7009 section 2.1).
	hintAccess  = "access_token"
	hintRefresh = "refresh_token"
)

// protectedClaims are never overridden by a ClaimsFunc: they are what makes
// an ID token valid for this issuer, client and request.
var protectedClaims = []string{claimIssuer, claimSubject, claimAudience, claimExpires, claimIssuedAt, claimNonce, claimAuthTime, claimAZP, claimAtHash, "nbf", "jti", "sid", "act"}

// TokenRequest is a token request, RFC 6749 sections 4.1.3, 4.4.2 and 6.
// Handler fills the client credentials from the Authorization header or the
// form, and Method with how they came.
type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	CodeVerifier string `json:"code_verifier"`
	RefreshToken string `json:"refresh_token"`
	// DeviceCode is the RFC 8628 device_code, for the device grant served
	// through WithGrant.
	DeviceCode string `json:"device_code"`
	// DPoPProof is the request's DPoP header; Handler fills it.
	DPoPProof string `json:"dpop_proof"`
	Scope     string `json:"scope"`
	// Resource is the RFC 8707 resource; at a code exchange or refresh it
	// must be the one the grant was issued for.
	Resource     string `json:"resource"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	// ClientAuthMethod is how the client authenticated: AuthMethodBasic,
	// AuthMethodPost or AuthMethodNone. It must be the client's registered
	// method.
	ClientAuthMethod string `json:"client_auth_method"`
	// ClientAssertion is a private_key_jwt assertion; Handler checks
	// client_assertion_type.
	ClientAssertion string `json:"client_assertion"`
	// ClientAssertionType and ClientCertificates are for an extension
	// ClientAuthMethod (an assertion of its type, mutual TLS).
	ClientAssertionType string              `json:"client_assertion_type,omitempty"`
	ClientCertificates  []*x509.Certificate `json:"-"`
}

func (in TokenRequest) credentials() ClientCredentials {
	return ClientCredentials{ID: in.ClientID, Secret: in.ClientSecret, Method: in.ClientAuthMethod, Assertion: in.ClientAssertion, AssertionType: in.ClientAssertionType, Certificates: in.ClientCertificates}
}

// TokenResponse is the token endpoint's answer, RFC 6749 section 5.1. The
// tokens are plain strings: this is the one place they are meant to be seen.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	// ExpiresAt is when the access token expires, in Unix seconds.
	ExpiresAt    int64  `json:"expires_at,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope"`
	// Extra are the TokenResponseFields additions; a standard member's
	// name is ignored.
	Extra map[string]any `json:"-"`
}

// standardTokenFields can never be replaced by TokenResponseFields.
var standardTokenFields = []string{"access_token", "token_type", "expires_in", "expires_at", "refresh_token", "id_token", "scope"}

// MarshalJSON writes the standard members and, beside them, Extra.
func (r TokenResponse) MarshalJSON() ([]byte, error) {
	type plain TokenResponse
	b, err := json.Marshal(plain(r))
	if err != nil || len(r.Extra) == 0 {
		return b, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	for k, v := range r.Extra {
		if !slices.Contains(standardTokenFields, k) {
			m[k] = v
		}
	}
	return json.Marshal(m)
}

// Token runs a token request from Go.
func (p *Plugin) Token(ctx context.Context, in TokenRequest) (TokenResponse, error) {
	return p.token.Call(ctx, in)
}

func (p *Plugin) doToken(ctx context.Context, _ *auth.Call, in TokenRequest) (TokenResponse, error) {
	if !slices.Contains(p.servedGrants(), in.GrantType) {
		return TokenResponse{}, ErrUnsupportedGrantType
	}
	client, err := p.authenticateClient(ctx, in.credentials(), p.endpoint(pathToken))
	if err != nil {
		return TokenResponse{}, err
	}
	if !slices.Contains(client.client().GrantTypes, in.GrantType) {
		return TokenResponse{}, ErrUnauthorizedClient
	}
	switch in.GrantType {
	case GrantAuthorizationCode:
		return p.exchangeCode(ctx, client, in)
	case GrantRefreshToken:
		return p.refresh(ctx, client, in)
	case GrantClientCredentials:
		return p.clientCredentialsGrant(ctx, client, in)
	}
	// servedGrants holds only built-ins and extensions, so this finds one.
	g, _ := p.extension(in.GrantType)
	return p.extensionGrant(ctx, g, client, in)
}

func (p *Plugin) exchangeCode(ctx context.Context, client clientRow, in TokenRequest) (TokenResponse, error) {
	if in.Code == "" {
		return TokenResponse{}, ErrInvalidRequest
	}
	r, err := p.redeemCode(ctx, in.Code)
	if err != nil {
		return TokenResponse{}, err
	}
	// The code is bound to the client it was issued to and the redirect URI
	// the request named (RFC 6749 section 4.1.3), and to the PKCE verifier.
	if r.client != client.c.ClientID || r.redirect != in.RedirectURI {
		return TokenResponse{}, ErrInvalidGrant
	}
	if err := checkPKCE(r, in.CodeVerifier); err != nil {
		return TokenResponse{}, err
	}
	if err := p.userExists(ctx, r.user); err != nil {
		return TokenResponse{}, err
	}
	resource, err := narrowResources(in.Resource, deref(r.resource))
	if err != nil {
		return TokenResponse{}, err
	}
	authTime := r.authTime
	return p.issue(ctx, issuance{grantType: GrantAuthorizationCode, proof: in.DPoPProof, expectedJKT: deref(r.dpopJKT), client: client, userID: r.user, sessionID: r.session, scopes: strings.Fields(r.scopes), family: r.id, authTime: &authTime, nonce: deref(r.nonce), resource: resource, userInfoClaims: splitClaims(r.claims), referenceID: deref(r.refID)})
}

// tokenRow is a stored token issuance.
type tokenRow struct {
	id, family, client, scopes string
	user, session, resource    *string
	claims, jkt, x5t, refID    *string
	accessExpires              time.Time
	refreshExpires, authTime   *time.Time
	created                    time.Time
	rotated, revoked           *time.Time
	// accessRevoked ends the access token alone (RevokeAccessTokenOnly).
	accessRevoked *time.Time
}

func (r *tokenRow) bindings() []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(TokenID, &r.id), sqlb.Bind(TokenFamily, &r.family), sqlb.Bind(TokenClient, &r.client), sqlb.Bind(TokenScopes, &r.scopes),
		sqlb.Bind(TokenUser, &r.user), sqlb.Bind(TokenSession, &r.session), sqlb.Bind(TokenAccessExpires, &r.accessExpires),
		sqlb.Bind(TokenRefreshExpires, &r.refreshExpires), sqlb.Bind(TokenAuthTime, &r.authTime), sqlb.Bind(TokenCreated, &r.created),
		sqlb.Bind(TokenRotated, &r.rotated), sqlb.Bind(TokenRevoked, &r.revoked), sqlb.Bind(TokenResource, &r.resource), sqlb.Bind(TokenClaims, &r.claims), sqlb.Bind(TokenJKT, &r.jkt),
		sqlb.Bind(TokenX5T, &r.x5t), sqlb.Bind(TokenRef, &r.refID), sqlb.Bind(TokenAccessRevoked, &r.accessRevoked),
	}
}

// refresh rotates a refresh token: the presented one is spent and a new
// pair is issued in the same family. Presenting a spent or revoked refresh
// token is reuse, which revokes the whole family (OAuth 2.1 section 4.3.1),
// on a write the refused request's rollback does not undo.
func (p *Plugin) refresh(ctx context.Context, client clientRow, in TokenRequest) (TokenResponse, error) {
	if in.RefreshToken == "" {
		return TokenResponse{}, ErrInvalidRequest
	}
	hash, ok := p.refreshHash(ctx, in.RefreshToken)
	if !ok {
		return TokenResponse{}, ErrInvalidGrant
	}
	now := p.core.Now()
	n, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableToken).Set(sqlb.Set(TokenRotated, &now)).
		Where(sqlb.Eq(TokenRefresh, hash), sqlb.IsNull(TokenRotated), sqlb.IsNull(TokenRevoked)))
	if err != nil {
		return TokenResponse{}, err
	}
	var r tokenRow
	err = p.core.One(ctx, p.core.Select().Columns(r.bindings()...).From(TableToken).Where(sqlb.Eq(TokenRefresh, hash)))
	if errors.Is(err, sqlb.ErrNoRows) {
		return TokenResponse{}, ErrInvalidGrant
	}
	if err != nil {
		return TokenResponse{}, err
	}
	if n == 0 && !p.withinReuse(r, now) {
		family := r.family
		p.core.AfterTx(ctx, func(ctx context.Context) { p.revokeFamily(ctx, family) })
		return TokenResponse{}, ErrInvalidGrant
	}
	if n == 0 && p.replay != nil && r.client == client.c.ClientID {
		// A reuse inside the window: a replay of the first answer, when one
		// is stored. A bound family still needs a proof of
		// its key for this request.
		res, found, err := p.replayed(ctx, r.id, in, now)
		if err != nil {
			return TokenResponse{}, err
		}
		if found {
			if _, err := p.tokenBinding(ctx, in.DPoPProof, deref(r.jkt), deref(r.jkt) != ""); err != nil {
				return TokenResponse{}, err
			}
			return res, nil
		}
	}
	if r.client != client.c.ClientID || r.refreshExpires == nil || !now.Before(*r.refreshExpires) || r.user == nil {
		return TokenResponse{}, ErrInvalidGrant
	}
	if err := p.userExists(ctx, *r.user); err != nil {
		return TokenResponse{}, err
	}
	scopes := strings.Fields(r.scopes)
	if in.Scope != "" {
		narrowed := dedupe(strings.Fields(in.Scope))
		for _, s := range narrowed {
			if !slices.Contains(scopes, s) {
				return TokenResponse{}, ErrInvalidScope
			}
		}
		scopes = narrowed
	}
	resource, err := narrowResources(in.Resource, deref(r.resource))
	if err != nil {
		return TokenResponse{}, err
	}
	res, err := p.issue(ctx, issuance{grantType: GrantRefreshToken, proof: in.DPoPProof, expectedJKT: deref(r.jkt), client: client, userID: *r.user, sessionID: deref(r.session), scopes: scopes, family: r.family, authTime: r.authTime, refreshing: true, resource: resource, userInfoClaims: splitClaims(r.claims), referenceID: deref(r.refID)})
	if err == nil && n == 1 && p.replay != nil {
		err = p.storeReplay(ctx, r.id, in, res)
	}
	return res, err
}

// userExists checks that a grant's user still exists: a deleted user is
// invalid_grant, and a failed read is its own error, so a database blip
// never tells the client its grant is dead.
func (p *Plugin) userExists(ctx context.Context, id string) error {
	_, err := p.core.User(ctx, id)
	if errors.Is(err, auth.ErrUserNotFound) {
		return ErrInvalidUser
	}
	return err
}

// withinReuse reports whether a spent refresh token is being presented
// again inside RefreshReuseInterval of its rotation, which is allowed: a
// revoked family, or a reuse after the interval, is not.
func (p *Plugin) withinReuse(r tokenRow, now time.Time) bool {
	return p.refreshReuse > 0 && r.revoked == nil && r.rotated != nil && now.Sub(*r.rotated) <= p.refreshReuse
}

func (p *Plugin) clientCredentialsGrant(ctx context.Context, client clientRow, in TokenRequest) (TokenResponse, error) {
	cl := client.client()
	// The server-owned ceiling decides, and without one the
	// client may not use the grant; public clients never have one.
	if client.c.AuthMethod == AuthMethodNone || len(cl.ClientCredentialsScopes) == 0 {
		return TokenResponse{}, ErrUnauthorizedClient
	}
	scopes := dedupe(strings.Fields(in.Scope))
	if len(scopes) == 0 {
		scopes = slices.Clone(cl.ClientCredentialsScopes)
	}
	for _, s := range scopes {
		// No user is behind this token, so a scope that acts for one is
		// never granted, whatever the ceiling says.
		if !slices.Contains(cl.ClientCredentialsScopes, s) || slices.Contains(userScopes, s) {
			return TokenResponse{}, ErrInvalidScope
		}
	}
	family, err := p.core.NewID(familyPrefix)
	if err != nil {
		return TokenResponse{}, err
	}
	return p.issue(ctx, issuance{grantType: GrantClientCredentials, proof: in.DPoPProof, client: client, scopes: scopes, family: family, resource: in.Resource})
}

// issuance is what one token response is made from.
type issuance struct {
	client     clientRow
	userID     string
	sessionID  string
	scopes     []string
	family     string
	authTime   *time.Time
	nonce      string
	refreshing bool
	// resource is the RFC 8707 resource; with one, the access token is a
	// JWT whose aud is it.
	resource string
	// userInfoClaims are the claims request's userinfo names.
	userInfoClaims []string
	// jkt is the DPoP key the tokens are bound to, or "", decided by issue
	// from proof and expectedJKT (a bound code's or refresh token's key).
	jkt, proof, expectedJKT string
	// policy is the resource's, resolved by issue.
	policy Resource
	// grantType names the grant, for TokenResponseFields.
	grantType string
	// accessClaims and idClaims are an extension grant's per-issuance
	// claims (GrantDecision).
	accessClaims, idClaims map[string]any
	// referenceID is the post-login reference the consent was given for.
	referenceID string
	// presetJKT is a DPoP binding IssueTokens was given, used instead of
	// a proof.
	presetJKT string
}

// confirmation is the tokens' cnf: the DPoP key and the client
// certificate an extension method bound, or nil.
func (is issuance) confirmation() *Confirmation {
	c := Confirmation{JKT: is.jkt}
	if is.client.confirmation != nil {
		c.X5TS256 = is.client.confirmation.X5TS256
	}
	if c == (Confirmation{}) {
		return nil
	}
	return &c
}

// x5t is the client certificate thumbprint the tokens are bound to, or "".
func (is issuance) x5t() string {
	if is.client.confirmation == nil {
		return ""
	}
	return is.client.confirmation.X5TS256
}

// issue stores a new token row and answers its tokens: an access token, a
// refresh token when offline_access was granted and the client may refresh,
// and an ID token when openid was granted.
func (p *Plugin) issue(ctx context.Context, is issuance) (TokenResponse, error) {
	// The resource is resolved again at every issuance (a code exchange, a
	// refresh, client credentials): a resource disabled since, or a link
	// removed, stops new tokens (invalid_target), and its policy applies.
	scopes, pol, err := p.resourcePolicy(ctx, is.resource, is.client.c.ClientID, is.scopes)
	if err != nil {
		return TokenResponse{}, err
	}
	is.scopes, is.policy = scopes, pol
	required := is.client.c.DPoPBoundAccessTokens || is.expectedJKT != "" || pol.DPoPRequired
	if is.presetJKT != "" {
		is.jkt = is.presetJKT
	} else if is.jkt, err = p.tokenBinding(ctx, is.proof, is.expectedJKT, required); err != nil {
		return TokenResponse{}, err
	}
	now := p.core.Now()
	id, err := p.core.NewID(tokenIDPrefix)
	if err != nil {
		return TokenResponse{}, err
	}
	access, err := newRandom(p.genAccess)
	if err != nil {
		return TokenResponse{}, err
	}
	res := TokenResponse{AccessToken: PrefixAccessToken + access, TokenType: tokenTypeBearer, ExpiresIn: int64(p.accessTTLFor(is) / time.Second), ExpiresAt: now.Add(p.accessTTLFor(is)).Unix(), Scope: strings.Join(is.scopes, listSeparator)}
	if is.jkt != "" {
		res.TokenType = SchemeDPoP
	}
	if is.resource != "" {
		at, err := p.jwtAccessToken(ctx, is, id)
		if err != nil {
			return TokenResponse{}, err
		}
		res.AccessToken = at
	}
	var refreshHash *[]byte
	var refreshExp *time.Time
	if is.userID != "" && slices.Contains(is.scopes, ScopeOfflineAccess) && slices.Contains(is.client.client().GrantTypes, GrantRefreshToken) && slices.Contains(p.grantTypes, GrantRefreshToken) {
		raw, err := newRandom(p.genRefresh)
		if err != nil {
			return TokenResponse{}, err
		}
		h := p.hashSecret(SecretRefresh, PrefixRefreshToken+raw)
		if res.RefreshToken, err = p.encodeRefresh(ctx, raw, is.sessionID); err != nil {
			return TokenResponse{}, err
		}
		e := now.Add(p.refreshTTLFor(is))
		refreshHash, refreshExp = &h, &e
	}
	if p.responseFields != nil {
		// Called before the token row is written, before any side effect, so
		// a failing hook issues nothing.
		info := TokenFieldsInfo{GrantType: is.grantType, ClientID: is.client.c.ClientID, Scopes: slices.Clone(is.scopes), UserID: is.userID}
		extra, err := p.responseFields(ctx, info)
		if err != nil {
			return TokenResponse{}, err
		}
		res.Extra = extra
	}
	if _, err := p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableToken).Row(
		sqlb.Set(TokenID, id), sqlb.Set(TokenAccessHash, p.hashSecret(SecretAccess, res.AccessToken)), sqlb.Set(TokenRefreshNull, refreshHash),
		sqlb.Set(TokenFamily, is.family), sqlb.Set(TokenClient, is.client.c.ClientID), sqlb.Set(TokenUser, optional(is.userID)),
		sqlb.Set(TokenSession, optional(is.sessionID)), sqlb.Set(TokenScopes, res.Scope), sqlb.Set(TokenAccessExpires, now.Add(p.accessTTLFor(is))),
		sqlb.Set(TokenRefreshExpires, refreshExp), sqlb.Set(TokenAuthTime, is.authTime), sqlb.Set(TokenCreated, now),
		sqlb.Set(TokenResource, optional(is.resource)), sqlb.Set(TokenClaims, joinClaims(is.userInfoClaims)), sqlb.Set(TokenJKT, optional(is.jkt)),
		sqlb.Set(TokenX5T, optional(is.x5t())), sqlb.Set(TokenRef, optional(is.referenceID)),
	)); err != nil {
		return TokenResponse{}, err
	}
	if is.userID != "" && slices.Contains(is.scopes, ScopeOpenID) {
		idt, err := p.idToken(ctx, is, res.AccessToken)
		if err != nil {
			return TokenResponse{}, err
		}
		res.IDToken = idt
	}
	return res, nil
}

// idToken signs an ID token with the jwt plugin's key: sub, aud (the
// client), azp, auth_time, the nonce of the authorization request, and the
// claims of the granted scopes.
func (p *Plugin) idToken(ctx context.Context, is issuance, accessToken string) (string, error) {
	u, err := p.core.User(ctx, is.userID)
	if err != nil {
		return "", err
	}
	claims, err := p.claimsFor(ctx, u, is.scopes, nil)
	if err != nil {
		return "", err
	}
	delete(claims, claimSubject)
	claims[claimAZP] = is.client.c.ClientID
	if is.authTime != nil {
		claims[claimAuthTime] = is.authTime.Unix()
	}
	if is.nonce != "" {
		claims[claimNonce] = is.nonce
	}
	if h, ok := p.atHash(accessToken); ok {
		claims[claimAtHash] = h
	}
	p.extensionIDClaims(ctx, claims, ClaimsInfo{User: u, ClientID: is.client.c.ClientID, Scopes: is.scopes}, is.idClaims)
	tok, err := p.signer.Sign(ctx, jwt.SignRequest{Subject: p.subjectFor(is.client, u.ID), Audience: []string{is.client.c.ClientID}, TTL: p.idTokenTTL, Claims: claims, SessionID: is.sessionID})
	if err != nil {
		return "", err
	}
	return tok.Token, nil
}

// claimsFor builds the claims the granted scopes release (OpenID Connect
// Core section 5.4), plus the userinfo claims the request named individually
// (section 5.5), then the app's Claims on top, which may not replace a
// protected claim.
func (p *Plugin) claimsFor(ctx context.Context, u auth.User, scopes, requested []string) (map[string]any, error) {
	claims := map[string]any{claimSubject: u.ID}
	want := func(name string) bool {
		return slices.Contains(scopes, standardClaims[name]) || slices.Contains(requested, name)
	}
	given, family := splitDisplayName(u.Name)
	for name, v := range map[string]string{claimName: u.Name, claimPicture: u.Image, claimGivenName: given, claimFamilyName: family} {
		if v != "" && want(name) {
			claims[name] = v
		}
	}
	if want(claimEmail) || want(claimEmailVerified) {
		ids, err := p.core.Identities(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		e, ok := primaryEmail(ids)
		if ok && want(claimEmail) {
			claims[claimEmail] = e.Value
		}
		if want(claimEmailVerified) {
			claims[claimEmailVerified] = ok && e.Verified()
		}
	}
	if p.claims != nil {
		for k, v := range p.claims(ctx, u, slices.Clone(scopes)) {
			if !slices.Contains(protectedClaims, k) {
				claims[k] = v
			}
		}
	}
	return claims, nil
}

// primaryEmail picks the user's primary email identity, or the first one.
func primaryEmail(ids []auth.Identity) (auth.Identity, bool) {
	var first *auth.Identity
	for i := range ids {
		if ids[i].Kind != email.KindEmail {
			continue
		}
		if ids[i].IsPrimary {
			return ids[i], true
		}
		if first == nil {
			first = &ids[i]
		}
	}
	if first == nil {
		return auth.Identity{}, false
	}
	return *first, true
}

// revokeFamily revokes every token of a family. It runs after a refused
// replay, outside the request's transaction, so a failure is only logged.
func (p *Plugin) revokeFamily(ctx context.Context, family string) {
	now := p.core.Now()
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableToken).Set(sqlb.Set(TokenRevoked, &now)).
		Where(sqlb.Eq(TokenFamily, family), sqlb.IsNull(TokenRevoked))); err != nil {
		p.core.Logger().Error("oauthprovider: revoke token family", "family", family, "error", err)
	}
}

// AccessToken is a verified access token, for a resource server.
type AccessToken struct {
	ID        string    `json:"id"`
	ClientID  string    `json:"client_id"`
	UserID    string    `json:"user_id,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	Scopes    []string  `json:"scopes"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Resource is the RFC 8707 resource the token is bound to (its aud), or
	// "" for a token for no particular resource.
	Resource string `json:"resource,omitempty"`
	// userInfoClaims are the claims the authorization request asked for
	// individually, which userinfo releases.
	userInfoClaims []string
	// JKT is the thumbprint of the DPoP key the token is bound to, or "".
	JKT string `json:"jkt,omitempty"`
	// X5TS256 is the thumbprint of the client certificate the token is
	// bound to (RFC 8705), or "".
	X5TS256 string `json:"x5t#S256,omitempty"`
	// ReferenceID is the post-login reference (an organization) the
	// authorization was given for, or "".
	ReferenceID string `json:"reference_id,omitempty"`
}

// HasScope reports whether the token carries scope.
func (t AccessToken) HasScope(scope string) bool { return slices.Contains(t.Scopes, scope) }

// VerifyAccessToken checks an access token for a resource server: it exists,
// is neither expired nor revoked, and its client is enabled. Every failure is
// ErrInvalidToken.
func (p *Plugin) VerifyAccessToken(ctx context.Context, token string) (AccessToken, error) {
	if !strings.HasPrefix(token, PrefixAccessToken) && strings.Count(token, ".") != 2 {
		return AccessToken{}, ErrInvalidToken
	}
	var r tokenRow
	err := p.core.One(ctx, p.core.Select().Columns(r.bindings()...).From(TableToken).Where(sqlb.Eq(TokenAccessHash, p.hashSecret(SecretAccess, token))))
	if errors.Is(err, sqlb.ErrNoRows) {
		return AccessToken{}, ErrInvalidToken
	}
	if err != nil {
		return AccessToken{}, err
	}
	if ok, err := p.active(ctx, r, false); err != nil {
		return AccessToken{}, err
	} else if !ok {
		return AccessToken{}, ErrInvalidToken
	}
	return AccessToken{ID: r.id, ClientID: r.client, UserID: deref(r.user), SessionID: deref(r.session), Scopes: strings.Fields(r.scopes), IssuedAt: r.created, ExpiresAt: r.accessExpires, Resource: deref(r.resource), userInfoClaims: splitClaims(r.claims), JKT: deref(r.jkt), X5TS256: deref(r.x5t), ReferenceID: deref(r.refID)}, nil
}

// active reports whether a token row's access (or refresh) token is usable:
// not revoked, not expired, its client enabled. A failed read is an error,
// never "inactive": a resource server may cache an inactive answer, and a
// database blip must not read as a revocation.
func (p *Plugin) active(ctx context.Context, r tokenRow, refresh bool) (bool, error) {
	now := p.core.Now()
	if r.revoked != nil {
		return false, nil
	}
	if refresh {
		if r.rotated != nil || r.refreshExpires == nil || !now.Before(*r.refreshExpires) {
			return false, nil
		}
	} else if !now.Before(r.accessExpires) || r.accessRevoked != nil {
		return false, nil
	}
	c, err := p.loadClient(ctx, r.client)
	if errors.Is(err, ErrClientNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if c.disabledAt != nil {
		return false, nil
	}
	// A token for a resource that was deleted is inactive; a disabled one
	// still verifies until it expires.
	for _, res := range splitResources(deref(r.resource)) {
		if ok, err := p.resourceKnown(ctx, res); err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// sessionAlive is the introspection session check: an access
// token issued on a session is inactive once that session is gone, even by
// expiry, which ends no tokens the way a sign-out does (SessionEnded). A
// refresh token outlives its session by design (offline_access), and a
// stateless deployment cannot list sessions, so both answer true.
func (p *Plugin) sessionAlive(ctx context.Context, r tokenRow, refresh bool) (bool, error) {
	if refresh {
		return true, nil
	}
	return p.sessionLive(ctx, deref(r.user), deref(r.session))
}

// UserInfoRequest carries the access token, from the Authorization header
// or the form (Handler refuses both at once).
type UserInfoRequest struct {
	AccessToken string `json:"access_token"`
	// Scheme, DPoPProof, Method and URL describe how the token was
	// presented, for a DPoP-bound one; "" Scheme is Bearer. Handler fills
	// them.
	Scheme    string `json:"-"`
	DPoPProof string `json:"-"`
	Method    string `json:"-"`
	URL       string `json:"-"`
	// Certificate is the connection's TLS client certificate, for a token
	// bound to one.
	Certificate *x509.Certificate `json:"-"`
}

// UserInfo answers the OpenID Connect userinfo request from Go.
func (p *Plugin) UserInfo(ctx context.Context, token string) (map[string]any, error) {
	return p.userinfo.Call(ctx, UserInfoRequest{AccessToken: token})
}

func (p *Plugin) doUserInfo(ctx context.Context, _ *auth.Call, in UserInfoRequest) (map[string]any, error) {
	scheme := in.Scheme
	if scheme == "" {
		scheme = schemeBearer
	}
	t, err := p.VerifyPresentedToken(ctx, PresentedToken{Scheme: scheme, Token: in.AccessToken, Proof: in.DPoPProof, Method: in.Method, URL: in.URL, Certificate: in.Certificate})
	if err != nil {
		return nil, err
	}
	if t.UserID == "" || !t.HasScope(ScopeOpenID) {
		if p.userInfoForbidden {
			return nil, ErrInsufficientScope
		}
		return nil, ErrInvalidScope
	}
	// A token whose session has ended is invalid_token here,
	// even before it expires.
	if live, err := p.sessionLive(ctx, t.UserID, t.SessionID); err != nil {
		return nil, err
	} else if !live {
		return nil, ErrInvalidToken
	}
	u, err := p.core.User(ctx, t.UserID)
	if errors.Is(err, auth.ErrUserNotFound) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}
	claims, err := p.claimsFor(ctx, u, t.Scopes, t.userInfoClaims)
	if err != nil {
		return nil, err
	}
	p.extensionUserInfo(ctx, claims, ClaimsInfo{User: u, ClientID: t.ClientID, Scopes: t.Scopes})
	if claims[claimSubject], err = p.subjectForClient(ctx, t.ClientID, u.ID); err != nil {
		return nil, err
	}
	return claims, nil
}

// IntrospectRequest is RFC 7662 section 2.1, with the caller's client
// credentials.
type IntrospectRequest struct {
	Token            string `json:"token"`
	TokenTypeHint    string `json:"token_type_hint"`
	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret"`
	ClientAuthMethod string `json:"client_auth_method"`
	// ClientAssertion is a private_key_jwt assertion; Handler checks
	// client_assertion_type.
	ClientAssertion string `json:"client_assertion"`
	// ClientAssertionType and ClientCertificates are for an extension
	// ClientAuthMethod (an assertion of its type, mutual TLS).
	ClientAssertionType string              `json:"client_assertion_type,omitempty"`
	ClientCertificates  []*x509.Certificate `json:"-"`
}

// Introspection is RFC 7662 section 2.2. An inactive token answers only
// active false.
type Introspection struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Subject   string `json:"sub,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	Audience  string `json:"aud,omitempty"`
	// Audiences are the resources of a token issued for several; aud is
	// then written as their array, and Audience holds them space-separated.
	Audiences []string `json:"-"`
	// Confirmation is cnf: the DPoP key a bound token needs.
	Confirmation *Confirmation `json:"cnf,omitempty"`
	// Extra are the token's resource's custom claims; a member named like
	// one of the fields above is ignored.
	Extra map[string]any `json:"-"`
}

// MarshalJSON writes the fields and, beside them, Extra's claims that do
// not collide with a field or a protected claim.
func (in Introspection) MarshalJSON() ([]byte, error) {
	type plain Introspection
	b, err := json.Marshal(plain(in))
	if err != nil || (len(in.Extra) == 0 && len(in.Audiences) < 2) {
		return b, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if len(in.Audiences) > 1 {
		m[claimAudience] = in.Audiences
	}
	for k, v := range in.Extra {
		if _, taken := m[k]; !taken && !slices.Contains(protectedClaims, k) && k != claimClientID && k != claimScope && k != "active" && k != "token_type" {
			m[k] = v
		}
	}
	return json.Marshal(m)
}

// Confirmation is RFC 7800's cnf: a DPoP key thumbprint (RFC 9449) or a
// client certificate thumbprint (RFC 8705, which an extension
// ClientAuthMethod binds; the token type stays Bearer).
type Confirmation struct {
	JKT     string `json:"jkt,omitempty"`
	X5TS256 string `json:"x5t#S256,omitempty"`
}

// Introspect runs an introspection request from Go.
func (p *Plugin) Introspect(ctx context.Context, in IntrospectRequest) (Introspection, error) {
	return p.introspect.Call(ctx, in)
}

// findToken looks a token up as an access token and a refresh token, in the
// order the hint suggests; an unknown hint is ignored (RFC 7009 section
// 2.1).
func (p *Plugin) findToken(ctx context.Context, token, hint string) (tokenRow, bool, bool, error) {
	hash := p.hashSecret(SecretAccess, token)
	order := []bool{false, true}
	if hint == hintRefresh {
		order = []bool{true, false}
	}
	for _, refresh := range order {
		col, h := TokenAccessHash, hash
		if refresh {
			col = TokenRefresh
			var ok bool
			if h, ok = p.refreshHash(ctx, token); !ok {
				continue
			}
		}
		var r tokenRow
		err := p.core.One(ctx, p.core.Select().Columns(r.bindings()...).From(TableToken).Where(sqlb.Eq(col, h)))
		if errors.Is(err, sqlb.ErrNoRows) {
			continue
		}
		if err != nil {
			return tokenRow{}, false, false, err
		}
		return r, refresh, true, nil
	}
	return tokenRow{}, false, false, nil
}

func (p *Plugin) doIntrospect(ctx context.Context, _ *auth.Call, in IntrospectRequest) (Introspection, error) {
	client, err := p.authenticateClient(ctx, ClientCredentials{ID: in.ClientID, Secret: in.ClientSecret, Method: in.ClientAuthMethod, Assertion: in.ClientAssertion, AssertionType: in.ClientAssertionType, Certificates: in.ClientCertificates}, p.endpoint(pathIntrospect))
	if err != nil {
		return Introspection{}, err
	}
	if client.c.AuthMethod == AuthMethodNone {
		// A public client cannot keep a secret, so anyone could introspect
		// as it.
		return Introspection{}, ErrInvalidClient
	}
	if in.Token == "" {
		return Introspection{}, ErrInvalidRequest
	}
	r, refresh, found, err := p.findToken(ctx, in.Token, in.TokenTypeHint)
	if err != nil {
		return Introspection{}, err
	}
	// A client sees only its own tokens unless it is a resource server
	// (IntrospectAny); another client's token is reported inactive, the
	// same as an unknown one.
	// A client sees its own tokens; a resource server (IntrospectAny, or a
	// client linked to the token's resource) sees others'.
	mayView := r.client == client.c.ClientID || client.c.IntrospectAny
	for _, res := range splitResources(deref(r.resource)) {
		if mayView || !found {
			break
		}
		if mayView, err = p.linked(ctx, client.c.ClientID, res); err != nil {
			return Introspection{}, err
		}
	}
	if !found || !mayView {
		return Introspection{Active: false}, nil
	}
	if ok, err := p.active(ctx, r, refresh); err != nil {
		return Introspection{}, err
	} else if !ok {
		return Introspection{Active: false}, nil
	}
	if ok, err := p.sessionAlive(ctx, r, refresh); err != nil {
		return Introspection{}, err
	} else if !ok {
		return Introspection{Active: false}, nil
	}
	sub, err := p.subjectForClient(ctx, r.client, deref(r.user))
	if err != nil {
		return Introspection{}, err
	}
	out := Introspection{Active: true, Scope: r.scopes, ClientID: r.client, Subject: sub, IssuedAt: r.created.Unix(), Issuer: p.issuer, TokenType: hintAccess, ExpiresAt: r.accessExpires.Unix(), Audience: deref(r.resource), Audiences: splitResources(deref(r.resource))}
	if refresh {
		out.TokenType, out.ExpiresAt = hintRefresh, r.refreshExpires.Unix()
	}
	if deref(r.jkt) != "" || deref(r.x5t) != "" {
		out.Confirmation = &Confirmation{JKT: deref(r.jkt), X5TS256: deref(r.x5t)}
	}
	var policy Resource
	for _, res := range splitResources(deref(r.resource)) {
		// The resources' custom claims, as their JWT access tokens carry
		// them; a disabled resource's still apply to tokens already issued.
		rr, err := p.Resource(ctx, res)
		switch {
		case err == nil:
			if cerr := combinePolicy(&policy, rr); cerr != nil {
				// Pins that conflict were refused at issuance; a row
				// changed since does not hide the token's claims.
				policy.SigningAlgorithm, policy.SigningKeyID = "", ""
			}
		case !errors.Is(err, ErrInvalidTarget):
			// A failed read would drop the resource's claims from an
			// active answer.
			return Introspection{}, err
		}
	}
	out.Extra = policy.CustomClaims
	if !refresh {
		// An access token's own claims (the extensions', AccessTokenClaims,
		// the resource's), as a JWT one carries them.
		claims, err := p.accessClaimsFor(ctx, issuance{client: clientRow{c: Client{ClientID: r.client}}, userID: deref(r.user), scopes: strings.Fields(r.scopes),
			resource: deref(r.resource), referenceID: deref(r.refID), policy: policy})
		if err != nil {
			return Introspection{}, err
		}
		out.Extra = claims
	}
	return out, nil
}

// RevokeRequest is RFC 7009 section 2.1, with the caller's client
// credentials.
type RevokeRequest struct {
	Token            string `json:"token"`
	TokenTypeHint    string `json:"token_type_hint"`
	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret"`
	ClientAuthMethod string `json:"client_auth_method"`
	// ClientAssertion is a private_key_jwt assertion; Handler checks
	// client_assertion_type.
	ClientAssertion string `json:"client_assertion"`
	// ClientAssertionType and ClientCertificates are for an extension
	// ClientAuthMethod (an assertion of its type, mutual TLS).
	ClientAssertionType string              `json:"client_assertion_type,omitempty"`
	ClientCertificates  []*x509.Certificate `json:"-"`
}

// Revoke runs a revocation request from Go.
func (p *Plugin) Revoke(ctx context.Context, in RevokeRequest) error {
	_, err := p.revoke.Call(ctx, in)
	return err
}

// doRevoke revokes a token the client holds: an access token alone, or a
// refresh token with its whole family. An unknown token, or one issued to
// another client, answers success and changes nothing (RFC 7009 section
// 2.2), so the endpoint says nothing about tokens the caller does not hold.
func (p *Plugin) doRevoke(ctx context.Context, _ *auth.Call, in RevokeRequest) (auth.Done, error) {
	client, err := p.authenticateClient(ctx, ClientCredentials{ID: in.ClientID, Secret: in.ClientSecret, Method: in.ClientAuthMethod, Assertion: in.ClientAssertion, AssertionType: in.ClientAssertionType, Certificates: in.ClientCertificates}, p.endpoint(pathRevoke))
	if err != nil {
		return auth.Done{}, err
	}
	if in.Token == "" {
		return auth.Done{}, ErrInvalidRequest
	}
	r, refresh, found, err := p.findToken(ctx, in.Token, in.TokenTypeHint)
	if err != nil || !found || r.client != client.c.ClientID {
		return auth.Done{OK: err == nil}, err
	}
	if !refresh && p.refuseJWTRevoke && isJWT(in.Token) {
		// A live JWT cannot be called back from offline verifiers, so the
		// client is told; a dead one is a no-op.
		live, err := p.active(ctx, r, false)
		if err != nil {
			return auth.Done{}, err
		}
		if live {
			return auth.Done{}, ErrUnsupportedTokenType
		}
		return auth.Done{OK: true}, nil
	}
	now := p.core.Now()
	where, col := sqlb.Eq(TokenID, r.id), TokenRevoked
	switch {
	case refresh:
		where = sqlb.Eq(TokenFamily, r.family)
	case p.revokeAccessOnly:
		col = TokenAccessRevoked
	}
	_, err = p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableToken).Set(sqlb.Set(col, &now)).Where(where, sqlb.IsNull(col)))
	return auth.Done{OK: err == nil}, err
}

// payload decodes a compact JWT's claims without verifying it, for the
// issuer probe in Init, which checks a token this process just signed.
func payload(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	return claims, json.Unmarshal(b, &claims)
}

// jwtAccessToken signs an access token for a resource with the jwt
// plugin's key (RFC 9068's claims: sub, aud the resource, client_id, scope,
// iat, exp, jti), so a resource server in another process verifies it
// offline against <base>/jwks. It is stored hashed like an opaque one, so
// revocation and introspection still apply. The subject is the user, or the
// client for a client_credentials token.
func (p *Plugin) jwtAccessToken(ctx context.Context, is issuance, rowID string) (string, error) {
	sub := p.subjectFor(is.client, is.userID)
	if sub == "" {
		sub = is.client.c.ClientID
	}
	claims, err := p.accessClaimsFor(ctx, is)
	if err != nil {
		return "", err
	}
	claims[claimClientID], claims[claimScope], claims[claimTokenRow] = is.client.c.ClientID, strings.Join(is.scopes, listSeparator), rowID
	if cnf := is.confirmation(); cnf != nil {
		claims[claimConfirm] = cnf
	}
	aud := splitResources(is.resource)
	if slices.Contains(is.scopes, ScopeOpenID) {
		// The userinfo endpoint is an implicit audience of a token for a
		// resource that also carries openid.
		aud = append(aud, p.endpoint(pathUserInfo))
	}
	tok, err := p.signer.Sign(ctx, jwt.SignRequest{Subject: sub, Audience: aud, TTL: p.accessTTLFor(is), Claims: claims, Type: AccessTokenType, Alg: jwt.Alg(is.policy.SigningAlgorithm), KeyID: is.policy.SigningKeyID})
	if err != nil {
		return "", err
	}
	return tok.Token, nil
}

// AccessTokenType is the JWS typ header of a JWT access token, RFC 9068's.
// A resource server verifying one offline passes it in jwt.Verifier.Types.
//
//ds:def id=oauthprovider-accesstokentype-k9w2mq4x owner=@khanakia stability=stable
const AccessTokenType = "at+jwt"

// claimTokenRow names the token row a JWT access token belongs to, for a
// resource server that wants to tell two tokens of one user apart.
const claimTokenRow = "token_id"

// atHash is the ID token's at_hash (OpenID Connect Core section 3.1.3.6):
// the left half of the access token's hash under the signing algorithm's
// hash, base64url: SHA-256, SHA-384 or SHA-512 by the algorithm's suffix,
// and SHA-512 for EdDSA (jwt.HashOf).
func (p *Plugin) atHash(accessToken string) (string, bool) {
	keys := p.signer.PublicKeys().Keys
	if len(keys) == 0 || accessToken == "" {
		return "", false
	}
	h := jwt.HashOf(jwt.Alg(keys[0].Alg))
	if h == 0 {
		return "", false
	}
	d := h.New()
	d.Write([]byte(accessToken))
	sum := d.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]), true
}
