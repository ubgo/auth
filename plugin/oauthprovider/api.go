package oauthprovider

import (
	"context"
	"errors"
	"slices"
	"time"
)

// ErrNoGrantType is an IssueTokens call without a grant type: better-auth's
// issueTokens refuses one, because the grant is what TokenResponseFields
// and the audit trail see.
var ErrNoGrantType = errors.New("oauthprovider: IssueTokens needs a GrantType")

// IssueRequest is what IssueTokens mints, better-auth's
// OAuthTokenIssueParams. It is a raw minting primitive: the caller has
// already authenticated the client and decided that these scopes, this user
// and this resource are allowed (CheckScopes helps); nothing here asks the
// user.
type IssueRequest struct {
	// GrantType names the grant the tokens come from. Required.
	GrantType string
	// ClientID is the client the tokens are for; it must exist and be
	// enabled.
	ClientID string
	// UserID and SessionID are the user the tokens act for and the session
	// behind them; "" for a client's own token, which then cannot carry a
	// user scope.
	UserID, SessionID string
	Scopes            []string
	// Resource makes the access token a JWT for that resource (RFC 8707).
	Resource string
	// Nonce and AuthTime go into the ID token.
	Nonce    string
	AuthTime *time.Time
	// Confirmation binds the tokens (cnf): a DPoP key thumbprint or a
	// client certificate's, better-auth's issueTokens confirmation. The
	// token type becomes DPoP for a JKT.
	Confirmation *Confirmation
	// ReferenceID is the post-login reference the authorization was given
	// for.
	ReferenceID string
}

// IssueTokens mints an access token (and a refresh token with
// offline_access, and an ID token with openid) outside the token endpoint,
// better-auth's getOAuthProviderApi(...).issueTokens: for an app endpoint
// that runs its own grant. The resource's policy, the lifetimes, the token
// response fields and the hashed storage all apply as at the token
// endpoint.
func (p *Plugin) IssueTokens(ctx context.Context, in IssueRequest) (TokenResponse, error) {
	if in.GrantType == "" {
		return TokenResponse{}, ErrNoGrantType
	}
	r, err := p.resolveClient(ctx, in.ClientID)
	if err != nil {
		return TokenResponse{}, err
	}
	if r.disabledAt != nil {
		return TokenResponse{}, ErrInvalidClient
	}
	for _, s := range in.Scopes {
		if !slices.Contains(p.scopes, s) {
			return TokenResponse{}, ErrInvalidScope
		}
	}
	if in.UserID == "" {
		for _, s := range in.Scopes {
			if slices.Contains(userScopes, s) {
				return TokenResponse{}, ErrInvalidScope
			}
		}
	} else if err := p.userExists(ctx, in.UserID); err != nil {
		return TokenResponse{}, err
	}
	family, err := p.core.NewID(extensionFamilyPrefix)
	if err != nil {
		return TokenResponse{}, err
	}
	is := issuance{grantType: in.GrantType, client: r, userID: in.UserID, sessionID: in.SessionID, scopes: dedupe(in.Scopes),
		family: family, authTime: in.AuthTime, nonce: in.Nonce, resource: in.Resource, referenceID: in.ReferenceID}
	if c := in.Confirmation; c != nil {
		is.presetJKT = c.JKT
		if c.X5TS256 != "" {
			is.client.confirmation = &Confirmation{X5TS256: c.X5TS256}
		}
	}
	return p.issue(ctx, is)
}

// HashToken is the stored form of a token or secret, better-auth's
// hashToken: SHA-256, or HashStoredSecrets' function. A caller uses it to
// find or revoke a row by a token's value; the provider never stores the
// value itself.
func (p *Plugin) HashToken(token string, kind SecretKind) []byte { return p.hashSecret(kind, token) }

// ConsumeClientAssertion verifies a private_key_jwt client assertion (RFC
// 7523) for the client it names and spends its jti, better-auth's
// consumeClientAssertion: signed by a key of the client's jwks or jwks_uri,
// iss and sub the client, aud audience (the endpoint URL) or the issuer, exp
// within AssertionMaxLifetime, and a jti never seen before. Every failure
// is ErrInvalidClient.
func (p *Plugin) ConsumeClientAssertion(ctx context.Context, clientID, assertion, audience string) error {
	r, err := p.resolveClient(ctx, clientID)
	if err != nil || r.disabledAt != nil || r.c.AuthMethod != AuthMethodPrivateKeyJWT {
		return ErrInvalidClient
	}
	return p.verifyAssertion(ctx, r, assertion, audience)
}
