package oauthprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Errors answered under these names.
var (
	// ErrUnsupportedTokenType is a revocation of a still-valid JWT access
	// token under RefuseJWTRevocation (RFC 7009 section 2.2.1).
	ErrUnsupportedTokenType = auth.NewError("oauthprovider.unsupported_token_type", http.StatusBadRequest, "This token type cannot be revoked; it expires on its own.")
	// ErrInvalidUser is a grant whose user has been deleted since it was
	// issued.
	ErrInvalidUser = auth.NewError("oauthprovider.invalid_user", http.StatusBadRequest, "The user of this grant no longer exists.")
	// ErrUnsupportedPromptSelectAccount is prompt=select_account with no
	// SelectAccount page; SelectAccountFallsBackToLogin sends such a request to
	// the login page instead.
	ErrUnsupportedPromptSelectAccount = auth.NewError("oauthprovider.unsupported_prompt_select_account", http.StatusBadRequest, "This server cannot show an account picker.")
)

// RevokeAccessTokenOnly makes revoking an access token end that token only:
// its refresh token keeps working. Off by default, because a client that
// revokes an access token after a leak usually wants the whole grant gone, and
// RFC 7009 lets the server end both; auth.New logs a warning while it is on.
func RevokeAccessTokenOnly() Option { return func(p *Plugin) { p.revokeAccessOnly = true } }

// RefuseJWTRevocation answers the revocation of a still-valid JWT access
// token with unsupported_token_type (an expired or unknown one is a 200
// no-op), which tells the client the token stays usable by offline verifiers
// until it expires. Off by default: the provider then revokes it, so in-process
// checks and introspection refuse it at once. auth.New logs a warning while it
// is on.
func RefuseJWTRevocation() Option { return func(p *Plugin) { p.refuseJWTRevoke = true } }

// UserInfoInsufficientScope answers userinfo for a token without openid
// with RFC 6750's 403 insufficient_scope instead of 400 invalid_scope (the
// default).
func UserInfoInsufficientScope() Option { return func(p *Plugin) { p.userInfoForbidden = true } }

// SelectAccountFallsBackToLogin sends prompt=select_account, when no
// SelectAccount page is configured, to the login page so the user can sign
// in as someone else; the default is ErrUnsupportedPromptSelectAccount.
func SelectAccountFallsBackToLogin() Option { return func(p *Plugin) { p.selectViaLogin = true } }

// warnOptIns logs, at every start, the options that relax a default, so
// none is on by accident.
func (p *Plugin) warnOptIns(a *auth.Auth) {
	warn := func(option, risk string) {
		a.Logger().Warn("oauthprovider: "+option+" is on", "risk", risk)
	}
	if p.revokeAccessOnly {
		warn("RevokeAccessTokenOnly", "revoking an access token leaves its refresh token working")
	}
	if p.refuseJWTRevoke {
		warn("RefuseJWTRevocation", "a JWT access token cannot be revoked and stays usable until it expires")
	}
	if p.secretCrypt != nil {
		warn("EncryptClientSecrets", "client secrets are stored recoverable; whoever holds the key and the database holds every secret")
	}
	if p.replay != nil {
		warn("RefreshReplay", "issued tokens are stored recoverable for the reuse window")
	}
}

// isJWT reports a compact JWS: three dot-separated parts.
func isJWT(token string) bool { return strings.Count(token, ".") == 2 }

// sessionLive is sessionAlive for a user and a session id: true when the
// session still exists, there is none, or sessions cannot be listed.
func (p *Plugin) sessionLive(ctx context.Context, userID, sessionID string) (bool, error) {
	if userID == "" || sessionID == "" {
		return true, nil
	}
	live, err := p.core.Sessions(ctx, userID)
	if errors.Is(err, auth.ErrSessionsUnavailable) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(live, func(s auth.Session) bool { return s.ID == sessionID }), nil
}

// SecretEncryption seals and opens a value the provider must be able to
// read back: client secrets under EncryptClientSecrets, cached token
// responses under RefreshReplay. Encrypt must be authenticated encryption
// (an AEAD such as AES-GCM, under a key from the app's secret store) so a
// changed ciphertext fails Decrypt instead of opening to something else.
type SecretEncryption struct {
	Encrypt func(plaintext string) (string, error)
	Decrypt func(ciphertext string) (string, error)
}

// ErrBadEncryption is a SecretEncryption without both functions, or whose
// Decrypt does not give back what Encrypt sealed; auth.New fails with it.
var ErrBadEncryption = errors.New("oauthprovider: a SecretEncryption needs Encrypt and Decrypt, and Decrypt(Encrypt(x)) == x")

// ErrSecretNotRecoverable is RevealClientSecret for a client whose secret
// was stored only as a hash: without EncryptClientSecrets, or created
// before it was turned on, or a client with no secret.
var ErrSecretNotRecoverable = auth.NewError("oauthprovider.secret_not_recoverable", http.StatusNotFound, "This client's secret cannot be read back.")

// EncryptClientSecrets also stores each new client secret encrypted, so
// RevealClientSecret can read it back (for client_secret_jwt-style use, or to
// show it again). Authentication still compares the hash in constant time. Off
// by default because a recoverable secret is a weaker store than a hash:
// whoever holds the key and a copy of the database holds every secret. auth.New
// logs a warning while it is on.
func EncryptClientSecrets(e SecretEncryption) Option { return func(p *Plugin) { p.secretCrypt = &e } }

// RefreshReplay makes a refresh token reused inside RefreshReuseInterval
// answer the response its first use got, instead of a new pair: the response is
// stored encrypted until the window ends, and a reuse asking for other
// scopes, another resource or another DPoP key is invalid_grant without
// revoking the family. Needs RefreshReuseInterval. Off by default because
// it stores issued tokens in a recoverable form; auth.New logs a warning
// while it is on.
func RefreshReplay(e SecretEncryption) Option { return func(p *Plugin) { p.replay = &e } }

// validateEncryption checks every SecretEncryption with a round trip.
func (p *Plugin) validateEncryption() error {
	// Each refusal names the option that set the SecretEncryption, because
	// both take the same type and the sentinel alone cannot say which.
	for _, s := range []struct {
		option string
		e      *SecretEncryption
	}{
		{"oauthprovider.EncryptClientSecrets", p.secretCrypt},
		{"oauthprovider.RefreshReplay", p.replay},
	} {
		e := s.e
		if e == nil {
			continue
		}
		if e.Encrypt == nil || e.Decrypt == nil {
			return fmt.Errorf("%w: %s needs both functions", ErrBadEncryption, s.option)
		}
		c, err := e.Encrypt("probe")
		if err != nil {
			return errors.Join(fmt.Errorf("%w: %s: Encrypt failed", ErrBadEncryption, s.option), err)
		}
		if back, err := e.Decrypt(c); err != nil || back != "probe" {
			return fmt.Errorf("%w: %s: Decrypt does not give back what Encrypt sealed", ErrBadEncryption, s.option)
		}
	}
	if p.replay != nil && p.refreshReuse <= 0 {
		return errors.Join(ErrBadEncryption, errors.New("oauthprovider: RefreshReplay needs RefreshReuseInterval"))
	}
	return nil
}

// sealSecret is the encrypted form of a new client secret, or nil without
// EncryptClientSecrets.
func (p *Plugin) sealSecret(secret string) (*string, error) {
	if p.secretCrypt == nil || secret == "" {
		return nil, nil
	}
	c, err := p.secretCrypt.Encrypt(secret)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// RevealClientSecret reads a client's secret back under
// EncryptClientSecrets; ErrSecretNotRecoverable otherwise. It is Go-only:
// no operation exposes it.
func (p *Plugin) RevealClientSecret(ctx context.Context, clientID string) (string, error) {
	var enc *string
	err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(ClientSecretEnc, &enc)).From(TableClient).Where(sqlb.Eq(ClientIDCol, clientID)))
	if errors.Is(err, sqlb.ErrNoRows) {
		return "", ErrClientNotFound
	}
	if err != nil {
		return "", err
	}
	if enc == nil || p.secretCrypt == nil {
		return "", ErrSecretNotRecoverable
	}
	return p.secretCrypt.Decrypt(*enc)
}
