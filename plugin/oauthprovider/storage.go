package oauthprovider

import (
	"crypto/sha256"
	"errors"

	"github.com/ubgo/auth"
)

// SecretKind names what a stored secret is, for a SecretHasher that hashes
// them differently.
type SecretKind string

// The secrets the provider stores hashed.
const (
	SecretClient  SecretKind = "client_secret"
	SecretCode    SecretKind = "authorization_code"
	SecretAccess  SecretKind = "access_token"
	SecretRefresh SecretKind = "refresh_token"
)

// SecretHasher computes the stored form of a client secret, code, access
// token or refresh token: an HMAC with a key from the app's secret store (a
// pepper), say, so a copy of the database alone cannot even confirm a guessed
// token. It must be deterministic, because tokens are looked up by their hash,
// and return exactly 32 bytes, the width of the hash columns on every engine
// (SHA-256's size). Changing it invalidates every stored secret.
type SecretHasher func(secret string, kind SecretKind) []byte

// ErrBadSecretHasher is a HashStoredSecrets function that is not
// deterministic or does not return 32 bytes; auth.New fails with it.
var ErrBadSecretHasher = errors.New("oauthprovider: HashStoredSecrets must return the same 32 bytes for the same input")

// storedHashSize is the hash columns' width.
const storedHashSize = sha256.Size

// HashStoredSecrets replaces SHA-256 as the stored form of every secret;
// see SecretHasher. Encrypted client secrets (EncryptClientSecrets) are a
// separate opt-in; the hash stays the form authentication compares.
func HashStoredSecrets(fn SecretHasher) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.HashStoredSecrets", fn) {
			return
		}
		p.secretHasher = fn
	}
}

// hashSecret is the stored form of secret.
func (p *Plugin) hashSecret(kind SecretKind, secret string) []byte {
	if p.secretHasher == nil {
		return auth.HashToken(auth.Token(secret))
	}
	return p.secretHasher(secret, kind)
}

// validateSecretHasher probes HashStoredSecrets twice per kind.
func (p *Plugin) validateSecretHasher() error {
	if p.secretHasher == nil {
		return nil
	}
	for _, k := range []SecretKind{SecretClient, SecretCode, SecretAccess, SecretRefresh} {
		a, b := p.secretHasher("probe", k), p.secretHasher("probe", k)
		if len(a) != storedHashSize || string(a) != string(b) {
			return ErrBadSecretHasher
		}
	}
	return nil
}

// TokenGenerator returns the random part of a new token (after its
// prefix): at least 22 characters from a cryptographic source,
// or the issuance fails with ErrShortGenerated.
type TokenGenerator func() string

// GenerateAccessToken replaces the opaque access token generator.
func GenerateAccessToken(fn TokenGenerator) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.GenerateAccessToken", fn) {
			return
		}
		p.genAccess = fn
	}
}

// GenerateRefreshToken replaces the refresh token generator.
func GenerateRefreshToken(fn TokenGenerator) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.GenerateRefreshToken", fn) {
			return
		}
		p.genRefresh = fn
	}
}

// newRandom is a generated token's random part: fn's, checked, or 256
// random bits.
func newRandom(fn TokenGenerator) (string, error) {
	if fn == nil {
		return auth.NewToken().Reveal(), nil
	}
	s := fn()
	if len(s) < minGeneratedLength {
		return "", ErrShortGenerated
	}
	return s, nil
}
