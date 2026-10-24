package auth

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
)

// MinSecretSize is the shortest secret WithSecret accepts, in bytes: 32
// bytes is 256 bits, the strength of the AES-256 keys derived from it, so a
// shorter secret would make every derived key weaker than its algorithm.
// `openssl rand -base64 32` produces 44 characters, which is plenty.
//
//ds:def id=minsecretsize-7wq2kx9m owner=@khanakia stability=stable
const MinSecretSize = 32

// Wiring errors of the secret.
var (
	// ErrSecretTooShort is returned by New when WithSecret got fewer than
	// MinSecretSize bytes, including an empty value from an unset variable:
	// a deployment that forgot its secret must not start with none.
	ErrSecretTooShort = errors.New("auth: the secret must be at least 32 bytes")

	// ErrNoSecret is returned by Config.DeriveKey when no WithSecret was
	// given, so a plugin can tell "derive one" from "the app passed none".
	ErrNoSecret = errors.New("auth: no secret configured; pass auth.WithSecret or an explicit key")
)

// Labels under which the core derives its own keys from the secret. A plugin
// derives under its own label, conventionally its name, so no two features
// ever share a key even though they share the secret.
const (
	// KeyLabelStatelessSessions seals stateless session tokens when
	// WithStatelessSessions was given no key.
	KeyLabelStatelessSessions = "stateless-sessions"
	// KeyLabelSnapshotCache seals the client-held session snapshot when
	// NewSnapshotCache was given no key.
	KeyLabelSnapshotCache = "snapshot-cache"
	// KeyLabelCompactCache signs the client-held, readable session copy
	// when NewCompactSessionCache was given no key.
	KeyLabelCompactCache = "compact-cache"
	// KeyLabelTwoFactor is plugin/twofactor's label for the key that seals
	// enrolled TOTP secrets when twofactor.WithEncryptionKey was not given.
	KeyLabelTwoFactor = "twofactor"
	// KeyLabelOAuthTokens is plugin/oauth's label for the key that seals
	// stored provider tokens when oauth.StoreTokens was given no key.
	KeyLabelOAuthTokens = "oauth-tokens"
	// KeyLabelOAuthState is plugin/oauth's label for the key that seals the
	// flow state into the flow cookie under oauth.StateInCookie.
	KeyLabelOAuthState = "oauth-state"
	// KeyLabelAuthGate is authgate's label for the key that seals its
	// session and flow cookies, derived from authgate.WithSecret.
	KeyLabelAuthGate = "authgate"
	// KeyLabelDeliveryOutbox seals the delivery outbox's payloads when
	// WithDeliveryOutbox was given no key.
	KeyLabelDeliveryOutbox = "delivery-outbox"
)

// keyLabelPrefix namespaces every HKDF info string, so a key derived here
// never equals one another library derives from the same secret and label.
const keyLabelPrefix = "github.com/ubgo/auth/"

// WithSecret sets one secret from which every sealing key the deployment did
// not pass explicitly is derived: the stateless session key, the snapshot
// and compact cache keys, and a plugin's key when it asks Config.DeriveKey. Each is
// HKDF-SHA256 of the secret under its own fixed label, so the features share
// one variable in the secret store and no key material. An explicit key still
// wins where one was given.
//
// Rotation: pass the new secret first and the old one after it. Keys derived
// from the first seal; keys derived from every secret open (KeyRing), so a
// stateless token or a sealed plugin value from before the rotation still
// opens, and the old secret is dropped once everything sealed under it has
// expired or been resealed. That is the same "current first, previous after"
// shape every ring-taking option has.
//
// There is no default and no development fallback. A missing or short secret
// fails New (ErrSecretTooShort), because a generated one would sign every
// user out at the next restart and nobody would know why.
//
//ds:def id=opt-withsecret-4ht8vn2q owner=@khanakia stability=stable
func WithSecret(current []byte, previous ...[]byte) Option {
	return func(s *settings) { s.cfg.secrets, s.secretSet = append([][]byte{current}, previous...), true }
}

// HasSecret reports whether WithSecret was given, so a plugin's Validate can
// say "pass a key or a secret" precisely.
func (c Config) HasSecret() bool { return len(c.secrets) > 0 }

// DeriveKey returns the SealKeySize-byte key for label, derived from the
// current WithSecret secret with HKDF-SHA256: the key that seals. The same
// secret and label always give the same key, and different labels give
// unrelated keys. label is one of the KeyLabel constants or a plugin's own
// fixed constant, never built from input: a label an attacker chooses is a
// key an attacker chooses. The error is ErrNoSecret when there is no secret.
//
//ds:def id=core-derivekey-6zp3rw8k owner=@khanakia stability=stable
func (c Config) DeriveKey(label string) ([]byte, error) {
	keys, err := c.DeriveKeys(label)
	if err != nil {
		return nil, err
	}
	return keys[0], nil
}

// DeriveKeys returns the key for label from every secret, current first:
// exactly the argument list NewKeyRing takes, so a plugin that seals its own
// values builds its ring with NewKeyRing(keys[0], keys[1:]...) and opens
// values sealed before a secret rotation.
//
//ds:def id=core-derivekeys-7xq4mn2b owner=@khanakia stability=stable
func (c Config) DeriveKeys(label string) ([][]byte, error) {
	return DeriveSecretKeys(label, c.secrets...)
}

// DeriveSecretKeys is Config.DeriveKeys without an Auth: the key for label
// from every secret, current first, by the same HKDF-SHA256 under the same
// label namespace. It exists for a package that seals values with no
// auth.New behind it (authgate, a login gate with no database), so its keys
// come from one derivation rule rather than a copy that could drift. The
// errors are ErrNoSecret for no secret, ErrSecretTooShort for a secret under
// MinSecretSize (New refuses those before Config.DeriveKeys can see them, so
// the check changes nothing there), and ErrBadOperation for an empty label.
// label is a fixed constant, never built from input.
//
//ds:def id=core-derivesecretkeys-4qv8nt2k owner=@khanakia stability=stable
func DeriveSecretKeys(label string, secrets ...[]byte) ([][]byte, error) {
	if len(secrets) == 0 {
		return nil, ErrNoSecret
	}
	if label == "" {
		return nil, fmt.Errorf("%w: DeriveKey needs a label", ErrBadOperation)
	}
	out := make([][]byte, 0, len(secrets))
	for i, secret := range secrets {
		if len(secret) < MinSecretSize {
			return nil, fmt.Errorf("%w: secret %d has %d bytes", ErrSecretTooShort, i, len(secret))
		}
		// hkdf.Key fails only for a length beyond 255 hashes; SealKeySize is
		// one, so the error cannot occur with a non-empty secret.
		key, err := hkdf.Key(sha256.New, secret, nil, keyLabelPrefix+label, SealKeySize)
		if err != nil {
			return nil, fmt.Errorf("auth: derive key %q: %w", label, err)
		}
		out = append(out, key)
	}
	return out, nil
}

// derivedOrGiven returns keys when the option got any, else the key derived
// for label, else ErrNoKeys naming the option: the stateless store and the
// snapshot cache both take "a key, or the secret".
func (c Config) derivedOrGiven(what, label string, keys [][]byte) ([][]byte, error) {
	if len(keys) > 0 {
		return keys, nil
	}
	derived, err := c.DeriveKeys(label)
	if errors.Is(err, ErrNoSecret) {
		return nil, fmt.Errorf("%w: %s (pass a key or auth.WithSecret)", ErrNoKeys, what)
	}
	if err != nil {
		return nil, err
	}
	return derived, nil
}
