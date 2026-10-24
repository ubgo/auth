package jwt

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Signer signs tokens. The plugin ships two: the key passed to
// WithSigningKey, and Rotating, which derives a fresh Ed25519 key every
// interval. An app whose private key must never leave a KMS implements it
// (or, simpler, passes a KMS crypto.Signer to WithSigningKey): Sign asks the
// service for the signature and PublicKeys returns what the JWKS must list.
// The algorithm follows the first key: ed25519.PublicKey is EdDSA,
// *rsa.PublicKey RS256, *ecdsa.PublicKey on P-256 ES256; any other key is
// ErrUnsupportedKey. The signature the plugin receives is checked against
// that key before a token is minted (ErrSignature).
//
//ds:def id=signer-v8kd3qxw owner=@khanakia stability=stable
type Signer interface {
	// PublicKeys returns every key a token in flight may carry, the key
	// that signs now first: its KeyID becomes the token's kid header, and
	// the JWKS publishes the list in this order. An empty list means the
	// signer cannot sign, and Token fails with ErrSignerKey.
	PublicKeys() []crypto.PublicKey
	// Sign returns the JWS signature of the signing input (header dot
	// payload) with the private half of key, the first key PublicKeys
	// returned when the token's header was built: for EdDSA the Ed25519
	// signature of the input, for RS256 the PKCS #1 v1.5 signature of its
	// SHA-256, for ES256 the 64-byte r||s of its SHA-256 (RFC 7518 section
	// 3.4, not the ASN.1 form crypto.Signer returns). The key is passed
	// back, rather than assumed current, so a signer whose key changes
	// between the two calls, at the instant of a rotation, still signs with
	// the key the header names.
	Sign(ctx context.Context, key crypto.PublicKey, signingInput []byte) ([]byte, error)
}

// ErrSignerKey is a Signer with no key to sign with, or a Rotating signer
// asked to sign with a key outside its grace: the token would carry a kid no
// verifier could find, so the call fails instead of minting it.
var ErrSignerKey = errors.New("jwt: Signer has no published key to sign with")

// WithSigner replaces WithSigningKey with a custom Signer: a KMS, an HSM, or
// Rotating. One of the two is required.
//
//ds:def id=withsigner-k2mz7nrt owner=@khanakia stability=stable
func WithSigner(s Signer) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("jwt.WithSigner", s) {
			return
		}
		p.signer = s
	}
}

// keySigner signs with one private key, the WithSigningKey case: Ed25519,
// RSA, ECDSA, or a KMS behind crypto.Signer.
type keySigner struct{ key crypto.Signer }

func (s keySigner) Sign(_ context.Context, _ crypto.PublicKey, in []byte) ([]byte, error) {
	return signWithKey(s.key, in)
}

func (s keySigner) PublicKeys() []crypto.PublicKey { return []crypto.PublicKey{s.key.Public()} }

// Rotation constants.
const (
	// RotationSeedSize is the length of the seed Rotating derives keys from:
	// 256 bits, so the seed is as strong as the keys it makes.
	//ds:def id=rotationseedsize-f4wq9bkm owner=@khanakia stability=stable
	RotationSeedSize = 32
	// MinRotationInterval bounds how often keys change: below an hour the
	// key set churns faster than verifiers refetch it, and every unknown kid
	// becomes a fetch.
	//ds:def id=minrotationinterval-h7zt2vcp owner=@khanakia stability=stable
	MinRotationInterval = time.Hour
	// rotationInfo is the HKDF info string that binds a derived key to its
	// purpose and period, so a seed shared with another purpose can never
	// yield the same key.
	rotationInfo = "github.com/ubgo/auth/plugin/jwt rotating key "
)

// Rotation errors, returned by auth.New.
var (
	// ErrRotationSeed is a seed that is not RotationSeedSize bytes.
	ErrRotationSeed = errors.New("jwt: Rotating needs a 32-byte seed")
	// ErrRotationInterval is an interval below MinRotationInterval.
	ErrRotationInterval = errors.New("jwt: Rotating interval is at least an hour")
	// ErrRotationGrace is a grace period shorter than the token TTL: a
	// token could then outlive its key's publication and fail to verify
	// while still valid.
	ErrRotationGrace = errors.New("jwt: Rotating grace period is at least the token TTL")
)

// Rotating is a Signer that changes Ed25519 (EdDSA) keys automatically. RS256
// and ES256 keys rotate by hand (WithSigningKey with the new key, PreviousKeys
// with the old), because the standard library derives no RSA key from a seed
// and only Go 1.25 parses a raw ECDSA scalar. The key of each
// period (interval-wide, counted from the Unix epoch) is derived from the
// seed with HKDF-SHA256, so every instance of the app derives the same key
// for the same period with no storage and no coordination, and a restart
// changes nothing. The JWKS publishes the current key first, then the keys
// of the periods that ended within grace, so a token signed just before a
// rotation verifies until it expires; grace must be at least the TTL.
//
// The seed is the one secret: whoever holds it can derive every key, past
// and future, which is also true of a stored private key. Rotating buys
// a bounded lifetime per key and an automatic schedule, not protection
// against a leaked seed; rotate the seed itself for that.
//
//ds:def id=rotating-q3nx8wtd owner=@khanakia stability=stable
func Rotating(seed []byte, interval, grace time.Duration) Signer {
	return &rotatingSigner{seed: seed, interval: interval, grace: grace, now: time.Now}
}

// rotatingSigner derives per-period keys; now is the clock, replaced by the
// plugin's Init so tests and the core agree on the time.
type rotatingSigner struct {
	seed     []byte
	interval time.Duration
	grace    time.Duration
	now      func() time.Time
}

// validate is the configuration check auth.New runs through Validate.
func (r *rotatingSigner) validate(ttl time.Duration) error {
	switch {
	case len(r.seed) != RotationSeedSize:
		return ErrRotationSeed
	case r.interval < MinRotationInterval:
		return ErrRotationInterval
	case r.grace < ttl:
		return ErrRotationGrace
	}
	return nil
}

// period numbers the interval t falls in.
func (r *rotatingSigner) period(t time.Time) int64 { return t.Unix() / int64(r.interval/time.Second) }

// keyFor derives the key of period n. HKDF's output is deterministic, so
// the derivation is repeated rather than cached: a cache would be state,
// and the derivation costs two hashes.
func (r *rotatingSigner) keyFor(n int64) ed25519.PrivateKey {
	seed, err := hkdf.Key(sha256.New, r.seed, nil, rotationInfo+strconv.FormatInt(n, 10), ed25519.SeedSize)
	if err != nil {
		// hkdf.Key fails only for an output longer than the hash allows;
		// ed25519.SeedSize is far below that, so this is unreachable.
		panic(fmt.Sprintf("jwt: derive rotating key: %v", err))
	}
	return ed25519.NewKeyFromSeed(seed)
}

// Sign signs with the published key whose public half is pub: the current
// period's, or an earlier one still within grace when the period turned
// between PublicKeys and Sign.
func (r *rotatingSigner) Sign(_ context.Context, pub crypto.PublicKey, in []byte) ([]byte, error) {
	for _, k := range r.privateKeys() {
		if k.Public().(ed25519.PublicKey).Equal(pub) {
			return ed25519.Sign(k, in), nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrSignerKey, KeyID(pub))
}

// PublicKeys lists the current period's key, then each earlier period whose
// end is within grace of now.
func (r *rotatingSigner) PublicKeys() []crypto.PublicKey {
	keys := r.privateKeys()
	out := make([]crypto.PublicKey, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Public().(ed25519.PublicKey))
	}
	return out
}

// privateKeys derives the current period's key and the keys of the periods
// that ended within grace, current first.
func (r *rotatingSigner) privateKeys() []ed25519.PrivateKey {
	t := r.now()
	cur := r.period(t)
	out := []ed25519.PrivateKey{r.keyFor(cur)}
	for n := cur - 1; n >= 0; n-- {
		end := time.Unix((n+1)*int64(r.interval/time.Second), 0)
		if t.Sub(end) > r.grace {
			break
		}
		out = append(out, r.keyFor(n))
	}
	return out
}
