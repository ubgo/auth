package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
)

// SealKeySize is the length of a key for Seal: AES-256.
//
//ds:def id=sealkeysize-ks8du6jx owner=@khanakia stability=stable
const SealKeySize = 32

// ErrSealedCorrupt is returned by Open for a value that does not open with the
// key and the additional data: tampered, copied to another row, or sealed with
// a different key.
var ErrSealedCorrupt = errors.New("auth: sealed value does not open; was the key changed?")

// Seal encrypts a secret a plugin must store and read back, such as a TOTP
// secret or a provider's refresh token, with AES-256-GCM. aad binds it to its
// row — pass the row's id — so a sealed value copied onto another row does not
// open. The result is base64 text, safe for any text column.
//
//ds:def id=core-seal-6juxhbp8 owner=@khanakia stability=stable
func Seal(key, plain []byte, aad string) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := randomBytes(gcm.NonceSize())
	return base64.RawStdEncoding.EncodeToString(gcm.Seal(nonce, nonce, plain, []byte(aad))), nil
}

// Open reverses Seal: it returns the plaintext of a value sealed with key and
// aad, or ErrSealedCorrupt for anything else, without saying which check
// failed, so a probe learns nothing about the key.
func Open(key []byte, sealed, aad string) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	raw, err := base64.RawStdEncoding.DecodeString(sealed)
	if err != nil || len(raw) < gcm.NonceSize() {
		return nil, ErrSealedCorrupt
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], []byte(aad))
	if err != nil {
		return nil, ErrSealedCorrupt
	}
	return plain, nil
}

// newGCM refuses any key but an AES-256 one. aes.NewCipher alone would also
// take 16- and 24-byte keys; the length test narrows it, and one branch covers
// both refusals.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil || len(key) != SealKeySize {
		return nil, fmt.Errorf("auth: seal key is %d bytes, want %d", len(key), SealKeySize)
	}
	return cipher.NewGCM(block)
}

// Sealer encrypts the secrets a plugin keeps at rest and must read back
// (provider refresh tokens, TOTP secrets): the seam for an app whose keys
// live in a KMS or HSM (Vault transit, AWS KMS, Google Cloud KMS) rather than
// in process memory. The default is the AES-256-GCM KeyRing (RingSealer);
// WithSealer supplies another for every plugin that seals through it.
//
// Seal returns text that fits a text column. It is opaque to the core, so an
// implementation that rotates keys puts its key id inside it (Vault's
// "vault:v3:…" form) and Open picks the key from it; the KeyRing needs none,
// because it tries each of its keys. aad binds the value to its row, exactly
// as Seal's aad does: Open must refuse a value sealed under another aad.
// Open answers ErrSealedCorrupt (or an error wrapping it) for a value that
// does not open, and any other error for a failure to reach the key service;
// callers treat both as "no secret", never as an empty one.
//
//ds:def id=core-sealer-4kw9vn2t owner=@khanakia stability=stable
type Sealer interface {
	Seal(ctx context.Context, plain []byte, aad string) (string, error)
	Open(ctx context.Context, sealed, aad string) ([]byte, error)
}

// RingSealer is the default Sealer: r's current key seals and every key
// opens, in the same format as KeyRing.Seal, so values sealed before an app
// switched to a Sealer still open.
//
//ds:def id=core-ringsealer-9qz3xh6p owner=@khanakia stability=stable
func RingSealer(r *KeyRing) Sealer { return ringSealer{r: r} }

// ringSealer adapts a KeyRing to Sealer; the ring needs no context and
// cannot fail to seal.
type ringSealer struct{ r *KeyRing }

func (s ringSealer) Seal(_ context.Context, plain []byte, aad string) (string, error) {
	return s.r.Seal(plain, aad), nil
}

func (s ringSealer) Open(_ context.Context, sealed, aad string) ([]byte, error) {
	return s.r.Open(sealed, aad)
}

// WithSealer makes s the Sealer every plugin that keeps secrets at rest uses
// when it was given no key of its own: an explicit plugin key still wins, and
// without WithSealer those plugins derive a KeyRing from WithSecret as
// before. A nil s is refused by New. Session tokens and the snapshot cache
// are not sealed through it: they are opened on every request, where a
// network round trip to a key service would be the wrong trade.
//
//ds:def id=opt-withsealer-2mt7rk5c owner=@khanakia stability=stable
func WithSealer(s Sealer) Option {
	return func(st *settings) {
		if st.optErrs.RefuseNil("auth.WithSealer", s) {
			return
		}
		st.cfg.sealer = s
	}
}

// Sealer returns the WithSealer value, or nil when the app set none and a
// plugin should fall back to its own key or DeriveKeys.
//
//ds:def id=core-config-sealer-6hd4pw8n owner=@khanakia stability=stable
func (c Config) Sealer() Sealer { return c.sealer }
