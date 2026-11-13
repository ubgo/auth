package oidcclient

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Sealer encrypts what the package puts in cookies (the session under the
// default store, the session id under a server-side one, and the sign-in
// flow's state, nonce and PKCE verifier) and opens it again. It is the seam
// for keys that live in a KMS or HSM (Vault transit, AWS KMS) and for an app
// that already has a sealer.
//
// The method set is the same as github.com/ubgo/auth's Sealer, so a value of
// that type (auth.RingSealer) is accepted as is, without this module
// importing the core.
//
// aad is the cookie's name: Open must refuse a value sealed under another
// aad, so a flow cookie can never be replayed as a session cookie. Open
// answers ErrSealedCorrupt (or an error wrapping it) for a value that does
// not open, which reads as "no session" (the person signs in again); any
// other error is a failure to reach the key service, answered as a failure
// (ReasonStoreFailed), never as an empty session. A Sealer that rotates keys
// puts its key id inside the sealed text; the built-in one tries each key.
type Sealer interface {
	Seal(ctx context.Context, plain []byte, aad string) (string, error)
	Open(ctx context.Context, sealed, aad string) ([]byte, error)
}

// MinSecretSize is the shortest secret NewSecretSealer accepts: 32 bytes,
// the AES-256 key size, so the derived key never has less entropy than its
// cipher. Generate one with `openssl rand -base64 32` and decode it.
const MinSecretSize = 32

// sealKeyInfo is the HKDF info that derives the cookie key from a secret.
// It names this package and a version, so the same secret given to another
// component derives an unrelated key, and a future format change can derive
// a new one without a new secret.
const sealKeyInfo = "github.com/ubgo/auth/oidcclient cookie v1"

// NewSecretSealer is the default Sealer: AES-256-GCM under a key derived
// from current with HKDF-SHA256, with the cookie name as associated data.
// current seals; current and every previous secret open, newest first, so a
// secret is rotated without signing anyone out: put the new secret first
// and the old one in previous, deploy, and drop the old one once the
// longest session lifetime has passed. Each secret is at least
// MinSecretSize bytes.
func NewSecretSealer(current []byte, previous ...[]byte) (Sealer, error) {
	for i, s := range append([][]byte{current}, previous...) {
		if len(s) < MinSecretSize {
			return nil, fmt.Errorf("%w: sealing secret %d is %d bytes, want at least %d", ErrInvalidConfig, i, len(s), MinSecretSize)
		}
	}
	keys := make([]cipher.AEAD, 0, 1+len(previous))
	for _, secret := range append([][]byte{current}, previous...) {
		key, err := hkdf.Key(sha256.New, secret, nil, sealKeyInfo, sealKeySize)
		if err != nil {
			return nil, fmt.Errorf("oidcclient: derive sealing key: %w", err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("oidcclient: sealing cipher: %w", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("oidcclient: sealing cipher: %w", err)
		}
		keys = append(keys, aead)
	}
	return &secretSealer{keys: keys}, nil
}

// sealKeySize is the AES-256 key size the secret is stretched to.
const sealKeySize = 32

// secretSealer is NewSecretSealer's Sealer: keys[0] seals, every key opens.
// The sealed form is base64url(nonce || ciphertext || tag), which is also a
// valid cookie value without escaping. A fresh random 96-bit nonce per seal
// keeps GCM safe for far more seals than one key ever sees here.
type secretSealer struct {
	keys []cipher.AEAD
}

// Seal encrypts plain under the current key with aad bound in.
func (s *secretSealer) Seal(_ context.Context, plain []byte, aad string) (string, error) {
	k := s.keys[0]
	nonce := make([]byte, k.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("oidcclient: seal nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(k.Seal(nonce, nonce, plain, []byte(aad))), nil
}

// Open decrypts sealed with each key in turn, newest first. Anything that
// does not open under any key with this aad is ErrSealedCorrupt.
func (s *secretSealer) Open(_ context.Context, sealed, aad string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(sealed)
	if err != nil {
		return nil, ErrSealedCorrupt
	}
	for _, k := range s.keys {
		if len(raw) < k.NonceSize()+k.Overhead() {
			return nil, ErrSealedCorrupt
		}
		if plain, err := k.Open(nil, raw[:k.NonceSize()], raw[k.NonceSize():], []byte(aad)); err == nil {
			return plain, nil
		}
	}
	return nil, ErrSealedCorrupt
}
