package auth

import (
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
)

// KeyRing holds the current sealing key and the previous ones, so a key can
// be rotated without losing what the old key sealed: new values are sealed
// with the current key, and a value is opened with whichever key opens it.
// Stateless session tokens, snapshot cache values and any plugin value sealed
// through Seal and Open can all ride on one ring.
//
// A sealed value carries no key id: GCM refuses a wrong key in constant
// time, so trying each key in turn costs microseconds and keeps the sealed
// format identical to a single key's, which is what lets a deployment move
// from one key to a ring with nothing resealed. The order matters only as a
// hint: the current key first, then the previous ones newest first, so most
// values open on the first try.
//
//ds:def id=core-keyring-6zn8rq2v owner=@khanakia stability=stable
type KeyRing struct {
	gcms []cipher.AEAD
}

// NewKeyRing returns a ring whose first key seals and whose every key opens.
// Each key is SealKeySize bytes; a ring with no key, or with a key of another
// size, is an error. Rotation is: generate a new key, pass it first and the
// old one second, deploy; once every value sealed with the old key has
// expired or been resealed, drop it.
//
//ds:def id=core-newkeyring-3wk7xm5p owner=@khanakia stability=stable
func NewKeyRing(current []byte, previous ...[]byte) (*KeyRing, error) {
	keys := append([][]byte{current}, previous...)
	r := &KeyRing{gcms: make([]cipher.AEAD, 0, len(keys))}
	for i, k := range keys {
		gcm, err := newGCM(k)
		if err != nil {
			return nil, fmt.Errorf("auth: key ring: key %d: %w", i, err)
		}
		r.gcms = append(r.gcms, gcm)
	}
	return r, nil
}

// ErrNoKeys is returned by New when a ring-taking option got no key at all.
var ErrNoKeys = errors.New("auth: no sealing key given")

// Len returns how many keys the ring holds.
func (r *KeyRing) Len() int { return len(r.gcms) }

// Seal encrypts plain with the current key, as Seal does; see that function
// for aad.
func (r *KeyRing) Seal(plain []byte, aad string) string {
	return base64.RawStdEncoding.EncodeToString(r.sealRaw(plain, aad))
}

// Open reverses Seal with whichever key opens the value, or ErrSealedCorrupt
// when none does, without saying which check failed.
func (r *KeyRing) Open(sealed, aad string) ([]byte, error) {
	raw, err := base64.RawStdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, ErrSealedCorrupt
	}
	return r.openRaw(raw, aad)
}

// sealRaw seals with the current key: nonce, then ciphertext.
func (r *KeyRing) sealRaw(plain []byte, aad string) []byte {
	gcm := r.gcms[0]
	nonce := randomBytes(gcm.NonceSize())
	return gcm.Seal(nonce, nonce, plain, []byte(aad))
}

// openRaw tries every key in order. Every GCM in the ring has the same
// nonce size, since all are AES-256-GCM.
func (r *KeyRing) openRaw(raw []byte, aad string) ([]byte, error) {
	size := r.gcms[0].NonceSize()
	if len(raw) < size {
		return nil, ErrSealedCorrupt
	}
	for _, gcm := range r.gcms {
		if plain, err := gcm.Open(nil, raw[:size], raw[size:], []byte(aad)); err == nil {
			return plain, nil
		}
	}
	return nil, ErrSealedCorrupt
}

// ringOf builds the ring an option received: one key or several. It is how
// WithStatelessSessions and NewSnapshotCache take a rotation without a
// second option.
func ringOf(what string, keys [][]byte) (*KeyRing, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoKeys, what)
	}
	r, err := NewKeyRing(keys[0], keys[1:]...)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrBadOperation, what, err)
	}
	return r, nil
}
