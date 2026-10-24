package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/ubgo/auth"
)

// kmsPrefix starts every value the fake key service seals, followed by the
// key version and the ciphertext: "kms:v2:…". Vault transit writes
// "vault:v2:…" the same way, so a rotated service knows which key opens a
// value without trying them all.
const kmsPrefix = "kms:v"

// kmsKeySize is the AES-256 key size the fake service uses for each version.
const kmsKeySize = 32

// errKMSUnavailable is what the fake service answers while it is down, the
// way a real one answers a timeout or a 503.
var errKMSUnavailable = errors.New("kms: service unavailable")

// fakeKMS stands in for a key service such as Vault transit, AWS KMS or
// Google Cloud KMS. Its keys never leave it: the app sends a plaintext and
// gets text back, and sends the text back to open it. It keeps every key
// version, seals with the newest and opens with the one the text names, so
// Rotate needs no re-encryption of what is stored. A real implementation
// replaces the body of Seal and Open with a call to the service, passing aad
// as its additional authenticated data (Vault's "context", KMS's
// "EncryptionContext").
type fakeKMS struct {
	mu       sync.Mutex
	versions []cipher.AEAD // versions[i] is key version i+1
	down     bool
	seals    int
	opens    int
}

// newFakeKMS starts the service with one key version.
func newFakeKMS() (*fakeKMS, error) {
	k := &fakeKMS{}
	if err := k.Rotate(); err != nil {
		return nil, err
	}
	return k, nil
}

// Rotate adds a key version, which seals from now on. Earlier versions keep
// opening what they sealed.
func (k *fakeKMS) Rotate() error {
	key := make([]byte, kmsKeySize)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.versions = append(k.versions, gcm)
	return nil
}

// Seal encrypts plain under the newest key version, bound to aad, and
// returns "kms:v<version>:<base64url(nonce|ciphertext)>".
// ds:def id=fakekms-seal-sx8hws4z
func (k *fakeKMS) Seal(_ context.Context, plain []byte, aad string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.down {
		return "", errKMSUnavailable
	}
	k.seals++
	gcm := k.versions[len(k.versions)-1]
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := gcm.Seal(nonce, nonce, plain, []byte(aad))
	return kmsPrefix + strconv.Itoa(len(k.versions)) + ":" + base64.RawURLEncoding.EncodeToString(out), nil
}

// Open decrypts a value Seal returned, with the key version it names, and
// refuses one sealed under another aad: a secret copied to another row
// does not open there. A value that does not open answers an error wrapping
// auth.ErrSealedCorrupt, as the Sealer contract asks.
func (k *fakeKMS) Open(_ context.Context, sealed, aad string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.down {
		return nil, errKMSUnavailable
	}
	k.opens++
	rest, ok := strings.CutPrefix(sealed, kmsPrefix)
	if !ok {
		return nil, fmt.Errorf("%w: not a kms value", auth.ErrSealedCorrupt)
	}
	ver, body, ok := strings.Cut(rest, ":")
	n, err := strconv.Atoi(ver)
	if !ok || err != nil || n < 1 || n > len(k.versions) {
		return nil, fmt.Errorf("%w: unknown key version %q", auth.ErrSealedCorrupt, ver)
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	gcm := k.versions[n-1]
	if err != nil || len(raw) < gcm.NonceSize() {
		return nil, fmt.Errorf("%w: malformed", auth.ErrSealedCorrupt)
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", auth.ErrSealedCorrupt, err)
	}
	return plain, nil
}

// setDown takes the service down or brings it back, for the outage test.
func (k *fakeKMS) setDown(down bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.down = down
}

// calls reports how many seals and opens reached the service.
func (k *fakeKMS) calls() (seals, opens int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.seals, k.opens
}

// The fake service is an auth.Sealer; the compiler checks it here.
var _ auth.Sealer = (*fakeKMS)(nil)
