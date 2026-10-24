package password

import (
	"crypto/subtle"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// ScryptParams are the scrypt cost parameters and the derived key length of a
// stored "salt:key" hash. The format carries no parameters, so the verifier
// must be told the ones the old stack used.
//
//ds:def id=scryptparams-6kq2vn9b owner=@khanakia stability=stable
type ScryptParams struct {
	// N is the CPU and memory cost, a power of two.
	N int
	// R is the block size.
	R int
	// P is the parallelization factor.
	P int
	// KeyLen is the derived key length in bytes.
	KeyLen int
}

// BetterAuthScrypt are the parameters of the common scrypt hash format with a
// 16-byte hex salt and a 64-byte key: N 16384, r 16, p 1. An app importing
// hashes in that format passes them to Scrypt.
//
//ds:def id=betterauthscrypt-v7h4ym2e owner=@khanakia stability=stable
var BetterAuthScrypt = ScryptParams{N: 16384, R: 16, P: 1, KeyLen: 64}

// scryptSeparator joins the hex salt and the hex key in a stored hash.
const scryptSeparator = ":"

// Scrypt returns a Verifier for scrypt hashes stored as "hexsalt:hexkey" with
// the given parameters, the form Node's scrypt examples use.
// It only verifies; matches are re-hashed with the plugin's Hasher.
//
// Some producers of this format normalize the password to NFKC before
// hashing. The standard library has no NFKC, so a password is checked as
// typed; the rare password whose NFKC form differs from what the user types
// verifies only after a reset.
//
//ds:def id=scrypt-verifier-r5d9pw3c owner=@khanakia stability=stable
func Scrypt(params ScryptParams) Verifier { return scryptVerifier{params: params} }

type scryptVerifier struct{ params ScryptParams }

// Recognizes accepts "hex:hex" where the key part has the configured length.
// The format has no prefix, so the shape is the only signature; an argon2id
// or bcrypt string never has it, because both start with "$".
func (v scryptVerifier) Recognizes(encoded string) bool {
	_, _, ok := v.parse(encoded)
	return ok
}

func (v scryptVerifier) parse(encoded string) (salt, key []byte, ok bool) {
	saltHex, keyHex, found := strings.Cut(encoded, scryptSeparator)
	if !found || saltHex == "" || len(keyHex) != hex.EncodedLen(v.params.KeyLen) {
		return nil, nil, false
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, nil, false
	}
	key, err = hex.DecodeString(keyHex)
	if err != nil {
		return nil, nil, false
	}
	return salt, key, true
}

// Verify derives the key with the configured parameters and compares it in
// constant time. Recognizes already parsed the string, so an unparsable one
// here is errBadHash.
func (v scryptVerifier) Verify(pw Secret, encoded string) (bool, error) {
	salt, key, ok := v.parse(encoded)
	if !ok {
		return false, errBadHash
	}
	got, err := scrypt.Key([]byte(pw.Reveal()), salt, v.params.N, v.params.R, v.params.P, v.params.KeyLen)
	if err != nil {
		// scrypt refuses parameters it cannot run (N not a power of two, or
		// too much memory): a configuration mistake, not a wrong password.
		return false, err
	}
	return subtle.ConstantTimeCompare(got, key) == 1, nil
}
