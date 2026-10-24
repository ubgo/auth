package password

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// Django's default password hasher writes
// "pbkdf2_sha256$<iterations>$<salt>$<base64 key>". The salt is used as the
// literal ASCII string, not decoded; the key is standard base64 with padding.
const (
	djangoPrefix    = "pbkdf2_sha256$"
	djangoSeparator = "$"
	djangoSections  = 3
	// maxPBKDF2Iterations bounds what a stored row can make the server
	// compute. Django's default has grown to about a million; ten million is
	// far above any version's default, so a hostile row with a billion
	// iterations is a bad hash, not a denial of service.
	maxPBKDF2Iterations = 10_000_000
)

// DjangoPBKDF2 returns a Verifier for Django's default password format,
// PBKDF2-HMAC-SHA256 as "pbkdf2_sha256$iterations$salt$key". It only
// verifies; matches are re-hashed with the plugin's Hasher. Django's other
// hashers (bcrypt_sha256, argon2, scrypt) are not this format: bcrypt_sha256
// hashes a SHA-256 digest, so Bcrypt cannot verify it either.
//
//ds:def id=djangopbkdf2-verifier-t2x6bk8n owner=@khanakia stability=stable
func DjangoPBKDF2() Verifier { return djangoVerifier{} }

type djangoVerifier struct{}

func (djangoVerifier) Recognizes(encoded string) bool {
	return strings.HasPrefix(encoded, djangoPrefix)
}

// Verify derives the key and compares it in constant time. A string with the
// prefix but the wrong shape, a non-numeric or out-of-range iteration count,
// or undecodable base64 is errBadHash.
func (djangoVerifier) Verify(pw Secret, encoded string) (bool, error) {
	rest, _ := strings.CutPrefix(encoded, djangoPrefix)
	parts := strings.Split(rest, djangoSeparator)
	if len(parts) != djangoSections || parts[1] == "" {
		return false, errBadHash
	}
	iterations, err := strconv.Atoi(parts[0])
	if err != nil || iterations < 1 || iterations > maxPBKDF2Iterations {
		return false, errBadHash
	}
	key, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(key) == 0 {
		return false, errBadHash
	}
	got := pbkdf2.Key([]byte(pw.Reveal()), []byte(parts[1]), iterations, len(key), sha256.New)
	return subtle.ConstantTimeCompare(got, key) == 1, nil
}
