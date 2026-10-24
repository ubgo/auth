package password

import (
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// bcryptPrefixes start the modular-crypt bcrypt strings in use: $2a$ (the
// original), $2b$ (OpenBSD's fix) and $2y$ (PHP's; Laravel and Symfony). Go's
// bcrypt reads all three, so an import from Rails, Laravel, Spring or Django's
// bcrypt hasher verifies without rewriting the strings. $2x$ (PHP's deliberately
// buggy variant) is left out: it does not verify correctly anywhere else either.
var bcryptPrefixes = []string{"$2a$", "$2b$", "$2y$"}

// Bcrypt returns a Verifier for bcrypt hashes, the format of Rails
// (has_secure_password), Laravel, Spring Security and many others. It only
// verifies; new and re-hashed passwords use the plugin's Hasher, so an
// imported user base migrates to argon2id one sign-in at a time.
//
// bcrypt reads at most 72 bytes of a password; a longer imported password
// verifies on its first 72 bytes, as it did on the old stack, and is then
// re-hashed in full.
//
//ds:def id=bcrypt-verifier-m3t8xd5q owner=@khanakia stability=stable
func Bcrypt() Verifier { return bcryptVerifier{} }

type bcryptVerifier struct{}

func (bcryptVerifier) Recognizes(encoded string) bool {
	for _, p := range bcryptPrefixes {
		if strings.HasPrefix(encoded, p) {
			return true
		}
	}
	return false
}

// Verify runs bcrypt's own constant-time comparison. A mismatch is false; a
// string that bcrypt cannot parse, or whose cost is outside bcrypt's range,
// is errBadHash, so a corrupt row is a server error and never a cheap refusal.
func (bcryptVerifier) Verify(pw Secret, encoded string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(encoded), []byte(pw.Reveal()))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
		return false, nil
	}
	return false, errBadHash
}
