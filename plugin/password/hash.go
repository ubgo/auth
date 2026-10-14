package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Verifier checks passwords against stored hashes of one format. The plugin
// asks each configured verifier whether it Recognizes a stored string before
// asking it to Verify, so verifiers for different formats can coexist and a
// row is never checked by the wrong algorithm.
//
// Verify must compare in constant time and must report a corrupt or hostile
// stored string as an error, never as a mismatch: a stored string that no
// verifier recognizes is a bug or an attack, and sign-in reports it as a
// server error rather than a wrong password.
//
//ds:def id=verifier-h7k2mx3q owner=@khanakia stability=stable
type Verifier interface {
	// Recognizes reports whether encoded is in this verifier's format. It
	// must be cheap and must not run the hash.
	Recognizes(encoded string) bool
	// Verify reports whether pw matches encoded.
	Verify(pw Secret, encoded string) (bool, error)
}

// Hasher is a Verifier that can also make hashes: the algorithm new and
// re-hashed passwords are stored with. The default is Argon2id; WithHasher
// replaces it, for an HSM, a key-derivation service or an app's own
// parameters. Every hash a Hasher makes must be one it Recognizes.
//
//ds:def id=hasher-2p9vq8rt owner=@khanakia stability=stable
type Hasher interface {
	Verifier
	// Hash returns the string to store for pw. An error fails the sign-up,
	// reset or change; it never stores anything.
	Hash(pw Secret) (string, error)
}

// Rehasher is optionally implemented by a Hasher whose own format carries
// parameters, so it can tell that a stored hash of its own format was made
// with other parameters than it uses now. The plugin replaces such a hash at
// the user's next successful sign-in. A Hasher without it never re-hashes its
// own format; hashes of other formats (AcceptLegacyHashes) are always
// re-hashed after a match.
//
//ds:def id=rehasher-c4n7wk2d owner=@khanakia stability=stable
type Rehasher interface {
	NeedsRehash(encoded string) bool
}

// Argon2Params are the argon2id cost parameters. They are written into every
// stored hash, so a hash is always checked with the cost it was made with, and
// a hash whose parameters differ from the plugin's is re-hashed at the next
// successful sign-in.
type Argon2Params struct {
	// Memory is the memory cost in KiB.
	Memory uint32
	// Time is the number of passes over the memory.
	Time uint32
	// Threads is the degree of parallelism (lanes).
	Threads uint8
}

// DefaultArgon2 follows the OWASP guidance for argon2id: 64 MiB, 3 passes,
// 2 lanes. About 50 ms on a current server core.
var DefaultArgon2 = Argon2Params{Memory: 64 * 1024, Time: 3, Threads: 2}

// Salt and key sizes, in bytes.
const (
	saltLen = 16
	keyLen  = 32
)

// hashPrefix starts every encoded hash, in the PHC string format that other
// argon2 implementations read, so a hash can move to another stack.
const hashPrefix = "$argon2id$v=19$"

// Bounds on stored parameters. argon2 itself needs at least 8 KiB per lane;
// 4 GiB and 100 passes are far above any real configuration.
const (
	minMemoryKiB = 8
	maxMemoryKiB = 4 << 20
	maxTime      = 100
	// maxKeyLen bounds the stored key; argon2 output length is ours to pick,
	// and 64 bytes is twice what the plugin writes.
	maxKeyLen = 64
)

// errBadHash is a stored string no configured verifier recognizes, or an
// argon2id string that does not parse. It is a server error at sign-in, never
// ErrInvalidCredentials: the row is corrupt, and the user cannot fix that by
// typing another password.
var errBadHash = errors.New("password: stored hash is in no recognized format")

// Argon2id is the default Hasher: argon2id in the PHC string format, with
// the cost in Params. It is exported so an app can wrap it (log timings,
// run it in a worker pool) or combine it with other verifiers through
// WithHasher and AcceptLegacyHashes. The zero value has no usable cost; take
// Params from DefaultArgon2 or your own.
//
//ds:def id=argon2id-9fw3jq6n owner=@khanakia stability=stable
type Argon2id struct {
	Params Argon2Params
}

var (
	_ Hasher   = Argon2id{}
	_ Rehasher = Argon2id{}
)

// Hash returns the PHC string of pw. It cannot fail: crypto/rand.Read never
// returns an error since Go 1.24 (it crashes the program instead, because a
// process without randomness must not mint salts), so the error is always
// nil and exists only to satisfy Hasher.
func (h Argon2id) Hash(pw Secret) (string, error) {
	if err := h.Params.check(); err != nil {
		return "", err
	}
	return hashPassword(pw, h.Params), nil
}

// ErrBadArgon2 is returned for argon2 parameters argon2 itself cannot run:
// a Time or Threads of 0. argon2.IDKey panics on them, so before this check
// password.Argon2(Argon2Params{}) made auth.New panic in Init's dummy hash.
var ErrBadArgon2 = errors.New("password: Argon2 needs Time and Threads of at least 1")

// check refuses the parameters argon2.IDKey panics on.
func (p Argon2Params) check() error {
	if p.Time < 1 || p.Threads < 1 {
		return fmt.Errorf("%w (Time %d, Threads %d)", ErrBadArgon2, p.Time, p.Threads)
	}
	return nil
}

// Recognizes reports whether encoded is an argon2id PHC string.
func (h Argon2id) Recognizes(encoded string) bool { return strings.HasPrefix(encoded, hashPrefix) }

// Verify reports whether pw matches encoded. The comparison is constant-time.
func (h Argon2id) Verify(pw Secret, encoded string) (bool, error) {
	ok, _, err := checkArgon2(pw, encoded)
	return ok, err
}

// NeedsRehash reports whether encoded was made with other parameters than
// Params, so the plugin can upgrade it at the next successful sign-in. A
// string that does not parse needs no re-hash, because Verify refuses it
// first.
func (h Argon2id) NeedsRehash(encoded string) bool {
	parsed, err := parseHash(encoded)
	return err == nil && parsed.params != h.Params
}

// hashPassword returns the PHC string of pw with cost p.
func hashPassword(pw Secret, p Argon2Params) string {
	salt := make([]byte, saltLen)
	rand.Read(salt)
	key := argon2.IDKey([]byte(pw.Reveal()), salt, p.Time, p.Memory, p.Threads, keyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("%sm=%d,t=%d,p=%d$%s$%s", hashPrefix, p.Memory, p.Time, p.Threads, enc.EncodeToString(salt), enc.EncodeToString(key))
}

// checkArgon2 reports whether pw matches encoded, and the parameters the
// hash was made with. The comparison is constant-time.
func checkArgon2(pw Secret, encoded string) (bool, Argon2Params, error) {
	h, err := parseHash(encoded)
	if err != nil {
		return false, Argon2Params{}, err
	}
	got := argon2.IDKey([]byte(pw.Reveal()), h.salt, h.params.Time, h.params.Memory, h.params.Threads, uint32(len(h.key)))
	return subtle.ConstantTimeCompare(got, h.key) == 1, h.params, nil
}

// parsedHash is a PHC string taken apart.
type parsedHash struct {
	params Argon2Params
	salt   []byte
	key    []byte
}

// parseHash reads a stored PHC string. A corrupt or hostile row is errBadHash,
// including one whose parameters would make argon2 allocate gigabytes or
// spin: parameters outside the sane range are a bad hash, not a cost.
func parseHash(encoded string) (parsedHash, error) {
	rest, ok := strings.CutPrefix(encoded, hashPrefix)
	if !ok {
		return parsedHash{}, errBadHash
	}
	parts := strings.Split(rest, "$")
	if len(parts) != 3 {
		return parsedHash{}, errBadHash
	}
	var p Argon2Params
	if _, err := fmt.Sscanf(parts[0], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return parsedHash{}, errBadHash
	}
	if p.Memory < minMemoryKiB || p.Memory > maxMemoryKiB || p.Time < 1 || p.Time > maxTime || p.Threads < 1 {
		return parsedHash{}, errBadHash
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[1])
	if err != nil || len(salt) == 0 {
		return parsedHash{}, errBadHash
	}
	key, err := enc.DecodeString(parts[2])
	if err != nil || len(key) == 0 || len(key) > maxKeyLen {
		return parsedHash{}, errBadHash
	}
	return parsedHash{params: p, salt: salt, key: key}, nil
}

// checkPassword is the one place a password meets a stored hash. It picks the
// verifier by format: the Hasher's own format first, then the legacy
// verifiers in the order given, and errBadHash when none recognizes the
// string. rehash is true when the match should be stored again with the
// Hasher: every legacy match, and an own-format hash the Hasher says is out
// of date (Rehasher).
//
// Until re-hashed, an imported account costs its old algorithm's time at
// sign-in, while an unknown identifier costs the Hasher's (the dummy hash).
// That difference is inherent in verifying foreign hashes at all and ends at
// the user's first successful sign-in; the guard on doSignIn still holds,
// because every path runs exactly one verification.
func (p *Plugin) checkPassword(pw Secret, encoded string) (ok, rehash bool, err error) {
	if p.hasher.Recognizes(encoded) {
		ok, err := p.hasher.Verify(pw, encoded)
		if err != nil || !ok {
			return false, false, err
		}
		r, can := p.hasher.(Rehasher)
		return true, can && r.NeedsRehash(encoded), nil
	}
	for _, v := range p.legacy {
		if v.Recognizes(encoded) {
			ok, err := v.Verify(pw, encoded)
			return ok, ok, err
		}
	}
	return false, false, errBadHash
}
