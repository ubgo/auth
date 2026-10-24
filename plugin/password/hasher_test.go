package password

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// tinyScrypt is the smallest scrypt cost the library runs, for tests.
var tinyScrypt = ScryptParams{N: 16, R: 1, P: 1, KeyLen: 64}

func scryptHash(t *testing.T, pw string, p ScryptParams) string {
	t.Helper()
	salt := []byte("0123456789abcdef")
	key, err := scrypt.Key([]byte(pw), salt, p.N, p.R, p.P, p.KeyLen)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(salt) + scryptSeparator + hex.EncodeToString(key)
}

func djangoHash(pw, salt string, iterations int) string {
	key := pbkdf2.Key([]byte(pw), []byte(salt), iterations, sha256.Size, sha256.New)
	return fmt.Sprintf("%s%d$%s$%s", djangoPrefix, iterations, salt, base64.StdEncoding.EncodeToString(key))
}

// TestLegacyVerifiers_RoundTrip: each built-in verifier recognizes its own
// format, matches the right password, refuses a wrong one, and does not claim
// the other formats or an argon2id string.
func TestLegacyVerifiers_RoundTrip(t *testing.T) {
	bc, err := bcrypt.GenerateFromPassword([]byte("correct horse"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	hashes := map[string]string{
		"bcrypt": string(bc),
		"scrypt": scryptHash(t, "correct horse", tinyScrypt),
		"django": djangoHash("correct horse", "saltsalt", 1000),
		"argon2": hashPassword("correct horse", fast),
	}
	verifiers := map[string]Verifier{"bcrypt": Bcrypt(), "scrypt": Scrypt(tinyScrypt), "django": DjangoPBKDF2()}
	for name, v := range verifiers {
		for format, h := range hashes {
			if got, want := v.Recognizes(h), format == name; got != want {
				t.Errorf("%s.Recognizes(%s hash) = %v, want %v", name, format, got, want)
			}
		}
		if ok, err := v.Verify("correct horse", hashes[name]); err != nil || !ok {
			t.Errorf("%s: right password = %v, %v", name, ok, err)
		}
		if ok, err := v.Verify("correct horsE", hashes[name]); err != nil || ok {
			t.Errorf("%s: wrong password = %v, %v", name, ok, err)
		}
	}
}

// TestBcrypt_PrefixesAndCorruptStrings: the three live prefixes are
// recognized, $2x$ is not, and a string with the prefix that bcrypt cannot
// parse is errBadHash rather than a mismatch.
func TestBcrypt_PrefixesAndCorruptStrings(t *testing.T) {
	v := Bcrypt()
	for _, p := range []string{"$2a$", "$2b$", "$2y$"} {
		if !v.Recognizes(p + "04$abc") {
			t.Errorf("%s not recognized", p)
		}
	}
	if v.Recognizes("$2x$04$abc") || v.Recognizes("$argon2id$v=19$") {
		t.Error("recognized a format that is not bcrypt")
	}
	if _, err := v.Verify("x", "$2a$04$tooshort"); !errors.Is(err, errBadHash) {
		t.Errorf("corrupt bcrypt err = %v, want errBadHash", err)
	}
}

// TestScrypt_ShapeAndParameters: only "hex:hex" with the configured key
// length is recognized; a wrong parameter set is a mismatch, not an error, and
// parameters scrypt cannot run are an error.
func TestScrypt_ShapeAndParameters(t *testing.T) {
	v := Scrypt(tinyScrypt)
	good := scryptHash(t, "pw", tinyScrypt)
	for _, bad := range []string{"", "nocolon", ":" + strings.Repeat("ab", 64), "zz:" + strings.Repeat("ab", 64), "abcd:" + strings.Repeat("ab", 63), "abcd:" + strings.Repeat("zz", 64)} {
		if v.Recognizes(bad) {
			t.Errorf("Recognizes(%q) = true", bad)
		}
		if _, err := v.Verify("pw", bad); !errors.Is(err, errBadHash) {
			t.Errorf("Verify(%q) err = %v, want errBadHash", bad, err)
		}
	}
	if ok, err := Scrypt(ScryptParams{N: 32, R: 1, P: 1, KeyLen: 64}).Verify("pw", good); err != nil || ok {
		t.Errorf("other parameters: %v, %v; want a plain mismatch", ok, err)
	}
	if _, err := Scrypt(ScryptParams{N: 15, R: 1, P: 1, KeyLen: 64}).Verify("pw", good); err == nil || errors.Is(err, errBadHash) {
		t.Errorf("N not a power of two: err = %v, want scrypt's own error", err)
	}
	if !v.Recognizes(scryptHash(t, "pw", BetterAuthScrypt)) {
		t.Error("the 16-byte salt, 64-byte key shape must be recognized")
	}
}

// TestDjangoPBKDF2_CorruptStrings: wrong section count, empty salt,
// non-numeric, zero or absurd iteration counts, and bad base64 are all
// errBadHash; the iteration bound keeps a hostile row from spinning the CPU.
func TestDjangoPBKDF2_CorruptStrings(t *testing.T) {
	v := DjangoPBKDF2()
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	for _, bad := range []string{
		djangoPrefix + "1000$salt",
		djangoPrefix + "1000$salt$" + key + "$extra",
		djangoPrefix + "1000$$" + key,
		djangoPrefix + "lots$salt$" + key,
		djangoPrefix + "0$salt$" + key,
		fmt.Sprintf("%s%d$salt$%s", djangoPrefix, maxPBKDF2Iterations+1, key),
		djangoPrefix + "1000$salt$!!!",
		djangoPrefix + "1000$salt$",
	} {
		if _, err := v.Verify("x", bad); !errors.Is(err, errBadHash) {
			t.Errorf("Verify(%q) err = %v, want errBadHash", bad, err)
		}
	}
	if !v.Recognizes(djangoPrefix+"1$s$"+key) || v.Recognizes("pbkdf2_sha1$1$s$"+key) {
		t.Error("Recognizes must be exactly the pbkdf2_sha256 prefix")
	}
}

// TestArgon2id_HasherContract: the exported Hasher recognizes only its own
// strings, verifies, and asks for a re-hash only when the parameters differ.
func TestArgon2id_HasherContract(t *testing.T) {
	h := Argon2id{Params: fast}
	enc, err := h.Hash("passphrase")
	if err != nil || !h.Recognizes(enc) {
		t.Fatalf("Hash = %q, %v", enc, err)
	}
	if ok, err := h.Verify("passphrase", enc); err != nil || !ok {
		t.Fatalf("Verify = %v, %v", ok, err)
	}
	if h.NeedsRehash(enc) {
		t.Error("same parameters must not need a re-hash")
	}
	other := Argon2id{Params: Argon2Params{Memory: 128, Time: 1, Threads: 1}}
	if !other.NeedsRehash(enc) {
		t.Error("other parameters must need a re-hash")
	}
	if other.NeedsRehash("$argon2id$v=19$garbage") || h.Recognizes("$2a$04$x") {
		t.Error("a string that does not parse needs no re-hash; bcrypt is not argon2id")
	}
}

// fakeHasher stores "fake:<password>" so tests can see what was hashed, and
// fails on demand.
type fakeHasher struct {
	err     error
	rehash  bool
	hashed  []string
	verifys int
}

func (f *fakeHasher) Hash(pw Secret) (string, error) {
	f.hashed = append(f.hashed, pw.Reveal())
	return "fake:" + pw.Reveal(), f.err
}
func (f *fakeHasher) Recognizes(encoded string) bool { return strings.HasPrefix(encoded, "fake:") }
func (f *fakeHasher) Verify(pw Secret, encoded string) (bool, error) {
	f.verifys++
	return encoded == "fake:"+pw.Reveal(), nil
}
func (f *fakeHasher) NeedsRehash(string) bool { return f.rehash }

// TestCheckPassword_DispatchesByFormat: the Hasher's format goes to the
// Hasher and re-hashes only on NeedsRehash; a legacy match always re-hashes;
// the first verifier that recognizes a string decides; nothing recognized is
// errBadHash and never a match.
func TestCheckPassword_DispatchesByFormat(t *testing.T) {
	fh := &fakeHasher{}
	p := New(WithHasher(fh), AcceptLegacyHashes(Scrypt(tinyScrypt), DjangoPBKDF2()))
	ok, rehash, err := p.checkPassword("pw", "fake:pw")
	if err != nil || !ok || rehash {
		t.Fatalf("own format = %v %v %v", ok, rehash, err)
	}
	fh.rehash = true
	if ok, rehash, err := p.checkPassword("pw", "fake:pw"); err != nil || !ok || !rehash {
		t.Fatalf("own format, out of date = %v %v %v", ok, rehash, err)
	}
	if ok, rehash, err := p.checkPassword("wrong", "fake:pw"); err != nil || ok || rehash {
		t.Fatalf("own format, wrong password = %v %v %v; a mismatch must never ask for a re-hash", ok, rehash, err)
	}
	if ok, rehash, err := p.checkPassword("pw", scryptHash(t, "pw", tinyScrypt)); err != nil || !ok || !rehash {
		t.Fatalf("legacy match = %v %v %v; want a re-hash", ok, rehash, err)
	}
	if ok, rehash, err := p.checkPassword("nope", djangoHash("pw", "s", 10)); err != nil || ok || rehash {
		t.Fatalf("legacy mismatch = %v %v %v", ok, rehash, err)
	}
	if ok, _, err := p.checkPassword("pw", hashPassword("pw", fast)); !errors.Is(err, errBadHash) || ok {
		t.Fatalf("argon2id without a verifier for it = %v, %v; want errBadHash", ok, err)
	}
	if fh.verifys != 3 {
		t.Fatalf("the Hasher verified %d times, want 3: legacy strings must not reach it", fh.verifys)
	}
}

// TestNew_DefaultHasherFollowsArgon2Option: without WithHasher the Hasher is
// Argon2id with the Argon2 option's parameters, so existing configurations
// behave exactly as before.
func TestNew_DefaultHasherFollowsArgon2Option(t *testing.T) {
	p := New(Argon2(fast))
	h, ok := p.hasher.(Argon2id)
	if !ok || h.Params != fast {
		t.Fatalf("hasher = %#v, want Argon2id{fast}", p.hasher)
	}
	if h := New().hasher.(Argon2id); h.Params != DefaultArgon2 {
		t.Fatalf("default params = %+v", h.Params)
	}
}

// TestInit_HasherErrorFailsStartUp: a Hasher that cannot hash cannot make the
// dummy, and auth.New reports it instead of starting without a dummy.
func TestInit_HasherErrorFailsStartUp(t *testing.T) {
	down := errors.New("hsm unreachable")
	p := New(WithHasher(&fakeHasher{err: down}))
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(loginKind{recover: true}, p)); !errors.Is(err, down) {
		t.Fatalf("auth.New err = %v, want the hasher's error", err)
	}
}

// TestSetPassword_HasherErrorStoresNothing: SetPassword hashes before it
// opens a transaction, so a failing Hasher is the error returned and no
// database is touched (there is none here, and ErrNoDatabase does not appear).
func TestSetPassword_HasherErrorStoresNothing(t *testing.T) {
	fh := &fakeHasher{}
	p := New(WithHasher(fh))
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(loginKind{recover: true}, p)); err != nil {
		t.Fatal(err)
	}
	fh.err = errors.New("hsm unreachable")
	if err := p.SetPassword(context.Background(), "usr_1", "a long enough passphrase"); !errors.Is(err, fh.err) {
		t.Fatalf("SetPassword err = %v, want the hasher's error", err)
	}
}

// TestRecognizes_IsWhatImportHashAccepts: the Hasher's own format and every
// legacy verifier's, nothing else, and ImportHash refuses before any read.
func TestRecognizes_IsWhatImportHashAccepts(t *testing.T) {
	plain := New()
	own, err := plain.hasher.Hash("pw")
	if err != nil {
		t.Fatal(err)
	}
	legacy := New(AcceptLegacyHashes(Bcrypt(), DjangoPBKDF2()))
	cases := []struct {
		p    *Plugin
		hash string
		want bool
	}{
		{plain, own, true},
		{plain, "$2a$04$xN3/uPFBYU1N.1Fl2a1xb.7kmRMS/iDm2BsmB.roxIok1byFBCDoe", false},
		{legacy, "$2a$04$xN3/uPFBYU1N.1Fl2a1xb.7kmRMS/iDm2BsmB.roxIok1byFBCDoe", true},
		{legacy, "pbkdf2_sha256$600000$salt$a2V5", true},
		{legacy, "md5$abc", false},
		{legacy, "", false},
	}
	for _, c := range cases {
		if got := c.p.recognizes(c.hash); got != c.want {
			t.Errorf("recognizes(%q) = %v, want %v", c.hash, got, c.want)
		}
	}
	if err := plain.ImportHash(context.Background(), "usr_1", "md5$abc"); !errors.Is(err, ErrHashUnrecognized) {
		t.Errorf("ImportHash with an unknown format = %v", err)
	}
}
