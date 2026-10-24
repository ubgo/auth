package password

import "testing"

// FuzzParseHash feeds arbitrary stored hashes to the parser: a corrupt row
// must be an error, never a panic, and an accepted one must be within the
// bounds that keep argon2 cheap to refuse.
func FuzzParseHash(f *testing.F) {
	good := hashPassword("seed passphrase", fast)
	for _, s := range []string{good, "", "$argon2id$v=19$m=0,t=0,p=0$$", "$argon2id$v=19$m=64,t=1,p=1$c2FsdA$aGFzaA", "$argon2id$v=19$m=99999999,t=1,p=1$c2FsdA$aGFzaA"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, encoded string) {
		h, err := parseHash(encoded)
		if err != nil {
			return
		}
		if h.params.Memory > maxMemoryKiB || h.params.Time > maxTime || len(h.key) == 0 || len(h.key) > maxKeyLen || len(h.salt) == 0 {
			t.Fatalf("accepted out-of-bounds hash %q: %+v", encoded, h.params)
		}
	})
}
