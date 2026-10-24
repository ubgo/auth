package deviceauth

import (
	"crypto/rand"
	"math/big"
)

// randomString draws n characters of alphabet uniformly from crypto/rand.
// rand.Int rejects out-of-range draws itself, so no character is likelier
// than another whatever the alphabet's length. crypto/rand.Reader never
// fails (since Go 1.24 a failure crashes the program), so neither does
// rand.Int on it.
func randomString(alphabet string, n int) string {
	out := make([]byte, n)
	size := big.NewInt(int64(len(alphabet)))
	for i := range out {
		k, _ := rand.Int(rand.Reader, size)
		out[i] = alphabet[k.Int64()]
	}
	return string(out)
}
