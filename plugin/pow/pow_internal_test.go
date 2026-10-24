package pow

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"
)

// goodChallenge is a well-formed challenge value: 32 hex digits.
const goodChallenge = "00112233445566778899aabbccddeeff"

func TestLeadingZeroBits(t *testing.T) {
	cases := []struct {
		first []byte
		want  int
	}{
		{[]byte{0xff}, 0},
		{[]byte{0x7f}, 1},
		{[]byte{0x01}, 7},
		{[]byte{0x00, 0x80}, 8},
		{[]byte{0x00, 0x0f}, 12},
		{[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, 71},
	}
	for _, c := range cases {
		var sum [sha256.Size]byte
		copy(sum[:], c.first)
		for i := len(c.first); i < len(sum); i++ {
			sum[i] = 0xff
		}
		if got := leadingZeroBits(sum); got != c.want {
			t.Errorf("% x: %d zero bits, want %d", c.first, got, c.want)
		}
	}
	if got := leadingZeroBits([sha256.Size]byte{}); got != sha256.Size*8 {
		t.Errorf("all zero = %d", got)
	}
}

// TestSolve_FindsAProofThatMeetsTheDifficultyAndNoLess: the proof Solve finds
// has the work asked for, and a nonce that has less is not accepted.
func TestSolve_FindsAProofThatMeetsTheDifficultyAndNoLess(t *testing.T) {
	ch := Challenge{Challenge: goodChallenge, Difficulty: 12, Algorithm: AlgorithmSHA256}
	proof, err := Solve(context.Background(), ch)
	if err != nil {
		t.Fatal(err)
	}
	challenge, nonce, ok := splitProof(proof)
	if !ok || challenge != goodChallenge {
		t.Fatalf("proof %q does not parse", proof)
	}
	if !meetsDifficulty(challenge, nonce, 12) {
		t.Fatalf("proof %q lacks the work", proof)
	}
	// Solve returns the FIRST nonce that works, so the one before it does not
	// (when there is one), and a harder difficulty may reject the same proof.
	if nonce != "0" {
		prev := nonce[:len(nonce)-1] + string(nonce[len(nonce)-1]-1)
		if nonce[len(nonce)-1] > '0' && meetsDifficulty(challenge, prev, 12) {
			t.Fatalf("nonce %s before %s also works: not the first", prev, nonce)
		}
	}
}

func TestSolve_RefusesWhatItCannotSolve(t *testing.T) {
	ctx := context.Background()
	for name, ch := range map[string]Challenge{
		"unknown algorithm": {Challenge: goodChallenge, Difficulty: 8, Algorithm: "md5"},
		"zero difficulty":   {Challenge: goodChallenge, Difficulty: 0, Algorithm: AlgorithmSHA256},
		"huge difficulty":   {Challenge: goodChallenge, Difficulty: MaxDifficulty + 1, Algorithm: AlgorithmSHA256},
	} {
		if _, err := Solve(ctx, ch); err == nil {
			t.Errorf("%s: solved", name)
		}
	}
}

// TestSolve_StopsWhenItsContextEnds: an unsolvable-in-time difficulty returns
// the context's error instead of spinning.
func TestSolve_StopsWhenItsContextEnds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := Solve(ctx, Challenge{Challenge: goodChallenge, Difficulty: MaxDifficulty, Algorithm: AlgorithmSHA256})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the deadline", err)
	}
}

func TestSplitProof(t *testing.T) {
	for proof, want := range map[string]bool{
		goodChallenge + ".0":                          true,
		goodChallenge + ".18446744073709551615":       true,
		goodChallenge + "." + strings.Repeat("9", 21): false,
		goodChallenge + ".":                           false,
		goodChallenge + ".12a":                        false,
		goodChallenge + ".-1":                         false,
		goodChallenge:                                 false,
		"":                                            false,
		goodChallenge[:30] + ".1":                     false,
		"zz112233445566778899aabbccddeeff.1":          false,
		goodChallenge + goodChallenge + ".1":          false,
		strings.ToUpper(goodChallenge[:6]) + goodChallenge[6:] + ".1": true,
	} {
		if _, _, ok := splitProof(proof); ok != want {
			t.Errorf("splitProof(%q) = %v, want %v", proof, ok, want)
		}
	}
}

// TestOptions_RefuseWhatCannotWork: every option records an error naming
// itself instead of taking a value that would break at the first request.
func TestOptions_RefuseWhatCannotWork(t *testing.T) {
	for name, opt := range map[string]Option{
		"pow.Difficulty":    Difficulty(0),
		"pow.Difficulty ":   Difficulty(MaxDifficulty + 1),
		"pow.ChallengeTTL":  ChallengeTTL(0),
		"pow.ChallengeTTL ": ChallengeTTL(MaxChallengeTTL + time.Second),
		"pow.WithHeader":    WithHeader(""),
		"pow.WithHeader ":   WithHeader("Bad Header"),
	} {
		err := New(opt).OptionErr()
		if err == nil || !strings.Contains(err.Error(), strings.TrimSpace(name)+"(") {
			t.Errorf("%s: OptionErr = %v", name, err)
		}
	}
	p := New(Difficulty(1), Difficulty(MaxDifficulty), ChallengeTTL(MaxChallengeTTL), WithHeader("X-Proof"))
	if p.OptionErr() != nil || p.difficulty != MaxDifficulty || p.ttl != MaxChallengeTTL || p.header != "X-Proof" {
		t.Fatalf("valid options: %v %+v", p.OptionErr(), p)
	}
}
