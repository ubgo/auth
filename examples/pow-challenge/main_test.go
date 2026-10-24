package main

import (
	"context"
	"crypto/sha256"
	"math/bits"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/pow"
)

const (
	adaMail = "ada@example.com"
	adaPass = "correct horse battery staple"
	// testDifficulty keeps the tests fast: 8 zero bits is 256 hashes on
	// average, where pow.DefaultDifficulty is about a million.
	testDifficulty = 8
	// nonceSearch bounds the search for a nonce that carries too little work;
	// at 8 bits nearly every nonce does, so the first few suffice.
	nonceSearch = 1000
)

// world is the app with ada signed up.
func world(t *testing.T) (*authtest.Env, *authtest.Browser) {
	t.Helper()
	e := authtest.New(t,
		authtest.WithOptions(auth.WithRateRules(signInRule())),
		authtest.WithPlugins(func(*authtest.Env) []auth.Plugin { return plugins(testDifficulty) }))
	b := e.Browser(newHandler(e.Auth))
	b.Post("/auth/password/sign-up", map[string]string{"identifier": adaMail, "password": adaPass, "name": "Ada"}).Expect(http.StatusOK)
	return e, b
}

// signIn posts a sign-in, with a proof in the proof header when one is given.
func signIn(t *testing.T, b *authtest.Browser, proof string) *authtest.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, b.URL()+"/auth/password/sign-in", strings.NewReader(`{"identifier":"`+adaMail+`","password":"`+adaPass+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", b.Origin)
	if proof != "" {
		req.Header.Set(pow.ProofHeader, proof)
	}
	return b.Do(req)
}

// useFreeSignIns spends the calls the rule lets through without work.
func useFreeSignIns(t *testing.T, b *authtest.Browser) {
	t.Helper()
	for i := range freeSignIns {
		if r := signIn(t, b, ""); r.Status != http.StatusOK {
			t.Fatalf("sign-in %d under the limit: %d %s", i+1, r.Status, r.Body)
		}
	}
}

// challenge fetches a challenge over HTTP, as a client would.
func challenge(t *testing.T, b *authtest.Browser) pow.Challenge {
	t.Helper()
	var ch pow.Challenge
	b.Post("/auth/pow/challenge", nil).Expect(http.StatusOK).Decode(&ch)
	if ch.Difficulty != testDifficulty || ch.Algorithm != pow.AlgorithmSHA256 || ch.Challenge == "" {
		t.Fatalf("challenge = %+v", ch)
	}
	return ch
}

// solve is the challenge's proof, found by the reference solver.
func solve(t *testing.T, ch pow.Challenge) string {
	t.Helper()
	proof, err := pow.Solve(context.Background(), ch)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

// zeroBits counts the leading zero bits of SHA-256("<challenge>:<nonce>"),
// computed here independently of the plugin so the test does not trust the
// code it checks.
func zeroBits(challenge string, nonce int) int {
	sum := sha256.Sum256([]byte(challenge + ":" + strconv.Itoa(nonce)))
	n := 0
	for _, by := range sum {
		if by != 0 {
			return n + bits.LeadingZeros8(by)
		}
		n += 8
	}
	return n
}

// TestPoW_ChallengeOnlyOverTheLimitAndEachProofOnce: the first calls need no
// work; the call over the limit is asked for it with 428; a solved challenge
// goes through; the same proof sent again is refused as a spent challenge.
//
//ds:def id=powchallenge-example-test-flow-9wq2kn6v
func TestPoW_ChallengeOnlyOverTheLimitAndEachProofOnce(t *testing.T) {
	_, b := world(t)
	useFreeSignIns(t, b)
	over := signIn(t, b, "").Expect(http.StatusPreconditionRequired)
	if over.ErrorCode() != auth.ErrChallengeRequired.Code {
		t.Fatalf("over the limit: %s", over.Body)
	}
	proof := solve(t, challenge(t, b))
	signIn(t, b, proof).Expect(http.StatusOK)
	if code := signIn(t, b, proof).Expect(pow.ErrChallengeInvalid.Status).ErrorCode(); code != pow.ErrChallengeInvalid.Code {
		t.Fatalf("the same proof again: %s, want %s", code, pow.ErrChallengeInvalid.Code)
	}
}

// TestPoW_AProofWithoutEnoughWorkIsRefused: a nonce whose hash has fewer zero
// bits than the difficulty is refused before the challenge is touched, so the
// honest proof for the same challenge still works afterwards.
func TestPoW_AProofWithoutEnoughWorkIsRefused(t *testing.T) {
	_, b := world(t)
	useFreeSignIns(t, b)
	ch := challenge(t, b)
	weak := -1
	for n := range nonceSearch {
		if zeroBits(ch.Challenge, n) < testDifficulty {
			weak = n
			break
		}
	}
	if weak < 0 {
		t.Fatal("no nonce with too little work found")
	}
	lazy := ch.Challenge + "." + strconv.Itoa(weak)
	if code := signIn(t, b, lazy).Expect(pow.ErrProofInvalid.Status).ErrorCode(); code != pow.ErrProofInvalid.Code {
		t.Fatalf("a proof without the work: %s, want %s", code, pow.ErrProofInvalid.Code)
	}
	signIn(t, b, solve(t, ch)).Expect(http.StatusOK)
}

// TestPoW_AnExpiredChallengeIsRefused: a challenge solved but sent after its
// lifetime is refused, and the client must ask for a new one.
func TestPoW_AnExpiredChallengeIsRefused(t *testing.T) {
	e, b := world(t)
	proof := solve(t, challenge(t, b))
	e.Clock.Advance(pow.DefaultChallengeTTL + time.Second)
	// The rate window moved on with the clock, so spend the free calls now:
	// a proof sent inside the limit is never looked at.
	useFreeSignIns(t, b)
	if code := signIn(t, b, proof).Expect(pow.ErrChallengeInvalid.Status).ErrorCode(); code != pow.ErrChallengeInvalid.Code {
		t.Fatalf("an expired challenge: %s, want %s", code, pow.ErrChallengeInvalid.Code)
	}
	signIn(t, b, solve(t, challenge(t, b))).Expect(http.StatusOK)
}
