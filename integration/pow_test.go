package integration

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/bits"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/pow"
)

// powDifficulty keeps the tests fast: 8 bits is 256 hashes on average.
const powDifficulty = 8

// powStack is password sign-in limited to one call an hour per address under
// a challenge, with proof of work as the challenger.
type powStack struct {
	h    http.Handler
	a    *auth.Auth
	p    *pow.Plugin
	pw   *password.Plugin
	sink *auth.MemorySecuritySink
}

func newPowStack(t *testing.T, e *env, opts ...pow.Option) *powStack {
	return newPowStackFor(t, e, true, opts...)
}

// newPowStackFor is newPowStack that signs ada up only when signUp is set, for a
// second instance on the same database.
func newPowStackFor(t *testing.T, e *env, signUp bool, opts ...pow.Option) *powStack {
	t.Helper()
	s := &powStack{p: pow.New(append([]pow.Option{pow.Difficulty(powDifficulty)}, opts...)...), sink: &auth.MemorySecuritySink{}}
	pw := e.passwordPlugin()
	s.pw = pw
	s.a = e.newAuth(t, []auth.Option{
		auth.WithSecuritySink(s.sink, auth.SecurityQueue{}),
		auth.WithRateRules(auth.RateRule{Match: password.EndpointSignIn, Key: auth.ByIP, Limit: 1, Window: time.Hour, Action: auth.RateChallenge}),
	}, e.emailPlugin(), pw, s.p)
	if signUp {
		if _, err := pw.SignUp(context.Background(), password.SignUpRequest{Identifier: "ada@example.com", Password: password.Secret(secret)}); err != nil {
			t.Fatal(err)
		}
	}
	s.h = authhttp.Handler(s.a, authhttp.Prefix("/auth"))
	return s
}

// signIn posts a password sign-in with proof in the proof header when given.
func (s *powStack) signIn(proof string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/auth/password/sign-in", strings.NewReader(`{"identifier":"ada@example.com","password":"`+secret+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", testBaseURL)
	if proof != "" {
		req.Header.Set(pow.ProofHeader, proof)
	}
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, req)
	return rec
}

// challenge asks for a challenge over HTTP, as a client would.
func (s *powStack) challenge(t *testing.T) pow.Challenge {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/auth/pow/challenge", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", testBaseURL)
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge: %d %s", rec.Code, rec.Body)
	}
	var ch pow.Challenge
	if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	return ch
}

// solved is the challenge's proof.
func solved(t *testing.T, ch pow.Challenge) string {
	t.Helper()
	proof, err := pow.Solve(context.Background(), ch)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

// powCode reads the error code of a response body.
func powCode(rec *httptest.ResponseRecorder) string {
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return body.Error.Code
}

// zeroBits is the work in challenge:nonce, computed here independently of the
// plugin so the test does not trust the code it checks.
func zeroBits(challenge string, nonce int) int {
	sum := sha256.Sum256([]byte(challenge + ":" + strconv.Itoa(nonce)))
	n := 0
	for _, b := range sum {
		if b != 0 {
			return n + bits.LeadingZeros8(b)
		}
		n += 8
	}
	return n
}

// TestPoW_ChallengeFlowOverHTTP: under the limit nothing is asked; over it the
// call is 428; fetching a challenge, solving it and resending the call with the
// proof goes through; the same proof is refused the second time.
func TestPoW_ChallengeFlowOverHTTP(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		s := newPowStack(t, e)
		if rec := s.signIn(""); rec.Code != http.StatusOK {
			t.Fatalf("under the limit: %d %s", rec.Code, rec.Body)
		}
		if rec := s.signIn(""); rec.Code != http.StatusPreconditionRequired || powCode(rec) != "auth.challenge_required" {
			t.Fatalf("over the limit, no proof: %d %s", rec.Code, rec.Body)
		}
		ch := s.challenge(t)
		if ch.Difficulty != powDifficulty || ch.Algorithm != pow.AlgorithmSHA256 || !ch.ExpiresAt.After(e.clock.Now()) || len(ch.Challenge) != 32 {
			t.Fatalf("challenge = %+v", ch)
		}
		proof := solved(t, ch)
		if rec := s.signIn(proof); rec.Code != http.StatusOK {
			t.Fatalf("with a proof: %d %s", rec.Code, rec.Body)
		}
		// A proof is single use.
		if rec := s.signIn(proof); powCode(rec) != "pow.challenge_invalid" {
			t.Fatalf("the proof again: %d %s, want pow.challenge_invalid", rec.Code, rec.Body)
		}
		_ = s.a.FlushSecurity(context.Background())
		var outcomes []auth.RateOutcome
		for _, ev := range s.sink.OfKind(auth.SecurityRateLimit) {
			outcomes = append(outcomes, ev.Outcome)
		}
		if len(outcomes) == 0 || outcomes[0] != auth.RateOutcomeChallenged {
			t.Fatalf("rate events = %v", outcomes)
		}
	})
}

// TestPoW_RefusesProofsThatAreNotWorth: malformed proofs, a proof with too
// little work, a made-up challenge and an expired challenge are each refused,
// and the refusals do not spend the genuine challenge.
func TestPoW_RefusesProofsThatAreNotWorth(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		s := newPowStack(t, e)
		s.signIn("") // use the free call
		ch := s.challenge(t)
		good := solved(t, ch)
		weak := -1
		for n := range 1000 {
			if zeroBits(ch.Challenge, n) < powDifficulty {
				weak = n
				break
			}
		}
		if weak < 0 {
			t.Fatal("no weak nonce found")
		}
		for name, proof := range map[string]string{
			"garbage":           "nonsense",
			"no nonce":          ch.Challenge + ".",
			"short challenge":   "abcd.1",
			"unknown challenge": "00112233445566778899aabbccddeeff.1",
			"too little work":   ch.Challenge + "." + strconv.Itoa(weak),
		} {
			rec := s.signIn(proof)
			if rec.Code == http.StatusOK || (powCode(rec) != "pow.proof_invalid" && powCode(rec) != "pow.challenge_invalid") {
				t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
			}
		}
		if rec := s.signIn(good); rec.Code != http.StatusOK {
			t.Fatalf("the genuine proof after the bad ones: %d %s", rec.Code, rec.Body)
		}
		proof2 := solved(t, s.challenge(t))
		e.clock.Advance(pow.DefaultChallengeTTL + time.Second)
		if rec := s.signIn(proof2); powCode(rec) != "pow.challenge_invalid" {
			t.Fatalf("expired challenge: %d %s", rec.Code, rec.Body)
		}
	})
}

// TestPoW_ChallengeIsJudgedByTheStricterDifficulty: a challenge issued at 16
// bits is not weakened when another instance (or a later configuration) asks
// for 8: a proof with 8 to 15 zero bits is refused, one with 16 passes.
func TestPoW_ChallengeIsJudgedByTheStricterDifficulty(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		hard := newPowStack(t, e, pow.Difficulty(16))
		easy := newPowStackFor(t, e, false, pow.Difficulty(8))
		ch := hard.challenge(t)
		if ch.Difficulty != 16 {
			t.Fatalf("issued at %d bits, want 16", ch.Difficulty)
		}
		mid := -1
		for n := range 100000 {
			if z := zeroBits(ch.Challenge, n); z >= 8 && z < 16 {
				mid = n
				break
			}
		}
		if mid < 0 {
			t.Fatal("no middling nonce found")
		}
		easy.signIn("") // use the free call
		if rec := easy.signIn(ch.Challenge + "." + strconv.Itoa(mid)); powCode(rec) != "pow.proof_invalid" {
			t.Fatalf("a proof meeting only the lower setting: %d %s", rec.Code, rec.Body)
		}
		// The weak proof spent that challenge (the work is judged after the
		// challenge is read), so the client asks for another.
		if rec := easy.signIn(solved(t, hard.challenge(t))); rec.Code != http.StatusOK {
			t.Fatalf("a proof meeting the issued difficulty: %d %s", rec.Code, rec.Body)
		}
	})
}

// failAfterSignIn is a plugin whose After hook fails the sign-in while on, so
// the sign-in's transaction rolls back after the rate challenge was passed.
type failAfterSignIn struct{ on atomic.Bool }

func (*failAfterSignIn) Name() string { return "failafter" }

func (p *failAfterSignIn) OperationHooks() []auth.OperationHook {
	return []auth.OperationHook{{Match: []auth.EndpointID{password.EndpointSignIn}, After: func(context.Context, *auth.Call, any) error {
		if p.on.Load() {
			return errors.New("hook refused")
		}
		return nil
	}}}
}

// TestPoW_AProofSpentInARolledBackSignInIsStillSpent: an impossible-travel
// challenge is passed inside the sign-in's transaction; when the sign-in then
// fails and rolls back, the challenge row is un-spent, and only the replay
// marker in the rate store keeps the proof from being used again.
func TestPoW_AProofSpentInARolledBackSignInIsStillSpent(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, p, hook := e.emailPlugin(), e.passwordPlugin(), pow.New(pow.Difficulty(powDifficulty)), &failAfterSignIn{}
		a := e.newAuth(t, []auth.Option{
			auth.WithGeoLocator(geoTable), auth.WithImpossibleTravel(auth.ImpossibleTravelRule{Action: auth.RateChallenge}),
		}, em, pw, p, hook)
		signUpVerified(t, e, a, pw, em) // a session from Berlin
		e.clock.Advance(time.Hour)
		signInWith := func(proof string) error {
			req := auth.Request{
				Transport: auth.TransportHTTP, Client: auth.Client{IP: geoNewYork, UserAgent: "test", Origin: testBaseURL},
				Header: func(n string) string {
					if n == pow.ProofHeader {
						return proof
					}
					return ""
				},
			}
			_, err := pw.SignIn(a.WithRequest(context.Background(), req), password.SignInRequest{Identifier: alice, Password: secret})
			return err
		}
		if err := signInWith(""); !errors.Is(err, auth.ErrChallengeRequired) {
			t.Fatalf("impossible travel without a proof: %v, want ErrChallengeRequired", err)
		}
		ch, err := p.Challenge(anon(a))
		if err != nil {
			t.Fatal(err)
		}
		proof := solved(t, ch)
		hook.on.Store(true)
		if err := signInWith(proof); err == nil || !strings.Contains(err.Error(), "hook refused") {
			t.Fatalf("sign-in failing after the challenge: %v", err)
		}
		hook.on.Store(false)
		if err := signInWith(proof); !errors.Is(err, pow.ErrChallengeInvalid) {
			t.Fatalf("the proof of a failed sign-in, used again: %v, want ErrChallengeInvalid", err)
		}
		ch2, err := p.Challenge(anon(a))
		if err != nil {
			t.Fatal(err)
		}
		if err := signInWith(solved(t, ch2)); err != nil {
			t.Fatalf("a fresh proof: %v", err)
		}
	})
}

// TestPoW_OneProofServesTwoChallengingRules: a call that a rate rule and the
// travel rule both challenge spends its proof once.
func TestPoW_OneProofServesTwoChallengingRules(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, p := e.emailPlugin(), e.passwordPlugin(), pow.New(pow.Difficulty(powDifficulty))
		a := e.newAuth(t, []auth.Option{
			auth.WithGeoLocator(geoTable), auth.WithImpossibleTravel(auth.ImpossibleTravelRule{Action: auth.RateChallenge}),
			auth.WithRateRules(auth.RateRule{Match: password.EndpointSignIn, Key: auth.ByIP, Limit: 1, Window: time.Hour, Action: auth.RateChallenge}),
		}, em, pw, p)
		signUpVerified(t, e, a, pw, em)
		e.clock.Advance(time.Hour)
		withProof := func(proof string) error {
			req := auth.Request{
				Transport: auth.TransportHTTP, Client: auth.Client{IP: geoNewYork, UserAgent: "test", Origin: testBaseURL},
				Header: func(n string) string {
					if n == pow.ProofHeader {
						return proof
					}
					return ""
				},
			}
			_, err := pw.SignIn(a.WithRequest(context.Background(), req), password.SignInRequest{Identifier: alice, Password: secret})
			return err
		}
		// The rate rule's free call; the travel rule still asks.
		if err := withProof(""); !errors.Is(err, auth.ErrChallengeRequired) {
			t.Fatalf("travel without a proof: %v, want ErrChallengeRequired", err)
		}
		ch, err := p.Challenge(anon(a))
		if err != nil {
			t.Fatal(err)
		}
		if err := withProof(solved(t, ch)); err != nil {
			t.Fatalf("one proof for the rate rule and the travel rule: %v", err)
		}
	})
}

// TestPoW_AGoCallIsNotChallenged: the app's own code is not the flood the
// challenge is for, as for a captcha, however far over the limit it goes.
func TestPoW_AGoCallIsNotChallenged(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		s := newPowStack(t, e)
		// A Go call that carries an address, so the by-address rule counts it.
		ctx := s.a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportGo, Client: auth.Client{IP: "203.0.113.7"}})
		for i := range 3 {
			if _, err := s.pw.SignIn(ctx, password.SignInRequest{Identifier: "ada@example.com", Password: password.Secret(secret)}); err != nil {
				t.Fatalf("Go call %d: %v", i, err)
			}
		}
	})
}
