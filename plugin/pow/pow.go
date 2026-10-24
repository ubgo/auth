// Package pow is a proof-of-work challenge: a client proves it spent CPU time
// before a call that a rate rule found suspicious is let through. It is the
// auth.RateChallenger of an app that wants a challenge with no third party in
// the loop (no captcha provider, no user tracking), so an auth.RateRule with
// Action auth.RateChallenge asks the client for work instead of refusing it.
//
// The scheme is hashcash. The server issues a random challenge (POST
// /auth/pow/challenge, or Plugin.Challenge from Go) with a difficulty D. The
// client finds a decimal nonce such that SHA-256 of "<challenge>:<nonce>" starts
// with at least D zero bits, and sends "<challenge>.<nonce>" in the
// ProofHeader of the call that was answered 428 auth.challenge_required. A
// challenge is single use, expires (DefaultChallengeTTL) and is spent only by a
// proof that carries enough work; Solve does the search in Go, for tests and
// for a CLI or desktop client.
//
// What it is for: it makes a flood of sign-in guesses cost the sender CPU time
// per guess instead of nothing, which a human behind a busy shared address
// barely notices once. What it is not: a bot detector. A determined attacker
// with a GPU farm pays the cost and carries on, so keep the rate limits and use
// it where a captcha is not welcome.
package pow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ubgo/auth"
)

// PluginName is the plugin's permanent identity and route prefix.
const PluginName = "pow"

// EndpointChallenge is the operation that issues a challenge, exported so a
// rate rule or a hook can name it. A wire name, stable across releases.
const EndpointChallenge auth.EndpointID = "pow.challenge"

// pathChallenge is the route under the plugin's prefix.
const pathChallenge = "/challenge"

// PurposeChallenge is the verification purpose of a challenge. Its Identifier
// is the difficulty it was issued at, so a proof is judged by the difficulty
// the challenge carried, whatever the plugin is configured with by then.
const PurposeChallenge auth.Purpose = "pow.challenge"

// ProofHeader is the request header the proof travels in.
//
//ds:def id=proofheader-pow-5qm8tk3w owner=@khanakia stability=stable
const ProofHeader = "X-Pow-Proof"

// AlgorithmSHA256 names the only hash this plugin issues, so a client can
// refuse a challenge for an algorithm it does not know.
const AlgorithmSHA256 = "sha256"

// AnnotationVerified is the auth.Call annotation set once the call's proof was
// accepted: a proof is single use, so a call that two rules challenge (a rate
// rule and a geo rule) must not spend it twice. The value is "true", never the
// proof.
const AnnotationVerified = "pow.verified"

// annotationTrue is AnnotationVerified's value.
const annotationTrue = "true"

// Defaults and bounds.
const (
	// DefaultDifficulty is 20 zero bits: about a million hashes, a fraction of
	// a second in Go and a second or two in a browser.
	//ds:def id=pow-defaultdifficulty-2vk9wq6n owner=@khanakia stability=stable
	DefaultDifficulty = 20
	// MaxDifficulty caps Difficulty. 2^32 hashes is beyond a phone and a
	// browser tab; a higher setting is a lock-out, not a challenge.
	MaxDifficulty = 32
	// DefaultChallengeTTL is how long a challenge can be solved and used.
	//ds:def id=pow-defaultchallengettl-8nr3xk5m owner=@khanakia stability=stable
	DefaultChallengeTTL = 5 * time.Minute
	// MaxChallengeTTL caps ChallengeTTL: an unsolved challenge is a row in the
	// database until it expires or a sweep removes it.
	MaxChallengeTTL = time.Hour

	// challengeBytes is the entropy of a challenge: 128 bits, hex-encoded. It
	// is unguessable, and it is the secret that makes a proof usable: the
	// store finds it by its hash alone.
	challengeBytes = 16
	// maxNonceDigits bounds the nonce text: a uint64 has at most 20 digits.
	maxNonceDigits = 20
	// issueIPLimit and issueIPWindow bound POST /auth/pow/challenge per
	// address: each call writes a row, and a client needs one per attempt.
	issueIPLimit  = 60
	issueIPWindow = time.Minute
	// spentKeyPrefix names the replay marker in the rate store; see spend.
	spentKeyPrefix = "pow.spent|"
	// proofSeparator joins the challenge and the nonce in a proof, and
	// hashSeparator joins them in the text that is hashed. They differ so a
	// proof string is never itself the hash input.
	proofSeparator = "."
	hashSeparator  = ":"
)

var (
	// ErrProofInvalid: the proof is malformed, or does not carry the work the
	// challenge asked for.
	ErrProofInvalid = auth.NewError("pow.proof_invalid", http.StatusForbidden, "The proof of work was not accepted.")
	// ErrChallengeInvalid: the challenge is unknown, expired or already used.
	// The three are one answer, like auth.ErrTokenInvalid; the client asks for
	// a new challenge.
	ErrChallengeInvalid = auth.NewError("pow.challenge_invalid", http.StatusBadRequest, "The challenge has expired. Request a new one.")
)

// Challenge is what the server issues and the client solves.
//
//ds:def id=pow-challenge-6zt4qn8k owner=@khanakia stability=stable
type Challenge struct {
	// Challenge is the random value to hash, hex text.
	Challenge string `json:"challenge"`
	// Difficulty is the number of leading zero bits the hash must have.
	Difficulty int `json:"difficulty"`
	// Algorithm is AlgorithmSHA256.
	Algorithm string `json:"algorithm"`
	// ExpiresAt is when the challenge stops working.
	ExpiresAt time.Time `json:"expiresAt"`
}

// Plugin is the proof-of-work challenger. Build it with New.
type Plugin struct {
	optErrs    auth.OptionErrors
	difficulty int
	ttl        time.Duration
	header     string
	core       *auth.Auth

	challenge *auth.Op[struct{}, Challenge]
}

// Option configures the plugin.
type Option func(*Plugin)

// OptionErr is every error the options recorded; auth.New refuses to start
// while it is not nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Difficulty sets the leading zero bits a proof needs, 1 to MaxDifficulty
// (default DefaultDifficulty). Each bit doubles the client's expected work and
// the server's cost stays one hash.
func Difficulty(bitsRequired int) Option {
	return func(p *Plugin) {
		if bitsRequired < 1 || bitsRequired > MaxDifficulty {
			p.optErrs.JoinOptionErr(fmt.Errorf("pow.Difficulty(%d): must be 1 to %d", bitsRequired, MaxDifficulty))
			return
		}
		p.difficulty = bitsRequired
	}
}

// ChallengeTTL sets how long a challenge works (default DefaultChallengeTTL),
// at most MaxChallengeTTL.
func ChallengeTTL(d time.Duration) Option {
	return func(p *Plugin) {
		if d <= 0 || d > MaxChallengeTTL {
			p.optErrs.JoinOptionErr(fmt.Errorf("pow.ChallengeTTL(%v): must be positive and at most %v", d, MaxChallengeTTL))
			return
		}
		p.ttl = d
	}
}

// WithHeader renames the header the proof arrives in (default ProofHeader). It
// must be a valid HTTP header name.
func WithHeader(name string) Option {
	return func(p *Plugin) {
		if !validHeaderName(name) {
			p.optErrs.JoinOptionErr(fmt.Errorf("pow.WithHeader(%q): not an HTTP header name", name))
			return
		}
		p.header = name
	}
}

// validHeaderName reports whether name is a non-empty RFC 9110 token.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r)
		if !ok {
			return false
		}
	}
	return true
}

var (
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.RateLimiter       = (*Plugin)(nil)
	_ auth.RateChallenger    = (*Plugin)(nil)
	_ auth.OptionChecker     = (*Plugin)(nil)
)

// New builds the plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{difficulty: DefaultDifficulty, ttl: DefaultChallengeTTL, header: ProofHeader}
	for _, o := range opts {
		o(p)
	}
	p.challenge = auth.Define(auth.OpInfo{ID: EndpointChallenge, Kind: auth.Mutation, Require: auth.Public, Path: pathChallenge}, p.doChallenge)
	return p
}

// Name returns PluginName.
func (p *Plugin) Name() string { return PluginName }

// Init keeps the core handle the challenge and the replay marker use.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	return nil
}

// Operations lists the challenge route.
func (p *Plugin) Operations() []auth.Operation { return []auth.Operation{p.challenge} }

// RateLimits bounds challenge requests per address.
func (p *Plugin) RateLimits() []auth.RateRule {
	return []auth.RateRule{{Match: EndpointChallenge, Key: auth.ByIP, Limit: issueIPLimit, Window: issueIPWindow}}
}

// Challenge issues a challenge: the typed form of POST /auth/pow/challenge.
func (p *Plugin) Challenge(ctx context.Context) (Challenge, error) {
	return p.challenge.Call(ctx, struct{}{})
}

// doChallenge stores a fresh random challenge as a single-use verification
// token and returns it with the difficulty it was issued at.
func (p *Plugin) doChallenge(ctx context.Context, c *auth.Call, _ struct{}) (Challenge, error) {
	raw := make([]byte, challengeBytes)
	// Since Go 1.24 Read cannot fail: a system with no randomness crashes the
	// program, so there is no weaker challenge to fall back to.
	_, _ = rand.Read(raw)
	ch := hex.EncodeToString(raw)
	if err := c.Auth.IssueVerificationToken(ctx, PurposeChallenge, strconv.Itoa(p.difficulty), auth.Token(ch), p.ttl, ""); err != nil {
		return Challenge{}, err
	}
	return Challenge{Challenge: ch, Difficulty: p.difficulty, Algorithm: AlgorithmSHA256, ExpiresAt: c.Auth.Now().Add(p.ttl)}, nil
}

// PassChallenge is auth.RateChallenger. A Go call passes (the app's own code is
// not the flood); a call with no proof is auth.ErrChallengeRequired (428), so
// the client knows to fetch a challenge, solve it and send the call again; a
// proof is checked by verify.
//
//ds:def id=passchallenge-pow-4wn7qk2z owner=@khanakia stability=stable
func (p *Plugin) PassChallenge(ctx context.Context, c *auth.Call) error {
	if c.Transport == auth.TransportGo || c.Annotation(AnnotationVerified) == annotationTrue {
		return nil
	}
	proof := c.Header(p.header)
	if proof == "" {
		return auth.ErrChallengeRequired
	}
	if err := p.verify(ctx, proof); err != nil {
		return err
	}
	c.Annotate(AnnotationVerified, annotationTrue)
	return nil
}

// verify checks a proof in the order that keeps a bad one cheap:
//
//  1. its shape, and the work in it (one hash, no database), judged against the
//     configured difficulty, so garbage and low-effort proofs never reach the
//     store;
//  2. the challenge (one single-use read): it must be one this server issued,
//     unexpired and unspent, and the work must also meet the difficulty it was
//     ISSUED at, so the stricter of the configured and the issued difficulty
//     applies;
//  3. a replay marker in the rate store, which survives the rollback of a
//     transaction the spend happened in (the geo challenge runs inside a
//     sign-in's), so a proof cannot be reused after the call it was spent in
//     failed.
//
// Nothing here compares a secret: the challenge is found by its hash through
// the store (auth.HashToken), never by comparing plaintext, and the work check
// reads public values.
func (p *Plugin) verify(ctx context.Context, proof string) error {
	challenge, nonce, ok := splitProof(proof)
	if !ok || !meetsDifficulty(challenge, nonce, p.difficulty) {
		return ErrProofInvalid
	}
	v, err := p.core.ConsumeVerification(ctx, PurposeChallenge, auth.Token(challenge))
	if err != nil {
		if errors.Is(err, auth.ErrTokenInvalid) {
			return ErrChallengeInvalid
		}
		return err
	}
	if issued, err := strconv.Atoi(v.Identifier); err != nil || !meetsDifficulty(challenge, nonce, issued) {
		return ErrProofInvalid
	}
	return p.spend(ctx, challenge)
}

// spend marks the challenge used in the rate store, outside any transaction the
// spend ran in. A second use of the same challenge finds the marker.
func (p *Plugin) spend(ctx context.Context, challenge string) error {
	n, err := p.core.RateHit(ctx, spentKeyPrefix+challenge, p.ttl)
	if err != nil {
		return err
	}
	if n > 1 {
		return ErrChallengeInvalid
	}
	return nil
}

// splitProof parses "<challenge>.<nonce>": a hex challenge of the length the
// plugin issues and a decimal nonce of at most maxNonceDigits digits.
func splitProof(proof string) (challenge, nonce string, ok bool) {
	challenge, nonce, ok = strings.Cut(proof, proofSeparator)
	if !ok || len(challenge) != 2*challengeBytes || nonce == "" || len(nonce) > maxNonceDigits {
		return "", "", false
	}
	if _, err := hex.DecodeString(challenge); err != nil {
		return "", "", false
	}
	for _, r := range nonce {
		if r < '0' || r > '9' {
			return "", "", false
		}
	}
	return challenge, nonce, true
}

// hashOf is the hash a proof is judged by: SHA-256 of "<challenge>:<nonce>".
func hashOf(challenge, nonce string) [sha256.Size]byte {
	return sha256.Sum256([]byte(challenge + hashSeparator + nonce))
}

// leadingZeroBits counts the zero bits a hash starts with.
func leadingZeroBits(sum [sha256.Size]byte) int {
	n := 0
	for _, b := range sum {
		if b == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(b)
	}
	return n
}

// meetsDifficulty reports whether the proof's hash has at least d leading
// zero bits.
func meetsDifficulty(challenge, nonce string, d int) bool {
	return leadingZeroBits(hashOf(challenge, nonce)) >= d
}

// solveCheckEvery is how many hashes Solve tries between looks at its context.
const solveCheckEvery = 4096

// Solve finds the proof for ch: it tries nonces 0, 1, 2, … until the hash has
// ch.Difficulty leading zero bits, and returns the value for the ProofHeader.
// It stops with the context's error when ctx ends, so a client can bound the
// search. It is the reference solver, for tests, a CLI and a desktop app; a
// browser uses the same loop in script.
//
//ds:def id=pow-solve-3xq8wn5v owner=@khanakia stability=stable
func Solve(ctx context.Context, ch Challenge) (string, error) {
	if ch.Algorithm != AlgorithmSHA256 {
		return "", fmt.Errorf("pow: unsupported algorithm %q", ch.Algorithm)
	}
	if ch.Difficulty < 1 || ch.Difficulty > MaxDifficulty {
		return "", fmt.Errorf("pow: difficulty %d is not 1 to %d", ch.Difficulty, MaxDifficulty)
	}
	for n := uint64(0); ; n++ {
		if n%solveCheckEvery == 0 {
			if err := ctx.Err(); err != nil {
				return "", err
			}
		}
		nonce := strconv.FormatUint(n, 10)
		if meetsDifficulty(ch.Challenge, nonce, ch.Difficulty) {
			return ch.Challenge + proofSeparator + nonce, nil
		}
	}
}
