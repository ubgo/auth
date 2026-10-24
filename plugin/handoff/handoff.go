// Package handoff moves a signed-in session to another client in one step: a
// web page hands a native app a short-lived, single-use token, and the app
// exchanges it for a session of its own. The same works for a second domain,
// a desktop helper, or a CLI the user authorized in the browser.
//
// The token is a core verification token, so it is stored hashed, expires,
// and is spent by exactly one exchange even under concurrent attempts. The
// exchange creates a NEW session rather than copying the source one: the
// source's raw token is never stored, and two clients sharing one session
// would let either end the other's.
//
// A client that will receive the token on a channel another program could
// also receive it on (a custom URL scheme) binds it first: it sends the
// S256 challenge of a verifier with generate and the verifier with verify,
// as a native OAuth client does with PKCE (RFC 7636, RFC 8252 §8.1), so a
// token caught by the wrong app cannot be spent.
package handoff

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ubgo/auth"
)

// PluginName is the plugin's permanent identity.
const PluginName = "handoff"

// Operation ids, exported so a hook or a rate rule can name them. They are
// wire names, stable across releases.
const (
	EndpointGenerate auth.EndpointID = "handoff.generate"
	EndpointVerify   auth.EndpointID = "handoff.verify"
)

// PurposeHandoff is the verification purpose of a hand-off token. Its
// Identifier is the user id; its Meta is the id of the session that minted
// it, so an exchange after that session ended is refused.
//
//ds:def id=purposehandoff-6y9kr3mt owner=@khanakia stability=stable
const PurposeHandoff auth.Purpose = "handoff.token"

// The optional verifier binding (RFC 7636 PKCE, method S256 only). A client
// that will receive the token on a channel another program could also
// receive it on (a custom URL scheme, which any app on the machine can
// register) makes a random verifier, sends its SHA-256 challenge with
// generate, and sends the verifier with verify; a token minted with a
// challenge is spent only by the holder of the verifier. "plain" is not
// offered: it would put the verifier itself on the URL.
const (
	// ChallengeMethod is the one method; it is named so a client can state
	// it, as an OAuth client states code_challenge_method.
	//ds:def id=handoff-challengemethod-4k7xp2nm owner=@khanakia stability=stable
	ChallengeMethod = "S256"
	// VerifierBytes is how much randomness NewVerifier draws: 32 bytes, the
	// size of the hash that binds it, encoded as 43 characters.
	//ds:def id=handoff-verifierbytes-8q2mt5rw owner=@khanakia stability=stable
	VerifierBytes = 32
	// MinVerifierLen and MaxVerifierLen bound a verifier as RFC 7636 §4.1
	// does: 43 to 128 characters of the unreserved set. A shorter one has
	// too little entropy to be a secret; a longer one is a mistake.
	//ds:def id=handoff-minverifierlen-6n9wq3kt owner=@khanakia stability=stable
	MinVerifierLen = 43
	//ds:def id=handoff-maxverifierlen-2m5zr8vp owner=@khanakia stability=stable
	MaxVerifierLen = 128
	// challengeLen is the length of a base64url SHA-256 without padding; a
	// challenge of any other length cannot be one.
	challengeLen = 43
	// verifierAlphabet is RFC 3986's unreserved set, the characters a
	// verifier may use; the base64url alphabet is a subset.
	verifierAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	// metaSeparator joins the session id and the challenge in a token's
	// Meta. A newline occurs in neither, so the split is unambiguous; a
	// token minted with no challenge keeps the plain session id, so tokens
	// minted before this field existed still verify.
	metaSeparator = "\n"
)

// Defaults and limits.
const (
	// DefaultTTL is three minutes: a hand-off happens within seconds of
	// being asked for, and a longer life only serves whoever reads the
	// token off a URL or a log later.
	//ds:def id=defaultttl-k8w2pn5q owner=@khanakia stability=stable
	DefaultTTL = 3 * time.Minute
	// generateLimit tokens per IP per generateWindow: a client hands its
	// session off once, and a retry or two; a loop minting tokens is a
	// script.
	//ds:def id=generatelimit-3c7vx9ht owner=@khanakia stability=stable
	generateLimit = 10
	//ds:def id=generatewindow-5m2zq8rk owner=@khanakia stability=stable
	generateWindow = time.Minute
	// verifyLimit exchanges per IP per verifyWindow. A client exchanges one
	// token, and a retry or two; the bound exists because a refused exchange
	// leaves a bound token unspent, so without it a verifier could be guessed
	// at volume within the token's life.
	//ds:def id=handoff-verifylimit-3xr8mq2w owner=@khanakia stability=stable
	verifyLimit = 10
	//ds:def id=handoff-verifywindow-7kp4nt9v owner=@khanakia stability=stable
	verifyWindow = time.Minute
	// verifyTokenLimit exchanges per token per verifyWindow, counted on the
	// token's hash: the right client needs one, and five is already more
	// retries than a bug deserves, so whoever caught a bound token on a shared
	// channel gets five guesses at a 256-bit verifier, then waits.
	//ds:def id=handoff-verifytokenlimit-5qw2zn8k owner=@khanakia stability=stable
	verifyTokenLimit = 5
)

// SetOTTHeader is the response header IssueOnNewSession hands the token in.
// The transport lists it in Access-Control-Expose-Headers.
//
//ds:def id=handoff-setottheader-5wn8kq3v owner=@khanakia stability=stable
const SetOTTHeader = "Set-OTT"

// ErrBadTTL is a configuration error from auth.New: WithTTL was given zero or
// less, which would make every token expired at birth.
var ErrBadTTL = errors.New("handoff: WithTTL needs a positive duration")

// Request errors of the verifier binding. Both describe the shape of what
// the client sent and reveal nothing about any token: a challenge that is
// not a base64url SHA-256, a verifier outside RFC 7636's bounds. A verifier
// that is well formed but wrong, missing for a bound token or present for an
// unbound one answers auth.ErrTokenInvalid, like a wrong token, so the two
// cases cannot be told apart from outside.
var (
	ErrChallengeInvalid = auth.NewError("handoff.challenge_invalid", http.StatusBadRequest, "The challenge is not a base64url SHA-256.")
	ErrVerifierInvalid  = auth.NewError("handoff.verifier_invalid", http.StatusBadRequest, "The verifier must be 43 to 128 unreserved characters.")
)

// Plugin is the hand-off token plugin. Build it with New: the zero value has
// no TTL and no operations.
type Plugin struct {
	ttl        time.Duration
	serverOnly bool
	// onNewSession mints a token for every new full session (IssueOnNewSession).
	onNewSession bool
	perIP        limit
	verifyIP     limit
	core         *auth.Auth

	generate *auth.Op[GenerateRequest, GenerateResult]
	verify   *auth.Op[VerifyRequest, VerifyResult]
}

// Option configures the plugin; options are applied in order by New.
type Option func(*Plugin)

// WithTTL overrides DefaultTTL, how long a token can be exchanged.
func WithTTL(d time.Duration) Option { return func(p *Plugin) { p.ttl = d } }

// ServerOnly makes the generate route answer auth.ErrUnknownOperation, so
// tokens are minted only by the app's own Go code through Generate, for an
// app that hands sessions off on its own terms (after its own checks, say).
// The operation is then SelfServed: no transport mounts the route and no
// generated client or API reference lists it, while Generate keeps running
// the pipeline. A call that reaches the operation some other way (a custom
// transport through Auth.Operation) is still told apart by a marker only
// Generate sets, not by transport, because the app's handler calls Generate
// inside an HTTP request too.
func ServerOnly() Option { return func(p *Plugin) { p.serverOnly = true } }

// IssueOnNewSession also mints a hand-off token whenever an operation starts
// a new signed-in session (a sign-in, a sign-up, a promotion after the second
// factor) and hands it in the SetOTTHeader response header. A Go caller reads
// it with NewSessionToken.
//
// The token is exactly one generate would mint for that session: bound to
// it, DefaultTTL or WithTTL, single use, refused once the session ends. None
// is minted for a pending session (the second factor is still owed, and the
// exchange would skip it), for an impersonation (generate refuses those too),
// or by verify itself (its client is the one the hand-off was for). The cost
// of the option is that every sign-in answer carries a second credential, so
// a response logged or cached by a proxy leaks a session; prefer generate,
// called when a hand-off is actually wanted, unless the client needs one on
// every sign-in.
//
//ds:def id=handoff-issueonnewsession-8qw3mz6k owner=@khanakia stability=stable
func IssueOnNewSession() Option { return func(p *Plugin) { p.onNewSession = true } }

// WithGenerateLimit replaces the default of 10 tokens per IP per minute.
func WithGenerateLimit(n int, window time.Duration) Option {
	return func(p *Plugin) { p.perIP = limit{n, window} }
}

// WithVerifyLimit replaces the default of 10 exchanges per IP per minute. The
// per-token rule (verifyTokenLimit per minute) is not configurable: it is
// what bounds guessing a verifier, and a token has no legitimate use for more.
func WithVerifyLimit(n int, window time.Duration) Option {
	return func(p *Plugin) { p.verifyIP = limit{n, window} }
}

// limit is one rate rule's numbers.
type limit struct {
	n      int
	window time.Duration
}

// check refuses a rule that could not count, under the option that set it,
// before the core's generic rate check would refuse it without that name.
func (l limit) check(option string) error {
	if l.n < 1 || l.window <= 0 {
		return fmt.Errorf("%w: handoff.%s(%d, %v): the limit and the window must both be positive",
			auth.ErrBadOperation, option, l.n, l.window)
	}
	return nil
}

// Compile-time proof of each capability; a wrong signature would otherwise
// silently drop it.
var (
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.RateLimiter       = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.OperationHooker   = (*Plugin)(nil)
)

// New builds the plugin. With no options a token lives DefaultTTL and both
// routes are served.
func New(opts ...Option) *Plugin {
	p := &Plugin{ttl: DefaultTTL, perIP: limit{generateLimit, generateWindow}, verifyIP: limit{verifyLimit, verifyWindow}}
	for _, o := range opts {
		o(p)
	}
	p.generate = auth.Define(auth.OpInfo{ID: EndpointGenerate, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/generate", SelfServed: p.serverOnly}, p.doGenerate)
	p.verify = auth.Define(auth.OpInfo{ID: EndpointVerify, Kind: auth.Mutation, Require: auth.Public, Path: "/verify", SignIn: true}, p.doVerify)
	return p
}

// Name returns PluginName, the key the core registers this plugin under.
func (p *Plugin) Name() string { return PluginName }

// Validate refuses a lifetime nobody could use and a rate limit that could
// not count.
func (p *Plugin) Validate(*auth.Config) error {
	if p.ttl <= 0 {
		return ErrBadTTL
	}
	if err := p.perIP.check("WithGenerateLimit"); err != nil {
		return err
	}
	return p.verifyIP.check("WithVerifyLimit")
}

// Init captures the core handle Generate uses from Go.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	return nil
}

// OperationHooks adds, under IssueOnNewSession, the after-hook on every
// operation that mints a token for the session it started; nothing
// otherwise.
func (p *Plugin) OperationHooks() []auth.OperationHook {
	if !p.onNewSession {
		return nil
	}
	return []auth.OperationHook{{After: p.afterNewSession}}
}

// afterNewSession mints the token for the last session the call issued, if
// it is a full session. The hook runs inside the call's transaction, so the
// session it resolves is the one just written, and a failure to mint fails
// the call as a failing after-hook does.
func (p *Plugin) afterNewSession(ctx context.Context, c *auth.Call, _ any) error {
	if c.Op.ID == EndpointVerify {
		return nil
	}
	var issued auth.Token
	for _, e := range c.Effects.List() {
		if e.Kind == auth.EffectIssueSession {
			issued = e.Token
		}
	}
	if issued == "" {
		return nil
	}
	s, _, _, err := c.Auth.ResolveSession(ctx, issued)
	if errors.Is(err, auth.ErrSignedOut) {
		// A pending session resolves as signed out: no token for it.
		return nil
	}
	if err != nil {
		return err
	}
	if s.ImpersonatedBy != nil {
		return nil
	}
	tok, err := c.Auth.IssueVerification(ctx, PurposeHandoff, s.UserID, p.ttl, s.ID)
	if err != nil {
		return err
	}
	c.Effects.Header(SetOTTHeader, tok.Reveal())
	return nil
}

// NewSessionToken returns the token IssueOnNewSession handed out during the
// request in ctx, for a Go caller, which has no response headers to read;
// false when there is none (the option is off, or no full session started).
//
//ds:def id=handoff-newsessiontoken-3kv9pw2n owner=@khanakia stability=stable
func NewSessionToken(ctx context.Context) (auth.Token, bool) {
	for _, e := range auth.RequestEffects(ctx) {
		if e.Kind == auth.EffectHeader && e.Name == SetOTTHeader {
			return auth.Token(e.Value), true
		}
	}
	return "", false
}

// Operations lists generate and verify.
func (p *Plugin) Operations() []auth.Operation { return []auth.Operation{p.generate, p.verify} }

// RateLimits bounds token minting per IP, and exchanges per IP and per token.
// Guessing a token is not a strategy (256 bits, spent on first use). A bound
// token is different in one way: a refused exchange leaves it unspent, so
// whoever intercepted it could retry verifiers. That is harmless because a
// verifier is at least MinVerifierLen (43) unreserved characters, about 256
// bits like the token, so the guess space is the same; the two verify rules
// exist so that the retries cost the attacker time as well, a handful a
// minute per token and per address.
func (p *Plugin) RateLimits() []auth.RateRule {
	return []auth.RateRule{
		{Match: EndpointGenerate, Key: auth.ByIP, Limit: p.perIP.n, Window: p.perIP.window},
		{Match: EndpointVerify, Key: auth.ByIP, Limit: p.verifyIP.n, Window: p.verifyIP.window},
		{Match: EndpointVerify, Key: auth.ByIdentifier, Limit: verifyTokenLimit, Window: verifyWindow},
	}
}

// GenerateRequest is the input of generate. Challenge is optional: when the
// receiving client made a verifier (NewVerifier), its challenge binds the
// token so that only that client can spend it; see ChallengeMethod.
//
//ds:def id=handoff-generaterequest-9t3kw6xq owner=@khanakia stability=stable
type GenerateRequest struct {
	Challenge string `json:"challenge,omitempty"`
}

// GenerateResult is the output of generate. The token is the one value a
// result struct carries in the clear, because handing it to the client is
// the operation's whole purpose; it is a hand-off token, not the session's.
//
//ds:def id=generateresult-7r4tk2wq owner=@khanakia stability=stable
type GenerateResult struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// VerifyRequest carries the token the other client received and, when the
// token was minted with a challenge, the verifier that challenge was made
// from.
//
//ds:def id=handoff-verifyrequest-5r8nz2wm owner=@khanakia stability=stable
type VerifyRequest struct {
	Token    auth.WireToken `json:"token"`
	Verifier string         `json:"verifier,omitempty"`
}

// RateIdentifier counts exchanges per token, keyed by the token's hash so the
// rate store never holds the credential itself.
func (r VerifyRequest) RateIdentifier() string {
	return hex.EncodeToString(auth.HashToken(r.Token.Token()))
}

// VerifyResult is the output of verify: the user now signed in on this
// client. Token is the new session's token for Go callers and bearer
// transports, never encoded into JSON; a cookie client gets the cookie.
//
//ds:def id=verifyresult-9n3mw8xs owner=@khanakia stability=stable
type VerifyResult struct {
	User  auth.UserView `json:"user"`
	Token auth.Token    `json:"-"`
}

// Generate mints a token for the signed-in session in ctx, through the same
// operation the HTTP route runs.
//
//ds:def id=plugin-generate-2q6vh4nd owner=@khanakia stability=stable
func (p *Plugin) Generate(ctx context.Context) (GenerateResult, error) {
	return p.GenerateWith(ctx, GenerateRequest{})
}

// GenerateWith is Generate with a challenge from the receiving client, for a
// page that passes the app's challenge through.
//
//ds:def id=plugin-generatewith-3v7qk9rt owner=@khanakia stability=stable
func (p *Plugin) GenerateWith(ctx context.Context, in GenerateRequest) (GenerateResult, error) {
	return p.generate.Call(context.WithValue(ctx, fromGoKey{}, true), in)
}

// fromGoKey marks a ctx that reached generate through Generate rather than a
// transport; see ServerOnly.
type fromGoKey struct{}

// Verify exchanges a token for a new session of its user and records it on
// the call's effects, so the transport sets the cookie or bearer token.
//
//ds:def id=plugin-verify-8k5tz3fp owner=@khanakia stability=stable
func (p *Plugin) Verify(ctx context.Context, t auth.Token) (VerifyResult, error) {
	return p.VerifyWith(ctx, VerifyRequest{Token: t.Wire()})
}

// VerifyWith is Verify with the verifier of a token minted with a challenge.
//
//ds:def id=plugin-verifywith-7h2sm4pq owner=@khanakia stability=stable
func (p *Plugin) VerifyWith(ctx context.Context, in VerifyRequest) (VerifyResult, error) {
	return p.verify.Call(ctx, in)
}

// NewVerifier makes a verifier for the client that will receive a token and
// the challenge to send with generate. The verifier stays in the client's
// memory; only the challenge travels.
//
//ds:def id=handoff-newverifier-6w4jt8kn owner=@khanakia stability=stable
func NewVerifier() (verifier, challenge string, err error) {
	b := make([]byte, VerifierBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	return verifier, ChallengeOf(verifier), nil
}

// ChallengeOf is the S256 challenge of a verifier: the base64url SHA-256 of
// its ASCII bytes, without padding (RFC 7636 §4.2).
//
//ds:def id=handoff-challengeof-8p5rv3dm owner=@khanakia stability=stable
func ChallengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// validChallenge reports whether c has the shape of an S256 challenge; the
// base64url alphabet is checked by decoding.
func validChallenge(c string) bool {
	if len(c) != challengeLen {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(c)
	return err == nil
}

// validVerifier reports whether v is within RFC 7636's bounds and alphabet.
func validVerifier(v string) bool {
	if len(v) < MinVerifierLen || len(v) > MaxVerifierLen {
		return false
	}
	return strings.Trim(v, verifierAlphabet) == ""
}

// doGenerate mints the token for the request's own session. An admin acting
// as the user may not hand that session to another client, which would
// outlive the impersonation's short lifetime.
func (p *Plugin) doGenerate(ctx context.Context, c *auth.Call, in GenerateRequest) (GenerateResult, error) {
	if fromGo, _ := ctx.Value(fromGoKey{}).(bool); p.serverOnly && !fromGo {
		return GenerateResult{}, auth.ErrUnknownOperation
	}
	if c.Session.ImpersonatedBy != nil {
		return GenerateResult{}, auth.ErrImpersonationRefused
	}
	meta := c.Session.ID
	if len(in.Challenge) > 0 {
		if !validChallenge(in.Challenge) {
			return GenerateResult{}, ErrChallengeInvalid
		}
		meta += metaSeparator + in.Challenge
	}
	tok, err := c.Auth.IssueVerification(ctx, PurposeHandoff, c.User.ID, p.ttl, meta)
	if err != nil {
		return GenerateResult{}, err
	}
	return GenerateResult{Token: tok.Reveal(), ExpiresAt: c.Auth.Now().Add(p.ttl)}, nil
}

// doVerify spends the token and starts a session for its user. The source
// session must still be live: a token minted before a sign-out must not
// outlive it. The new session skips the second factor, because the source
// session already passed it; a pending session cannot reach generate.
//
// A malformed verifier is refused before the token is touched. A wrong or
// missing one is found after the consume, but the operation runs in one
// transaction that rolls back on error, so the token is not spent: whoever
// caught it on a shared channel cannot burn it, and the client holding the
// verifier still exchanges it within the token's life.
func (p *Plugin) doVerify(ctx context.Context, c *auth.Call, in VerifyRequest) (VerifyResult, error) {
	if len(in.Verifier) > 0 && !validVerifier(in.Verifier) {
		return VerifyResult{}, ErrVerifierInvalid
	}
	v, err := c.Auth.ConsumeVerification(ctx, PurposeHandoff, in.Token.Token())
	if err != nil {
		return VerifyResult{}, err
	}
	sessionID, challenge, bound := strings.Cut(v.Meta, metaSeparator)
	if bound != (len(in.Verifier) > 0) {
		return VerifyResult{}, auth.ErrTokenInvalid
	}
	if bound && subtle.ConstantTimeCompare([]byte(ChallengeOf(in.Verifier)), []byte(challenge)) != 1 {
		return VerifyResult{}, auth.ErrTokenInvalid
	}
	live, err := p.sourceLive(ctx, v.Identifier, sessionID)
	if err != nil {
		return VerifyResult{}, err
	}
	if !live {
		return VerifyResult{}, auth.ErrTokenInvalid
	}
	u, err := c.Auth.User(ctx, v.Identifier)
	if errors.Is(err, auth.ErrUserNotFound) {
		// The user was deleted after the token was minted: the same answer
		// as a spent token.
		return VerifyResult{}, auth.ErrTokenInvalid
	}
	if err != nil {
		return VerifyResult{}, err
	}
	s, tok, err := c.Auth.CreateMultiFactorSession(ctx, u.ID, c.Client)
	if err != nil {
		return VerifyResult{}, err
	}
	c.Effects.IssueSessionOf(s, tok)
	return VerifyResult{User: auth.ViewOf(u), Token: tok}, nil
}

// sourceLive reports whether the session that minted a token still exists.
// In stateless mode the server keeps no session list, so the check cannot
// run and the token's own short life is the bound; that is reported as live.
func (p *Plugin) sourceLive(ctx context.Context, userID, sessionID string) (bool, error) {
	list, err := p.core.Sessions(ctx, userID)
	if errors.Is(err, auth.ErrSessionsUnavailable) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	for _, s := range list {
		if s.ID == sessionID {
			return true, nil
		}
	}
	return false, nil
}
