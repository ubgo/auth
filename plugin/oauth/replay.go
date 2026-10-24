package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ubgo/auth"
)

// ID-token replay protection. A provider ID token is a bearer proof: whoever
// holds it can post it to the id-token sign-in or to the ID-token
// re-authentication until it expires, and its nonce does not stop that,
// because the client chooses the nonce and sends it beside the token. So
// every ID token these operations accept is claimed once: after its
// signature and claims verify, and before anything is created, linked or
// refreshed, the plugin asks an IDTokenReplayGuard to claim it until it
// expires, and a token already claimed is ErrIDTokenReplayed.
//
// The default guard keeps the claim as a verification row of purpose
// PurposeIDTokenClaim in the core's verification store, so it needs no table
// of its own, joins the operation's transaction (a sign-in that fails after
// the claim leaves the token unclaimed, under the SQL store), and is removed
// by auth.Sweep like any expired token. It needs a store that refuses a
// duplicate (auth.ExclusiveVerificationStore): the SQL store and the
// key-value store over a SetIfAbsenter (memory, contrib/redis) do, and
// auth.New refuses any other while an ID-token provider is configured,
// rather than run unprotected. WithIDTokenReplayGuard swaps the guard;
// AllowIDTokenReplay turns the check off by name.

// PurposeIDTokenClaim is the verification purpose of the default guard's
// claims. Its Identifier is the provider name, and the token's hash is
// IDTokenClaim.Key, so the stored row holds no part of the token.
//
//ds:def id=oauth-purposeidtokenclaim-4mw8kq2n owner=@khanakia stability=stable
const PurposeIDTokenClaim auth.Purpose = "oauth.id_token_claim"

// ErrIDTokenReplayed refuses an ID token that was already accepted once, by
// a native sign-in or an ID-token re-authentication. It says only that this
// token is spent, which its holder can learn by using it, so it reveals no
// account. The app asks the provider's SDK for a new token and tries again.
//
//ds:def id=oauth-erridtokenreplayed-9kq2wm5t owner=@khanakia stability=stable
var ErrIDTokenReplayed = auth.NewError("oauth.id_token_replayed", http.StatusUnauthorized, "This sign-in token was already used. Sign in with the provider again.")

// ErrIDTokenReplayConfig refuses a replay configuration that cannot work: a
// guard given together with AllowIDTokenReplay, or the default guard over a
// verification store that does not refuse duplicates.
var ErrIDTokenReplayConfig = errors.New("oauth: ID-token replay protection")

// IDTokenClaim is one accepted ID token, as the guard is asked to claim it.
//
//ds:def id=oauth-idtokenclaim-6vn3kw8q owner=@khanakia stability=stable
type IDTokenClaim struct {
	// Key identifies the token's issuance: the hex SHA-256 of its signed
	// part (the JWS header and payload, without the signature), or of the
	// whole token when it is not a compact JWS. Not the raw token, because
	// an ES256 signature has a second valid form (s and n-s), so one
	// issuance has two spellings; and not issuer, subject, audience and jti,
	// because jti is optional (Apple's tokens carry none) and two tokens
	// issued in one second would share the rest. Every claim the provider
	// signed is in the key, so two different issuances never share it.
	Key string
	// Provider is the provider that verified the token.
	Provider string
	// Until is when the claim may be forgotten: the token's exp plus the
	// verifier's clock leeway, after which the token is refused as expired
	// anyway. A verifier whose profile carries no exp claim gets
	// idTokenClaimFallback from now.
	Until time.Time
}

// IDTokenReplayGuard decides whether an ID token may be accepted: Claim
// records claim.Key as used until claim.Until and returns nil the first
// time, and ErrIDTokenReplayed (or an error wrapping it) for a key already
// claimed and not yet past its Until. Of concurrent claims of one key
// exactly one may succeed. Any other error is a failure of the guard, and
// the operation fails with it rather than accept an unchecked token.
//
//ds:def id=oauth-idtokenreplayguard-3kw9nq7m owner=@khanakia stability=stable
type IDTokenReplayGuard interface {
	Claim(ctx context.Context, claim IDTokenClaim) error
}

// IDTokenReplayGuardFunc adapts a function to IDTokenReplayGuard.
type IDTokenReplayGuardFunc func(ctx context.Context, claim IDTokenClaim) error

// Claim calls f.
func (f IDTokenReplayGuardFunc) Claim(ctx context.Context, claim IDTokenClaim) error {
	return f(ctx, claim)
}

// WithIDTokenReplayGuard replaces the default guard (a claim row in the
// core's verification store) with g: a shared cache, a dedicated table, a
// service. A nil g is refused (auth.ErrNilOption); turning the check off is
// AllowIDTokenReplay, never a nil.
//
//ds:def id=oauth-withidtokenreplayguard-8qn2wk4v owner=@khanakia stability=stable
func WithIDTokenReplayGuard(g IDTokenReplayGuard) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauth.WithIDTokenReplayGuard", g) {
			return
		}
		p.replayGuard = g
	}
}

// AllowIDTokenReplay turns ID-token replay protection off: a captured token
// then signs in, or re-authenticates its user's session, as often as its
// holder likes until it expires (minutes to an hour at the providers). For
// an app whose client legitimately posts one token twice and cannot ask the
// SDK for a new one. auth.New logs WarnIDTokenReplayAllowed when it is set.
//
//ds:def id=oauth-allowidtokenreplay-5wq8nk3d owner=@khanakia stability=stable
func AllowIDTokenReplay() Option { return func(p *Plugin) { p.allowReplay = true } }

// WarnIDTokenReplayAllowed is logged at start-up under AllowIDTokenReplay.
const WarnIDTokenReplayAllowed = "oauth: AllowIDTokenReplay is set; a captured ID token can be used again until it expires"

// idTokenClaimFallback is how long a claim holds when the verifier's profile
// names no exp: a custom IDTokenVerifier that fills no Claims. A day is
// longer than any provider's ID-token lifetime, so the token expires first.
const idTokenClaimFallback = 24 * time.Hour

// initReplayGuard settles the guard at Init: AllowIDTokenReplay with a guard
// is a contradiction; the default guard needs a store that refuses
// duplicates, checked only when an ID-token operation exists.
func (p *Plugin) initReplayGuard(a *auth.Auth) error {
	switch {
	case p.allowReplay && p.replayGuard != nil:
		return fmt.Errorf("%w: WithIDTokenReplayGuard and AllowIDTokenReplay are both set; keep one", ErrIDTokenReplayConfig)
	case p.allowReplay:
		if p.reauthIDToken != nil {
			a.Logger().Warn(WarnIDTokenReplayAllowed)
		}
		return nil
	case p.replayGuard != nil:
		return nil
	}
	p.replayGuard = storeReplayGuard{a: a}
	if p.reauthIDToken == nil {
		return nil
	}
	if s, ok := a.VerificationStore().(auth.ExclusiveVerificationStore); !ok || !s.RefusesDuplicateTokens() {
		return fmt.Errorf("%w: the verification store does not refuse duplicate tokens (auth.ExclusiveVerificationStore), so the default guard cannot claim an ID token once; give its storage SetIfAbsent, pass oauth.WithIDTokenReplayGuard, or oauth.AllowIDTokenReplay", ErrIDTokenReplayConfig)
	}
	return nil
}

// claimIDToken claims a verified token through the guard. A replay is logged,
// reported to the security stream (auth.SecurityTokenReplay) and answered
// ErrIDTokenReplayed; a guard failure fails the operation.
func (p *Plugin) claimIDToken(ctx context.Context, c *auth.Call, provider, idToken string, prof Profile) error {
	if p.allowReplay {
		return nil
	}
	claim := IDTokenClaim{Key: idTokenKey(idToken), Provider: provider, Until: idTokenUntil(prof, c.Auth.Now())}
	err := p.replayGuard.Claim(ctx, claim)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrIDTokenReplayed):
		c.Auth.Logger().Warn("oauth: id token replayed", "provider", provider)
		c.Auth.EmitSecurityOf(c, auth.SecurityEvent{
			Kind: auth.SecurityTokenReplay, Severity: auth.SeverityAlert, Outcome: auth.RateOutcomeBlocked,
			Attrs: map[string]string{auth.AttrProvider: provider},
		})
		return ErrIDTokenReplayed
	default:
		return fmt.Errorf("oauth: id token replay guard: %w", err)
	}
}

// idTokenKey is IDTokenClaim.Key of token.
func idTokenKey(token string) string {
	signed := token
	if i := strings.LastIndexByte(token, '.'); i > 0 && strings.Count(token, ".") == 2 {
		signed = token[:i]
	}
	sum := sha256.Sum256([]byte(signed))
	return hex.EncodeToString(sum[:])
}

// idTokenUntil is IDTokenClaim.Until for a verified profile at now.
func idTokenUntil(prof Profile, now time.Time) time.Time {
	var exp int64
	if raw, ok := prof.Claims[claimExp]; ok && json.Unmarshal(raw, &exp) == nil && exp > 0 {
		return time.Unix(exp, 0).Add(idTokenLeeway)
	}
	return now.Add(idTokenClaimFallback)
}

// claimExp is the ID token's expiry claim.
const claimExp = "exp"

// storeReplayGuard is the default guard: a verification row of purpose
// PurposeIDTokenClaim, filed under the provider, whose token is the claim's
// key. The store refuses a second row for one key (auth.ErrTokenExists),
// which initReplayGuard checked it can promise.
type storeReplayGuard struct{ a *auth.Auth }

// Claim implements IDTokenReplayGuard.
func (g storeReplayGuard) Claim(ctx context.Context, claim IDTokenClaim) error {
	// A key-value store needs a positive lifetime; the SQL row keeps its
	// uniqueness whatever its expiry, until Sweep removes it after the
	// token itself has expired.
	ttl := max(claim.Until.Sub(g.a.Now()), time.Second)
	err := g.a.IssueVerificationToken(ctx, PurposeIDTokenClaim, claim.Provider, auth.Token(claim.Key), ttl, "")
	if errors.Is(err, auth.ErrTokenExists) {
		return ErrIDTokenReplayed
	}
	return err
}
