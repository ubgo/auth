package magiclink

import (
	"context"
	"fmt"

	"github.com/ubgo/auth"
)

// TokenGenerator returns the token a link carries instead of the core's
// random one, given the normalized identifier the link goes to.
type TokenGenerator func(ctx context.Context, identifier string) (string, error)

// GenerateToken replaces the core's random 256-bit token with fn's. It is a
// plain override: whatever fn returns is the token, and an error from fn
// fails the send. Off by default.
//
// Risk: a link token is found by its hash alone, with no attempt counter, so
// a guessable fn signs in whoever guesses it.
//
//ds:def id=magiclink-generatetoken-3vr7kx2m owner=@khanakia stability=stable
func GenerateToken(fn TokenGenerator) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("magiclink.GenerateToken", fn) {
			return
		}
		p.genToken = fn
	}
}

// issue stores the link's token: the core's random one, or GenerateToken's.
func (p *Plugin) issue(ctx context.Context, a *auth.Auth, identifier, value, meta string) (auth.Token, error) {
	if p.genToken == nil {
		return a.IssueVerification(ctx, PurposeSignIn, identifier, p.ttl, meta)
	}
	raw, err := p.genToken(ctx, value)
	if err != nil {
		return "", fmt.Errorf("magiclink: generate token: %w", err)
	}
	tok := auth.Token(raw)
	return tok, a.IssueVerificationToken(ctx, PurposeSignIn, identifier, tok, p.ttl, meta)
}
