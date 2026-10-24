package email

import (
	"context"
	"fmt"
	"time"

	"github.com/ubgo/auth"
)

// CodeFor is what a custom code generator (GenerateCode) is told about the
// code it makes: the normalized address it goes to and its kind.
type CodeFor struct {
	Email string
	Kind  CodeKind
}

// CodeGenerator returns the code to mail instead of the core's random digits.
type CodeGenerator func(ctx context.Context, in CodeFor) (string, error)

// GenerateCode replaces the core's random digits with fn's code, for every
// code this plugin mails (verify, sign-in, change and approve). It is a plain
// override: whatever fn returns is the code, compared exactly, and an error
// from fn fails the send. Off by default; the default draws
// auth.WithCodeLength digits from crypto/rand.
//
// Risk: a code is only as hard to guess as fn makes it.
//
//ds:def id=email-generatecode-5mq8vt3k owner=@khanakia stability=stable
func GenerateCode(fn CodeGenerator) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("email.GenerateCode", fn) {
			return
		}
		p.genCode = fn
	}
}

// ReuseCodeOnResend makes a resend mail the same code again and extend its
// life by the code TTL ("reuse"), instead of replacing it with a new one (the
// default, "rotate"). Wrong guesses already made still count: a resend never
// refills the attempt budget, and a code with no attempts left or past its
// expiry is replaced as usual.
//
// Off by default, and the risk is the secret: a code that must be mailed
// again is derived from its row id with a key from auth.WithSecret, or, with
// GenerateCode, stored sealed under that key (auth.CodeOptions.Reuse), so
// auth.New requires the secret. Anyone with the database AND the secret can
// read open codes; and a code that lives longer gives a guesser more time
// across its attempt budget.
//
//ds:def id=email-reusecodeonresend-8wn2kd6r owner=@khanakia stability=stable
func ReuseCodeOnResend() Option { return func(p *Plugin) { p.reuseCode = true } }

// issueCode issues every code the plugin mails, through the one core call, so
// GenerateCode and ReuseCodeOnResend apply to all four kinds alike.
func (p *Plugin) issueCode(ctx context.Context, kind CodeKind, purpose auth.Purpose, subject, address string, ttl time.Duration) (string, error) {
	o := auth.CodeOptions{Reuse: p.reuseCode, MaxAttempts: p.codeTries}
	if p.genCode != nil {
		o.Generate = func(ctx context.Context) (string, error) {
			code, err := p.genCode(ctx, CodeFor{Email: address, Kind: kind})
			if err != nil {
				return "", fmt.Errorf("email: generate code: %w", err)
			}
			return code, nil
		}
	}
	return p.core.IssueCodeWith(ctx, purpose, subject, ttl, o)
}
