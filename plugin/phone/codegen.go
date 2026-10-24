package phone

import (
	"context"
	"errors"
	"fmt"

	"github.com/ubgo/auth"
)

// CodeFor is what a custom code generator (GenerateCode) is told about the
// code it makes: the normalized number it goes to and the code's purpose,
// PurposeVerifyCode, PurposeChangeCode or PurposeSignInCode.
type CodeFor struct {
	Phone   string
	Purpose auth.Purpose
}

// CodeGenerator returns the code to text instead of the core's random digits.
type CodeGenerator func(ctx context.Context, in CodeFor) (string, error)

// ErrGenerateWithVerifier is GenerateCode together with WithVerifier: the
// provider makes and checks the code, so a generator would never be used.
var ErrGenerateWithVerifier = errors.New("phone: GenerateCode has no effect with WithVerifier, whose provider makes the code")

// GenerateCode replaces the core's random digits with fn's code, for every
// code this plugin texts (verify, change and sign-in), as email.GenerateCode
// does for mail: a fixed code for an app-store review account, a code in
// another alphabet, one from the app's own generator. Whatever fn returns is
// the code, compared exactly; an error from fn fails the send; the core
// refuses an empty code or one longer than auth.MaxGeneratedCodeLength. Off
// by default; the default draws auth.WithCodeLength digits (4 to 10) from
// crypto/rand. auth.New refuses it beside WithVerifier.
//
// Risk: a code is only as hard to guess as fn makes it, and the attempt and
// rate limits are tuned for random digits of the configured length.
//
//ds:def id=phone-generatecode-3tq8mw6c owner=@khanakia stability=stable
func GenerateCode(fn CodeGenerator) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("phone.GenerateCode", fn) {
			return
		}
		p.genCode = fn
	}
}

// newCode issues the code for subject through the one core call, with fn's
// code when GenerateCode is set.
func (p *Plugin) newCode(ctx context.Context, purpose auth.Purpose, subject, number string) (string, error) {
	if p.genCode == nil {
		return p.core.IssueCode(ctx, purpose, subject, p.codeTTL)
	}
	gen := func(ctx context.Context) (string, error) {
		code, err := p.genCode(ctx, CodeFor{Phone: number, Purpose: purpose})
		if err != nil {
			return "", fmt.Errorf("phone: generate code: %w", err)
		}
		return code, nil
	}
	return p.core.IssueCodeWith(ctx, purpose, subject, p.codeTTL, auth.CodeOptions{Generate: gen})
}
