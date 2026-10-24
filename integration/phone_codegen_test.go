package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth/plugin/phone"
)

// reviewCode is the fixed code an app-store review account gets, the case
// phone.GenerateCode exists for.
const reviewCode = "424242"

// TestPhone_GenerateCodeTextsAndChecksTheGeneratedCode: with GenerateCode
// the text carries fn's code, the generator is told the normalized number
// and the purpose, that code verifies, a wrong one does not, and a
// generator's error fails the send.
func TestPhone_GenerateCodeTextsAndChecksTheGeneratedCode(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var asked []phone.CodeFor
		gen := phone.GenerateCode(func(_ context.Context, in phone.CodeFor) (string, error) {
			asked = append(asked, in)
			return reviewCode, nil
		})
		ph := e.phonePlugin(phone.Login(), gen)
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), ph)
		_, tok := identUser(t, a, alice)
		if err := ph.Add(request(a, tok), phoneOld); err != nil {
			t.Fatal(err)
		}
		if got := e.sms.LastCode(t, a, phoneOld); got != reviewCode {
			t.Fatalf("texted code = %q, want the generated %q", got, reviewCode)
		}
		if len(asked) != 1 || asked[0].Phone != phoneOld || asked[0].Purpose != phone.PurposeVerifyCode {
			t.Fatalf("generator asked with %+v", asked)
		}
		if err := ph.Verify(request(a, tok), phoneOld, "000000"); !errors.Is(err, phone.ErrCodeInvalid) {
			t.Fatalf("a wrong code = %v", err)
		}
		if err := ph.Verify(request(a, tok), phoneOld, reviewCode); err != nil {
			t.Fatalf("the generated code = %v", err)
		}

		down := errors.New("generator down")
		bad := e.phonePlugin(phone.Login(), phone.GenerateCode(func(context.Context, phone.CodeFor) (string, error) { return "", down }))
		b := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), bad)
		_, tok = identUser(t, b, "gen-down@example.com")
		if err := bad.Add(request(b, tok), phoneNew); !errors.Is(err, down) {
			t.Fatalf("add with a failing generator = %v, want its error", err)
		}
	})
}
