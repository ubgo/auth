package integration

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/sqlb"
)

// r21Secret is the app secret the reuse tests seal codes under.
var r21Secret = []byte("r21-secret-r21-secret-r21-secret")

// TestR21_EmailReuseCodeOnResend: under ReuseCodeOnResend a second send mails
// the same code and pushes its expiry out, wrong guesses still count, and a
// code with no attempts left is replaced; without the option a resend
// rotates.
func TestR21_EmailReuseCodeOnResend(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.SignUpWithCode(), email.ReuseCodeOnResend(), email.WithMaxAttempts(3), email.WithCodeSendLimit(50, time.Hour), email.WithCodeTryLimit(50, time.Hour))
		a := e.newAuth(t, []auth.Option{auth.WithSecret(r21Secret)}, em)
		const addr = "reuse@example.com"
		send := func() string {
			t.Helper()
			a.WaitDeliveries()
			if err := em.SendCode(anon(a), addr); err != nil {
				t.Fatal(err)
			}
			a.WaitDeliveries()
			return lastMailCode(t, e, a, addr)
		}
		first := send()
		e.clock.Advance(email.DefaultCodeTTL - time.Minute)
		if again := send(); again != first {
			t.Fatalf("reuse mailed %s, then %s", first, again)
		}
		// Past the first expiry, inside the extended one.
		e.clock.Advance(2 * time.Minute)
		if _, err := em.SignInCode(anon(a), addr, wrongCode(first)); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("wrong code: %v", err)
		}
		if again := send(); again != first {
			t.Fatal("a wrong guess must not rotate a reused code")
		}
		in, err := em.SignInCode(anon(a), addr, first)
		if err != nil || !in.Created {
			t.Fatalf("extended code = %+v %v", in, err)
		}
		// Spend the attempt budget: the next send replaces the code.
		spent := send()
		for range 3 {
			_, _ = em.SignInCode(anon(a), addr, wrongCode(spent))
		}
		if fresh := send(); fresh == spent {
			t.Fatal("a code with no attempts left was reused")
		}
	})
}

// TestR21_EmailRotatesByDefault: without ReuseCodeOnResend every send is a
// new code, and the old one stops working.
func TestR21_EmailRotatesByDefault(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.SignUpWithCode())
		a := e.newAuth(t, nil, em)
		const addr = "rotate@example.com"
		must0(t, em.SendCode(anon(a), addr))
		a.WaitDeliveries()
		first := lastMailCode(t, e, a, addr)
		must0(t, em.SendCode(anon(a), addr))
		a.WaitDeliveries()
		if _, err := em.SignInCode(anon(a), addr, first); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("a rotated-out code still works: %v", err)
		}
	})
}

// TestR21_EmailGenerateCode: the generator's code is the one mailed and
// accepted, and it is told the address and the kind.
func TestR21_EmailGenerateCode(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var n atomic.Int64
		var seen atomic.Value
		gen := func(_ context.Context, in email.CodeFor) (string, error) {
			seen.Store(in)
			return fmt.Sprintf("%06d", 100000+n.Add(1)), nil
		}
		em := e.emailPlugin(email.SignUpWithCode(), email.GenerateCode(gen))
		a := e.newAuth(t, nil, em)
		const addr = "gen@example.com"
		must0(t, em.SendCode(anon(a), addr))
		a.WaitDeliveries()
		code := lastMailCode(t, e, a, addr)
		if want := fmt.Sprintf("%06d", 100000+n.Load()); code != want {
			t.Fatalf("mailed %s, generator made %s", code, want)
		}
		if got := seen.Load().(email.CodeFor); got.Email != addr || got.Kind != email.CodeKindSignIn {
			t.Fatalf("generator told %+v", got)
		}
		if in, err := em.SignInCode(anon(a), addr, code); err != nil || !in.Created {
			t.Fatalf("generated code = %+v %v", in, err)
		}
	})
}

// TestR21_MagicLinkGenerateToken: the generator's token is the one linked
// and it signs in.
func TestR21_MagicLinkGenerateToken(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var last atomic.Value
		gen := func(_ context.Context, identifier string) (string, error) {
			b := make([]byte, 32)
			_, _ = rand.Read(b)
			tok := "ml-" + base64.RawURLEncoding.EncodeToString(b)
			last.Store(identifier + " " + tok)
			return tok, nil
		}
		em, ml := e.emailPlugin(), magiclink.New(magiclink.SignUp(), magiclink.GenerateToken(gen))
		a := e.newAuth(t, nil, em, ml)
		const addr = "link@example.com"
		must0(t, ml.Send(anon(a), addr))
		a.WaitDeliveries()
		tok := e.mail.LastToken(t, a, addr)
		if want := addr + " " + tok.Reveal(); last.Load().(string) != want {
			t.Fatalf("linked %q, generator made %q", want, last.Load())
		}
		if in, err := ml.SignIn(anon(a), tok); err != nil || !in.Created {
			t.Fatalf("generated token = %+v %v", in, err)
		}
	})
}

// Sign-up field columns: two app columns of different types.
const (
	r21ColPlan  = "plan"
	r21ColSeats = "seats"
)

var (
	r21Plan  = sqlb.Col[*string](auth.TableUser, r21ColPlan)
	r21Seats = sqlb.Col[*int64](auth.TableUser, r21ColSeats)
)

// r21FieldsOpts declares the app columns and lets a sign-up body set them.
func r21FieldsOpts() []auth.Option {
	return []auth.Option{
		auth.WithUserColumns(
			auth.ColumnExtension{Name: r21ColPlan, Type: auth.ColumnText, Nullable: true},
			auth.ColumnExtension{Name: r21ColSeats, Type: auth.ColumnInt, Nullable: true},
		),
		auth.WithSignUpFields(r21ColPlan, r21ColSeats),
	}
}

// r21Fields builds a fields object from Go values.
func r21Fields(t *testing.T, kv map[string]any) auth.Fields {
	t.Helper()
	f := auth.Fields{}
	for k, v := range kv {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		f[k] = raw
	}
	return f
}

// r21ReadFields returns the user's plan and seats ("" and 0 for null).
func r21ReadFields(t *testing.T, a *auth.Auth, userID string) (string, int64) {
	t.Helper()
	var plan *string
	var seats *int64
	if err := a.LoadUserColumns(context.Background(), userID, sqlb.Bind(r21Plan, &plan), sqlb.Bind(r21Seats, &seats)); err != nil {
		t.Fatal(err)
	}
	var p string
	var s int64
	if plan != nil {
		p = *plan
	}
	if seats != nil {
		s = *seats
	}
	return p, s
}

// TestR21_PasswordSignUpFields: declared fields are written at sign-up; an
// unknown or wrong-typed one is refused with auth.ErrFieldInvalid and leaves
// no account behind.
func TestR21_PasswordSignUpFields(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, r21FieldsOpts(), em, pw)
		up := func(addr string, f auth.Fields) (password.SignInResult, error) {
			return pw.SignUp(anon(a), password.SignUpRequest{Identifier: addr, Password: secret, Fields: f})
		}
		res, err := up("fields@example.com", r21Fields(t, map[string]any{r21ColPlan: "pro", r21ColSeats: 5}))
		if err != nil {
			t.Fatal(err)
		}
		if p, s := r21ReadFields(t, a, res.User.ID); p != "pro" || s != 5 {
			t.Fatalf("fields = %q %d", p, s)
		}
		for name, f := range map[string]auth.Fields{
			"unknown":    r21Fields(t, map[string]any{"role": "admin"}),
			"wrong type": r21Fields(t, map[string]any{r21ColSeats: "five"}),
			"core":       r21Fields(t, map[string]any{"name": "x"}),
		} {
			const addr = "refused@example.com"
			if _, err := up(addr, f); !errors.Is(err, auth.ErrFieldInvalid) {
				t.Fatalf("%s field: %v", name, err)
			}
			if _, err := a.FindIdentity(anon(a), email.KindEmail, addr, false); !errors.Is(err, auth.ErrIdentityNotFound) {
				t.Fatalf("%s field left an identity: %v", name, err)
			}
		}
	})
}

// TestR21_PhoneSignInFields: the account a phone code creates gets the
// fields; an existing owner's columns are not touched by a later sign-in.
func TestR21_PhoneSignInFields(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ph := e.phonePlugin(phone.Login(), phone.SignInWithCode())
		a := e.newAuth(t, r21FieldsOpts(), ph)
		const number = "+14155550188"
		signIn := func(f auth.Fields) (phone.SignInResult, error) {
			must0(t, ph.SendCode(anon(a), number))
			return ph.SignInWith(anon(a), phone.SignInRequest{Phone: number, Code: e.sms.LastCode(t, a, number), Fields: f})
		}
		if _, err := ph.SignInWith(anon(a), phone.SignInRequest{Phone: number, Code: "000000", Fields: r21Fields(t, map[string]any{"role": "x"})}); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("unknown field: %v", err)
		}
		in, err := signIn(r21Fields(t, map[string]any{r21ColPlan: "team"}))
		if err != nil || !in.Created {
			t.Fatalf("sign-up = %+v %v", in, err)
		}
		if p, _ := r21ReadFields(t, a, in.User.ID); p != "team" {
			t.Fatalf("plan = %q", p)
		}
		again, err := signIn(r21Fields(t, map[string]any{r21ColPlan: "free"}))
		if err != nil || again.Created {
			t.Fatalf("second sign-in = %+v %v", again, err)
		}
		if p, _ := r21ReadFields(t, a, in.User.ID); p != "team" {
			t.Fatalf("a sign-in rewrote plan to %q", p)
		}
	})
}

// TestR21_EmailCodeSignUpFields: the account an email code creates gets the
// fields.
func TestR21_EmailCodeSignUpFields(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.SignUpWithCode())
		a := e.newAuth(t, r21FieldsOpts(), em)
		const addr = "codefields@example.com"
		must0(t, em.SendCode(anon(a), addr))
		a.WaitDeliveries()
		in, err := em.SignInCodeWith(anon(a), email.CodeRequest{Email: addr, Code: lastMailCode(t, e, a, addr), Fields: r21Fields(t, map[string]any{r21ColSeats: 3})})
		if err != nil || !in.Created {
			t.Fatalf("sign-up = %+v %v", in, err)
		}
		if _, s := r21ReadFields(t, a, in.User.ID); s != 3 {
			t.Fatalf("seats = %d", s)
		}
	})
}

// wrongCode returns a code of the same length that is not code.
func wrongCode(code string) string {
	if code[0] == '9' {
		return "0" + code[1:]
	}
	return "9" + code[1:]
}

// must0 fails the test on err.
func must0(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// TestR21_GeneratorErrorsFailTheSend: an error from a GenerateCode or
// GenerateToken generator fails the send, and nothing is mailed.
func TestR21_GeneratorErrorsFailTheSend(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		down := errors.New("generator down")
		code := func(context.Context, email.CodeFor) (string, error) { return "", down }
		tok := func(context.Context, string) (string, error) { return "", down }
		em, ml := e.emailPlugin(email.SignUpWithCode(), email.GenerateCode(code)), magiclink.New(magiclink.SignUp(), magiclink.GenerateToken(tok))
		a := e.newAuth(t, nil, em, ml)
		if err := em.SendCode(anon(a), "down@example.com"); !errors.Is(err, down) {
			t.Fatalf("code generator error: %v", err)
		}
		if err := ml.Send(anon(a), "down@example.com"); !errors.Is(err, down) {
			t.Fatalf("token generator error: %v", err)
		}
		a.WaitDeliveries()
		if n := len(e.mail.To(a, "down@example.com")); n != 0 {
			t.Fatalf("%d mails sent after a generator error", n)
		}
	})
}

// TestR21_EmptyGeneratedValuesFailTheSend: an empty code or token cannot be
// sent, so it fails the send; any other value is used as returned.
func TestR21_EmptyGeneratedValuesFailTheSend(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		code := func(context.Context, email.CodeFor) (string, error) { return "", nil }
		tok := func(context.Context, string) (string, error) { return "", nil }
		em, ml := e.emailPlugin(email.SignUpWithCode(), email.GenerateCode(code)), magiclink.New(magiclink.SignUp(), magiclink.GenerateToken(tok))
		a := e.newAuth(t, nil, em, ml)
		if err := em.SendCode(anon(a), "empty@example.com"); err == nil {
			t.Fatal("an empty code was sent")
		}
		if err := ml.Send(anon(a), "empty@example.com"); err == nil {
			t.Fatal("an empty token was sent")
		}
		a.WaitDeliveries()
		if n := len(e.mail.To(a, "empty@example.com")); n != 0 {
			t.Fatalf("%d mails sent with an empty secret", n)
		}
	})
}

// TestR21_EmailReuseWithGenerator: with GenerateCode, a reused code is the
// generated one, sealed and mailed again, and it signs in.
func TestR21_EmailReuseWithGenerator(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var n atomic.Int64
		gen := func(context.Context, email.CodeFor) (string, error) { return fmt.Sprintf("%06d", 200000+n.Add(1)), nil }
		em := e.emailPlugin(email.SignUpWithCode(), email.ReuseCodeOnResend(), email.GenerateCode(gen), email.WithCodeSendLimit(50, time.Hour))
		a := e.newAuth(t, []auth.Option{auth.WithSecret(r21Secret)}, em)
		const addr = "reusegen@example.com"
		must0(t, em.SendCode(anon(a), addr))
		a.WaitDeliveries()
		first := lastMailCode(t, e, a, addr)
		must0(t, em.SendCode(anon(a), addr))
		a.WaitDeliveries()
		if again := lastMailCode(t, e, a, addr); again != first || n.Load() != 1 {
			t.Fatalf("mailed %s then %s after %d generator calls", first, again, n.Load())
		}
		if in, err := em.SignInCode(anon(a), addr, first); err != nil || !in.Created {
			t.Fatalf("reused generated code = %+v %v", in, err)
		}
	})
}

// TestR21_TopLevelSignUpFields: a declared column may sit at the top level of
// the body; an undeclared top-level key is refused as
// before, and a column sent both ways is auth.ErrFieldInvalid. The body goes
// through the request types' UnmarshalJSON, as the HTTP transport does.
func TestR21_TopLevelSignUpFields(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(email.SignUpWithCode()), e.passwordPlugin()
		ph := e.phonePlugin(phone.Login(), phone.SignInWithCode())
		a := e.newAuth(t, r21FieldsOpts(), em, pw, ph)
		up := func(body string) (password.SignInResult, error) {
			var in password.SignUpRequest
			if err := json.Unmarshal([]byte(body), &in); err != nil {
				t.Fatal(err)
			}
			return pw.SignUp(anon(a), in)
		}
		res, err := up(`{"identifier":"top@example.com","password":"` + secret + `","plan":"pro","fields":{"seats":4}}`)
		if err != nil {
			t.Fatal(err)
		}
		if p, s := r21ReadFields(t, a, res.User.ID); p != "pro" || s != 4 {
			t.Fatalf("fields = %q %d", p, s)
		}
		if _, err := up(`{"identifier":"top2@example.com","password":"` + secret + `","role":"admin"}`); !errors.Is(err, auth.ErrBadRequest) {
			t.Fatalf("undeclared top-level key: %v", err)
		}
		if _, err := up(`{"identifier":"top3@example.com","password":"` + secret + `","plan":"a","fields":{"plan":"b"}}`); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("a column sent both ways: %v", err)
		}

		const number = "+14155550199"
		must0(t, ph.SendCode(anon(a), number))
		var pin phone.SignInRequest
		must0(t, json.Unmarshal([]byte(`{"phone":"`+number+`","code":"`+e.sms.LastCode(t, a, number)+`","plan":"team"}`), &pin))
		pres, err := ph.SignInWith(anon(a), pin)
		if err != nil || !pres.Created {
			t.Fatalf("phone sign-up = %+v %v", pres, err)
		}
		if p, _ := r21ReadFields(t, a, pres.User.ID); p != "team" {
			t.Fatalf("phone plan = %q", p)
		}

		const addr = "topcode@example.com"
		must0(t, em.SendCode(anon(a), addr))
		a.WaitDeliveries()
		var ein email.CodeRequest
		must0(t, json.Unmarshal([]byte(`{"email":"`+addr+`","code":"`+lastMailCode(t, e, a, addr)+`","seats":9}`), &ein))
		eres, err := em.SignInCodeWith(anon(a), ein)
		if err != nil || !eres.Created {
			t.Fatalf("email sign-up = %+v %v", eres, err)
		}
		if _, s := r21ReadFields(t, a, eres.User.ID); s != 9 {
			t.Fatalf("email seats = %d", s)
		}
	})
}
