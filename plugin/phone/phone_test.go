package phone_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/sqlb"
)

var noSMS = phone.SMSFunc(func(context.Context, string, string) error { return nil })

type signIn struct{}

func (signIn) Name() string  { return "signin" }
func (signIn) SignsIn() bool { return true }

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"+1 (555) 010-0100": "+15550100100",
		" +44 20 7946 0958": "+442079460958",
		"+91.98765.43210":   "+919876543210",
	}
	for raw, want := range cases {
		if got, err := phone.Normalize(raw); err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, bad := range []string{"555 0100", "+1 555 x100", "+١٢٣٤٥٦٧"} {
		if _, err := phone.Normalize(bad); err == nil {
			t.Errorf("Normalize(%q) accepted", bad)
		}
	}
}

func TestValidate_DigitCount(t *testing.T) {
	if err := phone.Validate("+123456"); err == nil {
		t.Error("6 digits accepted")
	}
	if err := phone.Validate("+1234567890123456"); err == nil {
		t.Error("16 digits accepted")
	}
	if err := phone.Validate("+15550100100"); err != nil {
		t.Error(err)
	}
}

func TestNew_Validation(t *testing.T) {
	if _, err := auth.New(auth.WithPlugins(signIn{}, phone.New())); !errors.Is(err, phone.ErrNoSMS) {
		t.Fatalf("no sender: %v", err)
	}
	if _, err := auth.New(auth.WithPlugins(signIn{}, phone.New(phone.WithSMS(noSMS), phone.SignInWithCode()))); !errors.Is(err, phone.ErrCodeNoLogin) {
		t.Fatalf("code sign-in without Login: %v", err)
	}
	// Phone codes are the only way in here, and they are off: no sign-in method.
	if _, err := auth.New(auth.WithPlugins(phone.New(phone.WithSMS(noSMS), phone.Login()))); !errors.Is(err, auth.ErrNoSignInMethod) {
		t.Fatalf("phone without code sign-in counted as a way in: %v", err)
	}
	a, err := auth.New(auth.WithPlugins(phone.New(phone.WithSMS(noSMS), phone.Login(), phone.SignInWithCode())))
	if err != nil {
		t.Fatalf("phone-only app: %v", err)
	}
	if _, ok := a.Operation(phone.EndpointSignIn); !ok {
		t.Fatal("code sign-in operation not registered")
	}
}

func TestDefaultTemplate_CarriesTheCodeOrLink(t *testing.T) {
	if s := phone.DefaultTemplate(auth.Message{Purpose: auth.PurposeSignInCode, Code: "123456"}); !strings.Contains(s, "123456") {
		t.Fatalf("code text = %q", s)
	}
	if s := phone.DefaultTemplate(auth.Message{Purpose: auth.PurposeReset, Link: "https://x/r"}); !strings.Contains(s, "https://x/r") {
		t.Fatalf("reset text = %q", s)
	}
}

// TestPlugin_OwnsNoTable: codes are the core's, so phone ships no migration.
func TestPlugin_OwnsNoTable(t *testing.T) {
	var p any = phone.New(phone.WithSMS(noSMS))
	if _, ok := p.(auth.Migrator); ok {
		t.Fatal("phone must not own a table; its codes are the core's")
	}
}

func TestUserJoin_PicksExactlyOneRow(t *testing.T) {
	j := phone.UserJoin()
	if j.Type != sqlb.JoinLeft || len(j.On) != 3 {
		t.Fatalf("join = %+v; kind and primary must both be in ON", j)
	}
}

func TestData_AbsenceIsDistinguishable(t *testing.T) {
	var d phone.Data
	if d.Exists() || d.Verified() {
		t.Fatal("zero Data must read as absent")
	}
}

func TestTemplatesByLocale(t *testing.T) {
	var got string
	p := phone.New(phone.WithSMS(phone.SMSFunc(func(_ context.Context, _, text string) error { got = text; return nil })),
		phone.TemplatesByLocale(map[string]func(auth.Message) string{"es": func(m auth.Message) string { return "Tu código es " + m.Code }}))
	_ = p.Deliver(context.Background(), auth.Identity{Value: "+15550100100"}, auth.Message{Purpose: auth.PurposeSignInCode, Code: "123456", Locale: "es-MX"})
	if got != "Tu código es 123456" {
		t.Fatalf("es-MX = %q", got)
	}
}

// TestDefaultTemplate_ResetCode: a reset by code carries the code and
// promises no lifetime, which belongs to the password plugin.
func TestDefaultTemplate_ResetCode(t *testing.T) {
	s := phone.DefaultTemplate(auth.Message{Purpose: auth.PurposeReset, Code: "424242"})
	if !strings.Contains(s, "424242") || strings.Contains(s, "expires") || strings.Contains(s, "http") {
		t.Fatalf("reset code text = %q", s)
	}
}

// TestRound2Operations: change and confirm-change are always registered and
// rate-limited; a Verifier does not remove the SMSSender requirement.
func TestRound2Operations(t *testing.T) {
	ph := phone.New(phone.WithSMS(phone.SMSFunc(func(context.Context, string, string) error { return nil })))
	ids := map[auth.EndpointID]bool{}
	for _, op := range ph.Operations() {
		ids[op.Info().ID] = true
	}
	if !ids[phone.EndpointChange] || !ids[phone.EndpointConfirmChange] {
		t.Fatalf("operations = %v", ids)
	}
	limited := map[auth.EndpointID]bool{}
	for _, r := range ph.RateLimits() {
		limited[r.Match] = true
	}
	if !limited[phone.EndpointChange] || !limited[phone.EndpointConfirmChange] {
		t.Fatalf("rate rules = %v", limited)
	}
	if _, err := auth.New(auth.WithPlugins(phone.New(phone.Login(), phone.SignInWithCode(), phone.WithVerifier(nopVerifier{})))); !errors.Is(err, phone.ErrNoSMS) {
		t.Fatalf("a verifier without an SMS sender = %v", err)
	}
}

// nopVerifier satisfies Verifier for the wiring test.
type nopVerifier struct{}

func (nopVerifier) Send(context.Context, string) error          { return nil }
func (nopVerifier) Check(context.Context, string, string) error { return nil }
