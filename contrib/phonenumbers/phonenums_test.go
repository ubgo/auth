package phonenums

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/phone"
)

func TestNormalizer(t *testing.T) {
	au := Normalizer("AU")
	cases := map[string]string{
		"0412 345 678":      "+61412345678",
		"+61 412 345 678":   "+61412345678",
		"+1 (650) 253-0000": "+16502530000",
	}
	for in, want := range cases {
		if got, err := au(in); err != nil || got != want {
			t.Errorf("Normalizer(AU)(%q) = %q %v, want %q", in, got, err, want)
		}
	}
	if _, err := au("not a number"); !errors.Is(err, ErrNotANumber) {
		t.Errorf("garbage: %v", err)
	}
}

func TestValidator(t *testing.T) {
	v := Validator()
	if err := v("+61412345678"); err != nil {
		t.Errorf("a real mobile range: %v", err)
	}
	if err := v("+61012345678"); !errors.Is(err, ErrNotANumber) {
		t.Errorf("an unassigned range: %v", err)
	}
	// A value the phone plugin's normalizer never produced, such as one read
	// back from a row written before the normalizer was plugged in.
	if err := v("not a number"); !errors.Is(err, ErrNotANumber) {
		t.Errorf("garbage: %v", err)
	}
}

type signIn struct{}

func (signIn) Name() string  { return "stub" }
func (signIn) SignsIn() bool { return true }

// TestWithThePhonePlugin: the core stores the E.164 form of a national number.
func TestWithThePhonePlugin(t *testing.T) {
	sms := phone.SMSFunc(func(context.Context, string, string) error { return nil })
	a, err := auth.New(auth.WithPlugins(signIn{}, phone.New(phone.Login(), phone.WithSMS(sms),
		phone.WithNormalizer(Normalizer("AU")), phone.WithValidator(Validator()))))
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.Normalize(phone.KindPhone, "0412 345 678")
	if err != nil || got != "+61412345678" {
		t.Fatalf("Normalize = %q %v", got, err)
	}
}
