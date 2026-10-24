package redisrate

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// TestOptions_RefuseNil: Clock(nil) is refused with auth.ErrNilOption naming
// it, and every store the package builds reports it through OptionErr, which
// auth.New checks, instead of the first call panicking on the nil clock.
// TestGuard_OptionsRefuseNil in the core module fails when an option that
// takes a func or an interface is missing from this table.
func TestOptions_RefuseNil(t *testing.T) {
	for name, opt := range map[string]Option{
		"redisrate.Clock": Clock(nil),
	} {
		for store, oc := range map[string]auth.OptionChecker{
			"New":                   New(nil, opt),
			"NewSessionStore":       NewSessionStore(nil, opt),
			"NewSessionCache":       NewSessionCache(nil, opt),
			"NewSessionRevocations": NewSessionRevocations(nil, opt),
			"NewStorage":            NewStorage(nil, opt),
		} {
			if err := oc.OptionErr(); !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
				t.Errorf("%s(%s(nil)): OptionErr = %v, want auth.ErrNilOption naming it", store, name, err)
			}
		}
		vs, ok := NewVerificationStore(nil, opt).(auth.OptionChecker)
		if !ok || !errors.Is(vs.OptionErr(), auth.ErrNilOption) {
			t.Errorf("NewVerificationStore(%s(nil)): the wrapped storage's OptionErr is lost", name)
		}
		if _, err := auth.New(auth.WithRateStore(New(nil, opt))); !errors.Is(err, auth.ErrNilOption) {
			t.Errorf("auth.New(WithRateStore(New(%s(nil)))) = %v, want auth.ErrNilOption", name, err)
		}
	}
	if err := New(nil).OptionErr(); err != nil {
		t.Fatalf("no options: OptionErr = %v", err)
	}
}
