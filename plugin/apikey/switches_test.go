package apikey

import (
	"errors"
	"testing"

	"github.com/ubgo/auth"
)

func TestValidate_Limits(t *testing.T) {
	wire := func(opts ...Option) error {
		_, err := auth.New(auth.WithPlugins(stubSignIn{}, New(append([]Option{Scopes("s")}, opts...)...)))
		return err
	}
	for name, opts := range map[string][]Option{
		"zero max keys":     {MaxKeys(0)},
		"zero name length":  {NameLength(0)},
		"negative min days": {WithExpiry(Expiry{MinDays: -1})},
		"min above max":     {WithExpiry(Expiry{MinDays: 30, MaxDays: 7})},
		"default below min": {WithExpiry(Expiry{MinDays: 7, DefaultDays: 1})},
		"default above max": {WithExpiry(Expiry{MaxDays: 7, DefaultDays: 30})},
	} {
		if err := wire(opts...); !errors.Is(err, ErrBadLimits) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, opts := range map[string][]Option{
		"defaults":        nil,
		"a year at most":  {WithExpiry(Expiry{MaxDays: 365, DefaultDays: 90})},
		"a week at least": {WithExpiry(Expiry{MinDays: 7}), MaxKeys(5), NameLength(20), RequireName()},
	} {
		if err := wire(opts...); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	p := New(Scopes("s"))
	if p.maxKeys != MaxKeysPerUser || p.nameLength != maxNameLength || p.requireName || p.expiry != (Expiry{}) {
		t.Fatalf("defaults = %+v", p)
	}
}
