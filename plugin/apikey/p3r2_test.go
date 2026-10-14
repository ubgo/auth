package apikey

import (
	"errors"
	"testing"

	"github.com/ubgo/auth"
)

func TestCheckDistinctPrefixes(t *testing.T) {
	cases := []struct {
		name string
		opts []Option
		want error
	}{
		{"off", nil, nil},
		{"default prefix", []Option{RejectUnknownKeys()}, ErrPrefixNotDistinct},
		{"dotted", []Option{RejectUnknownKeys(), Prefix("sk.live_")}, nil},
		{"dot in the middle only", []Option{RejectUnknownKeys(), Prefix("a.b_")}, nil},
		{"a configuration's plain prefix", []Option{RejectUnknownKeys(), Prefix("sk.live_"), Configuration("test", Prefix("sk_test_"))}, ErrPrefixNotDistinct},
	}
	for _, tc := range cases {
		p := New(append([]Option{Scopes("s")}, tc.opts...)...)
		if err := p.Validate(&auth.Config{}); !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	if err := New(Scopes("s"), Configuration("x", RejectUnknownKeys())).Validate(&auth.Config{}); !errors.Is(err, ErrBadConfig) {
		t.Fatalf("RejectUnknownKeys inside a configuration: %v, want ErrBadConfig", err)
	}
}

func TestRejectUnknownKeys_Answers(t *testing.T) {
	plain, reject, both := New(), New(RejectUnknownKeys()), New(RejectUnknownKeys(), DistinctErrors())
	for _, tc := range []struct {
		p                  *Plugin
		refuse, owner, unk error
	}{
		{plain, auth.ErrSignedOut, nil, auth.ErrSignedOut},
		{reject, ErrInvalidKey, ErrInvalidKey, ErrInvalidKey},
		{both, ErrKeyDisabled, ErrOwnerBlocked, ErrInvalidKey},
	} {
		if got := tc.p.refuse(ErrKeyDisabled); !errors.Is(got, tc.refuse) {
			t.Errorf("refuse = %v, want %v", got, tc.refuse)
		}
		if got := tc.p.OwnerRefused(); !errors.Is(got, tc.owner) || (tc.owner == nil && got != nil) {
			t.Errorf("OwnerRefused = %v, want %v", got, tc.owner)
		}
		if got := tc.p.unknownKey(auth.ErrSignedOut); !errors.Is(got, tc.unk) {
			t.Errorf("unknownKey = %v, want %v", got, tc.unk)
		}
	}
	other := errors.New("db down")
	if got := reject.unknownKey(other); got != other {
		t.Fatalf("unknownKey changed another error: %v", got)
	}
}
