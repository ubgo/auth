package apikey

import (
	"errors"
	"testing"
	"time"
)

// TestExpiryOf pins CreateRequest.ExpiresIn: seconds are better-auth's unit,
// held to the WithExpiry day bounds as a duration, and never combined with
// ExpiresInDays.
func TestExpiryOf(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	p := New(Scopes("s"))
	if exp, err := p.expiryOf(0, 3600, now); err != nil || !exp.Equal(now.Add(time.Hour)) {
		t.Fatalf("an hour = %v %v", exp, err)
	}
	if exp, err := p.expiryOf(2, 0, now); err != nil || !exp.Equal(now.Add(2*day)) {
		t.Fatalf("days still work = %v %v", exp, err)
	}
	if exp, err := p.expiryOf(0, 0, now); err != nil || exp != nil {
		t.Fatalf("neither = never: %v %v", exp, err)
	}
	if _, err := p.expiryOf(1, 60, now); !errors.Is(err, ErrExpiryConflict) {
		t.Fatalf("both: %v", err)
	}
	for _, sec := range []int64{-1, maxExpirySeconds + 1} {
		if _, err := p.expiryOf(0, sec, now); !errors.Is(err, ErrExpiryOutOfRange) {
			t.Errorf("%d seconds: %v", sec, err)
		}
	}
	if _, err := p.expiryOf(0, maxExpirySeconds, now); err != nil {
		t.Fatalf("the longest duration: %v", err)
	}
	b := New(Scopes("s"), WithExpiry(Expiry{MinDays: 1, MaxDays: 30}))
	for _, sec := range []int64{3600, 30*86400 + 1} {
		if _, err := b.expiryOf(0, sec, now); !errors.Is(err, ErrExpiryOutOfRange) {
			t.Errorf("%d seconds outside one to thirty days: %v", sec, err)
		}
	}
	for _, sec := range []int64{86400, 30 * 86400} {
		if exp, err := b.expiryOf(0, sec, now); err != nil || !exp.Equal(now.Add(time.Duration(sec)*time.Second)) {
			t.Errorf("%d seconds on a bound: %v %v", sec, exp, err)
		}
	}
	// The day count is bounded too: past a time.Duration it would wrap into
	// the past and mint a key that is already expired.
	if _, err := p.expiryFor(maxExpiryDays+1, now); !errors.Is(err, ErrExpiryOutOfRange) {
		t.Fatalf("days past a duration: %v", err)
	}
}

// TestStampEveryUse_IsPluginWide pins that StampEveryUse is refused inside a
// Configuration, like the other options that change how every key resolves.
func TestStampEveryUse_IsPluginWide(t *testing.T) {
	p := New(Scopes("s"), Configuration("live", StampEveryUse()))
	p.buildConfigs()
	if !errors.Is(p.nestErr, ErrBadConfig) {
		t.Fatalf("nested StampEveryUse: %v", p.nestErr)
	}
	if !New(StampEveryUse()).stampEvery {
		t.Fatal("StampEveryUse did not set the switch")
	}
}
