package auth_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
)

// TestRingSealer_MatchesTheKeyRing: the default Sealer is the KeyRing in
// the same format both ways, so values sealed before an app moved to the
// Sealer interface still open, and aad still binds a value to its row.
func TestRingSealer_MatchesTheKeyRing(t *testing.T) {
	ctx := context.Background()
	cur, old := bytes.Repeat([]byte("c"), auth.SealKeySize), bytes.Repeat([]byte("o"), auth.SealKeySize)
	ring, err := auth.NewKeyRing(cur, old)
	if err != nil {
		t.Fatal(err)
	}
	s := auth.RingSealer(ring)
	sealed, err := s.Seal(ctx, []byte("refresh"), "row_1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ring.Open(sealed, "row_1"); err != nil || string(got) != "refresh" {
		t.Fatalf("the ring must open what the Sealer sealed: %q %v", got, err)
	}
	legacy, err := auth.Seal(old, []byte("legacy"), "row_2")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Open(ctx, legacy, "row_2"); err != nil || string(got) != "legacy" {
		t.Fatalf("the Sealer must open what the previous key sealed: %q %v", got, err)
	}
	if _, err := s.Open(ctx, sealed, "row_2"); !errors.Is(err, auth.ErrSealedCorrupt) {
		t.Fatalf("a value moved to another row opened: %v", err)
	}
}

// nopSealer is a Sealer that New only stores.
type nopSealer struct{}

func (nopSealer) Seal(context.Context, []byte, string) (string, error) { return "", nil }
func (nopSealer) Open(context.Context, string, string) ([]byte, error) { return nil, nil }

// TestWithSealer_ReachesConfigAndRefusesNil: plugins read the app's Sealer
// from Config, none set reads nil, and a nil Sealer is a configuration
// mistake rather than a request for the default.
func TestWithSealer_ReachesConfigAndRefusesNil(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(signIn{on: true}), auth.WithSealer(nopSealer{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Config().Sealer().(nopSealer); !ok {
		t.Fatalf("Config().Sealer() = %T, want the WithSealer value", a.Config().Sealer())
	}
	a, err = newAuth(auth.WithPlugins(signIn{on: true}))
	if err != nil || a.Config().Sealer() != nil {
		t.Fatalf("no WithSealer must read nil: %v %v", a, err)
	}
	if _, err := newAuth(auth.WithPlugins(signIn{on: true}), auth.WithSealer(nil)); !errors.Is(err, auth.ErrNilOption) {
		t.Fatalf("WithSealer(nil) = %v, want ErrNilOption", err)
	}
}
