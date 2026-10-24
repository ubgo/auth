package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/pow"
)

// failingMarkers is a rate store that fails the counters plugins keep with
// RateHit (their keys start with "plugin|") while armed, and counts rules'
// keys as the memory store does.
type failingMarkers struct {
	auth.RateStore
	armed bool
}

// Hit fails a plugin's counter while armed.
func (f *failingMarkers) Hit(ctx context.Context, key string, window time.Duration) (int, error) {
	if f.armed && strings.HasPrefix(key, "plugin|") {
		return 0, errMarkerStore
	}
	return f.RateStore.Hit(ctx, key, window)
}

// errMarkerStore is the failure the armed store returns.
var errMarkerStore = errors.New("rate store: unreachable")

// powSweep is an Env with password sign-in under a proof-of-work challenge,
// on SQLite with fault injection.
type powSweep struct {
	*authtest.Env
	pw    *password.Plugin
	p     *pow.Plugin
	rates *failingMarkers
}

func newPowSweep(t *testing.T) (*powSweep, *authtest.Faults) {
	t.Helper()
	f := authtest.NewFaults()
	pw, p := password.New(password.Argon2(fastArgon2)), pow.New(pow.Difficulty(powDifficulty))
	rates := &failingMarkers{RateStore: auth.NewMemoryRateStore(time.Now)}
	e := authtest.New(t, authtest.WithFaults(f),
		authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin {
			return []auth.Plugin{email.New(email.Login(), email.Recover(), email.WithMailer(e.Mail)), pw, p}
		}),
		authtest.WithOptions(auth.WithRateStore(rates),
			auth.WithRateRules(auth.RateRule{Match: password.EndpointSignIn, Key: auth.ByIP, Limit: 1, Window: time.Hour, Action: auth.RateChallenge})))
	return &powSweep{Env: e, pw: pw, p: p, rates: rates}, f
}

// signInWith is ada's password sign-in from a browser carrying proof.
func (s *powSweep) signInWith(ctx context.Context, proof string) error {
	req := auth.Request{
		Transport: auth.TransportHTTP, Client: auth.Client{IP: "203.0.113.7", UserAgent: "test", Origin: testBaseURL},
		Header: func(name string) string {
			if name == pow.ProofHeader {
				return proof
			}
			return ""
		},
	}
	_, err := s.pw.SignIn(s.Auth.WithRequest(ctx, req), password.SignInRequest{Identifier: "ada@example.com", Password: password.Secret(secret)})
	return err
}

// TestPoW_EveryDatabaseFailureSurfaces: asking for a challenge, and passing a
// call over its limit with a proof, return an error whichever database call
// fails: the challenge row, its spend, the replay marker in the rate store.
func TestPoW_EveryDatabaseFailureSurfaces(t *testing.T) {
	t.Run("issuing a challenge", func(t *testing.T) {
		authtest.SweepFaults(t, func() (*powSweep, *authtest.Faults) { return newPowSweep(t) }, func(s *powSweep) func(context.Context) error {
			return func(ctx context.Context) error {
				_, err := s.p.Challenge(s.Anonymous(ctx))
				return err
			}
		})
	})
	t.Run("passing a challenged sign-in", func(t *testing.T) {
		authtest.SweepFaults(t, func() (*powSweep, *authtest.Faults) { return newPowSweep(t) }, func(s *powSweep) func(context.Context) error {
			if _, err := s.pw.SignUp(s.Anonymous(context.Background()), password.SignUpRequest{Identifier: "ada@example.com", Password: password.Secret(secret)}); err != nil {
				t.Fatal(err)
			}
			if err := s.signInWith(context.Background(), ""); err != nil { // the free call
				t.Fatal(err)
			}
			ch, err := s.p.Challenge(s.Anonymous(context.Background()))
			if err != nil {
				t.Fatal(err)
			}
			proof, err := pow.Solve(context.Background(), ch)
			if err != nil {
				t.Fatal(err)
			}
			return func(ctx context.Context) error { return s.signInWith(ctx, proof) }
		})
	})
}

// TestPoW_ARateStoreThatCannotRecordTheSpendRefusesTheProof: the replay marker
// is part of accepting a proof, so a store that cannot write it fails the call
// instead of letting a proof through that could be used again.
func TestPoW_ARateStoreThatCannotRecordTheSpendRefusesTheProof(t *testing.T) {
	s, _ := newPowSweep(t)
	if _, err := s.pw.SignUp(s.Anonymous(context.Background()), password.SignUpRequest{Identifier: "ada@example.com", Password: password.Secret(secret)}); err != nil {
		t.Fatal(err)
	}
	if err := s.signInWith(context.Background(), ""); err != nil { // the free call
		t.Fatal(err)
	}
	ch, err := s.p.Challenge(s.Anonymous(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := pow.Solve(context.Background(), ch)
	if err != nil {
		t.Fatal(err)
	}
	s.rates.armed = true
	if err := s.signInWith(context.Background(), proof); !errors.Is(err, errMarkerStore) {
		t.Fatalf("with the marker store down: %v, want its error", err)
	}
	s.rates.armed = false
	// The challenge row was spent before the marker failed (a rate challenge
	// runs ahead of the call's transaction), so the client asks for another
	// challenge: a store outage costs a proof, never lets one be reused.
	if err := s.signInWith(context.Background(), proof); !errors.Is(err, pow.ErrChallengeInvalid) {
		t.Fatalf("the same proof once the store is back: %v, want ErrChallengeInvalid", err)
	}
}
