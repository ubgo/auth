package jwt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

func TestSign_MintsATokenWithoutASession(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := New(WithSigningKey(key), Issuer("https://iss"), Audience("svc"), WithTTL(10*time.Minute),
		Subject(func(context.Context, auth.User, auth.Session) string { return "ignored" }),
		Claims(func(context.Context, auth.User) map[string]any { return map[string]any{"from_option": true} }))
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	res, err := p.Sign(ctx, SignRequest{Subject: "job-7", Claims: map[string]any{"role": "worker"}})
	if err != nil {
		t.Fatal(err)
	}
	v := Verifier{Keys: KeysFromJWKS(p.PublicKeys()), Issuer: "https://iss", Audience: "svc"}
	got, err := v.Verify(res.Token)
	if err != nil || got.Subject != "job-7" || got.SessionID != "" || string(got.Extra["role"]) != `"worker"` {
		t.Fatalf("verified = %+v %v", got, err)
	}
	// The option's Subject and Claims are the session path's, not Sign's.
	if _, ok := got.Extra["from_option"]; ok {
		t.Fatal("Claims option applied to Sign")
	}
	if d := res.ExpiresAt.Sub(p.core.Now()); d < 9*time.Minute || d > 10*time.Minute {
		t.Fatalf("expires in %v, want the plugin's TTL", d)
	}
	// Its own audience, TTL (capped) and no audience at all.
	res, err = p.Sign(ctx, SignRequest{Subject: "s", Audience: []string{"a", "b"}, TTL: 48 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if d := res.ExpiresAt.Sub(p.core.Now()); d > MaxTTL || d < MaxTTL-time.Minute {
		t.Fatalf("expires in %v, want the cap", d)
	}
	if _, err := (Verifier{Keys: KeysFromJWKS(p.PublicKeys()), Audience: "b"}).Verify(res.Token); err != nil {
		t.Fatalf("second audience: %v", err)
	}
	if _, err := (Verifier{Keys: KeysFromJWKS(p.PublicKeys()), Audience: "svc"}).Verify(res.Token); !errors.Is(err, ErrInvalid) {
		t.Fatal("the plugin's audience leaked into a token with its own")
	}
	none, _ := p.Sign(ctx, SignRequest{Subject: "s", Audience: []string{}})
	if _, err := (Verifier{Keys: KeysFromJWKS(p.PublicKeys()), Audience: "svc"}).Verify(none.Token); !errors.Is(err, ErrInvalid) {
		t.Fatal("an empty audience list still carried one")
	}
	// Refusals: no subject, a reserved claim, a claim with no JSON form.
	if _, err := p.Sign(ctx, SignRequest{}); !errors.Is(err, ErrEmptySubject) {
		t.Fatalf("empty subject: %v", err)
	}
	if _, err := p.Sign(ctx, SignRequest{Subject: "s", Claims: map[string]any{claimSession: "x"}}); !errors.Is(err, ErrReservedClaim) {
		t.Fatalf("reserved claim: %v", err)
	}
	if _, err := p.Sign(ctx, SignRequest{Subject: "s", Claims: map[string]any{"ch": make(chan int)}}); err == nil {
		t.Fatal("a channel claim was encoded")
	}
}
