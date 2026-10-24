package jwt

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

func TestAudience_OneIsAStringSeveralAreAnArray(t *testing.T) {
	k := key(t)
	now := time.Unix(1_800_000_000, 0)
	one, err := sign(k, map[string]any{claimSubject: "u", claimExpires: now.Add(time.Minute).Unix(), claimAudience: "api"})
	if err != nil {
		t.Fatal(err)
	}
	many, err := sign(k, map[string]any{claimSubject: "u", claimExpires: now.Add(time.Minute).Unix(), claimAudience: []string{"api", "reports"}})
	if err != nil {
		t.Fatal(err)
	}
	keys := KeysFromJWKS((&Plugin{signer: keySigner{key: k}}).PublicKeys())
	for _, aud := range []string{"api", "reports"} {
		v := Verifier{Keys: keys, Audience: aud, Now: func() time.Time { return now }}
		if _, err := v.Verify(many); err != nil {
			t.Errorf("audience %q in an array: %v", aud, err)
		}
	}
	v := Verifier{Keys: keys, Audience: "reports", Now: func() time.Time { return now }}
	if _, err := v.Verify(one); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a token for api verified for reports: %v", err)
	}
	bad, _ := sign(k, map[string]any{claimSubject: "u", claimExpires: now.Add(time.Minute).Unix(), claimAudience: 42})
	if _, err := v.Verify(bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a numeric aud: %v", err)
	}
	// The option collects several values.
	p := New(WithSigningKey(k), Audience("api"), Audience("reports", "billing"))
	if len(p.audience) != 3 || p.audience[2] != "billing" {
		t.Fatalf("audiences = %v", p.audience)
	}
}

func TestSubject_OptionIsKept(t *testing.T) {
	fn := func(context.Context, auth.User, auth.Session) string { return "ext" }
	p := New(WithSigningKey(key(t)), Subject(fn))
	if p.subject == nil || p.subject(context.Background(), auth.User{}, auth.Session{}) != "ext" {
		t.Fatal("Subject was not kept")
	}
}
