package auth

import (
	"bytes"
	"testing"
	"time"
)

// TestWithSecret_StatelessInstancesShareTheDerivedKey: two instances built
// from the same secret open each other's stateless tokens, which is what lets
// a fleet share one variable; an explicit key wins over the secret.
func TestWithSecret_StatelessInstancesShareTheDerivedKey(t *testing.T) {
	secret := bytes.Repeat([]byte("s"), MinSecretSize)
	mk := func(keys ...[]byte) *Auth {
		a, err := New(WithPlugins(scriptSignIn{}), WithSecret(secret), WithStatelessSessions(keys...))
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	a, b := mk(), mk()
	s := Session{ID: "s", UserID: "u", ExpiresAt: time.Now().Add(time.Hour)}
	tok, err := a.stateless.seal(s)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.stateless.open(tok); err != nil || got.UserID != "u" {
		t.Fatalf("the second instance did not open the first's token: %+v %v", got, err)
	}
	explicit := mk(bytes.Repeat([]byte{7}, SealKeySize))
	tok2, err := explicit.stateless.seal(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.stateless.open(tok2); err == nil {
		t.Fatal("a token sealed with an explicit key must not open under the derived one")
	}
	if a.stateless.ring.Len() != 1 {
		t.Fatalf("derived ring has %d keys, want 1", a.stateless.ring.Len())
	}
}

// TestWithSecret_RotationOpensOldStatelessTokens: a token issued under the
// old secret still opens on an instance given WithSecret(new, old), and not
// on one given the new secret alone.
func TestWithSecret_RotationOpensOldStatelessTokens(t *testing.T) {
	old := bytes.Repeat([]byte("o"), MinSecretSize)
	cur := bytes.Repeat([]byte("n"), MinSecretSize)
	mk := func(secrets ...[]byte) *Auth {
		a, err := New(WithPlugins(scriptSignIn{}), WithSecret(secrets[0], secrets[1:]...), WithStatelessSessions())
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	tok, err := mk(old).stateless.seal(Session{ID: "s", UserID: "u", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := mk(cur, old).stateless.open(tok); err != nil || got.UserID != "u" {
		t.Fatalf("rotated instance: %+v %v", got, err)
	}
	if _, err := mk(cur).stateless.open(tok); err == nil {
		t.Fatal("the new secret alone must not open the old token")
	}
}
