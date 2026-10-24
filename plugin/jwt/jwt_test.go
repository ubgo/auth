package jwt

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSignVerifyAndRejections(t *testing.T) {
	k := key(t)
	now := time.Unix(1_800_000_000, 0)
	tok, err := sign(k, map[string]any{"iss": "https://app", "sub": "usr_1", "aud": "api", "exp": now.Add(time.Minute).Unix(), "nbf": now.Unix(), "sid": "ses_1", "role": "editor"})
	if err != nil {
		t.Fatal(err)
	}
	p := &Plugin{signer: keySigner{key: k}}
	v := Verifier{Keys: KeysFromJWKS(p.PublicKeys()), Issuer: "https://app", Audience: "api", Now: func() time.Time { return now }}
	got, err := v.Verify(tok)
	if err != nil || got.Subject != "usr_1" || got.SessionID != "ses_1" || string(got.Extra["role"]) != `"editor"` {
		t.Fatalf("verify = %+v %v", got, err)
	}
	if _, ok := got.Extra["exp"]; ok {
		t.Fatal("registered claims must not appear in Extra")
	}

	parts := strings.Split(tok, ".")
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"` + KeyID(k.Public().(ed25519.PublicKey)) + `"}`))
	cases := map[string]string{
		"alg none":      none + "." + parts[1] + ".",
		"tampered body": parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"usr_admin","exp":9999999999}`)) + "." + parts[2],
		"two parts":     parts[0] + "." + parts[1],
	}
	for name, bad := range cases {
		if _, err := v.Verify(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, vv := range map[string]Verifier{
		"expired":        {Keys: v.Keys, Now: func() time.Time { return now.Add(time.Hour) }},
		"wrong audience": {Keys: v.Keys, Audience: "other", Now: v.Now},
		"wrong issuer":   {Keys: v.Keys, Issuer: "https://evil", Now: v.Now},
		"unknown key":    {Keys: KeysFromJWKS((&Plugin{signer: keySigner{key: key(t)}}).PublicKeys()), Now: v.Now},
	} {
		if _, err := vv.Verify(tok); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRotation_PreviousKeysStillVerify(t *testing.T) {
	old, cur := key(t), key(t)
	tok, _ := sign(old, map[string]any{"sub": "u", "exp": time.Now().Add(time.Minute).Unix()})
	p := &Plugin{signer: keySigner{key: cur}, previous: []crypto.PublicKey{old.Public()}}
	if _, err := (Verifier{Keys: KeysFromJWKS(p.PublicKeys())}).Verify(tok); err != nil {
		t.Fatalf("a token signed before rotation: %v", err)
	}
}
