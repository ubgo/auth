package jwt

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// fakeKMS is a Signer that holds its key outside the plugin, the way a key
// management service does, and can be made to misbehave.
type fakeKMS struct {
	key     ed25519.PrivateKey
	publish bool
	fail    error
	calls   int
}

func (k *fakeKMS) Sign(_ context.Context, pub crypto.PublicKey, in []byte) ([]byte, error) {
	k.calls++
	if k.fail != nil {
		return nil, k.fail
	}
	if !k.key.Public().(ed25519.PublicKey).Equal(pub) {
		return nil, errors.New("asked for another key")
	}
	return ed25519.Sign(k.key, in), nil
}
func (k *fakeKMS) PublicKeys() []crypto.PublicKey {
	if !k.publish {
		return nil
	}
	return []crypto.PublicKey{k.key.Public()}
}

func TestSigner_CustomSignerSignsAndIsChecked(t *testing.T) {
	k := key(t)
	kms := &fakeKMS{key: k, publish: true}
	kid := KeyID(k.Public().(ed25519.PublicKey))
	now := time.Unix(1_800_000_000, 0)
	claims := map[string]any{claimSubject: "u", claimExpires: now.Add(time.Minute).Unix()}
	tok, err := signWith(context.Background(), kms, tokenType, claims)
	if err != nil || kms.calls != 1 {
		t.Fatalf("sign through a custom signer: %v (%d calls)", err, kms.calls)
	}
	// The header carries the published key's id, and the token verifies
	// against the key set the plugin would publish for this signer.
	v := Verifier{Keys: KeysFromJWKS((&Plugin{signer: kms}).PublicKeys()), Now: func() time.Time { return now }}
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("verify: %v", err)
	}
	var hdr struct {
		Kid string `json:"kid"`
	}
	hb, _ := decodeSegment(strings.Split(tok, ".")[0])
	if err := json.Unmarshal(hb, &hdr); err != nil || hdr.Kid != kid {
		t.Fatalf("header = %s %v", hb, err)
	}
	// A signer that does not publish its key, and one that fails, both
	// fail the call rather than minting an unverifiable token.
	kms.publish = false
	if _, err := signWith(context.Background(), kms, tokenType, claims); !errors.Is(err, ErrSignerKey) {
		t.Fatalf("unpublished key: %v", err)
	}
	kms.publish, kms.fail = true, errors.New("kms down")
	if _, err := signWith(context.Background(), kms, tokenType, claims); err == nil || !strings.Contains(err.Error(), "kms down") {
		t.Fatalf("failing signer: %v", err)
	}
	// The plugin wires it like a key.
	p := New(WithSigner(kms), Issuer("https://iss"))
	if p.signer != kms || len(p.PublicKeys().Keys) != 1 || p.PublicKeys().Keys[0].KeyID != kid {
		t.Fatalf("plugin with a custom signer = %+v", p.PublicKeys())
	}
	if _, err := auth.New(auth.WithPlugins(signIn{}, New(WithSigner(kms), Issuer("x")))); err != nil {
		t.Fatal(err)
	}
	// A short key is not a signer at all.
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, New(WithSigningKey(ed25519.PrivateKey("short"))))); !errors.Is(err, ErrNoKey) {
		t.Fatalf("short key: %v", err)
	}
}

func decodeSegment(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func TestRotating_DerivesTheSameKeysEverywhereAndPublishesWithinGrace(t *testing.T) {
	seed := []byte(strings.Repeat("s", RotationSeedSize))
	start := time.Unix(1_800_000_000, 0).Truncate(2 * time.Hour)
	clock := start.Add(time.Minute)
	a := Rotating(seed, 2*time.Hour, 30*time.Minute).(*rotatingSigner)
	b := Rotating(seed, 2*time.Hour, 30*time.Minute).(*rotatingSigner)
	a.now, b.now = func() time.Time { return clock }, func() time.Time { return clock }
	if KeyID(a.PublicKeys()[0]) != KeyID(b.PublicKeys()[0]) {
		t.Fatal("two instances derive different keys for one period")
	}
	other := Rotating([]byte(strings.Repeat("o", RotationSeedSize)), 2*time.Hour, 30*time.Minute).(*rotatingSigner)
	other.now = a.now
	if KeyID(other.PublicKeys()[0]) == KeyID(a.PublicKeys()[0]) {
		t.Fatal("another seed derives the same key")
	}
	// Right after the period starts, the previous key is still published
	// (its end is within grace); mid-period it is gone.
	if keys := a.PublicKeys(); len(keys) != 2 || KeyID(keys[0]) != KeyID(a.PublicKeys()[0]) {
		t.Fatalf("keys just after a rotation = %d", len(keys))
	}
	clock = start.Add(time.Hour)
	if keys := a.PublicKeys(); len(keys) != 1 {
		t.Fatalf("keys mid-period = %d", len(keys))
	}
	// A token signed before a rotation verifies through the key set after
	// it, until grace runs out.
	clock = start.Add(2*time.Hour - time.Second)
	keyBefore := a.PublicKeys()[0]
	kidBefore := KeyID(keyBefore)
	claims := map[string]any{claimSubject: "u", claimExpires: clock.Add(10 * time.Minute).Unix()}
	tok, err := signWith(context.Background(), a, tokenType, claims)
	if err != nil {
		t.Fatal(err)
	}
	clock = start.Add(2*time.Hour + time.Second)
	if KeyID(a.PublicKeys()[0]) == kidBefore {
		t.Fatal("the key did not rotate")
	}
	v := Verifier{Keys: KeysFromJWKS((&Plugin{signer: a}).PublicKeys()), Now: func() time.Time { return clock }}
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("token from the previous period: %v", err)
	}
	// Signing with the previous period's kid still works inside grace (the
	// KeyID-then-Sign race at the boundary), not outside it.
	if _, err := a.Sign(context.Background(), keyBefore, []byte("x")); err != nil {
		t.Fatalf("sign with the previous key inside grace: %v", err)
	}
	clock = start.Add(3 * time.Hour)
	if _, err := a.Sign(context.Background(), keyBefore, []byte("x")); !errors.Is(err, ErrSignerKey) {
		t.Fatalf("sign with a retired key: %v", err)
	}
	if _, err := (Verifier{Keys: KeysFromJWKS((&Plugin{signer: a}).PublicKeys()), Now: func() time.Time { return clock }}).Verify(tok); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a token from a retired key: %v", err)
	}
}

func TestRotating_Validation(t *testing.T) {
	seed := []byte(strings.Repeat("s", RotationSeedSize))
	wire := func(s Signer, opts ...Option) error {
		_, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, New(append([]Option{WithSigner(s)}, opts...)...)))
		return err
	}
	if err := wire(Rotating([]byte("short"), time.Hour, time.Hour)); !errors.Is(err, ErrRotationSeed) {
		t.Fatalf("short seed: %v", err)
	}
	if err := wire(Rotating(seed, time.Minute, time.Hour)); !errors.Is(err, ErrRotationInterval) {
		t.Fatalf("minute interval: %v", err)
	}
	if err := wire(Rotating(seed, time.Hour, time.Minute)); !errors.Is(err, ErrRotationGrace) {
		t.Fatalf("grace below the TTL: %v", err)
	}
	r := Rotating(seed, 24*time.Hour, time.Hour).(*rotatingSigner)
	clock := time.Unix(1_800_000_000, 0)
	a, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithClock(func() time.Time { return clock }), auth.WithPlugins(signIn{}, New(WithSigner(r))))
	if err != nil {
		t.Fatal(err)
	}
	// Init handed the signer the core's clock.
	if !r.now().Equal(a.Now()) {
		t.Fatalf("signer clock %v, core clock %v", r.now(), a.Now())
	}
}

func TestRemoteKeys_FetchesCachesAndBoundsRefresh(t *testing.T) {
	k1, k2 := key(t), key(t)
	set := (&Plugin{signer: keySigner{key: k1}}).PublicKeys()
	var fetches atomic.Int32
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(set)
	}))
	defer srv.Close()
	now := time.Unix(1_800_000_000, 0)
	remote := NewRemoteKeys(srv.URL, srv.Client())
	remote.Now = func() time.Time { return now }
	kid1, kid2 := KeyID(k1.Public().(ed25519.PublicKey)), KeyID(k2.Public().(ed25519.PublicKey))

	// First lookup fetches; a known kid is served from the cache.
	if pub, ok := remote.Lookup(kid1); !ok || !k1.Public().(ed25519.PublicKey).Equal(pub) || fetches.Load() != 1 {
		t.Fatalf("first lookup: %v %d", ok, fetches.Load())
	}
	remote.Lookup(kid1)
	if fetches.Load() != 1 {
		t.Fatal("a cached kid refetched")
	}
	// An unknown kid inside the refresh window does not fetch; after the
	// window it does and finds the rotated key.
	set = (&Plugin{signer: keySigner{key: k2}, previous: []crypto.PublicKey{k1.Public()}}).PublicKeys()
	if _, ok := remote.Lookup(kid2); ok || fetches.Load() != 1 {
		t.Fatalf("unknown kid inside the window: %v %d", ok, fetches.Load())
	}
	now = now.Add(RemoteMinRefresh)
	if _, ok := remote.Lookup(kid2); !ok || fetches.Load() != 2 {
		t.Fatalf("unknown kid after the window: %v %d", ok, fetches.Load())
	}
	// A stale set is refetched even for a known kid; a failed fetch keeps
	// the old keys and is reported by LastError.
	now = now.Add(RemoteMaxAge + time.Second)
	status = http.StatusInternalServerError
	if _, ok := remote.Lookup(kid2); !ok || fetches.Load() != 3 || !errors.Is(remote.LastError(), ErrRemoteKeys) {
		t.Fatalf("stale set with the issuer down: %v %d %v", ok, fetches.Load(), remote.LastError())
	}
	status = http.StatusOK
	now = now.Add(RemoteMinRefresh)
	if _, ok := remote.Lookup("nope"); ok || remote.LastError() != nil {
		t.Fatalf("unknown kid after recovery: %v %v", ok, remote.LastError())
	}

	// A Verifier uses Lookup for a kid its Keys lack, and nothing else.
	tok, err := sign(k2, map[string]any{claimSubject: "u", claimExpires: now.Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	v := Verifier{Lookup: remote.Lookup, Now: func() time.Time { return now }}
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("verify through remote keys: %v", err)
	}
	if _, err := (Verifier{Now: v.Now}).Verify(tok); !errors.Is(err, ErrInvalid) {
		t.Fatalf("verify with no keys and no lookup: %v", err)
	}
	// A lookup that hands back a malformed key is refused.
	bad := Verifier{Lookup: func(string) (crypto.PublicKey, bool) { return ed25519.PublicKey("short"), true }, Now: v.Now}
	if _, err := bad.Verify(tok); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed key from lookup: %v", err)
	}

	// Unreachable, not JSON, and a nil client with the default timeout.
	down := NewRemoteKeys("http://127.0.0.1:1/jwks", nil)
	if _, ok := down.Lookup(kid1); ok || !errors.Is(down.LastError(), ErrRemoteKeys) {
		t.Fatalf("unreachable issuer: %v %v", ok, down.LastError())
	}
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }))
	defer page.Close()
	html := NewRemoteKeys(page.URL, page.Client())
	if _, ok := html.Lookup(kid1); ok || !errors.Is(html.LastError(), ErrRemoteKeys) {
		t.Fatalf("html answer: %v %v", ok, html.LastError())
	}
	// A response cut short is a read error, not a key set.
	short := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("{"))
	}))
	defer short.Close()
	cut := NewRemoteKeys(short.URL, short.Client())
	if _, ok := cut.Lookup(kid1); ok || !errors.Is(cut.LastError(), ErrRemoteKeys) {
		t.Fatalf("truncated answer: %v %v", ok, cut.LastError())
	}
	broken := NewRemoteKeys("://bad", nil)
	if _, ok := broken.Lookup(kid1); ok || !errors.Is(broken.LastError(), ErrRemoteKeys) {
		t.Fatalf("bad url: %v %v", ok, broken.LastError())
	}
}
