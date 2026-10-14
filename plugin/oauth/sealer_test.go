package oauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// fakeKMS is an auth.Sealer standing in for a key service: its sealed form
// carries a key id ("fake:v1:"), binds aad, and its errors are settable.
type fakeKMS struct {
	id      string
	sealErr error
	// sealErrAfter, when positive, lets that many seals succeed and fails
	// every later one with sealErr, so a test can fail a write midway.
	sealErrAfter int
	openErr      error
	sealed       int
	openings     int
}

func (k *fakeKMS) Seal(_ context.Context, plain []byte, aad string) (string, error) {
	if k.sealErr != nil && k.sealed >= k.sealErrAfter {
		return "", k.sealErr
	}
	k.sealed++
	return "fake:" + k.id + ":" + base64.RawStdEncoding.EncodeToString([]byte(aad+"\x00"+string(plain))), nil
}

func (k *fakeKMS) Open(_ context.Context, sealed, aad string) ([]byte, error) {
	if k.openErr != nil {
		return nil, k.openErr
	}
	k.openings++
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(sealed, "fake:"+k.id+":"))
	gotAAD, plain, ok := strings.Cut(string(raw), "\x00")
	if err != nil || !ok || gotAAD != aad {
		return nil, auth.ErrSealedCorrupt
	}
	return []byte(plain), nil
}

// wireTokens builds the plugin with opt and the core with opts, failing the
// test when auth.New refuses.
func wireTokens(t *testing.T, opt Option, opts ...auth.Option) *Plugin {
	t.Helper()
	p := New(WithProviders(Google("a", "b")), opt)
	if _, err := auth.New(append(opts, auth.WithBaseURL("https://a.example"), auth.WithPlugins(p))...); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestStoreTokens_SealerPrecedence: a StoreTokens key beats every Sealer,
// StoreTokensWith beats auth.WithSealer, and auth.WithSealer beats the keys
// derived from the app secret; each winner both seals and opens.
func TestStoreTokens_SealerPrecedence(t *testing.T) {
	ctx := context.Background()
	secret := bytes.Repeat([]byte("s"), auth.MinSecretSize)
	key := bytes.Repeat([]byte("k"), auth.SealKeySize)

	app, own := &fakeKMS{id: "app"}, &fakeKMS{id: "own"}
	p := wireTokens(t, StoreTokens(), auth.WithSecret(secret), auth.WithSealer(app))
	sealed, err := p.seal(ctx, "at", "acc_1")
	if err != nil || !strings.HasPrefix(sealed, "fake:app:") {
		t.Fatalf("WithSealer must seal over the secret: %q %v", sealed, err)
	}
	if got, err := p.open(ctx, sealed, "acc_1"); err != nil || got.Reveal() != "at" || app.openings != 1 {
		t.Fatalf("WithSealer must open: %q %v", got.Reveal(), err)
	}
	if _, err := p.open(ctx, sealed, "acc_2"); !errors.Is(err, auth.ErrSealedCorrupt) {
		t.Fatalf("a token copied to another account opened: %v", err)
	}

	p = wireTokens(t, StoreTokensWith(own), auth.WithSealer(app))
	if sealed, err = p.seal(ctx, "at", "acc_1"); err != nil || !strings.HasPrefix(sealed, "fake:own:") {
		t.Fatalf("StoreTokensWith must win over WithSealer: %q %v", sealed, err)
	}

	p = wireTokens(t, StoreTokens(key), auth.WithSealer(app))
	if sealed, err = p.seal(ctx, "at", "acc_1"); err != nil {
		t.Fatal(err)
	}
	if got, err := auth.Open(key, sealed, "acc_1"); err != nil || string(got) != "at" {
		t.Fatalf("an explicit key must win over every Sealer: %v", err)
	}

	// A Sealer alone is enough: no key and no secret is not ErrBadTokenKey.
	wireTokens(t, StoreTokensWith(own))
	wireTokens(t, StoreTokens(), auth.WithSealer(app))
}

// TestStoreTokens_SealerErrorsFailClosed: a key service that cannot seal
// fails the write, and one that cannot open is reported, never read as an
// empty token.
func TestStoreTokens_SealerErrorsFailClosed(t *testing.T) {
	ctx := context.Background()
	down := errors.New("kms unreachable")
	p := wireTokens(t, StoreTokensWith(&fakeKMS{id: "x", sealErr: down}))
	if err := p.storeTokens(ctx, "acc_1", TokenSet{AccessToken: "at"}); !errors.Is(err, down) {
		t.Fatalf("storeTokens with a failing sealer = %v, want its error", err)
	}
	p = wireTokens(t, StoreTokensWith(&fakeKMS{id: "x", openErr: down}))
	if got, err := p.open(ctx, "fake:x:anything", "acc_1"); !errors.Is(err, down) || got != "" {
		t.Fatalf("open with a failing sealer = %q, %v", got.Reveal(), err)
	}
}

// TestStoreTokens_SealerFailingMidwayWritesNothing: a key service that fails
// on the refresh token, the ID token or the refresh parameters (after the
// earlier values sealed) fails the whole write with its error, whichever
// value it failed on.
func TestStoreTokens_SealerFailingMidwayWritesNothing(t *testing.T) {
	ctx := context.Background()
	down := errors.New("kms unreachable")
	ts := TokenSet{AccessToken: "at", RefreshToken: "rt", IDToken: "it", RefreshParams: url.Values{"device_id": {"d"}}}
	for after := 1; after <= 3; after++ {
		p := wireTokens(t, StoreTokensWith(&fakeKMS{id: "x", sealErr: down, sealErrAfter: after}))
		if err := p.storeTokens(ctx, "acc_1", ts); !errors.Is(err, down) {
			t.Errorf("sealer failing after %d seals: storeTokens = %v, want its error", after, err)
		}
	}
}
