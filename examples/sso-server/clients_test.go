package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ubgo/auth/plugin/oauthprovider"
)

// signedOutURI is where the wiki wants the browser after sign-out.
const signedOutURI = "https://wiki.example.com/signed-out"

// newProvider is the server of main.go on a fresh database, without HTTP:
// the client administration runs from Go.
func newProvider(t *testing.T) *oauthprovider.Plugin {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, op, err := newAuth(db, []byte(testSecret), key, fakeGoogle{email: "bob@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); db.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return op
}

// enableSignOut adds the sign-out URI and switches end-session on, and
// keeps every other field: the redirect URI and the skipped consent.
//
//ds:def id=testssoserver-enablesignoutkeepstherest-5q8mx2kw owner=@khanakia stability=stable
func TestSSOServer_EnableSignOutKeepsTheRest(t *testing.T) {
	ctx := context.Background()
	op := newProvider(t)
	if _, err := op.CreateClient(ctx, oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{Name: "wiki", RedirectURIs: []string{appRedirect}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := op.CreateClient(ctx, oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "ops", RedirectURIs: []string{"https://ops.example.com/callback"}}}); err != nil {
		t.Fatal(err)
	}
	got, err := enableSignOut(ctx, op, "wiki", signedOutURI)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := op.Client(ctx, got.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(stored.PostLogoutRedirectURIs, []string{signedOutURI}) || !stored.EndSession {
		t.Fatalf("sign-out not set: %v end-session=%v", stored.PostLogoutRedirectURIs, stored.EndSession)
	}
	if !slices.Equal(stored.RedirectURIs, []string{appRedirect}) || !stored.SkipConsent || stored.Name != "wiki" {
		t.Fatalf("other fields changed: %+v", stored)
	}
	ops, err := clientByName(ctx, op, "ops")
	if err != nil || ops.EndSession || len(ops.PostLogoutRedirectURIs) != 0 {
		t.Fatalf("the other app changed: %+v %v", ops, err)
	}
}

// A name no client has is ErrClientNotFound, and a sign-out URI a
// registration would refuse is refused by the patch too.
//
//ds:def id=testssoserver-enablesignoutrefuses-9w2kn6tz owner=@khanakia stability=stable
func TestSSOServer_EnableSignOutRefuses(t *testing.T) {
	ctx := context.Background()
	op := newProvider(t)
	if _, err := enableSignOut(ctx, op, "nobody", signedOutURI); !errors.Is(err, oauthprovider.ErrClientNotFound) {
		t.Fatalf("unknown app: err = %v, want ErrClientNotFound", err)
	}
	if _, err := op.CreateClient(ctx, oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "wiki", RedirectURIs: []string{appRedirect}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := enableSignOut(ctx, op, "wiki", "javascript:alert(1)"); err == nil {
		t.Fatal("a javascript: sign-out URI was stored")
	}
	stored, err := clientByName(ctx, op, "wiki")
	if err != nil || len(stored.PostLogoutRedirectURIs) != 0 || stored.EndSession {
		t.Fatalf("a refused patch changed the client: %+v %v", stored, err)
	}
}
