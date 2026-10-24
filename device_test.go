package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// listener is a sign-in method that hears credential changes.
type listener struct {
	name  string
	heard []string
	err   error
}

func (l *listener) Name() string { return l.name }
func (*listener) SignsIn() bool  { return true }

func (l *listener) CredentialChanged(_ context.Context, userID string) error {
	l.heard = append(l.heard, userID)
	return l.err
}

func TestCredentialChanged_ReachesEveryListenerInOrder(t *testing.T) {
	first := &listener{name: "first"}
	second := &listener{name: "second"}
	a, err := newAuth(auth.WithPlugins(first, basic("plain"), second))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.CredentialChanged(context.Background(), "usr_1"); err != nil {
		t.Fatal(err)
	}
	if len(first.heard) != 1 || first.heard[0] != "usr_1" || len(second.heard) != 1 {
		t.Fatalf("heard: first=%v second=%v", first.heard, second.heard)
	}
	// The first error stops the chain.
	first.err = errors.New("no")
	if err := a.CredentialChanged(context.Background(), "usr_2"); !errors.Is(err, first.err) {
		t.Fatalf("got %v, want the listener's error", err)
	}
	if len(second.heard) != 1 {
		t.Fatalf("the second listener ran after the first failed: %v", second.heard)
	}
}

func TestRequestDevice_ReadsTheRequestsDeviceToken(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(basic("s")))
	if err != nil {
		t.Fatal(err)
	}
	if tok := auth.RequestDevice(context.Background()); tok != "" {
		t.Fatalf("outside a request: %q", tok.Reveal())
	}
	ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP})
	if tok := auth.RequestDevice(ctx); tok != "" {
		t.Fatalf("a request without a device: %q", tok.Reveal())
	}
	ctx = a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Device: "dev-1"})
	if tok := auth.RequestDevice(ctx); tok != "dev-1" {
		t.Fatalf("got %q, want the device token", tok.Reveal())
	}
}

func TestEffects_RememberDevice(t *testing.T) {
	var e auth.Effects
	at := time.Now().Add(time.Hour)
	e.RememberDevice("dev-1", at)
	e.RememberDevice("", time.Time{})
	list := e.List()
	if len(list) != 2 || list[0].Kind != auth.EffectRememberDevice || list[0].Token != "dev-1" || !list[0].ExpiresAt.Equal(at) || list[1].Token != "" {
		t.Fatalf("effects = %+v", list)
	}
	found := false
	for _, k := range auth.EffectKindValues {
		found = found || k == auth.EffectRememberDevice
	}
	if !found {
		t.Fatal("EffectKindValues must list EffectRememberDevice")
	}
}
