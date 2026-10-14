package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
)

// Multi-session wiring, without a database; the behaviour is proven in the
// integration suite (r2_core_test.go).

func TestWithMultiSession_WiresTheOperationsOnlyWhenOn(t *testing.T) {
	off, err := newAuth(auth.WithPlugins(basic("s")))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []auth.EndpointID{auth.EndpointDeviceSessions, auth.EndpointSwitchDeviceSession, auth.EndpointRevokeDeviceSession} {
		if _, ok := off.Operation(id); ok {
			t.Errorf("%s is served without WithMultiSession", id)
		}
	}
	if cfg := off.Config().MultiSession; cfg.Enabled || cfg.Max != 0 {
		t.Fatalf("default MultiSession = %+v", cfg)
	}
	if _, err := off.DeviceSessions(context.Background()); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("DeviceSessions when off: %v, want ErrOperationNotWired", err)
	}

	on, err := newAuth(auth.WithPlugins(basic("s")), auth.WithMultiSession(0))
	if err != nil {
		t.Fatal(err)
	}
	if cfg := on.Config().MultiSession; !cfg.Enabled || cfg.Max != auth.DefaultMaxDeviceSessions {
		t.Fatalf("MultiSession(0) = %+v, want the default maximum", cfg)
	}
	for id, route := range map[auth.EndpointID]string{
		auth.EndpointDeviceSessions:      "/device-sessions",
		auth.EndpointSwitchDeviceSession: "/device-sessions/switch",
		auth.EndpointRevokeDeviceSession: "/device-sessions/revoke",
	} {
		op, ok := on.Operation(id)
		if !ok || op.Route() != route || op.Info().Require != auth.SignedIn {
			t.Errorf("%s: ok=%v route=%q require=%q", id, ok, op.Route(), op.Info().Require)
		}
	}
	if _, err := on.DeviceSessions(context.Background()); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("DeviceSessions signed out: %v, want ErrSignedOut", err)
	}
	if err := on.SwitchDeviceSession(context.Background(), "x"); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("Switch signed out: %v", err)
	}
	if err := on.RevokeDeviceSession(context.Background(), "x"); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("Revoke signed out: %v", err)
	}
}

func TestNew_RefusesANegativeDeviceMaximum(t *testing.T) {
	if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithMultiSession(-1)); !errors.Is(err, auth.ErrBadOperation) {
		t.Fatalf("got %v, want ErrBadOperation", err)
	}
	if a, err := newAuth(auth.WithPlugins(basic("s")), auth.WithMultiSession(2)); err != nil || a.Config().MultiSession.Max != 2 {
		t.Fatalf("max 2: %v %+v", err, a.Config().MultiSession)
	}
}

func TestEffects_ForgetDeviceSessionIsAKind(t *testing.T) {
	var e auth.Effects
	e.ForgetDeviceSession("t1")
	list := e.List()
	if len(list) != 1 || list[0].Kind != auth.EffectForgetDeviceSession || list[0].Token != "t1" {
		t.Fatalf("effects = %+v", list)
	}
	found := false
	for _, k := range auth.EffectKindValues {
		found = found || k == auth.EffectForgetDeviceSession
	}
	if !found {
		t.Fatal("EffectKindValues must list the new kind, so transports learn it")
	}
}

func TestWithDeferredSessionRefresh_WiresTheRefreshRouteOnlyWhenOn(t *testing.T) {
	off, err := newAuth(auth.WithPlugins(basic("s")))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := off.Operation(auth.EndpointRefreshSession); ok {
		t.Fatal("/session/refresh is served without WithDeferredSessionRefresh")
	}
	if _, err := off.RefreshSession(context.Background()); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("RefreshSession when off: %v", err)
	}
	on, err := newAuth(auth.WithPlugins(basic("s")), auth.WithDeferredSessionRefresh())
	if err != nil {
		t.Fatal(err)
	}
	op, ok := on.Operation(auth.EndpointRefreshSession)
	if !ok || op.Route() != "/session/refresh" || op.Info().Kind != auth.Mutation || op.Info().Require != auth.SignedIn {
		t.Fatalf("refresh op: ok=%v %+v", ok, op.Info())
	}
	if _, err := on.RefreshSession(context.Background()); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("RefreshSession signed out: %v", err)
	}
}

func TestWithSessionArchive_NeedsTheSQLStore(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(basic("s")), auth.WithSessionArchive())
	if err != nil {
		t.Fatalf("with the default store: %v", err)
	}
	if _, err := a.RevokedSessions(context.Background(), "usr_1"); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("RevokedSessions without a database: %v", err)
	}
	if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithSessionArchive(), auth.WithSessionStore(auth.NewMemorySessionStore())); !errors.Is(err, auth.ErrBadOperation) {
		t.Fatalf("with a memory store: %v, want ErrBadOperation", err)
	}
	if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithSessionArchive(), auth.WithStatelessSessions(key(1))); !errors.Is(err, auth.ErrBadOperation) {
		t.Fatalf("stateless: %v, want ErrBadOperation", err)
	}
}
