package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Self-service account deletion: what New settles without a database. The
// behaviour on a database is in the integration suite (r2_core_test.go).

func TestNew_AccountDeletionByLinkNeedsALink(t *testing.T) {
	_, err := auth.New(auth.WithPlugins(basic("s")), auth.WithAccountDeletion(auth.AccountDeletion{ConfirmByLink: true}))
	if !errors.Is(err, auth.ErrDeleteAccountNeedsLink) {
		t.Fatalf("no base URL and no Link: %v, want ErrDeleteAccountNeedsLink", err)
	}
	if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithAccountDeletion(auth.AccountDeletion{ConfirmByLink: true})); err != nil {
		t.Fatalf("with a base URL: %v", err)
	}
	link := func(auth.Token) string { return "https://x" }
	if _, err := auth.New(auth.WithPlugins(basic("s")), auth.WithAccountDeletion(auth.AccountDeletion{ConfirmByLink: true, Link: link})); err != nil {
		t.Fatalf("with a Link and no base URL: %v", err)
	}
	// Without ConfirmByLink nothing is sent, so no link is needed.
	if _, err := auth.New(auth.WithPlugins(basic("s")), auth.WithAccountDeletion(auth.AccountDeletion{LinkTTL: time.Minute})); err != nil {
		t.Fatalf("delete at once needs no link: %v", err)
	}
}

func TestNew_AccountDeletionIsOptIn(t *testing.T) {
	off, err := newAuth(auth.WithPlugins(basic("s")))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []auth.EndpointID{auth.EndpointDeleteAccount, auth.EndpointConfirmDeleteAccount} {
		if _, ok := off.Operation(id); ok {
			t.Errorf("%s is served without WithAccountDeletion", id)
		}
	}
	if _, err := off.DeleteAccount(context.Background()); !errors.Is(err, auth.ErrAccountDeletionOff) {
		t.Fatalf("DeleteAccount when off: %v, want ErrAccountDeletionOff", err)
	}
	if err := off.ConfirmDeleteAccount(context.Background(), "x"); !errors.Is(err, auth.ErrAccountDeletionOff) {
		t.Fatalf("ConfirmDeleteAccount when off: %v, want ErrAccountDeletionOff", err)
	}

	a, err := newAuth(auth.WithPlugins(basic("s")), auth.WithAccountDeletion(auth.AccountDeletion{}))
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[auth.EndpointID]struct {
		route   string
		require auth.Requirement
	}{
		auth.EndpointDeleteAccount:        {"/account/delete", auth.FreshSignIn},
		auth.EndpointConfirmDeleteAccount: {"/account/delete/confirm", auth.Public},
	} {
		op, ok := a.Operation(id)
		if !ok || op.Route() != want.route || op.Info().Require != want.require || op.Info().Kind != auth.Mutation {
			t.Errorf("%s: ok=%v route=%q require=%q", id, ok, op.Route(), op.Info().Require)
		}
	}
	// A disabled deletion is answered like an unknown operation, from Go too.
	disabled, err := newAuth(auth.WithPlugins(basic("s")), auth.WithAccountDeletion(auth.AccountDeletion{}), auth.WithDisabledOperations(auth.EndpointDeleteAccount))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := disabled.DeleteAccount(context.Background()); !errors.Is(err, auth.ErrUnknownOperation) {
		t.Fatalf("disabled DeleteAccount: %v, want ErrUnknownOperation", err)
	}
}

func TestDeleteAccount_NeedsAFreshSession(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(basic("s")), auth.WithAccountDeletion(auth.AccountDeletion{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.DeleteAccount(context.Background()); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("signed out: %v, want ErrSignedOut", err)
	}
	if err := a.ConfirmDeleteAccount(context.Background(), "nope"); !errors.Is(err, auth.ErrNoDatabase) {
		// Public, so the pipeline lets it through to the token lookup, which
		// needs the database this instance has none of.
		t.Fatalf("confirm without a database: %v, want ErrNoDatabase", err)
	}
}

func TestWithOperationHooks_RefusesAnUnknownTarget(t *testing.T) {
	_, err := newAuth(auth.WithPlugins(basic("s")), auth.WithOperationHooks(auth.OperationHook{Match: []auth.EndpointID{"nope.missing"}}))
	if !errors.Is(err, auth.ErrUnknownHookTarget) || !strings.Contains(err.Error(), "WithOperationHooks") {
		t.Fatalf("got %v, want ErrUnknownHookTarget naming WithOperationHooks", err)
	}
	// A hook on a disabled operation is kept, like a plugin's.
	if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithAccountDeletion(auth.AccountDeletion{}), auth.WithDisabledOperations(auth.EndpointDeleteAccount),
		auth.WithOperationHooks(auth.OperationHook{Match: []auth.EndpointID{auth.EndpointDeleteAccount}})); err != nil {
		t.Fatalf("hook on a disabled operation: %v", err)
	}
}

func TestWithOperationHooks_RunLikeAPluginsHooks(t *testing.T) {
	refused := errors.New("not today")
	var seen []auth.EndpointID
	a, err := newAuth(auth.WithPlugins(basic("s")), auth.WithAccountDeletion(auth.AccountDeletion{}), auth.WithOperationHooks(
		auth.OperationHook{Before: func(_ context.Context, c *auth.Call) error { seen = append(seen, c.Op.ID); return nil }},
		auth.OperationHook{Match: []auth.EndpointID{auth.EndpointConfirmDeleteAccount}, Before: func(context.Context, *auth.Call) error { return refused }},
	))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.ConfirmDeleteAccount(context.Background(), "x"); !errors.Is(err, refused) {
		t.Fatalf("the app's Before hook must refuse the call: %v", err)
	}
	if len(seen) != 1 || seen[0] != auth.EndpointConfirmDeleteAccount {
		t.Fatalf("the unmatched hook sees every call: %v", seen)
	}
}

func TestWithDataHooks_AreWiredAfterThePlugins(t *testing.T) {
	// Without a database the hooks never run; what New must do is accept
	// them and keep the configuration. The run order is proven on a database
	// in the integration suite.
	h := auth.DataHooks{User: auth.TableHooks[auth.User]{BeforeDelete: func(context.Context, sqlb.DBTX, *auth.User) error { return nil }}}
	if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithDataHooks(h, h)); err != nil {
		t.Fatal(err)
	}
}
