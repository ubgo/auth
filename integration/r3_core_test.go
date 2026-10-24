package integration

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Round 3 of the feature work, the core's remaining rows: the
// app's own user columns, the secret-derived stateless key and translated
// errors, each on a real database.

// appPlan is the app-owned column these tests add to auth_user.
var appPlan = sqlb.Col[string](auth.TableUser, "plan")

// r3Secret is a valid WithSecret value, exactly the minimum.
var r3Secret = bytes.Repeat([]byte("r3"), auth.MinSecretSize/2)

func TestWithUserColumns_WrittenByTheAppAndLoaded(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := coreAuth(t, e, nil, auth.WithUserColumns(auth.ColumnExtension{Name: "plan", Type: auth.ColumnText, Default: "'free'"}))
		ctx := context.Background()
		u, _ := coreUser(t, a)
		var plan string
		if err := a.LoadUserColumns(ctx, u.ID, sqlb.Bind(appPlan, &plan)); err != nil || plan != "free" {
			t.Fatalf("default: %q %v", plan, err)
		}
		if err := auth.SetUserColumn(ctx, a, auth.AppName, u.ID, appPlan, "pro"); err != nil {
			t.Fatal(err)
		}
		if err := a.LoadUserColumns(ctx, u.ID, sqlb.Bind(appPlan, &plan)); err != nil || plan != "pro" {
			t.Fatalf("after SetUserColumn: %q %v", plan, err)
		}
		// Only the app may write its column; a plugin is refused before any
		// statement runs.
		if err := auth.SetUserColumn(ctx, a, coreStubName, u.ID, appPlan, "x"); !errors.Is(err, auth.ErrNotColumnOwner) {
			t.Fatalf("a plugin writing the app's column: %v", err)
		}
		// The migration is in the ledger under the app's name and applying
		// again is a no-op.
		states := must[[]auth.MigrationState](t)(a.MigrationStatus(ctx))
		var found bool
		for _, s := range states {
			if s.Owner == auth.AppName {
				found = found || s.Applied && !s.Changed
			}
		}
		if !found {
			t.Fatalf("the app's column migration is not applied: %+v", states)
		}
	})
	t.Run("faults", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil, auth.WithUserColumns(auth.ColumnExtension{Name: "plan", Type: auth.ColumnText, Default: "'free'"}))
			u, _ := coreUser(t, a)
			return func(ctx context.Context) error { return auth.SetUserColumn(ctx, a, auth.AppName, u.ID, appPlan, "pro") }
		})
	})
}

func TestWithSecret_StatelessSessionsOnADatabase(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		// Two instances of the same deployment: one issues, the other
		// resolves, with no session row and no key but the secret.
		a := coreAuth(t, e, nil, auth.WithSecret(r3Secret), auth.WithStatelessSessions())
		b := coreAuth(t, e, nil, auth.WithSecret(r3Secret), auth.WithStatelessSessions())
		ctx := context.Background()
		u, _ := coreUser(t, a)
		_, tok, err := a.CreateSession(ctx, u.ID, auth.Client{})
		if err != nil {
			t.Fatal(err)
		}
		s, got, _, err := b.ResolveSession(ctx, tok)
		if err != nil || s == nil || got == nil || got.ID != u.ID {
			t.Fatalf("the second instance did not resolve the first's token: %v %v %v", s, got, err)
		}
		// Sign out everywhere still works without a store: the cutoff is on
		// the user row, and refuses every token issued before it.
		e.clock.Advance(time.Second)
		if err := a.DeleteUserSessions(ctx, u.ID, ""); err != nil {
			t.Fatal(err)
		}
		if s, _, _, err := b.ResolveSession(ctx, tok); s != nil || !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("after sign-out everywhere: %v %v, want signed out", s, err)
		}
	})
}

func TestWithMessages_TranslatesARefusalOnTheRequestsLocale(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := coreAuth(t, e, nil, auth.WithMessages(auth.Messages{"de": {"auth.signed_out": "Bitte anmelden."}}))
		ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{Locale: "de-AT"}})
		_, err := a.Session(ctx)
		if !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("Session without a token: %v", err)
		}
		info := auth.ErrorInfoFor(ctx, err)
		if info.Code != auth.ErrSignedOut.Code || info.Message != "Bitte anmelden." {
			t.Fatalf("translated refusal: %+v", info)
		}
		// A real session answers in any language.
		_, tok := coreSignedIn(t, a)
		res, err := a.Session(a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialCookie, Token: tok, Client: auth.Client{Locale: "de"}}))
		if err != nil || res.User.ID == "" {
			t.Fatalf("Session: %+v %v", res, err)
		}
	})
}
