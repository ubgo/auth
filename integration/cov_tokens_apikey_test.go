package integration

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/password"
)

func intp(n int) *int { return &n }

// tokensUse resolves raw as a key and returns the resolution error, so a
// limit's refusal is observable in one line.
func tokensUse(a *auth.Auth, raw string) error { return a.Resolve(tokensBearer(a, raw)) }

func TestTokensAPIKey_Update(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak := apikey.New(apikey.Scopes("s"), apikey.AllowMetadata(), apikey.WithExpiry(apikey.Expiry{MaxDays: 365}))
		a := e.newAuth(t, nil, em, pw, ak)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		made := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "k", ExpiresInDays: 10, Metadata: json.RawMessage(`{"env":"dev"}`)}))
		if string(made.Key.Metadata) != `{"env":"dev"}` || made.Key.Disabled || !made.Key.Limits.None() {
			t.Fatalf("created = %+v", made.Key)
		}

		// Nothing to update, and an unknown or foreign id, are refused.
		if _, err := ak.Update(ctx, apikey.UpdateRequest{ID: made.Key.ID}); !errors.Is(err, apikey.ErrNoChanges) {
			t.Fatalf("empty update: %v", err)
		}
		name := "renamed"
		if _, err := ak.Update(ctx, apikey.UpdateRequest{ID: "key_nope", Name: &name}); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("unknown id: %v", err)
		}
		other := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret}))
		if _, err := ak.Update(request(a, other.Token), apikey.UpdateRequest{ID: made.Key.ID, Name: &name}); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("another user's key: %v", err)
		}

		// Rename, re-expire, pause, resume, and replace the metadata.
		e.clock.Advance(time.Second)
		k := must[apikey.Key](t)(ak.Update(ctx, apikey.UpdateRequest{ID: made.Key.ID, Name: &name, ExpiresInDays: intp(30), Metadata: json.RawMessage(`{"env":"prod"}`)}))
		if k.Name != "renamed" || !k.ExpiresAt.Equal(e.clock.Now().Add(30*24*time.Hour)) || string(k.Metadata) != `{"env":"prod"}` {
			t.Fatalf("updated = %+v", k)
		}
		if _, err := ak.Update(ctx, apikey.UpdateRequest{ID: made.Key.ID, ExpiresInDays: intp(0)}); !errors.Is(err, apikey.ErrExpiryOutOfRange) {
			t.Fatalf("never under a maximum: %v", err)
		}
		if _, err := ak.Update(ctx, apikey.UpdateRequest{ID: made.Key.ID, Metadata: json.RawMessage(`[1]`)}); !errors.Is(err, apikey.ErrBadMetadata) {
			t.Fatalf("array metadata: %v", err)
		}
		tokensMust(t, tokensUse(a, made.Secret))
		paused := must[apikey.Key](t)(ak.Update(ctx, apikey.UpdateRequest{ID: made.Key.ID, Disabled: boolp(true)}))
		if !paused.Disabled {
			t.Fatal("not disabled")
		}
		gone := tokensBearer(a, made.Secret)
		tokensMust(t, a.Resolve(gone))
		if _, ok := auth.CurrentUser(gone); ok {
			t.Fatal("a disabled key still signs in")
		}
		resumed := must[apikey.Key](t)(ak.Update(ctx, apikey.UpdateRequest{ID: made.Key.ID, Disabled: boolp(false)}))
		back := tokensBearer(a, made.Secret)
		tokensMust(t, a.Resolve(back))
		if _, ok := auth.CurrentUser(back); !ok || resumed.Disabled {
			t.Fatal("a resumed key does not sign in")
		}
		// The list shows the same view update returned.
		keys := must[[]apikey.Key](t)(ak.List(ctx))
		if len(keys) != 1 || keys[0].Name != "renamed" || string(keys[0].Metadata) != `{"env":"prod"}` || keys[0].Disabled {
			t.Fatalf("list = %+v", keys)
		}

		// Without AllowMetadata, metadata is refused on create and update;
		// RequireName applies to a rename.
		strict := apikey.New(apikey.Scopes("s"), apikey.RequireName())
		a2 := e.newAuth(t, nil, em, pw, strict)
		ctx2 := request(a2, up.Token)
		if _, err := strict.Create(ctx2, apikey.CreateRequest{Name: "m", Metadata: json.RawMessage(`{}`)}); !errors.Is(err, apikey.ErrMetadataDisabled) {
			t.Fatalf("metadata while disabled: %v", err)
		}
		blank := " "
		if _, err := strict.Update(ctx2, apikey.UpdateRequest{ID: made.Key.ID, Name: &blank}); !errors.Is(err, apikey.ErrNameRequired) {
			t.Fatalf("blank rename under RequireName: %v", err)
		}
	})
}

func boolp(b bool) *bool { return &b }

func TestTokensAPIKey_RateLimitAndQuota(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak := apikey.New(apikey.Scopes("s"), apikey.DefaultLimits(apikey.Limits{RateMax: 3, RateWindow: time.Minute}))
		a := e.newAuth(t, nil, em, pw, ak)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)

		// The default limits apply to keys made through the operation: three
		// requests pass, the fourth is refused, and the window reopens.
		made := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "k"}))
		if made.Key.Limits.RateMax != 3 || made.Key.Limits.RateWindow != time.Minute {
			t.Fatalf("limits = %+v", made.Key.Limits)
		}
		for i := 0; i < 3; i++ {
			tokensMust(t, tokensUse(a, made.Secret))
		}
		if err := tokensUse(a, made.Secret); !errors.Is(err, auth.ErrRateLimited) {
			t.Fatalf("fourth request in the window: %v", err)
		}
		e.clock.Advance(time.Minute)
		tokensMust(t, tokensUse(a, made.Secret))

		// A quota goes down with every use and refuses at zero; a refill
		// resets it once the interval has passed since creation.
		quota := must[apikey.CreateResult](t)(ak.CreateFor(context.Background(), up.User.ID, apikey.CreateRequest{Name: "q"},
			apikey.Limits{Remaining: intp(2), RefillAmount: 2, RefillInterval: time.Hour}))
		tokensMust(t, tokensUse(a, quota.Secret))
		tokensMust(t, tokensUse(a, quota.Secret))
		if err := tokensUse(a, quota.Secret); !errors.Is(err, apikey.ErrUsageExceeded) {
			t.Fatalf("third use of a two-use key: %v", err)
		}
		keys := must[[]apikey.Key](t)(ak.List(ctx))
		if r := keys[1].Limits.Remaining; r == nil || *r != 0 {
			t.Fatalf("remaining after exhaustion = %v", r)
		}
		e.clock.Advance(time.Hour)
		tokensMust(t, tokensUse(a, quota.Secret)) // the refill spends one
		tokensMust(t, tokensUse(a, quota.Secret))
		if err := tokensUse(a, quota.Secret); !errors.Is(err, apikey.ErrUsageExceeded) {
			t.Fatalf("after spending the refill: %v", err)
		}
		// The second refill is measured from the first, not from creation.
		e.clock.Advance(time.Hour)
		tokensMust(t, tokensUse(a, quota.Secret))
		keys = must[[]apikey.Key](t)(ak.List(ctx))
		if r := keys[1].Limits.Remaining; r == nil || *r != 1 {
			t.Fatalf("remaining after the second refill = %v", r)
		}
		// A key without a refill just runs out.
		once := must[apikey.CreateResult](t)(ak.CreateFor(context.Background(), up.User.ID, apikey.CreateRequest{Name: "once"}, apikey.Limits{Remaining: intp(1)}))
		tokensMust(t, tokensUse(a, once.Secret))
		e.clock.Advance(24 * time.Hour)
		if err := tokensUse(a, once.Secret); !errors.Is(err, apikey.ErrUsageExceeded) {
			t.Fatalf("a non-refilling key: %v", err)
		}

		// SetLimits replaces the limits and resets the counters.
		if err := ak.SetLimits(context.Background(), "key_nope", apikey.Limits{}); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("set limits on an unknown key: %v", err)
		}
		if err := ak.SetLimits(context.Background(), once.Key.ID, apikey.Limits{RateMax: 1}); !errors.Is(err, apikey.ErrBadLimitsValue) {
			t.Fatalf("unpaired limits: %v", err)
		}
		tokensMust(t, ak.SetLimits(context.Background(), once.Key.ID, apikey.Limits{Remaining: intp(1), RateMax: 1, RateWindow: time.Minute}))
		tokensMust(t, tokensUse(a, once.Secret))
		if err := tokensUse(a, once.Secret); !errors.Is(err, auth.ErrRateLimited) {
			t.Fatalf("after new limits, second request in the window: %v", err)
		}
		tokensMust(t, ak.SetLimits(context.Background(), once.Key.ID, apikey.Limits{}))
		for i := 0; i < 5; i++ {
			tokensMust(t, tokensUse(a, once.Secret))
		}

		// CreateFor checks its inputs like create does.
		if _, err := ak.CreateFor(context.Background(), up.User.ID, apikey.CreateRequest{Name: "x"}, apikey.Limits{RefillAmount: 1}); !errors.Is(err, apikey.ErrBadLimitsValue) {
			t.Fatalf("create for with unpaired limits: %v", err)
		}
		if _, err := ak.CreateFor(context.Background(), "usr_nobody", apikey.CreateRequest{Name: "x"}, apikey.Limits{}); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("create for an unknown user: %v", err)
		}
		if _, err := ak.CreateFor(context.Background(), up.User.ID, apikey.CreateRequest{Name: "x", Scopes: []string{"nope"}}, apikey.Limits{}); !errors.Is(err, apikey.ErrUnknownScope) {
			t.Fatalf("create for with an unknown scope: %v", err)
		}
		// Metadata is accepted from Go without AllowMetadata.
		withMeta := must[apikey.CreateResult](t)(ak.CreateFor(context.Background(), up.User.ID, apikey.CreateRequest{Name: "m", Metadata: json.RawMessage(`{"plan":"pro"}`)}, apikey.Limits{}))
		if string(withMeta.Key.Metadata) != `{"plan":"pro"}` {
			t.Fatalf("metadata = %s", withMeta.Key.Metadata)
		}
	})
}

// TestTokensAPIKey_LimitsHoldUnderConcurrency: the guarded writes never let
// a burst exceed RateMax or drive Remaining below zero.
func TestTokensAPIKey_LimitsHoldUnderConcurrency(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		if e.engine == auth.EngineSQLite {
			t.Skip("one writer at a time; concurrency is exercised on Postgres and MySQL")
		}
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak := apikey.New(apikey.Scopes("s"))
		a := e.newAuth(t, nil, em, pw, ak)
		up := signUpVerified(t, e, a, pw, em)
		made := must[apikey.CreateResult](t)(ak.CreateFor(context.Background(), up.User.ID, apikey.CreateRequest{Name: "k"},
			apikey.Limits{RateMax: 5, RateWindow: time.Minute, Remaining: intp(7)}))
		var wg sync.WaitGroup
		var mu sync.Mutex
		passed, limited := 0, 0
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := tokensUse(a, made.Secret)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					passed++
				case errors.Is(err, auth.ErrRateLimited):
					limited++
				default:
					t.Errorf("unexpected: %v", err)
				}
			}()
		}
		wg.Wait()
		if passed != 5 || limited != 15 {
			t.Fatalf("passed %d limited %d", passed, limited)
		}
		keys := must[[]apikey.Key](t)(ak.List(request(a, up.Token)))
		if r := keys[0].Limits.Remaining; r == nil || *r != 2 {
			t.Fatalf("remaining = %v, want 7 minus the 5 that passed", r)
		}
	})
}

func TestTokensAPIKey_LimitFaults(t *testing.T) {
	limited := func(l apikey.Limits, advance time.Duration, prime int) func(t *testing.T, e *faultEnv) func(context.Context) error {
		return func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw := e.emailPlugin(), e.passwordPlugin()
			ak := apikey.New(apikey.Scopes("s"))
			a := e.newAuth(t, nil, em, pw, ak)
			up := signUpVerified(t, e.env, a, pw, em)
			made := must[apikey.CreateResult](t)(ak.CreateFor(context.Background(), up.User.ID, apikey.CreateRequest{Name: "k"}, l))
			for i := 0; i < prime; i++ {
				tokensMust(t, tokensUse(a, made.Secret))
			}
			e.clock.Advance(advance)
			return func(context.Context) error { return tokensUse(a, made.Secret) }
		}
	}
	// recordUse is the one swallowed write; its step moves as the counter
	// writes come before it.
	t.Run("rate window starts", func(t *testing.T) {
		sweepFaults(t, limited(apikey.Limits{RateMax: 5, RateWindow: time.Minute}, 0, 0), 3)
	})
	t.Run("rate window increments", func(t *testing.T) {
		sweepFaults(t, limited(apikey.Limits{RateMax: 5, RateWindow: time.Minute}, 0, 1), 3)
	})
	t.Run("rate window resets", func(t *testing.T) {
		sweepFaults(t, limited(apikey.Limits{RateMax: 5, RateWindow: time.Minute}, time.Minute, 1), 3)
	})
	t.Run("quota decrements", func(t *testing.T) {
		sweepFaults(t, limited(apikey.Limits{Remaining: intp(5)}, 0, 0), 3)
	})
	t.Run("quota refills", func(t *testing.T) {
		sweepFaults(t, limited(apikey.Limits{Remaining: intp(1), RefillAmount: 2, RefillInterval: time.Hour}, time.Hour, 1), 3)
	})
	t.Run("update", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ak, up, made := tokensKeyed(t, e, nil)
			name := "n"
			return func(context.Context) error {
				_, err := ak.Update(request(a, up.Token), apikey.UpdateRequest{ID: made.Key.ID, Name: &name})
				return err
			}
		})
	})
	t.Run("create for", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ak, up, _ := tokensKeyed(t, e, nil)
			_ = a
			return func(ctx context.Context) error {
				_, err := ak.CreateFor(ctx, up.User.ID, apikey.CreateRequest{Name: "k2"}, apikey.Limits{})
				return err
			}
		})
	})
	t.Run("set limits", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			_, ak, _, made := tokensKeyed(t, e, nil)
			return func(ctx context.Context) error {
				return ak.SetLimits(ctx, made.Key.ID, apikey.Limits{Remaining: intp(3)})
			}
		})
	})
}

// TestTokensAPIKey_KeyJSONShape pins the wire form a client sees, so a
// field rename is a deliberate change.
func TestTokensAPIKey_KeyJSONShape(t *testing.T) {
	b, err := json.Marshal(apikey.Key{ID: "key_1", Scopes: []string{}, Limits: apikey.Limits{RateMax: 2, RateWindow: time.Minute}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"disabled":false`, `"metadata":null`, `"limits":{"rateMax":2,"rateWindowSeconds":60,"remaining":null,"refillAmount":0,"refillIntervalSeconds":0}`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("key json %s lacks %s", b, want)
		}
	}
}
