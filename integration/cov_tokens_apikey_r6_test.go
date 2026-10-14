package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
)

// r6Keyed wires an apikey plugin built from opts and signs a verified user
// up, the setup every round-6 test shares.
func r6Keyed(t *testing.T, e *env, opts ...apikey.Option) (*auth.Auth, *apikey.Plugin, password.SignInResult) {
	t.Helper()
	em, pw := e.emailPlugin(), e.passwordPlugin()
	ak := apikey.New(opts...)
	a := e.newAuth(t, nil, em, pw, ak)
	return a, ak, signUpVerified(t, e, a, pw, em)
}

// r6Raw changes a key row behind the plugin's back, as another instance or
// a concurrent request would, through the Auth so a renamed table is found.
func r6Raw(t *testing.T, a *auth.Auth, st auth.Statement) {
	t.Helper()
	if _, err := a.Exec(context.Background(), st); err != nil {
		t.Fatal(err)
	}
}

func r6DeleteRow(t *testing.T, a *auth.Auth, id string) {
	r6Raw(t, a, sqlb.NewDelete(a.Dialect()).From(apikey.TableKey).Where(sqlb.Eq(apikey.KeyID, id)))
}

func r6Exists(t *testing.T, a *auth.Auth, id string) bool {
	t.Helper()
	var n int64
	if err := a.One(context.Background(), a.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(apikey.TableKey).Where(sqlb.Eq(apikey.KeyID, id))); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// TestTokensAPIKey_Configurations: two configurations beside the default
// share the table, each with its own prefix, scopes and limits; requests
// name one with configId; a key of every configuration resolves; VerifyFor
// refuses a key of another configuration before its counters move.
func TestTokensAPIKey_Configurations(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, ak, up := r6Keyed(t, e, apikey.Scopes("read"), apikey.MaxKeys(1),
			apikey.Configuration("live", apikey.Prefix("sk_live_"), apikey.Scopes("write"), apikey.DefaultLimits(apikey.Limits{Remaining: intp(5)})),
			apikey.Configuration("test", apikey.Prefix("sk_test_")))
		ctx := request(a, up.Token)
		def := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "d", Scopes: []string{"read"}}))
		live := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Config: "live", Name: "l", Scopes: []string{"read", "write"}}))
		test := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Config: "test", Name: "t"}))
		if !strings.HasPrefix(def.Secret, apikey.DefaultPrefix) || def.Key.Config != apikey.DefaultConfig || def.Key.Prefix != apikey.DefaultPrefix {
			t.Fatalf("default = %+v", def.Key)
		}
		if !strings.HasPrefix(live.Secret, "sk_live_") || live.Key.Config != "live" || live.Key.Prefix != "sk_live_" || live.Key.Limits.Remaining == nil || *live.Key.Limits.Remaining != 5 {
			t.Fatalf("live = %+v", live.Key)
		}
		if !strings.HasPrefix(test.Secret, "sk_test_") || test.Key.Config != "test" || test.Key.UpdatedAt == nil {
			t.Fatalf("test = %+v", test.Key)
		}
		// Scopes and the cap are per configuration: write exists only on live,
		// and MaxKeys(1) counts each configuration's keys apart.
		if _, err := ak.Create(ctx, apikey.CreateRequest{Config: "test", Scopes: []string{"write"}}); !errors.Is(err, apikey.ErrUnknownScope) {
			t.Fatal("test inherited live's scope")
		}
		if _, err := ak.Create(ctx, apikey.CreateRequest{Name: "d2"}); !errors.Is(err, apikey.ErrTooMany) {
			t.Fatalf("second default key: %v", err)
		}
		if _, err := ak.Create(ctx, apikey.CreateRequest{Config: "nope"}); !errors.Is(err, apikey.ErrUnknownConfig) {
			t.Fatalf("unknown configuration: %v", err)
		}
		if _, err := ak.CreateFor(context.Background(), up.User.ID, apikey.CreateRequest{Config: "nope"}, apikey.Limits{}); !errors.Is(err, apikey.ErrUnknownConfig) {
			t.Fatalf("CreateFor, unknown configuration: %v", err)
		}
		// Every configuration's key resolves through the core.
		for _, k := range []apikey.CreateResult{def, live, test} {
			if s, ok := auth.CurrentSession(tokensResolved(t, a, k.Secret)); !ok || s.APIKeyID != k.Key.ID {
				t.Fatalf("%s key did not resolve", k.Key.Config)
			}
		}
		// List, get, update and revoke scoped by configuration.
		if r := must[apikey.ListResult](t)(ak.ListKeys(ctx, apikey.ListRequest{Config: "live"})); r.Total != 1 || r.Keys[0].ID != live.Key.ID {
			t.Fatalf("live list = %+v", r)
		}
		if r := must[apikey.ListResult](t)(ak.ListKeys(ctx, apikey.ListRequest{})); r.Total != 3 {
			t.Fatalf("whole list = %+v", r)
		}
		if _, err := ak.ListKeys(ctx, apikey.ListRequest{Config: "nope"}); !errors.Is(err, apikey.ErrUnknownConfig) {
			t.Fatalf("list, unknown configuration: %v", err)
		}
		if _, err := tokensInvoke[apikey.Key](ctx, a, apikey.EndpointGet, map[string]string{"id": live.Key.ID, "configId": "test"}); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("get under the wrong configuration: %v", err)
		}
		if got, err := tokensInvoke[apikey.Key](ctx, a, apikey.EndpointGet, map[string]string{"id": live.Key.ID, "configId": "live"}); err != nil || got.Config != "live" {
			t.Fatalf("get under its configuration = %+v %v", got, err)
		}
		// An update follows the key's own configuration: write is a scope of
		// live, so a live key may take it.
		if k, err := ak.Update(ctx, apikey.UpdateRequest{ID: live.Key.ID, Scopes: []string{"write"}}); err != nil || len(k.Scopes) != 1 {
			t.Fatalf("update live = %+v %v", k, err)
		}
		if _, err := ak.Update(ctx, apikey.UpdateRequest{ID: def.Key.ID, Scopes: []string{"write"}}); !errors.Is(err, apikey.ErrUnknownScope) {
			t.Fatalf("update default with live's scope: %v", err)
		}
		if _, err := tokensInvoke[auth.Done](ctx, a, apikey.EndpointRevoke, map[string]string{"id": test.Key.ID, "configId": "live"}); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("revoke under the wrong configuration: %v", err)
		}
		// VerifyFor: the key's configuration passes; another is refused
		// without spending its quota; an unknown one says so.
		bg := context.Background()
		if v := must[apikey.Verification](t)(ak.VerifyFor(bg, "live", live.Secret)); !v.Valid {
			t.Fatalf("live under live = %+v", v)
		}
		left := *must[apikey.Key](t)(ak.Get(ctx, live.Key.ID)).Limits.Remaining
		if v := must[apikey.Verification](t)(ak.VerifyFor(bg, "test", live.Secret)); v.Valid || !errors.Is(v.Reason, auth.ErrSignedOut) {
			t.Fatalf("live under test = %+v", v)
		}
		if now := *must[apikey.Key](t)(ak.Get(ctx, live.Key.ID)).Limits.Remaining; now != left {
			t.Fatalf("a refused VerifyFor spent quota: %d -> %d", left, now)
		}
		if v := must[apikey.Verification](t)(ak.VerifyFor(bg, "", def.Secret)); !v.Valid {
			t.Fatalf("default under \"\" = %+v", v)
		}
		if v := must[apikey.Verification](t)(ak.VerifyFor(bg, "nope", def.Secret)); v.Valid || !errors.Is(v.Reason, apikey.ErrUnknownConfig) {
			t.Fatalf("unknown configuration = %+v", v)
		}
	})
}

// TestTokensAPIKey_KeyPrefixAndDefaultScopes: AllowKeyPrefix puts a
// request's prefix after the configuration's; DefaultScopes fills a create
// without scopes and never an explicit empty list.
func TestTokensAPIKey_KeyPrefixAndDefaultScopes(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, ak, up := r6Keyed(t, e, apikey.Scopes("read", "write"), apikey.DefaultScopes("read"),
			apikey.Configuration("open", apikey.Prefix("op_"), apikey.AllowKeyPrefix(6),
				apikey.DefaultScopesFunc(func(_ context.Context, userID string) []string {
					if userID == "" {
						return []string{"nope"}
					}
					return []string{"write"}
				})))
		ctx := request(a, up.Token)
		k := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Config: "open", Prefix: "acme-1"}))
		if !strings.HasPrefix(k.Secret, "op_acme-1") || k.Key.Prefix != "op_acme-1" || k.Key.Hint != k.Secret[:len("op_acme-1")+4] {
			t.Fatalf("prefixed = %+v %s", k.Key, k.Secret[:12])
		}
		tokensMust(t, tokensUse(a, k.Secret))
		if len(k.Key.Scopes) != 1 || k.Key.Scopes[0] != "write" {
			t.Fatalf("function default scopes = %v", k.Key.Scopes)
		}
		for name, in := range map[string]apikey.CreateRequest{
			"not allowed": {Prefix: "acme"},
			"too long":    {Config: "open", Prefix: "acme-12"},
			"bad char":    {Config: "open", Prefix: "ac.me"},
		} {
			if _, err := ak.Create(ctx, in); !errors.Is(err, apikey.ErrBadKeyPrefix) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		def := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{}))
		if len(def.Key.Scopes) != 1 || def.Key.Scopes[0] != "read" {
			t.Fatalf("default scopes = %v", def.Key.Scopes)
		}
		none := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Scopes: []string{}}))
		if len(none.Key.Scopes) != 0 {
			t.Fatalf("explicit empty list = %v", none.Key.Scopes)
		}
	})
}

// TestTokensAPIKey_PreCheckAndDistinctErrors: PreCheck refuses before the
// lookup; DistinctErrors names each refusal on Verify and on the wire.
func TestTokensAPIKey_PreCheckAndDistinctErrors(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var seen int
		var blocked string
		a, ak, up := r6Keyed(t, e, apikey.Scopes("s"), apikey.DistinctErrors(),
			apikey.PreCheck(func(_ context.Context, key string) bool { seen++; return key != blocked }))
		ctx := request(a, up.Token)
		bg := context.Background()
		paused := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "p"}))
		expiring := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "e", ExpiresInDays: 1}))
		orphan := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "o"}))
		// PreCheck refuses a key that exists and is valid, before its lookup.
		good := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "g"}))
		blocked = good.Secret
		must[apikey.Key](t)(ak.Update(ctx, apikey.UpdateRequest{ID: paused.Key.ID, Disabled: boolp(true)}))
		r6Raw(t, a, sqlb.NewUpdate(a.Dialect()).Table(apikey.TableKey).Set(sqlb.Set(apikey.KeyUserID, "usr_gone")).Where(sqlb.Eq(apikey.KeyID, orphan.Key.ID)))
		e.clock.Advance(25 * time.Hour)
		for name, c := range map[string]struct {
			secret string
			want   error
		}{
			"unknown":   {apikey.DefaultPrefix + strings.Repeat("x", 43), apikey.ErrInvalidKey},
			"precheck":  {good.Secret, apikey.ErrInvalidKey},
			"disabled":  {paused.Secret, apikey.ErrKeyDisabled},
			"expired":   {expiring.Secret, apikey.ErrKeyExpired},
			"no owner":  {orphan.Secret, apikey.ErrKeyOwnerGone},
			"no prefix": {"sk_" + strings.Repeat("x", 43), apikey.ErrInvalidKey},
		} {
			if v := must[apikey.Verification](t)(ak.Verify(bg, c.secret)); v.Valid || !errors.Is(v.Reason, c.want) {
				t.Fatalf("%s = %+v", name, v)
			}
		}
		if seen == 0 {
			t.Fatal("PreCheck never ran")
		}
		// On the wire: each refusal is its own 401 code, even on a route that
		// would serve an anonymous caller.
		app := authhttp.Middleware(a)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		for secret, code := range map[string]string{paused.Secret: "apikey.key_disabled", expiring.Secret: "apikey.key_expired", orphan.Secret: "apikey.invalid_owner"} {
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			req.Header.Set("Authorization", "Bearer "+secret)
			rec := httptest.NewRecorder()
			app.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), code) {
				t.Fatalf("%s: %d %s", code, rec.Code, rec.Body.String())
			}
		}
	})
}

// TestTokensAPIKey_DefaultStaysSilent: without DistinctErrors the same keys
// are all auth.ErrSignedOut, and a refused key on an open route is served as
// anonymous; the default the option must not change.
func TestTokensAPIKey_DefaultStaysSilent(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, ak, up := r6Keyed(t, e, apikey.Scopes("s"))
		ctx := request(a, up.Token)
		paused := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "p"}))
		must[apikey.Key](t)(ak.Update(ctx, apikey.UpdateRequest{ID: paused.Key.ID, Disabled: boolp(true)}))
		if v := must[apikey.Verification](t)(ak.Verify(context.Background(), paused.Secret)); !errors.Is(v.Reason, auth.ErrSignedOut) {
			t.Fatalf("disabled = %+v", v)
		}
		app := authhttp.Middleware(a)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+paused.Secret)
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("open route = %d %s", rec.Code, rec.Body.String())
		}
	})
}

// TestTokensAPIKey_DeleteSpentKeys: an expired key and an exhausted key
// without refill are deleted when presented; a refillable one is kept.
func TestTokensAPIKey_DeleteSpentKeys(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, ak, up := r6Keyed(t, e, apikey.Scopes("s"), apikey.DeleteSpentKeys())
		ctx, bg := request(a, up.Token), context.Background()
		expiring := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "e", ExpiresInDays: 1}))
		once := must[apikey.CreateResult](t)(ak.CreateFor(bg, up.User.ID, apikey.CreateRequest{Name: "o"}, apikey.Limits{Remaining: intp(1)}))
		refill := must[apikey.CreateResult](t)(ak.CreateFor(bg, up.User.ID, apikey.CreateRequest{Name: "r"}, apikey.Limits{Remaining: intp(1), RefillAmount: 1, RefillInterval: time.Hour}))
		tokensMust(t, tokensUse(a, once.Secret))
		tokensMust(t, tokensUse(a, refill.Secret))
		if err := tokensUse(a, once.Secret); !errors.Is(err, apikey.ErrUsageExceeded) {
			t.Fatalf("exhausted: %v", err)
		}
		if err := tokensUse(a, refill.Secret); !errors.Is(err, apikey.ErrUsageExceeded) {
			t.Fatalf("refillable exhausted: %v", err)
		}
		if r6Exists(t, a, once.Key.ID) || !r6Exists(t, a, refill.Key.ID) {
			t.Fatal("exhausted key kept, or refillable key deleted")
		}
		e.clock.Advance(25 * time.Hour)
		if v := must[apikey.Verification](t)(ak.Verify(bg, expiring.Secret)); v.Valid {
			t.Fatal("expired key valid")
		}
		if r6Exists(t, a, expiring.Key.ID) {
			t.Fatal("expired key kept")
		}
	})
}

// TestTokensAPIKey_DefaultKeepsSpentKeys: without DeleteSpentKeys an
// expired or exhausted key stays listed.
func TestTokensAPIKey_DefaultKeepsSpentKeys(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, ak, up := r6Keyed(t, e, apikey.Scopes("s"))
		bg := context.Background()
		once := must[apikey.CreateResult](t)(ak.CreateFor(bg, up.User.ID, apikey.CreateRequest{Name: "o", ExpiresInDays: 1}, apikey.Limits{Remaining: intp(1)}))
		tokensMust(t, tokensUse(a, once.Secret))
		if err := tokensUse(a, once.Secret); !errors.Is(err, apikey.ErrUsageExceeded) {
			t.Fatalf("exhausted: %v", err)
		}
		e.clock.Advance(25 * time.Hour)
		_ = tokensUse(a, once.Secret)
		if !r6Exists(t, a, once.Key.ID) {
			t.Fatal("a spent key was deleted without DeleteSpentKeys")
		}
	})
}

// TestTokensAPIKey_Cache: a hit spares the database (a row deleted behind
// the plugin keeps working until the TTL); revoke and update drop the entry
// at once; the limits hold through stale cached counters; a key deleted
// during a request is refused rather than counted.
func TestTokensAPIKey_Cache(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		cache := apikey.NewMemoryCacheAt(e.clock.Now)
		a, ak, up := r6Keyed(t, e, apikey.Scopes("s"), apikey.WithCache(cache, 30*time.Second))
		ctx, bg := request(a, up.Token), context.Background()
		k := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "k"}))
		tokensMust(t, tokensUse(a, k.Secret))
		r6DeleteRow(t, a, k.Key.ID)
		if err := tokensUse(a, k.Secret); err != nil {
			t.Fatalf("cached key: %v", err)
		}
		if s, ok := auth.CurrentSession(tokensResolved(t, a, k.Secret)); !ok || s.APIKeyID != k.Key.ID {
			t.Fatal("a cache hit did not resolve the key")
		}
		e.clock.Advance(31 * time.Second)
		if s, ok := auth.CurrentSession(tokensResolved(t, a, k.Secret)); ok {
			t.Fatalf("expired entry still resolves: %+v", s)
		}

		// Revoke and update drop the entry at once.
		for _, act := range []func(id string){
			func(id string) { tokensMust(t, ak.Revoke(ctx, id)) },
			func(id string) {
				must[apikey.Key](t)(ak.Update(ctx, apikey.UpdateRequest{ID: id, Disabled: boolp(true)}))
			},
			func(id string) { tokensMust(t, ak.SetLimits(bg, id, apikey.Limits{Remaining: intp(0)})) },
		} {
			k := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "k"}))
			tokensMust(t, tokensUse(a, k.Secret))
			act(k.Key.ID)
			rctx := tokensBearer(a, k.Secret)
			if err := a.Resolve(rctx); err == nil {
				if _, ok := auth.CurrentSession(rctx); ok {
					t.Fatal("a changed key still resolved from the cache")
				}
			}
		}

		// The rate limit and the quota hold through the stale cached counters.
		limited := must[apikey.CreateResult](t)(ak.CreateFor(bg, up.User.ID, apikey.CreateRequest{Name: "l"}, apikey.Limits{RateMax: 2, RateWindow: time.Minute}))
		quota := must[apikey.CreateResult](t)(ak.CreateFor(bg, up.User.ID, apikey.CreateRequest{Name: "q"}, apikey.Limits{Remaining: intp(2)}))
		for range 2 {
			tokensMust(t, tokensUse(a, limited.Secret))
			tokensMust(t, tokensUse(a, quota.Secret))
		}
		if err := tokensUse(a, limited.Secret); !errors.Is(err, auth.ErrRateLimited) {
			t.Fatalf("third within the window: %v", err)
		}
		if err := tokensUse(a, quota.Secret); !errors.Is(err, apikey.ErrUsageExceeded) {
			t.Fatalf("third against the quota: %v", err)
		}
		// A refill another request won leaves the cached refill clock stale:
		// the lost compare-and-swap re-reads and refills from the fresh row
		// instead of answering usage_exceeded.
		refill := must[apikey.CreateResult](t)(ak.CreateFor(bg, up.User.ID, apikey.CreateRequest{Name: "r"}, apikey.Limits{Remaining: intp(1), RefillAmount: 1, RefillInterval: 10 * time.Second}))
		tokensMust(t, tokensUse(a, refill.Secret))
		e.clock.Advance(11 * time.Second)
		tokensMust(t, tokensUse(a, refill.Secret))
		e.clock.Advance(11 * time.Second)
		if err := tokensUse(a, refill.Secret); err != nil {
			t.Fatalf("refill due under a stale cached clock: %v", err)
		}
		// A key deleted behind a cached entry is refused at its counter
		// write, not counted and not answered usage_exceeded.
		r6DeleteRow(t, a, quota.Key.ID)
		if _, ok := auth.CurrentSession(tokensResolved(t, a, quota.Secret)); ok {
			t.Fatal("a deleted key with limits resolved from the cache")
		}
		if err := tokensUse(a, quota.Secret); err != nil {
			t.Fatalf("a deleted key with limits: %v", err)
		}
	})
}

// tokensResolved resolves raw as a bearer token and returns the request.
func tokensResolved(t *testing.T, a *auth.Auth, raw string) context.Context {
	t.Helper()
	ctx := tokensBearer(a, raw)
	if err := a.Resolve(ctx); err != nil {
		t.Fatal(err)
	}
	return ctx
}

// TestTokensAPIKey_DeferUpdates: the last-use stamp happens through the
// background runner, after the check.
func TestTokensAPIKey_DeferUpdates(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, ak, up := r6Keyed(t, e, apikey.Scopes("s"), apikey.DeferUpdates())
		ctx := request(a, up.Token)
		k := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "k"}))
		e.clock.Advance(time.Second)
		tokensMust(t, tokensUse(a, k.Secret))
		a.WaitDeliveries()
		got := must[apikey.Key](t)(ak.Get(ctx, k.Key.ID))
		if got.LastUsedAt == nil || got.UpdatedAt == nil || !got.UpdatedAt.After(k.Key.CreatedAt) {
			t.Fatalf("deferred stamp = %+v", got)
		}
	})
}

// TestTokensAPIKey_Round6Faults: every database call the round-6 paths add
// reaches the caller, except the logged stamps and deletes.
func TestTokensAPIKey_Round6Faults(t *testing.T) {
	keyed := func(opts ...apikey.Option) func(t *testing.T, e *faultEnv) (*auth.Auth, *apikey.Plugin, password.SignInResult) {
		return func(t *testing.T, e *faultEnv) (*auth.Auth, *apikey.Plugin, password.SignInResult) {
			em, pw := e.emailPlugin(), e.passwordPlugin()
			ak := apikey.New(opts...)
			a := e.newAuth(t, nil, em, pw, ak)
			return a, ak, signUpVerified(t, e.env, a, pw, em)
		}
	}
	t.Run("revoke with a cache", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ak, up := keyed(apikey.Scopes("s"), apikey.WithCache(apikey.NewMemoryCache(), 0))(t, e)
			k := must[apikey.CreateResult](t)(ak.Create(request(a, up.Token), apikey.CreateRequest{Name: "k"}))
			return func(context.Context) error { return ak.Revoke(request(a, up.Token), k.Key.ID) }
		})
	})
	t.Run("owner check", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ak, up := keyed(apikey.Scopes("s"), apikey.DistinctErrors())(t, e)
			k := must[apikey.CreateResult](t)(ak.Create(request(a, up.Token), apikey.CreateRequest{Name: "k"}))
			return func(context.Context) error { return tokensUse(a, k.Secret) }
		}, 3)
	})
	t.Run("spent key delete", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ak, up := keyed(apikey.Scopes("s"), apikey.DeleteSpentKeys())(t, e)
			k := must[apikey.CreateResult](t)(ak.Create(request(a, up.Token), apikey.CreateRequest{Name: "k", ExpiresInDays: 1}))
			e.clock.Advance(25 * time.Hour)
			return func(context.Context) error { return a.Resolve(tokensBearer(a, k.Secret)) }
		}, 2)
	})
	t.Run("exhausted re-read", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ak, up := keyed(apikey.Scopes("s"))(t, e)
			k := must[apikey.CreateResult](t)(ak.CreateFor(context.Background(), up.User.ID, apikey.CreateRequest{Name: "k"}, apikey.Limits{Remaining: intp(1)}))
			tokensMust(t, tokensUse(a, k.Secret))
			return func(context.Context) error {
				if err := tokensUse(a, k.Secret); !errors.Is(err, apikey.ErrUsageExceeded) {
					return err
				}
				return nil
			}
		})
	})
}

// r6FailingCache is an apikey.Cache whose every call can be made to fail, or
// whose Get returns bytes that are not an entry.
type r6FailingCache struct {
	inner               *apikey.MemoryCache
	getErr, setErr, del bool
	garbage             bool
}

var errCacheDown = errors.New("cache down")

func (c *r6FailingCache) Get(ctx context.Context, k string) ([]byte, bool, error) {
	switch {
	case c.getErr:
		return nil, false, errCacheDown
	case c.garbage:
		return []byte("{"), true, nil
	}
	return c.inner.Get(ctx, k)
}

func (c *r6FailingCache) Set(ctx context.Context, k string, v []byte, ttl time.Duration) error {
	if c.setErr {
		return errCacheDown
	}
	return c.inner.Set(ctx, k, v, ttl)
}

func (c *r6FailingCache) Delete(ctx context.Context, k string) error {
	if c.del {
		return errCacheDown
	}
	return c.inner.Delete(ctx, k)
}

// TestTokensAPIKey_CacheFailures: a cache that cannot read or write only
// costs the database read; one that cannot delete fails the revoke, update
// or SetLimits, which then changes nothing, because the old key would
// otherwise keep working from the cache.
func TestTokensAPIKey_CacheFailures(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		c := &r6FailingCache{inner: apikey.NewMemoryCacheAt(e.clock.Now)}
		a, ak, up := r6Keyed(t, e, apikey.Scopes("s"), apikey.WithCache(c, time.Minute), apikey.DeleteSpentKeys())
		ctx, bg := request(a, up.Token), context.Background()
		k := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "k", ExpiresInDays: 1}))
		for name, set := range map[string]func(){
			"get fails": func() { c.getErr = true },
			"set fails": func() { c.setErr = true },
			"garbage":   func() { c.garbage = true },
		} {
			*c = r6FailingCache{inner: c.inner}
			set()
			if s, ok := auth.CurrentSession(tokensResolved(t, a, k.Secret)); !ok || s.APIKeyID != k.Key.ID {
				t.Fatalf("%s: the key did not resolve from the database", name)
			}
		}
		*c = r6FailingCache{inner: c.inner, del: true}
		if err := ak.Revoke(ctx, k.Key.ID); !errors.Is(err, errCacheDown) {
			t.Fatalf("revoke with a failing delete: %v", err)
		}
		if !r6Exists(t, a, k.Key.ID) {
			t.Fatal("a revoke that could not drop the cache entry deleted the row")
		}
		name := "renamed"
		if _, err := ak.Update(ctx, apikey.UpdateRequest{ID: k.Key.ID, Name: &name}); !errors.Is(err, errCacheDown) {
			t.Fatalf("update with a failing delete: %v", err)
		}
		if got := must[apikey.Key](t)(ak.Get(ctx, k.Key.ID)); got.Name != "k" {
			t.Fatalf("an update that could not drop the entry kept its change: %q", got.Name)
		}
		if err := ak.SetLimits(bg, k.Key.ID, apikey.Limits{Remaining: intp(1)}); !errors.Is(err, errCacheDown) {
			t.Fatalf("SetLimits with a failing delete: %v", err)
		}
		if err := ak.SetLimits(bg, "key_nope", apikey.Limits{}); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("SetLimits of an unknown key: %v", err)
		}
		// A spent key is deleted even when its entry cannot be dropped; the
		// failure is only logged.
		e.clock.Advance(25 * time.Hour)
		if _, ok := auth.CurrentSession(tokensResolved(t, a, k.Secret)); ok {
			t.Fatal("expired key resolved")
		}
		if r6Exists(t, a, k.Key.ID) {
			t.Fatal("the spent key was kept because its entry could not be dropped")
		}
	})
}

// TestTokensAPIKey_RemovedConfiguration: a key whose configuration was
// removed from the code stops resolving, and cannot be updated, rather than
// falling back to the default's rules.
func TestTokensAPIKey_RemovedConfiguration(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, ak, up := r6Keyed(t, e, apikey.Scopes("s"), apikey.Configuration("live", apikey.Prefix("sk_live_")))
		k := must[apikey.CreateResult](t)(ak.Create(request(a, up.Token), apikey.CreateRequest{Config: "live", Name: "k"}))
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak2 := apikey.New(apikey.Scopes("s"), apikey.Prefix("sk_"))
		a2 := e.newAuth(t, nil, em, pw, ak2)
		if _, ok := auth.CurrentSession(tokensResolved(t, a2, k.Secret)); ok {
			t.Fatal("a key of a removed configuration resolved")
		}
		name := "n"
		if _, err := ak2.Update(request(a2, up.Token), apikey.UpdateRequest{ID: k.Key.ID, Name: &name}); !errors.Is(err, apikey.ErrUnknownConfig) {
			t.Fatalf("update: %v", err)
		}
	})
}

// TestTokensAPIKey_CachedRateLimit: a cached window start is stale after the
// first request, so the next one loses its guard and re-reads; a key deleted
// under the entry is refused at that re-read.
func TestTokensAPIKey_CachedRateLimit(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, ak, up := r6Keyed(t, e, apikey.Scopes("s"), apikey.WithCache(apikey.NewMemoryCacheAt(e.clock.Now), time.Minute))
		k := must[apikey.CreateResult](t)(ak.CreateFor(context.Background(), up.User.ID, apikey.CreateRequest{Name: "l"}, apikey.Limits{RateMax: 5, RateWindow: time.Minute}))
		for range 3 {
			if _, ok := auth.CurrentSession(tokensResolved(t, a, k.Secret)); !ok {
				t.Fatal("a cached key within its limit did not resolve")
			}
		}
		if got := must[apikey.Key](t)(ak.Get(request(a, up.Token), k.Key.ID)); got.UpdatedAt == nil || got.UpdatedAt.Before(k.Key.CreatedAt) {
			t.Fatalf("updated_at = %v", got.UpdatedAt)
		}
		r6DeleteRow(t, a, k.Key.ID)
		if _, ok := auth.CurrentSession(tokensResolved(t, a, k.Secret)); ok {
			t.Fatal("a deleted rate-limited key resolved from the cache")
		}
	})
	t.Run("faults", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw := e.emailPlugin(), e.passwordPlugin()
			ak := apikey.New(apikey.Scopes("s"), apikey.WithCache(apikey.NewMemoryCacheAt(e.clock.Now), time.Minute))
			a := e.newAuth(t, nil, em, pw, ak)
			up := signUpVerified(t, e.env, a, pw, em)
			k := must[apikey.CreateResult](t)(ak.CreateFor(context.Background(), up.User.ID, apikey.CreateRequest{Name: "l"}, apikey.Limits{RateMax: 5, RateWindow: time.Minute}))
			tokensMust(t, tokensUse(a, k.Secret))
			return func(context.Context) error { return tokensUse(a, k.Secret) }
		})
	})
}
