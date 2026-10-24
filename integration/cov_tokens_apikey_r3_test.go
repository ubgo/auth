package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/password"
)

func TestTokensAPIKey_GetAndListPaging(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak := apikey.New(apikey.Scopes("s"))
		a := e.newAuth(t, nil, em, pw, ak)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		var made []apikey.CreateResult
		for _, c := range []struct {
			name string
			days int
		}{{"charlie", 30}, {"alpha", 10}, {"bravo", 20}} {
			e.clock.Advance(time.Second)
			made = append(made, must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: c.name, ExpiresInDays: c.days})))
		}

		// Get: the owner's view of one key; another user's and an unknown id
		// are both not found.
		k := must[apikey.Key](t)(ak.Get(ctx, made[1].Key.ID))
		if k.Name != "alpha" || k.ID != made[1].Key.ID {
			t.Fatalf("get = %+v", k)
		}
		other := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret}))
		if _, err := ak.Get(request(a, other.Token), made[1].Key.ID); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("another user's key: %v", err)
		}
		if _, err := ak.Get(ctx, "key_nope"); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("unknown id: %v", err)
		}
		// The HTTP shape: a query of strings reaches the operation.
		if got, err := tokensInvoke[apikey.Key](ctx, a, apikey.EndpointGet, map[string]string{"id": made[0].Key.ID}); err != nil || got.Name != "charlie" {
			t.Fatalf("get over the wire = %+v %v", got, err)
		}

		// List: the zero request is the whole list oldest first with the
		// total; List keeps the old shape.
		names := func(r apikey.ListResult) string {
			var ns []string
			for _, k := range r.Keys {
				ns = append(ns, k.Name)
			}
			return strings.Join(ns, ",")
		}
		all := must[apikey.ListResult](t)(ak.ListKeys(ctx, apikey.ListRequest{}))
		if names(all) != "charlie,alpha,bravo" || all.Total != 3 || all.Limit != 0 || all.Offset != 0 {
			t.Fatalf("all = %s %+v", names(all), all)
		}
		if keys := must[[]apikey.Key](t)(ak.List(ctx)); len(keys) != 3 || keys[0].Name != "charlie" {
			t.Fatalf("List = %+v", keys)
		}
		page := must[apikey.ListResult](t)(ak.ListKeys(ctx, apikey.ListRequest{Limit: "2", Offset: "1"}))
		if names(page) != "alpha,bravo" || page.Total != 3 || page.Limit != 2 || page.Offset != 1 {
			t.Fatalf("page = %s %+v", names(page), page)
		}
		past := must[apikey.ListResult](t)(ak.ListKeys(ctx, apikey.ListRequest{Limit: "2", Offset: "5"}))
		if len(past.Keys) != 0 || past.Total != 3 || past.Keys == nil {
			t.Fatalf("past the end = %+v", past)
		}
		byName := must[apikey.ListResult](t)(ak.ListKeys(ctx, apikey.ListRequest{SortBy: apikey.SortByName, Sort: apikey.SortDesc}))
		if names(byName) != "charlie,bravo,alpha" {
			t.Fatalf("by name desc = %s", names(byName))
		}
		byExpiry := must[apikey.ListResult](t)(ak.ListKeys(ctx, apikey.ListRequest{SortBy: apikey.SortByExpiresAt, Sort: apikey.SortAsc}))
		if names(byExpiry) != "alpha,bravo,charlie" {
			t.Fatalf("by expiry asc = %s", names(byExpiry))
		}
		newest := must[apikey.ListResult](t)(ak.ListKeys(ctx, apikey.ListRequest{Sort: apikey.SortDesc, Limit: "1"}))
		if names(newest) != "bravo" {
			t.Fatalf("newest = %s", names(newest))
		}
		// Sorting by last use works on every engine once every key has one.
		for _, m := range made {
			e.clock.Advance(time.Second)
			tokensMust(t, tokensUse(a, m.Secret))
		}
		byUse := must[apikey.ListResult](t)(ak.ListKeys(ctx, apikey.ListRequest{SortBy: apikey.SortByLastUsedAt, Sort: apikey.SortDesc}))
		if names(byUse) != "bravo,alpha,charlie" {
			t.Fatalf("by last use desc = %s", names(byUse))
		}
		for name, in := range map[string]apikey.ListRequest{
			"bad limit": {Limit: "x"}, "negative offset": {Offset: "-1"}, "bad sort": {SortBy: "hint"}, "bad direction": {Sort: "down"},
		} {
			if _, err := ak.ListKeys(ctx, in); !errors.Is(err, apikey.ErrBadList) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		// Another user sees only their own total.
		if r := must[apikey.ListResult](t)(ak.ListKeys(request(a, other.Token), apikey.ListRequest{})); r.Total != 0 || len(r.Keys) != 0 {
			t.Fatalf("other's list = %+v", r)
		}
	})
}

func TestTokensAPIKey_Verify(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak := apikey.New(apikey.Scopes("read", "write"))
		a := e.newAuth(t, nil, em, pw, ak)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		made := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "k", Scopes: []string{"read"}}))
		bg := context.Background()

		v := must[apikey.Verification](t)(ak.Verify(bg, made.Secret))
		if !v.Valid || v.Reason != nil || v.Key == nil || v.Key.ID != made.Key.ID || v.UserID != up.User.ID {
			t.Fatalf("valid key = %+v", v)
		}
		if v := must[apikey.Verification](t)(ak.Verify(bg, made.Secret, "read")); !v.Valid {
			t.Fatalf("with its scope = %+v", v)
		}
		if v := must[apikey.Verification](t)(ak.Verify(bg, made.Secret, "read", "write")); v.Valid || !errors.Is(v.Reason, apikey.ErrScopeMissing) || v.Key != nil || v.UserID != "" {
			t.Fatalf("missing scope = %+v", v)
		}
		for name, secret := range map[string]string{"unknown": apikey.DefaultPrefix + strings.Repeat("x", 43), "other prefix": "sk_" + strings.Repeat("x", 43), "empty": ""} {
			if v := must[apikey.Verification](t)(ak.Verify(bg, secret)); v.Valid || !errors.Is(v.Reason, auth.ErrSignedOut) {
				t.Fatalf("%s = %+v", name, v)
			}
		}
		// A paused key, then a key past its rate limit and one past its quota.
		must[apikey.Key](t)(ak.Update(ctx, apikey.UpdateRequest{ID: made.Key.ID, Disabled: boolp(true)}))
		if v := must[apikey.Verification](t)(ak.Verify(bg, made.Secret)); v.Valid || !errors.Is(v.Reason, auth.ErrSignedOut) {
			t.Fatalf("disabled = %+v", v)
		}
		limited := must[apikey.CreateResult](t)(ak.CreateFor(bg, up.User.ID, apikey.CreateRequest{Name: "l"}, apikey.Limits{RateMax: 1, RateWindow: time.Minute}))
		if v := must[apikey.Verification](t)(ak.Verify(bg, limited.Secret)); !v.Valid {
			t.Fatalf("first use = %+v", v)
		}
		if v := must[apikey.Verification](t)(ak.Verify(bg, limited.Secret)); v.Valid || !errors.Is(v.Reason, auth.ErrRateLimited) {
			t.Fatalf("second use in the window = %+v", v)
		}
		quota := must[apikey.CreateResult](t)(ak.CreateFor(bg, up.User.ID, apikey.CreateRequest{Name: "q"}, apikey.Limits{Remaining: intp(1)}))
		must[apikey.Verification](t)(ak.Verify(bg, quota.Secret))
		if v := must[apikey.Verification](t)(ak.Verify(bg, quota.Secret)); v.Valid || !errors.Is(v.Reason, apikey.ErrUsageExceeded) {
			t.Fatalf("exhausted = %+v", v)
		}
		// Verify counts as a use: the live Remaining in the returned key.
		fresh := must[apikey.CreateResult](t)(ak.CreateFor(bg, up.User.ID, apikey.CreateRequest{Name: "r"}, apikey.Limits{Remaining: intp(5)}))
		if v := must[apikey.Verification](t)(ak.Verify(bg, fresh.Secret)); v.Key.Limits.Remaining == nil || *v.Key.Limits.Remaining != 4 {
			t.Fatalf("remaining after one verify = %+v", v.Key.Limits)
		}
	})
}

func TestTokensAPIKey_ScopesNamesHintAndGenerator(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak := apikey.New(apikey.Scopes("read", "write"), apikey.NameBounds(2, 8), apikey.HintLength(0))
		a := e.newAuth(t, nil, em, pw, ak)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)

		// Names are refused outside the bounds, at create and rename; the
		// hint is the prefix alone.
		if _, err := ak.Create(ctx, apikey.CreateRequest{Name: "x"}); !errors.Is(err, apikey.ErrBadName) {
			t.Fatalf("short name: %v", err)
		}
		if _, err := ak.Create(ctx, apikey.CreateRequest{Name: "nine-char"}); !errors.Is(err, apikey.ErrBadName) {
			t.Fatalf("long name: %v", err)
		}
		made := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "ok", Scopes: []string{"read"}}))
		if made.Key.Hint != apikey.DefaultPrefix {
			t.Fatalf("hint = %q", made.Key.Hint)
		}
		long := "nine-char"
		if _, err := ak.Update(ctx, apikey.UpdateRequest{ID: made.Key.ID, Name: &long}); !errors.Is(err, apikey.ErrBadName) {
			t.Fatalf("long rename: %v", err)
		}

		// Scopes change on update, take effect on the next request, refuse
		// an undeclared scope, and an empty list clears them.
		kctx := tokensBearer(a, made.Secret)
		tokensMust(t, a.Resolve(kctx))
		if !auth.HasScope(kctx, "read") || auth.HasScope(kctx, "write") {
			t.Fatal("initial scopes")
		}
		k := must[apikey.Key](t)(ak.Update(ctx, apikey.UpdateRequest{ID: made.Key.ID, Scopes: []string{"write", "read", "write"}}))
		if strings.Join(k.Scopes, ",") != "read,write" {
			t.Fatalf("updated scopes = %v", k.Scopes)
		}
		kctx = tokensBearer(a, made.Secret)
		tokensMust(t, a.Resolve(kctx))
		if !auth.HasScope(kctx, "write") {
			t.Fatal("new scope not effective")
		}
		if _, err := ak.Update(ctx, apikey.UpdateRequest{ID: made.Key.ID, Scopes: []string{"admin"}}); !errors.Is(err, apikey.ErrUnknownScope) {
			t.Fatalf("undeclared scope: %v", err)
		}
		k = must[apikey.Key](t)(ak.Update(ctx, apikey.UpdateRequest{ID: made.Key.ID, Scopes: []string{}}))
		if len(k.Scopes) != 0 || k.Scopes == nil {
			t.Fatalf("cleared scopes = %#v", k.Scopes)
		}

		// A custom generator shapes the random part; a short one fails the
		// create; the longest hint shows eight characters of it.
		custom := apikey.New(apikey.Scopes("s"), apikey.HintLength(8), apikey.Generate(func() string { return "ABCDEFGH" + strings.Repeat("z", 20) }))
		a2 := e.newAuth(t, nil, em, pw, custom)
		ctx2 := request(a2, up.Token)
		got := must[apikey.CreateResult](t)(custom.Create(ctx2, apikey.CreateRequest{Name: "c"}))
		if !strings.HasPrefix(got.Secret, apikey.DefaultPrefix+"ABCDEFGH") || got.Key.Hint != apikey.DefaultPrefix+"ABCDEFGH" {
			t.Fatalf("custom secret %q hint %q", got.Secret, got.Key.Hint)
		}
		tokensMust(t, tokensUse(a2, got.Secret))
		short := apikey.New(apikey.Scopes("s"), apikey.Generate(func() string { return "short" }))
		a3 := e.newAuth(t, nil, em, pw, short)
		if _, err := short.Create(request(a3, up.Token), apikey.CreateRequest{Name: "c"}); !errors.Is(err, apikey.ErrShortSecret) {
			t.Fatalf("short secret: %v", err)
		}

		// A refillable quota with no starting count starts full, through
		// CreateFor, DefaultLimits and SetLimits alike.
		bg := context.Background()
		refill := apikey.Limits{RefillAmount: 2, RefillInterval: time.Hour}
		r := must[apikey.CreateResult](t)(ak.CreateFor(bg, up.User.ID, apikey.CreateRequest{Name: "rf"}, refill))
		if r.Key.Limits.Remaining == nil || *r.Key.Limits.Remaining != 2 {
			t.Fatalf("remaining = %+v", r.Key.Limits)
		}
		tokensMust(t, tokensUse(a, r.Secret))
		tokensMust(t, tokensUse(a, r.Secret))
		if err := tokensUse(a, r.Secret); !errors.Is(err, apikey.ErrUsageExceeded) {
			t.Fatalf("third use: %v", err)
		}
		tokensMust(t, ak.SetLimits(bg, made.Key.ID, refill))
		if k := must[apikey.Key](t)(ak.Get(ctx, made.Key.ID)); k.Limits.Remaining == nil || *k.Limits.Remaining != 2 {
			t.Fatalf("after SetLimits = %+v", k.Limits)
		}
		dl := apikey.New(apikey.Scopes("s"), apikey.DefaultLimits(refill))
		a4 := e.newAuth(t, nil, em, pw, dl)
		if d := must[apikey.CreateResult](t)(dl.Create(request(a4, up.Token), apikey.CreateRequest{Name: "d"})); d.Key.Limits.Remaining == nil || *d.Key.Limits.Remaining != 2 {
			t.Fatalf("default limits = %+v", d.Key.Limits)
		}
	})
}

func TestTokensAPIKey_Round3Faults(t *testing.T) {
	t.Run("get", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ak, up, made := tokensKeyed(t, e, nil)
			return func(context.Context) error { _, err := ak.Get(request(a, up.Token), made.Key.ID); return err }
		})
	})
	t.Run("list a page", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ak, up, _ := tokensKeyed(t, e, nil)
			return func(context.Context) error {
				_, err := ak.ListKeys(request(a, up.Token), apikey.ListRequest{Limit: "1", SortBy: apikey.SortByName})
				return err
			}
		})
	})
	t.Run("update scopes", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ak, up, made := tokensKeyed(t, e, nil)
			return func(context.Context) error {
				_, err := ak.Update(request(a, up.Token), apikey.UpdateRequest{ID: made.Key.ID, Scopes: []string{}})
				return err
			}
		})
	})
	t.Run("verify", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			_, ak, _, made := tokensKeyed(t, e, nil)
			return func(ctx context.Context) error {
				v, err := ak.Verify(ctx, made.Secret, "s")
				if err == nil && !v.Valid {
					return v.Reason
				}
				return err
			}
		}, tokensResolveRecordUseStep)
	})
}
