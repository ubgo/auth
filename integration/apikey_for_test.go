package integration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth/plugin/apikey"
)

// TestAPIKeyFor: the app manages another user's keys from Go, a parent
// account's bot user here, with no session. ListFor pages that user's keys
// only; GetFor, UpdateFor and RevokeFor reach a key of the named user and
// answer ErrNotFound for anyone else's; a key disabled or revoked this way is
// refused on its next use although its verification was cached, and a
// metadata update is accepted without AllowMetadata, as CreateFor's is.
func TestAPIKeyFor(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, ak, parent := r6Keyed(t, e, apikey.Scopes("read"), apikey.WithCache(apikey.NewMemoryCacheAt(e.clock.Now), 10*time.Minute))
		bot, _ := identUser(t, a, "bot@example.test")
		bg := context.Background()
		mk := func(name string) apikey.CreateResult {
			return must[apikey.CreateResult](t)(ak.CreateFor(bg, bot, apikey.CreateRequest{Name: name}, apikey.Limits{}))
		}
		k1, k2 := mk("b-first"), mk("a-second")
		mine := must[apikey.CreateResult](t)(ak.CreateFor(bg, parent.User.ID, apikey.CreateRequest{Name: "parent"}, apikey.Limits{}))
		valid := func(secret string) bool {
			v, err := ak.Verify(bg, secret)
			if err != nil {
				t.Fatal(err)
			}
			return v.Valid
		}

		// ListFor: the bot's keys only, paged and sorted as asked.
		page := must[apikey.ListResult](t)(ak.ListFor(bg, bot, apikey.ListRequest{Limit: "1", SortBy: apikey.SortByName}))
		if page.Total != 2 || len(page.Keys) != 1 || page.Keys[0].ID != k2.Key.ID {
			t.Fatalf("ListFor page = %+v", page)
		}
		if all := must[apikey.ListResult](t)(ak.ListFor(bg, parent.User.ID, apikey.ListRequest{})); all.Total != 1 || all.Keys[0].ID != mine.Key.ID {
			t.Fatalf("the parent's own list = %+v", all)
		}
		if _, err := ak.ListFor(bg, bot, apikey.ListRequest{Limit: "-1"}); !errors.Is(err, apikey.ErrBadList) {
			t.Fatalf("a bad page: %v", err)
		}

		// GetFor: the owner reads it, nobody else does.
		if got := must[apikey.Key](t)(ak.GetFor(bg, bot, k1.Key.ID)); got.Name != "b-first" {
			t.Fatalf("GetFor = %+v", got)
		}
		if _, err := ak.GetFor(bg, parent.User.ID, k1.Key.ID); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("GetFor another user's key: %v", err)
		}

		// UpdateFor: rename, expiry, metadata, then disable; the cached
		// verification does not outlive the change.
		if !valid(k1.Secret) {
			t.Fatal("k1 refused before any change")
		}
		name, hour := "renamed", int64(3600)
		got := must[apikey.Key](t)(ak.UpdateFor(bg, bot, apikey.UpdateRequest{ID: k1.Key.ID, Name: &name, ExpiresIn: &hour, Metadata: json.RawMessage(`{"team":"ci"}`)}))
		if got.Name != name || got.ExpiresAt == nil || !got.ExpiresAt.Equal(e.clock.Now().Add(time.Hour)) || string(got.Metadata) != `{"team":"ci"}` {
			t.Fatalf("UpdateFor = %+v", got)
		}
		off := true
		if _, err := ak.UpdateFor(bg, parent.User.ID, apikey.UpdateRequest{ID: k1.Key.ID, Disabled: &off}); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("UpdateFor another user's key: %v", err)
		}
		if !valid(k1.Secret) {
			t.Fatal("a refused UpdateFor disabled the key")
		}
		if got := must[apikey.Key](t)(ak.UpdateFor(bg, bot, apikey.UpdateRequest{ID: k1.Key.ID, Disabled: &off})); !got.Disabled {
			t.Fatalf("UpdateFor disable = %+v", got)
		}
		if valid(k1.Secret) {
			t.Fatal("a disabled key still verifies from the cache")
		}
		if _, err := ak.UpdateFor(bg, bot, apikey.UpdateRequest{ID: k1.Key.ID}); !errors.Is(err, apikey.ErrNoChanges) {
			t.Fatalf("UpdateFor nothing: %v", err)
		}

		// RevokeFor: only the owner's call deletes, and the next use is
		// refused although it was cached.
		if !valid(k2.Secret) {
			t.Fatal("k2 refused before the revoke")
		}
		if err := ak.RevokeFor(bg, parent.User.ID, k2.Key.ID); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("RevokeFor another user's key: %v", err)
		}
		if !valid(k2.Secret) {
			t.Fatal("a refused RevokeFor revoked the key")
		}
		if err := ak.RevokeFor(bg, bot, k2.Key.ID); err != nil {
			t.Fatal(err)
		}
		if valid(k2.Secret) {
			t.Fatal("a revoked key still verifies from the cache")
		}
		if err := ak.RevokeFor(bg, bot, k2.Key.ID); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("a second RevokeFor: %v", err)
		}
		if left := must[apikey.ListResult](t)(ak.ListFor(bg, bot, apikey.ListRequest{})); left.Total != 1 || left.Keys[0].ID != k1.Key.ID {
			t.Fatalf("after the revoke = %+v", left)
		}
	})
}
