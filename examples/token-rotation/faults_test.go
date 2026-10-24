package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// The failure and edge paths of token rotation.

var errFault = errors.New("fault")

// faultRotator is the memory store (which has SessionTokenRotator and no
// single-query finder, so the rotated lookup reads the user separately) with
// RotateToken and Delete made to fail or lose on demand.
type faultRotator struct {
	auth.SessionStore
	rotateErr, rotateLoses, failDelete atomic.Bool
}

func (f *faultRotator) inner() auth.SessionTokenRotator {
	return f.SessionStore.(auth.SessionTokenRotator)
}

func (f *faultRotator) RotateToken(ctx context.Context, id string, oldHash, newHash []byte, grace, exp, seen time.Time) (bool, error) {
	switch {
	case f.rotateErr.Load():
		return false, errFault
	case f.rotateLoses.Load():
		return false, nil
	}
	return f.inner().RotateToken(ctx, id, oldHash, newHash, grace, exp, seen)
}

func (f *faultRotator) FindRotated(ctx context.Context, h []byte, now time.Time) (auth.Session, time.Time, error) {
	return f.inner().FindRotated(ctx, h, now)
}

func (f *faultRotator) Delete(ctx context.Context, userID, id string) error {
	if f.failDelete.Load() {
		return errFault
	}
	return f.SessionStore.Delete(ctx, userID, id)
}

// TestMemoryStore_GraceAndReuse: the same story as on SQL through a store
// without the joined lookup: the user of a token in its grace is read
// separately, and reuse after it revokes.
func TestMemoryStore_GraceAndReuse(t *testing.T) {
	store := &faultRotator{SessionStore: auth.NewMemorySessionStore()}
	app := newTestApp(t, true, auth.WithSessionStore(store))
	first := app.call(t, http.MethodPost, "/auth/password/sign-up", "", credentials(), http.StatusOK).Header.Get(authhttp.SetTokenHeader)
	app.advance(refreshAfter + time.Second)
	second := app.call(t, http.MethodGet, "/me", first, nil, http.StatusOK).Header.Get(authhttp.SetTokenHeader)
	if second == "" || second == first {
		t.Fatal("no rotation")
	}
	app.call(t, http.MethodGet, "/me", first, nil, http.StatusOK)
	app.advance(rotationGrace + time.Second)
	app.call(t, http.MethodGet, "/me", first, nil, http.StatusUnauthorized)
	app.call(t, http.MethodGet, "/me", second, nil, http.StatusUnauthorized)
}

// TestRotation_StoreFailures: a rotation the store fails is a 500; one a
// concurrent request already made leaves this request with its token; a
// revocation the store fails is a 500, never a pass.
func TestRotation_StoreFailures(t *testing.T) {
	store := &faultRotator{SessionStore: auth.NewMemorySessionStore()}
	app := newTestApp(t, true, auth.WithSessionStore(store))
	first := app.call(t, http.MethodPost, "/auth/password/sign-up", "", credentials(), http.StatusOK).Header.Get(authhttp.SetTokenHeader)
	app.advance(refreshAfter + time.Second)

	store.rotateErr.Store(true)
	app.call(t, http.MethodGet, "/me", first, nil, http.StatusInternalServerError)
	store.rotateErr.Store(false)

	store.rotateLoses.Store(true)
	if got := app.call(t, http.MethodGet, "/me", first, nil, http.StatusOK).Header.Get(authhttp.SetTokenHeader); got != "" {
		t.Fatalf("a lost rotation issued %q", got)
	}
	store.rotateLoses.Store(false)

	app.call(t, http.MethodGet, "/me", first, nil, http.StatusOK) // rotates now
	app.advance(rotationGrace + time.Second)
	store.failDelete.Store(true)
	app.call(t, http.MethodGet, "/me", first, nil, http.StatusInternalServerError)
}

// TestRotatedRow_WithoutAGraceEndIsReuse: a row whose previous hash has no
// grace end (written by hand, or half a migration) gives that token no
// grace at all: presenting it revokes, failing closed.
func TestRotatedRow_WithoutAGraceEndIsReuse(t *testing.T) {
	app := newTestApp(t, true)
	tok := app.call(t, http.MethodPost, "/auth/password/sign-up", "", credentials(), http.StatusOK).Header.Get(authhttp.SetTokenHeader)
	const copied = "a-token-from-before-the-rotation"
	if _, err := app.db.Exec("UPDATE "+auth.TableNameSession+" SET "+auth.ColSessionPreviousTokenHash+" = ?, "+auth.ColSessionPreviousValidUntil+" = NULL",
		auth.HashToken(copied)); err != nil {
		t.Fatal(err)
	}
	app.call(t, http.MethodGet, "/me", copied, nil, http.StatusUnauthorized)
	app.call(t, http.MethodGet, "/me", tok, nil, http.StatusUnauthorized)
	app.waitEvents(t, 1)
}

// dropCache is the memory cache whose Drop can fail.
type dropCache struct {
	auth.SessionCache
	failDrop atomic.Bool
	drops    atomic.Int32
}

func (d *dropCache) Drop(ctx context.Context, k auth.CacheKey) error {
	d.drops.Add(1)
	if d.failDrop.Load() {
		return errFault
	}
	return d.SessionCache.Drop(ctx, k)
}

// TestFreshOperation_DropsTheReplacedTokensCacheEntry: a FreshSignIn
// operation looks a cached session up again; when that lookup rotates the
// token, the cache entry of the replaced token is dropped, so it cannot keep
// answering past its grace. A failing drop is a 500.
func TestFreshOperation_DropsTheReplacedTokensCacheEntry(t *testing.T) {
	for _, fail := range []bool{false, true} {
		cache := &dropCache{SessionCache: auth.NewMemorySessionCache(100)}
		app := newTestApp(t, true, auth.WithSessionCache(cache, 5*time.Minute))
		tok := app.call(t, http.MethodPost, "/auth/password/sign-up", "", credentials(), http.StatusOK).Header.Get(authhttp.SetTokenHeader)
		app.call(t, http.MethodGet, "/me", tok, nil, http.StatusOK) // cached now
		app.advance(refreshAfter + time.Second)
		cache.failDrop.Store(fail)
		body, _ := json.Marshal(map[string]string{"current": testPassword, "new": testPassword + " again"}) // strings always encode
		want := http.StatusOK
		if fail {
			want = http.StatusInternalServerError
		}
		app.call(t, http.MethodPost, "/auth/password/change", tok, body, want)
		if cache.drops.Load() == 0 {
			t.Fatalf("fail=%v: the replaced token's cache entry was never dropped", fail)
		}
	}
}
