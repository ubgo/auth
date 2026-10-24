package sessiontest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// RunCache checks the SessionCache that open returns against the contract
// every cache must keep, whether it holds entries on the server (memory,
// Redis: Put returns "") or hands the client a copy (the sealed snapshot,
// the jwt plugin's signed snapshot: Put returns the value). open is called
// once per case. The core's caches, contrib/redis and plugin/jwt run it.
//
// The rules: an entry comes back whole (every session and user field) for
// the token it was put for and no other; it is used before its expiry and
// never at or after it; a client copy that was changed, truncated or made up
// is a miss, never an error, so the request falls back to the store; a
// server-side entry is forgotten by Drop; a cache that implements
// auth.SessionCacheUserDropper forgets every entry of one user, and only
// that user's, on DropUser.
func RunCache(t *testing.T, open func(t *testing.T) auth.SessionCache) {
	t.Helper()
	for name, c := range cacheCases {
		t.Run(name, func(t *testing.T) { c(t, open(t)) })
	}
}

// cacheUntil is when the cases' entries stop being used: a minute after now,
// on a whole second, because a client copy may carry its expiry in whole
// seconds (a JWT's exp), rounded down.
var cacheUntil = now.Add(time.Minute)

// cachedSession is a session with every field set, so a cache that drops
// one on the way through is caught.
func cachedSession() (auth.Session, auth.User) {
	admin := "usr_admin"
	maxExp := now.Add(24 * time.Hour)
	s := session("ses_cached", "usr_cached", now.Add(-time.Hour))
	s.ImpersonatedBy, s.Transient, s.IdleSeconds, s.RefreshSeconds, s.MaxExpiresAt = &admin, true, 600, 60, &maxExp
	u := auth.User{ID: "usr_cached", Name: "Ada", Image: "https://img.example/a.png", CreatedAt: now.Add(-48 * time.Hour), UpdatedAt: now.Add(-time.Hour)}
	return s, u
}

// sameJSON compares two values by their JSON, which is the form every
// client copy carries and the one in which a lost field shows.
func sameJSON(t T, what string, got, want any) {
	g, err1 := json.Marshal(got)
	w, err2 := json.Marshal(want)
	if err1 != nil || err2 != nil || string(g) != string(w) {
		t.Fatalf("%s came back changed:\n got %s\nwant %s", what, g, w)
	}
}

// put stores the full entry for the token labelled tok and returns the key
// a later request presents.
func put(t T, c auth.SessionCache, tok string) auth.CacheKey {
	s, u := cachedSession()
	k := auth.CacheKey{TokenHash: hash(tok)}
	v, err := c.Put(context.Background(), k, s, u, cacheUntil)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	k.Client = v
	return k
}

// miss asserts a Get finds nothing and does not fail.
func miss(t T, c auth.SessionCache, k auth.CacheKey, at time.Time, why string) {
	_, _, ok, err := c.Get(context.Background(), k, at)
	if err != nil {
		t.Fatalf("%s: Get must miss, not fail: %v", why, err)
	}
	if ok {
		t.Fatalf("%s: Get must miss", why)
	}
}

// cacheCases is every cache contract, by name.
var cacheCases = map[string]func(t T, c auth.SessionCache){
	"an entry comes back whole for its token": func(t T, c auth.SessionCache) {
		k := put(t, c, "tok-a")
		s, u, ok, err := c.Get(context.Background(), k, now)
		if err != nil || !ok {
			t.Fatalf("Get after Put = %v, %v", ok, err)
		}
		ws, wu := cachedSession()
		sameJSON(t, "the session", s, ws)
		sameJSON(t, "the user", u, wu)
	},
	"an entry is used until its expiry and never at or after it": func(t T, c auth.SessionCache) {
		k := put(t, c, "tok-a")
		if _, _, ok, err := c.Get(context.Background(), k, cacheUntil.Add(-2*time.Second)); err != nil || !ok {
			t.Fatalf("Get two seconds before the expiry = %v, %v", ok, err)
		}
		miss(t, c, k, cacheUntil, "at the expiry")
		miss(t, c, k, cacheUntil.Add(time.Hour), "after the expiry")
	},
	"an entry is never used with another token": func(t T, c auth.SessionCache) {
		k := put(t, c, "tok-a")
		miss(t, c, auth.CacheKey{TokenHash: hash("tok-b"), Client: k.Client}, now, "another token with this token's copy")
		other := put(t, c, "tok-b")
		if other.Client != "" {
			// A server-side cache has no copy to swap; its own entry for
			// this token answers, rightly.
			miss(t, c, auth.CacheKey{TokenHash: k.TokenHash, Client: other.Client}, now, "this token with another token's copy")
		}
	},
	"a changed or made-up client copy is a miss": func(t T, c auth.SessionCache) {
		k := put(t, c, "tok-a")
		if k.Client == "" {
			return // a server-side cache has no client copy to change
		}
		mid := len(k.Client) / 2
		flipped := k.Client[:mid] + string(k.Client[mid]^1) + k.Client[mid+1:]
		for why, v := range map[string]string{
			"no copy":         "",
			"a changed copy":  flipped,
			"a truncated one": k.Client[:mid],
			"a made-up one":   "not-a-cache-value",
			"three dots":      "a.b.c",
		} {
			miss(t, c, auth.CacheKey{TokenHash: k.TokenHash, Client: v}, now, why)
		}
	},
	"a server-side entry needs no client copy and is forgotten by Drop": func(t T, c auth.SessionCache) {
		k := put(t, c, "tok-a")
		if k.Client != "" {
			return // a client copy is cleared by the transport, not by Drop
		}
		if _, _, ok, err := c.Get(context.Background(), k, now); err != nil || !ok {
			t.Fatalf("Get with no client copy = %v, %v", ok, err)
		}
		if err := c.Drop(context.Background(), k); err != nil {
			t.Fatalf("Drop: %v", err)
		}
		miss(t, c, k, now, "after Drop")
	},
	"DropUser forgets every entry of the user and no other": func(t T, c auth.SessionCache) {
		d, ok := c.(auth.SessionCacheUserDropper)
		if !ok {
			return // a client copy cannot be found by user
		}
		a1, a2 := put(t, c, "tok-a"), put(t, c, "tok-a2")
		s, u := cachedSession()
		s.ID, s.UserID, u.ID = "ses_other", "usr_other", "usr_other"
		other := auth.CacheKey{TokenHash: hash("tok-other")}
		if _, err := c.Put(context.Background(), other, s, u, cacheUntil); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := d.DropUser(context.Background(), "usr_cached"); err != nil {
			t.Fatalf("DropUser: %v", err)
		}
		miss(t, c, a1, now, "the user's first entry after DropUser")
		miss(t, c, a2, now, "the user's second entry after DropUser")
		if _, _, ok, err := c.Get(context.Background(), other, now); err != nil || !ok {
			t.Fatalf("another user's entry after DropUser = %v, %v", ok, err)
		}
		if err := d.DropUser(context.Background(), "usr_nobody"); err != nil {
			t.Fatalf("DropUser of a user with no entry: %v", err)
		}
	},
	"Drop of an entry never put does not fail": func(t T, c auth.SessionCache) {
		if err := c.Drop(context.Background(), auth.CacheKey{TokenHash: hash("never")}); err != nil {
			t.Fatalf("Drop: %v", err)
		}
	},
}
