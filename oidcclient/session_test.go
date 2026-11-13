package oidcclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// apiGet is an API call (no text/html in Accept).
func apiGet(b *browser, target string) *httpResult {
	res := b.do(http.MethodGet, target, nil, "Accept", mediaTypeJSON)
	return &httpResult{code: res.Code, body: res.Body.String(), header: res.Header()}
}

// httpResult is the part of an answer the session tests read.
type httpResult struct {
	code   int
	body   string
	header http.Header
}

// TestSession_StaysSignedInAcrossDays is the spec's story: signed in on
// Monday, the browser closed, back on Wednesday and still signed in (each
// visit re-checks and slides the idle window), refused at the next request
// after the login server removes the person, even with a copy of the old
// cookie.
func TestSession_StaysSignedInAcrossDays(t *testing.T) {
	f := newFixture(t, algEdDSA)
	b := f.signIn("hazar", "/")
	saved := b.snapshot()
	f.clock.advance(2 * 24 * time.Hour)
	if r := apiGet(b, "/"); r.code != http.StatusOK || r.body != "hello hazar" {
		t.Fatalf("Wednesday: %d %q", r.code, r.body)
	}
	if f.op.tokenCalls.Load() != 1 {
		t.Fatalf("refreshes %d, want 1", f.op.tokenCalls.Load())
	}
	f.op.deny("hazar")
	f.clock.advance(DefaultRecheckInterval)
	if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
		t.Fatalf("after removal: %d, want 401", r.code)
	}
	if _, ok := b.cookies[DefaultCookieName]; ok {
		t.Error("the refused session's cookie was not cleared")
	}
	// The saved copy from Monday carries a refresh token the server already
	// rotated, and the person is removed: refused.
	b.restore(saved)
	if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
		t.Fatalf("saved cookie after removal: %d, want 401", r.code)
	}
}

// TestSession_SavedCopyRefusedAfterServerSaysNo: a copy of the cookie
// taken before the server said no is refused, both when the copy is the
// same one the refused request carried and inside the window where a
// finished re-check is remembered.
func TestSession_SavedCopyRefusedAfterServerSaysNo(t *testing.T) {
	f := newFixture(t, algEdDSA)
	b := f.signIn("hazar", "/")
	f.clock.advance(DefaultRecheckInterval)
	saved := b.snapshot()
	f.op.deny("hazar")
	if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
		t.Fatalf("refused request: %d", r.code)
	}
	b.restore(saved)
	if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
		t.Fatalf("saved copy right after: %d", r.code)
	}
	f.clock.advance(recentRecheckTTL + time.Second)
	b.restore(saved)
	if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
		t.Fatalf("saved copy later: %d", r.code)
	}
}

// TestSession_FreshNoRecheck: within the interval nothing calls the
// server; past it one refresh rotates the tokens and rewrites the cookie.
func TestSession_FreshNoRecheck(t *testing.T) {
	f := newFixture(t, algEdDSA)
	b := f.signIn("alice", "/")
	before := b.cookies[DefaultCookieName].Value
	f.clock.advance(DefaultRecheckInterval - time.Second)
	apiGet(b, "/")
	if n := f.op.tokenCalls.Load(); n != 0 {
		t.Fatalf("refreshes %d within the interval", n)
	}
	f.clock.advance(time.Second)
	if r := apiGet(b, "/"); r.code != http.StatusOK {
		t.Fatalf("stale request %d", r.code)
	}
	if n := f.op.tokenCalls.Load(); n != 1 {
		t.Fatalf("refreshes %d, want 1", n)
	}
	if b.cookies[DefaultCookieName].Value == before {
		t.Error("cookie not rewritten after the refresh")
	}
	if !f.events.has(EventRefresh, "") {
		t.Errorf("events %v", f.events.kinds())
	}
}

// TestSession_RecheckEveryRequest: interval zero asks on every request.
func TestSession_RecheckEveryRequest(t *testing.T) {
	f := newFixture(t, algEdDSA, WithRecheckInterval(RecheckEveryRequest))
	b := f.signIn("alice", "/")
	for range 3 {
		f.clock.advance(recentRecheckTTL) // past the remembered result
		if r := apiGet(b, "/"); r.code != http.StatusOK {
			t.Fatalf("%d", r.code)
		}
	}
	if n := f.op.tokenCalls.Load(); n != 3 {
		t.Fatalf("refreshes %d, want 3", n)
	}
}

// TestSession_Lifetimes: idle expiry, absolute expiry, and sliding.
func TestSession_Lifetimes(t *testing.T) {
	lt := WithLifetimes(Lifetimes{Idle: time.Hour, Absolute: 3 * time.Hour})
	t.Run("idle", func(t *testing.T) {
		f := newFixture(t, algEdDSA, lt)
		b := f.signIn("alice", "/")
		f.clock.advance(time.Hour)
		if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
			t.Fatalf("idle session %d", r.code)
		}
		if !f.events.has(EventRefuse, ReasonIdleExpired) {
			t.Errorf("events %v", f.events.kinds())
		}
	})
	t.Run("sliding then absolute", func(t *testing.T) {
		f := newFixture(t, algEdDSA, lt)
		b := f.signIn("alice", "/")
		for range 5 { // 2.5 hours of use, every 30 minutes
			f.clock.advance(30 * time.Minute)
			if r := apiGet(b, "/"); r.code != http.StatusOK {
				t.Fatalf("active session refused: %d", r.code)
			}
		}
		f.clock.advance(30 * time.Minute)
		if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
			t.Fatalf("past absolute %d", r.code)
		}
		if !f.events.has(EventRefuse, ReasonAbsoluteExpired) {
			t.Errorf("events %v", f.events.kinds())
		}
	})
	t.Run("cookie expiry", func(t *testing.T) {
		f := newFixture(t, algEdDSA, lt)
		b := f.signIn("alice", "/")
		c := b.cookies[DefaultCookieName]
		if c.MaxAge != int(time.Hour/time.Second) {
			t.Fatalf("cookie Max-Age %d, want the idle lifetime", c.MaxAge)
		}
	})
}

// TestSession_SingleFlight: many concurrent requests of one stale session
// spend its refresh token once, and every one is let through with the new
// cookie. Run with -race.
func TestSession_SingleFlight(t *testing.T) {
	f := newFixture(t, algEdDSA)
	b := f.signIn("alice", "/")
	f.op.set(func(op *testOP) { op.refreshDelay = 50 * time.Millisecond })
	f.clock.advance(DefaultRecheckInterval)
	jar := b.snapshot()
	const n = 20
	var wg sync.WaitGroup
	codes := make([]int, n)
	values := make([]string, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tab := newBrowser(t, f.h)
			tab.restore(jar)
			codes[i] = apiGet(tab, "/").code
			values[i] = tab.cookies[DefaultCookieName].Value
		}()
	}
	wg.Wait()
	if got := f.op.tokenCalls.Load(); got != 1 {
		t.Fatalf("refresh grants %d, want 1", got)
	}
	for i := range n {
		if codes[i] != http.StatusOK || values[i] != values[0] {
			t.Fatalf("request %d: %d, cookie same as first: %v", i, codes[i], values[i] == values[0])
		}
	}
}

// TestSession_LateTabReusesFinishedRecheck: a request carrying the old
// cookie that arrives after the re-check finished (the two tabs did not
// overlap) gets the same result instead of spending the rotated refresh
// token, which the server would read as reuse and revoke the family for.
func TestSession_LateTabReusesFinishedRecheck(t *testing.T) {
	f := newFixture(t, algEdDSA)
	b := f.signIn("alice", "/")
	f.clock.advance(DefaultRecheckInterval)
	old := b.snapshot()
	if r := apiGet(b, "/"); r.code != http.StatusOK {
		t.Fatal(r.code)
	}
	f.clock.advance(2 * time.Second)
	late := newBrowser(t, f.h)
	late.restore(old)
	if r := apiGet(late, "/"); r.code != http.StatusOK {
		t.Fatalf("late tab %d", r.code)
	}
	if got := f.op.tokenCalls.Load(); got != 1 {
		t.Fatalf("refresh grants %d, want 1 (the late tab spent the old token)", got)
	}
	// Both tabs still work afterwards: the family was never revoked.
	f.clock.advance(DefaultRecheckInterval)
	if r := apiGet(b, "/"); r.code != http.StatusOK {
		t.Fatalf("first tab after: %d", r.code)
	}
}

// TestSession_OutageGrace: an unreachable server keeps the last "yes" for
// the grace, counted from CheckedAt, then refuses with 503 while keeping
// the session, which works again the moment the server answers.
func TestSession_OutageGrace(t *testing.T) {
	f := newFixture(t, algEdDSA)
	b := f.signIn("alice", "/")
	f.op.down.Store(true)
	f.clock.advance(DefaultRecheckInterval)
	if r := apiGet(b, "/"); r.code != http.StatusOK {
		t.Fatalf("within grace %d", r.code)
	}
	if !f.events.has(EventGrace, "") {
		t.Errorf("events %v", f.events.kinds())
	}
	f.clock.advance(DefaultOutageGrace - DefaultRecheckInterval)
	if r := apiGet(b, "/"); r.code != http.StatusOK {
		t.Fatalf("at the end of grace %d", r.code)
	}
	f.clock.advance(time.Second + recentRecheckTTL)
	if r := apiGet(b, "/"); r.code != http.StatusServiceUnavailable {
		t.Fatalf("past grace %d, want 503", r.code)
	}
	if _, ok := b.cookies[DefaultCookieName]; !ok {
		t.Fatal("the session was dropped during an outage")
	}
	f.op.down.Store(false)
	f.clock.advance(recentRecheckTTL)
	if r := apiGet(b, "/"); r.code != http.StatusOK {
		t.Fatalf("after the outage %d", r.code)
	}
}

// TestSession_NoOutageGrace refuses at once.
func TestSession_NoOutageGrace(t *testing.T) {
	f := newFixture(t, algEdDSA, WithOutageGrace(NoOutageGrace))
	b := f.signIn("alice", "/")
	f.op.down.Store(true)
	f.clock.advance(DefaultRecheckInterval)
	if r := apiGet(b, "/"); r.code != http.StatusServiceUnavailable {
		t.Fatalf("%d, want 503", r.code)
	}
}

// TestSession_NoOutageGraceSameInstant: with RecheckEveryRequest and no
// grace, an outage refuses even in the very instant the last "yes" was
// given.
func TestSession_NoOutageGraceSameInstant(t *testing.T) {
	f := newFixture(t, algEdDSA, WithRecheckInterval(RecheckEveryRequest), WithOutageGrace(NoOutageGrace))
	b := f.signIn("alice", "/")
	f.op.down.Store(true)
	if r := apiGet(b, "/"); r.code != http.StatusServiceUnavailable {
		t.Fatalf("%d, want 503", r.code)
	}
}

// TestSession_TooLargeAtRefresh: a refresh that makes the session too big
// for the cookie ends it (its refresh token is spent) instead of keeping a
// cookie that can no longer be re-checked.
func TestSession_TooLargeAtRefresh(t *testing.T) {
	f := newFixture(t, algEdDSA)
	f.op.set(func(op *testOP) { op.refreshID = true })
	b := f.signIn("alice", "/")
	f.op.set(func(op *testOP) { op.extraID["blob"] = strings.Repeat("x", 9000) })
	f.clock.advance(DefaultRecheckInterval)
	if r := apiGet(b, "/"); r.code != http.StatusInternalServerError {
		t.Fatalf("%d, want 500", r.code)
	}
	if _, ok := b.cookies[DefaultCookieName]; ok {
		t.Fatal("cookie kept after an oversize refresh")
	}
}

// TestSession_GraceNeverPastLifetimes: the grace does not keep a session
// past its idle lifetime.
func TestSession_GraceNeverPastLifetimes(t *testing.T) {
	f := newFixture(t, algEdDSA, WithLifetimes(Lifetimes{Idle: 2 * time.Minute}), WithOutageGrace(time.Hour))
	b := f.signIn("alice", "/")
	f.op.down.Store(true)
	f.clock.advance(2 * time.Minute)
	if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
		t.Fatalf("%d, want 401", r.code)
	}
}

// TestSession_TamperedCookie: a changed byte, a dropped chunk, a cookie of
// another name or another key: no session, and the bad cookie is cleared.
func TestSession_TamperedCookie(t *testing.T) {
	f := newFixture(t, algEdDSA)
	b := f.signIn("alice", "/")
	c := b.cookies[DefaultCookieName]
	v := []byte(c.Value)
	v[len(v)/2] ^= 1
	if v[len(v)/2] == '-' || v[len(v)/2] == '_' {
		v[len(v)/2] = 'A'
	}
	c.Value = string(v)
	if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
		t.Fatalf("tampered cookie %d", r.code)
	}
	if _, ok := b.cookies[DefaultCookieName]; ok {
		t.Error("tampered cookie not cleared")
	}
	// The flow cookie's sealed value presented as the session cookie.
	b2 := newBrowser(t, f.h)
	f.startLogin(b2)
	b2.cookies[DefaultCookieName] = b2.cookies[DefaultCookieName+FlowCookieSuffix]
	if r := apiGet(b2, "/"); r.code != http.StatusUnauthorized {
		t.Fatalf("flow cookie as session %d", r.code)
	}
}

// TestSession_KeyRotation: a cookie sealed before a rotation still opens
// with the old secret listed as previous, and does not once it is dropped.
func TestSession_KeyRotation(t *testing.T) {
	clock := newTestClock()
	op := newTestOP(t, clock, algEdDSA)
	f := newFixtureWith(t, op, testConfig(op))
	b := f.signIn("alice", "/")
	newSecret := Secret(strings.Repeat("n", 40))
	rotated := testConfig(op)
	rotated.SessionSecret, rotated.PreviousSessionSecrets = newSecret, []Secret{testSecret}
	f2 := newFixtureWith(t, op, rotated)
	b.h = f2.h
	if r := apiGet(b, "/"); r.code != http.StatusOK {
		t.Fatalf("old cookie after rotation %d", r.code)
	}
	dropped := testConfig(op)
	dropped.SessionSecret = newSecret
	f3 := newFixtureWith(t, op, dropped)
	b2 := f.signIn("bob", "/")
	b2.h = f3.h
	if r := apiGet(b2, "/"); r.code != http.StatusUnauthorized {
		t.Fatalf("cookie under a retired key %d", r.code)
	}
}

// TestSession_Chunking: a session too big for one cookie spans two or
// three and round-trips; one beyond three is refused at sign-in with no
// cookie written; a missing chunk is no session.
func TestSession_Chunking(t *testing.T) {
	t.Run("two chunks", func(t *testing.T) {
		f := newFixture(t, algEdDSA)
		f.op.set(func(op *testOP) { op.extraID["blob"] = strings.Repeat("x", 3000) })
		b := f.signIn("alice", "/")
		if _, ok := b.cookies[chunkName(DefaultCookieName, 1)]; !ok {
			t.Fatalf("no second chunk; cookies %v", len(b.cookies))
		}
		if r := apiGet(b, "/"); r.code != http.StatusOK {
			t.Fatalf("chunked session %d", r.code)
		}
		delete(b.cookies, chunkName(DefaultCookieName, 1))
		if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
			t.Fatalf("missing chunk %d", r.code)
		}
	})
	t.Run("too large", func(t *testing.T) {
		f := newFixture(t, algEdDSA)
		f.op.set(func(op *testOP) { op.extraID["blob"] = strings.Repeat("x", 9000) })
		b, code := f.callbackWith("alice", nil)
		if code != http.StatusInternalServerError {
			t.Fatalf("oversize session %d, want 500", code)
		}
		if _, ok := b.cookies[DefaultCookieName]; ok {
			t.Fatal("an oversize session wrote a cookie")
		}
		if !f.events.has(EventRefuse, ReasonStoreFailed) {
			t.Errorf("events %v", f.events.kinds())
		}
	})
	t.Run("shrinks back", func(t *testing.T) {
		f := newFixture(t, algEdDSA)
		f.op.set(func(op *testOP) { op.extraID["blob"] = strings.Repeat("x", 3000); op.refreshID = true })
		b := f.signIn("alice", "/")
		if _, ok := b.cookies[chunkName(DefaultCookieName, 1)]; !ok {
			t.Fatal("no second chunk")
		}
		// The refresh brings a small ID token, so the session shrinks.
		f.op.set(func(op *testOP) { op.extraID = map[string]any{} })
		f.clock.advance(DefaultRecheckInterval)
		if r := apiGet(b, "/"); r.code != http.StatusOK {
			t.Fatal(r.code)
		}
		if _, ok := b.cookies[chunkName(DefaultCookieName, 1)]; ok {
			t.Fatal("the second chunk outlived the smaller session")
		}
		if r := apiGet(b, "/"); r.code != http.StatusOK {
			t.Fatalf("shrunk session %d", r.code)
		}
	})
}

// TestSession_CookieOfAnotherIssuer: a session whose User names another
// issuer (a store shared by two Clients) is not honoured.
func TestSession_CookieOfAnotherIssuer(t *testing.T) {
	f := newFixture(t, algEdDSA)
	b := newBrowser(t, f.h)
	s := Session{ID: randomToken(), User: User{Issuer: "https://other.example", Subject: "alice"}, CreatedAt: f.clock.now(), LastSeenAt: f.clock.now(), CheckedAt: f.clock.now()}
	raw, _ := json.Marshal(s)
	sealed, err := f.c.set.sealer.Seal(t.Context(), raw, DefaultCookieName)
	if err != nil {
		t.Fatal(err)
	}
	b.cookies[DefaultCookieName] = &http.Cookie{Name: DefaultCookieName, Value: sealed}
	if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
		t.Fatalf("%d, want 401", r.code)
	}
}

// TestSession_MemoryStore: the server-side store keeps only an ID in the
// cookie, and expires and sweeps by its own clock.
func TestSession_MemoryStore(t *testing.T) {
	st := NewMemoryStore()
	f := newFixture(t, algEdDSA, WithSessionStore(st))
	b := f.signIn("alice", "/")
	if r := apiGet(b, "/"); r.code != http.StatusOK {
		t.Fatal(r.code)
	}
	if n := len(st.rows); n != 1 {
		t.Fatalf("rows %d", n)
	}
	ctx := t.Context()
	wall := time.Now()
	st.now = func() time.Time { return wall }
	if _, err := st.Save(ctx, Session{ID: "old", ExpiresAt: wall.Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(ctx, []byte("old")); !errors.Is(err, ErrNoSession) {
		t.Fatalf("expired row loaded: %v", err)
	}
	if _, err := st.Save(ctx, Session{ID: "stale", ExpiresAt: wall.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	wall = wall.Add(2 * memorySweepEvery)
	if _, err := st.Save(ctx, Session{ID: "new", ExpiresAt: wall.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.rows["stale"]; ok {
		t.Fatal("sweep kept an expired row")
	}
	if _, err := st.Save(ctx, Session{}); err == nil {
		t.Fatal("saved a session without an ID")
	}
	if err := st.Delete(ctx, Session{ID: "absent"}); err != nil {
		t.Fatal(err)
	}
}
