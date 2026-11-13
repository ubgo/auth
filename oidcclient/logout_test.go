package oidcclient

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestLogout: POST from this origin ends the session in the store and
// sends the browser to the end-session endpoint with the ID token as hint;
// a copy of the cookie is refused afterwards (server-side store).
func TestLogout(t *testing.T) {
	st := NewMemoryStore()
	f := newFixture(t, algEdDSA, WithSessionStore(st), WithPostLogoutPath("/bye"))
	b := f.signIn("alice", "/")
	saved := b.snapshot()
	res := b.do(http.MethodPost, "/auth/logout", url.Values{}, headerOrigin, testAppURL)
	if res.Code != http.StatusSeeOther {
		t.Fatalf("logout %d", res.Code)
	}
	u, _ := url.Parse(res.Header().Get(headerLocation))
	q := u.Query()
	if u.Path != "/logout" || q.Get(paramIDTokenHint) == "" || q.Get(paramPostLogoutRedirect) != testAppURL+"/bye" || q.Get(paramClientID) != f.op.clientID {
		t.Fatalf("end-session URL %s", u)
	}
	if _, ok := b.cookies[DefaultCookieName]; ok {
		t.Fatal("cookie kept")
	}
	b.restore(saved)
	if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
		t.Fatalf("saved cookie after logout %d", r.code)
	}
}

// TestLogout_SameOriginOnly: GET, a cross-site POST, a POST without Origin
// or Sec-Fetch-Site, and an Origin of "null" are refused; Sec-Fetch-Site
// same-origin is accepted.
func TestLogout_SameOriginOnly(t *testing.T) {
	f := newFixture(t, algEdDSA)
	b := f.signIn("alice", "/")
	cases := []struct {
		method string
		hdr    []string
		want   int
	}{
		{http.MethodGet, nil, http.StatusMethodNotAllowed},
		{http.MethodPost, []string{headerOrigin, "https://evil.example"}, http.StatusForbidden},
		{http.MethodPost, []string{headerOrigin, "null"}, http.StatusForbidden},
		{http.MethodPost, []string{headerOrigin, "https://app.example.evil.example"}, http.StatusForbidden},
		{http.MethodPost, []string{headerSecFetchSite, "cross-site"}, http.StatusForbidden},
		{http.MethodPost, nil, http.StatusForbidden},
	}
	for _, tc := range cases {
		if res := b.do(tc.method, "/auth/logout", url.Values{}, tc.hdr...); res.Code != tc.want {
			t.Errorf("%s %v: %d, want %d", tc.method, tc.hdr, res.Code, tc.want)
		}
		if !f.signedIn(b) {
			t.Fatalf("%s %v signed the person out", tc.method, tc.hdr)
		}
	}
	if res := b.do(http.MethodPost, "/auth/logout", url.Values{}, headerSecFetchSite, fetchSameOrigin); res.Code != http.StatusSeeOther {
		t.Fatalf("same-origin logout %d", res.Code)
	}
	if f.signedIn(b) {
		t.Fatal("still signed in")
	}
}

// TestLogout_NoEndSession: a server without an end-session endpoint ends
// the app's session and lands on the post-logout path; a server that cannot
// be reached does the same.
func TestLogout_NoEndSession(t *testing.T) {
	f := newFixture(t, algEdDSA)
	f.op.set(func(op *testOP) { op.meta = map[string]any{"end_session_endpoint": ""} })
	b := f.signIn("alice", "/")
	res := b.do(http.MethodPost, "/auth/logout", url.Values{}, headerOrigin, "HTTPS://APP.EXAMPLE")
	if res.Code != http.StatusSeeOther || res.Header().Get(headerLocation) != siteRoot {
		t.Fatalf("%d %q", res.Code, res.Header().Get(headerLocation))
	}
	// Signed out already: logout again still lands.
	if res := b.do(http.MethodPost, "/auth/logout", url.Values{}, headerOrigin, testAppURL); res.Code != http.StatusSeeOther {
		t.Fatalf("logout without a session %d", res.Code)
	}
}

// TestLogout_StoreDeleteFails: a store that cannot forget the session is
// reported, not hidden behind a redirect.
func TestLogout_StoreDeleteFails(t *testing.T) {
	st := &failingStore{SessionStore: NewMemoryStore()}
	f := newFixture(t, algEdDSA, WithSessionStore(st))
	b := f.signIn("alice", "/")
	st.set(func(s *failingStore) { s.failDelete = true })
	if res := b.do(http.MethodPost, "/auth/logout", url.Values{}, headerOrigin, testAppURL); res.Code != http.StatusInternalServerError {
		t.Fatalf("%d, want 500", res.Code)
	}
}

// backchannelPost posts a logout token to the fixture.
func (f *fixture) backchannelPost(token string) int {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/backchannel", strings.NewReader(url.Values{paramLogoutToken: {token}}.Encode()))
	req.Header.Set(headerContentType, mediaTypeForm)
	f.h.ServeHTTP(rec, req)
	return rec.Code
}

// TestBackchannel: a valid logout token ends the person's sessions at
// once, cookie or not; by sid it ends only that browser's.
func TestBackchannel(t *testing.T) {
	t.Run("by sub", func(t *testing.T) {
		f := newFixture(t, algEdDSA, WithSessionStore(NewMemoryStore()))
		a1, a2, bob := f.signIn("alice", "/"), f.signIn("alice", "/"), f.signIn("bob", "/")
		if code := f.backchannelPost(f.op.logoutToken("alice", "", nil)); code != http.StatusOK {
			t.Fatalf("%d", code)
		}
		if f.signedIn(a1) || f.signedIn(a2) {
			t.Fatal("alice still signed in")
		}
		if !f.signedIn(bob) {
			t.Fatal("bob signed out")
		}
		if !f.events.has(EventBackchannelLogout, "") {
			t.Errorf("events %v", f.events.kinds())
		}
	})
	t.Run("by sid only", func(t *testing.T) {
		f := newFixture(t, algEdDSA, WithSessionStore(NewMemoryStore()))
		a := f.signIn("alice", "/")
		if code := f.backchannelPost(f.op.logoutToken("", "sid-other", nil)); code != http.StatusOK || !f.signedIn(a) {
			t.Fatalf("another sid: %d", code)
		}
		if code := f.backchannelPost(f.op.logoutToken("", "sid-alice", nil)); code != http.StatusOK || f.signedIn(a) {
			t.Fatalf("own sid: %d", code)
		}
	})
}

// TestBackchannel_Refusals: every logout token the specification says to
// refuse is 400 and ends nothing.
func TestBackchannel_Refusals(t *testing.T) {
	cases := map[string]func(c map[string]any){
		"no events":           func(c map[string]any) { delete(c, "events") },
		"other event":         func(c map[string]any) { c["events"] = map[string]any{"http://example/other": map[string]any{}} },
		"event not an object": func(c map[string]any) { c["events"] = map[string]any{backchannelEvent: "yes"} },
		"nonce present":       func(c map[string]any) { c["nonce"] = "n" },
		"no sub nor sid":      func(c map[string]any) { delete(c, "sub") },
		"no jti":              func(c map[string]any) { delete(c, "jti") },
		"wrong audience":      func(c map[string]any) { c["aud"] = "oac_other" },
		"wrong issuer":        func(c map[string]any) { c["iss"] = "https://evil.example" },
		"expired":             func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
		"too old":             func(c map[string]any) { c["iat"] = time.Now().Add(-10 * time.Minute).Unix(); delete(c, "exp") },
		"no iat":              func(c map[string]any) { delete(c, "iat") },
		"iat in the future":   func(c map[string]any) { c["iat"] = time.Now().Add(10 * time.Minute).Unix() },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, algEdDSA, WithSessionStore(NewMemoryStore()))
			b := f.signIn("alice", "/")
			if code := f.backchannelPost(f.op.logoutToken("alice", "", mutate)); code != http.StatusBadRequest {
				t.Fatalf("%d, want 400", code)
			}
			if !f.signedIn(b) {
				t.Fatal("a refused logout token ended the session")
			}
		})
	}
	t.Run("an ID token is not a logout token", func(t *testing.T) {
		f := newFixture(t, algEdDSA, WithSessionStore(NewMemoryStore()))
		f.signIn("alice", "/")
		if code := f.backchannelPost(f.op.idToken("alice", "", "sid-alice", "")); code != http.StatusBadRequest {
			t.Fatalf("%d", code)
		}
	})
	t.Run("bad signature and bad alg", func(t *testing.T) {
		f := newFixture(t, algEdDSA, WithSessionStore(NewMemoryStore()))
		tok := f.op.logoutToken("alice", "", nil)
		if code := f.backchannelPost(tok[:len(tok)-4] + "AAAA"); code != http.StatusBadRequest {
			t.Fatalf("bad signature %d", code)
		}
		parts := strings.Split(tok, ".")
		parts[0] = b64([]byte(`{"alg":"none"}`))
		if code := f.backchannelPost(parts[0] + "." + parts[1] + "."); code != http.StatusBadRequest {
			t.Fatalf("alg none %d", code)
		}
		if code := f.backchannelPost(""); code != http.StatusBadRequest {
			t.Fatalf("empty %d", code)
		}
	})
	t.Run("replay", func(t *testing.T) {
		f := newFixture(t, algEdDSA, WithSessionStore(NewMemoryStore()))
		tok := f.op.logoutToken("alice", "", nil)
		if code := f.backchannelPost(tok); code != http.StatusOK {
			t.Fatal(code)
		}
		if code := f.backchannelPost(tok); code != http.StatusBadRequest {
			t.Fatalf("replayed token %d, want 400", code)
		}
	})
	t.Run("unsupported store", func(t *testing.T) {
		f := newFixture(t, algEdDSA)
		if code := f.backchannelPost(f.op.logoutToken("alice", "", nil)); code != http.StatusNotImplemented {
			t.Fatalf("%d, want 501", code)
		}
	})
	t.Run("store failure can be retried", func(t *testing.T) {
		st := &revokeFailing{MemoryStore: NewMemoryStore(), fail: true}
		f := newFixture(t, algEdDSA, WithSessionStore(st))
		tok := f.op.logoutToken("alice", "", nil)
		if code := f.backchannelPost(tok); code != http.StatusInternalServerError {
			t.Fatalf("%d", code)
		}
		st.fail = false
		if code := f.backchannelPost(tok); code != http.StatusOK {
			t.Fatalf("retry %d", code)
		}
	})
	t.Run("keys unreachable", func(t *testing.T) {
		f := newFixture(t, algEdDSA, WithSessionStore(NewMemoryStore()))
		tok := f.op.logoutToken("alice", "", nil)
		f.op.srv.Config.Handler = http.NotFoundHandler()
		if code := f.backchannelPost(tok); code != http.StatusServiceUnavailable {
			t.Fatalf("%d, want 503", code)
		}
	})
}

// revokeFailing fails RevokeSessions on demand.
type revokeFailing struct {
	*MemoryStore
	fail bool
}

func (r *revokeFailing) RevokeSessions(ctx context.Context, t LogoutTarget) (int, error) {
	if r.fail {
		return 0, errBoom
	}
	return r.MemoryStore.RevokeSessions(ctx, t)
}

// TestReplayCache_Full: a full cache drops expired entries, and refuses
// when every entry is live.
func TestReplayCache_Full(t *testing.T) {
	var rc replayCache
	now := time.Now()
	for i := range maxReplayEntries {
		rc.remember(string(rune(i))+"x", now.Add(time.Minute), now)
	}
	if rc.remember("new", now.Add(time.Minute), now) {
		t.Fatal("a full cache of live entries accepted another")
	}
	if !rc.remember("new", now.Add(time.Hour), now.Add(2*time.Minute)) {
		t.Fatal("a full cache of expired entries refused")
	}
}

// TestLogoutTarget_Matches pins the rule every SessionRevoker applies.
func TestLogoutTarget_Matches(t *testing.T) {
	s := Session{User: User{Issuer: "i", Subject: "alice"}, ProviderSessionID: "s1"}
	for _, tc := range []struct {
		t    LogoutTarget
		want bool
	}{
		{LogoutTarget{Issuer: "i", Subject: "alice"}, true},
		{LogoutTarget{Issuer: "i", ProviderSessionID: "s1"}, true},
		{LogoutTarget{Issuer: "i", Subject: "alice", ProviderSessionID: "s1"}, true},
		{LogoutTarget{Issuer: "i", Subject: "alice", ProviderSessionID: "s2"}, false},
		{LogoutTarget{Issuer: "i", Subject: "bob"}, false},
		{LogoutTarget{Issuer: "other", Subject: "alice"}, false},
		{LogoutTarget{Issuer: "i"}, false},
		{LogoutTarget{Subject: "alice"}, false},
	} {
		if got := tc.t.Matches(s); got != tc.want {
			t.Errorf("%+v: %v", tc.t, got)
		}
	}
}

// TestOptional: a public page sees the User when Require would let the
// request through, goes on without one otherwise, and a session the server
// refused is ended exactly as under Require.
func TestOptional(t *testing.T) {
	f := newFixture(t, algEdDSA)
	anon := newBrowser(t, f.h)
	if r := apiGet(anon, "/public"); r.code != http.StatusOK || r.body != "public anon" {
		t.Fatalf("anonymous %d %q", r.code, r.body)
	}
	if len(f.events.kinds()) != 0 {
		t.Fatalf("Optional reported an anonymous visit: %v", f.events.kinds())
	}
	b := f.signIn("alice", "/")
	if r := apiGet(b, "/public"); r.body != "public alice" {
		t.Fatalf("signed in %q", r.body)
	}
	f.op.deny("alice")
	f.clock.advance(DefaultRecheckInterval)
	if r := apiGet(b, "/public"); r.code != http.StatusOK || r.body != "public anon" {
		t.Fatalf("refused session %d %q", r.code, r.body)
	}
	if _, ok := b.cookies[DefaultCookieName]; ok {
		t.Fatal("refused session kept under Optional")
	}
	if !f.events.has(EventRefuse, ReasonServerRefused) {
		t.Errorf("events %v", f.events.kinds())
	}
}

// TestOptional_Authorizer: Optional applies the Authorizer too.
func TestOptional_Authorizer(t *testing.T) {
	f := newFixture(t, algEdDSA, WithAuthorizer(func(context.Context, AuthorizeRequest) (Decision, error) { return Deny, errors.New("x") }))
	b := f.signIn("alice", "/")
	if r := apiGet(b, "/public"); r.body != "public anon" {
		t.Fatalf("%q", r.body)
	}
}

// TestLogout_RevokesRefreshToken: under the stateless cookie store,
// deleting the session forgets nothing, so logout revokes the refresh
// token: a cookie copy saved before logout is refused at its next
// re-check.
func TestLogout_RevokesRefreshToken(t *testing.T) {
	f := newFixture(t, algEdDSA)
	b := f.signIn("alice", "/")
	saved := b.snapshot()
	if res := b.do(http.MethodPost, "/auth/logout", url.Values{}, headerOrigin, testAppURL); res.Code != http.StatusSeeOther {
		t.Fatalf("logout %d", res.Code)
	}
	if f.op.revokeCalls.Load() != 1 {
		t.Fatalf("revocations %d, want 1", f.op.revokeCalls.Load())
	}
	b.restore(saved)
	f.clock.advance(DefaultRecheckInterval)
	if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
		t.Fatalf("saved cookie after logout %d, want 401", r.code)
	}
}

// TestLogout_RevocationFails: a revocation endpoint that fails does not
// block the sign-out; the failure is observed as EventRevokeFailed, just
// before the EventLogout of the same sign-out, which carries no error. A
// server with no revocation endpoint is observed the same way.
func TestLogout_RevocationFails(t *testing.T) {
	f := newFixture(t, algEdDSA)
	b := f.signIn("alice", "/")
	f.op.revokeDown.Store(true)
	res := b.do(http.MethodPost, "/auth/logout", url.Values{}, headerOrigin, testAppURL)
	if res.Code != http.StatusSeeOther || !strings.Contains(res.Header().Get(headerLocation), "/logout?") {
		t.Fatalf("logout %d %q", res.Code, res.Header().Get(headerLocation))
	}
	if _, ok := b.cookies[DefaultCookieName]; ok {
		t.Fatal("cookie kept")
	}
	checkRevokeFailed(t, f.events.ev, func(err error) bool { return errors.Is(err, ErrProviderUnavailable) })
	// A server without the endpoint: signed out, reported, no request.
	g := newFixture(t, algEdDSA)
	g.op.set(func(op *testOP) { op.meta = map[string]any{"revocation_endpoint": ""} })
	b = g.signIn("alice", "/")
	if res := b.do(http.MethodPost, "/auth/logout", url.Values{}, headerOrigin, testAppURL); res.Code != http.StatusSeeOther {
		t.Fatalf("logout without revocation %d", res.Code)
	}
	if g.op.revokeCalls.Load() != 0 {
		t.Fatal("revoked without an endpoint")
	}
	checkRevokeFailed(t, g.events.ev, func(err error) bool { return errors.Is(err, errNoRevocation) })
}

// checkRevokeFailed asserts the events of one sign-out end with an
// EventRevokeFailed whose Err matches, followed by an EventLogout of the
// same session with no Err.
func checkRevokeFailed(t *testing.T, events []Event, match func(error) bool) {
	t.Helper()
	n := len(events)
	if n < 2 || events[n-2].Kind != EventRevokeFailed || events[n-1].Kind != EventLogout {
		kinds := make([]EventKind, 0, n)
		for _, e := range events {
			kinds = append(kinds, e.Kind)
		}
		t.Fatalf("events %v, want ... %s, %s", kinds, EventRevokeFailed, EventLogout)
	}
	rf, lo := events[n-2], events[n-1]
	if !match(rf.Err) {
		t.Fatalf("EventRevokeFailed.Err = %v, want the revocation failure", rf.Err)
	}
	if rf.SessionID == "" || rf.SessionID != lo.SessionID || rf.Subject != lo.Subject {
		t.Fatalf("revoke_failed session %q/%q, logout %q/%q", rf.SessionID, rf.Subject, lo.SessionID, lo.Subject)
	}
	if lo.Err != nil {
		t.Fatalf("EventLogout.Err = %v, want nil (the failure has its own event)", lo.Err)
	}
}

// TestNoRevocationEndpoint_Warns: a discovery document without a
// revocation endpoint is logged once, at New for a given document and at
// the first fetch otherwise.
func TestNoRevocationEndpoint_Warns(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	m := ProviderMetadata{Issuer: "https://l.example", AuthorizationEndpoint: "https://l.example/a", TokenEndpoint: "https://l.example/t", JWKSURI: "https://l.example/j"}
	if _, err := New(Config{Issuer: m.Issuer, ClientID: "x", ClientSecret: "s", AppURL: testAppURL, SessionSecret: testSecret}, WithDiscovery(m), WithLogger(logger)); err != nil {
		t.Fatal(err)
	}
	if strings.Count(buf.String(), "revocation_endpoint") != 1 {
		t.Fatalf("log %q", buf.String())
	}
	buf.Reset()
	f := newFixture(t, algEdDSA, WithLogger(logger))
	f.op.set(func(op *testOP) { op.meta = map[string]any{"revocation_endpoint": ""} })
	for range 2 {
		if _, err := f.c.provider.Metadata(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Count(buf.String(), "revocation_endpoint") != 1 {
		t.Fatalf("log %q", buf.String())
	}
}
