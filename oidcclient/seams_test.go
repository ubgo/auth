package oidcclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every seam is tested four ways: a custom value that allows, one that
// denies, one that fails (which must refuse), and the default unchanged.

var errBoom = errors.New("boom")

// TestSeam_UserMapper: OnLogin mapping.
func TestSeam_UserMapper(t *testing.T) {
	t.Run("custom allow", func(t *testing.T) {
		var reasons []MapReason
		var mu sync.Mutex
		f := newFixture(t, algEdDSA, WithUserMapper(func(_ context.Context, in MapUserRequest) (User, error) {
			mu.Lock()
			reasons = append(reasons, in.Reason)
			mu.Unlock()
			if in.Reason == MapRefresh && (in.Previous == nil || in.Previous.ID != "app-1") {
				return User{}, fmt.Errorf("refresh without the previous user: %+v", in.Previous)
			}
			if in.AccessToken.IsZero() || in.Provider == nil {
				return User{}, errors.New("no access token or provider")
			}
			u := DefaultUser(in.Identity)
			u.ID, u.Roles, u.Claims = "app-1", []string{"admin"}, nil
			return u, nil
		}))
		f.op.set(func(op *testOP) { op.refreshID = true })
		app := f.c.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, _ := UserFrom(r.Context())
			fmt.Fprintf(w, "%s %v", u.ID, u.Roles)
		}))
		b := f.signIn("alice", "/")
		b.h = app
		if r := apiGet(b, "/"); r.body != "app-1 [admin]" {
			t.Fatalf("mapped user %q", r.body)
		}
		f.clock.advance(DefaultRecheckInterval)
		if r := apiGet(b, "/"); r.code != http.StatusOK {
			t.Fatalf("after refresh %d %s", r.code, r.body)
		}
		if !slices.Equal(reasons, []MapReason{MapSignIn, MapRefresh}) {
			t.Fatalf("mapper reasons %v", reasons)
		}
	})
	t.Run("custom deny", func(t *testing.T) {
		f := newFixture(t, algEdDSA, WithUserMapper(func(_ context.Context, in MapUserRequest) (User, error) {
			if !in.Identity.EmailVerified {
				return User{}, ErrAccessDenied
			}
			return DefaultUser(in.Identity), nil
		}))
		f.op.set(func(op *testOP) { op.extraID["email_verified"] = "false" })
		b, code := f.callbackWith("alice", nil)
		if code != http.StatusForbidden || f.signedIn(b) {
			t.Fatalf("unverified email: %d", code)
		}
		if !f.events.has(EventRefuse, ReasonNotAuthorized) {
			t.Errorf("events %v", f.events.kinds())
		}
	})
	t.Run("error fails closed", func(t *testing.T) {
		f := newFixture(t, algEdDSA, WithUserMapper(func(context.Context, MapUserRequest) (User, error) { return User{}, errBoom }))
		b, code := f.callbackWith("alice", nil)
		if code != http.StatusInternalServerError || f.signedIn(b) {
			t.Fatalf("mapper error: %d", code)
		}
	})
	t.Run("changing the subject fails closed", func(t *testing.T) {
		f := newFixture(t, algEdDSA, WithUserMapper(func(_ context.Context, in MapUserRequest) (User, error) {
			u := DefaultUser(in.Identity)
			u.Subject = "root"
			return u, nil
		}))
		if b, code := f.callbackWith("alice", nil); code != http.StatusInternalServerError || f.signedIn(b) {
			t.Fatalf("subject change: %d", code)
		}
	})
	t.Run("error at refresh ends the session", func(t *testing.T) {
		fail := false
		var mu sync.Mutex
		f := newFixture(t, algEdDSA, WithUserMapper(func(_ context.Context, in MapUserRequest) (User, error) {
			mu.Lock()
			defer mu.Unlock()
			if fail {
				return User{}, ErrAccessDenied
			}
			return DefaultUser(in.Identity), nil
		}))
		f.op.set(func(op *testOP) { op.refreshID = true })
		b := f.signIn("alice", "/")
		mu.Lock()
		fail = true
		mu.Unlock()
		f.clock.advance(DefaultRecheckInterval)
		if r := apiGet(b, "/"); r.code != http.StatusForbidden {
			t.Fatalf("%d, want 403", r.code)
		}
		if _, ok := b.cookies[DefaultCookieName]; ok {
			t.Fatal("session kept after the mapper refused at refresh")
		}
	})
	t.Run("default", func(t *testing.T) {
		f := newFixture(t, algEdDSA)
		var got User
		b := f.signIn("alice", "/")
		b.h = f.c.Require(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got, _ = UserFrom(r.Context()) }))
		apiGet(b, "/")
		if got.ID != "alice" || got.Subject != "alice" || got.Email != "alice@example.com" || !got.EmailVerified || got.Name != "Person alice" || got.Issuer != f.op.issuer() {
			t.Fatalf("default user %+v", got)
		}
		if v, _ := got.Claims.String("sid"); v != "sid-alice" {
			t.Fatalf("claims %v", got.Claims)
		}
	})
}

// TestSeam_Authorizer: the app's own rule.
func TestSeam_Authorizer(t *testing.T) {
	rule := func(_ context.Context, in AuthorizeRequest) (Decision, error) {
		switch {
		case strings.HasPrefix(in.Request.URL.Path, "/boom"):
			return Allow, errBoom
		case strings.HasPrefix(in.Request.URL.Path, "/denied"):
			return Allow, ErrAccessDenied
		case strings.HasPrefix(in.Request.URL.Path, "/admin") && !slices.Contains(in.User.Roles, "admin"):
			return Deny, nil
		case strings.HasPrefix(in.Request.URL.Path, "/forgot"):
			var d Decision // the zero value
			return d, nil
		}
		return Allow, nil
	}
	f := newFixture(t, algEdDSA, WithAuthorizer(rule))
	b := f.signIn("alice", "/")
	for path, want := range map[string]int{
		"/":       http.StatusOK,
		"/admin":  http.StatusForbidden,
		"/forgot": http.StatusForbidden,
		"/boom":   http.StatusInternalServerError,
		"/denied": http.StatusForbidden,
	} {
		if r := apiGet(b, path); r.code != want {
			t.Errorf("%s: %d, want %d", path, r.code, want)
		}
	}
	if !f.events.has(EventRefuse, ReasonHookFailed) || !f.events.has(EventRefuse, ReasonNotAuthorized) {
		t.Errorf("events %v", f.events.kinds())
	}
	// Default: no authorizer, every signed-in person passes.
	f2 := newFixture(t, algEdDSA)
	if r := apiGet(f2.signIn("alice", "/"), "/admin"); r.code != http.StatusOK {
		t.Fatalf("default authorizer %d", r.code)
	}
}

// TestSeam_Rechecker: a custom rechecker that allows, denies, fails, and
// reports an outage; the default refreshes.
func TestSeam_Rechecker(t *testing.T) {
	cases := []struct {
		name  string
		r     Rechecker
		want  int
		ended bool
	}{
		{"custom allow", RecheckerFunc(func(context.Context, RecheckRequest) (RecheckResult, error) {
			return RecheckResult{Decision: Allow}, nil
		}), http.StatusOK, false},
		{"custom deny", RecheckerFunc(func(context.Context, RecheckRequest) (RecheckResult, error) {
			return RecheckResult{}, nil
		}), http.StatusUnauthorized, true},
		{"error with allow fails closed", RecheckerFunc(func(context.Context, RecheckRequest) (RecheckResult, error) {
			return RecheckResult{Decision: Allow}, errBoom
		}), http.StatusUnauthorized, true},
		{"refused and unavailable at once is refused", RecheckerFunc(func(context.Context, RecheckRequest) (RecheckResult, error) {
			return RecheckResult{}, errors.Join(ErrProviderRefused, ErrProviderUnavailable)
		}), http.StatusUnauthorized, true},
		{"outage keeps the grace", RecheckerFunc(func(context.Context, RecheckRequest) (RecheckResult, error) {
			return RecheckResult{}, fmt.Errorf("dns: %w", ErrProviderUnavailable)
		}), http.StatusOK, false},
		{"panic fails closed", RecheckerFunc(func(context.Context, RecheckRequest) (RecheckResult, error) {
			panic("rechecker bug")
		}), http.StatusInternalServerError, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, algEdDSA, WithRechecker(tc.r))
			b := f.signIn("alice", "/")
			f.clock.advance(DefaultRecheckInterval)
			h := b.h
			b.h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer func() {
					if p := recover(); p != nil {
						w.WriteHeader(http.StatusInternalServerError)
					}
				}()
				h.ServeHTTP(w, r)
			})
			if r := apiGet(b, "/"); r.code != tc.want {
				t.Fatalf("%d, want %d", r.code, tc.want)
			}
			if _, ok := b.cookies[DefaultCookieName]; ok == tc.ended {
				t.Fatalf("cookie present %v, want ended %v", ok, tc.ended)
			}
		})
	}
	t.Run("panic releases waiters", func(t *testing.T) {
		var g recheckGroup
		s := Session{ID: "x"}
		func() {
			defer func() { _ = recover() }()
			g.do(t.Context(), s, time.Now, func(context.Context) recheckResult { panic("bug") })
		}()
		res := g.do(t.Context(), s, time.Now, func(context.Context) recheckResult { return recheckResult{} })
		if res.ref != nil {
			t.Fatalf("a later re-check after a panic: %+v", res.ref)
		}
	})
	t.Run("default refreshes", func(t *testing.T) {
		f := newFixture(t, algEdDSA)
		b := f.signIn("alice", "/")
		f.clock.advance(DefaultRecheckInterval)
		apiGet(b, "/")
		if f.op.tokenCalls.Load() != 1 {
			t.Fatal("the default rechecker did not refresh")
		}
	})
	t.Run("refreshed identity of another person", func(t *testing.T) {
		f := newFixture(t, algEdDSA, WithRechecker(RecheckerFunc(func(ctx context.Context, in RecheckRequest) (RecheckResult, error) {
			id := Identity{Issuer: in.Session.User.Issuer, Subject: "mallory"}
			return RecheckResult{Decision: Allow, Refreshed: &Refreshed{tokens: in.Session.Tokens, identity: &id}}, nil
		})))
		b := f.signIn("alice", "/")
		f.clock.advance(DefaultRecheckInterval)
		if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
			t.Fatalf("%d, want 401", r.code)
		}
	})
}

// TestRecheckByIntrospection: allows while the server says active for
// this person and client, refuses once it does not.
func TestRecheckByIntrospection(t *testing.T) {
	f := newFixture(t, algEdDSA, WithRechecker(RecheckByIntrospection()))
	b := f.signIn("alice", "/")
	f.clock.advance(DefaultRecheckInterval)
	if r := apiGet(b, "/"); r.code != http.StatusOK {
		t.Fatalf("active %d", r.code)
	}
	if f.op.tokenCalls.Load() != 0 {
		t.Fatal("introspection refreshed the token")
	}
	f.op.deny("alice")
	f.clock.advance(DefaultRecheckInterval)
	if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
		t.Fatalf("inactive %d", r.code)
	}
	// Another client's token, or another person's, is not this session's.
	for _, answer := range []map[string]any{{"active": true, "sub": "bob"}, {"active": true, "client_id": "oac_other"}} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { writeTestJSON(w, http.StatusOK, answer) }))
		f.c.provider.meta.IntrospectionEndpoint = srv.URL
		res, err := RecheckByIntrospection().Recheck(t.Context(), RecheckRequest{Session: Session{User: User{Subject: "alice"}, Tokens: Tokens{AccessToken: "a"}}, Provider: f.c.provider})
		srv.Close()
		if err != nil || res.Decision != Deny {
			t.Errorf("%v: %v %v", answer, res.Decision, err)
		}
	}
}

// TestRecheckByUserInfo: allows on a 200 for the same subject, refreshes
// an expired access token first, refuses on 401.
func TestRecheckByUserInfo(t *testing.T) {
	f := newFixture(t, algEdDSA, WithRechecker(RecheckByUserInfo()))
	b := f.signIn("alice", "/")
	f.clock.advance(DefaultRecheckInterval)
	if r := apiGet(b, "/"); r.code != http.StatusOK {
		t.Fatalf("userinfo yes %d", r.code)
	}
	if f.op.tokenCalls.Load() != 0 {
		t.Fatal("refreshed a live access token")
	}
	f.clock.advance(5 * time.Minute) // the access token's expires_in
	if r := apiGet(b, "/"); r.code != http.StatusOK {
		t.Fatalf("after expiry %d", r.code)
	}
	if f.op.tokenCalls.Load() != 1 {
		t.Fatal("an expired access token was not refreshed first")
	}
	f.op.deny("alice")
	f.clock.advance(DefaultRecheckInterval)
	if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
		t.Fatalf("userinfo no %d", r.code)
	}
	// A userinfo answer for another subject is refused.
	f.op.set(func(op *testOP) { op.userInfo["sub"] = "mallory" })
	at := "at_x"
	f.op.set(func(op *testOP) { op.access[at] = "bob" })
	if _, err := f.c.provider.UserInfo(t.Context(), Secret(at), "bob"); !errors.Is(err, ErrProviderRefused) {
		t.Fatalf("userinfo of another subject: %v", err)
	}
}

// TestRecheckBackchannelOnly never calls the server and needs a revoker.
func TestRecheckBackchannelOnly(t *testing.T) {
	f := newFixture(t, algEdDSA, WithRechecker(RecheckBackchannelOnly()), WithSessionStore(NewMemoryStore()))
	b := f.signIn("alice", "/")
	f.clock.advance(time.Hour)
	if r := apiGet(b, "/"); r.code != http.StatusOK {
		t.Fatal(r.code)
	}
	if f.op.tokenCalls.Load() != 0 {
		t.Fatal("back-channel-only called the server")
	}
	if _, err := New(testConfig(f.op), WithRechecker(RecheckBackchannelOnly())); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("back-channel-only with the cookie store: %v", err)
	}
}

// failingStore is a SessionStore whose calls fail on demand.
type failingStore struct {
	SessionStore
	mu                      sync.Mutex
	failSave, failLoad      bool
	failDelete, noSessionLd bool
}

func (s *failingStore) Save(ctx context.Context, sess Session) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failSave {
		return nil, errBoom
	}
	return s.SessionStore.Save(ctx, sess)
}

func (s *failingStore) Load(ctx context.Context, v []byte) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failLoad {
		return Session{}, errBoom
	}
	return s.SessionStore.Load(ctx, v)
}

func (s *failingStore) Delete(ctx context.Context, sess Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failDelete {
		return errBoom
	}
	return s.SessionStore.Delete(ctx, sess)
}

func (s *failingStore) set(f func(*failingStore)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

// TestSeam_SessionStore: a custom store is used (the cookie carries what
// it returns), its failures refuse, and the default store is stateless.
func TestSeam_SessionStore(t *testing.T) {
	t.Run("custom allow", func(t *testing.T) {
		st := &failingStore{SessionStore: NewMemoryStore()}
		f := newFixture(t, algEdDSA, WithSessionStore(st))
		b := f.signIn("alice", "/")
		plain, err := f.c.set.sealer.Open(t.Context(), readChunkedFrom(b), DefaultCookieName)
		if err != nil || strings.Contains(string(plain), "alice") {
			t.Fatalf("the cookie carries more than the session ID: %q %v", plain, err)
		}
	})
	t.Run("load error fails closed", func(t *testing.T) {
		st := &failingStore{SessionStore: CookieStore()}
		f := newFixture(t, algEdDSA, WithSessionStore(st))
		b := f.signIn("alice", "/")
		st.set(func(s *failingStore) { s.failLoad = true })
		if r := apiGet(b, "/"); r.code != http.StatusInternalServerError {
			t.Fatalf("%d, want 500", r.code)
		}
	})
	t.Run("save error at sign-in fails closed", func(t *testing.T) {
		st := &failingStore{SessionStore: CookieStore(), failSave: true}
		f := newFixture(t, algEdDSA, WithSessionStore(st))
		if b, code := f.callbackWith("alice", nil); code != http.StatusInternalServerError || len(b.cookies) != 0 {
			t.Fatalf("%d, cookies %d", code, len(b.cookies))
		}
	})
	t.Run("save error at refresh ends the session", func(t *testing.T) {
		st := &failingStore{SessionStore: CookieStore()}
		f := newFixture(t, algEdDSA, WithSessionStore(st))
		b := f.signIn("alice", "/")
		st.set(func(s *failingStore) { s.failSave = true })
		f.clock.advance(DefaultRecheckInterval)
		if r := apiGet(b, "/"); r.code != http.StatusInternalServerError {
			t.Fatalf("%d", r.code)
		}
		if _, ok := b.cookies[DefaultCookieName]; ok {
			t.Fatal("cookie kept")
		}
	})
	t.Run("default is stateless", func(t *testing.T) {
		f := newFixture(t, algEdDSA)
		b := f.signIn("alice", "/")
		plain, err := f.c.set.sealer.Open(t.Context(), readChunkedFrom(b), DefaultCookieName)
		if err != nil {
			t.Fatal(err)
		}
		var s Session
		if err := json.Unmarshal(plain, &s); err != nil || s.User.Subject != "alice" || s.Tokens.RefreshToken.IsZero() || s.ExpiresAt.IsZero() {
			t.Fatalf("cookie session %+v %v", s, err)
		}
	})
}

// readChunkedFrom joins b's session cookie chunks.
func readChunkedFrom(b *browser) string {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	return readChunked(req, DefaultCookieName)
}

// testSealer is a custom Sealer: base64 of aad + plain, with failures on
// demand. It exists to prove the seam is used, not to seal anything.
type testSealer struct {
	mu                 sync.Mutex
	failSeal, failOpen bool
	seals              int
}

func (s *testSealer) Seal(_ context.Context, plain []byte, aad string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failSeal {
		return "", errBoom
	}
	s.seals++
	return b64(append([]byte(aad+"|"), plain...)), nil
}

func (s *testSealer) Open(_ context.Context, sealed, aad string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failOpen {
		return nil, errBoom
	}
	raw, err := decodeB64(sealed)
	if err != nil || !strings.HasPrefix(string(raw), aad+"|") {
		return nil, ErrSealedCorrupt
	}
	return raw[len(aad)+1:], nil
}

// TestSeam_Sealer: a custom sealer is used, its Open failure refuses as a
// failure (not as a silent sign-out), its Seal failure refuses sign-in.
func TestSeam_Sealer(t *testing.T) {
	cfg := func(op *testOP) Config { c := testConfig(op); c.SessionSecret = ""; return c }
	t.Run("custom allow", func(t *testing.T) {
		sl := &testSealer{}
		clock := newTestClock()
		op := newTestOP(t, clock, algEdDSA)
		f := newFixtureWith(t, op, cfg(op), WithSealer(sl))
		b := f.signIn("alice", "/")
		if r := apiGet(b, "/"); r.code != http.StatusOK || sl.seals < 2 {
			t.Fatalf("%d seals %d", r.code, sl.seals)
		}
	})
	t.Run("open error fails closed", func(t *testing.T) {
		sl := &testSealer{}
		clock := newTestClock()
		op := newTestOP(t, clock, algEdDSA)
		f := newFixtureWith(t, op, cfg(op), WithSealer(sl))
		b := f.signIn("alice", "/")
		sl.mu.Lock()
		sl.failOpen = true
		sl.mu.Unlock()
		if r := apiGet(b, "/"); r.code != http.StatusInternalServerError {
			t.Fatalf("%d, want 500", r.code)
		}
	})
	t.Run("seal error fails closed", func(t *testing.T) {
		sl := &testSealer{failSeal: true}
		clock := newTestClock()
		op := newTestOP(t, clock, algEdDSA)
		f := newFixtureWith(t, op, cfg(op), WithSealer(sl))
		res := newBrowser(t, f.h).get("/auth/login")
		if res.Code != http.StatusInternalServerError {
			t.Fatalf("%d", res.Code)
		}
	})
}

// TestSeam_Responder: a custom responder writes the answer but cannot let
// the request through; the default redirects pages and answers APIs with
// JSON.
func TestSeam_Responder(t *testing.T) {
	var got []Refusal
	f := newFixture(t, algEdDSA, WithResponder(ResponderFunc(func(w http.ResponseWriter, r *http.Request, ref Refusal) {
		got = append(got, ref)
		if ref.Kind == RefusalLoginRequired {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		DefaultResponder().Respond(w, r, ref)
	})))
	b := newBrowser(t, f.h)
	res := b.get("/x?y=1")
	if res.Code != http.StatusTeapot || strings.Contains(res.Body.String(), "hello") {
		t.Fatalf("%d %q", res.Code, res.Body)
	}
	if len(got) != 1 || got[0].Reason != ReasonNoSession || got[0].LoginURL != "/auth/login?return_to=%2Fx%3Fy%3D1" {
		t.Fatalf("refusals %+v", got)
	}

	d := newFixture(t, algEdDSA)
	b = newBrowser(t, d.h)
	if res := b.get("/x"); res.Code != http.StatusFound || res.Header().Get(headerLocation) != "/auth/login?return_to=%2Fx" {
		t.Fatalf("page: %d %q", res.Code, res.Header().Get(headerLocation))
	}
	r := apiGet(b, "/x")
	var body refusalBody
	if r.code != http.StatusUnauthorized || json.Unmarshal([]byte(r.body), &body) != nil || body.Error != RefusalLoginRequired || body.LoginURL == "" {
		t.Fatalf("api: %d %q", r.code, r.body)
	}
	if r.header.Get(headerCacheControl) != cacheNoStore {
		t.Error("refusal cacheable")
	}
	for _, tc := range []struct {
		ref  Refusal
		page bool
		want int
	}{
		{Refusal{Kind: RefusalNoAccess}, true, http.StatusForbidden},
		{Refusal{Kind: RefusalUnavailable}, false, http.StatusServiceUnavailable},
		{Refusal{Kind: RefusalFailed, Reason: ReasonBadCallback}, true, http.StatusBadRequest},
		{Refusal{Kind: RefusalFailed, Reason: ReasonStoreFailed}, false, http.StatusInternalServerError},
		{Refusal{Kind: RefusalLoginRequired}, true, http.StatusUnauthorized},
		{Refusal{Kind: "unknown"}, true, http.StatusInternalServerError},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if tc.page {
			req.Header.Set(headerAccept, "text/html,application/xhtml+xml")
		}
		rec := httptest.NewRecorder()
		DefaultResponder().Respond(rec, req, tc.ref)
		if rec.Code != tc.want {
			t.Errorf("%+v: %d, want %d", tc.ref, rec.Code, tc.want)
		}
	}
	post := httptest.NewRequest(http.MethodPost, "/", nil)
	post.Header.Set(headerAccept, mediaTypeHTML)
	if IsPageRequest(post) {
		t.Error("a POST is a page request")
	}
}

// TestSeam_Cookie: a custom name and Strict mode; the floors on prefixes
// and SameSite.
func TestSeam_Cookie(t *testing.T) {
	f := newFixture(t, algEdDSA, WithCookie(CookieOptions{Name: "__Host-app", SameSite: http.SameSiteStrictMode}))
	b := newBrowser(t, f.h)
	cb := f.op.approve(f.startLogin(b), "alice")
	if b.cookies["__Host-app_flow"].SameSite != http.SameSiteLaxMode {
		t.Error("flow cookie not Lax under Strict")
	}
	res := b.get(cb)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `url='/home'`) {
		t.Fatalf("strict landing: %d %q", res.Code, res.Body)
	}
	c := b.cookies["__Host-app"]
	if c == nil || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie %+v", c)
	}
	d := newFixture(t, algEdDSA, WithCookie(CookieOptions{Name: "__Secure-app", Domain: "app.example"}))
	b = d.signIn("alice", "/")
	if c := b.cookies["__Secure-app"]; c == nil || c.Domain != "app.example" || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("domain cookie %+v", c)
	}
}

// TestLanding_EscapesPath: the Strict landing page never lets a path break
// out of its attribute.
func TestLanding_EscapesPath(t *testing.T) {
	f := newFixture(t, algEdDSA, WithCookie(CookieOptions{SameSite: http.SameSiteStrictMode}))
	rec := httptest.NewRecorder()
	f.c.land(rec, httptest.NewRequest(http.MethodGet, "/", nil), `/a'"><script>x</script>`)
	body := rec.Body.String()
	if strings.Contains(body, "<script>") || !strings.Contains(body, "/a%27%22&gt;") {
		t.Fatalf("unescaped: %s", body)
	}
}

// TestSeam_Paths: routes under another prefix, and the handlers mounted
// one by one.
func TestSeam_Paths(t *testing.T) {
	p := PathsUnder("/sso/")
	if p.Login != "/sso/login" || p.Backchannel != "/sso/backchannel" {
		t.Fatalf("%+v", p)
	}
	clock := newTestClock()
	op := newTestOP(t, clock, algEdDSA)
	c, err := New(testConfig(op), WithPaths(p), WithClock(clock.now))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/sso/login", c.LoginHandler())
	mux.Handle("/sso/callback", c.CallbackHandler())
	mux.Handle("/sso/logout", c.LogoutHandler())
	mux.Handle("/sso/backchannel", c.BackchannelHandler())
	mux.Handle("/", c.Require(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "in") })))
	b := newBrowser(t, mux)
	res := b.get("/x")
	if res.Header().Get(headerLocation) != "/sso/login?return_to=%2Fx" {
		t.Fatalf("login URL %q", res.Header().Get(headerLocation))
	}
	res = b.get(res.Header().Get(headerLocation))
	u, _ := url.Parse(res.Header().Get(headerLocation))
	if u.Query().Get(paramRedirectURI) != testAppURL+"/sso/callback" {
		t.Fatalf("redirect_uri %q", u.Query().Get(paramRedirectURI))
	}
	res = b.get(op.approve(res.Header().Get(headerLocation), "alice"))
	if res.Code != http.StatusFound {
		t.Fatal(res.Code)
	}
	if r := apiGet(b, "/x"); r.body != "in" {
		t.Fatal(r.body)
	}
	// Handler serves only its four paths, each with its methods.
	h := c.Handler()
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/sso/other", http.StatusNotFound},
		{http.MethodPost, "/sso/login", http.StatusMethodNotAllowed},
		{http.MethodGet, "/sso/logout", http.StatusMethodNotAllowed},
		{http.MethodGet, "/sso/backchannel", http.StatusMethodNotAllowed},
		{http.MethodPost, "/sso/callback", http.StatusMethodNotAllowed},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.want {
			t.Errorf("%s %s: %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}
}

// TestSeam_ClientAuth: basic by default, post and public on request, a
// failing custom authenticator refuses without sending anything.
func TestSeam_ClientAuth(t *testing.T) {
	t.Run("default basic", func(t *testing.T) {
		f := newFixture(t, algEdDSA)
		f.signIn("alice", "/")
		f.op.mu.Lock()
		defer f.op.mu.Unlock()
		if !strings.HasPrefix(f.op.lastAuth, schemeBasic) || f.op.lastForm.Get(paramClientSecret) != "" {
			t.Fatalf("auth %q form %v", f.op.lastAuth, f.op.lastForm)
		}
	})
	for name, auth := range map[string]func(op *testOP) ClientAuth{
		"post":   func(op *testOP) ClientAuth { return ClientSecretPost(op.clientID, Secret(op.secret)) },
		"public": func(op *testOP) ClientAuth { return PublicClient(op.clientID) },
	} {
		t.Run(name, func(t *testing.T) {
			clock := newTestClock()
			op := newTestOP(t, clock, algEdDSA)
			cfg := testConfig(op)
			cfg.ClientSecret = ""
			f := newFixtureWith(t, op, cfg, WithClientAuth(auth(op)))
			f.signIn("alice", "/")
			op.mu.Lock()
			defer op.mu.Unlock()
			if op.lastAuth != "" || op.lastForm.Get(paramClientID) != op.clientID {
				t.Fatalf("auth %q form %v", op.lastAuth, op.lastForm)
			}
		})
	}
	t.Run("custom error fails closed", func(t *testing.T) {
		clock := newTestClock()
		op := newTestOP(t, clock, algEdDSA)
		cfg := testConfig(op)
		cfg.ClientSecret = ""
		f := newFixtureWith(t, op, cfg, WithClientAuth(ClientAuthFunc(func(context.Context, ClientAuthRequest) error { return errBoom })))
		if b, code := f.callbackWith("alice", nil); code != http.StatusBadRequest || f.signedIn(b) {
			t.Fatalf("%d", code)
		}
	})
	t.Run("basic form-encodes", func(t *testing.T) {
		h := http.Header{}
		_ = ClientSecretBasic("a:b", "c d").Authenticate(t.Context(), ClientAuthRequest{Header: h, Form: url.Values{}})
		r := &http.Request{Header: h}
		id, secret, ok := r.BasicAuth()
		if !ok || id != "a%3Ab" || secret != "c+d" {
			t.Fatalf("%q %q", id, secret)
		}
	})
}

// TestSeam_Observer: the observer sees login, refresh, grace, refuse and
// logout, after the decision.
func TestSeam_Observer(t *testing.T) {
	f := newFixture(t, algEdDSA)
	b := f.signIn("alice", "/")
	f.clock.advance(DefaultRecheckInterval)
	apiGet(b, "/")
	f.op.down.Store(true)
	f.clock.advance(DefaultRecheckInterval)
	apiGet(b, "/")
	b.do(http.MethodPost, "/auth/logout", url.Values{}, headerOrigin, testAppURL)
	for _, k := range []EventKind{EventLogin, EventRefresh, EventGrace, EventLogout} {
		if !f.events.has(k, "") {
			t.Errorf("no %s in %v", k, f.events.kinds())
		}
	}
	for _, e := range f.events.ev {
		if e.At.IsZero() {
			t.Errorf("%s without a time", e.Kind)
		}
	}
}

// TestSeam_Discovery: a given document is used without a fetch, and held
// to the same checks.
func TestSeam_Discovery(t *testing.T) {
	clock := newTestClock()
	op := newTestOP(t, clock, algEdDSA)
	var m ProviderMetadata
	raw, _ := json.Marshal(op.metadata())
	_ = json.Unmarshal(raw, &m)
	f := newFixtureWith(t, op, testConfig(op), WithDiscovery(m))
	op.srv.Config.Handler = discoveryRefusing(op.srv.Config.Handler)
	if r := apiGet(f.signIn("alice", "/"), "/"); r.code != http.StatusOK {
		t.Fatal(r.code)
	}
	bad := m
	bad.Issuer = "https://evil.example"
	if _, err := New(testConfig(op), WithDiscovery(bad)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("mix-up document accepted: %v", err)
	}
	bad = m
	bad.TokenEndpoint = "http://evil.example/token"
	if _, err := New(testConfig(op), WithDiscovery(bad)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("http endpoint accepted: %v", err)
	}
	bad = m
	bad.CodeChallengeMethodsSupported = []string{"plain"}
	if _, err := New(testConfig(op), WithDiscovery(bad)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("no S256 accepted: %v", err)
	}
}

// discoveryRefusing fails the test server's discovery route.
func discoveryRefusing(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == wellKnownOpenID {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// decodeB64 is the test sealer's decoder.
func decodeB64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
