package oidcclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// sessionOf opens the session b's cookie names, through the Client's own
// sealer and store, so a test can read ExpiresAt and LastSeenAt.
func (f *fixture) sessionOf(b *browser) Session {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range b.cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	s, _, err := f.c.openSession(req.Context(), req)
	if err != nil {
		f.t.Fatalf("open session: %v", err)
	}
	return s
}

// TestLifetimes_ExpiresAt: the expiry every store sets its TTL from, for
// each combination of limited and unlimited bounds; always a real time.
func TestLifetimes_ExpiresAt(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seen := created.Add(48 * time.Hour)
	for name, tc := range map[string]struct {
		l    Lifetimes
		want time.Time
	}{
		"both limited, idle first":     {Lifetimes{Idle: 24 * time.Hour, Absolute: 30 * 24 * time.Hour}, seen.Add(24 * time.Hour)},
		"both limited, absolute first": {Lifetimes{Idle: 24 * time.Hour, Absolute: 60 * time.Hour}, created.Add(60 * time.Hour)},
		"no absolute":                  {Lifetimes{Idle: 24 * time.Hour, Absolute: NoLimit}, seen.Add(24 * time.Hour)},
		"no idle":                      {Lifetimes{Idle: NoLimit, Absolute: 90 * 24 * time.Hour}, created.Add(90 * 24 * time.Hour)},
		"no idle, absolute past cap":   {Lifetimes{Idle: NoLimit, Absolute: 1000 * 24 * time.Hour}, seen.Add(MaxCookieLifetime)},
		"neither":                      {Lifetimes{Idle: NoLimit, Absolute: NoLimit}, seen.Add(MaxCookieLifetime)},
		"finite idle above the cap":    {Lifetimes{Idle: 500 * 24 * time.Hour, Absolute: NoLimit}, seen.Add(500 * 24 * time.Hour)},
	} {
		if got := tc.l.expiresAt(created, seen); !got.Equal(tc.want) {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
	far := created.Add(200 * 365 * 24 * time.Hour)
	none := Lifetimes{Idle: NoLimit, Absolute: NoLimit}
	if none.absoluteOver(created, far) || none.idleOver(created, far) {
		t.Error("NoLimit bounds expired")
	}
	if !(Lifetimes{Idle: time.Hour, Absolute: time.Hour}).idleOver(created, created.Add(time.Hour)) {
		t.Error("a limited idle bound did not expire at its end")
	}
}

// TestNew_Options refuses each new option's out-of-range values and accepts
// the documented NoLimit combinations.
func TestNew_Options(t *testing.T) {
	refused := map[string][]Option{
		"negative slide":                 {WithSlideInterval(-time.Second)},
		"slide not below idle":           {WithLifetimes(Lifetimes{Idle: time.Hour}), WithSlideInterval(time.Hour)},
		"slide NoLimit with finite idle": {WithSlideInterval(NoLimit)},
		"negative skew":                  {WithClockSkew(-time.Second)},
		"skew above max":                 {WithClockSkew(MaxClockSkew + time.Second)},
		"zero flow lifetime":             {WithFlowLifetime(0)},
		"negative flow lifetime":         {WithFlowLifetime(-time.Minute)},
		"NoLimit flow lifetime":          {WithFlowLifetime(NoLimit)},
		"idle above absolute":            {WithLifetimes(Lifetimes{Idle: 48 * time.Hour, Absolute: 24 * time.Hour})},
		"nothing ends a cookie session": {
			WithLifetimes(Lifetimes{Idle: NoLimit, Absolute: NoLimit}), WithRecheckInterval(NoLimit),
		},
	}
	for name, opts := range refused {
		if _, err := New(validConfig(), opts...); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: New = %v, want ErrInvalidConfig", name, err)
		}
	}
	accepted := map[string][]Option{
		"no absolute":             {WithLifetimes(Lifetimes{Absolute: NoLimit})},
		"no idle":                 {WithLifetimes(Lifetimes{Idle: NoLimit})},
		"no idle, short absolute": {WithLifetimes(Lifetimes{Idle: NoLimit, Absolute: time.Hour})},
		"neither, re-checked":     {WithLifetimes(Lifetimes{Idle: NoLimit, Absolute: NoLimit})},
		"neither, never re-checked, revoking store": {
			WithLifetimes(Lifetimes{Idle: NoLimit, Absolute: NoLimit}), WithRecheckInterval(NoLimit), WithSessionStore(NewMemoryStore()),
		},
		"never re-checked, limited":     {WithRecheckInterval(NoLimit)},
		"grace without end":             {WithOutageGrace(NoLimit)},
		"slide every request":           {WithSlideInterval(0)},
		"slide NoLimit without idle":    {WithLifetimes(Lifetimes{Idle: NoLimit}), WithSlideInterval(NoLimit)},
		"exact clocks":                  {WithClockSkew(0)},
		"max skew":                      {WithClockSkew(MaxClockSkew)},
		"long flow":                     {WithFlowLifetime(time.Hour)},
		"browser-session cookie":        {WithCookie(CookieOptions{BrowserSession: true})},
		"app-only logout":               {WithLogoutPolicy(LogoutAlways(LogoutAppOnly))},
		"zero Lifetimes keep defaults":  {WithLifetimes(Lifetimes{})},
		"absolute only, idle defaulted": {WithLifetimes(Lifetimes{Absolute: 90 * 24 * time.Hour})},
	}
	for name, opts := range accepted {
		if _, err := New(validConfig(), opts...); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	c, err := New(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if c.set.slide != DefaultSlideInterval || c.set.skew != DefaultClockSkew || c.set.flowTTL != DefaultFlowLifetime ||
		c.set.lifetimes != (Lifetimes{Idle: DefaultIdleLifetime, Absolute: DefaultAbsoluteLifetime}) {
		t.Fatalf("defaults %+v", c.set)
	}
}

// TestNoLimit_Absolute: with Absolute: NoLimit a session that is used at
// least once per idle window outlives the 30-day default, re-checked with
// the login server all along, and still ends at the server's first "no"
// and at an idle gap.
// ds:def id=testnolimit-absolute-rm3q5kxs owner=@khanakia stability=stable
func TestNoLimit_Absolute(t *testing.T) {
	f := newFixture(t, algEdDSA, WithLifetimes(Lifetimes{Absolute: NoLimit}))
	b := f.signIn("alice", "/")
	for day := 6; day <= 120; day += 6 {
		f.clock.advance(6 * 24 * time.Hour)
		if r := apiGet(b, "/"); r.code != http.StatusOK {
			t.Fatalf("day %d: %d", day, r.code)
		}
	}
	s := f.sessionOf(b)
	if want := f.clock.now().Add(DefaultIdleLifetime); !s.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt %v, want LastSeenAt + idle %v", s.ExpiresAt, want)
	}
	if n := f.op.tokenCalls.Load(); n != 20 {
		t.Fatalf("refreshes %d, want one per visit (20)", n)
	}
	f.op.deny("alice")
	f.clock.advance(DefaultRecheckInterval)
	if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
		t.Fatalf("after removal %d", r.code)
	}

	g := newFixture(t, algEdDSA, WithLifetimes(Lifetimes{Absolute: NoLimit}))
	b = g.signIn("alice", "/")
	g.clock.advance(DefaultIdleLifetime)
	if r := apiGet(b, "/"); r.code != http.StatusUnauthorized || !g.events.has(EventRefuse, ReasonIdleExpired) {
		t.Fatalf("idle gap without absolute: %d %v", r.code, g.events.kinds())
	}
}

// TestNoLimit_Idle: with Idle: NoLimit an untouched session lives until the
// absolute lifetime, and no longer.
func TestNoLimit_Idle(t *testing.T) {
	f := newFixture(t, algEdDSA, WithLifetimes(Lifetimes{Idle: NoLimit, Absolute: 60 * 24 * time.Hour}))
	b := f.signIn("alice", "/")
	if s := f.sessionOf(b); !s.ExpiresAt.Equal(s.CreatedAt.Add(60 * 24 * time.Hour)) {
		t.Fatalf("ExpiresAt %v", s.ExpiresAt)
	}
	f.clock.advance(59 * 24 * time.Hour)
	if r := apiGet(b, "/"); r.code != http.StatusOK {
		t.Fatalf("after 59 untouched days %d", r.code)
	}
	f.clock.advance(24 * time.Hour)
	if r := apiGet(b, "/"); r.code != http.StatusUnauthorized || !f.events.has(EventRefuse, ReasonAbsoluteExpired) {
		t.Fatalf("past absolute %d %v", r.code, f.events.kinds())
	}
}

// TestNoLimit_Neither: with no lifetime at all the session stands for as
// long as the login server says yes, its ExpiresAt and cookie are the
// browser's 400-day horizon from the last use, and the server's "no" still
// ends it.
// ds:def id=testnolimit-neither-gaemd5sj owner=@khanakia stability=stable
func TestNoLimit_Neither(t *testing.T) {
	f := newFixture(t, algEdDSA, WithLifetimes(Lifetimes{Idle: NoLimit, Absolute: NoLimit}))
	b := f.signIn("alice", "/")
	f.clock.advance(300 * 24 * time.Hour)
	if r := apiGet(b, "/"); r.code != http.StatusOK {
		t.Fatalf("after 300 untouched days %d", r.code)
	}
	s := f.sessionOf(b)
	if want := f.clock.now().Add(MaxCookieLifetime); !s.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt %v, want %v", s.ExpiresAt, want)
	}
	if c := b.cookies[DefaultCookieName]; c.MaxAge != int(MaxCookieLifetime/time.Second) {
		t.Fatalf("cookie Max-Age %d, want %d", c.MaxAge, int(MaxCookieLifetime/time.Second))
	}
	f.op.deny("alice")
	f.clock.advance(DefaultRecheckInterval)
	if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
		t.Fatalf("after removal %d", r.code)
	}
}

// TestNoLimit_NeverRecheck: interval NoLimit with a revoking store never
// calls the server again; a back-channel logout still ends the session.
func TestNoLimit_NeverRecheck(t *testing.T) {
	f := newFixture(t, algEdDSA, WithSessionStore(NewMemoryStore()), WithRecheckInterval(NoLimit),
		WithLifetimes(Lifetimes{Idle: NoLimit, Absolute: NoLimit}))
	b := f.signIn("alice", "/")
	f.clock.advance(100 * 24 * time.Hour)
	if r := apiGet(b, "/"); r.code != http.StatusOK || f.op.tokenCalls.Load() != 0 {
		t.Fatalf("%d with %d refreshes", r.code, f.op.tokenCalls.Load())
	}
	if code := f.backchannelPost(f.op.logoutToken("alice", "", nil)); code != http.StatusOK || f.signedIn(b) {
		t.Fatalf("back-channel %d", code)
	}
}

// TestNoLimit_OutageGrace: a grace without end keeps the session usable
// through a long outage, never past its lifetimes.
func TestNoLimit_OutageGrace(t *testing.T) {
	f := newFixture(t, algEdDSA, WithOutageGrace(NoLimit))
	b := f.signIn("alice", "/")
	f.op.down.Store(true)
	f.clock.advance(6 * 24 * time.Hour)
	if r := apiGet(b, "/"); r.code != http.StatusOK {
		t.Fatalf("six days into the outage %d", r.code)
	}
	f.clock.advance(DefaultIdleLifetime)
	if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
		t.Fatalf("past the idle lifetime %d", r.code)
	}
}

// TestSlideInterval: the idle window moves at the configured step; zero
// moves it on every request; NoLimit only at a re-check.
func TestSlideInterval(t *testing.T) {
	long := WithRecheckInterval(24 * time.Hour)
	t.Run("ten minutes", func(t *testing.T) {
		f := newFixture(t, algEdDSA, long, WithSlideInterval(10*time.Minute))
		b := f.signIn("alice", "/")
		f.clock.advance(9 * time.Minute)
		if r := apiGet(b, "/"); len(r.header.Values("Set-Cookie")) != 0 {
			t.Fatalf("slid within the step: %v", r.header.Values("Set-Cookie"))
		}
		f.clock.advance(time.Minute)
		if r := apiGet(b, "/"); len(r.header.Values("Set-Cookie")) == 0 {
			t.Fatal("did not slide after the step")
		}
		if s := f.sessionOf(b); !s.LastSeenAt.Equal(f.clock.now()) {
			t.Fatalf("LastSeenAt %v", s.LastSeenAt)
		}
	})
	t.Run("every request", func(t *testing.T) {
		f := newFixture(t, algEdDSA, long, WithSlideInterval(0))
		b := f.signIn("alice", "/")
		for range 3 {
			f.clock.advance(time.Second)
			if r := apiGet(b, "/"); len(r.header.Values("Set-Cookie")) == 0 {
				t.Fatal("did not slide")
			}
		}
		if r := apiGet(b, "/"); len(r.header.Values("Set-Cookie")) != 0 {
			t.Fatal("slid twice at one instant")
		}
	})
	t.Run("never", func(t *testing.T) {
		f := newFixture(t, algEdDSA, long, WithSlideInterval(NoLimit), WithLifetimes(Lifetimes{Idle: NoLimit}))
		b := f.signIn("alice", "/")
		f.clock.advance(23 * time.Hour)
		if r := apiGet(b, "/"); r.code != http.StatusOK || len(r.header.Values("Set-Cookie")) != 0 {
			t.Fatalf("%d, slid: %v", r.code, r.header.Values("Set-Cookie"))
		}
		f.clock.advance(time.Hour)
		if r := apiGet(b, "/"); len(r.header.Values("Set-Cookie")) == 0 {
			t.Fatal("the re-check did not write the session")
		}
	})
}

// TestClockSkew: a token whose iat is two minutes ahead is refused under
// the default skew and accepted under three minutes; zero skew refuses a
// token that expired a second ago.
func TestClockSkew(t *testing.T) {
	ahead := func(op *testOP) {
		op.tamperID = func(_, c map[string]any) { c["iat"] = c["iat"].(int64) + 120 }
	}
	f := newFixture(t, algEdDSA)
	f.op.set(ahead)
	if b, code := f.callbackWith("alice", nil); code != http.StatusBadRequest || f.signedIn(b) {
		t.Fatalf("default skew: %d", code)
	}
	g := newFixture(t, algEdDSA, WithClockSkew(3*time.Minute))
	g.op.set(ahead)
	if b, code := g.callbackWith("alice", nil); code != http.StatusFound || !g.signedIn(b) {
		t.Fatalf("three minutes: %d", code)
	}
	h := newFixture(t, algEdDSA, WithClockSkew(0))
	h.op.set(func(op *testOP) {
		op.tamperID = func(_, c map[string]any) { c["exp"] = c["iat"].(int64) - 1 }
	})
	if b, code := h.callbackWith("alice", nil); code != http.StatusBadRequest || h.signedIn(b) {
		t.Fatalf("zero skew, expired a second ago: %d", code)
	}
	k := newFixture(t, algEdDSA)
	k.op.set(func(op *testOP) {
		op.tamperID = func(_, c map[string]any) { c["exp"] = c["iat"].(int64) - 1 }
	})
	if _, code := k.callbackWith("alice", nil); code != http.StatusFound {
		t.Fatalf("default skew, expired a second ago: %d", code)
	}
}

// TestFlowLifetime: a sign-in may take as long as WithFlowLifetime says,
// and the flow cookie lives that long.
func TestFlowLifetime(t *testing.T) {
	f := newFixture(t, algEdDSA, WithFlowLifetime(time.Hour))
	b := newBrowser(t, f.h)
	cb := f.op.approve(f.startLogin(b), "alice")
	if c := b.cookies[DefaultCookieName+FlowCookieSuffix]; c == nil || c.MaxAge != int(time.Hour/time.Second) {
		t.Fatalf("flow cookie %+v", c)
	}
	f.clock.advance(50 * time.Minute)
	if res := b.get(cb); res.Code != http.StatusFound {
		t.Fatalf("50-minute sign-in %d", res.Code)
	}
	g := newFixture(t, algEdDSA, WithFlowLifetime(time.Minute))
	b = newBrowser(t, g.h)
	cb = g.op.approve(g.startLogin(b), "alice")
	g.clock.advance(time.Minute + time.Second)
	if res := b.get(cb); res.Code != http.StatusBadRequest {
		t.Fatalf("past a one-minute flow %d", res.Code)
	}
}

// TestBrowserSessionCookie: the session cookie carries no expiry, the flow
// cookie still does, and the lifetimes still end the session.
func TestBrowserSessionCookie(t *testing.T) {
	f := newFixture(t, algEdDSA, WithCookie(CookieOptions{BrowserSession: true}), WithLifetimes(Lifetimes{Idle: time.Hour, Absolute: 2 * time.Hour}))
	b := newBrowser(t, f.h)
	cb := f.op.approve(f.startLogin(b), "alice")
	if c := b.cookies[DefaultCookieName+FlowCookieSuffix]; c == nil || c.MaxAge <= 0 {
		t.Fatalf("flow cookie lost its expiry: %+v", c)
	}
	res := b.get(cb)
	var session *http.Cookie
	for _, c := range res.Result().Cookies() {
		if c.Name == DefaultCookieName {
			session = c
		}
	}
	if session == nil || session.MaxAge != 0 || !session.Expires.IsZero() || session.RawExpires != "" {
		t.Fatalf("session cookie %+v, want no expiry", session)
	}
	f.clock.advance(time.Hour)
	if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
		t.Fatalf("past idle %d", r.code)
	}
}

// hookLog records every hook call.
type hookLog struct {
	mu       sync.Mutex
	starts   []SessionStart
	ends     []SessionEnd
	failures []RefreshFailure
}

func (h *hookLog) options() []Option {
	return []Option{
		WithOnSessionStart(func(_ context.Context, in SessionStart) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.starts = append(h.starts, in)
			return nil
		}),
		WithOnSessionEnd(func(_ context.Context, in SessionEnd) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.ends = append(h.ends, in)
		}),
		WithOnRefreshFailed(func(_ context.Context, in RefreshFailure) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.failures = append(h.failures, in)
		}),
	}
}

func (h *hookLog) lastEnd(t *testing.T) SessionEnd {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.ends) == 0 {
		t.Fatal("no SessionEnd")
	}
	return h.ends[len(h.ends)-1]
}

// TestHooks_SessionStartAndEnd: the start hook sees the session that is
// saved; the end hook hears each way a session ends, with that session.
func TestHooks_SessionStartAndEnd(t *testing.T) {
	logout := func(f *fixture, b *browser) {
		if res := b.do(http.MethodPost, "/auth/logout", url.Values{}, headerOrigin, testAppURL); res.Code != http.StatusSeeOther {
			t.Fatalf("logout %d", res.Code)
		}
	}
	cases := map[string]struct {
		opts []Option
		end  func(f *fixture, b *browser)
		want EndReason
	}{
		"logout":   {end: logout, want: EndLogout},
		"idle":     {opts: []Option{WithLifetimes(Lifetimes{Idle: time.Hour})}, end: func(f *fixture, b *browser) { f.clock.advance(time.Hour); apiGet(b, "/") }, want: EndIdleExpired},
		"absolute": {opts: []Option{WithLifetimes(Lifetimes{Idle: time.Hour, Absolute: time.Hour})}, end: func(f *fixture, b *browser) { f.clock.advance(time.Hour); apiGet(b, "/") }, want: EndAbsoluteExpired},
		"refused": {end: func(f *fixture, b *browser) {
			f.op.deny("alice")
			f.clock.advance(DefaultRecheckInterval)
			apiGet(b, "/")
		}, want: EndRecheckRefused},
		"replaced": {end: func(f *fixture, b *browser) {
			cb := f.op.approve(f.startLogin(b), "alice")
			if res := b.get(cb); res.Code != http.StatusFound {
				t.Fatalf("second sign-in %d", res.Code)
			}
		}, want: EndReplaced},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := &hookLog{}
			f := newFixture(t, algEdDSA, append(h.options(), tc.opts...)...)
			b := f.signIn("alice", "/")
			if len(h.starts) != 1 || h.starts[0].Identity.Subject != "alice" || h.starts[0].Request == nil {
				t.Fatalf("starts %+v", h.starts)
			}
			started := h.starts[0].Session
			if got := f.sessionOf(b); got.ID != started.ID || !got.ExpiresAt.Equal(started.ExpiresAt) {
				t.Fatalf("saved session %s, hook saw %s", got.ID, started.ID)
			}
			tc.end(f, b)
			e := h.lastEnd(t)
			if e.Reason != tc.want || e.Session == nil || e.Session.ID != started.ID || e.Request == nil {
				t.Fatalf("end %+v, want %s of %s", e, tc.want, started.ID)
			}
			if tc.want == EndRecheckRefused && e.Err == nil {
				t.Error("a refused re-check without its cause")
			}
		})
	}
	t.Run("back-channel", func(t *testing.T) {
		h := &hookLog{}
		f := newFixture(t, algEdDSA, append(h.options(), WithSessionStore(NewMemoryStore()))...)
		f.signIn("alice", "/")
		f.signIn("alice", "/")
		if code := f.backchannelPost(f.op.logoutToken("alice", "", nil)); code != http.StatusOK {
			t.Fatalf("%d", code)
		}
		e := h.lastEnd(t)
		if e.Reason != EndBackchannel || e.Session != nil || e.Target == nil || e.Target.Subject != "alice" || e.Count != 2 {
			t.Fatalf("end %+v", e)
		}
	})
}

// TestHooks_SessionStartRefuses: an error from the start hook refuses the
// sign-in and writes no session: ErrAccessDenied as no access (403), any
// other error as a failure (500).
func TestHooks_SessionStartRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		code int
	}{
		"denied": {ErrAccessDenied, http.StatusForbidden},
		"failed": {errors.New("audit table down"), http.StatusInternalServerError},
	} {
		t.Run(name, func(t *testing.T) {
			st := NewMemoryStore()
			f := newFixture(t, algEdDSA, WithSessionStore(st), WithOnSessionStart(func(context.Context, SessionStart) error { return tc.err }))
			b := newBrowser(t, f.h)
			res := b.get(f.op.approve(f.startLogin(b), "alice"))
			if res.Code != tc.code || f.signedIn(b) {
				t.Fatalf("callback %d, want %d", res.Code, tc.code)
			}
			if len(st.rows) != 0 {
				t.Fatalf("%d sessions saved", len(st.rows))
			}
		})
	}
}

// TestHooks_RefreshFailed: a refused re-check is reported once with
// Outage false; an outage with Outage true, the session kept.
func TestHooks_RefreshFailed(t *testing.T) {
	h := &hookLog{}
	f := newFixture(t, algEdDSA, h.options()...)
	b := f.signIn("alice", "/")
	f.op.down.Store(true)
	f.clock.advance(DefaultRecheckInterval)
	if r := apiGet(b, "/"); r.code != http.StatusOK {
		t.Fatalf("within grace %d", r.code)
	}
	if len(h.failures) != 1 || !h.failures[0].Outage || !errors.Is(h.failures[0].Err, ErrProviderUnavailable) || h.failures[0].Session.User.Subject != "alice" {
		t.Fatalf("outage failures %+v", h.failures)
	}
	if len(h.ends) != 0 {
		t.Fatalf("an outage ended the session: %+v", h.ends)
	}
	f.op.down.Store(false)
	f.op.deny("alice")
	f.clock.advance(recentRecheckTTL)
	if r := apiGet(b, "/"); r.code != http.StatusUnauthorized {
		t.Fatalf("refused %d", r.code)
	}
	if len(h.failures) != 2 || h.failures[1].Outage || h.failures[1].Err == nil {
		t.Fatalf("refusal failures %+v", h.failures)
	}
}

// TestLogoutPolicy: app-only lands on the post-logout path without the
// end-session redirect and still revokes the refresh token; a per-request
// policy reads the app's own form field; an unknown mode signs out at the
// server.
func TestLogoutPolicy(t *testing.T) {
	post := func(f *fixture, b *browser, form url.Values) *httptest.ResponseRecorder {
		return b.do(http.MethodPost, "/auth/logout", form, headerOrigin, testAppURL)
	}
	t.Run("app only", func(t *testing.T) {
		f := newFixture(t, algEdDSA, WithLogoutPolicy(LogoutAlways(LogoutAppOnly)), WithPostLogoutPath("/bye"))
		b := f.signIn("alice", "/")
		res := post(f, b, url.Values{})
		if res.Code != http.StatusSeeOther || res.Header().Get(headerLocation) != "/bye" {
			t.Fatalf("%d to %q", res.Code, res.Header().Get(headerLocation))
		}
		if f.op.revokeCalls.Load() != 1 || f.signedIn(b) {
			t.Fatalf("revocations %d", f.op.revokeCalls.Load())
		}
	})
	t.Run("per request", func(t *testing.T) {
		var seen *Session
		policy := func(in LogoutRequest) LogoutMode {
			seen = in.Session
			if in.Request.PostFormValue("everywhere") == "1" {
				return LogoutAtServer
			}
			return LogoutAppOnly
		}
		f := newFixture(t, algEdDSA, WithLogoutPolicy(policy))
		b := f.signIn("alice", "/")
		if res := post(f, b, url.Values{}); res.Header().Get(headerLocation) != "/" || seen == nil || seen.User.Subject != "alice" {
			t.Fatalf("here: %q, session %v", res.Header().Get(headerLocation), seen)
		}
		b = f.signIn("alice", "/")
		res := post(f, b, url.Values{"everywhere": {"1"}})
		if u, _ := url.Parse(res.Header().Get(headerLocation)); u.Path != "/logout" {
			t.Fatalf("everywhere: %q", res.Header().Get(headerLocation))
		}
		if res := post(f, newBrowser(t, f.h), url.Values{}); res.Code != http.StatusSeeOther || seen != nil {
			t.Fatalf("no session: %d, session %v", res.Code, seen)
		}
	})
	t.Run("unknown mode", func(t *testing.T) {
		f := newFixture(t, algEdDSA, WithLogoutPolicy(LogoutAlways("nowhere")))
		b := f.signIn("alice", "/")
		if u, _ := url.Parse(post(f, b, url.Values{}).Header().Get(headerLocation)); u.Path != "/logout" {
			t.Fatalf("unknown mode landed on %s", u)
		}
	})
}

// TestHooks_RefreshFailedOncePerFlight: twenty tabs whose re-check the
// server refuses produce one RefreshFailure and one SessionEnd, because
// the re-check is single-flight.
func TestHooks_RefreshFailedOncePerFlight(t *testing.T) {
	h := &hookLog{}
	f := newFixture(t, algEdDSA, h.options()...)
	b := f.signIn("alice", "/")
	f.op.set(func(op *testOP) { op.refreshDelay = 50 * time.Millisecond })
	f.op.deny("alice")
	f.clock.advance(DefaultRecheckInterval)
	jar := b.snapshot()
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tab := newBrowser(t, f.h)
			tab.restore(jar)
			if r := apiGet(tab, "/"); r.code != http.StatusUnauthorized {
				t.Errorf("tab %d", r.code)
			}
		}()
	}
	wg.Wait()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.failures) != 1 || len(h.ends) != 1 {
		t.Fatalf("failures %d, ends %d, want 1 each", len(h.failures), len(h.ends))
	}
}
