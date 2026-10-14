package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/sessiontest"
)

// Round 6 of the better-auth comparison: the core rows built for parity.

// A Before hook's SetInput is what the operation runs with, on the Go and the
// transport path, and later hooks see it in Input.
func TestCall_SetInputReplacesTheInput(t *testing.T) {
	var sawLater any
	p := newTestPlugin(
		auth.OperationHook{Match: []auth.EndpointID{opEcho}, Before: func(_ context.Context, c *auth.Call) error {
			in := c.Input.(echoIn)
			c.SetInput(echoIn{Text: in.Text + "!"})
			return nil
		}},
		auth.OperationHook{Match: []auth.EndpointID{opEcho}, Before: func(_ context.Context, c *auth.Call) error {
			sawLater = c.Input
			return nil
		}},
	)
	wire(t, p)
	out, err := p.echo.Call(context.Background(), echoIn{Text: "hi"})
	if err != nil || out.Text != "hi!" {
		t.Fatalf("Call = %+v, %v; want hi!", out, err)
	}
	if sawLater != (echoIn{Text: "hi!"}) {
		t.Fatalf("the later hook saw %v", sawLater)
	}
	got, err := p.echo.Invoke(context.Background(), func(dst any) error { return json.Unmarshal([]byte(`{"text":"yo"}`), dst) })
	if err != nil || got.(echoOut).Text != "yo!" {
		t.Fatalf("Invoke = %+v, %v; want yo!", got, err)
	}
}

// Assigning Input without SetInput changes nothing, and a SetInput of the
// wrong type fails the call before the operation runs.
func TestCall_SetInputIsTypeChecked(t *testing.T) {
	p := newTestPlugin(auth.OperationHook{Match: []auth.EndpointID{opEcho}, Before: func(_ context.Context, c *auth.Call) error {
		c.Input = echoIn{Text: "ignored"}
		return nil
	}})
	wire(t, p)
	if out, err := p.echo.Call(context.Background(), echoIn{Text: "kept"}); err != nil || out.Text != "kept" {
		t.Fatalf("plain assignment changed the input: %+v, %v", out, err)
	}
	q := newTestPlugin(auth.OperationHook{Match: []auth.EndpointID{opEcho}, Before: func(_ context.Context, c *auth.Call) error {
		c.SetInput("not an echoIn")
		return nil
	}})
	wire(t, q)
	if _, err := q.echo.Call(context.Background(), echoIn{Text: "x"}); !errors.Is(err, auth.ErrBadOperation) || q.ran != 0 {
		t.Fatalf("err = %v, ran = %d; want ErrBadOperation before the operation", err, q.ran)
	}
}

// Respond answers the call: the remaining Before hooks, the operation and the
// After hooks are skipped, and the effects the hook recorded still apply.
func TestCall_RespondShortCircuits(t *testing.T) {
	var later, after int
	p := newTestPlugin(
		auth.OperationHook{Match: []auth.EndpointID{opIssue}, Before: func(_ context.Context, c *auth.Call) error {
			c.Effects.Redirect("/maintenance")
			c.Respond(echoOut{Text: "canned"})
			return nil
		}},
		auth.OperationHook{Match: []auth.EndpointID{opIssue},
			Before: func(context.Context, *auth.Call) error { later++; return nil },
			After:  func(context.Context, *auth.Call, any) error { after++; return nil }},
	)
	a := wire(t, p)
	ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{Origin: trustedOrigin}})
	out, err := p.issue.Call(ctx, struct{}{})
	if err != nil || out.Text != "canned" {
		t.Fatalf("Call = %+v, %v; want canned", out, err)
	}
	if p.ran != 0 || later != 0 || after != 0 {
		t.Fatalf("ran %d, later before %d, after %d; want all skipped", p.ran, later, after)
	}
	effects := auth.RequestEffects(ctx)
	if len(effects) != 1 || effects[0].Kind != auth.EffectRedirect {
		t.Fatalf("effects = %+v; want the hook's redirect only", effects)
	}
}

// A Respond value of the wrong type fails the call; Respond from an After
// hook changes nothing.
func TestCall_RespondIsTypeCheckedAndBeforeOnly(t *testing.T) {
	p := newTestPlugin(auth.OperationHook{Match: []auth.EndpointID{opEcho}, Before: func(_ context.Context, c *auth.Call) error {
		c.Respond(42)
		return nil
	}})
	wire(t, p)
	if _, err := p.echo.Call(context.Background(), echoIn{}); !errors.Is(err, auth.ErrBadOperation) {
		t.Fatalf("err = %v, want ErrBadOperation", err)
	}
	var second int
	q := newTestPlugin(
		auth.OperationHook{Match: []auth.EndpointID{opEcho}, After: func(_ context.Context, c *auth.Call, _ any) error {
			c.Respond(echoOut{Text: "late"})
			return nil
		}},
		auth.OperationHook{Match: []auth.EndpointID{opEcho}, After: func(context.Context, *auth.Call, any) error { second++; return nil }},
	)
	wire(t, q)
	if out, err := q.echo.Call(context.Background(), echoIn{Text: "real"}); err != nil || out.Text != "real" || second != 1 {
		t.Fatalf("Call = %+v, %v, second after hook ran %d; want real and 1", out, err, second)
	}
}

// RunInBackground hands the task to the WithBackground runner with a context
// that outlives the caller's cancellation, and WaitDeliveries waits for it.
func TestRunInBackground_UsesTheRunnerAndIsWaitedFor(t *testing.T) {
	var handed, done atomic.Int32
	runner := func(ctx context.Context, task func(context.Context)) {
		handed.Add(1)
		go task(ctx)
	}
	a, err := newAuth(auth.WithPlugins(signIn{on: true}), auth.WithBackground(runner))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.RunInBackground(ctx, func(ctx context.Context) {
		if ctx.Err() == nil {
			if _, ok := ctx.Deadline(); ok {
				done.Add(1)
			}
		}
	})
	a.WaitDeliveries()
	if handed.Load() != 1 || done.Load() != 1 {
		t.Fatalf("handed %d, done %d; want the runner used and a live, bounded context", handed.Load(), done.Load())
	}
}

// RedirectOnError("") takes WithErrorURL's page; without the option such a
// failure stays JSON; New refuses an off-site page.
func TestWithErrorURL(t *testing.T) {
	failing := func() *testPlugin {
		return newTestPlugin(auth.OperationHook{Match: []auth.EndpointID{opFail}, Before: func(_ context.Context, c *auth.Call) error {
			c.RedirectOnError("")
			return nil
		}})
	}
	for _, tc := range []struct {
		opts []auth.Option
		want string
	}{
		{[]auth.Option{auth.WithErrorURL("/auth/error")}, "/auth/error?error=testp.failed"},
		{nil, ""},
	} {
		p := failing()
		a, err := auth.New(append([]auth.Option{auth.WithBaseURL(trustedOrigin), auth.WithPlugins(p)}, tc.opts...)...)
		if err != nil {
			t.Fatal(err)
		}
		ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{Origin: trustedOrigin}})
		if _, err := p.fail.Call(ctx, struct{}{}); !errors.Is(err, errOpFailed) {
			t.Fatalf("err = %v", err)
		}
		got := ""
		for _, ef := range auth.RequestEffects(ctx) {
			if ef.Kind == auth.EffectRedirect {
				got = ef.URL
			}
		}
		if got != tc.want || a.Config().ErrorURL != strings.TrimSuffix(tc.want, "?error=testp.failed") {
			t.Fatalf("redirect %q, want %q", got, tc.want)
		}
	}
	if _, err := newAuth(auth.WithPlugins(signIn{on: true}), auth.WithErrorURL("https://evil.example/oops")); !errors.Is(err, auth.ErrBadOperation) {
		t.Fatalf("an off-site error page: %v", err)
	}
}

// RequireOwner on a call with no user refuses before any read.
func TestRequireOwner_SignedOut(t *testing.T) {
	p := newTestPlugin(auth.OperationHook{Match: []auth.EndpointID{opEcho}, Before: func(ctx context.Context, c *auth.Call) error {
		return c.RequireOwner(ctx, auth.Ownership{Table: auth.TableSession}, "ses_1")
	}})
	wire(t, p)
	if _, err := p.echo.Call(context.Background(), echoIn{}); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("err = %v", err)
	}
}

// CheckCookieName takes a lower-case name and refuses the core's own.
func TestCheckCookieName(t *testing.T) {
	for _, ok := range []string{"two_factor", "a", "x1"} {
		if err := auth.CheckCookieName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Two", "1x", "a-b", "session", "flow", "session_cache", "device", "account_x", strings.Repeat("a", 33)} {
		if err := auth.CheckCookieName(bad); !errors.Is(err, auth.ErrBadCookieName) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	var e auth.Effects
	if err := e.SetCookie("session", "x", time.Time{}); !errors.Is(err, auth.ErrBadCookieName) || len(e.List()) != 0 {
		t.Fatalf("a reserved name was recorded: %v", err)
	}
}

// cookieJar is a Request.Cookie over a map, as a transport fills it.
func cookieJar(m map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) { v, ok := m[name]; return v, ok }
}

// cookieApp is an Auth under secrets whose echo hook reads the plain and the
// signed cookie into reads and sets both again.
type cookieApp struct {
	a     *auth.Auth
	p     *testPlugin
	reads []string
}

func newCookieApp(t *testing.T, secrets ...[]byte) *cookieApp {
	t.Helper()
	ca := &cookieApp{}
	ca.p = newTestPlugin(auth.OperationHook{Match: []auth.EndpointID{opEcho}, Before: func(_ context.Context, c *auth.Call) error {
		v, ok := c.Cookie("plain")
		_, bad := c.Cookie("Bad-Name")
		sv, sok := c.SignedCookie("state")
		ca.reads = append(ca.reads, fmt.Sprintf("%s %v %v %s %v", v, ok, bad, sv, sok))
		if err := c.Effects.SetCookie("plain", "bye", time.Unix(0, 0).Add(time.Hour)); err != nil {
			return err
		}
		return c.SetSignedCookie("state", "s1", time.Time{})
	}})
	opts := []auth.Option{auth.WithBaseURL(trustedOrigin), auth.WithPlugins(ca.p)}
	if len(secrets) > 0 {
		opts = append(opts, auth.WithSecret(secrets[0], secrets[1:]...))
	}
	a, err := auth.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	ca.a = a
	return ca
}

// call runs echo with jar as the client's cookies and returns the effects
// and the error.
func (ca *cookieApp) call(jar map[string]string) ([]auth.Effect, error) {
	ctx := ca.a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{Origin: trustedOrigin}, Cookie: cookieJar(jar)})
	_, err := ca.p.echo.Call(ctx, echoIn{})
	return auth.RequestEffects(ctx), err
}

// A hook reads the cookies the client sent and sets its own as effects; a
// signed cookie verifies only unchanged, with the current or a previous
// secret, and needs a secret to be set at all.
func TestPluginCookies(t *testing.T) {
	cur, old := []byte(strings.Repeat("n", 32)), []byte(strings.Repeat("o", 32))
	signer := newCookieApp(t, old)
	effects, err := signer.call(map[string]string{"plain": "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if len(effects) != 2 || effects[0].Kind != auth.EffectCookie || effects[0].Name != "plain" || effects[0].Value != "bye" || effects[1].Name != "state" {
		t.Fatalf("effects = %+v", effects)
	}
	signed := effects[1].Value
	if strings.Contains(signed, "s1") || !strings.Contains(signed, ".") {
		t.Fatalf("signed value %q", signed)
	}
	if signer.reads[0] != "hello true false  false" {
		t.Fatalf("first read %q", signer.reads[0])
	}
	rotated := newCookieApp(t, cur, old)
	// The tampered value ends in two characters it did not end in; a
	// signature already ending in "AA" would otherwise be left intact.
	tail := "AA"
	if strings.HasSuffix(signed, tail) {
		tail = "BB"
	}
	for _, tc := range []struct{ value, want string }{
		{signed, "s1 true"},
		{signed[:len(signed)-2] + tail, " false"},
		{"no-separator", " false"},
		{"!!.AA", " false"},
		{"czE.!!", " false"},
	} {
		rotated.reads = nil
		if _, err := rotated.call(map[string]string{"state": tc.value}); err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimPrefix(rotated.reads[0], " false false "); got != tc.want {
			t.Errorf("%q read as %q, want %q", tc.value, got, tc.want)
		}
	}
	// The previous secret dropped: the old signature stops verifying.
	fresh := newCookieApp(t, cur)
	if _, err := fresh.call(map[string]string{"state": signed}); err != nil || !strings.HasSuffix(fresh.reads[0], " false") {
		t.Fatalf("a value from a dropped secret: %q, %v", fresh.reads, err)
	}
	// No secret: SignedCookie reads nothing and SetSignedCookie fails the call.
	none := newCookieApp(t)
	if _, err := none.call(map[string]string{"state": signed}); !errors.Is(err, auth.ErrNoSecret) || !strings.HasSuffix(none.reads[0], " false") {
		t.Fatalf("no secret: %q, %v", none.reads, err)
	}
	// Outside a request, and from a Go call with no cookies, there are none.
	if _, ok := auth.RequestCookie(context.Background(), "plain"); ok {
		t.Fatal("a cookie outside a request")
	}
}

// A signed cookie name is checked like a plain one.
func TestSetSignedCookie_ChecksTheName(t *testing.T) {
	p := newTestPlugin(auth.OperationHook{Match: []auth.EndpointID{opEcho}, Before: func(_ context.Context, c *auth.Call) error {
		return c.SetSignedCookie("flow", "x", time.Time{})
	}})
	if _, err := auth.New(auth.WithBaseURL(trustedOrigin), auth.WithPlugins(p), auth.WithSecret([]byte(strings.Repeat("k", 32)))); err != nil {
		t.Fatal(err)
	}
	if _, err := p.echo.Call(context.Background(), echoIn{}); !errors.Is(err, auth.ErrBadCookieName) {
		t.Fatalf("err = %v", err)
	}
}

// PageSize keeps a request within the list's limit, and WithDefaultPageSize
// replaces only the default, never the limit; New refuses a negative one.
func TestPageSize(t *testing.T) {
	var none auth.Config
	set := auth.Config{DefaultPageSize: 20}
	big := auth.Config{DefaultPageSize: 500}
	for _, tc := range []struct {
		c                          auth.Config
		requested, fallback, limit int
		want                       int
	}{
		{none, 0, 50, 200, 50},
		{none, 10, 50, 200, 10},
		{none, 900, 50, 200, 200},
		{set, 0, 50, 200, 20},
		{set, -1, 50, 200, 20},
		{set, 30, 50, 200, 30},
		{big, 0, 50, 200, 200},
	} {
		if got := tc.c.PageSize(tc.requested, tc.fallback, tc.limit); got != tc.want {
			t.Errorf("%+v: %d, want %d", tc, got, tc.want)
		}
	}
	a, err := newAuth(auth.WithPlugins(signIn{on: true}), auth.WithDefaultPageSize(20))
	if err != nil || a.Config().DefaultPageSize != 20 {
		t.Fatalf("%v", err)
	}
	if _, err := newAuth(auth.WithPlugins(signIn{on: true}), auth.WithDefaultPageSize(-1)); !errors.Is(err, auth.ErrBadOperation) {
		t.Fatalf("negative: %v", err)
	}
}

// StartSpan without a tracer is a no-op; MiddlewareSpan names the plugin and
// the route.
func TestStartSpan_NoTracer(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(signIn{on: true}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	got, end := a.StartSpan(ctx, auth.MiddlewareSpan("p", auth.TransportHTTP, "/x"))
	end(nil)
	if got != ctx {
		t.Fatal("a span without a tracer changed the context")
	}
	if s := auth.MiddlewareSpan("p", auth.TransportHTTP, "/x"); s.Name != "auth.middleware p /x" || s.Kind != auth.SpanMiddleware || s.Route != "/x" {
		t.Fatalf("%+v", s)
	}
}

// The storage-backed session store meets the SessionStore contract over the
// in-memory SecondaryStorage.
func TestStorageSessionStore_Contract(t *testing.T) {
	sessiontest.Run(t, func(*testing.T) auth.SessionStore {
		return auth.NewStorageSessionStore(auth.NewMemoryStorage(nil))
	})
}

// "Sign out everywhere" ends a session the user's list lost (two instances
// interleaving their list writes), because Find checks the generation, not
// the list; the excepted session survives.
func TestStorageSessionStore_DeleteUserDoesNotTrustTheList(t *testing.T) {
	ctx := context.Background()
	kv := auth.NewMemoryStorage(nil)
	st := auth.NewStorageSessionStore(kv)
	now := time.Now()
	mk := func(id string) auth.Session {
		return auth.Session{ID: id, UserID: "usr_1", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}
	}
	for _, id := range []string{"a", "b", "lost"} {
		if err := st.Insert(ctx, mk(id), []byte("hash-"+id)); err != nil {
			t.Fatal(err)
		}
	}
	// Another instance's write dropped "lost" from the list.
	if err := kv.Set(ctx, "auth:user-sessions:usr_1", "a b", 0); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteUser(ctx, "usr_1", "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Find(ctx, []byte("hash-lost"), now); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("the session the list lost survived: %v", err)
	}
	if _, err := st.Find(ctx, []byte("hash-b"), now); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("a listed session survived: %v", err)
	}
	if s, err := st.Find(ctx, []byte("hash-a"), now); err != nil || s.ID != "a" {
		t.Fatalf("the excepted session: %v", err)
	}
	// A session made after the sign-out opens.
	if err := st.Insert(ctx, mk("new"), []byte("hash-new")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Find(ctx, []byte("hash-new"), now); err != nil {
		t.Fatalf("a new session: %v", err)
	}
}

// The in-memory storage expires keys on its clock, counts in a fixed window
// and refuses a negative ttl or a non-counter.
func TestMemoryStorage(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	kv := auth.NewMemoryStorage(func() time.Time { return now })
	if err := kv.Set(ctx, "k", "v", time.Minute); err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := kv.Get(ctx, "k"); !ok || v != "v" {
		t.Fatal("set then get")
	}
	for i, want := range []int64{1, 2} {
		if n, err := kv.Increment(ctx, "c", time.Minute); err != nil || n != want {
			t.Fatalf("increment %d: %d, %v", i, n, err)
		}
	}
	now = now.Add(time.Minute)
	if _, ok, _ := kv.Get(ctx, "k"); ok {
		t.Fatal("an expired key was read")
	}
	if n, _ := kv.Increment(ctx, "c", time.Minute); n != 1 {
		t.Fatalf("a new window starts at 1, got %d", n)
	}
	_ = kv.Delete(ctx, "c")
	if _, ok, _ := kv.Get(ctx, "c"); ok {
		t.Fatal("deleted key read")
	}
	if err := kv.Set(ctx, "k", "v", -time.Second); err == nil {
		t.Fatal("negative ttl set")
	}
	if _, err := kv.Increment(ctx, "k2", -time.Second); err == nil {
		t.Fatal("negative ttl increment")
	}
	_ = kv.Set(ctx, "text", "abc", 0)
	if _, err := kv.Increment(ctx, "text", 0); err == nil {
		t.Fatal("incremented a non-counter")
	}
	if n, _ := kv.Increment(ctx, "forever", 0); n != 1 {
		t.Fatal("increment without ttl")
	}
	if auth.NewMemoryStorage(nil) == nil {
		t.Fatal("nil clock")
	}
}

// WithSecondaryStorage puts sessions and rate counts in the storage: a rate
// rule counts through Increment.
func TestWithSecondaryStorage_RateStore(t *testing.T) {
	kv := auth.NewMemoryStorage(nil)
	rs := auth.NewStorageRateStore(kv)
	for want := 1; want <= 2; want++ {
		if n, err := rs.Hit(context.Background(), "ip:1", time.Minute); err != nil || n != want {
			t.Fatalf("hit %d: %d, %v", want, n, err)
		}
	}
	if v, ok, _ := kv.Get(context.Background(), "auth:rate:ip:1"); !ok || v != "2" {
		t.Fatalf("counter %q %v", v, ok)
	}
	if _, err := newAuth(auth.WithPlugins(signIn{on: true}), auth.WithSecondaryStorage(kv)); err != nil {
		t.Fatal(err)
	}
}

// faultKV is a SecondaryStorage that fails its armed call (1-based) and
// counts calls; 0 arms nothing.
type faultKV struct {
	auth.SecondaryStorage
	armed, calls int
}

var errKV = errors.New("kv: injected failure")

func (f *faultKV) hit() error {
	f.calls++
	if f.calls == f.armed {
		return errKV
	}
	return nil
}
func (f *faultKV) Get(ctx context.Context, k string) (string, bool, error) {
	if err := f.hit(); err != nil {
		return "", false, err
	}
	return f.SecondaryStorage.Get(ctx, k)
}
func (f *faultKV) Set(ctx context.Context, k, v string, ttl time.Duration) error {
	if err := f.hit(); err != nil {
		return err
	}
	return f.SecondaryStorage.Set(ctx, k, v, ttl)
}
func (f *faultKV) Delete(ctx context.Context, k string) error {
	if err := f.hit(); err != nil {
		return err
	}
	return f.SecondaryStorage.Delete(ctx, k)
}
func (f *faultKV) Increment(ctx context.Context, k string, ttl time.Duration) (int64, error) {
	if err := f.hit(); err != nil {
		return 0, err
	}
	return f.SecondaryStorage.Increment(ctx, k, ttl)
}

// Every storage call each store method makes reaches the caller when it
// fails: the sweep fails call 1, 2, ... until a run makes fewer calls.
func TestStorageSessionStore_Faults(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	sess := func(id string) auth.Session {
		return auth.Session{ID: id, UserID: "usr_1", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}
	}
	// seed holds two sessions of usr_1, one pending, so List, DeleteUser and
	// the rest walk every branch.
	seed := func(st auth.SessionStore) {
		p := sess("p")
		p.SecondFactorPending = true
		for _, s := range []auth.Session{sess("a"), sess("b"), p} {
			if err := st.Insert(ctx, s, []byte("h"+s.ID)); err != nil {
				t.Fatal(err)
			}
		}
	}
	ops := map[string]func(st auth.SessionStore) error{
		"insert": func(st auth.SessionStore) error { return st.Insert(ctx, sess("c"), []byte("hc")) },
		"find": func(st auth.SessionStore) error {
			_, err := st.Find(ctx, []byte("ha"), now)
			return err
		},
		"touch": func(st auth.SessionStore) error {
			_, err := st.Touch(ctx, "a", now.Add(2*time.Hour), now)
			return err
		},
		"list": func(st auth.SessionStore) error {
			_, err := st.List(ctx, "usr_1", now)
			return err
		},
		"delete":      func(st auth.SessionStore) error { return st.Delete(ctx, "usr_1", "a") },
		"delete user": func(st auth.SessionStore) error { return st.DeleteUser(ctx, "usr_1", "a") },
		"set data":    func(st auth.SessionStore) error { return st.SetData(ctx, "a", auth.AppData(`{"x":1}`)) },
	}
	for name, op := range ops {
		for k := 1; ; k++ {
			f := &faultKV{SecondaryStorage: auth.NewMemoryStorage(nil)}
			st := auth.NewStorageSessionStore(f)
			seed(st)
			f.calls, f.armed = 0, k
			err := op(st)
			if f.calls < k {
				if err != nil {
					t.Fatalf("%s: unfaulted run failed: %v", name, err)
				}
				break
			}
			if !errors.Is(err, errKV) {
				t.Errorf("%s: fault at call %d returned %v", name, k, err)
			}
		}
	}
}

// Records that do not decode are errors, not misses; a session whose data is
// not JSON is refused at Insert; a session the store does not hold is no
// error to Touch, Delete or SetData.
func TestStorageSessionStore_BadRecords(t *testing.T) {
	ctx := context.Background()
	kv := auth.NewMemoryStorage(nil)
	st := auth.NewStorageSessionStore(kv)
	now := time.Now()
	s := auth.Session{ID: "a", UserID: "usr_1", CreatedAt: now, ExpiresAt: now.Add(time.Hour), Data: auth.AppData("{")}
	if err := st.Insert(ctx, s, []byte("ha")); err == nil {
		t.Fatal("data that is not JSON was stored")
	}
	_ = kv.Set(ctx, "auth:session:"+fmt.Sprintf("%x", "hb"), "{", 0)
	if _, err := st.Find(ctx, []byte("hb"), now); err == nil || errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("a broken record: %v", err)
	}
	s.Data = nil
	if err := st.Insert(ctx, s, []byte("ha")); err != nil {
		t.Fatal(err)
	}
	_ = kv.Set(ctx, "auth:user-generation:usr_1", "x", 0)
	if _, err := st.Find(ctx, []byte("ha"), now); err == nil || errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("a broken generation: %v", err)
	}
	_ = kv.Delete(ctx, "auth:user-generation:usr_1")
	if _, err := st.Find(ctx, []byte("ha"), now.Add(2*time.Hour)); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := st.Find(ctx, []byte("nope"), now); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if moved, err := st.Touch(ctx, "nope", now, now); moved || err != nil {
		t.Fatalf("touch missing: %v %v", moved, err)
	}
	if err := st.Delete(ctx, "usr_2", "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Find(ctx, []byte("ha"), now); err != nil {
		t.Fatalf("another user's delete ended the session: %v", err)
	}
	if err := st.SetData(ctx, "nope", nil); err != nil {
		t.Fatal(err)
	}
	if n, err := st.Sweep(ctx, now); n != 0 || err != nil {
		t.Fatal("sweep")
	}
	// DeleteUser with a listed id whose records are gone skips it.
	_ = kv.Set(ctx, "auth:user-sessions:usr_1", "a gone", 0)
	if err := st.DeleteUser(ctx, "usr_1", ""); err != nil {
		t.Fatal(err)
	}
	if ids, _, _ := kv.Get(ctx, "auth:user-sessions:usr_1"); ids != "" {
		t.Fatalf("list after sign-out everywhere: %q", ids)
	}
}

// BaseURLFor answers the request's base URL, and "" outside a request.
func TestBaseURLFor(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(signIn{on: true}))
	if err != nil {
		t.Fatal(err)
	}
	if got := auth.BaseURLFor(context.Background()); got != "" {
		t.Fatalf("outside a request: %q", got)
	}
	if got := auth.BaseURLFor(a.WithRequest(context.Background(), auth.Request{})); got != "https://app.example.com" {
		t.Fatalf("in a request: %q", got)
	}
}
