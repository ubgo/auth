package auth_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// The configuration switches: each test proves the switch and that the
// default keeps the earlier behaviour.

func TestTrustsOrigin_WildcardPatterns(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(basic("s")), auth.WithTrustedOrigins("https://*.example.com", "http://*.local.test:3000"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"https://app.example.com":       true,
		"https://deep.sub.example.com":  true,
		"https://app.example.com:8443":  true, // a pattern without a port matches any port
		"https://example.com":           false,
		"https://evilexample.com":       false,
		"https://.example.com":          false,
		"http://app.example.com":        false, // the scheme is part of the pattern
		"http://web.local.test:3000":    true,
		"http://web.local.test":         false, // a pattern with a port needs it
		"https://app.example.com.evil":  false,
		"":                              false,
		"https://app.example.com/path":  false, // an origin has no path
		"https://other.app.example.net": false,
	}
	for origin, want := range cases {
		if got := a.TrustsOrigin(origin); got != want {
			t.Errorf("TrustsOrigin(%q) = %v, want %v", origin, got, want)
		}
	}
	if !a.TrustsOrigin(trustedOrigin) {
		t.Fatal("the base URL stays trusted next to the patterns")
	}
}

func TestNew_RefusesMalformedOriginPatterns(t *testing.T) {
	for _, raw := range []string{"https://*", "https://*.com", "https://api.*", "https://*.example.*", "https://a[b]*.example.com", "https://*.example.com/path", "https://*.example.com:http", "https://*..example.com", "https://u@*.example.com"} {
		_, err := newAuth(auth.WithPlugins(basic("s")), auth.WithTrustedOrigins(raw))
		if !errors.Is(err, auth.ErrBadOrigin) {
			t.Errorf("%q: got %v, want ErrBadOrigin", raw, err)
		}
	}
}

func TestTrustsOrigin_FunctionIsAskedLast(t *testing.T) {
	var asked []string
	fn := func(origin string) bool {
		asked = append(asked, origin)
		return origin == "https://tenant.example.org"
	}
	a, err := newAuth(auth.WithPlugins(basic("s")), auth.WithTrustedOriginFunc(fn))
	if err != nil {
		t.Fatal(err)
	}
	if !a.TrustsOrigin(trustedOrigin) {
		t.Fatal("the base URL must be trusted without asking")
	}
	if len(asked) != 0 {
		t.Fatalf("the function was asked for a statically trusted origin: %v", asked)
	}
	if !a.TrustsOrigin("https://tenant.example.org") || a.TrustsOrigin("https://other.example.org") {
		t.Fatal("the function's answer was not used")
	}
	if a.TrustsOrigin("") || len(asked) != 2 {
		t.Fatalf("an empty origin must be refused without asking; asked %v", asked)
	}
	// The pipeline uses the same answer: a cookie mutation from the dynamic
	// origin passes, one from elsewhere is refused.
	p := newTestPlugin()
	a, err = newAuth(auth.WithPlugins(p), auth.WithTrustedOriginFunc(fn))
	if err != nil {
		t.Fatal(err)
	}
	for origin, wantErr := range map[string]error{"https://tenant.example.org": nil, "https://other.example.org": auth.ErrOriginNotTrusted} {
		ctx := a.WithRequest(context.Background(), auth.Request{Credential: auth.CredentialCookie, Client: auth.Client{Origin: origin}})
		_, err := p.echo.Call(ctx, echoIn{Text: "x"})
		if !errors.Is(err, wantErr) {
			t.Errorf("from %q: got %v, want %v", origin, err, wantErr)
		}
	}
}

func TestWithDisabledOperations(t *testing.T) {
	p := newTestPlugin()
	a, err := newAuth(auth.WithPlugins(p), auth.WithDisabledOperations(opEcho))
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range a.Operations() {
		if op.Info().ID == opEcho {
			t.Fatal("a disabled operation is still in the list transports serve")
		}
	}
	if _, ok := a.Operation(opEcho); ok {
		t.Fatal("Operation found a disabled operation")
	}
	if _, err := p.echo.Call(context.Background(), echoIn{Text: "x"}); !errors.Is(err, auth.ErrUnknownOperation) {
		t.Fatalf("a Go call to a disabled operation: got %v, want ErrUnknownOperation", err)
	}
	if _, err := p.echo.Invoke(a.WithRequest(context.Background(), auth.Request{}), func(any) error { return nil }); !errors.Is(err, auth.ErrUnknownOperation) {
		t.Fatalf("Invoke of a disabled operation: got %v, want ErrUnknownOperation", err)
	}
	if p.ran != 0 {
		t.Fatal("the disabled operation's logic ran")
	}
	if _, err := p.issue.Call(context.Background(), struct{}{}); err != nil {
		t.Fatalf("the other operations must still run: %v", err)
	}
	if got := a.DisabledOperations(); len(got) != 1 || got[0] != opEcho {
		t.Fatalf("DisabledOperations = %v", got)
	}
	if got := newTestPlugin().echo; got.Plugin() != "" {
		t.Fatal("a fresh operation is not bound")
	}

	// A typo is refused: the operation the deployment meant to switch off
	// would otherwise still be served.
	_, err = newAuth(auth.WithPlugins(newTestPlugin()), auth.WithDisabledOperations("testp.nope"))
	if !errors.Is(err, auth.ErrUnknownHookTarget) {
		t.Fatalf("an unknown id: got %v, want ErrUnknownHookTarget", err)
	}

	// A hook and a rate rule aimed at the disabled operation are kept.
	hooked := newTestPlugin(auth.OperationHook{Match: []auth.EndpointID{opEcho}})
	_, err = newAuth(auth.WithPlugins(hooked, rulePlugin{rule: auth.RateRule{Match: opEcho, Key: auth.ByIP, Limit: 1, Window: time.Minute}}), auth.WithDisabledOperations(opEcho))
	if err != nil {
		t.Fatalf("a hook or rule on a disabled operation must not be refused: %v", err)
	}

	// Without the option the operation is served: the default is unchanged.
	fresh := newTestPlugin()
	a, err = newAuth(auth.WithPlugins(fresh))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Operation(opEcho); !ok || len(a.DisabledOperations()) != 0 {
		t.Fatal("without WithDisabledOperations every operation is served")
	}
}

// movingClock is a clock tests advance by hand.
type movingClock struct{ t time.Time }

func (c *movingClock) Now() time.Time { return c.t }

// limitedAuth wires the test plugin with a plugin rule of two calls a minute
// on echo, counted by IP, and the given extra options.
func limitedAuth(t *testing.T, clk *movingClock, opts ...auth.Option) (*auth.Auth, *testPlugin) {
	t.Helper()
	p := newTestPlugin()
	all := append([]auth.Option{
		auth.WithPlugins(p, rulePlugin{rule: auth.RateRule{Match: opEcho, Key: auth.ByIP, Limit: 2, Window: time.Minute}}),
		auth.WithClock(clk.Now), auth.WithRateStore(auth.NewMemoryRateStore(clk.Now)),
	}, opts...)
	a, err := newAuth(all...)
	if err != nil {
		t.Fatal(err)
	}
	return a, p
}

// callsUntilLimited runs op from ip until ErrRateLimited and returns how many
// calls succeeded, or -1 when max calls all succeed.
func callsUntilLimited(t *testing.T, a *auth.Auth, op *auth.Op[echoIn, echoOut], ip string, max int) int {
	t.Helper()
	ctx := a.WithRequest(context.Background(), auth.Request{Client: auth.Client{IP: ip}})
	for i := range max {
		_, err := op.Call(ctx, echoIn{Text: "x"})
		if errors.Is(err, auth.ErrRateLimited) {
			return i
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return -1
}

func TestWithRateRules_ReplacesThePluginsRules(t *testing.T) {
	clk := &movingClock{t: time.Unix(1_700_000_000, 0)}
	a, p := limitedAuth(t, clk)
	if n := callsUntilLimited(t, a, p.echo, "203.0.113.7", 10); n != 2 {
		t.Fatalf("the plugin's rule allows 2, got %d", n)
	}
	a, p = limitedAuth(t, clk, auth.WithRateRules(auth.RateRule{Match: opEcho, Key: auth.ByIP, Limit: 5, Window: time.Minute}))
	if n := callsUntilLimited(t, a, p.echo, "203.0.113.7", 10); n != 5 {
		t.Fatalf("the app's rule replaces the plugin's: want 5 calls, got %d", n)
	}
	// Two app rules for one operation accumulate; the first clears the
	// plugin's. The identifier rule here cannot fire (echoIn is not
	// Identified), which proves the IP rule alone is in force.
	a, p = limitedAuth(t, clk, auth.WithRateRules(
		auth.RateRule{Match: opEcho, Key: auth.ByIdentifier, Limit: 1, Window: time.Minute},
		auth.RateRule{Match: opEcho, Key: auth.ByIP, Limit: 3, Window: time.Minute},
	))
	if n := callsUntilLimited(t, a, p.echo, "203.0.113.7", 10); n != 3 {
		t.Fatalf("two app rules: want 3 calls, got %d", n)
	}
	// A rule for an operation nothing limits adds the first one.
	a, p = limitedAuth(t, clk, auth.WithRateRules(auth.RateRule{Match: opIssue, Key: auth.ByIP, Limit: 1, Window: time.Minute}))
	ctx := a.WithRequest(context.Background(), auth.Request{Client: auth.Client{IP: "203.0.113.7"}})
	if _, err := p.issue.Call(ctx, struct{}{}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.issue.Call(ctx, struct{}{}); !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("the added rule did not count: %v", err)
	}
	// The app's rules are validated like a plugin's.
	for name, r := range map[string]auth.RateRule{
		"unknown operation": {Match: "testp.nope", Key: auth.ByIP, Limit: 1, Window: time.Minute},
		"no limit":          {Match: opEcho, Key: auth.ByIP, Window: time.Minute},
		"no window":         {Match: opEcho, Key: auth.ByIP, Limit: 1},
		"unknown key":       {Match: opEcho, Key: "country", Limit: 1, Window: time.Minute},
	} {
		if _, err := newAuth(auth.WithPlugins(newTestPlugin()), auth.WithRateRules(r)); err == nil {
			t.Errorf("%s: New accepted an invalid app rule", name)
		}
	}
}

func TestWithRateLimit_IsAFloorUnderEveryOperation(t *testing.T) {
	clk := &movingClock{t: time.Unix(1_700_000_000, 0)}
	a, p := limitedAuth(t, clk, auth.WithRateLimit(3, time.Minute))
	// echo: the plugin's rule of 2 is tighter and still wins.
	if n := callsUntilLimited(t, a, p.echo, "203.0.113.7", 10); n != 2 {
		t.Fatalf("echo: want the plugin's 2, got %d", n)
	}
	// issue: no plugin rule, the blanket one applies, per operation and per
	// address.
	call := func(ip string) error {
		ctx := a.WithRequest(context.Background(), auth.Request{Client: auth.Client{IP: ip}})
		_, err := p.issue.Call(ctx, struct{}{})
		return err
	}
	for range 3 {
		if err := call("203.0.113.7"); err != nil {
			t.Fatal(err)
		}
	}
	if err := call("203.0.113.7"); !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("fourth call from one address: %v", err)
	}
	if err := call("203.0.113.8"); err != nil {
		t.Fatalf("another address has its own counter: %v", err)
	}
	if _, err := p.fail.Call(a.WithRequest(context.Background(), auth.Request{Client: auth.Client{IP: "203.0.113.7"}}), struct{}{}); !errors.Is(err, errOpFailed) {
		t.Fatalf("the counter is per operation: fail from the same address must run: %v", err)
	}
	// A Go call with no address is not counted by the blanket rule either.
	for range 5 {
		if _, err := p.issue.Call(context.Background(), struct{}{}); err != nil {
			t.Fatal(err)
		}
	}
	// The window reopens.
	clk.t = clk.t.Add(time.Minute)
	if err := call("203.0.113.7"); err != nil {
		t.Fatalf("after the window: %v", err)
	}
	for name, opt := range map[string]auth.Option{"no limit": auth.WithRateLimit(0, time.Minute), "no window": auth.WithRateLimit(1, 0)} {
		if _, err := newAuth(auth.WithPlugins(newTestPlugin()), opt); !errors.Is(err, auth.ErrBadOperation) {
			t.Errorf("%s: got %v, want ErrBadOperation", name, err)
		}
	}
}

func TestWithIPv6Prefix_CountsABlockAsOneClient(t *testing.T) {
	clk := &movingClock{t: time.Unix(1_700_000_000, 0)}
	// Default: whole addresses, so two addresses of one /64 are two clients.
	a, p := limitedAuth(t, clk)
	if n := callsUntilLimited(t, a, p.echo, "2001:db8:1:2::10", 10); n != 2 {
		t.Fatalf("first address: %d", n)
	}
	if n := callsUntilLimited(t, a, p.echo, "2001:db8:1:2::11", 10); n != 2 {
		t.Fatalf("by default a second address of the block has its own counter, got %d", n)
	}
	// Canonical forms are one counter even by default.
	a, p = limitedAuth(t, clk)
	if n := callsUntilLimited(t, a, p.echo, "2001:db8::1", 10); n != 2 {
		t.Fatalf("canonical: %d", n)
	}
	if n := callsUntilLimited(t, a, p.echo, "2001:0db8:0000:0000:0000:0000:0000:0001", 10); n != 0 {
		t.Fatalf("the long form of the same address must share the counter, got %d calls", n)
	}
	if n := callsUntilLimited(t, a, p.echo, "::ffff:203.0.113.7", 10); n != 2 {
		t.Fatalf("mapped v4: %d", n)
	}
	if n := callsUntilLimited(t, a, p.echo, "203.0.113.7", 10); n != 0 {
		t.Fatalf("an IPv4-mapped address is its IPv4 address, got %d calls", n)
	}
	// With a /64 the block shares one counter; IPv4 is unaffected.
	a, p = limitedAuth(t, clk, auth.WithIPv6Prefix(64))
	if n := callsUntilLimited(t, a, p.echo, "2001:db8:1:2::10", 10); n != 2 {
		t.Fatalf("first address of the block: %d", n)
	}
	if n := callsUntilLimited(t, a, p.echo, "2001:db8:1:2:ffff::11", 10); n != 0 {
		t.Fatalf("the block must share the counter, got %d calls", n)
	}
	if n := callsUntilLimited(t, a, p.echo, "2001:db8:1:3::10", 10); n != 2 {
		t.Fatalf("the next block is another client: %d", n)
	}
	if n := callsUntilLimited(t, a, p.echo, "203.0.113.7", 10); n != 2 {
		t.Fatalf("IPv4: %d", n)
	}
	// A value that is not an address is counted as given.
	if n := callsUntilLimited(t, a, p.echo, "not-an-address", 10); n != 2 {
		t.Fatalf("opaque value: %d", n)
	}
	for _, bits := range []int{-1, 129} {
		if _, err := newAuth(auth.WithPlugins(newTestPlugin()), auth.WithIPv6Prefix(bits)); !errors.Is(err, auth.ErrBadOperation) {
			t.Errorf("bits %d: got %v, want ErrBadOperation", bits, err)
		}
	}
	if _, err := newAuth(auth.WithPlugins(newTestPlugin()), auth.WithIPv6Prefix(auth.IPv6PrefixBits)); err != nil {
		t.Fatalf("the whole address is a valid prefix: %v", err)
	}
}

func TestCall_InputIsVisibleToHooks(t *testing.T) {
	var before, after any
	var beforeTransport auth.Transport
	p := newTestPlugin(auth.OperationHook{
		Match: []auth.EndpointID{opEcho},
		Before: func(_ context.Context, c *auth.Call) error {
			before, beforeTransport = c.Input, c.Transport
			in, ok := c.Input.(echoIn)
			if ok && in.Text == "forbidden" {
				return errOpFailed
			}
			return nil
		},
		After: func(_ context.Context, c *auth.Call, _ any) error { after = c.Input; return nil },
	})
	a, err := newAuth(auth.WithPlugins(p))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.echo.Call(context.Background(), echoIn{Text: "hello"}); err != nil {
		t.Fatal(err)
	}
	if before != (echoIn{Text: "hello"}) || after != (echoIn{Text: "hello"}) || beforeTransport != auth.TransportGo {
		t.Fatalf("hooks saw before=%v after=%v transport=%v", before, after, beforeTransport)
	}
	if _, err := p.echo.Call(context.Background(), echoIn{Text: "forbidden"}); !errors.Is(err, errOpFailed) {
		t.Fatalf("a Before hook that read the input could not refuse it: %v", err)
	}
	// Over a transport the decoded input is what the hook sees.
	ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP})
	out, err := p.echo.Invoke(ctx, func(dst any) error { *(dst.(*echoIn)) = echoIn{Text: "decoded"}; return nil })
	if err != nil || out != (echoOut{Text: "decoded"}) || before != (echoIn{Text: "decoded"}) || beforeTransport != auth.TransportHTTP {
		t.Fatalf("Invoke: out=%v err=%v before=%v transport=%v", out, err, before, beforeTransport)
	}
}

func TestWithObserver_SeesEveryCallEnd(t *testing.T) {
	clk := &movingClock{t: time.Unix(1_700_000_000, 0)}
	var events []auth.OperationEvent
	p := newTestPlugin(auth.OperationHook{Match: []auth.EndpointID{opEcho}, Before: func(context.Context, *auth.Call) error {
		clk.t = clk.t.Add(25 * time.Millisecond) // the operation takes time
		return nil
	}})
	a, err := newAuth(auth.WithPlugins(p), auth.WithClock(clk.Now),
		auth.WithObserver(auth.ObserverFunc(func(_ context.Context, e auth.OperationEvent) { events = append(events, e) })))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.echo.Call(context.Background(), echoIn{Text: "x"}); err != nil {
		t.Fatal(err)
	}
	ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP})
	if _, err := p.whoami.Call(ctx, struct{}{}); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("whoami signed out: %v", err)
	}
	if _, err := p.fail.Call(context.Background(), struct{}{}); !errors.Is(err, errOpFailed) {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}
	ok, refused, failed := events[0], events[1], events[2]
	if ok.Op.ID != opEcho || ok.Plugin != "testp" || ok.Err != nil || ok.Transport != auth.TransportGo || ok.Duration != 25*time.Millisecond {
		t.Fatalf("success event: %+v", ok)
	}
	if refused.Op.ID != opWhoami || !errors.Is(refused.Err, auth.ErrSignedOut) || refused.Transport != auth.TransportHTTP || refused.Duration != 0 {
		t.Fatalf("a call refused by the pipeline is still observed: %+v", refused)
	}
	if failed.Op.ID != opFail || !errors.Is(failed.Err, errOpFailed) {
		t.Fatalf("failure event: %+v", failed)
	}
}

// recordingDeliverer is a kind plugin whose deliveries are kept, with the
// locale each message carried.
type recordingDeliverer struct {
	*kindPlugin
	// mu guards locales: deliveries run concurrently in the background.
	mu      sync.Mutex
	locales []string
}

func (d *recordingDeliverer) Deliver(_ context.Context, _ auth.Identity, m auth.Message) error {
	d.mu.Lock()
	d.locales = append(d.locales, m.Locale)
	d.mu.Unlock()
	return nil
}

func TestWithDefaultLocale_FillsAMessageWithNoLanguage(t *testing.T) {
	d := &recordingDeliverer{kindPlugin: &kindPlugin{name: "m", kind: mailKind(auth.Recover())}}
	a, err := newAuth(auth.WithPlugins(basic("s"), d), auth.WithDefaultLocale("de"))
	if err != nil {
		t.Fatal(err)
	}
	to := auth.Identity{Kind: "mail", Value: "ada@example.com"}
	if err := a.Deliver(context.Background(), to, auth.Message{Purpose: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Deliver(a.WithRequest(context.Background(), auth.Request{Client: auth.Client{Locale: "fr-CH"}}), to, auth.Message{Purpose: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Deliver(context.Background(), to, auth.Message{Purpose: "x", Locale: "it"}); err != nil {
		t.Fatal(err)
	}
	a.WaitDeliveries()
	slices.Sort(d.locales) // deliveries run concurrently
	if want := []string{"de", "fr-CH", "it"}; !slices.Equal(d.locales, want) {
		t.Fatalf("locales %v, want %v: the default fills only a message with none", d.locales, want)
	}
	for _, bad := range []string{"de CH", "de_CH", "a-very-long-tag-that-no-language-registry-has-ever-issued"} {
		if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithDefaultLocale(bad)); !errors.Is(err, auth.ErrBadOperation) {
			t.Errorf("%q: got %v, want ErrBadOperation", bad, err)
		}
	}
	// Without the option a message with no language has none, as before.
	d2 := &recordingDeliverer{kindPlugin: &kindPlugin{name: "m", kind: mailKind(auth.Recover())}}
	a, err = newAuth(auth.WithPlugins(basic("s"), d2))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Deliver(context.Background(), to, auth.Message{Purpose: "x"}); err != nil {
		t.Fatal(err)
	}
	a.WaitDeliveries()
	if len(d2.locales) != 1 || d2.locales[0] != "" {
		t.Fatalf("without a default the locale stays empty: %v", d2.locales)
	}
}

func TestWithBackground_RunsDeliveryThroughTheApp(t *testing.T) {
	d := &recordingDeliverer{kindPlugin: &kindPlugin{name: "m", kind: mailKind(auth.Recover())}}
	type ctxKey struct{}
	var ran int
	var sawValue bool
	runner := func(ctx context.Context, task func(context.Context)) {
		ran++
		sawValue = ctx.Value(ctxKey{}) == "kept"
		if ctx.Err() != nil {
			t.Error("the task context must not carry the request's cancellation")
		}
		task(ctx) // inline: the app decides where the task runs
	}
	a, err := newAuth(auth.WithPlugins(basic("s"), d), auth.WithBackground(runner))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), ctxKey{}, "kept"))
	cancel() // the client hung up; the task still runs
	if err := a.Deliver(ctx, auth.Identity{Kind: "mail", Value: "ada@example.com"}, auth.Message{Purpose: "x"}); err != nil {
		t.Fatal(err)
	}
	a.WaitDeliveries()
	if ran != 1 || !sawValue || len(d.locales) != 1 {
		t.Fatalf("runner ran %d times, value kept %v, delivered %d", ran, sawValue, len(d.locales))
	}
}

func TestNew_StatelessVersionNeedsStatelessSessions(t *testing.T) {
	if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithStatelessVersion(2)); !errors.Is(err, auth.ErrBadOperation) {
		t.Fatalf("version without stateless mode: got %v, want ErrBadOperation", err)
	}
	key := make([]byte, auth.SealKeySize)
	if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithStatelessSessions(key), auth.WithStatelessVersion(-1)); !errors.Is(err, auth.ErrBadOperation) {
		t.Fatalf("a negative version: got %v, want ErrBadOperation", err)
	}
	if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithStatelessSessions(key), auth.WithStatelessVersion(3)); err != nil {
		t.Fatal(err)
	}
}

func TestNoSessionRefresh_IsBeyondEveryLifetime(t *testing.T) {
	// A session seen NoSessionRefresh after its last use has hit its hard
	// stop first, so a RefreshAfter of that value never slides anything.
	lt := auth.DefaultSessionConfig
	lt.RefreshAfter = auth.NoSessionRefresh
	s := auth.Session{CreatedAt: time.Unix(0, 0), LastSeenAt: time.Unix(0, 0)}
	if got := s.Lifetime(lt).RefreshAfter; got != auth.NoSessionRefresh || got < auth.MaxSessionLifetime {
		t.Fatalf("RefreshAfter %v", got)
	}
}

func TestNew_PendingSessionTTLAndCodeLength(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(basic("s")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg := a.Config(); cfg.PendingSessionTTL != auth.PendingSessionTTL || cfg.CodeLength != auth.DefaultCodeLength {
		t.Fatalf("defaults: pending %v, code length %d", cfg.PendingSessionTTL, cfg.CodeLength)
	}
	a, err = newAuth(auth.WithPlugins(basic("s")), auth.WithPendingSessionTTL(3*time.Minute), auth.WithCodeLength(8))
	if err != nil {
		t.Fatal(err)
	}
	if cfg := a.Config(); cfg.PendingSessionTTL != 3*time.Minute || cfg.CodeLength != 8 {
		t.Fatalf("set: pending %v, code length %d", cfg.PendingSessionTTL, cfg.CodeLength)
	}
	for name, opt := range map[string]auth.Option{
		"zero pending TTL":     auth.WithPendingSessionTTL(0),
		"negative pending TTL": auth.WithPendingSessionTTL(-time.Second),
		"code too short":       auth.WithCodeLength(auth.MinCodeLength - 1),
		"code too long":        auth.WithCodeLength(auth.MaxCodeLength + 1),
	} {
		if _, err := newAuth(auth.WithPlugins(basic("s")), opt); !errors.Is(err, auth.ErrBadOperation) {
			t.Errorf("%s: got %v, want ErrBadOperation", name, err)
		}
	}
}

// verifyingKind is a kind plugin that can re-send a verification.
type verifyingKind struct {
	*kindPlugin
	sent []auth.Identity
}

func (v *verifyingKind) SendVerification(_ context.Context, to auth.Identity) error {
	v.sent = append(v.sent, to)
	return nil
}

func TestSendVerification_DispatchesToTheKindsPlugin(t *testing.T) {
	v := &verifyingKind{kindPlugin: &kindPlugin{name: "m", kind: mailKind(auth.Recover())}}
	plain := &kindPlugin{name: "h", kind: handleKind()}
	a, err := newAuth(auth.WithPlugins(basic("s"), v, plain))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SendVerification(context.Background(), auth.Identity{Kind: "mail", Value: "ada@example.com"}); err != nil {
		t.Fatal(err)
	}
	if len(v.sent) != 1 || v.sent[0].Value != "ada@example.com" {
		t.Fatalf("sent %v", v.sent)
	}
	if err := a.SendVerification(context.Background(), auth.Identity{Kind: "handle", Value: "ada"}); !errors.Is(err, auth.ErrNoVerificationSender) {
		t.Fatalf("a kind whose plugin cannot: %v, want ErrNoVerificationSender", err)
	}
	if err := a.SendVerification(context.Background(), auth.Identity{Kind: "nope"}); !errors.Is(err, auth.ErrNoVerificationSender) {
		t.Fatalf("an unknown kind: %v, want ErrNoVerificationSender", err)
	}
}
