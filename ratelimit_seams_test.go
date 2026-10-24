package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// tenantHeader is the header the ByFunc tests count by: a stand-in for any
// key an app derives from the call (a tenant, an API key, a device).
const tenantHeader = "X-Tenant"

// tenantKey is a RateKeyFunc counting by tenantHeader.
func tenantKey(_ context.Context, c *auth.Call) (string, error) { return c.Header(tenantHeader), nil }

// seamOp is a public query the rate-seam tests limit.
func seamOp() *auth.Op[struct{}, struct{}] {
	return auth.Define(auth.OpInfo{ID: "r.op", Kind: auth.Query, Require: auth.Public, Path: "/op"},
		func(context.Context, *auth.Call, struct{}) (struct{}, error) { return struct{}{}, nil })
}

// callAs calls op as a browser request carrying tenant in tenantHeader.
func callAs(a *auth.Auth, op *auth.Op[struct{}, struct{}], tenant string) error {
	h := func(name string) string {
		if name == tenantHeader {
			return tenant
		}
		return ""
	}
	_, err := op.Call(a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{IP: "203.0.113.9"}, Header: h}), struct{}{})
	return err
}

// TestRateByFunc_CountsPerKeyValue: a ByFunc rule counts each value its
// KeyFunc returns on its own counter, refuses past the limit, and skips a
// call whose key is "", whatever the address.
func TestRateByFunc_CountsPerKeyValue(t *testing.T) {
	op := seamOp()
	a, err := newAuth(auth.WithPlugins(&stubPlugin{name: "r", ops: []auth.Operation{op}},
		rulePlugin{rule: auth.RateRule{Match: "r.op", Key: auth.ByFunc, KeyFunc: tenantKey, Limit: 2, Window: time.Minute}}))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := callAs(a, op, "acme"); err != nil {
			t.Fatal(err)
		}
	}
	if err := callAs(a, op, "acme"); !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("third acme call = %v, want ErrRateLimited", err)
	}
	if err := callAs(a, op, "globex"); err != nil {
		t.Fatalf("another tenant shares acme's counter: %v", err)
	}
	for range 5 {
		if err := callAs(a, op, ""); err != nil {
			t.Fatalf("a call with no key was counted: %v", err)
		}
	}
}

// TestRateByFunc_KeyErrorFailsClosed: a key function that cannot tell who is
// calling fails the call rather than letting it through uncounted.
func TestRateByFunc_KeyErrorFailsClosed(t *testing.T) {
	op := seamOp()
	boom := errors.New("tenant lookup down")
	fn := func(context.Context, *auth.Call) (string, error) { return "", boom }
	a, err := newAuth(auth.WithPlugins(&stubPlugin{name: "r", ops: []auth.Operation{op}},
		rulePlugin{rule: auth.RateRule{Match: "r.op", Key: auth.ByFunc, KeyFunc: fn, Limit: 5, Window: time.Minute}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := callAs(a, op, "acme"); !errors.Is(err, boom) {
		t.Fatalf("call = %v, want the key function's error", err)
	}
}

// TestRateByFunc_KeyIsHashed: the store sees a ByFunc value only as a hash,
// as it does an IP or an identifier.
func TestRateByFunc_KeyIsHashed(t *testing.T) {
	op := seamOp()
	rec := &keyRecorder{}
	a, err := newAuth(auth.WithPlugins(&stubPlugin{name: "r", ops: []auth.Operation{op}},
		rulePlugin{rule: auth.RateRule{Match: "r.op", Key: auth.ByFunc, KeyFunc: tenantKey, Limit: 5, Window: time.Minute}}),
		auth.WithRateStore(rec))
	if err != nil {
		t.Fatal(err)
	}
	if err := callAs(a, op, "acme-tenant-secret"); err != nil {
		t.Fatal(err)
	}
	if len(rec.keys) != 1 || strings.Contains(rec.keys[0], "acme") || !strings.HasPrefix(rec.keys[0], "r.op|func|") {
		t.Fatalf("keys = %q, want one hashed r.op|func key", rec.keys)
	}
}

// TestRateByFunc_RefusesIncoherentRules: a ByFunc rule needs a KeyFunc, and
// a KeyFunc on any other key would never run, so New refuses both.
func TestRateByFunc_RefusesIncoherentRules(t *testing.T) {
	for name, r := range map[string]auth.RateRule{
		"func without KeyFunc": {Match: "r.op", Key: auth.ByFunc, Limit: 1, Window: time.Minute},
		"KeyFunc on ByIP":      {Match: "r.op", Key: auth.ByIP, KeyFunc: tenantKey, Limit: 1, Window: time.Minute},
	} {
		_, err := newAuth(auth.WithPlugins(&stubPlugin{name: "r", ops: []auth.Operation{seamOp()}}, rulePlugin{rule: r}))
		if !errors.Is(err, auth.ErrBadOperation) {
			t.Errorf("%s: New = %v, want ErrBadOperation", name, err)
		}
	}
}

// deciderStore is a RateDecider that answers from fields and records the
// rule it was asked about, and counts any Hit so a test can prove Hit is not
// used once Allow exists.
type deciderStore struct {
	allow bool
	retry time.Duration
	err   error
	rules []auth.RateRule
	keys  []string
	hits  int
}

func (s *deciderStore) Hit(context.Context, string, time.Duration) (int, error) {
	s.hits++
	return 1, nil
}

func (s *deciderStore) Allow(_ context.Context, key string, r auth.RateRule) (bool, time.Duration, error) {
	s.keys, s.rules = append(s.keys, key), append(s.rules, r)
	return s.allow, s.retry, s.err
}

// TestRateDecider_DecidesInsteadOfCounting: a store implementing RateDecider
// gets the hashed key and the rule, its verdict is final, its retry-after is
// what the caller is told (the rule's window when it gives none), Hit is
// never called, and its error fails the call.
func TestRateDecider_DecidesInsteadOfCounting(t *testing.T) {
	rule := auth.RateRule{Match: "r.op", Key: auth.ByIP, Limit: 3, Window: time.Minute}
	build := func(s *deciderStore) (*auth.Auth, *auth.Op[struct{}, struct{}]) {
		t.Helper()
		op := seamOp()
		a, err := newAuth(auth.WithPlugins(&stubPlugin{name: "r", ops: []auth.Operation{op}}, rulePlugin{rule: rule}), auth.WithRateStore(s))
		if err != nil {
			t.Fatal(err)
		}
		return a, op
	}

	ok := &deciderStore{allow: true}
	a, op := build(ok)
	for range 10 {
		if err := callAs(a, op, ""); err != nil {
			t.Fatalf("allowed call = %v", err)
		}
	}
	if ok.hits != 0 || len(ok.rules) != 10 || ok.rules[0].Limit != 3 || strings.Contains(ok.keys[0], "203.0.113") {
		t.Fatalf("hits=%d rules=%d keys=%q: Allow must see every call, the rule and a hashed key, and Hit none", ok.hits, len(ok.rules), ok.keys)
	}

	deny := &deciderStore{retry: 7 * time.Second}
	a, op = build(deny)
	err := callAs(a, op, "")
	if d, _ := auth.RetryAfter(err); !errors.Is(err, auth.ErrRateLimited) || d != 7*time.Second {
		t.Fatalf("denied call = %v after %v, want ErrRateLimited after 7s", err, d)
	}

	a, op = build(&deciderStore{})
	if d, _ := auth.RetryAfter(callAs(a, op, "")); d != time.Minute {
		t.Fatalf("retry with none given = %v, want the window", d)
	}

	boom := errors.New("limiter down")
	a, op = build(&deciderStore{allow: true, err: boom})
	if err := callAs(a, op, ""); !errors.Is(err, boom) || errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("decider error = %v, want the call failed with it", err)
	}
}
