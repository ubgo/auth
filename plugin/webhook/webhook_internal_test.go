package webhook

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/webhook/signature"
)

// TestPublicAddr_Matrix: every non-public range is refused, in its IPv4,
// IPv4-mapped IPv6 and native IPv6 spellings, and ordinary public addresses
// pass.
func TestPublicAddr_Matrix(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "1.1.1.1": true, "2606:4700:4700::1111": true, "93.184.216.34": true,
		"127.0.0.1": false, "127.255.255.254": false, "::1": false, "::ffff:127.0.0.1": false,
		"10.0.0.1": false, "172.16.0.1": false, "192.168.1.1": false, "::ffff:10.0.0.1": false,
		"169.254.169.254": false, "fe80::1": false, "fc00::1": false, "fd12::1": false,
		"0.0.0.0": false, "::": false, "0.1.2.3": false, "100.64.0.1": false, "100.127.255.255": false,
		"192.0.0.8": false, "192.0.2.1": false, "198.18.0.1": false, "198.51.100.1": false, "203.0.113.1": false,
		"240.0.0.1": false, "255.255.255.255": false, "224.0.0.1": false, "ff02::1": false,
		"64:ff9b::a00:1": false, "2001:db8::1": false,
	} {
		if got := publicAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("publicAddr(%s) = %v, want %v", addr, got, want)
		}
	}
}

// TestCheckURL_Matrix: registration refuses what is not an https URL to a
// public host, and AllowPrivateNetworks lets through exactly the local
// destinations and plain http, never credentials or a bad shape.
func TestCheckURL_Matrix(t *testing.T) {
	strict, local := New(), New(AllowPrivateNetworks())
	for raw, c := range map[string]struct{ strict, local error }{
		"https://hooks.example.com/in?x=1":  {nil, nil},
		"https://hooks.example.com:8443/in": {nil, nil},
		"http://hooks.example.com/in":       {ErrBadURL, nil},
		"http://127.0.0.1:9000/in":          {ErrBadURL, nil},
		"https://127.0.0.1/in":              {ErrDestinationRefused, nil},
		"https://[::1]/in":                  {ErrDestinationRefused, nil},
		"https://[::ffff:10.0.0.1]/in":      {ErrDestinationRefused, nil},
		"https://169.254.169.254/":          {ErrDestinationRefused, nil},
		"https://localhost/in":              {ErrDestinationRefused, nil},
		"https://LocalHost./in":             {ErrDestinationRefused, nil},
		"https://api.localhost/in":          {ErrDestinationRefused, nil},
		"https://user:pass@example.com/in":  {ErrBadURL, ErrBadURL},
		"https://example.com/in#frag":       {ErrBadURL, ErrBadURL},
		"ftp://example.com/in":              {ErrBadURL, ErrBadURL},
		"/relative":                         {ErrBadURL, ErrBadURL},
		"https:///nohost":                   {ErrBadURL, ErrBadURL},
		"":                                  {ErrBadURL, ErrBadURL},
		"https://example.com/" + strings.Repeat("a", MaxURLLength): {ErrBadURL, ErrBadURL},
		"https://exa mple.com/": {ErrBadURL, ErrBadURL},
	} {
		if _, err := strict.checkURL(raw); !errors.Is(err, c.strict) {
			t.Errorf("strict %q: %v, want %v", raw, err, c.strict)
		}
		if _, err := local.checkURL(raw); !errors.Is(err, c.local) {
			t.Errorf("local %q: %v, want %v", raw, err, c.local)
		}
	}
}

// TestPost_DialGuard: the guard runs on the address actually dialled, so a
// send to a loopback receiver is refused before a byte reaches it even though
// post itself never looks at the URL; with AllowPrivateNetworks the same send
// arrives. A name ("localhost") is resolved first and refused the same way,
// which is what stops DNS rebinding.
func TestPost_DialGuard(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer srv.Close()
	secret := signature.NewSecret()
	ctx := context.Background()
	byName := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	for _, u := range []string{srv.URL, byName} {
		code, cause := New().post(ctx, u, "msg_1", []byte(`{}`), []string{secret})
		if code != 0 || !strings.Contains(cause, "non-public") {
			t.Fatalf("guarded send to %s = %d %q", u, code, cause)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("receiver was reached %d times through the guard", n)
	}
	if code, cause := New(AllowPrivateNetworks()).post(ctx, srv.URL, "msg_1", []byte(`{}`), []string{secret}); code != http.StatusOK || cause != "" || hits.Load() != 1 {
		t.Fatalf("allowed send = %d %q, hits %d", code, cause, hits.Load())
	}
}

// TestPost_Outcomes: 2xx is success, a redirect is never followed and counts
// as a failure, any other status is a failure naming it, and the cause never
// carries the URL (whose query may hold a token) or the secret.
func TestPost_Outcomes(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Store(true) }))
	defer target.Close()
	var status atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code := int(status.Load()); code == http.StatusFound {
			http.Redirect(w, r, target.URL, code)
		} else {
			w.WriteHeader(code)
		}
	}))
	defer srv.Close()
	p := New(AllowPrivateNetworks())
	secret := signature.NewSecret()
	u := srv.URL + "/in?token=topsecret"
	for _, c := range []struct {
		status int
		ok     bool
	}{{http.StatusOK, true}, {http.StatusNoContent, true}, {http.StatusFound, false}, {http.StatusBadRequest, false}, {http.StatusInternalServerError, false}, {http.StatusGone, false}} {
		status.Store(int64(c.status))
		code, cause := p.post(context.Background(), u, "msg_1", []byte(`{}`), []string{secret})
		if code != c.status || (cause == "") != c.ok {
			t.Errorf("status %d: got %d %q", c.status, code, cause)
		}
		if strings.Contains(cause, "topsecret") || strings.Contains(cause, strings.TrimPrefix(secret, signature.SecretPrefix)) {
			t.Errorf("status %d: cause leaks %q", c.status, cause)
		}
	}
	if redirected.Load() {
		t.Fatal("a redirect was followed")
	}
	// A network failure is a cause too, without the URL.
	srv.Close()
	if code, cause := p.post(context.Background(), u, "msg_1", []byte(`{}`), []string{secret}); code != 0 || cause == "" || strings.Contains(cause, "topsecret") {
		t.Fatalf("closed receiver = %d %q", code, cause)
	}
	if _, cause := p.post(context.Background(), u, "msg_1", []byte(`{}`), []string{"bad"}); cause != "signing secret is not valid" {
		t.Fatalf("bad secret cause = %q", cause)
	}
}

// TestMatches_Matrix: filters by exact type, by prefix and "*", and an empty
// list means every event; a prefix filter never matches a sibling that only
// shares letters.
func TestMatches_Matrix(t *testing.T) {
	for _, c := range []struct {
		filters []string
		typ     string
		want    bool
	}{
		{nil, EventUserCreated, true},
		{[]string{}, "anything.at.all", true},
		{[]string{"*"}, EventSessionRevoked, true},
		{[]string{EventUserCreated}, EventUserCreated, true},
		{[]string{EventUserCreated}, EventUserUpdated, false},
		{[]string{"user.*"}, EventUserDeleted, true},
		{[]string{"user.*"}, "users.created", false},
		{[]string{"user.*"}, "user", false},
		{[]string{"security.*"}, SecurityEventPrefix + "rate.limit", true},
		{[]string{"security.geo.*"}, SecurityEventPrefix + "rate.limit", false},
		{[]string{"session.created", "user.*"}, EventUserUpdated, true},
	} {
		if got := matches(c.filters, c.typ); got != c.want {
			t.Errorf("matches(%v, %q) = %v, want %v", c.filters, c.typ, got, c.want)
		}
	}
}

// TestCheckFilters: valid filters pass de-duplicated; a malformed one, an
// upper-case one or too many are refused.
func TestCheckFilters(t *testing.T) {
	got, err := checkFilters([]string{"user.*", "user.*", "*", "session.created"})
	if err != nil || len(got) != 3 {
		t.Fatalf("checkFilters = %v, %v", got, err)
	}
	for _, bad := range [][]string{{"User.created"}, {"user..created"}, {"user.*.x"}, {".user"}, {"user created"}, {""}, {"**"}, {strings.Repeat("a", maxEventTypeLength+1)}, make([]string, MaxEventFilters+1)} {
		if _, err := checkFilters(bad); !errors.Is(err, ErrBadEventType) {
			t.Errorf("checkFilters(%q) = %v", bad, err)
		}
	}
	for _, k := range auth.SecurityKindValues {
		if !validType(SecurityEventPrefix + string(k)) {
			t.Errorf("security kind %q does not make a valid type", k)
		}
	}
	for _, typ := range EventTypeValues {
		if !validType(typ) {
			t.Errorf("%q is not a valid type", typ)
		}
	}
}

// TestBackoff_Doubles: each failure doubles the wait from Base, capped at
// Max, with at most a tenth of jitter on top and never less than the base
// value.
func TestBackoff_Doubles(t *testing.T) {
	p := New(Retry(RetryPolicy{Base: time.Second, Max: 10 * time.Second}))
	for attempts, want := range map[int]time.Duration{1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 4: 8 * time.Second, 5: 10 * time.Second, 30: 10 * time.Second} {
		for range 20 {
			if got := p.backoff(attempts); got < want || got > want+want/jitterFraction {
				t.Fatalf("backoff(%d) = %v, want %v plus up to a tenth", attempts, got, want)
			}
		}
	}
}

// TestOptions_Refusals: an option given an impossible value is refused by
// name through OptionErr, which auth.New checks first.
func TestOptions_Refusals(t *testing.T) {
	for name, opt := range map[string]Option{
		"webhook.Timeout(0s)":                   Timeout(0),
		"webhook.Timeout(-1s)":                  Timeout(-time.Second),
		"webhook.Timeout(1m0s)":                 Timeout(time.Minute),
		"webhook.Retry: MaxAttempts -1":         Retry(RetryPolicy{MaxAttempts: -1}),
		"webhook.Retry: MaxAttempts 0, Base -1": Retry(RetryPolicy{Base: -time.Second}),
	} {
		err := New(opt).OptionErr()
		if !errors.Is(err, auth.ErrBadOperation) || !strings.Contains(err.Error(), strings.SplitN(name, ":", 2)[0]) {
			t.Errorf("%s: %v", name, err)
		}
	}
	p := New(Timeout(time.Second), Retry(RetryPolicy{MaxAttempts: 2}), Retention(time.Hour), Retention(-1))
	if p.OptionErr() != nil || p.timeout != time.Second || p.retry.MaxAttempts != 2 || p.retry.Base != DefaultRetryBase || p.retention != time.Hour {
		t.Fatalf("options = %+v", p)
	}
}

// TestNewMessageID: ids are unique, prefixed and never contain a dot.
func TestNewMessageID(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		id := newMessageID()
		if !strings.HasPrefix(id, messageIDPrefix) || strings.Contains(id, ".") || seen[id] {
			t.Fatalf("id %q", id)
		}
		seen[id] = true
	}
}

// TestGuardDial_Direct: the dial hook refuses an address it cannot read and
// lets a public one through; a send to a URL that cannot become a request is
// a failure with a cause, not a panic.
func TestGuardDial_Direct(t *testing.T) {
	if err := guardDial("tcp", "no-port", nil); !errors.Is(err, errPrivateAddress) {
		t.Fatalf("unreadable address = %v", err)
	}
	if err := guardDial("tcp", "name.example:443", nil); !errors.Is(err, errPrivateAddress) {
		t.Fatalf("unresolved name = %v", err)
	}
	if err := guardDial("tcp", "8.8.8.8:443", nil); err != nil {
		t.Fatalf("public address = %v", err)
	}
	if code, cause := New().post(context.Background(), "http://bad host/", "msg_1", []byte(`{}`), []string{signature.NewSecret()}); code != 0 || cause != "request could not be built" {
		t.Fatalf("bad URL = %d %q", code, cause)
	}
}
