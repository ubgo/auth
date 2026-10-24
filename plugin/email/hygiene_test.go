package email

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBlockDomains(t *testing.T) {
	check := BlockDomains(" Mailinator.COM. ", "", "tempmail.io")
	cases := map[string]bool{
		"a@mailinator.com":      true,
		"a@MAILINATOR.com":      true,
		"a@x.mailinator.com":    true,
		"a@tempmail.io":         true,
		"a@notmailinator.com":   false,
		"a@mailinator.com.evil": false,
		"a@example.com":         false,
		"a@localhost":           false,
	}
	for addr, blocked := range cases {
		err := check(context.Background(), addr)
		if blocked != errors.Is(err, ErrAddressRejected) || (!blocked && err != nil) {
			t.Errorf("%s: err %v, want blocked=%v", addr, err, blocked)
		}
	}
}

// TestAllowDomains: an entry allows its exact domain only; "*." allows
// every subdomain and not the domain itself; case and a trailing dot never
// matter; a look-alike suffix or a domain that merely ends the same is
// refused with the one enumeration-safe error.
func TestAllowDomains(t *testing.T) {
	check := mustAllow(t, " Acme.COM. ", "*.uni.edu")
	cases := map[string]bool{
		"pat@acme.com":         true,
		"pat@ACME.com":         true,
		"pat@acme.com.":        true,
		"pat@eu.acme.com":      false, // exact entry: no subdomain
		"pat@notacme.com":      false,
		"pat@acme.com.evil":    false,
		"pat@cs.uni.edu":       true,
		"pat@a.b.uni.edu":      true,
		"pat@CS.UNI.EDU":       true,
		"pat@uni.edu":          false, // wildcard entry: subdomains only
		"pat@notuni.edu":       false,
		"pat@uni.edu.evil.com": false,
		"pat@edu":              false,
	}
	for addr, allowed := range cases {
		err := check(context.Background(), addr)
		if allowed != (err == nil) || (!allowed && !errors.Is(err, ErrAddressRejected)) {
			t.Errorf("%s: err %v, want allowed=%v", addr, err, allowed)
		}
	}
	// Both entries allow the domain and every subdomain.
	both := mustAllow(t, "acme.com", "*.acme.com")
	for _, addr := range []string{"pat@acme.com", "pat@eu.acme.com"} {
		if err := both(context.Background(), addr); err != nil {
			t.Errorf("%s with both entries: %v", addr, err)
		}
	}
}

// mustAllow is AllowDomains' check for a list that must be valid.
func mustAllow(t *testing.T, domains ...string) AddressCheck {
	t.Helper()
	check, err := allowList(domains)
	if err != nil {
		t.Fatal(err)
	}
	return check
}

// TestAllowDomains_RefusesAListThatAllowsNobody: an empty list, or an entry
// naming no domain, is ErrBadDomainList from the plugin's OptionErr (which
// auth.New checks first), naming the option and the entry, never a panic
// and never a check that refuses everyone; nothing is added to the checks.
func TestAllowDomains_RefusesAListThatAllowsNobody(t *testing.T) {
	for name, list := range map[string][]string{
		"empty": nil, "blank": {""}, "bare wildcard": {"*."}, "star": {"*"},
		"address": {"pat@acme.com"}, "inner star": {"*.*.acme.com"}, "mid star": {"a*.com"},
		"one bad among good": {"acme.com", " "},
	} {
		p := New(AllowDomains(list...))
		err := p.OptionErr()
		if !errors.Is(err, ErrBadDomainList) || !strings.Contains(err.Error(), "email.AllowDomains") {
			t.Errorf("%s: OptionErr = %v, want ErrBadDomainList naming the option", name, err)
		}
		if len(p.checks) != 0 {
			t.Errorf("%s: a bad list added %d checks", name, len(p.checks))
		}
	}
	if err := New(AllowDomains("acme.com")).OptionErr(); err != nil {
		t.Fatalf("a good list: %v", err)
	}
}

// TestAllowDomains_JoinsTheChecksInOptionOrder: the option's check runs
// where it stands among CheckAddresses' checks, so given first it refuses an
// outside address before a later check is asked.
func TestAllowDomains_JoinsTheChecksInOptionOrder(t *testing.T) {
	asked := 0
	later := func(context.Context, string) error { asked++; return nil }
	p := New(AllowDomains("acme.com"), CheckAddresses(later))
	if err := p.checkAddress(context.Background(), "pat@other.com"); !errors.Is(err, ErrAddressRejected) || asked != 0 {
		t.Fatalf("outside address: %v, later check asked %d times", err, asked)
	}
	if err := p.checkAddress(context.Background(), "pat@acme.com"); err != nil || asked != 1 {
		t.Fatalf("listed address: %v, later check asked %d times", err, asked)
	}
	// Given after CheckAddresses, the earlier check is asked first.
	asked = 0
	q := New(CheckAddresses(later), AllowDomains("acme.com"))
	if err := q.checkAddress(context.Background(), "pat@other.com"); !errors.Is(err, ErrAddressRejected) || asked != 1 {
		t.Fatalf("allow-list given last: %v, earlier check asked %d times", err, asked)
	}
}

func TestParseDomainList(t *testing.T) {
	got, err := ParseDomainList(strings.NewReader("# disposable\nmailinator.com\n\n  tempmail.io  \n#x\n"))
	if err != nil || strings.Join(got, ",") != "mailinator.com,tempmail.io" {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := ParseDomainList(errReader{}); err == nil {
		t.Fatal("a read error was swallowed")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("disk gone") }

// fakeDNS answers from maps; a missing name is a not-found answer, and fail
// makes every lookup a temporary failure.
type fakeDNS struct {
	mx    map[string][]*net.MX
	hosts map[string][]string
	fail  bool
	// sawDeadline records that the lookup ran under RequireMX's timeout.
	sawDeadline bool
}

func (f *fakeDNS) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	_, f.sawDeadline = ctx.Deadline()
	if f.fail {
		return nil, &net.DNSError{Err: "timeout", Name: name, IsTimeout: true}
	}
	if mx, ok := f.mx[name]; ok {
		return mx, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeDNS) LookupHost(_ context.Context, host string) ([]string, error) {
	if h, ok := f.hosts[host]; ok {
		return h, nil
	}
	if host == "broken.example" {
		return nil, &net.DNSError{Err: "server misbehaving", Name: host, IsTemporary: true}
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestRequireMX(t *testing.T) {
	dns := &fakeDNS{
		mx: map[string][]*net.MX{
			"mail.example":   {{Host: "mx1.mail.example.", Pref: 10}},
			"nullmx.example": {{Host: ".", Pref: 0}},
		},
		hosts: map[string][]string{"aonly.example": {"192.0.2.1"}},
	}
	check := RequireMX(dns, 0)
	cases := map[string]error{
		"a@mail.example":    nil,
		"a@MAIL.example":    nil,
		"a@aonly.example":   nil,                // implicit MX (RFC 5321 §5.1)
		"a@nullmx.example":  ErrAddressRejected, // RFC 7505
		"a@nowhere.example": ErrAddressRejected,
		"a@broken.example":  nil, // the host lookup failed: let it through
	}
	for addr, want := range cases {
		if err := check(context.Background(), addr); !errors.Is(err, want) || (want == nil && err != nil) {
			t.Errorf("%s: %v, want %v", addr, err, want)
		}
	}
	if !dns.sawDeadline {
		t.Error("lookups ran without a timeout")
	}
	dns.fail = true
	if err := check(context.Background(), "a@nowhere.example"); err != nil {
		t.Errorf("an outage refused the address: %v", err)
	}
}

func TestRequireMX_Defaults(t *testing.T) {
	// nil and 0 take net.DefaultResolver and DefaultMXTimeout; a cancelled
	// context makes the real resolver fail, which lets the address through.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RequireMX(nil, 0)(ctx, "a@example.com"); err != nil {
		t.Fatalf("a failed lookup refused the address: %v", err)
	}
	if DefaultMXTimeout != 3*time.Second {
		t.Fatal("DefaultMXTimeout changed; update the README")
	}
}

func TestCheckAddresses_FirstRefusalWins(t *testing.T) {
	var ran []string
	mark := func(name string, err error) AddressCheck {
		return func(context.Context, string) error { ran = append(ran, name); return err }
	}
	p := New(CheckAddresses(mark("a", nil)), CheckAddresses(mark("b", ErrAddressRejected), mark("c", nil)))
	if err := p.checkAddress(context.Background(), "x@y.z"); !errors.Is(err, ErrAddressRejected) || strings.Join(ran, "") != "ab" {
		t.Fatalf("err %v, ran %v", err, ran)
	}
	if err := New().checkAddress(context.Background(), "x@y.z"); err != nil {
		t.Fatal(err)
	}
}
