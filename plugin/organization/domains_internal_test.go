package organization

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

func TestNormalizeDomain(t *testing.T) {
	ok := map[string]string{
		"acme.com": "acme.com", " ACME.com. ": "acme.com", "@acme.com": "acme.com", "mail.acme.co.uk": "mail.acme.co.uk",
		"xn--bcher-kva.de": "xn--bcher-kva.de", "a-b.io": "a-b.io", "1password.com": "1password.com",
	}
	for raw, want := range ok {
		if got, err := NormalizeDomain(raw); err != nil || got != want {
			t.Errorf("%q = %q, %v; want %q", raw, got, err, want)
		}
	}
	long := strings.Repeat("a", maxLabelLength+1) + ".com"
	huge := strings.Repeat("abcdefghi.", 26) + "com"
	for _, raw := range []string{"", " ", "com", "acme", ".acme.com", "acme..com", "-acme.com", "acme-.com", "ac me.com", "acme.com/x", "user@acme.com", "10.0.0.1", "acme.123", "bücher.de", "acme_x.com", long, huge, "@", "."} {
		if got, err := NormalizeDomain(raw); !errors.Is(err, ErrBadDomain) {
			t.Errorf("%q accepted as %q", raw, got)
		}
	}
}

func TestEmailDomain(t *testing.T) {
	for addr, want := range map[string]string{"bob@acme.com": "acme.com", "a@b@acme.com": "acme.com", "bob@ACME.com.": "acme.com", "bob": "", "bob@": "", "bob@localhost": ""} {
		if got := EmailDomain(addr); got != want {
			t.Errorf("%q = %q, want %q", addr, got, want)
		}
	}
}

func TestIsDefaultPublicDomain(t *testing.T) {
	if !IsDefaultPublicDomain("gmail.com") || IsDefaultPublicDomain("acme.com") || IsDefaultPublicDomain("GMAIL.COM") {
		t.Fatal("the list compares normalized names exactly")
	}
	for _, d := range DefaultPublicDomains {
		if n, err := NormalizeDomain(d); err != nil || n != d {
			t.Errorf("%q is not in normal form", d)
		}
	}
}

// fakeResolver answers LookupTXT from a map, or with err.
type fakeResolver struct {
	records map[string][]string
	err     error
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.records[name], nil
}

func TestDNSVerifier(t *testing.T) {
	ch := DomainChallenge{Domain: "acme.com", RecordName: "_auth-verification.acme.com", RecordValue: "auth-domain-verification=tok"}
	cases := []struct {
		name string
		r    fakeResolver
		ok   bool
		err  bool
	}{
		{"exact", fakeResolver{records: map[string][]string{ch.RecordName: {"v=spf1", ch.RecordValue}}}, true, false},
		{"padded", fakeResolver{records: map[string][]string{ch.RecordName: {" " + ch.RecordValue + " "}}}, true, false},
		{"prefix only", fakeResolver{records: map[string][]string{ch.RecordName: {ch.RecordValue + "x", "auth-domain-verification=to"}}}, false, false},
		{"other name", fakeResolver{records: map[string][]string{"acme.com": {ch.RecordValue}}}, false, false},
		{"case differs", fakeResolver{records: map[string][]string{ch.RecordName: {strings.ToUpper(ch.RecordValue)}}}, false, false},
		{"nxdomain", fakeResolver{err: &net.DNSError{Err: "no such host", Name: ch.RecordName, IsNotFound: true}}, false, false},
		{"outage", fakeResolver{err: &net.DNSError{Err: "timeout", Name: ch.RecordName, IsTimeout: true}}, false, true},
		{"other error", fakeResolver{err: errors.New("boom")}, false, true},
	}
	for _, tc := range cases {
		ok, err := DNSVerifier{Resolver: tc.r}.VerifyDomain(context.Background(), ch)
		if ok != tc.ok || (err != nil) != tc.err {
			t.Errorf("%s: ok=%v err=%v", tc.name, ok, err)
		}
	}
}

func TestDomainVerifierFunc(t *testing.T) {
	f := DomainVerifierFunc(func(_ context.Context, ch DomainChallenge) (bool, error) { return ch.Domain == "acme.com", nil })
	if ok, _ := f.VerifyDomain(context.Background(), DomainChallenge{Domain: "acme.com"}); !ok {
		t.Fatal("func not called")
	}
}

func wireDomains(t *testing.T, cfg DomainsConfig) (*Plugin, error) {
	t.Helper()
	p := New(Domains(cfg))
	_, err := auth.New(auth.WithBaseURL("https://app.example.com"),
		auth.WithPlugins(signInStub{}, email.New(email.WithMailer(email.MailerFunc(func(context.Context, email.Mail) error { return nil }))), p))
	return p, err
}

func TestDomains_ValidateAndDefaults(t *testing.T) {
	for _, cfg := range []DomainsConfig{{MaxDomains: -1}, {RecordPrefix: "auth"}, {RecordPrefix: "_a.b"}, {RecordPrefix: "_A"}} {
		if _, err := wireDomains(t, cfg); err == nil {
			t.Errorf("%+v accepted", cfg)
		}
	}
	p, err := wireDomains(t, DomainsConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.verifier().(DNSVerifier); !ok || p.recordPrefix() != DefaultDomainRecordPrefix || p.maxDomains() != DefaultMaxDomains || !p.isPublic("gmail.com") {
		t.Fatal("defaults are wrong")
	}
	custom := DomainVerifierFunc(func(context.Context, DomainChallenge) (bool, error) { return false, nil })
	p, err = wireDomains(t, DomainsConfig{Verifier: custom, RecordPrefix: "_corp-verify", MaxDomains: 3, IsPublicDomain: func(d string) bool { return d == "corp-mail.io" }})
	if err != nil {
		t.Fatal(err)
	}
	if p.recordPrefix() != "_corp-verify" || p.maxDomains() != 3 || p.isPublic("gmail.com") || !p.isPublic("corp-mail.io") {
		t.Fatal("config not applied")
	}
	if d := p.finish(OrgDomain{Domain: "acme.com", token: "t"}); d.RecordName != "_corp-verify.acme.com" || d.RecordValue != "auth-domain-verification=t" || d.Verified {
		t.Fatalf("finish = %+v", d)
	}
}

// TestDomains_OffByDefault: without Domains there are no domain tables,
// routes, rate rule or data hooks, so nothing enrolls anyone.
func TestDomains_OffByDefault(t *testing.T) {
	p := wireNoDB(t)
	if slices.Contains(p.Tables(), TableDomain) || len(p.Operations()) != len(New(Domains(DomainsConfig{})).Operations())-len(p.domainOps()) {
		t.Fatal("domain tables or operations without Domains")
	}
	if h := p.DataHooks(); h.Identity.AfterCreate != nil || h.Identity.AfterUpdate != nil {
		t.Fatal("enrollment hooks without Domains")
	}
	for _, r := range p.RateLimits() {
		if r.Match == EndpointVerifyDomain {
			t.Fatal("verify rule without Domains")
		}
	}
	if _, err := p.MarkDomainVerified(context.Background(), "odom_1"); !errors.Is(err, ErrDomainNotFound) {
		t.Fatalf("MarkDomainVerified without Domains: %v", err)
	}
}

func TestDomains_OnDeclaresEverything(t *testing.T) {
	p, err := wireDomains(t, DomainsConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.Tables(), TableDomain) || !slices.Contains(p.Tables(), TableDomainRequest) {
		t.Fatal("tables not declared")
	}
	if !slices.ContainsFunc(p.UserTables(), func(u auth.UserTable) bool { return u.Table == TableDomainRequest }) {
		t.Fatal("a deleted user's requests would stay")
	}
	if !slices.ContainsFunc(p.RateLimits(), func(r auth.RateRule) bool { return r.Match == EndpointVerifyDomain && r.Limit == DefaultVerifyLimit }) {
		t.Fatal("verify-domain is not rate limited")
	}
	if h := p.DataHooks(); h.Identity.AfterCreate == nil || h.Identity.AfterUpdate == nil {
		t.Fatal("no enrollment hooks")
	}
	for _, e := range []string{auth.EnginePostgres, auth.EngineMySQL, auth.EngineSQLite} {
		ms, err := p.TypedMigrations(e, auth.TypesFor(e))
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(ms, func(m auth.Migration) bool { return m.Name == migrationDomains })
		if i < 0 || !strings.Contains(ms[i].Statements[0], ColDomainVerified+" ") || !strings.Contains(ms[i].Statements[0], "NULL UNIQUE") {
			t.Fatalf("%s: no unique verified_domain: %+v", e, ms)
		}
	}
}

// TestEnroll_IgnoresWhatIsNotAVerifiedEmail: the hook returns before any
// query (there is no database here, so a query would fail) for an
// unverified email, another kind, or an email with no domain, and the
// update hook for an identity verified before.
func TestEnroll_IgnoresWhatIsNotAVerifiedEmail(t *testing.T) {
	p, err := wireDomains(t, DomainsConfig{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := p.core.Now()
	h := p.DataHooks().Identity
	for _, idn := range []auth.Identity{
		{Kind: email.KindEmail, Value: "bob@acme.com"},
		{Kind: "phone", Value: "+15550100", VerifiedAt: &now},
		{Kind: email.KindEmail, Value: "bob", VerifiedAt: &now},
	} {
		if err := h.AfterCreate(ctx, nil, &idn); err != nil {
			t.Errorf("%+v: %v", idn, err)
		}
	}
	old := auth.Identity{Kind: email.KindEmail, Value: "bob@acme.com", VerifiedAt: &now}
	if err := h.AfterUpdate(ctx, nil, &old, &old); err != nil {
		t.Fatalf("already verified: %v", err)
	}
	// A verified email does query, which proves the guard above is what
	// kept the others out.
	fresh := auth.Identity{Kind: email.KindEmail, Value: "bob@acme.com", VerifiedAt: &now}
	if err := h.AfterUpdate(ctx, nil, &auth.Identity{}, &fresh); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("verified email did not look up domains: %v", err)
	}
}

// TestEmailProves_OffByDefault: without TrustVerifiedEmail no address proves
// a domain, and no identity is even read (there is no database here).
func TestEmailProves_OffByDefault(t *testing.T) {
	p, err := wireDomains(t, DomainsConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := p.emailProves(context.Background(), "usr_1", "acme.com"); ok || err != nil {
		t.Fatalf("emailProves = %v, %v", ok, err)
	}
}
