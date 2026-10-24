package password

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// wired builds p into a core with no database and a fixed clock, which is
// all the policy helpers that touch no table need.
func wired(t *testing.T, p *Plugin, now time.Time) {
	t.Helper()
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithClock(func() time.Time { return now }), auth.WithPlugins(loginKind{recover: true}, p)); err != nil {
		t.Fatal(err)
	}
}

// TestValidatePolicies_RefusesOutOfRange: auth.New refuses a negative
// history, one past MaxHistory and a negative expiry, and takes the bounds.
func TestValidatePolicies_RefusesOutOfRange(t *testing.T) {
	for _, tc := range []struct {
		opt  Option
		want error
	}{
		{History(-1), ErrHistoryRange},
		{History(MaxHistory + 1), ErrHistoryRange},
		{ExpireAfter(-time.Hour), ErrExpireRange},
	} {
		_, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(loginKind{recover: true}, New(tc.opt)))
		if !errors.Is(err, tc.want) {
			t.Errorf("err = %v, want %v", err, tc.want)
		}
	}
	for _, opt := range []Option{History(1), History(MaxHistory), ExpireAfter(time.Hour)} {
		if err := New(opt).validatePolicies(); err != nil {
			t.Errorf("in range: %v", err)
		}
	}
}

// TestExpired_AtTheBoundary: a password set exactly ExpireAfter ago has
// expired, one a moment younger has not, and without ExpireAfter nothing
// expires.
func TestExpired_AtTheBoundary(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	p := New(Argon2(fast), ExpireAfter(90*24*time.Hour))
	wired(t, p, now)
	if !p.expired(now.Add(-90 * 24 * time.Hour)) {
		t.Fatal("a password exactly ExpireAfter old must have expired")
	}
	if p.expired(now.Add(-90*24*time.Hour + time.Second)) {
		t.Fatal("a younger password expired")
	}
	off := New(Argon2(fast))
	wired(t, off, now)
	if off.expired(now.Add(-100 * 365 * 24 * time.Hour)) {
		t.Fatal("without ExpireAfter nothing expires")
	}
}

// TestMatchAny_ChecksEveryHashAndSkipsUnknownFormats: a match anywhere in
// the list is ErrReused, a format nobody verifies is skipped, and no match
// is nil.
func TestMatchAny_ChecksEveryHashAndSkipsUnknownFormats(t *testing.T) {
	p := New(Argon2(fast), History(3))
	wired(t, p, time.Now())
	old := hashPassword("old passphrase one", fast)
	older := hashPassword("old passphrase two", fast)
	if err := p.matchAny("old passphrase two", []string{"not a hash", old, older}); !errors.Is(err, ErrReused) {
		t.Fatalf("match in the list: %v", err)
	}
	if err := p.matchAny("a brand new passphrase", []string{"not a hash", old, older}); err != nil {
		t.Fatalf("no match: %v", err)
	}
}

// TestHistory_DeclaresItsTableOnlyWhenOn: the history table, its user
// ownership and its migration exist under History and not otherwise, so a
// deployment without the policy gets no extra table.
func TestHistory_DeclaresItsTableOnlyWhenOn(t *testing.T) {
	off := New(Argon2(fast))
	wired(t, off, time.Now())
	if len(off.Tables()) != 1 || len(off.UserTables()) != 1 {
		t.Fatalf("without History: tables %v, user tables %v", off.Tables(), off.UserTables())
	}
	if m, _ := off.TypedMigrations(auth.EngineSQLite, auth.TypesFor(auth.EngineSQLite)); len(m) != 1 {
		t.Fatalf("without History: %d migrations", len(m))
	}
	on := New(Argon2(fast), History(5))
	wired(t, on, time.Now())
	if len(on.Tables()) != 2 || on.UserTables()[1].Table != TablePasswordHistory {
		t.Fatalf("with History: tables %v, user tables %v", on.Tables(), on.UserTables())
	}
	for _, engine := range []string{auth.EngineSQLite, auth.EnginePostgres, auth.EngineMySQL} {
		m, err := on.TypedMigrations(engine, auth.TypesFor(engine))
		if err != nil || len(m) != 2 || m[1].Name != migrationHistory {
			t.Fatalf("%s: %+v, %v", engine, m, err)
		}
		if !strings.Contains(strings.Join(m[1].Statements, ";"), TableNamePasswordHistory+historyIndexSuffix) {
			t.Fatalf("%s: no user_id index in %v", engine, m[1].Statements)
		}
	}
}

// TestExpireAfter_AddsChangeExpiredAndItsLimits: change-expired and its
// sign-in-sized rate rules exist only under ExpireAfter.
func TestExpireAfter_AddsChangeExpiredAndItsLimits(t *testing.T) {
	has := func(p *Plugin) (op, ip, account bool) {
		for _, o := range p.Operations() {
			op = op || o.Info().ID == EndpointChangeExpired
		}
		for _, r := range p.RateLimits() {
			ip = ip || (r.Match == EndpointChangeExpired && r.Key == auth.ByIP)
			account = account || (r.Match == EndpointChangeExpired && r.Key == auth.ByIdentifier)
		}
		return
	}
	if op, ip, account := has(New()); op || ip || account {
		t.Fatal("change-expired exists without ExpireAfter")
	}
	if op, ip, account := has(New(ExpireAfter(time.Hour))); !op || !ip || !account {
		t.Fatalf("under ExpireAfter: op %v ip %v account %v", op, ip, account)
	}
	if got := (ChangeExpiredRequest{Identifier: "  Ada@Example.com "}).RateIdentifier(); got != "ada@example.com" {
		t.Fatalf("RateIdentifier = %q", got)
	}
}
