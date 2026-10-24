package apikey

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

func intp(n int) *int { return &n }

func TestLimits_ValidateAndNone(t *testing.T) {
	for name, l := range map[string]Limits{
		"rate max without window":     {RateMax: 10},
		"window without max":          {RateWindow: time.Minute},
		"sub-second window":           {RateMax: 10, RateWindow: 500 * time.Millisecond},
		"negative max":                {RateMax: -1, RateWindow: time.Minute},
		"refill without interval":     {RefillAmount: 5},
		"interval without amount":     {RefillInterval: time.Hour},
		"negative remaining":          {Remaining: intp(-1)},
		"negative refill with window": {RefillAmount: -3, RefillInterval: time.Hour},
	} {
		if err := l.validate(); !errors.Is(err, ErrBadLimitsValue) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, l := range map[string]Limits{
		"none":       {},
		"rate only":  {RateMax: 10, RateWindow: time.Minute},
		"quota only": {Remaining: intp(100)},
		"refill":     {Remaining: intp(5), RefillAmount: 5, RefillInterval: time.Hour},
		"everything": {RateMax: 1, RateWindow: time.Second, Remaining: intp(0), RefillAmount: 1, RefillInterval: time.Second},
	} {
		if err := l.validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !(Limits{}).None() || (Limits{Remaining: intp(0)}).None() || (Limits{RateMax: 1, RateWindow: time.Second}).None() {
		t.Fatal("None misreports")
	}
}

func TestLimits_JSONIsInWholeSeconds(t *testing.T) {
	l := Limits{RateMax: 10, RateWindow: 90 * time.Second, Remaining: intp(7), RefillAmount: 50, RefillInterval: 24 * time.Hour}
	b, err := json.Marshal(l)
	if err != nil || string(b) != `{"rateMax":10,"rateWindowSeconds":90,"remaining":7,"refillAmount":50,"refillIntervalSeconds":86400}` {
		t.Fatalf("json = %s %v", b, err)
	}
	var back Limits
	if err := json.Unmarshal(b, &back); err != nil || back.RateWindow != l.RateWindow || back.RefillInterval != l.RefillInterval || *back.Remaining != 7 {
		t.Fatalf("round trip = %+v %v", back, err)
	}
	if err := json.Unmarshal([]byte(`"nope"`), &back); err == nil {
		t.Fatal("a string decoded as Limits")
	}
	b, _ = json.Marshal(Limits{})
	if string(b) != `{"rateMax":0,"rateWindowSeconds":0,"remaining":null,"refillAmount":0,"refillIntervalSeconds":0}` {
		t.Fatalf("zero limits = %s", b)
	}
}

func TestCheckMetadata(t *testing.T) {
	for name, raw := range map[string]string{"absent": "", "null": "null"} {
		if got, err := checkMetadata(json.RawMessage(raw), false); err != nil || got != nil {
			t.Errorf("%s: %v %v", name, got, err)
		}
	}
	if _, err := checkMetadata(json.RawMessage(`{"a":1}`), false); !errors.Is(err, ErrMetadataDisabled) {
		t.Fatalf("metadata while disabled: %v", err)
	}
	for name, raw := range map[string]string{
		"array":    `[1]`,
		"string":   `"x"`,
		"number":   `1`,
		"broken":   `{"a":`,
		"too long": `{"a":"` + strings.Repeat("x", maxMetadataLength) + `"}`,
	} {
		if _, err := checkMetadata(json.RawMessage(raw), true); !errors.Is(err, ErrBadMetadata) {
			t.Errorf("%s: %v", name, err)
		}
	}
	got, err := checkMetadata(json.RawMessage("{ \"env\" : \"prod\" ,\n \"n\": 2 }"), true)
	if err != nil || *got != `{"env":"prod","n":2}` {
		t.Fatalf("compacted = %q %v", *got, err)
	}
}

func TestMigrations_LimitsColumnsAreASecondMigration(t *testing.T) {
	p := New(Scopes("ok"))
	if _, err := auth.New(auth.WithPlugins(stubSignIn{}, p)); err != nil {
		t.Fatal(err)
	}
	for _, engine := range []string{auth.EngineMySQL, auth.EnginePostgres, auth.EngineSQLite} {
		ms, err := p.TypedMigrations(engine, auth.TypesFor(engine))
		if err != nil || len(ms) != 4 || ms[1].Name != migrationKeyLimits || len(ms[1].Statements) != 10 || ms[2].Name != migrationKeyConfig || len(ms[2].Statements) != 4 || ms[3].Name != migrationKeyOrg || len(ms[3].Statements) != 3 {
			t.Fatalf("%s: %+v %v", engine, ms, err)
		}
		// Each round's columns are a migration of their own: the earlier
		// ones' checksums are in every deployed ledger.
		for _, st := range append(slices.Clone(ms[1].Statements), ms[2].Statements[:3]...) {
			if !strings.HasPrefix(st, "ALTER TABLE "+TableNameKey+" ADD COLUMN ") {
				t.Fatalf("%s: %q", engine, st)
			}
		}
		if want := "CREATE INDEX " + TableNameKey + keyConfigIndexSuffix + " ON " + TableNameKey + " (" + ColConfigID + ")"; ms[2].Statements[3] != want {
			t.Fatalf("%s: index = %q", engine, ms[2].Statements[3])
		}
	}
}

func TestValidate_DefaultLimits(t *testing.T) {
	_, err := auth.New(auth.WithPlugins(stubSignIn{}, New(Scopes("s"), DefaultLimits(Limits{RateMax: 5}))))
	if !errors.Is(err, ErrBadLimits) || !errors.Is(err, ErrBadLimitsValue) {
		t.Fatalf("unpaired default limits: %v", err)
	}
	if _, err := auth.New(auth.WithPlugins(stubSignIn{}, New(Scopes("s"), DefaultLimits(Limits{RateMax: 5, RateWindow: time.Minute}), AllowMetadata()))); err != nil {
		t.Fatal(err)
	}
}

func TestExpiryFor(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	p := New(Scopes("s"))
	if exp, err := p.expiryFor(0, now); err != nil || exp != nil {
		t.Fatalf("never = %v %v", exp, err)
	}
	if exp, err := p.expiryFor(3, now); err != nil || !exp.Equal(now.Add(3*day)) {
		t.Fatalf("three days = %v %v", exp, err)
	}
	p = New(Scopes("s"), WithExpiry(Expiry{MinDays: 7, MaxDays: 30, DefaultDays: 14}))
	if exp, err := p.expiryFor(0, now); err != nil || !exp.Equal(now.Add(14*day)) {
		t.Fatalf("default = %v %v", exp, err)
	}
	for _, days := range []int{-1, 3, 31} {
		if _, err := p.expiryFor(days, now); !errors.Is(err, ErrExpiryOutOfRange) {
			t.Errorf("%d days: %v", days, err)
		}
	}
	strict := New(Scopes("s"), WithExpiry(Expiry{MaxDays: 30}))
	if _, err := strict.expiryFor(0, now); !errors.Is(err, ErrExpiryOutOfRange) {
		t.Fatalf("never under a maximum: %v", err)
	}
	named := New(Scopes("s"), RequireName())
	if _, err := named.checkName("  "); !errors.Is(err, ErrNameRequired) {
		t.Fatalf("blank name under RequireName: %v", err)
	}
	if name, err := New(Scopes("s"), NameLength(3)).checkName("abcdef"); err != nil || name != "abc" {
		t.Fatalf("cut name = %q %v", name, err)
	}
}

// TestRetryAfter_EveryShapeOfWindow pins the Retry-After a refused key gets:
// the time left in the open window, and the window's full length when the
// start is unknown or already past (a reset is due, so the next window is the
// soonest a request can pass).
func TestRetryAfter_EveryShapeOfWindow(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	window := time.Minute
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }
	cases := map[string]struct {
		start *time.Time
		want  time.Duration
	}{
		"window open":       {at(-20 * time.Second), 40 * time.Second},
		"start unknown":     {nil, window},
		"window already up": {at(-2 * time.Minute), window},
		"window just ended": {at(-window), window},
	}
	for name, c := range cases {
		r := keyRow{k: Key{Limits: Limits{RateWindow: window}}, windowStart: c.start}
		if got := retryAfter(r, now); got != c.want {
			t.Errorf("%s: retryAfter = %s, want %s", name, got, c.want)
		}
	}
}
