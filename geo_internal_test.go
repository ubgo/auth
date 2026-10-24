package auth

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// Locations by documentation address, far enough apart to tell journeys apart.
var travelPlaces = map[string]GeoLocation{
	"203.0.113.1": {Country: "DE", Latitude: 52.52, Longitude: 13.405, HasCoordinates: true},    // Berlin
	"203.0.113.2": {Country: "US", Latitude: 40.7128, Longitude: -74.006, HasCoordinates: true}, // New York, about 6,400 km
	"203.0.113.3": {Country: "DE", Latitude: 52.4, Longitude: 13.1, HasCoordinates: true},       // Potsdam, about 30 km
	"203.0.113.4": {Country: "FR"},                                                              // country only
}

var travelLocator = GeoLocatorFunc(func(_ context.Context, ip netip.Addr) (GeoLocation, bool, error) {
	if ip.String() == "203.0.113.9" {
		return GeoLocation{}, false, errors.New("locator down")
	}
	l, ok := travelPlaces[ip.String()]
	return l, ok, nil
})

// travelAuth wires impossible travel with a fixed clock and the history the
// test hands in.
func travelAuth(t *testing.T, now time.Time, h SignInHistory, rule ImpossibleTravelRule, extra ...Option) (*Auth, *MemorySecuritySink) {
	t.Helper()
	mem := &MemorySecuritySink{}
	a, err := New(append([]Option{
		WithPlugins(scriptSignIn{}), WithClock(func() time.Time { return now }), WithSecuritySink(mem, SecurityQueue{}),
		WithGeoLocator(travelLocator), WithImpossibleTravel(rule), WithTravelHistory(h),
	}, extra...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a, mem
}

// lastSeen is a history that always answers with ip, hoursAgo before now.
func lastSeen(now time.Time, ip string, ago time.Duration) SignInHistory {
	return SignInHistoryFunc(func(context.Context, *Auth, string) (PriorSignIn, bool, error) {
		return PriorSignIn{IP: ip, At: now.Add(-ago)}, true, nil
	})
}

func TestGreatCircle_KnownDistances(t *testing.T) {
	d := greatCircleKm(travelPlaces["203.0.113.1"], travelPlaces["203.0.113.2"])
	if d < 6350 || d > 6450 {
		t.Errorf("Berlin to New York = %.0f km, want about 6385", d)
	}
	if d := greatCircleKm(travelPlaces["203.0.113.1"], travelPlaces["203.0.113.1"]); d != 0 {
		t.Errorf("a place to itself = %v", d)
	}
	// Antipodes stay finite: asin's argument is clamped.
	if d := greatCircleKm(GeoLocation{Latitude: 0, Longitude: 0}, GeoLocation{Latitude: 0, Longitude: 180}); d < 20000 || d > 20100 {
		t.Errorf("antipodes = %.0f", d)
	}
}

// TestImpossibleTravel_SpeedThreshold: the same pair of places is possible
// after a long enough flight and impossible after a short one; a hop within
// the minimum distance is never judged; a journey of no time at all is
// impossible.
func TestImpossibleTravel_SpeedThreshold(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	client := func(ip string) Client { return Client{IP: ip} }
	cases := []struct {
		name string
		ago  time.Duration
		from string
		to   string
		want bool
	}{
		{"eight hours is a flight", 8 * time.Hour, "203.0.113.1", "203.0.113.2", false},
		{"two hours is not", 2 * time.Hour, "203.0.113.1", "203.0.113.2", true},
		{"no time at all", 0, "203.0.113.1", "203.0.113.2", true},
		{"a clock that ran backwards", -time.Hour, "203.0.113.1", "203.0.113.2", true},
		{"thirty kilometres in a minute is the same place", time.Minute, "203.0.113.1", "203.0.113.3", false},
		{"country-only data cannot judge", time.Minute, "203.0.113.1", "203.0.113.4", false},
		{"unknown address cannot judge", time.Minute, "203.0.113.1", "203.0.113.200", false},
		{"unknown previous address cannot judge", time.Minute, "203.0.113.200", "203.0.113.1", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, mem := travelAuth(t, now, lastSeen(now, c.from, c.ago), ImpossibleTravelRule{})
			err := a.geo.checkTravel(context.Background(), "usr_1", client(c.to))
			if got := errors.Is(err, ErrImpossibleTravel); got != c.want || (!c.want && err != nil) {
				t.Fatalf("err = %v, impossible want %v", err, c.want)
			}
			if err := a.FlushSecurity(context.Background()); err != nil {
				t.Fatal(err)
			}
			ev := mem.OfKind(SecurityImpossibleTravel)
			if c.want != (len(ev) == 1) {
				t.Fatalf("%d travel events, want one: %v", len(ev), c.want)
			}
			if c.want {
				e := ev[0]
				if e.Severity != SeverityAlert || e.Outcome != RateOutcomeBlocked || e.UserID != "usr_1" || e.Attrs[AttrCountry] != "US" || e.Attrs[AttrPreviousCountry] != "DE" || e.Attrs[AttrDistanceKm] == "" {
					t.Fatalf("event = %+v", e)
				}
			}
		})
	}
}

// TestImpossibleTravel_ThresholdsAreConfigurable: a stricter speed turns a
// plausible flight impossible, and a larger minimum distance excuses it.
func TestImpossibleTravel_ThresholdsAreConfigurable(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	hist := lastSeen(now, "203.0.113.1", 8*time.Hour) // ~800 km/h to New York
	a, _ := travelAuth(t, now, hist, ImpossibleTravelRule{MaxSpeedKmh: 500})
	if err := a.geo.checkTravel(context.Background(), "u", Client{IP: "203.0.113.2"}); !errors.Is(err, ErrImpossibleTravel) {
		t.Errorf("500 km/h limit: %v, want impossible", err)
	}
	a, _ = travelAuth(t, now, lastSeen(now, "203.0.113.1", time.Minute), ImpossibleTravelRule{MinDistanceKm: 10000})
	if err := a.geo.checkTravel(context.Background(), "u", Client{IP: "203.0.113.2"}); err != nil {
		t.Errorf("10,000 km minimum: %v, want excused", err)
	}
	a, _ = travelAuth(t, now, lastSeen(now, "203.0.113.1", time.Minute), ImpossibleTravelRule{})
	if a.geo.travel.MaxSpeedKmh != DefaultTravelSpeedKmh || a.geo.travel.MinDistanceKm != DefaultTravelMinDistanceKm || a.geo.travel.Action != RateBlock {
		t.Errorf("defaults = %+v", a.geo.travel)
	}
}

// TestImpossibleTravel_FailsOpenOnItsSources: a history or a locator that
// fails, a first sign-in, and an empty address never refuse a sign-in.
func TestImpossibleTravel_FailsOpenOnItsSources(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	broken := SignInHistoryFunc(func(context.Context, *Auth, string) (PriorSignIn, bool, error) {
		return PriorSignIn{}, false, errors.New("history down")
	})
	first := SignInHistoryFunc(func(context.Context, *Auth, string) (PriorSignIn, bool, error) { return PriorSignIn{}, false, nil })
	for name, tc := range map[string]struct {
		h  SignInHistory
		ip string
	}{
		"history error":   {broken, "203.0.113.2"},
		"first sign-in":   {first, "203.0.113.2"},
		"locator error":   {lastSeen(now, "203.0.113.1", time.Minute), "203.0.113.9"},
		"previous broken": {lastSeen(now, "203.0.113.9", time.Minute), "203.0.113.2"},
		"no address":      {lastSeen(now, "203.0.113.1", time.Minute), ""},
		"not an address":  {lastSeen(now, "203.0.113.1", time.Minute), "not-an-ip"},
	} {
		a, mem := travelAuth(t, now, tc.h, ImpossibleTravelRule{})
		if err := a.geo.checkTravel(ctx, "u", Client{IP: tc.ip}); err != nil {
			t.Errorf("%s: %v, want the sign-in to go ahead", name, err)
		}
		_ = a.FlushSecurity(ctx)
		if n := len(mem.Events()); n != 0 {
			t.Errorf("%s: %d events", name, n)
		}
	}
}

// TestImpossibleTravel_LogChallengeAndNoCall: log records and lets through;
// a challenge asks the call's challenger; with no call to ask (a Go caller)
// the challenge refuses like a block.
func TestImpossibleTravel_LogChallengeAndNoCall(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	hist := lastSeen(now, "203.0.113.1", time.Minute)
	a, mem := travelAuth(t, now, hist, ImpossibleTravelRule{Action: RateLog})
	if err := a.geo.checkTravel(ctx, "u", Client{IP: "203.0.113.2"}); err != nil {
		t.Fatalf("log action refused: %v", err)
	}
	_ = a.FlushSecurity(ctx)
	if ev := mem.Events(); len(ev) != 1 || ev[0].Outcome != RateOutcomeLogged {
		t.Fatalf("log events = %+v", ev)
	}

	asked := 0
	ch := RateChallengerFunc(func(context.Context, *Call) error {
		asked++
		if asked == 1 {
			return ErrChallengeRequired
		}
		return nil
	})
	a, mem = travelAuth(t, now, hist, ImpossibleTravelRule{Action: RateChallenge}, WithRateChallenger(ch))
	if err := a.geo.checkTravel(ctx, "u", Client{IP: "203.0.113.2"}); !errors.Is(err, ErrImpossibleTravel) || asked != 0 {
		t.Fatalf("challenge with no call = %v (asked %d), want a block", err, asked)
	}
	withCall := context.WithValue(ctx, callKey{}, &Call{})
	if err := a.geo.checkTravel(withCall, "u", Client{IP: "203.0.113.2"}); !errors.Is(err, ErrChallengeRequired) {
		t.Fatalf("first challenge = %v", err)
	}
	if err := a.geo.checkTravel(withCall, "u", Client{IP: "203.0.113.2"}); err != nil {
		t.Fatalf("second challenge (proof given) = %v", err)
	}
	_ = a.FlushSecurity(ctx)
	ev := mem.Events()
	if len(ev) != 3 || ev[0].Outcome != RateOutcomeBlocked || ev[1].Outcome != RateOutcomeChallenged || ev[2].Outcome != RateOutcomePassed {
		t.Fatalf("challenge events = %+v", ev)
	}
}
