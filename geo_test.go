package auth_test

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// Where the test addresses are. 203.0.113.0/24 is documentation space, which
// no real GeoIP database knows; the locator below stands in for one.
const (
	ipBerlin  = "203.0.113.10"
	ipParis   = "203.0.113.20"
	ipUnknown = "203.0.113.30"
	ipBroken  = "203.0.113.40"
)

// errLocator is the failure the broken address raises.
var errLocator = errors.New("geo database unreadable")

// testGeo is a GeoLocator over a fixed table.
var testGeo = auth.GeoLocatorFunc(func(_ context.Context, ip netip.Addr) (auth.GeoLocation, bool, error) {
	switch ip.String() {
	case ipBerlin:
		return auth.GeoLocation{Country: "de", Latitude: 52.52, Longitude: 13.405, HasCoordinates: true}, true, nil
	case ipParis:
		return auth.GeoLocation{Country: "FR", Latitude: 48.8566, Longitude: 2.3522, HasCoordinates: true}, true, nil
	case ipBroken:
		return auth.GeoLocation{}, false, errLocator
	}
	return auth.GeoLocation{}, false, nil
})

// signInOp is a mutation flagged as a sign-in, the kind country rules judge.
func signInOp() *auth.Op[struct{}, struct{}] {
	return auth.Define(auth.OpInfo{ID: "g.sign-in", Kind: auth.Mutation, Require: auth.Public, Path: "/sign-in", SignIn: true},
		func(context.Context, *auth.Call, struct{}) (struct{}, error) { return struct{}{}, nil })
}

// geoAuth wires op, the memory sink and the geo options.
func geoAuth(t *testing.T, op auth.Operation, mem *auth.MemorySecuritySink, opts ...auth.Option) (*auth.Auth, error) {
	t.Helper()
	opts = append([]auth.Option{auth.WithPlugins(&stubPlugin{name: "g", ops: []auth.Operation{op}}), auth.WithSecuritySink(mem, auth.SecurityQueue{}), auth.WithGeoLocator(testGeo)}, opts...)
	a, err := newAuth(opts...)
	if err == nil {
		t.Cleanup(func() { _ = a.Close() })
	}
	return a, err
}

// signInFrom calls op as a browser request from ip carrying proof in
// tenantHeader.
func signInFrom(a *auth.Auth, op *auth.Op[struct{}, struct{}], ip, proof string) error {
	h := func(name string) string {
		if name == tenantHeader {
			return proof
		}
		return ""
	}
	_, err := op.Call(a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{IP: ip}, Header: h}), struct{}{})
	return err
}

// TestGeoRules_DenyAllowAndUnknown: a denied country, a country outside the
// allow list and (only when asked) an unknown address are refused with
// auth.geo_blocked; the locator's own failure is never a refusal.
func TestGeoRules_DenyAllowAndUnknown(t *testing.T) {
	cases := []struct {
		name  string
		rules auth.GeoRules
		ip    string
		want  bool
	}{
		{"denied country", auth.GeoRules{Deny: []string{"de"}}, ipBerlin, true},
		{"other country passes a deny list", auth.GeoRules{Deny: []string{"DE"}}, ipParis, false},
		{"outside the allow list", auth.GeoRules{Allow: []string{"FR"}}, ipBerlin, true},
		{"inside the allow list", auth.GeoRules{Allow: []string{"FR", "DE"}}, ipBerlin, false},
		{"deny wins over allow", auth.GeoRules{Allow: []string{"DE"}, Deny: []string{"DE"}}, ipBerlin, true},
		{"unknown address passes by default", auth.GeoRules{Allow: []string{"FR"}}, ipUnknown, false},
		{"unknown address denied when asked", auth.GeoRules{DenyUnknown: true}, ipUnknown, true},
		{"locator failure fails open, even with DenyUnknown", auth.GeoRules{DenyUnknown: true, Allow: []string{"FR"}}, ipBroken, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			op := signInOp()
			mem := &auth.MemorySecuritySink{}
			a, err := geoAuth(t, op, mem, auth.WithGeoRules(c.rules))
			if err != nil {
				t.Fatal(err)
			}
			err = signInFrom(a, op, c.ip, "")
			if c.want != errors.Is(err, auth.ErrGeoBlocked) || (!c.want && err != nil) {
				t.Fatalf("err = %v, blocked want %v", err, c.want)
			}
			if err := a.FlushSecurity(context.Background()); err != nil {
				t.Fatal(err)
			}
			ev := mem.OfKind(auth.SecurityGeoCountry)
			if c.want != (len(ev) == 1) {
				t.Fatalf("%d geo events, blocked want %v", len(ev), c.want)
			}
			if c.want && (ev[0].Outcome != auth.RateOutcomeBlocked || ev[0].IP != c.ip || ev[0].Op != "g.sign-in") {
				t.Fatalf("event = %+v", ev[0])
			}
		})
	}
}

// TestGeoRules_OnlySignInsFromTheWireAreJudged: a Go call is the app's own
// code, and an operation that does not sign anyone in is not a sign-in.
func TestGeoRules_OnlySignInsFromTheWireAreJudged(t *testing.T) {
	op := signInOp()
	other := auth.Define(auth.OpInfo{ID: "g.other", Kind: auth.Mutation, Require: auth.Public, Path: "/other"},
		func(context.Context, *auth.Call, struct{}) (struct{}, error) { return struct{}{}, nil })
	a, err := geoAuth(t, op, &auth.MemorySecuritySink{}, auth.WithGeoRules(auth.GeoRules{Deny: []string{"DE"}}),
		auth.WithPlugins(&stubPlugin{name: "g2", ops: []auth.Operation{other}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := signInFrom(a, op, ipBerlin, ""); !errors.Is(err, auth.ErrGeoBlocked) {
		t.Fatalf("sign-in from a denied country = %v", err)
	}
	goCtx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportGo, Client: auth.Client{IP: ipBerlin}})
	if _, err := op.Call(goCtx, struct{}{}); err != nil {
		t.Fatalf("Go call from a denied address = %v, want it unjudged", err)
	}
	h := func(string) string { return "" }
	if _, err := other.Call(a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{IP: ipBerlin}, Header: h}), struct{}{}); err != nil {
		t.Fatalf("non-sign-in operation = %v, want it unjudged", err)
	}
}

// TestGeoRules_LogAndChallengeActions: log lets the call through and records
// it; challenge asks the rate challenger, and the proof decides.
func TestGeoRules_LogAndChallengeActions(t *testing.T) {
	op := signInOp()
	mem := &auth.MemorySecuritySink{}
	a, err := geoAuth(t, op, mem, auth.WithGeoRules(auth.GeoRules{Deny: []string{"DE"}, Action: auth.RateLog}))
	if err != nil {
		t.Fatal(err)
	}
	if err := signInFrom(a, op, ipBerlin, ""); err != nil {
		t.Fatalf("log action refused: %v", err)
	}
	_ = a.FlushSecurity(context.Background())
	if ev := mem.OfKind(auth.SecurityGeoCountry); len(ev) != 1 || ev[0].Outcome != auth.RateOutcomeLogged {
		t.Fatalf("log events = %+v", ev)
	}

	op2 := signInOp()
	mem2 := &auth.MemorySecuritySink{}
	a2, err := geoAuth(t, op2, mem2, auth.WithGeoRules(auth.GeoRules{Deny: []string{"DE"}, Action: auth.RateChallenge}),
		auth.WithPlugins(&challengerPlugin{stubPlugin{name: "proof"}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := signInFrom(a2, op2, ipBerlin, ""); !errors.Is(err, auth.ErrChallengeRequired) {
		t.Fatalf("no proof = %v, want ErrChallengeRequired", err)
	}
	if err := signInFrom(a2, op2, ipBerlin, "human"); err != nil {
		t.Fatalf("with proof = %v", err)
	}
	if err := signInFrom(a2, op2, ipParis, ""); err != nil {
		t.Fatalf("allowed country asked for proof: %v", err)
	}
	_ = a2.FlushSecurity(context.Background())
	ev := mem2.OfKind(auth.SecurityGeoCountry)
	if len(ev) != 2 || ev[0].Outcome != auth.RateOutcomeChallenged || ev[1].Outcome != auth.RateOutcomePassed || ev[1].Severity != auth.SeverityInfo {
		t.Fatalf("challenge events = %+v", ev)
	}
}

// TestGeo_NewRefusesWhatCannotWork: each misconfiguration fails at New naming
// the option, so it cannot silently check nothing.
func TestGeo_NewRefusesWhatCannotWork(t *testing.T) {
	op := signInOp()
	plug := auth.WithPlugins(&stubPlugin{name: "g", ops: []auth.Operation{op}})
	rules := auth.WithGeoRules(auth.GeoRules{Deny: []string{"DE"}})
	travel := auth.WithImpossibleTravel(auth.ImpossibleTravelRule{})
	hist := auth.WithTravelHistory(auth.SignInHistoryFunc(func(context.Context, *auth.Auth, string) (auth.PriorSignIn, bool, error) {
		return auth.PriorSignIn{}, false, nil
	}))
	cases := []struct {
		name string
		opts []auth.Option
		want string
	}{
		{"rules without a locator", []auth.Option{plug, rules}, "WithGeoLocator"},
		{"travel without a locator", []auth.Option{plug, travel}, "WithGeoLocator"},
		{"a locator that checks nothing", []auth.Option{plug, auth.WithGeoLocator(testGeo)}, "checks nothing"},
		{"history without travel", []auth.Option{plug, auth.WithGeoLocator(testGeo), rules, hist}, "WithTravelHistory"},
		{"history alone", []auth.Option{plug, hist}, "WithTravelHistory"},
		{"empty rules", []auth.Option{plug, auth.WithGeoLocator(testGeo), auth.WithGeoRules(auth.GeoRules{})}, "checks nothing"},
		{"bad country code", []auth.Option{plug, auth.WithGeoLocator(testGeo), auth.WithGeoRules(auth.GeoRules{Deny: []string{"GER"}})}, "alpha-2"},
		{"bad allow code", []auth.Option{plug, auth.WithGeoLocator(testGeo), auth.WithGeoRules(auth.GeoRules{Allow: []string{"1A"}})}, "alpha-2"},
		{"unknown action", []auth.Option{plug, auth.WithGeoLocator(testGeo), auth.WithGeoRules(auth.GeoRules{Deny: []string{"DE"}, Action: "throttle"})}, "unknown action"},
		{"challenge without a challenger", []auth.Option{plug, auth.WithGeoLocator(testGeo), auth.WithGeoRules(auth.GeoRules{Deny: []string{"DE"}, Action: auth.RateChallenge})}, "no challenger"},
		{"travel challenge without a challenger", []auth.Option{plug, auth.WithGeoLocator(testGeo), auth.WithImpossibleTravel(auth.ImpossibleTravelRule{Action: auth.RateChallenge})}, "no challenger"},
		{"negative speed", []auth.Option{plug, auth.WithGeoLocator(testGeo), auth.WithImpossibleTravel(auth.ImpossibleTravelRule{MaxSpeedKmh: -1})}, "finite"},
		{"NaN distance", []auth.Option{plug, auth.WithGeoLocator(testGeo), auth.WithImpossibleTravel(auth.ImpossibleTravelRule{MinDistanceKm: math.NaN()})}, "finite"},
		{"infinite speed", []auth.Option{plug, auth.WithGeoLocator(testGeo), auth.WithImpossibleTravel(auth.ImpossibleTravelRule{MaxSpeedKmh: math.Inf(1)})}, "finite"},
		{"travel without IP tracking", []auth.Option{plug, auth.WithGeoLocator(testGeo), travel, auth.WithoutIPTracking()}, "WithoutIPTracking"},
		{"travel on stateless sessions", []auth.Option{plug, auth.WithGeoLocator(testGeo), travel, auth.WithSecret([]byte(strings.Repeat("k", auth.MinSecretSize))), auth.WithStatelessSessions()}, "WithTravelHistory"},
		{"nil locator", []auth.Option{plug, auth.WithGeoLocator(nil), rules}, "WithGeoLocator"},
		{"nil history", []auth.Option{plug, auth.WithGeoLocator(testGeo), travel, auth.WithTravelHistory(nil)}, "WithTravelHistory"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := newAuth(c.opts...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one naming %q", err, c.want)
			}
		})
	}
	// Stateless with its own history is fine, as is the plain happy path.
	if _, err := newAuth(plug, auth.WithGeoLocator(testGeo), travel, hist, auth.WithSecret([]byte(strings.Repeat("k", auth.MinSecretSize))), auth.WithStatelessSessions()); err != nil {
		t.Errorf("stateless with a history: %v", err)
	}
	if _, err := newAuth(plug, auth.WithGeoLocator(testGeo), rules, travel); err != nil {
		t.Errorf("rules and travel: %v", err)
	}
}
