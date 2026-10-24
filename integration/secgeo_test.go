package integration

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
)

// Addresses the geo tests sign in from; 203.0.113.7 is the harness's default
// client, so a sign-up lands in Berlin.
const (
	geoBerlin   = "203.0.113.7"
	geoNewYork  = "203.0.113.8"
	geoMoscow   = "203.0.113.9"
	geoAttacker = "203.0.113.10"
)

// geoTable is the GeoLocator of these tests: a few documentation addresses.
var geoTable = auth.GeoLocatorFunc(func(_ context.Context, ip netip.Addr) (auth.GeoLocation, bool, error) {
	switch ip.String() {
	case geoBerlin:
		return auth.GeoLocation{Country: "DE", Latitude: 52.52, Longitude: 13.405, HasCoordinates: true}, true, nil
	case geoNewYork:
		return auth.GeoLocation{Country: "US", Latitude: 40.7128, Longitude: -74.006, HasCoordinates: true}, true, nil
	case geoMoscow, geoAttacker:
		return auth.GeoLocation{Country: "RU", Latitude: 55.7558, Longitude: 37.6173, HasCoordinates: true}, true, nil
	}
	return auth.GeoLocation{}, false, nil
})

// fromIP is a signed-out browser request from ip.
func fromIP(a *auth.Auth, ip string) context.Context {
	return a.WithRequest(context.Background(), auth.Request{
		Transport: auth.TransportHTTP, Client: auth.Client{IP: ip, UserAgent: "test", Origin: testBaseURL},
	})
}

// flushSecurity delivers every queued event to the sinks.
func flushSecurity(t *testing.T, a *auth.Auth) {
	t.Helper()
	if err := a.FlushSecurity(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// sessionCount is how many live sessions alice has.
func sessionCount(t *testing.T, a *auth.Auth, userID string) int {
	t.Helper()
	list, err := a.Sessions(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	return len(list)
}

// TestGeo_CountryRuleRefusesBeforeTheCredentialsAreChecked: a sign-in from a
// denied country is refused with the same answer whether the password is
// right or wrong, so the refusal reveals nothing about the guess.
func TestGeo_CountryRuleRefusesBeforeTheCredentialsAreChecked(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		mem := &auth.MemorySecuritySink{}
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, []auth.Option{
			auth.WithGeoLocator(geoTable), auth.WithGeoRules(auth.GeoRules{Deny: []string{"RU"}}), auth.WithSecuritySink(mem, auth.SecurityQueue{}),
		}, em, pw)
		signUpVerified(t, e, a, pw, em)
		for _, pass := range []password.Secret{secret, "not-the-password"} {
			_, err := pw.SignIn(fromIP(a, geoMoscow), password.SignInRequest{Identifier: alice, Password: pass})
			if !errors.Is(err, auth.ErrGeoBlocked) {
				t.Fatalf("denied country, password %q: %v, want ErrGeoBlocked", pass, err)
			}
		}
		if _, err := pw.SignIn(fromIP(a, geoNewYork), password.SignInRequest{Identifier: alice, Password: "not-the-password"}); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("allowed country, wrong password: %v", err)
		}
		if _, err := pw.SignIn(fromIP(a, geoNewYork), password.SignInRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatalf("allowed country, right password: %v", err)
		}
		flushSecurity(t, a)
		ev := mem.OfKind(auth.SecurityGeoCountry)
		if len(ev) != 2 || ev[0].Attrs[auth.AttrCountry] != "RU" || ev[0].Op != password.EndpointSignIn {
			t.Fatalf("events = %+v", ev)
		}
	})
}

// TestImpossibleTravel_BlocksTheSecondSignInAndNoSessionIsLeftBehind: Berlin,
// then New York an hour later, is refused and creates no session; after
// enough time the same sign-in goes through.
func TestImpossibleTravel_BlocksTheSecondSignInAndNoSessionIsLeftBehind(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		mem := &auth.MemorySecuritySink{}
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, []auth.Option{
			auth.WithGeoLocator(geoTable), auth.WithImpossibleTravel(auth.ImpossibleTravelRule{}), auth.WithSecuritySink(mem, auth.SecurityQueue{}),
		}, em, pw)
		up := signUpVerified(t, e, a, pw, em) // a session from Berlin
		userID := mustUserID(t, a, up)
		e.clock.Advance(time.Hour)
		// A session made by a job with no client address: newer than the
		// Berlin one, but it says nothing about where the user is, so the
		// history must pass over it.
		if _, _, err := a.CreateSession(context.Background(), userID, auth.Client{}); err != nil {
			t.Fatal(err)
		}
		_, err := pw.SignIn(fromIP(a, geoNewYork), password.SignInRequest{Identifier: alice, Password: secret})
		if !errors.Is(err, auth.ErrImpossibleTravel) {
			t.Fatalf("Berlin then New York in an hour: %v, want ErrImpossibleTravel", err)
		}
		if n := sessionCount(t, a, userID); n != 2 {
			t.Fatalf("%d sessions after the refused sign-in, want the sign-up's and the job's", n)
		}
		// The same city again is the same place, whatever the time.
		if _, err := pw.SignIn(fromIP(a, geoBerlin), password.SignInRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatalf("same city: %v", err)
		}
		e.clock.Advance(10 * time.Hour)
		if _, err := pw.SignIn(fromIP(a, geoNewYork), password.SignInRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatalf("New York ten hours later: %v", err)
		}
		flushSecurity(t, a)
		ev := mem.OfKind(auth.SecurityImpossibleTravel)
		if len(ev) != 1 || ev[0].UserID != userID || ev[0].IP != geoNewYork || ev[0].Attrs[auth.AttrPreviousCountry] != "DE" {
			t.Fatalf("events = %+v", ev)
		}
	})
}

// mustUserID is the signed-up user's id.
func mustUserID(t *testing.T, a *auth.Auth, up password.SignInResult) string {
	t.Helper()
	_, u, _, err := a.ResolveSession(context.Background(), up.Token)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

// TestImpossibleTravel_ASecondFactorIsJudgedOnce: the pending session made by
// the password step is the sign-in that is judged; promoting it after the
// second factor must not judge it again.
func TestImpossibleTravel_ASecondFactorIsJudgedOnce(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		mem := &auth.MemorySecuritySink{}
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor()
		a := e.newAuth(t, []auth.Option{
			auth.WithGeoLocator(geoTable), auth.WithImpossibleTravel(auth.ImpossibleTravelRule{Action: auth.RateLog}), auth.WithSecuritySink(mem, auth.SecurityQueue{}),
		}, em, pw, tf)
		f := factorsEnroll(t, e, a, pw, em, tf) // a session from Berlin
		e.clock.Advance(time.Hour)
		// Two password steps, the first left unfinished: each is judged, and
		// the promotion of the second is not judged again.
		abandoned := must[password.SignInResult](t)(pw.SignIn(fromIP(a, geoNewYork), password.SignInRequest{Identifier: alice, Password: secret}))
		in := must[password.SignInResult](t)(pw.SignIn(fromIP(a, geoNewYork), password.SignInRequest{Identifier: alice, Password: secret}))
		if !abandoned.SecondFactorRequired || !in.SecondFactorRequired {
			t.Fatal("sign-in must be pending")
		}
		ctx := a.WithRequest(context.Background(), auth.Request{
			Transport: auth.TransportHTTP, Client: auth.Client{IP: geoNewYork, UserAgent: "test", Origin: testBaseURL},
			Credential: auth.CredentialCookie, Token: in.Token,
		})
		if err := tf.Verify(ctx, totpAt(t, f.secret, e.clock.Now())); err != nil {
			t.Fatal(err)
		}
		flushSecurity(t, a)
		// One event per password step (both judged against Berlin, the only
		// full session), none for the promotion.
		if ev := mem.OfKind(auth.SecurityImpossibleTravel); len(ev) != 2 || ev[0].Outcome != auth.RateOutcomeLogged || ev[1].Outcome != auth.RateOutcomeLogged {
			t.Fatalf("%d travel events for two sign-ins, want 2 (logged): %+v", len(ev), ev)
		}
	})
}

// TestSecurityEvents_CredentialStuffingIsOneEventPerCrossing: the spraying
// guard reports the crossing of its limit once, not once per refusal after it.
func TestSecurityEvents_CredentialStuffingIsOneEventPerCrossing(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		mem := &auth.MemorySecuritySink{}
		pw := e.passwordPlugin(password.GuardCredentialStuffing(password.StuffingPolicy{PasswordFailures: 3, GlobalFailures: 5, Window: time.Minute}))
		a := e.newAuth(t, []auth.Option{stuffingSecret, auth.WithSecuritySink(mem, auth.SecurityQueue{})}, e.emailPlugin(), pw)
		for i := range 8 {
			who := string(rune('a'+i)) + "@example.com"
			// Three tries of one password cross the per-password limit; after
			// that other passwords carry on to the global one.
			guess := "Summer2026!"
			if i >= 3 {
				guess = fmt.Sprintf("Winter-%d!", i)
			}
			_ = stuffingSignIn(a, pw, who, guess)
		}
		flushSecurity(t, a)
		ev := mem.OfKind(auth.SecurityCredentialStuffing)
		if len(ev) != 2 {
			t.Fatalf("%d stuffing events, want 2 (one per scope): %+v", len(ev), ev)
		}
		scopes := map[string]auth.SecurityEvent{}
		for _, x := range ev {
			scopes[x.Attrs[auth.AttrScope]] = x
		}
		if p, g := scopes[auth.ScopePassword], scopes[auth.ScopeGlobal]; p.Attrs[auth.AttrFailures] != "3" || g.Attrs[auth.AttrFailures] != "5" ||
			p.Severity != auth.SeverityAlert || p.Outcome != auth.RateOutcomeBlocked || p.Op != password.EndpointSignIn {
			t.Fatalf("events = %+v", ev)
		}
		// Nothing carries the password.
		for _, x := range ev {
			for k, v := range x.Attrs {
				if v == "Summer2026!" || k == "password" {
					t.Fatalf("the password leaked into the event: %+v", x)
				}
			}
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		mem := &auth.MemorySecuritySink{}
		pw := e.passwordPlugin(password.GuardCredentialStuffing(password.StuffingPolicy{PasswordFailures: 2, LogOnly: true}))
		a := e.newAuth(t, []auth.Option{stuffingSecret, auth.WithSecuritySink(mem, auth.SecurityQueue{})}, e.emailPlugin(), pw)
		for _, who := range []string{"a@example.com", "b@example.com"} {
			_ = stuffingSignIn(a, pw, who, "Summer2026!")
		}
		flushSecurity(t, a)
		if ev := mem.OfKind(auth.SecurityCredentialStuffing); len(ev) != 1 || ev[0].Outcome != auth.RateOutcomeLogged {
			t.Fatalf("LogOnly events = %+v", ev)
		}
	})
}

// TestSecurityEvents_TwoFactorLockoutIsOneEventPerLock: the lock itself is
// reported once, with the user; the refusals while it holds are not.
func TestSecurityEvents_TwoFactorLockoutIsOneEventPerLock(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		mem := &auth.MemorySecuritySink{}
		em, pw := e.emailPlugin(), e.passwordPlugin()
		tf := factorsTwoFactor(twofactor.Lockout(2, time.Minute))
		a := e.newAuth(t, []auth.Option{auth.WithSecuritySink(mem, auth.SecurityQueue{})}, em, pw, tf)
		f := factorsEnroll(t, e, a, pw, em, tf)
		pending := factorsPending(t, a, pw)
		wrong := factorsWrongCode(t, e, f.secret)
		for range 2 {
			if err := tf.Verify(request(a, pending), wrong); !errors.Is(err, twofactor.ErrCodeInvalid) {
				t.Fatalf("wrong code: %v", err)
			}
		}
		for range 3 {
			if err := tf.Verify(request(a, pending), wrong); !errors.Is(err, twofactor.ErrLocked) {
				t.Fatalf("while locked: %v", err)
			}
		}
		flushSecurity(t, a)
		ev := mem.OfKind(auth.SecurityLockout)
		if len(ev) != 1 || ev[0].UserID == "" || ev[0].Attrs[auth.AttrFailures] != "2" || ev[0].Severity != auth.SeverityWarn {
			t.Fatalf("lockout events = %+v", ev)
		}
	})
}
