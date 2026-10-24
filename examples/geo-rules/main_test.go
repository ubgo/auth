package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/password"
)

const (
	adaMail = "ada@example.com"
	adaPass = "correct horse battery staple"
	// wrongPass is a guess that is not ada's password.
	wrongPass = "not-the-password"
	// forwardedFor is the header the trusted proxy writes the client into.
	forwardedFor = "X-Forwarded-For"
	// tooSoon is too little time to fly Berlin to New York (about 6,400 km);
	// longEnough is enough at 900 km/h.
	tooSoon    = time.Hour
	longEnough = 8 * time.Hour
)

// world is the app with a memory sink on the stream, and ada signed up from
// Berlin; it returns her user id.
func world(t *testing.T) (*authtest.Env, *authtest.Browser, *auth.MemorySecuritySink, string) {
	t.Helper()
	mem := &auth.MemorySecuritySink{}
	e := authtest.New(t,
		authtest.WithOptions(append(geoOptions(), auth.WithSecuritySink(mem, auth.SecurityQueue{}))...),
		authtest.WithPlugins(func(*authtest.Env) []auth.Plugin { return plugins() }))
	b := e.Browser(newHandler(e.Auth))
	var up password.SignInResult
	post(t, b, berlinIP, "/auth/password/sign-up", map[string]string{"identifier": adaMail, "password": adaPass, "name": "Ada"}).Expect(http.StatusOK).Decode(&up)
	return e, b, mem, up.User.ID
}

// post sends a JSON body to path as the proxy forwards a client at ip.
func post(t *testing.T, b *authtest.Browser, ip, path string, body map[string]string) *authtest.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, b.URL()+path, strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", b.Origin)
	req.Header.Set(forwardedFor, ip)
	return b.Do(req)
}

// signIn posts ada's sign-in from ip with pass.
func signIn(t *testing.T, b *authtest.Browser, ip, pass string) *authtest.Response {
	t.Helper()
	return post(t, b, ip, "/auth/password/sign-in", map[string]string{"identifier": adaMail, "password": pass})
}

// events flushes the stream and returns the events of one kind.
func events(t *testing.T, e *authtest.Env, mem *auth.MemorySecuritySink, k auth.SecurityKind) []auth.SecurityEvent {
	t.Helper()
	if err := e.Auth.FlushSecurity(context.Background()); err != nil {
		t.Fatal(err)
	}
	return mem.OfKind(k)
}

// sessions is how many live sessions ada has.
func sessions(t *testing.T, e *authtest.Env, userID string) int {
	t.Helper()
	list, err := e.Auth.Sessions(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	return len(list)
}

// TestGeoRules_DeniedCountryIsRefusedBeforeThePassword: from a denied
// country the right and the wrong password get the same 403
// auth.geo_blocked, so the refusal says nothing about the guess; from an
// allowed country the password decides.
//
//ds:def id=georules-example-test-country-8kq3wn5v
func TestGeoRules_DeniedCountryIsRefusedBeforeThePassword(t *testing.T) {
	e, b, mem, _ := world(t)
	for _, pass := range []string{adaPass, wrongPass} {
		if code := signIn(t, b, moscowIP, pass).Expect(auth.ErrGeoBlocked.Status).ErrorCode(); code != auth.ErrGeoBlocked.Code {
			t.Fatalf("denied country, password %q: %s", pass, code)
		}
	}
	if code := signIn(t, b, berlinIP, wrongPass).Expect(password.ErrInvalidCredentials.Status).ErrorCode(); code != password.ErrInvalidCredentials.Code {
		t.Fatalf("allowed country, wrong password: %s", code)
	}
	signIn(t, b, berlinIP, adaPass).Expect(http.StatusOK)
	got := events(t, e, mem, auth.SecurityGeoCountry)
	if len(got) != 2 {
		t.Fatalf("%d geo.country events, want 2: %+v", len(got), got)
	}
	for _, ev := range got {
		if ev.Attrs[auth.AttrCountry] != countryRussia || ev.Outcome != auth.RateOutcomeBlocked || ev.IP != moscowIP || ev.Op != password.EndpointSignIn {
			t.Fatalf("event = %+v", ev)
		}
	}
}

// TestGeoRules_ImpossibleTravelIsRefusedAndLeavesNoSession: Berlin, then New
// York an hour later, is refused with 403 auth.impossible_travel and creates
// no session; the same sign-in eight hours after Berlin goes through.
//
//ds:def id=georules-example-test-travel-4wn8qk2x
func TestGeoRules_ImpossibleTravelIsRefusedAndLeavesNoSession(t *testing.T) {
	e, b, mem, userID := world(t)
	signIn(t, b, berlinIP, adaPass).Expect(http.StatusOK)
	before := sessions(t, e, userID)

	e.Clock.Advance(tooSoon)
	if code := signIn(t, b, newYorkIP, adaPass).Expect(auth.ErrImpossibleTravel.Status).ErrorCode(); code != auth.ErrImpossibleTravel.Code {
		t.Fatalf("New York an hour after Berlin: %s", code)
	}
	if n := sessions(t, e, userID); n != before {
		t.Fatalf("%d sessions after the refused sign-in, want %d", n, before)
	}

	e.Clock.Advance(longEnough - tooSoon)
	signIn(t, b, newYorkIP, adaPass).Expect(http.StatusOK)
	if n := sessions(t, e, userID); n != before+1 {
		t.Fatalf("%d sessions after the later sign-in, want %d", n, before+1)
	}

	got := events(t, e, mem, auth.SecurityImpossibleTravel)
	if len(got) != 1 {
		t.Fatalf("%d impossible_travel events, want 1: %+v", len(got), got)
	}
	ev := got[0]
	if ev.UserID != userID || ev.IP != newYorkIP || ev.Attrs[auth.AttrCountry] != countryUS || ev.Attrs[auth.AttrPreviousCountry] != countryGermany ||
		ev.Severity != auth.SeverityAlert || ev.Outcome != auth.RateOutcomeBlocked || ev.Attrs[auth.AttrElapsed] != tooSoon.String() {
		t.Fatalf("event = %+v", ev)
	}
}
