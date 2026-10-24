package auth

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Geo policy at sign-in: country allow and deny rules, and impossible-travel
// detection. The library has no GeoIP database and no vendor client: where an
// address is is answered by the GeoLocator the app passes (a MaxMind reader,
// a CDN header, a lookup service, a table in a test). Everything is off until
// WithGeoLocator and a rule are given.
//
// The two checks sit in different places on purpose. Country rules run before
// the credentials are looked at (in the pipeline, for operations marked
// OpInfo.SignIn), so a refusal does not reveal whether a guess was right.
// Impossible travel needs the user, so it runs where the session is created,
// after the credentials were accepted; its refusal therefore tells someone
// holding a correct password that the password is correct. That is inherent
// in any risk-based sign-in check; RateChallenge or RateLog avoid showing it.

// GeoLocation is where an address is, as far as a GeoLocator knows.
//
//ds:def id=core-geolocation-6xk3wq8n owner=@khanakia stability=stable
type GeoLocation struct {
	// Country is the ISO 3166-1 alpha-2 code ("DE"), upper-case, or "" when
	// only coordinates are known.
	Country string
	// Latitude and Longitude are degrees, valid only when HasCoordinates.
	Latitude, Longitude float64
	// HasCoordinates is whether Latitude and Longitude mean anything; a
	// country-only database leaves it false and so cannot judge travel.
	HasCoordinates bool
}

// GeoLocator turns a client address into a location. found is false for an
// address the source does not know (a private range, a gap in the database);
// an error is a source that failed (a database that cannot be read). The
// library treats the two differently: see GeoRules.DenyUnknown.
//
// It runs on the sign-in request's goroutine, so it must be fast and local
// (an in-memory database, not a network call without a tight timeout).
//
//ds:def id=core-geolocator-2nw7kq5x owner=@khanakia stability=stable
type GeoLocator interface {
	Locate(ctx context.Context, ip netip.Addr) (loc GeoLocation, found bool, err error)
}

// GeoLocatorFunc adapts a function to GeoLocator.
type GeoLocatorFunc func(ctx context.Context, ip netip.Addr) (GeoLocation, bool, error)

// Locate calls f.
func (f GeoLocatorFunc) Locate(ctx context.Context, ip netip.Addr) (GeoLocation, bool, error) {
	return f(ctx, ip)
}

// GeoRules are the country rules for sign-in. A sign-in operation whose
// client address resolves to a country in Deny, or outside a non-empty Allow,
// gets Action.
//
//ds:def id=core-georules-9tm4vk2w owner=@khanakia stability=stable
type GeoRules struct {
	// Allow, when not empty, lists the only countries that may sign in (ISO
	// 3166-1 alpha-2, any case). Deny lists countries that may not; a country
	// in both is denied.
	Allow, Deny []string
	// DenyUnknown applies Action to an address the locator does not know
	// (found false). Off by default: private networks, a development machine
	// and gaps in the database would otherwise lock people out. A locator
	// that returns an error is never denied for it: the check fails open and
	// logs, because a GeoIP outage must not be a sign-in outage.
	DenyUnknown bool
	// Action is what a violation does: RateBlock (the default, 403
	// auth.geo_blocked), RateLog (record only) or RateChallenge (the
	// RateChallenger decides, as for a rate rule).
	Action RateAction
}

// ImpossibleTravelRule configures impossible-travel detection: a sign-in whose
// location is too far from the user's previous sign-in for the time between
// them.
//
//ds:def id=core-impossibletravelrule-5qk8wn3v owner=@khanakia stability=stable
type ImpossibleTravelRule struct {
	// MaxSpeedKmh is the fastest believable journey in km/h; 0 takes
	// DefaultTravelSpeedKmh. A negative or non-finite value is refused.
	MaxSpeedKmh float64
	// MinDistanceKm is the distance below which two locations count as the
	// same place, whatever the time: GeoIP is accurate to tens or hundreds of
	// kilometres, and a carrier's address can resolve to another city. 0 takes
	// DefaultTravelMinDistanceKm.
	MinDistanceKm float64
	// Action is what an impossible journey does: RateBlock (the default, 403
	// auth.impossible_travel), RateLog or RateChallenge.
	Action RateAction
}

// Defaults of ImpossibleTravelRule.
const (
	// DefaultTravelSpeedKmh is a little above an airliner's cruising speed,
	// so only a journey no flight could make is flagged.
	DefaultTravelSpeedKmh = 900.0
	// DefaultTravelMinDistanceKm ignores hops shorter than typical GeoIP error.
	DefaultTravelMinDistanceKm = 100.0
	// earthRadiusKm is the mean Earth radius for the great-circle distance.
	earthRadiusKm = 6371.0088
)

// PriorSignIn is the previous sign-in a SignInHistory found.
type PriorSignIn struct {
	IP string
	At time.Time
}

// SignInHistory answers "where and when did this user last sign in?" for
// impossible-travel detection. The default reads the user's sessions (live
// and, under WithSessionArchive, revoked ones); an app that keeps a login
// table, or runs stateless sessions, passes its own with WithTravelHistory.
// found false means there is nothing to compare with (a first sign-in), and
// no check is made. An error is logged and the sign-in goes ahead.
//
//ds:def id=core-signinhistory-3wx9qn6k owner=@khanakia stability=stable
type SignInHistory interface {
	PreviousSignIn(ctx context.Context, a *Auth, userID string) (prior PriorSignIn, found bool, err error)
}

// SignInHistoryFunc adapts a function to SignInHistory.
type SignInHistoryFunc func(ctx context.Context, a *Auth, userID string) (PriorSignIn, bool, error)

// PreviousSignIn calls f.
func (f SignInHistoryFunc) PreviousSignIn(ctx context.Context, a *Auth, userID string) (PriorSignIn, bool, error) {
	return f(ctx, a, userID)
}

// SessionSignInHistory is the default SignInHistory: the newest session of the
// user that carries an address, among the live ones and the archived revoked
// ones. Pending sessions (a second factor not yet passed) and impersonation
// sessions are not the user's own sign-ins. A user whose sessions have all
// expired and been swept has no history; keep WithSessionArchive for longer
// memory.
//
//ds:def id=core-sessionsigninhistory-7hv2xm4q owner=@khanakia stability=stable
func SessionSignInHistory() SignInHistory { return sessionSignInHistory{} }

type sessionSignInHistory struct{}

// PreviousSignIn finds the newest eligible session.
func (sessionSignInHistory) PreviousSignIn(ctx context.Context, a *Auth, userID string) (PriorSignIn, bool, error) {
	live, err := a.Sessions(ctx, userID)
	revoked, rerr := a.RevokedSessions(ctx, userID)
	if errors.Is(rerr, ErrNoDatabase) {
		rerr = nil // no archive without a database; the live sessions are all there is
	}
	if err := errors.Join(err, rerr); err != nil {
		return PriorSignIn{}, false, err
	}
	var best PriorSignIn
	found := false
	for _, s := range append(live, revoked...) {
		if s.IP == "" || s.SecondFactorPending || s.ImpersonatedBy != nil || s.APIKeyID != "" {
			continue
		}
		if !found || s.CreatedAt.After(best.At) {
			best, found = PriorSignIn{IP: s.IP, At: s.CreatedAt}, true
		}
	}
	return best, found, nil
}

// WithGeoLocator sets where client addresses are looked up. It turns nothing
// on by itself: New refuses it without WithGeoRules or WithImpossibleTravel,
// and refuses either of those without it.
//
//ds:def id=opt-withgeolocator-4nz8kw2m owner=@khanakia stability=stable
func WithGeoLocator(l GeoLocator) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithGeoLocator", l) {
			return
		}
		s.geoLocator = l
	}
}

// WithGeoRules applies country allow and deny rules to every sign-in
// operation (OpInfo.SignIn), before the credentials are checked. It needs
// WithGeoLocator. A Go call to CreateSession is the app's own code and is not
// judged: there is no client address.
//
//ds:def id=opt-withgeorules-8cq3vx5t owner=@khanakia stability=stable
func WithGeoRules(r GeoRules) Option { return func(s *settings) { s.geoRules = &r } }

// WithImpossibleTravel compares each new sign-in's location with the user's
// previous one and applies the rule's action when no journey could connect
// them: distance / elapsed time above the speed limit, for a distance above
// the minimum. It needs WithGeoLocator and sessions that record addresses
// (not WithoutIPTracking), and the default history needs a session list (not
// WithStatelessSessions) unless WithTravelHistory supplies one. A sign-in with
// no previous one, or whose locations lack coordinates, is not judged.
//
//ds:def id=opt-withimpossibletravel-6km2wq9v owner=@khanakia stability=stable
func WithImpossibleTravel(r ImpossibleTravelRule) Option {
	return func(s *settings) { s.travelRule = &r }
}

// WithTravelHistory replaces where the previous sign-in is read from. New
// refuses it without WithImpossibleTravel.
//
//ds:def id=opt-withtravelhistory-3xt7nk4w owner=@khanakia stability=stable
func WithTravelHistory(h SignInHistory) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithTravelHistory", h) {
			return
		}
		s.travelHistory = h
	}
}

var (
	// ErrGeoBlocked: a GeoRules violation under RateBlock.
	ErrGeoBlocked = NewError("auth.geo_blocked", http.StatusForbidden, "Sign-in is not available from your location.")
	// ErrImpossibleTravel: an impossible journey under RateBlock.
	ErrImpossibleTravel = NewError("auth.impossible_travel", http.StatusForbidden, "This sign-in looks unusual. Try again later or contact support.")
)

// geoPolicy is the resolved geo configuration.
type geoPolicy struct {
	a       *Auth
	locator GeoLocator
	rules   *GeoRules
	allow   []string
	deny    []string
	travel  *ImpossibleTravelRule
	history SignInHistory
}

// wireGeo validates the geo options at New, after the rate limiter (a
// challenge action needs its challenger).
func (a *Auth) wireGeo(s *settings) error {
	if s.geoLocator == nil && s.geoRules == nil && s.travelRule == nil {
		if s.travelHistory != nil {
			return fmt.Errorf("%w: auth.WithTravelHistory needs auth.WithImpossibleTravel", ErrBadOperation)
		}
		return nil
	}
	if s.geoLocator == nil {
		return fmt.Errorf("%w: auth.WithGeoRules and auth.WithImpossibleTravel need auth.WithGeoLocator", ErrBadOperation)
	}
	if s.geoRules == nil && s.travelRule == nil {
		return fmt.Errorf("%w: auth.WithGeoLocator needs auth.WithGeoRules or auth.WithImpossibleTravel, or it checks nothing", ErrBadOperation)
	}
	if s.travelHistory != nil && s.travelRule == nil {
		return fmt.Errorf("%w: auth.WithTravelHistory needs auth.WithImpossibleTravel", ErrBadOperation)
	}
	g := &geoPolicy{a: a, locator: s.geoLocator}
	if r := s.geoRules; r != nil {
		rules := *r
		var err error
		if g.allow, err = normalizeCountries("auth.WithGeoRules Allow", r.Allow); err != nil {
			return err
		}
		if g.deny, err = normalizeCountries("auth.WithGeoRules Deny", r.Deny); err != nil {
			return err
		}
		if len(g.allow) == 0 && len(g.deny) == 0 && !rules.DenyUnknown {
			return fmt.Errorf("%w: auth.WithGeoRules has no Allow, Deny or DenyUnknown, so it checks nothing", ErrBadOperation)
		}
		if err := a.checkGeoAction("auth.WithGeoRules", rules.Action); err != nil {
			return err
		}
		rules.Action = rules.Action.orDefault()
		g.rules = &rules
	}
	if r := s.travelRule; r != nil {
		t := *r
		if bad(t.MaxSpeedKmh) || bad(t.MinDistanceKm) {
			return fmt.Errorf("%w: auth.WithImpossibleTravel: speed %v and distance %v must be finite and not negative", ErrBadOperation, t.MaxSpeedKmh, t.MinDistanceKm)
		}
		if err := a.checkGeoAction("auth.WithImpossibleTravel", t.Action); err != nil {
			return err
		}
		if !a.trackIP {
			return fmt.Errorf("%w: auth.WithImpossibleTravel needs the client address on the session, which auth.WithoutIPTracking removes; pass auth.WithTravelHistory to keep your own", ErrBadOperation)
		}
		t.Action = t.Action.orDefault()
		if t.MaxSpeedKmh == 0 {
			t.MaxSpeedKmh = DefaultTravelSpeedKmh
		}
		if t.MinDistanceKm == 0 {
			t.MinDistanceKm = DefaultTravelMinDistanceKm
		}
		g.travel = &t
		g.history = s.travelHistory
		if g.history == nil {
			if a.stateless != nil {
				return fmt.Errorf("%w: auth.WithImpossibleTravel: the default history reads the user's sessions, which WithStatelessSessions does not keep; pass auth.WithTravelHistory", ErrBadOperation)
			}
			g.history = SessionSignInHistory()
		}
	}
	a.geo = g
	return nil
}

// bad reports a negative or non-finite number.
func bad(x float64) bool { return x < 0 || math.IsNaN(x) || math.IsInf(x, 0) }

// checkGeoAction refuses an unknown action, and a challenge with no
// challenger to ask.
func (a *Auth) checkGeoAction(owner string, x RateAction) error {
	if !validRateAction(x) {
		return fmt.Errorf("%w: %s: unknown action %q", ErrBadOperation, owner, x)
	}
	if x == RateChallenge && a.limiter.challenger == nil {
		return fmt.Errorf("%w: %s challenges, and no challenger is registered: add plugin/captcha or plugin/pow, or auth.WithRateChallenger", ErrBadOperation, owner)
	}
	return nil
}

// countryCodeLen is the length of an ISO 3166-1 alpha-2 code.
const countryCodeLen = 2

// normalizeCountries upper-cases a list and refuses anything that is not two
// ASCII letters, so a typo ("GER") fails at start-up rather than allowing or
// denying nobody.
func normalizeCountries(owner string, in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, c := range in {
		c = strings.ToUpper(strings.TrimSpace(c))
		if len(c) != countryCodeLen || c[0] < 'A' || c[0] > 'Z' || c[1] < 'A' || c[1] > 'Z' {
			return nil, fmt.Errorf("%w: %s: %q is not an ISO 3166-1 alpha-2 country code", ErrBadOperation, owner, c)
		}
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out, nil
}

// locate resolves an address; a bad address or a locator error is "unknown"
// with the error returned for logging.
func (g *geoPolicy) locate(ctx context.Context, ipText string) (GeoLocation, bool, error) {
	ip, err := netip.ParseAddr(ipText)
	if err != nil {
		return GeoLocation{}, false, nil
	}
	loc, found, err := g.locator.Locate(ctx, ip.Unmap())
	if err != nil {
		return GeoLocation{}, false, err
	}
	loc.Country = strings.ToUpper(loc.Country)
	return loc, found, nil
}

// checkSignIn applies the country rules to a sign-in call, before the
// credentials are read. A Go call, or a call with no address, passes.
func (g *geoPolicy) checkSignIn(ctx context.Context, c *Call) error {
	if g == nil || g.rules == nil || !c.Op.SignIn || c.Transport == TransportGo || c.Client.IP == "" {
		return nil
	}
	loc, found, err := g.locate(ctx, c.Client.IP)
	if err != nil {
		g.a.logger.Warn("auth: geo locator failed; the sign-in is not judged by country", "op", string(c.Op.ID), "error", err)
		return nil
	}
	var country string
	violated := false
	switch {
	case !found || loc.Country == "":
		violated = g.rules.DenyUnknown
	case slices.Contains(g.deny, loc.Country), len(g.allow) > 0 && !slices.Contains(g.allow, loc.Country):
		violated, country = true, loc.Country
	}
	if !violated {
		return nil
	}
	e := SecurityEvent{Kind: SecurityGeoCountry, Severity: SeverityWarn, Attrs: map[string]string{AttrCountry: country}}
	return g.apply(ctx, c, g.rules.Action, e, ErrGeoBlocked)
}

// checkTravel judges the sign-in a session is about to be created for.
func (g *geoPolicy) checkTravel(ctx context.Context, userID string, client Client) error {
	if g == nil || g.travel == nil || client.IP == "" {
		return nil
	}
	prior, found, err := g.history.PreviousSignIn(ctx, g.a, userID)
	if err != nil {
		g.a.logger.Warn("auth: sign-in history unavailable; impossible travel not checked", "user", userID, "error", err)
		return nil
	}
	if !found {
		return nil
	}
	here, ok1, err1 := g.locate(ctx, client.IP)
	there, ok2, err2 := g.locate(ctx, prior.IP)
	if err1 != nil || err2 != nil {
		g.a.logger.Warn("auth: geo locator failed; impossible travel not checked", "user", userID, "error", errors.Join(err1, err2))
		return nil
	}
	if !ok1 || !ok2 || !here.HasCoordinates || !there.HasCoordinates {
		return nil
	}
	km := greatCircleKm(here, there)
	if km < g.travel.MinDistanceKm {
		return nil
	}
	elapsed := g.a.now().Sub(prior.At)
	speed := math.Inf(1)
	if elapsed > 0 {
		speed = km / elapsed.Hours()
	}
	if speed <= g.travel.MaxSpeedKmh {
		return nil
	}
	e := SecurityEvent{Kind: SecurityImpossibleTravel, Severity: SeverityAlert, UserID: userID, IP: client.IP, Attrs: map[string]string{
		AttrCountry: here.Country, AttrPreviousCountry: there.Country,
		AttrDistanceKm: fmt.Sprintf("%.0f", km), AttrSpeedKmh: speedText(speed), AttrElapsed: elapsed.Round(time.Second).String(),
	}}
	call, _ := callOf(ctx)
	return g.apply(ctx, call, g.travel.Action, e, ErrImpossibleTravel)
}

// speedText renders a speed for an event; an instantaneous journey is "inf".
func speedText(v float64) string {
	if math.IsInf(v, 1) {
		return "inf"
	}
	return fmt.Sprintf("%.0f", v)
}

// apply carries out a violation's action and reports it to the stream. call
// may be nil (a Go call, or a session created outside an operation): a
// challenge then has nobody to ask, so it refuses like a block.
func (g *geoPolicy) apply(ctx context.Context, call *Call, action RateAction, e SecurityEvent, refusal error) error {
	return g.a.applyRiskAction(ctx, call, action, e, refusal)
}

// applyRiskAction is the shared tail of every risk decision (geo, IP
// reputation, bot and trial-abuse checks): block refuses with refusal, log
// lets the call through, challenge asks the RateChallenger. Whatever the
// action, exactly one event goes to the security stream. call may be nil.
func (a *Auth) applyRiskAction(ctx context.Context, call *Call, action RateAction, e SecurityEvent, refusal error) error {
	e = securityOfCall(call, e)
	var out error
	switch action {
	case RateLog:
		e.Outcome = RateOutcomeLogged
	case RateChallenge:
		if call == nil {
			e.Outcome, out = RateOutcomeBlocked, refusal
			break
		}
		if err := a.limiter.challenger.PassChallenge(ctx, call); err != nil {
			e.Outcome, out = RateOutcomeChallenged, err
		} else {
			e.Outcome = RateOutcomePassed
			e.Severity = SeverityInfo
		}
	default:
		e.Outcome, out = RateOutcomeBlocked, refusal
	}
	a.EmitSecurity(e)
	return out
}

// greatCircleKm is the haversine distance between two locations.
func greatCircleKm(a, b GeoLocation) float64 {
	rad := math.Pi / 180
	dLat := (b.Latitude - a.Latitude) * rad
	dLon := (b.Longitude - a.Longitude) * rad
	h := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(a.Latitude*rad)*math.Cos(b.Latitude*rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * earthRadiusKm * math.Asin(math.Min(1, math.Sqrt(h)))
}

// callKey carries the running *Call in the context of an operation, so the
// session creation it triggers can ask the RateChallenger about the same call.
type callKey struct{}

// callOf returns the operation call running in ctx.
func callOf(ctx context.Context) (*Call, bool) {
	c, ok := ctx.Value(callKey{}).(*Call)
	return c, ok
}
