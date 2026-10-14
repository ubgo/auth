package auth

// Escape hatches: better-auth's advanced.disableCSRFCheck and
// advanced.disableOriginCheck. Each turns off one check the library otherwise
// always runs, so each is opt-in, named for what it removes, and logged as a
// warning by New on every start while it is on: a switch that weakens the
// security of every request must not be something a deployment can forget it
// set.

// Start-up warnings New logs while an escape hatch is on. Constants so a test
// and an operator's log search match the exact text.
const (
	// WarnCSRFCheckOff is logged by New under WithoutCSRFCheck.
	//
	//ds:def id=core-warncsrfcheckoff-8vq3nk2w owner=@khanakia stability=stable
	WarnCSRFCheckOff = "auth: WithoutCSRFCheck is on: cookie-authenticated mutations are accepted from any origin (CSRF)"
	// WarnOriginCheckOff is logged by New under WithoutOriginCheck.
	//
	//ds:def id=core-warnorigincheckoff-3kd8wq5n owner=@khanakia stability=stable
	WarnOriginCheckOff = "auth: WithoutOriginCheck is on: every return and redirect URL is accepted (open redirect, token-bearing links to any host)"
	// WarnServerCallLimitsOff is logged by New under
	// WithoutServerCallRateLimits.
	//
	//ds:def id=core-warnservercalllimitsoff-4nd8qw2k owner=@khanakia stability=stable
	WarnServerCallLimitsOff = "auth: WithoutServerCallRateLimits is on: Go calls skip per-account rate limits (an app route that calls an operation is an unlimited guess channel)"
)

// WithoutCSRFCheck turns off the origin check that refuses a
// cookie-authenticated mutation from an untrusted origin, and the
// Sec-Fetch-Site check of WithFetchMetadata with it: better-auth's
// advanced.disableCSRFCheck. Off by default; New logs WarnCSRFCheckOff at
// every start while it is on.
//
// The attack it opens is cross-site request forgery: any page the user
// visits can POST to the auth routes and the browser attaches the session
// cookie, so another site can change the password (where no fresh sign-in is
// required), revoke sessions, unlink a provider, create an API key or sign
// the user out. Prefer the switches that keep the check: WithTrustedOrigins
// (patterns and custom schemes), WithTrustedOriginFunc, or bearer mode, which
// carries no cookie and is never origin-checked. Use this only behind
// another CSRF defence the app runs itself (a proxy that checks Origin, a
// synchronizer token), or in a test. authui's form pages keep their own
// origin check, which this does not reach.
//
//ds:def id=opt-withoutcsrfcheck-6tw2mz9k owner=@khanakia stability=stable
func WithoutCSRFCheck() Option { return func(s *settings) { s.noCSRFCheck = true } }

// WithoutOriginCheck turns off return-URL validation: TrustsReturnURL then
// accepts any target that is not empty and holds no line break or
// backslash, so every
// returnTo, errorTo, callbackURL and redirectTo is taken as given. It is
// better-auth's advanced.disableOriginCheck. Off by default; New logs
// WarnOriginCheckOff at every start while it is on. It does not touch the
// CSRF origin check (TrustsOrigin), which WithoutCSRFCheck controls.
//
// The risks it opens: an open redirect, where a link on the real domain
// sends the victim to a look-alike page, which phishing relies on; and,
// worse, a token-bearing link to any host: a flow that puts a token in the
// URL it was given (a password-reset redirectTo, a magic-link or
// verification callback) mails the victim a link to the attacker's site
// with a live token in it, which is account takeover on one click. Every
// legitimate target stays reachable with the check on, through
// WithTrustedOrigins (including "myapp://" schemes and wildcard subdomains),
// WithTrustedOriginFunc or WithLoopbackReturn. Line breaks and backslashes
// stay refused: they guard the Location header against injection and URL
// confusion, not where the browser may go.
//
//ds:def id=opt-withoutorigincheck-2nf7xq4d owner=@khanakia stability=stable
func WithoutOriginCheck() Option { return func(s *settings) { s.noOriginCheck = true } }

// WithoutServerCallRateLimits exempts direct Go calls (Transport
// TransportGo: no transport attached a request) from ByIdentifier and ByFunc rules too,
// so a server call is never counted at all: better-auth's rule that auth.api
// calls skip rate limiting. Go calls already skip ByIP rules, since they carry
// no address. Off by default; New logs WarnServerCallLimitsOff at every start
// while it is on. Calls through authhttp and every adapter are still counted.
//
// The risk it opens: an app route of its own that takes a password or a code
// from a browser and calls the operation from Go is then an unlimited guess
// channel against one account, which is exactly what the per-account rule
// exists to stop. Use it only when every Go call site is a trusted job (an
// import, a seed, a back-office tool), or put the app's own limiter in front
// of each route that forwards user input.
//
//ds:def id=opt-withoutservercallratelimits-7hq2xm5n owner=@khanakia stability=stable
func WithoutServerCallRateLimits() Option { return func(s *settings) { s.noServerCallLimits = true } }

// warnEscapes logs one warning per escape hatch that is on. New calls it
// once, after the instance is built, so the warning names a configuration
// that was accepted.
func (a *Auth) warnEscapes() {
	if a.noCSRFCheck {
		a.logger.Warn(WarnCSRFCheckOff)
	}
	if a.noOriginCheck {
		a.logger.Warn(WarnOriginCheckOff)
	}
	if a.limiter != nil && a.limiter.noServerCalls {
		a.logger.Warn(WarnServerCallLimitsOff)
	}
}
