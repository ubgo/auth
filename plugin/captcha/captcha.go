// Package captcha refuses chosen operations unless the request carries a
// captcha token a provider accepts, so a bot cannot sign up, sign in or ask for
// a reset link at the rate the rate rules allow a human to.
//
// The plugin is one operation hook. The client solves the challenge in the
// browser and sends the provider's token in the TokenHeader header; the hook
// reads it, asks the provider's siteverify endpoint once, and refuses the call
// before the operation runs when the token is missing, rejected or cannot be
// checked. Cloudflare Turnstile, Google reCAPTCHA (v2 and v3) and hCaptcha
// speak the same siteverify protocol and are built in; any other provider is a
// Verifier.
//
// A direct Go call has no headers and no browser, so it is never checked: the
// app's own code is not the bot the captcha is for. Every transport call —
// HTTP, GraphQL, an adapter — is.
package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
)

// PluginName is the plugin's permanent identity.
const PluginName = "captcha"

// TokenHeader is the request header the client sends the provider's token in.
// It is the header better-auth's clients already use, so a frontend written
// for one works against the other unchanged; WithHeader renames it.
//
//ds:def id=tokenheader-captcha-2k9fq3xa owner=@khanakia stability=stable
const TokenHeader = "X-Captcha-Response"

// AnnotationVerified is the auth.Call annotation the plugin sets once the
// call's token was accepted. A captcha token is single-use at the provider,
// so a call whose token already passed a rate challenge must not send it
// again to the operation guard, which would see it rejected as a replay; the
// guard reads this instead. The value is "true", never the token.
//
//ds:def id=annotationverified-captcha-6tq3mz8w owner=@khanakia stability=stable
const AnnotationVerified = "captcha.verified"

// annotationTrue is AnnotationVerified's value.
const annotationTrue = "true"

// DefaultTimeout bounds the siteverify call. Ten seconds is long enough for a
// provider having a slow day and short enough that a provider outage fails
// requests instead of holding every connection open until the client gives up.
//
//ds:def id=defaulttimeout-captcha-7mz2hq4e owner=@khanakia stability=stable
const DefaultTimeout = 10 * time.Second

// DefaultMinScore is the reCAPTCHA v3 score a token must reach. Google's own
// recommended starting point: 0.5 splits "likely a bot" from "likely human"
// on its 0 to 1 scale, and a lower value lets more bots through than it
// recovers humans.
//
//ds:def id=defaultminscore-captcha-3rp8wq5d owner=@khanakia stability=stable
const DefaultMinScore = 0.5

// Default protected operations: every way an anonymous request can create an
// account, prove a password, or make the app send a message. The ids are
// spelled out because their plugins live in other modules (password) or would
// make this plugin depend on every identifier plugin; the ones whose plugin
// is not registered are dropped at auth.New, so the default list is safe in
// any plugin set. Protect replaces it.
//
//ds:def id=defaultprotected-captcha-9vx4tn2c owner=@khanakia stability=stable
var DefaultProtected = []auth.EndpointID{
	"password.sign-up", "password.sign-in", "password.forgot", "password.reset",
	"email.send-code", "email.sign-in-code",
	"phone.send-code", "phone.sign-in",
	"magiclink.send",
}

// Errors. The first three carry stable codes a client checks for; the message
// of each is the same whatever the operation and whoever the account is.
var (
	// ErrMissing refuses a protected call that sent no token.
	ErrMissing = auth.NewError("captcha.missing", http.StatusBadRequest, "Complete the captcha and try again.")
	// ErrFailed refuses a token the provider rejected: expired, already
	// used, solved on another site, minted for another action, or scored
	// below the threshold. The client gets one answer for all of them so a
	// bot cannot learn which check it tripped.
	ErrFailed = auth.NewError("captcha.failed", http.StatusForbidden, "The captcha could not be verified. Try again.")
	// ErrUnavailable fails closed when the provider cannot be reached or
	// answers something that is not a verdict: an unreachable provider must
	// not become an open door.
	ErrUnavailable = auth.NewError("captcha.unavailable", http.StatusServiceUnavailable, "The captcha service is not available. Try again in a moment.")

	// ErrNoVerifier fails auth.New when New was given no Verifier: a captcha
	// plugin that cannot verify would refuse every protected call.
	ErrNoVerifier = errors.New("captcha: pass a Verifier such as captcha.Turnstile(secret)")
	// ErrNothingProtected fails auth.New when no protected operation is
	// registered: a captcha plugin that guards nothing is a configuration
	// mistake, usually a plugin list without the plugin it was meant for.
	ErrNothingProtected = errors.New("captcha: none of the protected operations is registered; pass captcha.Protect with the ids to guard")
	// ErrNoSecret fails the provider constructors' Validate when the secret
	// is empty, because every provider answers "invalid-input-secret" for it
	// and the symptom would be every sign-in failing in production.
	ErrNoSecret = errors.New("captcha: the provider secret key is empty")
)

// Verifier checks one token. It returns nil for a token the provider accepts,
// ErrFailed (or an error wrapping it) for one it rejects, and any other error
// when no verdict could be had; the plugin reports that as ErrUnavailable and
// refuses the call. remoteIP is the client address, "" when unknown, for
// providers that score it.
//
//ds:def id=verifier-captcha-5hw8rd7b owner=@khanakia stability=stable
type Verifier interface {
	Verify(ctx context.Context, token, remoteIP string) error
}

// VerifierFunc adapts a function to Verifier.
type VerifierFunc func(ctx context.Context, token, remoteIP string) error

// Verify calls f.
func (f VerifierFunc) Verify(ctx context.Context, token, remoteIP string) error {
	return f(ctx, token, remoteIP)
}

// Plugin is the captcha hook. Build it with New.
type Plugin struct {
	verifier Verifier
	header   string
	timeout  time.Duration
	protect  []auth.EndpointID
	explicit bool
	// patterns are ProtectPaths' route patterns, resolved to ids in
	// OperationHooks, when every operation is registered.
	patterns []string
	core     *auth.Auth
	// protected is the settled list: the explicit one, or the default list
	// narrowed to the operations the registered plugins provide.
	protected []auth.EndpointID
	// challengeOnly is ChallengeOnly: guard no operation always, only pass
	// the core's rate challenges.
	challengeOnly bool
}

// Option configures the plugin.
type Option func(*Plugin)

// Protect replaces DefaultProtected with the operations to guard. Unlike the
// default list, every id named here must be registered, so a typo fails
// auth.New (auth.ErrUnknownHookTarget) instead of leaving an operation open.
//
//ds:def id=protect-captcha-6bn3zf8k owner=@khanakia stability=stable
func Protect(ids ...auth.EndpointID) Option {
	return func(p *Plugin) { p.protect, p.explicit = slices.Clone(ids), true }
}

// ProtectPaths guards every operation whose route matches one of patterns,
// better-auth's endpoints option with wildcards: "*" matches within one path
// segment and "**" across segments, so "/password/*" guards
// /password/sign-in and /password/sign-up but not /oauth/google/start, and
// "/oauth/**" guards every OAuth route. A pattern with no wildcard is one
// exact route. Routes are the operation's own (Operation.Route, "/password/
// sign-in"), without authhttp's mount prefix.
//
// Like Protect it replaces DefaultProtected, and the two add up when both
// are given. The safety Protect has stays: a pattern that matches no
// registered operation fails auth.New with auth.ErrUnknownHookTarget naming
// the pattern, so a typo or a renamed route can never leave a form open in
// silence. It is matched once, at auth.New.
//
//ds:def id=protectpaths-captcha-5wq8kz3n owner=@khanakia stability=stable
func ProtectPaths(patterns ...string) Option {
	return func(p *Plugin) {
		if !p.explicit {
			p.protect = nil
		}
		p.patterns, p.explicit = append(p.patterns, patterns...), true
	}
}

// Wildcards of a ProtectPaths pattern.
const (
	// anySegments matches any run of characters, slashes included.
	anySegments = "**"
	// oneSegment matches any run of characters within one path segment.
	oneSegment = "*"
)

// patternRegexp compiles a ProtectPaths pattern into an anchored expression:
// "**" becomes ".*", "*" becomes "[^/]*", everything else is literal.
func patternRegexp(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i, part := range strings.Split(pattern, anySegments) {
		if i > 0 {
			b.WriteString(".*")
		}
		for j, lit := range strings.Split(part, oneSegment) {
			if j > 0 {
				b.WriteString("[^/]*")
			}
			b.WriteString(regexp.QuoteMeta(lit))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// MatchPath reports whether route matches a ProtectPaths pattern, for a page
// or a test that wants to know what a pattern guards before wiring it.
//
//ds:def id=matchpath-captcha-8nr2vx6q owner=@khanakia stability=stable
func MatchPath(pattern, route string) bool { return patternRegexp(pattern).MatchString(route) }

// ChallengeOnly makes the plugin guard no operation on every call and serve
// only as the core's rate challenger: a call is asked for a captcha when an
// auth.RateChallenge rule is over its limit, and never before. Without it
// the plugin does both, guarding its protected operations always and passing
// rate challenges anywhere. It cannot be combined with Protect or
// ProtectPaths, which would say the opposite.
//
//ds:def id=challengeonly-captcha-3wn8qk5v owner=@khanakia stability=stable
func ChallengeOnly() Option { return func(p *Plugin) { p.challengeOnly = true } }

// WithHeader renames the header the token arrives in, for a frontend that
// already sends it under another name.
func WithHeader(name string) Option { return func(p *Plugin) { p.header = name } }

// WithTimeout bounds each verification; see DefaultTimeout. A zero or negative
// value keeps the default, because a captcha with no timeout is a captcha that
// can hang every protected request.
func WithTimeout(d time.Duration) Option {
	return func(p *Plugin) {
		if d > 0 {
			p.timeout = d
		}
	}
}

var (
	_ auth.Validator       = (*Plugin)(nil)
	_ auth.Initializer     = (*Plugin)(nil)
	_ auth.OperationHooker = (*Plugin)(nil)
	_ auth.RateChallenger  = (*Plugin)(nil)
)

// New builds the plugin around v. auth.New fails with ErrNoVerifier for a nil
// v and with ErrNothingProtected when no protected operation exists.
func New(v Verifier, opts ...Option) *Plugin {
	p := &Plugin{verifier: v, header: TokenHeader, timeout: DefaultTimeout, protect: slices.Clone(DefaultProtected)}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Name identifies the plugin.
func (p *Plugin) Name() string { return PluginName }

// Validate refuses a plugin with no verifier, and asks a provider built here
// to check its own configuration.
func (p *Plugin) Validate(cfg *auth.Config) error {
	if p.verifier == nil {
		return ErrNoVerifier
	}
	if p.challengeOnly && p.explicit {
		return fmt.Errorf("captcha.ChallengeOnly: guards no operation always, and Protect or ProtectPaths asks it to; pass one or the other")
	}
	if v, ok := p.verifier.(auth.Validator); ok {
		return v.Validate(cfg)
	}
	return nil
}

// Init narrows the default list to the ids whose plugin is registered (an id
// is "<plugin>.<name>", so the prefix is the plugin) and refuses a plugin set
// in which none is: that is the "forgot the password plugin" mistake, and it
// must fail here, loudly, not guard nothing. An explicit list is kept whole
// and auth.New checks each id.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	if p.challengeOnly {
		p.protected = nil
		return nil
	}
	if p.explicit {
		// An empty Match would mean every operation, which is the opposite
		// of what Protect() with no ids reads as; refuse it like an empty
		// default list.
		if len(p.protect) == 0 && len(p.patterns) == 0 {
			return ErrNothingProtected
		}
		// An empty id or pattern is a slip (an unset variable), never a
		// choice; refused here, naming the option, before auth.New's
		// generic "hook names an operation that is not registered".
		if slices.Contains(p.protect, "") {
			return fmt.Errorf("%w: captcha.Protect: an operation id is empty", auth.ErrUnknownHookTarget)
		}
		if slices.Contains(p.patterns, "") {
			return fmt.Errorf("%w: captcha.ProtectPaths: a route pattern is empty", auth.ErrUnknownHookTarget)
		}
		p.protected = slices.Clone(p.protect)
		return nil
	}
	present := map[string]bool{}
	for _, reg := range a.Plugins() {
		present[reg.Name()] = true
	}
	p.protected = nil
	for _, id := range p.protect {
		if plugin, _, ok := strings.Cut(string(id), "."); ok && present[plugin] {
			p.protected = append(p.protected, id)
		}
	}
	if len(p.protected) == 0 {
		return ErrNothingProtected
	}
	return nil
}

// Protected lists the operations the plugin guards, settled at auth.New, for
// a page or a test that reports them.
func (p *Plugin) Protected() []auth.EndpointID { return slices.Clone(p.protected) }

// OperationHooks is the one hook: verify before the protected operations.
//
// auth.New asks for the hooks once every operation is registered, so the
// default list is narrowed here to the ids that exist (or were switched off
// by WithDisabledOperations): a plugin that is registered but, like a custom
// one reusing the name, lacks one of the operations does not fail New. When
// nothing would remain, the list is handed over whole so New refuses it with
// auth.ErrUnknownHookTarget rather than a hook with an empty Match, which
// would guard every operation.
//
//ds:def id=plugin-operationhooks-captcha-4qt7mw9n owner=@khanakia stability=stable
func (p *Plugin) OperationHooks() []auth.OperationHook {
	if p.challengeOnly {
		return nil
	}
	if len(p.patterns) > 0 {
		p.protected = append(p.protected, p.resolvePatterns()...)
	}
	if !p.explicit {
		known := map[auth.EndpointID]bool{}
		for _, id := range p.core.DisabledOperations() {
			known[id] = true
		}
		narrowed := make([]auth.EndpointID, 0, len(p.protected))
		for _, id := range p.protected {
			if _, ok := p.core.Operation(id); ok || known[id] {
				narrowed = append(narrowed, id)
			}
		}
		if len(narrowed) > 0 {
			p.protected = narrowed
		}
	}
	return []auth.OperationHook{{Match: slices.Clone(p.protected), Before: p.before}}
}

// resolvePatterns returns the ids whose route matches a ProtectPaths
// pattern, each once and not already listed. A pattern that matches nothing
// is returned as an id of its own: no operation has it, so auth.New refuses
// the hook with auth.ErrUnknownHookTarget and the pattern in the message,
// rather than wiring a guard that guards nothing.
func (p *Plugin) resolvePatterns() []auth.EndpointID {
	seen := map[auth.EndpointID]bool{}
	for _, id := range p.protected {
		seen[id] = true
	}
	var out []auth.EndpointID
	for _, pattern := range p.patterns {
		re := patternRegexp(pattern)
		matched := false
		for _, op := range p.core.Operations() {
			if !re.MatchString(op.Route()) {
				continue
			}
			matched = true
			if id := op.Info().ID; !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
		if !matched {
			out = append(out, auth.EndpointID(pattern))
		}
	}
	return out
}

// before is the check. A Go call is the app's own code and passes; a transport
// call passes only with a token the verifier accepts, and every other outcome
// is one of the three errors above.
func (p *Plugin) before(ctx context.Context, c *auth.Call) error {
	if c.Transport == auth.TransportGo || c.Annotation(AnnotationVerified) == annotationTrue {
		return nil
	}
	token := c.Header(p.header)
	if token == "" {
		return ErrMissing
	}
	return p.verify(ctx, c, token)
}

// PassChallenge is auth.RateChallenger: a call over an auth.RateChallenge
// rule passes with a token the verifier accepts. A Go call passes, as it
// does the operation guard; a call without a token is
// auth.ErrChallengeRequired (428), so the client knows to show the widget
// and send the call again; a rejected token is ErrFailed and an unreachable
// provider ErrUnavailable, as for a protected operation.
//
//ds:def id=passchallenge-captcha-7hm2wq4z owner=@khanakia stability=stable
func (p *Plugin) PassChallenge(ctx context.Context, c *auth.Call) error {
	if c.Transport == auth.TransportGo {
		return nil
	}
	token := c.Header(p.header)
	if token == "" {
		return auth.ErrChallengeRequired
	}
	return p.verify(ctx, c, token)
}

// verify checks one token within the timeout and maps the verdict to the
// plugin's errors.
func (p *Plugin) verify(ctx context.Context, c *auth.Call, token string) error {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	err := p.verifier.Verify(ctx, token, c.Client.IP)
	switch {
	case err == nil:
		c.Annotate(AnnotationVerified, annotationTrue)
		return nil
	case errors.Is(err, ErrFailed):
		return err
	default:
		c.Auth.Logger().Warn("captcha: verification unavailable", "op", c.Op.ID, "err", err)
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
}

// Siteverify endpoints of the built-in providers. Each takes a form POST of
// secret, response and remoteip and answers JSON with success, hostname,
// action, score and error-codes; WithEndpoint points at a mirror or a test
// server.
const (
	TurnstileEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	ReCAPTCHAEndpoint = "https://www.google.com/recaptcha/api/siteverify"
	HCaptchaEndpoint  = "https://api.hcaptcha.com/siteverify"
	// CaptchaFoxEndpoint speaks the hCaptcha-compatible siteverify protocol:
	// the same form fields, success and hostname in the verdict, no score.
	CaptchaFoxEndpoint = "https://api.captchafox.com/siteverify"
)

// Form field and JSON names of the siteverify protocol, shared by every
// built-in provider.
const (
	fieldSecret   = "secret"
	fieldResponse = "response"
	fieldRemoteIP = "remoteip"
	fieldSiteKey  = "sitekey"
)

// siteVerifyResponse is the verdict every provider returns. Score and Action
// are set by reCAPTCHA v3 and Turnstile; ErrorCodes are the provider's reasons
// and are logged, never sent to the client.
type siteVerifyResponse struct {
	Success    bool     `json:"success"`
	Hostname   string   `json:"hostname"`
	Action     string   `json:"action"`
	Score      *float64 `json:"score"`
	ErrorCodes []string `json:"error-codes"`
}

// SiteVerify is a Verifier over the siteverify protocol: Turnstile, reCAPTCHA,
// hCaptcha and CaptchaFox differ only in endpoint and in which optional fields
// they return. Build one with Turnstile, ReCAPTCHA, HCaptcha or CaptchaFox.
type SiteVerify struct {
	provider string
	endpoint string
	secret   string
	client   *http.Client
	// action is the expected action, "" to accept any.
	action string
	// hostnames are the sites a token may have been solved on, none to
	// accept any.
	hostnames []string
	// siteKey is sent to providers that bind a token to a site key, "" to
	// send none.
	siteKey string
	// minScore applies when the provider returns a score (reCAPTCHA v3,
	// Turnstile does not); a verdict without a score is judged by success.
	minScore float64
}

// ProviderOption configures a built-in provider.
type ProviderOption func(*SiteVerify)

// WithEndpoint replaces the provider's siteverify URL: a regional mirror, or
// a fake server in a test. It must be absolute.
func WithEndpoint(u string) ProviderOption { return func(s *SiteVerify) { s.endpoint = u } }

// WithHTTPClient replaces the client the verification uses, for a proxy or a
// test transport. The plugin's timeout still applies through the context.
func WithHTTPClient(c *http.Client) ProviderOption { return func(s *SiteVerify) { s.client = c } }

// WithExpectedAction rejects a token the widget minted for another action
// (reCAPTCHA v3 and Turnstile report it), so a token solved on the newsletter
// form cannot be replayed at sign-in.
func WithExpectedAction(action string) ProviderOption {
	return func(s *SiteVerify) { s.action = action }
}

// WithAllowedHostnames rejects a token solved on a site other than the ones
// listed, compared exactly against the hostname the provider reports.
func WithAllowedHostnames(hosts ...string) ProviderOption {
	return func(s *SiteVerify) { s.hostnames = slices.Clone(hosts) }
}

// WithSiteKey sends the site key with the verification, so the provider
// rejects a token solved under another key of the same account. hCaptcha and
// CaptchaFox support it; the others ignore the field.
func WithSiteKey(key string) ProviderOption { return func(s *SiteVerify) { s.siteKey = key } }

// WithMinScore sets the score a reCAPTCHA v3 token must reach; see
// DefaultMinScore. Out of the 0 to 1 range it keeps the default.
func WithMinScore(score float64) ProviderOption {
	return func(s *SiteVerify) {
		if score >= 0 && score <= 1 {
			s.minScore = score
		}
	}
}

func newSiteVerify(provider, endpoint, secret string, opts []ProviderOption) *SiteVerify {
	s := &SiteVerify{provider: provider, endpoint: endpoint, secret: secret, client: http.DefaultClient, minScore: DefaultMinScore}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Turnstile verifies Cloudflare Turnstile tokens with the site's secret key.
func Turnstile(secret string, opts ...ProviderOption) *SiteVerify {
	return newSiteVerify("turnstile", TurnstileEndpoint, secret, opts)
}

// ReCAPTCHA verifies Google reCAPTCHA tokens, v2 and v3, with the site's
// secret key. A v3 token carries a score and must reach WithMinScore; a v2
// token carries none and is judged by the provider's success flag.
func ReCAPTCHA(secret string, opts ...ProviderOption) *SiteVerify {
	return newSiteVerify("recaptcha", ReCAPTCHAEndpoint, secret, opts)
}

// HCaptcha verifies hCaptcha tokens with the site's secret key.
func HCaptcha(secret string, opts ...ProviderOption) *SiteVerify {
	return newSiteVerify("hcaptcha", HCaptchaEndpoint, secret, opts)
}

// CaptchaFox verifies CaptchaFox tokens with the site's secret key. The
// verdict carries no score, so a token is judged by success, hostname and the
// site key.
func CaptchaFox(secret string, opts ...ProviderOption) *SiteVerify {
	return newSiteVerify("captchafox", CaptchaFoxEndpoint, secret, opts)
}

// Provider names the built-in provider, for logs and pages.
func (s *SiteVerify) Provider() string { return s.provider }

// Validate refuses an empty secret and an endpoint that is not an absolute
// URL, at auth.New rather than at the first sign-in.
func (s *SiteVerify) Validate(*auth.Config) error {
	if s.secret == "" {
		return fmt.Errorf("%w (%s)", ErrNoSecret, s.provider)
	}
	if u, err := url.Parse(s.endpoint); err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("captcha.WithEndpoint: %s endpoint %q is not an absolute URL", s.provider, s.endpoint)
	}
	return nil
}

// Verify posts the token to the siteverify endpoint and applies the hostname,
// action and score checks to the verdict. Transport and decoding failures are
// returned as they are, for the plugin to fail closed on; a rejection is
// ErrFailed with the provider's reason wrapped for the log.
func (s *SiteVerify) Verify(ctx context.Context, token, remoteIP string) error {
	form := url.Values{fieldSecret: {s.secret}, fieldResponse: {token}}
	if remoteIP != "" {
		form.Set(fieldRemoteIP, remoteIP)
	}
	if s.siteKey != "" {
		form.Set(fieldSiteKey, s.siteKey)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("captcha: %s request: %w", s.provider, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("captcha: %s: %w", s.provider, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("captcha: %s answered %d", s.provider, resp.StatusCode)
	}
	var v siteVerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return fmt.Errorf("captcha: %s verdict: %w", s.provider, err)
	}
	return s.judge(v)
}

// judge turns a verdict into nil or ErrFailed. Every rejection reason is one
// error for the client; the reason rides along in the wrapped text for the
// log.
func (s *SiteVerify) judge(v siteVerifyResponse) error {
	switch {
	case !v.Success:
		return fmt.Errorf("%w: %s rejected the token (%s)", ErrFailed, s.provider, strings.Join(v.ErrorCodes, ", "))
	case s.action != "" && v.Action != s.action:
		return fmt.Errorf("%w: %s token action %q, expected %q", ErrFailed, s.provider, v.Action, s.action)
	case len(s.hostnames) > 0 && !slices.Contains(s.hostnames, v.Hostname):
		return fmt.Errorf("%w: %s token solved on %q", ErrFailed, s.provider, v.Hostname)
	case v.Score != nil && *v.Score < s.minScore:
		return fmt.Errorf("%w: %s score %.2f below %.2f", ErrFailed, s.provider, *v.Score, s.minScore)
	}
	return nil
}
