// Package magiclink signs users in with a single-use link sent to one of their
// identifiers, usually an email address.
//
// It knows no mail and no SMS: it asks the core to deliver to whichever plugin
// owns the identifier's kind, so it works with email, phone, or a kind a third
// plugin adds. A link signs in only the verified owner of the identifier; with
// SignUp it also creates an account for an identifier nobody has verified,
// whose control the click has just proven.
package magiclink

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

// PluginName is the plugin's permanent identity.
const PluginName = "magiclink"

// Operation ids, exported so a hook or a rate rule can name them. They are
// wire names, stable across releases.
const (
	EndpointSend   auth.EndpointID = "magiclink.send"
	EndpointSignIn auth.EndpointID = "magiclink.sign-in"
	// EndpointVerify is the GET sign-in VerifyByGET adds.
	EndpointVerify auth.EndpointID = "magiclink.verify"
)

// PurposeSignIn is the verification purpose of a link. Its Identifier is
// "<kind>:<normalized value>": the link is bound to the identifier it was
// sent to, not to an account, because the account may not exist yet. Its
// Meta is the tenant (auth.WithScope) the link was sent in, or "", followed by
// metaSeparator and the new user's name when the request gave one.
//
//ds:def id=purposesignin-9w1k7l0e owner=@khanakia stability=stable
const PurposeSignIn auth.Purpose = "magiclink.sign-in"

// identifierSeparator joins kind and value in a token's Identifier. Kind names
// match auth.KindNamePattern, which has no colon.
const identifierSeparator = ":"

// metaSeparator joins the tenant and the new user's name in a token's Meta,
// as "<scope>\x1f<name>". The unit separator cannot be typed into a name
// field, and a token issued before names were carried has no separator, so
// its whole Meta is still the tenant.
const metaSeparator = "\x1f"

// Defaults and limits.
const (
	// DefaultTTL is short: a sign-in link is used within minutes or not at
	// all, and a long one is only useful to whoever reads the mailbox later.
	//ds:def id=defaultttl-z8p2fp62 owner=@khanakia stability=stable
	DefaultTTL = 15 * time.Minute
	// DefaultPage is the app page a link opens; it POSTs the token to
	// magiclink.sign-in. A GET that signed in would be spent by every mail
	// scanner that previews links.
	//ds:def id=defaultpage-uke973qb owner=@khanakia stability=stable
	DefaultPage = "/magic-link"
	// sendLimit links per identifier per sendWindow: a retry for a slow
	// inbox, too few to flood a stranger's.
	//ds:def id=sendlimit-6v7fhkmf owner=@khanakia stability=stable
	sendLimit = 3
	//ds:def id=sendwindow-d5jquxvk owner=@khanakia stability=stable
	sendWindow = 15 * time.Minute
	// sendIPLimit links per IP per sendIPWindow bounds one client cycling
	// through many identifiers; an office behind one NAT still fits.
	//ds:def id=sendiplimit-f3us3sne owner=@khanakia stability=stable
	sendIPLimit = 20
	//ds:def id=sendipwindow-usu2f57p owner=@khanakia stability=stable
	sendIPWindow = time.Hour
)

// Configuration errors auth.New returns, so a setup that could never send a
// link fails at start rather than at the first sign-in.
var (
	ErrNoKinds  = errors.New("magiclink: no identifier kind can receive a link; add a Verifiable kind whose plugin delivers, such as email")
	ErrNoBase   = errors.New("magiclink: links need auth.WithBaseURL or magiclink.Links")
	ErrBadKinds = errors.New("magiclink: a kind given to Kinds must be registered, sign-in capable, verifiable and owned by a plugin that delivers")
	// ErrCallbackInvalid refuses a callbackURL, newUserCallbackURL or
	// errorCallbackURL that is not a page of this site or of a trusted
	// origin (auth.Auth.TrustsReturnURL), at send and at verify, so the GET
	// route is never an open redirect.
	//ds:def id=magiclink-errcallbackinvalid-7tq2mw5x owner=@khanakia stability=stable
	ErrCallbackInvalid = auth.NewError("magiclink.callback_invalid", http.StatusBadRequest, "This page cannot be opened after signing in.")
)

// DefaultMountPrefix is where VerifyByGET's default link assumes the auth
// handler is mounted, as the oauth plugin's default callback does.
//
//ds:def id=magiclink-defaultmountprefix-3nw8kq6v owner=@khanakia stability=stable
const DefaultMountPrefix = "/auth"

// The GET route and the query parameters of its link.
const (
	verifyPath           = "/verify"
	paramToken           = "token"
	paramCallback        = "callbackURL"
	paramNewUserCallback = "newUserCallbackURL"
	paramErrorCallback   = "errorCallbackURL"
)

// Plugin is the magic-link sign-in method. Build it with New: the zero value
// has no TTL and no operations.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs auth.OptionErrors
	kinds   []auth.IdentifierKindName
	signUp  bool
	ttl     time.Duration
	// perID and perIP are the send limits; the defaults are the constants
	// above, each option replaces one.
	perID, perIP limit
	links        func(t auth.Token) string
	// customLinks is set by Links: the app builds every link, VerifyByGET's
	// included. getVerify serves the GET route.
	customLinks bool
	getVerify   bool
	// genToken (GenerateToken) makes every link's token instead of the core.
	genToken TokenGenerator
	core     *auth.Auth

	send   *auth.Op[SendRequest, auth.Done]
	signIn *auth.Op[SignInRequest, SignInResult]
	verify *auth.Op[VerifyRequest, SignInResult]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin; options are applied in order by New.
type Option func(*Plugin)

// Kinds limits links to these identifier kinds. By default every registered
// kind that can sign in and has a verification flow accepts links.
//
//ds:def id=kinds-hrmvt2ay
func Kinds(kinds ...auth.IdentifierKindName) Option { return func(p *Plugin) { p.kinds = kinds } }

// SignUp lets a link create an account for an identifier nobody has
// verified. Without it, a link to an unknown identifier is not sent at all,
// and the answer is the same either way.
func SignUp() Option { return func(p *Plugin) { p.signUp = true } }

// WithTTL overrides DefaultTTL, how long a link works.
func WithTTL(d time.Duration) Option { return func(p *Plugin) { p.ttl = d } }

// WithSendLimit replaces the default of 3 links per identifier per 15
// minutes. Every link is a mail or a text to somebody, so this is what keeps
// the route from flooding an inbox.
func WithSendLimit(n int, window time.Duration) Option {
	return func(p *Plugin) { p.perID = limit{n, window} }
}

// WithIPLimit replaces the default of 20 links per IP per hour, which bounds
// one client cycling through many identifiers; raise it behind a shared NAT.
func WithIPLimit(n int, window time.Duration) Option {
	return func(p *Plugin) { p.perIP = limit{n, window} }
}

// limit is one rate rule's numbers.
type limit struct {
	n      int
	window time.Duration
}

// check refuses a rule that could not count, under the option that set it,
// before the core's generic rate check would refuse it without that name.
func (l limit) check(option string) error {
	if l.n < 1 || l.window <= 0 {
		return fmt.Errorf("%w: magiclink.%s(%d, %v): the limit and the window must both be positive",
			auth.ErrBadOperation, option, l.n, l.window)
	}
	return nil
}

// Links builds the URL a message carries, for an app whose sign-in page is
// not DefaultPage. The page must POST the token; a GET must not spend it,
// unless the app chose VerifyByGET and its risk.
//
//ds:def id=links-erc7vw4u
func Links(fn func(t auth.Token) string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("magiclink.Links", fn) {
			return
		}
		p.links, p.customLinks = fn, true
	}
}

// VerifyByGET adds a GET sign-in: the link in the message is
// BaseURL + DefaultMountPrefix + "/magiclink/verify?token=…" with the send
// request's callbackURL, newUserCallbackURL and errorCallbackURL, and that
// GET spends the token, signs in and redirects: to newUserCallbackURL when
// the link created the account (SignUp), else to callbackURL, and on a bad
// link to errorCallbackURL (or callbackURL) with ?error=<code>. Without a
// callbackURL it answers JSON like POST sign-in. Links still overrides the
// link.
//
// Off by default, and the risk is why: a GET spends the token, so a mail
// scanner or a chat preview that fetches the URL signs in itself and the
// person then gets "this link has expired"; and a GET sign-in cannot be
// origin-checked, so a link to the attacker's own account signs a victim
// into it (login CSRF), which auth.WithFetchMetadata, judging mutations
// only, does not cover. The default page, which POSTs the token, has
// neither problem. Every callback must pass auth.Auth.TrustsReturnURL.
//
//ds:def id=magiclink-verifybyget-5kr8nw2q owner=@khanakia stability=stable
func VerifyByGET() Option { return func(p *Plugin) { p.getVerify = true } }

var (
	_ auth.SignInMethod      = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.RateLimiter       = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
)

// New builds the plugin. With no options, every sign-in kind that can be
// verified and delivered to accepts links, and a link never creates an account.
func New(opts ...Option) *Plugin {
	p := &Plugin{ttl: DefaultTTL, perID: limit{sendLimit, sendWindow}, perIP: limit{sendIPLimit, sendIPWindow}}
	for _, o := range opts {
		o(p)
	}
	p.send = auth.Define(auth.OpInfo{ID: EndpointSend, Kind: auth.Mutation, Require: auth.Public, Path: "/send"}, p.doSend)
	p.signIn = auth.Define(auth.OpInfo{ID: EndpointSignIn, Kind: auth.Mutation, Require: auth.Public, Path: "/sign-in", SignIn: true}, p.doSignIn)
	p.verify = auth.Define(auth.OpInfo{ID: EndpointVerify, Kind: auth.Query, Require: auth.Public, Path: verifyPath, SignIn: true}, p.doVerify)
	return p
}

// Name returns PluginName, the key the core registers this plugin under.
func (p *Plugin) Name() string { return PluginName }

// SignsIn reports that a link is a way in, so an app with email and magic
// links and no password passes the core's "someone can sign in" check.
func (p *Plugin) SignsIn() bool { return true }

// Operations lists send and sign-in; both are public, since the link is the
// proof of identity.
func (p *Plugin) Operations() []auth.Operation {
	if p.getVerify {
		return []auth.Operation{p.send, p.signIn, p.verify}
	}
	return []auth.Operation{p.send, p.signIn}
}

// RateLimits bounds links per identifier and per IP, so the send endpoint
// cannot flood an inbox or be used to spam many.
func (p *Plugin) RateLimits() []auth.RateRule {
	return []auth.RateRule{
		{Match: EndpointSend, Key: auth.ByIdentifier, Limit: p.perID.n, Window: p.perID.window},
		{Match: EndpointSend, Key: auth.ByIP, Limit: p.perIP.n, Window: p.perIP.window},
	}
}

// usable reports whether kind k can carry a sign-in link.
func usable(k auth.IdentifierKind) bool { return k.CanLogin && k.Verifiable }

// Validate refuses a configuration with no kind that can carry a link, and a
// rate limit that could not count.
func (p *Plugin) Validate(c *auth.Config) error {
	if err := p.perID.check("WithSendLimit"); err != nil {
		return err
	}
	if err := p.perIP.check("WithIPLimit"); err != nil {
		return err
	}
	if p.links == nil && c.BaseURL == "" {
		return ErrNoBase
	}
	if len(p.kinds) > 0 {
		for _, name := range p.kinds {
			if k, ok := c.Identifier(name); !ok || !usable(k) {
				return ErrBadKinds
			}
		}
		return nil
	}
	for _, k := range c.Identifiers {
		if usable(k) {
			return nil
		}
	}
	return ErrNoKinds
}

// Init fills the default kinds and link, and refuses a kind whose plugin
// cannot deliver. Validate cannot see that: the configuration lists kinds, not
// the plugins behind them.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	can := deliverable(a)
	if len(p.kinds) == 0 {
		for _, k := range a.Config().Identifiers {
			if usable(k) && can[k.Name] {
				p.kinds = append(p.kinds, k.Name)
			}
		}
		if len(p.kinds) == 0 {
			return ErrNoKinds
		}
	}
	for _, k := range p.kinds {
		if !can[k] {
			return ErrBadKinds
		}
	}
	if p.links == nil {
		base := strings.TrimSuffix(a.Config().BaseURL, "/")
		p.links = func(t auth.Token) string { return base + DefaultPage + "?token=" + url.QueryEscape(t.Reveal()) }
	}
	return nil
}

// deliverable returns the kinds whose plugin is an auth.Deliverer. The core
// requires one only for recovery kinds, so a sign-in kind may lack it; a link
// to such a kind fails in Deliver, but only after the owner lookup, so the
// error would tell a stranger which identifiers have accounts.
func deliverable(a *auth.Auth) map[auth.IdentifierKindName]bool {
	out := map[auth.IdentifierKindName]bool{}
	for _, pl := range a.Plugins() {
		prov, ok := pl.(auth.IdentifierProvider)
		if !ok {
			continue
		}
		if _, ok := pl.(auth.Deliverer); !ok {
			continue
		}
		for _, k := range prov.Identifiers() {
			out[k.Name] = true
		}
	}
	return out
}

// SendRequest names where the link goes: any sign-in identifier, as typed;
// its kind is detected.
//
//ds:def id=sendrequest-gddp52ca
type SendRequest struct {
	Identifier string `json:"identifier"`
	// Name is the display name for the account the link creates (SignUp);
	// it travels in the token and is ignored when the identifier has an owner.
	Name string `json:"name,omitempty"`
	// Metadata travels to the delivering plugin's sender with the link (an
	// invite id, a page to return to) and is not stored. At most
	// email.MaxMetadataEntries entries of email.MaxMetadataLength bytes.
	Metadata map[string]string `json:"metadata,omitempty"`
	// CallbackURL, NewUserCallbackURL and ErrorCallbackURL are where the GET
	// sign-in (VerifyByGET) lands: after a sign-in, after an account was
	// created, after a failure. They travel in the link, are refused with
	// ErrCallbackInvalid unless auth.Auth.TrustsReturnURL accepts them, and
	// are ignored without VerifyByGET or with Links.
	CallbackURL        string `json:"callbackURL,omitempty"`
	NewUserCallbackURL string `json:"newUserCallbackURL,omitempty"`
	ErrorCallbackURL   string `json:"errorCallbackURL,omitempty"`
}

// VerifyRequest is the query of the GET sign-in (VerifyByGET): the token
// and the pages SendRequest named.
type VerifyRequest struct {
	Token              auth.WireToken `json:"token"`
	CallbackURL        string         `json:"callbackURL,omitempty"`
	NewUserCallbackURL string         `json:"newUserCallbackURL,omitempty"`
	ErrorCallbackURL   string         `json:"errorCallbackURL,omitempty"`
}

// RateIdentifier counts links per identifier, folded like the email
// normalizer so case changes do not reset the limit.
func (r SendRequest) RateIdentifier() string { return strings.ToLower(strings.TrimSpace(r.Identifier)) }

// SignInRequest carries the token from the link, which the page POSTs.
type SignInRequest struct {
	Token auth.WireToken `json:"token"`
}

// SignInResult is the output of sign-in. Token is for Go callers and bearer
// transports, never encoded into JSON.
//
//ds:def id=signinresult-pzyseqwp
type SignInResult struct {
	User auth.UserView `json:"user"`
	// Created is true when the link created the account (SignUp).
	Created              bool       `json:"created"`
	SecondFactorRequired bool       `json:"secondFactorRequired"`
	Token                auth.Token `json:"-"`
}

// Send delivers a sign-in link when the identifier may receive one, and
// answers the same when it may not.
//
//ds:def id=plugin-send-hhu67e5t
func (p *Plugin) Send(ctx context.Context, identifier string) error {
	_, err := p.send.Call(ctx, SendRequest{Identifier: identifier})
	return err
}

// SendAs is Send with the display name a new account gets (SignUp); the name
// is ignored when the identifier already has an owner.
func (p *Plugin) SendAs(ctx context.Context, identifier, name string) error {
	_, err := p.send.Call(ctx, SendRequest{Identifier: identifier, Name: name})
	return err
}

// SendWithMetadata is Send with metadata the sender receives beside the
// link; see SendRequest.Metadata.
func (p *Plugin) SendWithMetadata(ctx context.Context, identifier string, metadata map[string]string) error {
	_, err := p.send.Call(ctx, SendRequest{Identifier: identifier, Metadata: metadata})
	return err
}

// SendWith is Send with the whole request: the display name, metadata and
// the GET sign-in's pages (VerifyByGET).
func (p *Plugin) SendWith(ctx context.Context, in SendRequest) error {
	_, err := p.send.Call(ctx, in)
	return err
}

// SignIn spends a link's token and starts a session for the identifier's
// verified owner, or creates one with SignUp.
//
//ds:def id=plugin-signin-5g4s8hte
func (p *Plugin) SignIn(ctx context.Context, t auth.Token) (SignInResult, error) {
	return p.signIn.Call(ctx, SignInRequest{Token: t.Wire()})
}

func (p *Plugin) allowed(kind auth.IdentifierKindName) bool {
	for _, k := range p.kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// doSend answers the same for every input: a link is sent to a verified
// owner's identifier, or, with SignUp, to an identifier nobody has verified;
// otherwise nothing is sent. The link goes to the value typed, normalized, and
// never to an unverified row's account.
func (p *Plugin) doSend(ctx context.Context, c *auth.Call, in SendRequest) (auth.Done, error) {
	if err := email.CheckMetadata(in.Metadata); err != nil {
		return auth.Done{}, err
	}
	if err := p.checkCallbacks(c.Auth, in.CallbackURL, in.NewUserCallbackURL, in.ErrorCallbackURL); err != nil {
		return auth.Done{}, err
	}
	done := auth.Done{OK: true}
	kind, value, err := c.Auth.DetectKind(in.Identifier)
	if err != nil || !p.allowed(kind) {
		return done, nil
	}
	_, err = c.Auth.FindIdentity(ctx, kind, value, true)
	switch {
	case errors.Is(err, auth.ErrIdentityNotFound):
		if !p.signUp {
			return done, nil
		}
	case err != nil:
		return auth.Done{}, err
	}
	// The tenant is part of the link: the click is refused in another one.
	scope, _ := auth.ScopeFrom(ctx)
	meta := scope
	if in.Name != "" {
		meta += metaSeparator + in.Name
	}
	tok, err := p.issue(ctx, c.Auth, string(kind)+identifierSeparator+value, value, meta)
	if err != nil {
		return auth.Done{}, err
	}
	to := auth.Identity{Kind: kind, Value: value}
	return done, c.Auth.Deliver(ctx, to, auth.Message{Purpose: auth.PurposeSignInLink, Link: p.linkFor(tok, in), Metadata: in.Metadata})
}

// checkCallbacks refuses any non-empty callback TrustsReturnURL does not
// accept. It depends on the input only, so the refusal says nothing about
// the identifier.
func (p *Plugin) checkCallbacks(a *auth.Auth, urls ...string) error {
	for _, u := range urls {
		if u != "" && !a.TrustsReturnURL(u) {
			return ErrCallbackInvalid
		}
	}
	return nil
}

// linkFor is the link a message carries: the app's (Links) or the default
// page's, or, under VerifyByGET, the GET route with the request's callbacks.
func (p *Plugin) linkFor(t auth.Token, in SendRequest) string {
	if !p.getVerify || p.customLinks {
		return p.links(t)
	}
	q := url.Values{paramToken: {t.Reveal()}}
	for name, v := range map[string]string{paramCallback: in.CallbackURL, paramNewUserCallback: in.NewUserCallbackURL, paramErrorCallback: in.ErrorCallbackURL} {
		if v != "" {
			q.Set(name, v)
		}
	}
	return strings.TrimSuffix(p.core.Config().BaseURL, "/") + DefaultMountPrefix + "/" + PluginName + verifyPath + "?" + q.Encode()
}

// doVerify is sign-in over GET: the callbacks are checked before the token
// is touched (a bad one spends nothing), a failure redirects to the error
// page with the code, and a success redirects to the new-user page when the
// link created the account, else to callbackURL.
func (p *Plugin) doVerify(ctx context.Context, c *auth.Call, in VerifyRequest) (SignInResult, error) {
	// auth.WithErrorURL's page before the check, so a callback the app does
	// not trust lands there too rather than answering JSON to a browser.
	c.RedirectOnError("")
	if err := p.checkCallbacks(c.Auth, in.CallbackURL, in.NewUserCallbackURL, in.ErrorCallbackURL); err != nil {
		return SignInResult{}, err
	}
	// With neither page named, RedirectOnError falls back to
	// auth.WithErrorURL, and without that the failure answers JSON.
	c.RedirectOnError(cmp.Or(in.ErrorCallbackURL, in.CallbackURL))
	out, err := p.doSignIn(ctx, c, SignInRequest{Token: in.Token})
	if err != nil {
		return SignInResult{}, err
	}
	target := in.CallbackURL
	if out.Created && in.NewUserCallbackURL != "" {
		target = in.NewUserCallbackURL
	}
	if target != "" {
		c.Effects.Redirect(target)
	}
	return out, nil
}

// doSignIn spends the token. The verified owner of the identifier is signed
// in; with SignUp and no verified owner, a user is created whose identifier
// is verified by this very click. A link is one factor — control of a
// mailbox — so a user with two-factor still gets a pending session.
func (p *Plugin) doSignIn(ctx context.Context, c *auth.Call, in SignInRequest) (SignInResult, error) {
	v, err := c.Auth.ConsumeVerification(ctx, PurposeSignIn, in.Token.Token())
	if err != nil {
		return SignInResult{}, err
	}
	kindName, value, ok := strings.Cut(v.Identifier, identifierSeparator)
	if !ok {
		return SignInResult{}, auth.ErrTokenInvalid
	}
	kind := auth.IdentifierKindName(kindName)
	// Meta starts with the tenant the link was sent in, or "". A click in another
	// tenant is refused; a click with no tenant in the request uses the
	// link's own.
	scope, name, _ := strings.Cut(v.Meta, metaSeparator)
	if scope != "" {
		if s, ok := auth.ScopeFrom(ctx); ok && s != scope {
			return SignInResult{}, auth.ErrTokenInvalid
		}
		ctx = auth.WithScope(ctx, scope)
	}
	var create *auth.NewUser
	if p.signUp {
		create = &auth.NewUser{Name: name}
	}
	r, err := c.SignInProvenAs(ctx, kind, value, create)
	if errors.Is(err, auth.ErrIdentityNotFound) {
		// The owner went away after the link was sent: the same answer as a
		// spent link, so it reveals nothing.
		return SignInResult{}, auth.ErrTokenInvalid
	}
	if err != nil {
		return SignInResult{}, err
	}
	return SignInResult{User: auth.ViewOf(r.User), Created: r.Created, Token: r.Token, SecondFactorRequired: r.Session.SecondFactorPending}, nil
}
