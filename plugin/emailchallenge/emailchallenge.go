// Package emailchallenge signs users in without a password by one challenge
// that a link and a code both complete, and that always signs in the browser
// that asked, never the one that opened the mail: better-auth-email-challenge.
//
// A magic link signs in whichever browser opens it, which is the wrong one
// when the mail is read on a phone and the sign-in started on a laptop. Here
// the browser that starts a challenge keeps a poll token (a cookie, and in
// the answer for a client without cookies), the mail carries an approval link
// and a code, and:
//
//   - opening the link on another device only shows what is being approved
//     (context, a GET that changes nothing), and approving is a POST, so a
//     mail scanner that fetches every link approves nothing;
//   - opening it in the browser that holds the poll token approves at once,
//     because only that browser can hold it;
//   - the approval never creates a session: the poll does, for the holder of
//     the poll token, and the conditional delete that spends the challenge
//     lets exactly one poll through;
//   - the code is typed in the asking browser and checked against that
//     challenge only, through the core's attempt-counted codes.
//
// Every secret is stored as a hash. Like magiclink, it knows no mail: it asks
// the core to deliver to whichever plugin owns the identifier's kind.
package emailchallenge

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity and route prefix.
const PluginName = "emailchallenge"

// Operation ids, stable wire names a hook or a rate rule can name.
const (
	EndpointStart     auth.EndpointID = "emailchallenge.start"
	EndpointPoll      auth.EndpointID = "emailchallenge.poll"
	EndpointVerifyOTP auth.EndpointID = "emailchallenge.verify-otp"
	EndpointContext   auth.EndpointID = "emailchallenge.context"
	EndpointApprove   auth.EndpointID = "emailchallenge.approve"
)

// Message and code purposes. PurposeSignIn is the message the delivering
// plugin sends (its link and code); PurposeOTP is the core code checked
// against one challenge id.
const (
	PurposeSignIn auth.Purpose = "emailchallenge.sign_in"
	PurposeOTP    auth.Purpose = "emailchallenge.otp"
)

// CookieName is the plugin cookie that holds the poll token in the browser
// that started the challenge (authhttp names it __Host-auth_email_challenge).
const CookieName = "email_challenge"

// Defaults, better-auth-email-challenge's own.
const (
	// DefaultTTL is how long a challenge lives: five minutes, as a magic
	// link's, so an intercepted mail is useful for minutes only.
	// ds:def id=defaultttl-55ds4pcc owner=@khanakia stability=stable
	DefaultTTL = 5 * time.Minute
	// DefaultMaxAttempts wrong codes spend a challenge's code.
	DefaultMaxAttempts = 3
	// DefaultPage is the app page the link opens: it calls context with the
	// token and, when asked to confirm, POSTs approve.
	DefaultPage = "/email-challenge"
)

// Rate limits. Start is a mail to somebody, so it is bounded per identifier
// and per IP like magiclink's send; approve and verify-otp are guesses at a
// secret; poll and context are cheap reads a page repeats every second or
// two.
const (
	startLimit   = 3
	startWindow  = 15 * time.Minute
	startIPLimit = 20
	startIPWin   = time.Hour
	guessLimit   = 10
	guessWindow  = 15 * time.Minute
	pollLimit    = 120
	pollWindow   = time.Minute
)

// LinkMode chooses what a click on another device may do.
type LinkMode string

// The link modes. CrossDevice (the default) lets another device approve
// after an explicit POST; SameDevice refuses every click that does not come
// from the browser that asked, so only a same-browser click approves.
const (
	CrossDevice LinkMode = "cross-device"
	SameDevice  LinkMode = "same-device"
)

// Status is a challenge's state in the table. A completed challenge is
// deleted, so there is no consumed state.
type Status string

// The stored states.
const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
)

// State is what context and poll report; it adds the states a row cannot
// have (invalid, wrong-browser, completed).
type State string

// The reported states, better-auth-email-challenge's names.
const (
	StateInvalid           State = "invalid"
	StateNeedsConfirmation State = "needs-confirmation"
	StateApproved          State = "approved"
	StateWrongBrowser      State = "wrong-browser"
	StatePending           State = "pending"
	StateCompleted         State = "completed"
	StateExpired           State = "expired"
)

// The table: one row per open challenge, deleted when completed, swept when
// expired. No foreign key (ADR-0002) and no user id: the challenge is about
// an identifier, whose account may not exist yet.
const (
	TableNameChallenge  = "auth_email_challenge"
	TableAliasChallenge = "ech"

	ColID           = "id"
	ColIdentifier   = "identifier"
	ColApprovalHash = "approval_hash"
	ColBindingHash  = "binding_hash"
	ColStatus       = "status"
	ColName         = "name"
	ColScope        = "scope"
	ColIP           = "ip"
	ColUserAgent    = "user_agent"
	ColExpiresAt    = "expires_at"
	ColApprovedAt   = "approved_at"
	ColCreatedAt    = "created_at"

	migrationName = "0001_email_challenge"
	idPrefix      = "ech"
	// identifierSeparator joins kind and value in ColIdentifier; kind names
	// have no colon (auth.KindNamePattern).
	identifierSeparator = ":"
)

// TableChallenge and its typed columns, for an app that reads them.
var (
	TableChallenge = sqlb.Table{Name: TableNameChallenge, Alias: TableAliasChallenge}

	ChallengeID         = sqlb.Col[string](TableChallenge, ColID)
	ChallengeIdentifier = sqlb.Col[string](TableChallenge, ColIdentifier)
	ChallengeApproval   = sqlb.Col[[]byte](TableChallenge, ColApprovalHash)
	ChallengeBinding    = sqlb.Col[[]byte](TableChallenge, ColBindingHash)
	ChallengeStatus     = sqlb.Col[Status](TableChallenge, ColStatus)
	ChallengeName       = sqlb.Col[string](TableChallenge, ColName)
	ChallengeScope      = sqlb.Col[string](TableChallenge, ColScope)
	ChallengeIP         = sqlb.Col[string](TableChallenge, ColIP)
	ChallengeUserAgent  = sqlb.Col[string](TableChallenge, ColUserAgent)
	ChallengeExpiresAt  = sqlb.Col[time.Time](TableChallenge, ColExpiresAt)
	ChallengeApprovedAt = sqlb.Col[*time.Time](TableChallenge, ColApprovedAt)
	ChallengeCreatedAt  = sqlb.Col[time.Time](TableChallenge, ColCreatedAt)
)

// Errors. ErrInvalid covers an unknown, expired, spent and foreign
// challenge alike, so no answer says which.
var (
	ErrInvalid      = auth.NewError("emailchallenge.invalid", http.StatusBadRequest, "This sign-in request is not valid or has expired.")
	ErrWrongBrowser = auth.NewError("emailchallenge.wrong_browser", http.StatusForbidden, "Open this link in the browser where you started signing in.")

	ErrNoKinds    = errors.New("emailchallenge: no identifier kind can receive a challenge; add a Verifiable sign-in kind whose plugin delivers, such as email")
	ErrBadKinds   = errors.New("emailchallenge: a kind given to Kinds must be registered, sign-in capable, verifiable and owned by a plugin that delivers")
	ErrNoBase     = errors.New("emailchallenge: links need auth.WithBaseURL or emailchallenge.Links")
	ErrBadTTL     = errors.New("emailchallenge: WithTTL needs a positive duration")
	ErrBadAttempt = errors.New("emailchallenge: WithMaxAttempts needs a positive count")
	ErrBadMode    = errors.New("emailchallenge: LinkMode must be CrossDevice or SameDevice")
)

// Plugin is the email challenge sign-in method. Build it with New.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs     auth.OptionErrors
	kinds       []auth.IdentifierKindName
	signUp      bool
	ttl         time.Duration
	maxAttempts int
	mode        LinkMode
	links       func(t auth.Token) string
	core        *auth.Auth

	start, poll, verifyOTP, approve *auth.Op[StartOrToken, Result]
	context                         *auth.Op[TokenRequest, ContextResult]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin.
type Option func(*Plugin)

// Kinds limits challenges to these identifier kinds; by default every
// verifiable sign-in kind whose plugin delivers.
func Kinds(kinds ...auth.IdentifierKindName) Option { return func(p *Plugin) { p.kinds = kinds } }

// SignUp lets a completed challenge create an account for an identifier
// nobody has verified. Without it a challenge to an unknown identifier is
// accepted and never delivered, so the answer is the same either way and the
// poll stays pending until it expires.
func SignUp() Option { return func(p *Plugin) { p.signUp = true } }

// WithTTL replaces DefaultTTL.
func WithTTL(d time.Duration) Option { return func(p *Plugin) { p.ttl = d } }

// WithMaxAttempts replaces DefaultMaxAttempts, the wrong codes a challenge
// survives.
func WithMaxAttempts(n int) Option { return func(p *Plugin) { p.maxAttempts = n } }

// WithLinkMode chooses CrossDevice (the default) or SameDevice.
func WithLinkMode(m LinkMode) Option { return func(p *Plugin) { p.mode = m } }

// Links builds the URL a mail carries from the approval token, for an app
// whose page is not DefaultPage. The page must not approve on GET: it calls
// context, and approves with a POST.
func Links(fn func(t auth.Token) string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("emailchallenge.Links", fn) {
			return
		}
		p.links = fn
	}
}

var (
	_ auth.SignInMethod      = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.RateLimiter       = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.TableOwner        = (*Plugin)(nil)
	_ auth.TypedMigrator     = (*Plugin)(nil)
	_ auth.Sweeper           = (*Plugin)(nil)
)

// New builds the plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{ttl: DefaultTTL, maxAttempts: DefaultMaxAttempts, mode: CrossDevice}
	for _, o := range opts {
		o(p)
	}
	p.start = auth.Define(auth.OpInfo{ID: EndpointStart, Kind: auth.Mutation, Require: auth.Public, Path: "/start"}, p.doStart)
	p.poll = auth.Define(auth.OpInfo{ID: EndpointPoll, Kind: auth.Mutation, Require: auth.Public, Path: "/poll"}, p.doPoll)
	p.verifyOTP = auth.Define(auth.OpInfo{ID: EndpointVerifyOTP, Kind: auth.Mutation, Require: auth.Public, Path: "/verify-otp", SignIn: true}, p.doVerifyOTP)
	p.approve = auth.Define(auth.OpInfo{ID: EndpointApprove, Kind: auth.Mutation, Require: auth.Public, Path: "/approve"}, p.doApprove)
	p.context = auth.Define(auth.OpInfo{ID: EndpointContext, Kind: auth.Query, Require: auth.Public, Path: "/context"}, p.doContext)
	return p
}

// Name returns PluginName.
func (p *Plugin) Name() string { return PluginName }

// SignsIn reports that a challenge is a way in.
func (p *Plugin) SignsIn() bool { return true }

// Operations lists the five operations; all are public, since the mail and
// the poll token are the proofs.
func (p *Plugin) Operations() []auth.Operation {
	return []auth.Operation{p.start, p.poll, p.verifyOTP, p.approve, p.context}
}

// RateLimits bounds mails per identifier and IP, guesses per IP, and polls
// per IP.
func (p *Plugin) RateLimits() []auth.RateRule {
	return []auth.RateRule{
		{Match: EndpointStart, Key: auth.ByIdentifier, Limit: startLimit, Window: startWindow},
		{Match: EndpointStart, Key: auth.ByIP, Limit: startIPLimit, Window: startIPWin},
		{Match: EndpointVerifyOTP, Key: auth.ByIP, Limit: guessLimit, Window: guessWindow},
		{Match: EndpointApprove, Key: auth.ByIP, Limit: guessLimit, Window: guessWindow},
		{Match: EndpointPoll, Key: auth.ByIP, Limit: pollLimit, Window: pollWindow},
		{Match: EndpointContext, Key: auth.ByIP, Limit: pollLimit, Window: pollWindow},
	}
}

// usable reports whether kind k can carry a challenge.
func usable(k auth.IdentifierKind) bool { return k.CanLogin && k.Verifiable }

// Validate refuses a configuration that could never complete a challenge.
func (p *Plugin) Validate(c *auth.Config) error {
	switch {
	case p.ttl <= 0:
		return ErrBadTTL
	case p.maxAttempts <= 0:
		return ErrBadAttempt
	case p.mode != CrossDevice && p.mode != SameDevice:
		return fmt.Errorf("%w: emailchallenge.WithLinkMode(%q)", ErrBadMode, p.mode)
	case p.links == nil && c.BaseURL == "":
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

// Init fills the default kinds and link and refuses a kind whose plugin
// cannot deliver, which Validate cannot see.
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

// deliverable returns the kinds whose plugin is an auth.Deliverer.
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

// Tables declares the challenge table.
func (p *Plugin) Tables() []sqlb.Table { return []sqlb.Table{TableChallenge} }

// TypedMigrations creates the challenge table. Both token hashes are unique: a
// lookup by either finds one row.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	st := []string{
		"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableChallenge) + " (" +
			ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColIdentifier + " " + t.Long + " NOT NULL, " +
			ColApprovalHash + " " + t.Hash + " NOT NULL UNIQUE, " +
			ColBindingHash + " " + t.Hash + " NOT NULL UNIQUE, " +
			ColStatus + " " + t.Key + " NOT NULL, " +
			ColName + " " + t.Text + " NOT NULL, " +
			ColScope + " " + t.Text + " NOT NULL, " +
			ColIP + " " + t.Text + " NOT NULL, " +
			ColUserAgent + " " + t.Long + " NOT NULL, " +
			ColExpiresAt + " " + t.Timestamp + " NOT NULL, " +
			ColApprovedAt + " " + t.Timestamp + " NULL, " +
			ColCreatedAt + " " + t.Timestamp + " NOT NULL)" + t.TableSuffix,
	}
	return []auth.Migration{{Owner: PluginName, Name: migrationName, Statements: st}}, nil
}

// Sweep deletes challenges that expired before cutoff; a poll deletes the
// ones it sees expire, this catches the pages that were closed.
func (p *Plugin) Sweep(ctx context.Context, cutoff time.Time) (int64, error) {
	return p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableChallenge).Where(sqlb.Less(ChallengeExpiresAt, cutoff)))
}

// StartOrToken is the input of start, poll, verify-otp and approve. Each
// reads its own fields: start Identifier and Name; poll PollToken; verify-otp
// PollToken and OTP; approve Token.
type StartOrToken struct {
	// Identifier is where the challenge goes, as typed; its kind is detected.
	Identifier string `json:"identifier,omitempty"`
	// Name is the display name of the account a completed challenge creates
	// (SignUp); ignored when the identifier has an owner.
	Name string `json:"name,omitempty"`
	// PollToken is the asking browser's secret, for a client that keeps no
	// cookies; a browser sends the cookie instead.
	PollToken auth.WireToken `json:"pollToken,omitempty"`
	// OTP is the code from the mail.
	OTP string `json:"otp,omitempty"`
	// Token is the approval token from the link.
	Token auth.WireToken `json:"token,omitempty"`
}

// RateIdentifier counts starts per identifier, folded so case changes do not
// reset the limit.
func (r StartOrToken) RateIdentifier() string {
	return strings.ToLower(strings.TrimSpace(r.Identifier))
}

// Result is the answer of start, poll, verify-otp and approve. Start fills
// PollToken and ExpiresAt; poll fills State and, once completed, the user;
// approve fills State. Token is the new session's, for Go callers and bearer
// transports, never encoded.
type Result struct {
	State                State          `json:"state,omitempty"`
	PollToken            auth.WireToken `json:"pollToken,omitempty"`
	ExpiresAt            *time.Time     `json:"expiresAt,omitempty"`
	User                 *auth.UserView `json:"user,omitempty"`
	Created              bool           `json:"created,omitempty"`
	SecondFactorRequired bool           `json:"secondFactorRequired,omitempty"`
	Token                auth.Token     `json:"-"`
}

// TokenRequest is the query of context: the approval token from the link,
// and a poll token for a client without cookies.
type TokenRequest struct {
	Token     auth.WireToken `json:"token"`
	PollToken auth.WireToken `json:"pollToken,omitempty"`
}

// ContextResult is what the approval page shows. Everything but State is
// left out when State is invalid; the identifier, IP and user agent are those
// of the request that started the challenge, for the person to recognise or
// refuse.
type ContextResult struct {
	State      State      `json:"state"`
	Identifier string     `json:"identifier,omitempty"`
	IP         string     `json:"ipAddress,omitempty"`
	UserAgent  string     `json:"userAgent,omitempty"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
}

// Start opens a challenge for identifier and delivers its link and code when
// the identifier may receive one; the answer is the same when it may not.
func (p *Plugin) Start(ctx context.Context, identifier, name string) (Result, error) {
	return p.start.Call(ctx, StartOrToken{Identifier: identifier, Name: name})
}

// Poll reports the challenge of pollToken and, once approved, signs its
// holder in.
func (p *Plugin) Poll(ctx context.Context, pollToken auth.Token) (Result, error) {
	return p.poll.Call(ctx, StartOrToken{PollToken: pollToken.Wire()})
}

// VerifyOTP signs the holder of pollToken in with the code from the mail.
func (p *Plugin) VerifyOTP(ctx context.Context, pollToken auth.Token, otp string) (Result, error) {
	return p.verifyOTP.Call(ctx, StartOrToken{PollToken: pollToken.Wire(), OTP: otp})
}

// Approve approves the challenge of an approval token; it signs nobody in.
func (p *Plugin) Approve(ctx context.Context, token auth.Token) (Result, error) {
	return p.approve.Call(ctx, StartOrToken{Token: token.Wire()})
}

// Context reports what the approval page should show for token.
func (p *Plugin) Context(ctx context.Context, token auth.Token) (ContextResult, error) {
	return p.context.Call(ctx, TokenRequest{Token: token.Wire()})
}

// row is a challenge as the operations read it.
type row struct {
	id, identifier, name, scope, ip, userAgent string
	binding                                    []byte
	status                                     Status
	expiresAt                                  time.Time
}

// find loads the challenge whose hash column col holds hash.
func (p *Plugin) find(ctx context.Context, col sqlb.Expr[[]byte], hash []byte) (row, bool, error) {
	var r row
	q := p.core.Select().Columns(
		sqlb.Bind(ChallengeID, &r.id), sqlb.Bind(ChallengeIdentifier, &r.identifier), sqlb.Bind(ChallengeName, &r.name),
		sqlb.Bind(ChallengeScope, &r.scope), sqlb.Bind(ChallengeIP, &r.ip), sqlb.Bind(ChallengeUserAgent, &r.userAgent),
		sqlb.Bind(ChallengeBinding, &r.binding), sqlb.Bind(ChallengeStatus, &r.status), sqlb.Bind(ChallengeExpiresAt, &r.expiresAt),
	).From(TableChallenge).Where(sqlb.Eq(col, hash)).Limit(1)
	if err := p.core.One(ctx, q); err != nil {
		if errors.Is(err, sqlb.ErrNoRows) {
			return row{}, false, nil
		}
		return row{}, false, err
	}
	return r, true, nil
}

// pollToken is the poll token of this request: the body's, else the cookie's.
func pollToken(c *auth.Call, in auth.Token) auth.Token {
	if in != "" {
		return in
	}
	v, _ := c.Cookie(CookieName)
	return auth.Token(v)
}

// bound loads the live challenge of the request's poll token. A missing,
// unknown or expired one is false; an expired one is deleted after the call.
func (p *Plugin) bound(ctx context.Context, c *auth.Call, in auth.Token) (row, bool, error) {
	tok := pollToken(c, in)
	if tok == "" {
		return row{}, false, nil
	}
	r, ok, err := p.find(ctx, ChallengeBinding, auth.HashToken(tok))
	if err != nil || !ok {
		return row{}, false, err
	}
	if !c.Auth.Now().Before(r.expiresAt) {
		p.deleteAfter(ctx, r.id)
		return row{}, false, nil
	}
	return r, true, nil
}

// deleteAfter deletes a challenge once the call's transaction ends, so a
// failing call still clears an expired row.
func (p *Plugin) deleteAfter(ctx context.Context, id string) {
	del := sqlb.NewDelete(p.core.Dialect()).From(TableChallenge).Where(sqlb.Eq(ChallengeID, id))
	p.core.AfterTx(ctx, func(ctx context.Context) {
		if _, err := p.core.Exec(ctx, del); err != nil {
			p.core.Logger().Error("emailchallenge: delete expired challenge", "error", err)
		}
	})
}

// allowed reports whether kind may carry a challenge.
func (p *Plugin) allowed(kind auth.IdentifierKindName) bool {
	for _, k := range p.kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// doStart opens a challenge for every well-formed identifier of an allowed
// kind and delivers it only to a verified owner, or, with SignUp, to an
// identifier nobody verified: an undelivered challenge polls pending until it
// expires, exactly like one nobody clicked, so neither the answer nor the
// poll tells a stranger whether an account exists.
func (p *Plugin) doStart(ctx context.Context, c *auth.Call, in StartOrToken) (Result, error) {
	kind, value, err := c.Auth.DetectKind(in.Identifier)
	if err != nil || !p.allowed(kind) {
		return Result{}, auth.ErrIdentifierInvalid
	}
	deliver := true
	if _, err := c.Auth.FindIdentity(ctx, kind, value, true); err != nil {
		if !errors.Is(err, auth.ErrIdentityNotFound) {
			return Result{}, err
		}
		deliver = p.signUp
	}
	id, err := c.Auth.NewID(idPrefix)
	if err != nil {
		return Result{}, err
	}
	approval, poll := auth.NewToken(), auth.NewToken()
	now := c.Auth.Now()
	expires := now.Add(p.ttl)
	scope, _ := auth.ScopeFrom(ctx)
	ins := sqlb.NewInsert(c.Auth.Dialect()).Into(TableChallenge).Row(
		sqlb.Set(ChallengeID, id), sqlb.Set(ChallengeIdentifier, string(kind)+identifierSeparator+value),
		sqlb.Set(ChallengeApproval, auth.HashToken(approval)), sqlb.Set(ChallengeBinding, auth.HashToken(poll)),
		sqlb.Set(ChallengeStatus, StatusPending), sqlb.Set(ChallengeName, in.Name), sqlb.Set(ChallengeScope, scope),
		sqlb.Set(ChallengeIP, c.Client.IP), sqlb.Set(ChallengeUserAgent, c.Client.UserAgent),
		sqlb.Set(ChallengeExpiresAt, expires), sqlb.Set(ChallengeApprovedAt, nil), sqlb.Set(ChallengeCreatedAt, now),
	)
	if _, err := c.Auth.Exec(ctx, ins); err != nil {
		return Result{}, err
	}
	if err := c.Effects.SetCookie(CookieName, poll.Reveal(), expires); err != nil {
		return Result{}, err
	}
	c.Effects.Header("Cache-Control", "no-store")
	if deliver {
		code, err := c.Auth.IssueCode(ctx, PurposeOTP, id, p.ttl)
		if err != nil {
			return Result{}, err
		}
		link := p.links(approval)
		m := auth.Message{Purpose: PurposeSignIn, Link: link, Code: code,
			DefaultSubject: "Your sign-in request", DefaultText: DefaultText(link, code, c.Client.UserAgent, c.Client.IP)}
		if err := c.Auth.Deliver(ctx, auth.Identity{Kind: kind, Value: value}, m); err != nil {
			return Result{}, err
		}
	}
	return Result{State: StatePending, PollToken: poll.Wire(), ExpiresAt: &expires}, nil
}

// DefaultText is the English mail body when the app's mailer has no template
// for PurposeSignIn: the link, the code, and the request it approves.
func DefaultText(link, code, userAgent, ip string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "To sign in, open this link and confirm:\n%s\n\nOr type this code in the page that asked: %s\n", link, code)
	if userAgent != "" || ip != "" {
		fmt.Fprintf(&b, "\nThe request came from %s (%s).", userAgent, ip)
	}
	b.WriteString(" If you did not ask to sign in, ignore this message.\n")
	return b.String()
}

// doPoll reports a challenge to the holder of its poll token and, once it is
// approved, spends it and signs the holder in.
func (p *Plugin) doPoll(ctx context.Context, c *auth.Call, in StartOrToken) (Result, error) {
	r, ok, err := p.bound(ctx, c, in.PollToken.Token())
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{State: StateExpired}, nil
	}
	if r.status != StatusApproved {
		return Result{State: StatePending}, nil
	}
	out, err := p.complete(ctx, c, r, StatusApproved)
	if errors.Is(err, ErrInvalid) {
		return Result{State: StateExpired}, nil
	}
	return out, err
}

// doVerifyOTP checks the code against the poll token's challenge only, so a
// code is never guessed across challenges, and signs the holder in.
func (p *Plugin) doVerifyOTP(ctx context.Context, c *auth.Call, in StartOrToken) (Result, error) {
	r, ok, err := p.bound(ctx, c, in.PollToken.Token())
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{}, ErrInvalid
	}
	if err := c.Auth.CheckCode(ctx, PurposeOTP, r.id, strings.TrimSpace(in.OTP), p.maxAttempts); err != nil {
		return Result{}, err
	}
	return p.complete(ctx, c, r, r.status)
}

// complete spends challenge r, if it is still in state from, and signs in the
// identifier's verified owner, or creates one with SignUp. The conditional
// delete is the claim: of two polls racing for one approval, one signs in.
// ds:def id=plugin-complete-w73yta9q owner=@khanakia stability=stable
func (p *Plugin) complete(ctx context.Context, c *auth.Call, r row, from Status) (Result, error) {
	n, err := c.Auth.Exec(ctx, sqlb.NewDelete(c.Auth.Dialect()).From(TableChallenge).
		Where(sqlb.Eq(ChallengeID, r.id), sqlb.Eq(ChallengeStatus, from)))
	if err != nil {
		return Result{}, err
	}
	if n != 1 {
		return Result{}, ErrInvalid
	}
	kindName, value, _ := strings.Cut(r.identifier, identifierSeparator)
	if r.scope != "" {
		if s, ok := auth.ScopeFrom(ctx); ok && s != r.scope {
			return Result{}, ErrInvalid
		}
		ctx = auth.WithScope(ctx, r.scope)
	}
	var create *auth.NewUser
	if p.signUp {
		create = &auth.NewUser{Name: r.name}
	}
	in, err := c.SignInProvenAs(ctx, auth.IdentifierKindName(kindName), value, create)
	if errors.Is(err, auth.ErrIdentityNotFound) {
		// The owner went away, or (without SignUp) never existed and the
		// code was guessed: the same answer as a spent challenge.
		return Result{}, ErrInvalid
	}
	if err != nil {
		return Result{}, err
	}
	if err := c.Effects.SetCookie(CookieName, "", time.Time{}); err != nil {
		return Result{}, err
	}
	view := auth.ViewOf(in.User)
	return Result{State: StateCompleted, User: &view, Created: in.Created,
		SecondFactorRequired: in.Session.SecondFactorPending, Token: in.Token}, nil
}

// sameBrowser reports whether this request holds challenge r's poll token.
func sameBrowser(c *auth.Call, r row, in auth.Token) bool {
	tok := pollToken(c, in)
	return tok != "" && subtle.ConstantTimeCompare(auth.HashToken(tok), r.binding) == 1
}

// approveRow flips a pending challenge to approved; an approved one stays
// so, so a second click is a success too.
func (p *Plugin) approveRow(ctx context.Context, c *auth.Call, r row) error {
	if r.status == StatusApproved {
		return nil
	}
	now := c.Auth.Now()
	_, err := c.Auth.Exec(ctx, sqlb.NewUpdate(c.Auth.Dialect()).Table(TableChallenge).
		Set(sqlb.Set(ChallengeStatus, StatusApproved), sqlb.Set(ChallengeApprovedAt, &now)).
		Where(sqlb.Eq(ChallengeID, r.id), sqlb.Eq(ChallengeStatus, StatusPending)))
	return err
}

// live loads the unexpired challenge of an approval token.
func (p *Plugin) live(ctx context.Context, c *auth.Call, tok auth.Token) (row, bool, error) {
	if tok == "" {
		return row{}, false, nil
	}
	r, ok, err := p.find(ctx, ChallengeApproval, auth.HashToken(tok))
	if err != nil || !ok {
		return row{}, false, err
	}
	if !c.Auth.Now().Before(r.expiresAt) {
		return row{}, false, nil
	}
	return r, true, nil
}

// doContext is the approval page's read. It changes nothing, so a mail
// scanner that fetches the link approves nothing, except for the browser that
// holds the poll token, whose click is the approval: no third party can
// hold that cookie.
// ds:def id=plugin-docontext-kx8psdmg owner=@khanakia stability=stable
func (p *Plugin) doContext(ctx context.Context, c *auth.Call, in TokenRequest) (ContextResult, error) {
	r, ok, err := p.live(ctx, c, in.Token.Token())
	if err != nil {
		return ContextResult{}, err
	}
	if !ok {
		return ContextResult{State: StateInvalid}, nil
	}
	_, value, _ := strings.Cut(r.identifier, identifierSeparator)
	out := ContextResult{Identifier: value, IP: r.ip, UserAgent: r.userAgent, ExpiresAt: &r.expiresAt}
	switch {
	case sameBrowser(c, r, in.PollToken.Token()):
		if err := p.approveRow(ctx, c, r); err != nil {
			return ContextResult{}, err
		}
		out.State = StateApproved
	case r.status == StatusApproved:
		out.State = StateApproved
	case p.mode == SameDevice:
		out.State = StateWrongBrowser
	default:
		out.State = StateNeedsConfirmation
	}
	return out, nil
}

// doApprove is the confirm button: a POST that approves. In SameDevice mode
// only the asking browser may approve.
func (p *Plugin) doApprove(ctx context.Context, c *auth.Call, in StartOrToken) (Result, error) {
	r, ok, err := p.live(ctx, c, in.Token.Token())
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{}, ErrInvalid
	}
	if p.mode == SameDevice && !sameBrowser(c, r, in.PollToken.Token()) {
		return Result{}, ErrWrongBrowser
	}
	if err := p.approveRow(ctx, c, r); err != nil {
		return Result{}, err
	}
	return Result{State: StateApproved}, nil
}
