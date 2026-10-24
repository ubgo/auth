// Package lastlogin remembers how each user last signed in — password, a
// provider, a magic link, a code, a passkey — so a sign-in page can put the
// method the person used last in front, and so an app can see which methods
// its users actually use.
//
// It is one column on auth_user, written by a data hook on session creation,
// which every sign-in method ends with. The method's name is the plugin that
// ran the operation, so a method added later is recorded without knowing
// this plugin exists; WithResolver names it differently when the app wants
// the provider rather than "oauth".
package lastlogin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity: migration owner.
const PluginName = "lastlogin"

// Columns this plugin adds to auth_user.
const (
	// ColMethod is the method of the last sign-in: a plugin name such as
	// "password", "oauth", "magiclink", "phone", "passkey", "anonymous", or
	// what WithResolver returned. Empty for a user who never signed in since
	// the column existed.
	//ds:def id=colmethod-7q2nv8kx owner=@khanakia stability=stable
	ColMethod = "last_login_method"
	// ColAt is when that sign-in happened.
	ColAt = "last_login_at"
)

// Typed columns on auth_user, for an app that reports on sign-in methods in
// its own queries.
var (
	Method = sqlb.Col[string](auth.TableUser, ColMethod)
	At     = sqlb.Col[*time.Time](auth.TableUser, ColAt)
)

// LastLoginColumns is this plugin's flat part of a composite user (the
// columns are on auth_user, ADR-0001). The name stutters on purpose: Go names
// an embedded field after its type, and two plugins exporting Columns could
// not be embedded together.
type LastLoginColumns struct {
	LastLoginMethod string
	LastLoginAt     *time.Time
}

// Bindings binds LastLoginColumns for a query on auth_user.
func Bindings(c *LastLoginColumns) []sqlb.Binding {
	return []sqlb.Binding{sqlb.Bind(Method, &c.LastLoginMethod), sqlb.Bind(At, &c.LastLoginAt)}
}

// Resolver names the method of a sign-in from the operation that created the
// session and the session itself. It returns "" to record nothing for this
// sign-in.
//
//ds:def id=resolver-3m9xk2wt owner=@khanakia stability=stable
type Resolver func(ctx context.Context, op auth.OpInfo, s auth.Session) string

// DefaultResolver names the method after the plugin that ran the operation:
// "password", "oauth", "magiclink", … The plugin is the first segment of the
// operation id ("<plugin>.<name>").
func DefaultResolver(_ context.Context, op auth.OpInfo, _ auth.Session) string {
	id := string(op.ID)
	for i := range id {
		if id[i] == '.' {
			return id[:i]
		}
	}
	return id
}

// The cookie (WithCookie) that holds the last_used_login_method hint.
const (
	// DefaultCookieName is the plugin cookie's name; authhttp sends it as
	// __Host-auth_last_used_login_method, beside the core's cookies.
	//ds:def id=lastlogin-defaultcookiename-5qk8nw2v owner=@khanakia stability=stable
	DefaultCookieName = "last_used_login_method"
	// DefaultCookieMaxAge is 30 days: the hint is
	// for the next sign-in, which may be weeks away.
	//ds:def id=lastlogin-defaultcookiemaxage-8wr3mt6q owner=@khanakia stability=stable
	DefaultCookieMaxAge = 30 * 24 * time.Hour
)

// Operation ids of the cookie routes, served only under WithCookie.
const (
	EndpointMethod auth.EndpointID = "lastlogin.method"
	EndpointClear  auth.EndpointID = "lastlogin.clear"
)

// ConsentFunc decides, per sign-in, whether the cookie may be set, such as
// after the visitor accepted the app's cookie banner. The database record
// does not ask: it is the app's own data about its user, not a cookie in the
// visitor's browser.
type ConsentFunc func(ctx context.Context) bool

// sqlEmptyString is the SQL default of the method column: every existing user
// starts with no recorded method.
const sqlEmptyString = "''"

// Plugin records the last sign-in method. Build it with New.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs auth.OptionErrors
	resolve Resolver
	// cookie, cookieName, cookieAge and consent are WithCookie's choices.
	cookie     bool
	cookieName string
	cookieAge  time.Duration
	consent    ConsentFunc
	core       *auth.Auth

	method *auth.Op[struct{}, MethodResult]
	clear  *auth.Op[struct{}, auth.Done]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin; options are applied in order by New.
type Option func(*Plugin)

// WithResolver replaces DefaultResolver, for an app that wants "google"
// rather than "oauth", or that records nothing for some operations.
func WithResolver(fn Resolver) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("lastlogin.WithResolver", fn) {
			return
		}
		p.resolve = fn
	}
}

// WithCookie also keeps the last method in a cookie: every sign-in that
// records a method sets it for maxAge (0 takes DefaultCookieMaxAge), under
// name ("" takes DefaultCookieName; it must match auth.CookieNamePattern). A
// login page reads it before anyone is signed in: server-side through
// auth.RequestCookie, a script through GET <mount>/lastlogin/method, and POST
// <mount>/lastlogin/clear forgets it.
//
// The cookie is not readable by page scripts: every plugin cookie has the
// core's fixed attributes, HttpOnly among them, so no plugin can weaken the
// cookie rules; the route is how a script reads it. The value is a method
// name only, never an identifier, so it says how someone on this browser
// signed in, not who.
//
//ds:def id=lastlogin-withcookie-3vn9qk5t owner=@khanakia stability=stable
func WithCookie(name string, maxAge time.Duration) Option {
	return func(p *Plugin) { p.cookie, p.cookieName, p.cookieAge = true, name, maxAge }
}

// WithCookieConsent asks fn before each cookie is set; false skips the cookie
// for that sign-in only.
func WithCookieConsent(fn ConsentFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("lastlogin.WithCookieConsent", fn) {
			return
		}
		p.consent = fn
	}
}

// ErrBadCookieAge is a configuration error from auth.New: WithCookie was
// given a negative maxAge, a cookie that would be deleted as it is set.
var ErrBadCookieAge = errors.New("lastlogin: WithCookie needs a maxAge of zero (the default) or more")

// MethodResult is the answer of GET lastlogin/method: the method this
// browser last signed in with, or "" when its cookie is absent.
type MethodResult struct {
	Method string `json:"method"`
}

var (
	_ auth.ColumnExtender    = (*Plugin)(nil)
	_ auth.DataHooker        = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.OperationHooker   = (*Plugin)(nil)
)

// New builds the plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{resolve: DefaultResolver}
	for _, o := range opts {
		o(p)
	}
	if p.cookieName == "" {
		p.cookieName = DefaultCookieName
	}
	if p.cookieAge == 0 {
		p.cookieAge = DefaultCookieMaxAge
	}
	p.method = auth.Define(auth.OpInfo{ID: EndpointMethod, Kind: auth.Query, Require: auth.Public, Path: "/method"}, p.doMethod)
	p.clear = auth.Define(auth.OpInfo{ID: EndpointClear, Kind: auth.Mutation, Require: auth.Public, Path: "/clear"}, p.doClear)
	return p
}

// Validate refuses a cookie name the core would refuse at the first
// sign-in, and a negative lifetime.
func (p *Plugin) Validate(*auth.Config) error {
	if !p.cookie {
		return nil
	}
	if p.cookieAge < 0 {
		return ErrBadCookieAge
	}
	if err := auth.CheckCookieName(p.cookieName); err != nil {
		return fmt.Errorf("lastlogin.WithCookie: %w", err)
	}
	return nil
}

// Operations lists the cookie routes under WithCookie, and nothing
// otherwise: the database record needs no route.
func (p *Plugin) Operations() []auth.Operation {
	if !p.cookie {
		return nil
	}
	return []auth.Operation{p.method, p.clear}
}

// OperationHooks adds, under WithCookie, the after-hook that sets the cookie
// for the session a sign-in issued.
func (p *Plugin) OperationHooks() []auth.OperationHook {
	if !p.cookie {
		return nil
	}
	return []auth.OperationHook{{After: p.afterSignIn}}
}

// afterSignIn sets the cookie for the last session the call issued, by the
// same rules as the database record: the method the resolver names, not
// for the promotion after a second factor (the first step already set it)
// nor for an impersonation, and only with consent.
func (p *Plugin) afterSignIn(ctx context.Context, c *auth.Call, _ any) error {
	if c.Op.Require == auth.PendingSecondFactor {
		return nil
	}
	var issued *auth.Effect
	for _, e := range c.Effects.List() {
		if e.Kind == auth.EffectIssueSession && e.SessionID != "" {
			issued = &e
		}
	}
	if issued == nil {
		return nil
	}
	s, err := p.session(ctx, issued.UserID, issued.SessionID)
	if err != nil {
		return err
	}
	if s.ImpersonatedBy != nil {
		return nil
	}
	method := p.resolve(ctx, c.Op, s)
	if method == "" || (p.consent != nil && !p.consent(ctx)) {
		return nil
	}
	return c.Effects.SetCookie(p.cookieName, method, c.Auth.Now().Add(p.cookieAge))
}

// session finds the issued session among the user's, for the resolver and
// the impersonation check. In stateless mode the server lists no sessions;
// the session is then the id and the user, which is all the default
// resolver reads.
func (p *Plugin) session(ctx context.Context, userID, id string) (auth.Session, error) {
	list, err := p.core.Sessions(ctx, userID)
	if errors.Is(err, auth.ErrSessionsUnavailable) {
		return auth.Session{ID: id, UserID: userID}, nil
	}
	if err != nil {
		return auth.Session{}, err
	}
	for _, s := range list {
		if s.ID == id {
			return s, nil
		}
	}
	return auth.Session{ID: id, UserID: userID}, nil
}

// doMethod answers the cookie's value; a Go caller has no cookie and gets "".
func (p *Plugin) doMethod(_ context.Context, c *auth.Call, _ struct{}) (MethodResult, error) {
	m, _ := c.Cookie(p.cookieName)
	return MethodResult{Method: m}, nil
}

// doClear deletes the cookie: a zero expiry is the core's delete.
func (p *Plugin) doClear(_ context.Context, c *auth.Call, _ struct{}) (auth.Done, error) {
	if err := c.Effects.SetCookie(p.cookieName, "", time.Time{}); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

// Name returns PluginName, the key the core registers this plugin under.
func (p *Plugin) Name() string { return PluginName }

// Init captures the core handle the hook writes through.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	return nil
}

// Columns adds the method and its time to auth_user.
func (p *Plugin) Columns() []auth.ColumnExtension {
	return []auth.ColumnExtension{
		{Table: auth.TableNameUser, Name: ColMethod, Type: auth.ColumnText, Default: sqlEmptyString},
		{Table: auth.TableNameUser, Name: ColAt, Type: auth.ColumnTimestamp, Nullable: true},
	}
}

// DataHooks record the method on every session a sign-in operation creates.
//
// A pending second-factor session counts: the method was used, and the
// promotion that follows (a PendingSecondFactor operation) is skipped so the
// second step does not overwrite the first. An impersonation is not the
// user's own sign-in, and a session created outside an operation (a.
// CreateSession from Go) has no method to record.
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{Session: auth.TableHooks[auth.Session]{
		AfterCreate: func(ctx context.Context, _ sqlb.DBTX, s *auth.Session) error {
			op, ok := auth.OperationOf(ctx)
			if !ok || op.Require == auth.PendingSecondFactor || s.ImpersonatedBy != nil {
				return nil
			}
			method := p.resolve(ctx, op, *s)
			if method == "" {
				return nil
			}
			return p.record(ctx, s.UserID, method, s.CreatedAt)
		},
	}}
}

func (p *Plugin) record(ctx context.Context, userID, method string, at time.Time) error {
	if err := auth.SetUserColumn(ctx, p.core, PluginName, userID, Method, method); err != nil {
		return err
	}
	return auth.SetUserColumn(ctx, p.core, PluginName, userID, At, &at)
}

// Of returns how and when userID last signed in; the method is "" when
// nothing was recorded.
//
//ds:def id=plugin-of-5t8wn3qr owner=@khanakia stability=stable
func (p *Plugin) Of(ctx context.Context, userID string) (LastLoginColumns, error) {
	if p.core == nil {
		return LastLoginColumns{}, auth.ErrOperationNotWired
	}
	var c LastLoginColumns
	if err := p.core.LoadUserColumns(ctx, userID, Bindings(&c)...); err != nil {
		return LastLoginColumns{}, err
	}
	return c, nil
}
