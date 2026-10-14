// Package anonymous gives a visitor an account before they have told the app
// who they are: a guest session for a cart, a trial or a draft, and a link to
// the real account the moment they sign up or sign in.
//
// A guest is an ordinary auth_user row with no identifier and the plugin's
// is_anonymous column set, so every app table that references a user works
// for a guest unchanged. The link runs inside the sign-in's own transaction
// through a data hook on session creation, which is the one step every
// sign-in method ends with — password, code, link, provider, passkey — so no
// method has to know this plugin exists, and a method added later links too.
package anonymous

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity: route prefix and migration
// owner.
const PluginName = "anonymous"

// Operation ids, exported so a hook or a rate rule can name them. They are
// wire names, stable across releases.
const (
	EndpointSignIn auth.EndpointID = "anonymous.sign-in"
	EndpointDelete auth.EndpointID = "anonymous.delete"
)

// ColIsAnonymous is the column this plugin adds to auth_user. It is true for
// a guest and false for everyone else, including a guest who later proved an
// identifier of their own.
//
//ds:def id=colisanonymous-7h2kq9mw owner=@khanakia stability=stable
const ColIsAnonymous = "is_anonymous"

// IsAnonymous is the typed column on auth_user, for an app that filters
// guests out of its own queries.
var IsAnonymous = sqlb.Col[bool](auth.TableUser, ColIsAnonymous)

// AnonymousColumns is this plugin's flat part of a composite user: the column
// is on auth_user, so the field is flat (ADR-0001). The name stutters on
// purpose: Go names an embedded field after its type, and two plugins both
// exporting Columns could not be embedded together.
type AnonymousColumns struct {
	IsAnonymous bool
}

// Bindings binds AnonymousColumns for a query on auth_user.
func Bindings(c *AnonymousColumns) []sqlb.Binding {
	return []sqlb.Binding{sqlb.Bind(IsAnonymous, &c.IsAnonymous)}
}

// DefaultName is the display name a guest gets unless WithName says
// otherwise. A fixed word rather than a random one, so a guest can be told
// apart from a real user in any list that shows names.
//
//ds:def id=defaultname-m3xc8t4e owner=@khanakia stability=stable
const DefaultName = "Guest"

// Rate limit on guest creation. Every call creates a user row, so the limit
// is what keeps one client from filling the table.
const (
	// signInIPLimit guest sign-ins per IP per signInIPWindow: a visitor
	// clears their cookies a few times an hour at most.
	//ds:def id=signiniplimit-9v4bq2zp owner=@khanakia stability=stable
	signInIPLimit = 10
	//ds:def id=signinipwindow-2k7xw8rt owner=@khanakia stability=stable
	signInIPWindow = time.Hour
)

// isAnonymousDefault is the column's SQL default: every existing user is a
// real one. FALSE is spelled the same by all three engines.
const isAnonymousDefault = "FALSE"

// Errors this plugin returns. Both reach the user with stable codes.
var (
	// ErrAlreadyAnonymous refuses a guest who asks for another guest
	// session: the first one already holds their data, and piling up guest
	// rows per reload is the failure the refusal prevents.
	ErrAlreadyAnonymous = auth.NewError("anonymous.already", http.StatusConflict, "You already have a guest session.")
	// ErrNotAnonymous refuses the delete route for a real account, which
	// has sign-in methods and belongs with the app's own account deletion.
	ErrNotAnonymous = auth.NewError("anonymous.not_anonymous", http.StatusForbidden, "This is not a guest account.")
)

// LinkFunc is the app's hook when a guest becomes, or signs in to, a real
// account: move the guest's rows to user, inside tx, so the move and the
// sign-in commit or roll back together. guest is deleted right after it
// returns unless KeepUsers is set; an error fails the sign-in and leaves the
// guest as it was.
//
//ds:def id=linkfunc-5r8nq3vd owner=@khanakia stability=stable
type LinkFunc func(ctx context.Context, tx sqlb.DBTX, guest, user auth.User) error

// Plugin is the anonymous sign-in method. Build it with New: the zero value
// has no operations.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs auth.OptionErrors
	name    func() string
	keep    bool
	stale   bool
	onLink  LinkFunc
	perIP   limit
	core    *auth.Auth

	signIn *auth.Op[SignInRequest, SignInResult]
	remove *auth.Op[struct{}, auth.Done]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin; options are applied in order by New.
type Option func(*Plugin)

// WithName sets how a guest's display name is made, for an app that wants
// "Visitor 4812" or a random animal; the default is DefaultName for everyone.
func WithName(fn func() string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("anonymous.WithName", fn) {
			return
		}
		p.name = fn
	}
}

// KeepUsers leaves the guest row in place after it is linked and leaves the
// delete route out, for an app that keeps guest rows for its own records.
// Without it the guest is deleted once linked, so no orphan account remains.
func KeepUsers() Option { return func(p *Plugin) { p.keep = true } }

// OnLink sets the app's hook for moving a guest's data to the account they
// signed up or in with; see LinkFunc. Without it the guest is simply deleted
// (or kept, with KeepUsers) and nothing moves.
func OnLink(fn LinkFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("anonymous.OnLink", fn) {
			return
		}
		p.onLink = fn
	}
}

// SweepStale makes a.Sweep delete guests who never linked and whose every
// session has expired, once they are older than the sweep's retention. Off by
// default because deleting a user cascades to the app's rows that reference
// it; turn it on when guest data has no value after the session ends.
func SweepStale() Option { return func(p *Plugin) { p.stale = true } }

// WithSignInLimit replaces the default of 10 guest sign-ins per IP per hour.
func WithSignInLimit(n int, window time.Duration) Option {
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
		return fmt.Errorf("%w: anonymous.%s(%d, %v): the limit and the window must both be positive",
			auth.ErrBadOperation, option, l.n, l.window)
	}
	return nil
}

// Compile-time proof of each capability; a wrong signature would otherwise
// silently drop it.
var (
	_ auth.SignInMethod      = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.ColumnExtender    = (*Plugin)(nil)
	_ auth.DataHooker        = (*Plugin)(nil)
	_ auth.RateLimiter       = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.Sweeper           = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
)

// New builds the plugin. With no options a guest is named DefaultName, is
// deleted when linked, and may delete their own account.
func New(opts ...Option) *Plugin {
	p := &Plugin{name: func() string { return DefaultName }, perIP: limit{signInIPLimit, signInIPWindow}}
	for _, o := range opts {
		o(p)
	}
	p.signIn = auth.Define(auth.OpInfo{ID: EndpointSignIn, Kind: auth.Mutation, Require: auth.Public, Path: "/sign-in", SignIn: true}, p.doSignIn)
	p.remove = auth.Define(auth.OpInfo{ID: EndpointDelete, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/delete"}, p.doDelete)
	return p
}

// Name returns PluginName, the key the core registers this plugin under.
func (p *Plugin) Name() string { return PluginName }

// Validate refuses a sign-in limit that could not count.
func (p *Plugin) Validate(*auth.Config) error { return p.perIP.check("WithSignInLimit") }

// SignsIn reports that a guest session is a way in, so an app whose only
// other plugins add identifiers still passes the core's sign-in check. Such
// an app has guests and nothing else, which is a real shape for a demo.
func (p *Plugin) SignsIn() bool { return true }

// Init captures the core handle the hooks call.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	return nil
}

// Operations lists sign-in, and delete unless KeepUsers left it out.
func (p *Plugin) Operations() []auth.Operation {
	if p.keep {
		return []auth.Operation{p.signIn}
	}
	return []auth.Operation{p.signIn, p.remove}
}

// RateLimits bounds guest creation per IP.
func (p *Plugin) RateLimits() []auth.RateRule {
	return []auth.RateRule{{Match: EndpointSignIn, Key: auth.ByIP, Limit: p.perIP.n, Window: p.perIP.window}}
}

// Columns adds is_anonymous to auth_user, default false.
func (p *Plugin) Columns() []auth.ColumnExtension {
	return []auth.ColumnExtension{{Table: auth.TableNameUser, Name: ColIsAnonymous, Type: auth.ColumnBool, Default: isAnonymousDefault}}
}

// DataHooks link a guest to the account they sign in to, and turn a guest
// into a regular user once they prove an identifier of their own.
//
// The link runs on session creation because every sign-in method ends there.
// The request's signed-in user is the guest (auth.CurrentUser reads the
// request's own session, which the pipeline resolved before the operation
// ran); the new session's user is the account. A session for the same user,
// an impersonation, or a request with no guest changes nothing.
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{
		Session: auth.TableHooks[auth.Session]{AfterCreate: p.linkOnSession},
		Identity: auth.TableHooks[auth.Identity]{
			AfterCreate: func(ctx context.Context, _ sqlb.DBTX, row *auth.Identity) error {
				if !row.Verified() {
					return nil
				}
				return p.clearIfGuest(ctx, row.UserID)
			},
			AfterUpdate: func(ctx context.Context, _ sqlb.DBTX, old, row *auth.Identity) error {
				if old.Verified() || !row.Verified() {
					return nil
				}
				return p.clearIfGuest(ctx, row.UserID)
			},
		},
	}
}

// linkOnSession is the Session.AfterCreate hook; see DataHooks.
func (p *Plugin) linkOnSession(ctx context.Context, tx sqlb.DBTX, s *auth.Session) error {
	guest, ok := auth.CurrentUser(ctx)
	if !ok || guest.ID == s.UserID || s.ImpersonatedBy != nil {
		return nil
	}
	anon, err := p.IsAnonymous(ctx, guest.ID)
	if err != nil || !anon {
		return err
	}
	user, err := p.core.User(ctx, s.UserID)
	if err != nil {
		return err
	}
	if p.onLink != nil {
		if err := p.onLink(ctx, tx, guest, user); err != nil {
			return err
		}
	}
	if p.keep {
		return nil
	}
	return p.core.DeleteUser(ctx, guest.ID)
}

// clearIfGuest drops the guest flag of a user who just verified an
// identifier: a proven address or number is a way back in, so the account is
// no longer a guest's and must not be linked away or swept.
func (p *Plugin) clearIfGuest(ctx context.Context, userID string) error {
	anon, err := p.IsAnonymous(ctx, userID)
	if err != nil || !anon {
		return err
	}
	return auth.SetUserColumn(ctx, p.core, PluginName, userID, IsAnonymous, false)
}

// IsAnonymous reports whether userID is a guest.
//
//ds:def id=plugin-isanonymous-8w2nt6kp owner=@khanakia stability=stable
func (p *Plugin) IsAnonymous(ctx context.Context, userID string) (bool, error) {
	var c AnonymousColumns
	if err := p.core.LoadUserColumns(ctx, userID, Bindings(&c)...); err != nil {
		return false, err
	}
	return c.IsAnonymous, nil
}

// SignInRequest is the input of sign-in. It has no identifier: a guest is
// nobody in particular.
type SignInRequest struct {
	// Remember is the "remember me" box, as on a password sign-in: nil or
	// true keeps the guest session past the browser, false makes it
	// transient.
	Remember *bool `json:"remember,omitempty"`
}

// SignInResult is the output of sign-in. Token is for Go callers and bearer
// transports, never encoded into JSON.
//
//ds:def id=signinresult-4q7zd2vx owner=@khanakia stability=stable
type SignInResult struct {
	User  auth.UserView `json:"user"`
	Token auth.Token    `json:"-"`
}

// SignIn creates a guest and starts a session for them. A caller who is
// already a guest is refused with ErrAlreadyAnonymous.
//
//ds:def id=plugin-signin-6t3hk9ua owner=@khanakia stability=stable
func (p *Plugin) SignIn(ctx context.Context) (SignInResult, error) {
	return p.signIn.Call(ctx, SignInRequest{})
}

// Delete removes the signed-in guest's account and ends the session. A real
// account is refused with ErrNotAnonymous.
//
//ds:def id=plugin-delete-3n8vq5yc owner=@khanakia stability=stable
func (p *Plugin) Delete(ctx context.Context) error {
	_, err := p.remove.Call(ctx, struct{}{})
	return err
}

// doSignIn creates the guest and the session in one transaction. A signed-in
// real user who asks for a guest gets one, and their cookie is replaced: the
// request is explicit, and the real session is still theirs to return to.
func (p *Plugin) doSignIn(ctx context.Context, c *auth.Call, in SignInRequest) (SignInResult, error) {
	if c.User != nil {
		anon, err := p.IsAnonymous(ctx, c.User.ID)
		if err != nil {
			return SignInResult{}, err
		}
		if anon {
			return SignInResult{}, ErrAlreadyAnonymous
		}
	}
	u, err := c.Auth.CreateUser(ctx, auth.NewUser{Name: p.name()})
	if err != nil {
		return SignInResult{}, err
	}
	if err := auth.SetUserColumn(ctx, c.Auth, PluginName, u.ID, IsAnonymous, true); err != nil {
		return SignInResult{}, err
	}
	// A guest has no second factor, so CreateSession makes a full session;
	// it is used rather than CreateMultiFactorSession so a SecondFactor
	// plugin that decides otherwise one day still gets its say.
	s, tok, err := c.Auth.CreateSessionWithOptions(ctx, u.ID, c.Client, auth.SessionOptions{Transient: in.Remember != nil && !*in.Remember})
	if err != nil {
		return SignInResult{}, err
	}
	c.Effects.IssueSessionOf(s, tok)
	return SignInResult{User: auth.ViewOf(u), Token: tok}, nil
}

// doDelete ends the session first, through the core's sign-out so the
// session cache forgets it too, then deletes the user; the app's User
// BeforeDelete hooks run inside the same transaction.
func (p *Plugin) doDelete(ctx context.Context, c *auth.Call, _ struct{}) (auth.Done, error) {
	anon, err := p.IsAnonymous(ctx, c.User.ID)
	if err != nil {
		return auth.Done{}, err
	}
	if !anon {
		return auth.Done{}, ErrNotAnonymous
	}
	if err := c.Auth.SignOut(ctx); err != nil {
		return auth.Done{}, err
	}
	if err := c.Auth.DeleteUser(ctx, c.User.ID); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

// Sweep deletes guests created before cutoff who have no live session, when
// SweepStale is set; otherwise it deletes nothing. Each is deleted through
// the core, one by one, so the app's User BeforeDelete hooks run for every
// guest as they do for a delete by hand.
func (p *Plugin) Sweep(ctx context.Context, cutoff time.Time) (int64, error) {
	if !p.stale {
		return 0, nil
	}
	ids, err := p.staleGuests(ctx, cutoff)
	if err != nil {
		return 0, err
	}
	var n int64
	for _, id := range ids {
		if err := p.core.DeleteUser(ctx, id); err != nil {
			if errors.Is(err, auth.ErrUserNotFound) {
				continue // another instance's sweep got there first
			}
			return n, err
		}
		n++
	}
	return n, nil
}

// staleGuests lists guests older than cutoff with no session that is still
// live: a LEFT join of the live sessions, kept where none matched.
func (p *Plugin) staleGuests(ctx context.Context, cutoff time.Time) ([]string, error) {
	var id string
	var live *string
	q := p.core.Select().Columns(sqlb.Bind(auth.UserID, &id), sqlb.Bind(liveSessionID, &live)).From(auth.TableUser).
		Join(sqlb.Join{Type: sqlb.JoinLeft, Table: auth.TableSession, On: []sqlb.Predicate{
			sqlb.EqExpr(auth.SessionUserID, auth.UserID), sqlb.Greater(auth.SessionExpiresAt, p.core.Now()),
		}}).
		Where(sqlb.Eq(IsAnonymous, true), sqlb.Less(auth.UserCreatedAt, cutoff), sqlb.IsNull(auth.SessionID)).
		Order(sqlb.OrderBy(auth.UserCreatedAt, sqlb.SortAsc), sqlb.OrderBy(auth.UserID, sqlb.SortAsc))
	var out []string
	err := p.core.Each(ctx, q, func() error { out = append(out, id); return nil })
	return out, err
}

// liveSessionID is auth_session.id typed as nullable, for the LEFT join in
// staleGuests, whose unmatched rows scan NULL.
var liveSessionID = sqlb.Col[*string](auth.TableSession, auth.ColSessionID)
