// Package invite is invitation codes for users, better-invite's plugin: a
// signed-in user creates an invite, either public (a link anyone holding it
// may use, up to a number of uses) or private (mailed to one address, used
// once), with an expiry and optionally a role; every use is
// recorded with who used it and when; and Required makes sign-up refuse
// anyone without a valid invite.
//
// An invite is a token, stored as its hash. It reaches the sign-up in one of
// two ways, so every sign-up method works without knowing this plugin: the
// InviteHeader header on the sign-up request, or the invite cookie that
// activate sets for a signed-out visitor, which the provider callback of an
// OAuth sign-up carries too. A data hook on user creation spends it inside
// the sign-up's transaction, so an invite that runs out refuses the sign-up
// rather than leaving a user nobody invited.
//
// The plugin stores a role but never grants one: OnAccepted runs in the same
// transaction with the role, for the app to apply (admin.SetRole, an
// organization membership, a plan). A role in an invite is refused unless the
// app passed CanCreate, so no user can mint an invite that makes its holder
// an admin.
package invite

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
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity and route prefix.
const PluginName = "invite"

// Operation ids, stable wire names.
const (
	EndpointCreate   auth.EndpointID = "invite.create"
	EndpointGet      auth.EndpointID = "invite.get"
	EndpointList     auth.EndpointID = "invite.list"
	EndpointCancel   auth.EndpointID = "invite.cancel"
	EndpointReject   auth.EndpointID = "invite.reject"
	EndpointActivate auth.EndpointID = "invite.activate"
)

// InviteHeader carries an invite token on a sign-up request.
// ds:def id=inviteheader-b6pq8rb7 owner=@khanakia stability=stable
const InviteHeader = "Invite-Token"

// CookieName is the plugin cookie activate sets for a signed-out visitor,
// read when the account is created or the visitor signs in.
const CookieName = "invite"

// PurposeInvite is the message a private invite sends.
const PurposeInvite auth.Purpose = "invite.user"

// Defaults, better-invite's.
const (
	// DefaultTTL is how long an invite works: one hour.
	DefaultTTL = time.Hour
	// DefaultCookieTTL is how long an activated invite waits in the cookie
	// for its visitor to sign up or sign in: ten minutes.
	DefaultCookieTTL = 10 * time.Minute
	// DefaultPage is the app page the link opens; it calls get to show the
	// invite and activate to use it.
	DefaultPage = "/invite"
	// MaxTTL bounds a requested expiry: an invite is a standing credential.
	MaxTTL = 30 * 24 * time.Hour
	// MaxListLimit bounds one page of list.
	MaxListLimit = 100
	// defaultListLimit is list's page when none is asked for.
	defaultListLimit = 20
	// guessLimit get and activate calls per IP per guessWindow: the token is
	// unguessable, the limit stops anyone trying.
	guessLimit  = 30
	guessWindow = time.Minute
	// createLimit invites per IP per createWindow: a private invite is a mail.
	createLimit  = 20
	createWindow = time.Hour
)

// Status is an invite's state.
type Status string

// The states, better-invite's names. An invite whose uses ran out is used;
// an expired one keeps its last state and is refused by its expiry.
const (
	StatusPending  Status = "pending"
	StatusUsed     Status = "used"
	StatusCanceled Status = "canceled"
	StatusRejected Status = "rejected"
)

// The tables: invites, and one row per use. No foreign keys (ADR-0002).
const (
	TableNameInvite  = "auth_invite"
	TableAliasInvite = "inv"
	TableNameUse     = "auth_invite_use"
	TableAliasUse    = "inu"

	ColID        = "id"
	ColTokenHash = "token_hash"
	ColCreatedBy = "created_by"
	ColEmail     = "email"
	ColRole      = "role"
	ColMaxUses   = "max_uses"
	ColUses      = "uses"
	ColStatus    = "status"
	ColExpiresAt = "expires_at"
	ColCreatedAt = "created_at"

	ColUseInvite = "invite_id"
	ColUseUser   = "user_id"
	ColUseAt     = "used_at"

	migrationName = "0001_invite"
	idPrefix      = "inv"
)

// The tables and their typed columns, for an app that reads them.
var (
	TableInvite = sqlb.Table{Name: TableNameInvite, Alias: TableAliasInvite}
	TableUse    = sqlb.Table{Name: TableNameUse, Alias: TableAliasUse}

	InviteID        = sqlb.Col[string](TableInvite, ColID)
	InviteTokenHash = sqlb.Col[[]byte](TableInvite, ColTokenHash)
	InviteCreatedBy = sqlb.Col[string](TableInvite, ColCreatedBy)
	InviteEmail     = sqlb.Col[*string](TableInvite, ColEmail)
	InviteRole      = sqlb.Col[string](TableInvite, ColRole)
	InviteMaxUses   = sqlb.Col[int64](TableInvite, ColMaxUses)
	InviteUses      = sqlb.Col[int64](TableInvite, ColUses)
	InviteStatus    = sqlb.Col[Status](TableInvite, ColStatus)
	InviteExpiresAt = sqlb.Col[time.Time](TableInvite, ColExpiresAt)
	InviteCreatedAt = sqlb.Col[time.Time](TableInvite, ColCreatedAt)

	UseInviteID = sqlb.Col[string](TableUse, ColUseInvite)
	UseUserID   = sqlb.Col[string](TableUse, ColUseUser)
	UseAt       = sqlb.Col[time.Time](TableUse, ColUseAt)
)

// Errors. ErrInvalid covers an unknown, expired, spent, canceled and
// rejected invite alike.
var (
	ErrInvalid   = auth.NewError("invite.invalid", http.StatusBadRequest, "This invitation is not valid or has expired.")
	ErrRequired  = auth.NewError("invite.required", http.StatusForbidden, "An invitation is required to sign up.")
	ErrForbidden = auth.NewError("invite.forbidden", http.StatusForbidden, "You cannot create this invitation.")

	ErrNoBase  = errors.New("invite: links need auth.WithBaseURL or invite.Links")
	ErrBadTTL  = errors.New("invite: WithTTL and WithCookieTTL need a positive duration, WithTTL at most MaxTTL")
	ErrNoEmail = errors.New("invite: private invites mail an address, so the email plugin must be wired (or pass invite.PublicOnly)")
)

// Request is the input of create.
type Request struct {
	// Email makes the invite private: mailed to this address and usable
	// once; only the account with this address may reject it. The token is
	// the proof, as better-invite's: whoever holds the mailed link may use
	// it, which is how an invite to a work address can create an account
	// under another. Empty makes a public invite whose token the creator
	// shares.
	Email string `json:"email,omitempty"`
	// Role is stored and handed to OnAccepted; refused unless CanCreate is
	// set.
	Role string `json:"role,omitempty"`
	// MaxUses bounds a public invite's uses; 0 means unlimited. A private
	// invite is used once.
	MaxUses int64 `json:"maxUses,omitempty"`
	// ExpiresIn is seconds until the invite stops working; 0 means the
	// plugin's TTL. At most MaxTTL.
	ExpiresIn int64 `json:"expiresIn,omitempty"`
}

// Created is the answer of create. Token and URL are given for a public
// invite only; a private one goes by mail.
type Created struct {
	ID        string         `json:"id"`
	Token     auth.WireToken `json:"token,omitempty"`
	URL       string         `json:"url,omitempty"`
	ExpiresAt time.Time      `json:"expiresAt"`
}

// Accepted is what OnAccepted receives when a user uses an invite.
type Accepted struct {
	InviteID  string
	UserID    string
	CreatedBy string
	Role      string
	// NewAccount is true when the use created the account.
	NewAccount bool
}

// Plugin is the invite plugin. Build it with New.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs        auth.OptionErrors
	ttl, cookieTTL time.Duration
	required       bool
	shareInviter   bool
	// publicOnly turns private (addressed) invites off; see PublicOnly.
	publicOnly bool
	canCreate  func(ctx context.Context, inviter auth.User, in Request) error
	onAccepted func(ctx context.Context, a Accepted) error
	links      func(t auth.Token) string
	core       *auth.Auth

	create   *auth.Op[Request, Created]
	get      *auth.Op[TokenRequest, View]
	list     *auth.Op[ListRequest, ListResult]
	cancel   *auth.Op[IDRequest, auth.Done]
	reject   *auth.Op[TokenRequest, auth.Done]
	activate *auth.Op[TokenRequest, ActivateResult]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin.
type Option func(*Plugin)

// Required refuses a sign-up by a client (a public operation) that brings no
// valid invite. Users an admin or the app creates from Go are not refused.
func Required() Option { return func(p *Plugin) { p.required = true } }

// PublicOnly turns private invites off: a create that names an Email is
// refused with ErrForbidden, and the email plugin is no longer needed.
// Without it a private invite is mailed, so auth.New refuses the plugin
// with ErrNoEmail unless a plugin that delivers email (plugin/email) is
// wired, rather than the first private invite failing.
func PublicOnly() Option { return func(p *Plugin) { p.publicOnly = true } }

// WithTTL replaces DefaultTTL, an invite's default life.
func WithTTL(d time.Duration) Option { return func(p *Plugin) { p.ttl = d } }

// WithCookieTTL replaces DefaultCookieTTL.
func WithCookieTTL(d time.Duration) Option { return func(p *Plugin) { p.cookieTTL = d } }

// HideInviter leaves the inviter's name out of get, better-invite's
// shareInviterName false.
func HideInviter() Option { return func(p *Plugin) { p.shareInviter = false } }

// CanCreate decides who may create which invite: return an error (such as
// ErrForbidden) to refuse. Without it every signed-in user may create an
// invite with no role, and any role is refused.
func CanCreate(fn func(ctx context.Context, inviter auth.User, in Request) error) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("invite.CanCreate", fn) {
			return
		}
		p.canCreate = fn
	}
}

// OnAccepted runs in the transaction that records a use, to apply the role or
// anything else the invite stands for; an error undoes the use (and the
// sign-up it came with).
func OnAccepted(fn func(ctx context.Context, a Accepted) error) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("invite.OnAccepted", fn) {
			return
		}
		p.onAccepted = fn
	}
}

// Links builds the URL of an invite from its token, for an app whose page is
// not DefaultPage.
func Links(fn func(t auth.Token) string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("invite.Links", fn) {
			return
		}
		p.links = fn
	}
}

var (
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.DataHooker        = (*Plugin)(nil)
	_ auth.RateLimiter       = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.TableOwner        = (*Plugin)(nil)
	_ auth.UserTableOwner    = (*Plugin)(nil)
	_ auth.TypedMigrator     = (*Plugin)(nil)
)

// New builds the plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{ttl: DefaultTTL, cookieTTL: DefaultCookieTTL, shareInviter: true}
	for _, o := range opts {
		o(p)
	}
	p.create = auth.Define(auth.OpInfo{ID: EndpointCreate, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/create"}, p.doCreate)
	p.get = auth.Define(auth.OpInfo{ID: EndpointGet, Kind: auth.Query, Require: auth.Public, Path: "/get"}, p.doGet)
	p.list = auth.Define(auth.OpInfo{ID: EndpointList, Kind: auth.Query, Require: auth.SignedIn, Path: "/list"}, p.doList)
	p.cancel = auth.Define(auth.OpInfo{ID: EndpointCancel, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/cancel"}, p.doCancel)
	p.reject = auth.Define(auth.OpInfo{ID: EndpointReject, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/reject"}, p.doReject)
	p.activate = auth.Define(auth.OpInfo{ID: EndpointActivate, Kind: auth.Mutation, Require: auth.Public, Path: "/activate"}, p.doActivate)
	return p
}

// Name returns PluginName.
func (p *Plugin) Name() string { return PluginName }

// Operations lists the six operations.
func (p *Plugin) Operations() []auth.Operation {
	return []auth.Operation{p.create, p.get, p.list, p.cancel, p.reject, p.activate}
}

// RateLimits bounds lookups of a token and invites created per IP.
func (p *Plugin) RateLimits() []auth.RateRule {
	return []auth.RateRule{
		{Match: EndpointGet, Key: auth.ByIP, Limit: guessLimit, Window: guessWindow},
		{Match: EndpointActivate, Key: auth.ByIP, Limit: guessLimit, Window: guessWindow},
		{Match: EndpointCreate, Key: auth.ByIP, Limit: createLimit, Window: createWindow},
	}
}

// Validate refuses lifetimes that are not positive, or longer than MaxTTL.
func (p *Plugin) Validate(c *auth.Config) error {
	if p.ttl <= 0 || p.ttl > MaxTTL || p.cookieTTL <= 0 {
		return ErrBadTTL
	}
	if p.links == nil && c.BaseURL == "" {
		return ErrNoBase
	}
	// A private invite is mailed (doCreate's Deliver), so a kind nobody
	// delivers fails here, as organization.InviteBy does, instead of at the
	// first private invite.
	if !p.publicOnly && !c.CanDeliver(email.KindEmail) {
		return ErrNoEmail
	}
	return nil
}

// Init captures the core and fills the default link.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	if p.links == nil {
		base := strings.TrimSuffix(a.Config().BaseURL, "/")
		p.links = func(t auth.Token) string { return base + DefaultPage + "?token=" + url.QueryEscape(t.Reveal()) }
	}
	return nil
}

// Tables declares the two tables.
func (p *Plugin) Tables() []sqlb.Table { return []sqlb.Table{TableInvite, TableUse} }

// UserTables tells DeleteUser which rows are a user's: the invites they
// created, which stop working with them, and their uses.
func (p *Plugin) UserTables() []auth.UserTable {
	return []auth.UserTable{{Table: TableInvite, Column: ColCreatedBy}, {Table: TableUse, Column: ColUseUser}}
}

// TypedMigrations creates the two tables. A use's key is invite and user, so one
// user uses one invite once.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	st := []string{
		"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableInvite) + " (" +
			ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColTokenHash + " " + t.Hash + " NOT NULL UNIQUE, " +
			ColCreatedBy + " " + t.ID + " NOT NULL, " +
			ColEmail + " " + t.Value + " NULL, " +
			ColRole + " " + t.Text + " NOT NULL, " +
			ColMaxUses + " " + t.Int + " NOT NULL, " +
			ColUses + " " + t.Int + " NOT NULL, " +
			ColStatus + " " + t.Key + " NOT NULL, " +
			ColExpiresAt + " " + t.Timestamp + " NOT NULL, " +
			ColCreatedAt + " " + t.Timestamp + " NOT NULL)" + t.TableSuffix,
		"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableUse) + " (" +
			ColUseInvite + " " + t.ID + " NOT NULL, " +
			ColUseUser + " " + t.ID + " NOT NULL, " +
			ColUseAt + " " + t.Timestamp + " NOT NULL, " +
			"PRIMARY KEY (" + ColUseInvite + ", " + ColUseUser + "))" + t.TableSuffix,
	}
	return []auth.Migration{{Owner: PluginName, Name: migrationName, Statements: st}}, nil
}

// DataHooks spend the invite a request brings: on user creation, inside the
// sign-up's transaction, where a bad invite refuses the sign-up; and on
// session creation for an existing user who activated an invite while signed
// out, where a bad one is ignored so it never blocks a sign-in.
// ds:def id=plugin-datahooks-8kkfp2xr owner=@khanakia stability=stable
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{
		User: auth.TableHooks[auth.User]{AfterCreate: func(ctx context.Context, _ sqlb.DBTX, u *auth.User) error {
			tok := requestToken(ctx)
			if tok == "" {
				if p.required && clientSignUp(ctx) {
					return ErrRequired
				}
				return nil
			}
			return p.use(ctx, tok, u.ID, true)
		}},
		Session: auth.TableHooks[auth.Session]{AfterCreate: func(ctx context.Context, _ sqlb.DBTX, s *auth.Session) error {
			tok := requestToken(ctx)
			if tok == "" {
				return nil
			}
			if err := p.use(ctx, tok, s.UserID, false); err != nil && !errors.Is(err, ErrInvalid) {
				return err
			}
			return nil
		}},
	}
}

// clientSignUp reports whether the running operation is a client's own
// sign-up (a public operation), which Required applies to.
func clientSignUp(ctx context.Context) bool {
	op, ok := auth.OperationOf(ctx)
	return ok && op.Require == auth.Public
}

// requestToken is the invite the request brings: the header's, else the
// cookie's.
func requestToken(ctx context.Context) auth.Token {
	if h := strings.TrimSpace(auth.RequestHeader(ctx, InviteHeader)); h != "" {
		return auth.Token(h)
	}
	v, _ := auth.RequestCookie(ctx, CookieName)
	return auth.Token(v)
}

// row is an invite as the operations read it.
type row struct {
	id, createdBy, role string
	email               *string
	maxUses, uses       int64
	status              Status
	expiresAt           time.Time
	createdAt           time.Time
}

// columns binds every column of an invite into r.
func (r *row) columns() []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(InviteID, &r.id), sqlb.Bind(InviteCreatedBy, &r.createdBy), sqlb.Bind(InviteRole, &r.role),
		sqlb.Bind(InviteEmail, &r.email), sqlb.Bind(InviteMaxUses, &r.maxUses), sqlb.Bind(InviteUses, &r.uses),
		sqlb.Bind(InviteStatus, &r.status), sqlb.Bind(InviteExpiresAt, &r.expiresAt), sqlb.Bind(InviteCreatedAt, &r.createdAt),
	}
}

// find loads the invite of tok.
func (p *Plugin) find(ctx context.Context, tok auth.Token) (row, bool, error) {
	if tok == "" {
		return row{}, false, nil
	}
	var r row
	q := p.core.Select().Columns(r.columns()...).From(TableInvite).Where(sqlb.Eq(InviteTokenHash, auth.HashToken(tok))).Limit(1)
	if err := p.core.One(ctx, q); err != nil {
		if errors.Is(err, sqlb.ErrNoRows) {
			return row{}, false, nil
		}
		return row{}, false, err
	}
	return r, true, nil
}

// open reports whether r can still be used at now.
func (r row) open(now time.Time) bool {
	return r.status == StatusPending && now.Before(r.expiresAt) && (r.maxUses == 0 || r.uses < r.maxUses)
}

// usedBy reports whether userID already used invite id.
func (p *Plugin) usedBy(ctx context.Context, id, userID string) (bool, error) {
	var n int64
	q := p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableUse).
		Where(sqlb.Eq(UseInviteID, id), sqlb.Eq(UseUserID, userID))
	if err := p.core.One(ctx, q); err != nil {
		return false, err
	}
	return n > 0, nil
}

// usesLeft is an invite with no limit or uses below it, the condition the
// spending update repeats.
var usesLeft = sqlb.Or(sqlb.Eq(InviteMaxUses, 0), sqlb.LessExpr(InviteUses, InviteMaxUses))

// ownsEmail reports whether userID has addr among its email identities.
func (p *Plugin) ownsEmail(ctx context.Context, userID, addr string) (bool, error) {
	ids, err := p.core.Identities(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, id := range ids {
		if id.Kind == email.KindEmail && id.Value == addr {
			return true, nil
		}
	}
	return false, nil
}

// use spends one use of the invite of tok for userID. The token is the
// proof, for a private invite too: at sign-up the account has no identity
// yet to compare with the address. The update repeats every condition
// (pending, unexpired, usesLeft), so two sign-ups racing for the last use
// cannot both get it; the use row's key refuses a second use by one user.
// ds:def id=plugin-use-cza5uksu owner=@khanakia stability=stable
func (p *Plugin) use(ctx context.Context, tok auth.Token, userID string, newAccount bool) error {
	r, ok, err := p.find(ctx, tok)
	if err != nil {
		return err
	}
	now := p.core.Now()
	if !ok || !r.open(now) {
		return ErrInvalid
	}
	if used, err := p.usedBy(ctx, r.id, userID); err != nil || used {
		return cmp.Or(err, error(ErrInvalid))
	}
	d := p.core.Dialect()
	n, err := p.core.Exec(ctx, sqlb.NewUpdate(d).Table(TableInvite).
		Set(sqlb.SetExpr(InviteUses, sqlb.Add(InviteUses, sqlb.Param[int64](1)))).
		Where(sqlb.Eq(InviteID, r.id), sqlb.Eq(InviteStatus, StatusPending), sqlb.Greater(InviteExpiresAt, now), usesLeft))
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrInvalid
	}
	if r.maxUses > 0 && r.uses+1 >= r.maxUses {
		if _, err := p.core.Exec(ctx, sqlb.NewUpdate(d).Table(TableInvite).Set(sqlb.Set(InviteStatus, StatusUsed)).
			Where(sqlb.Eq(InviteID, r.id), sqlb.Eq(InviteStatus, StatusPending))); err != nil {
			return err
		}
	}
	if _, err := p.core.Exec(ctx, sqlb.NewInsert(d).Into(TableUse).Row(
		sqlb.Set(UseInviteID, r.id), sqlb.Set(UseUserID, userID), sqlb.Set(UseAt, now))); err != nil {
		return fmt.Errorf("invite: record use: %w", err)
	}
	if p.onAccepted != nil {
		return p.onAccepted(ctx, Accepted{InviteID: r.id, UserID: userID, CreatedBy: r.createdBy, Role: r.role, NewAccount: newAccount})
	}
	return nil
}

// Create creates an invite as the signed-in user.
func (p *Plugin) Create(ctx context.Context, in Request) (Created, error) {
	return p.create.Call(ctx, in)
}

// doCreate checks the request, stores the invite and, for a private one,
// mails the link.
func (p *Plugin) doCreate(ctx context.Context, c *auth.Call, in Request) (Created, error) {
	ttl := p.ttl
	if in.ExpiresIn != 0 {
		ttl = time.Duration(in.ExpiresIn) * time.Second
	}
	if in.ExpiresIn < 0 || ttl > MaxTTL || in.MaxUses < 0 {
		return Created{}, auth.ErrBadRequest
	}
	if p.canCreate != nil {
		if err := p.canCreate(ctx, *c.User, in); err != nil {
			return Created{}, err
		}
	} else if in.Role != "" {
		return Created{}, ErrForbidden
	}
	var addr *string
	maxUses := in.MaxUses
	if in.Email != "" {
		if p.publicOnly {
			return Created{}, ErrForbidden
		}
		v, err := c.Auth.Normalize(email.KindEmail, in.Email)
		if err != nil {
			return Created{}, err
		}
		addr, maxUses = &v, 1
	}
	id, err := c.Auth.NewID(idPrefix)
	if err != nil {
		return Created{}, err
	}
	tok := auth.NewToken()
	now := c.Auth.Now()
	expires := now.Add(ttl)
	ins := sqlb.NewInsert(c.Auth.Dialect()).Into(TableInvite).Row(
		sqlb.Set(InviteID, id), sqlb.Set(InviteTokenHash, auth.HashToken(tok)), sqlb.Set(InviteCreatedBy, c.User.ID),
		sqlb.Set(InviteEmail, addr), sqlb.Set(InviteRole, in.Role), sqlb.Set(InviteMaxUses, maxUses), sqlb.Set(InviteUses, int64(0)),
		sqlb.Set(InviteStatus, StatusPending), sqlb.Set(InviteExpiresAt, expires), sqlb.Set(InviteCreatedAt, now),
	)
	if _, err := c.Auth.Exec(ctx, ins); err != nil {
		return Created{}, err
	}
	link := p.links(tok)
	if addr == nil {
		return Created{ID: id, Token: tok.Wire(), URL: link, ExpiresAt: expires}, nil
	}
	m := auth.Message{Purpose: PurposeInvite, Link: link, DefaultSubject: "You are invited",
		DefaultText: DefaultText(p.inviterName(*c.User), link)}
	if err := c.Auth.Deliver(ctx, auth.Identity{Kind: email.KindEmail, Value: *addr}, m); err != nil {
		return Created{}, err
	}
	return Created{ID: id, ExpiresAt: expires}, nil
}

// inviterName is the name a message or get shows: the user's, unless
// HideInviter.
func (p *Plugin) inviterName(u auth.User) string {
	if !p.shareInviter {
		return ""
	}
	return u.Name
}

// DefaultText is the English body of a private invite's mail when the app's
// mailer has no template for PurposeInvite.
func DefaultText(inviter, link string) string {
	if inviter == "" {
		return "You have been invited. Open this link to accept:\n" + link + "\n"
	}
	return inviter + " invited you. Open this link to accept:\n" + link + "\n"
}

// TokenRequest carries an invite token.
type TokenRequest struct {
	Token auth.WireToken `json:"token"`
}

// View is what get shows the holder of a token.
type View struct {
	Status      Status    `json:"status"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Role        string    `json:"role,omitempty"`
	InviterName string    `json:"inviterName,omitempty"`
	// Private is true for an invite mailed to one address.
	Private bool `json:"private"`
}

// Get shows the invite of tok.
func (p *Plugin) Get(ctx context.Context, tok auth.Token) (View, error) {
	return p.get.Call(ctx, TokenRequest{Token: tok.Wire()})
}

// doGet answers ErrInvalid for an invite that cannot be used, so a page
// shows one "not valid" whatever the reason.
func (p *Plugin) doGet(ctx context.Context, c *auth.Call, in TokenRequest) (View, error) {
	r, ok, err := p.find(ctx, in.Token.Token())
	if err != nil {
		return View{}, err
	}
	if !ok || !r.open(c.Auth.Now()) {
		return View{}, ErrInvalid
	}
	out := View{Status: r.status, ExpiresAt: r.expiresAt, Role: r.role, Private: r.email != nil}
	if p.shareInviter {
		u, err := c.Auth.User(ctx, r.createdBy)
		if err != nil {
			return View{}, err
		}
		out.InviterName = u.Name
	}
	return out, nil
}

// ListRequest pages the caller's invites, newest first.
type ListRequest struct {
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// Invite is one invite in list: its use count, never its token.
type Invite struct {
	ID        string    `json:"id"`
	Email     string    `json:"email,omitempty"`
	Role      string    `json:"role,omitempty"`
	MaxUses   int64     `json:"maxUses"`
	Uses      int64     `json:"uses"`
	Status    Status    `json:"status"`
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
}

// ListResult is a page of list.
type ListResult struct {
	Invites []Invite `json:"invites"`
	Total   int64    `json:"total"`
}

// List returns the signed-in user's invites.
func (p *Plugin) List(ctx context.Context, in ListRequest) (ListResult, error) {
	return p.list.Call(ctx, in)
}

func (p *Plugin) doList(ctx context.Context, c *auth.Call, in ListRequest) (ListResult, error) {
	limit := in.Limit
	if limit <= 0 {
		limit = defaultListLimit
	}
	if limit > MaxListLimit || in.Offset < 0 {
		return ListResult{}, auth.ErrBadRequest
	}
	mine := sqlb.Eq(InviteCreatedBy, c.User.ID)
	out := ListResult{Invites: []Invite{}}
	if err := c.Auth.One(ctx, c.Auth.Select().Columns(sqlb.Bind(sqlb.Count(), &out.Total)).From(TableInvite).Where(mine)); err != nil {
		return ListResult{}, err
	}
	var r row
	q := c.Auth.Select().Columns(r.columns()...).From(TableInvite).Where(mine).
		Order(sqlb.OrderBy(InviteCreatedAt, sqlb.SortDesc), sqlb.OrderBy(InviteID, sqlb.SortDesc)).
		Limit(limit).Offset(in.Offset)
	err := c.Auth.Each(ctx, q, func() error {
		inv := Invite{ID: r.id, Role: r.role, MaxUses: r.maxUses, Uses: r.uses, Status: r.status, ExpiresAt: r.expiresAt, CreatedAt: r.createdAt}
		if r.email != nil {
			inv.Email = *r.email
		}
		out.Invites = append(out.Invites, inv)
		return nil
	})
	if err != nil {
		return ListResult{}, err
	}
	return out, nil
}

// IDRequest names an invite by id.
type IDRequest struct {
	ID string `json:"id"`
}

// Cancel cancels one of the signed-in user's own invites.
func (p *Plugin) Cancel(ctx context.Context, id string) error {
	_, err := p.cancel.Call(ctx, IDRequest{ID: id})
	return err
}

// doCancel cancels a pending invite of the caller's; another user's invite
// answers like an unknown id.
func (p *Plugin) doCancel(ctx context.Context, c *auth.Call, in IDRequest) (auth.Done, error) {
	n, err := c.Auth.Exec(ctx, sqlb.NewUpdate(c.Auth.Dialect()).Table(TableInvite).Set(sqlb.Set(InviteStatus, StatusCanceled)).
		Where(sqlb.Eq(InviteID, in.ID), sqlb.Eq(InviteCreatedBy, c.User.ID), sqlb.Eq(InviteStatus, StatusPending)))
	if err != nil {
		return auth.Done{}, err
	}
	if n != 1 {
		return auth.Done{}, ErrInvalid
	}
	return auth.Done{OK: true}, nil
}

// Reject declines a private invite addressed to the signed-in user.
func (p *Plugin) Reject(ctx context.Context, tok auth.Token) error {
	_, err := p.reject.Call(ctx, TokenRequest{Token: tok.Wire()})
	return err
}

// doReject lets only the addressee of a private invite reject it.
func (p *Plugin) doReject(ctx context.Context, c *auth.Call, in TokenRequest) (auth.Done, error) {
	r, ok, err := p.find(ctx, in.Token.Token())
	if err != nil {
		return auth.Done{}, err
	}
	if !ok || !r.open(c.Auth.Now()) || r.email == nil {
		return auth.Done{}, ErrInvalid
	}
	mine, err := p.ownsEmail(ctx, c.User.ID, *r.email)
	if err != nil {
		return auth.Done{}, err
	}
	if !mine {
		return auth.Done{}, ErrInvalid
	}
	n, err := c.Auth.Exec(ctx, sqlb.NewUpdate(c.Auth.Dialect()).Table(TableInvite).Set(sqlb.Set(InviteStatus, StatusRejected)).
		Where(sqlb.Eq(InviteID, r.id), sqlb.Eq(InviteStatus, StatusPending)))
	if err != nil {
		return auth.Done{}, err
	}
	if n != 1 {
		return auth.Done{}, ErrInvalid
	}
	return auth.Done{OK: true}, nil
}

// Action says what activate did.
type Action string

// The actions, better-invite's.
const (
	// ActionAccepted: the signed-in caller used the invite.
	ActionAccepted Action = "accepted"
	// ActionSignInRequired: the invite waits in the cookie for the visitor
	// to sign up or sign in.
	ActionSignInRequired Action = "sign_in_required"
)

// ActivateResult is the answer of activate.
type ActivateResult struct {
	Action Action `json:"action"`
}

// Activate uses the invite of tok for the signed-in caller, or keeps it in
// the cookie for a signed-out one.
func (p *Plugin) Activate(ctx context.Context, tok auth.Token) (ActivateResult, error) {
	return p.activate.Call(ctx, TokenRequest{Token: tok.Wire()})
}

// doActivate checks the invite first, so a visitor learns at once that a
// link is dead rather than after signing up.
func (p *Plugin) doActivate(ctx context.Context, c *auth.Call, in TokenRequest) (ActivateResult, error) {
	r, ok, err := p.find(ctx, in.Token.Token())
	if err != nil {
		return ActivateResult{}, err
	}
	now := c.Auth.Now()
	if !ok || !r.open(now) {
		return ActivateResult{}, ErrInvalid
	}
	if c.User != nil && c.Session != nil && !c.Session.SecondFactorPending {
		if err := p.use(ctx, in.Token.Token(), c.User.ID, false); err != nil {
			return ActivateResult{}, err
		}
		return ActivateResult{Action: ActionAccepted}, nil
	}
	expires := now.Add(p.cookieTTL)
	if r.expiresAt.Before(expires) {
		expires = r.expiresAt
	}
	if err := c.Effects.SetCookie(CookieName, in.Token.Reveal(), expires); err != nil {
		return ActivateResult{}, err
	}
	return ActivateResult{Action: ActionSignInRequired}, nil
}
