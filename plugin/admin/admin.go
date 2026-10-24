// Package admin gives an app's operators the user operations every product
// needs: find a user, see their identities, ban and unban, end their
// sessions, and grant or remove admin rights.
//
// An admin is a user whose admin_granted_at column is set. The first admin is
// granted from Go (Grant), for example from a one-off command, because no one
// can grant it over HTTP before an admin exists. A ban is a session check: the
// banned user's sessions stop working on their next request, on every
// instance. A ban ends the user's sessions, which evicts their entries from
// a server-side SessionCache (auth.EvictCachedSessions); a client-held cache
// copy keeps working until it expires, within auth.MaxSessionCacheTTL.
package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity.
const PluginName = "admin"

// Operation ids. They are permanent: rate rules, hooks and every transport
// route address an operation by id, so renaming one breaks deployed clients.
const (
	EndpointUsers             auth.EndpointID = "admin.users"
	EndpointSearchUsers       auth.EndpointID = "admin.search-users"
	EndpointUser              auth.EndpointID = "admin.user"
	EndpointBan               auth.EndpointID = "admin.ban"
	EndpointUnban             auth.EndpointID = "admin.unban"
	EndpointRevokeSessions    auth.EndpointID = "admin.revoke-sessions"
	EndpointSetAdmin          auth.EndpointID = "admin.set-admin"
	EndpointImpersonate       auth.EndpointID = "admin.impersonate"
	EndpointStopImpersonating auth.EndpointID = "admin.stop-impersonating"
	EndpointUpdateUser        auth.EndpointID = "admin.update-user"
	EndpointSessions          auth.EndpointID = "admin.sessions"
	EndpointRevokeSession     auth.EndpointID = "admin.revoke-session"
	EndpointRemoveUser        auth.EndpointID = "admin.remove-user"
	EndpointCreateUser        auth.EndpointID = "admin.create-user"
	EndpointSetPassword       auth.EndpointID = "admin.set-password"
	EndpointSetEmail          auth.EndpointID = "admin.set-email"
	EndpointAudit             auth.EndpointID = "admin.audit"
)

// Columns this plugin adds to auth_user, prefixed with the plugin name so no
// other plugin's column can collide with them.
const (
	ColGrantedAt    = "admin_granted_at"
	ColBannedAt     = "admin_banned_at"
	ColBanReason    = "admin_ban_reason"
	ColBanExpiresAt = "admin_ban_expires_at"
)

// Typed columns on auth_user, for an app that filters or shows users by
// admin or ban state in its own queries.
var (
	GrantedAt    = sqlb.Col[*time.Time](auth.TableUser, ColGrantedAt)
	BannedAt     = sqlb.Col[*time.Time](auth.TableUser, ColBannedAt)
	BanReason    = sqlb.Col[string](auth.TableUser, ColBanReason)
	BanExpiresAt = sqlb.Col[*time.Time](auth.TableUser, ColBanExpiresAt)
)

// AdminColumns is this plugin's flat part of a composite user. Flat rather
// than nested because the columns live on auth_user itself (ADR-0001); nil
// times mean "never granted" and "not banned".
type AdminColumns struct {
	AdminGrantedAt *time.Time
	BannedAt       *time.Time
	BanReason      string
	// BanExpiresAt is nil for a ban that lasts until unban. A ban whose
	// expiry has passed no longer blocks sessions; the row keeps the dates so
	// the history stays readable.
	BanExpiresAt *time.Time
	// Role is the stored admin roles, comma-joined; "" for none (the flag
	// and DefaultRole then decide, see RolesOf).
	Role string
}

// Bindings binds AdminColumns, for a composite user query or LoadUserColumns.
func Bindings(c *AdminColumns) []sqlb.Binding {
	return []sqlb.Binding{sqlb.Bind(GrantedAt, &c.AdminGrantedAt), sqlb.Bind(BannedAt, &c.BannedAt), sqlb.Bind(BanReason, &c.BanReason), sqlb.Bind(BanExpiresAt, &c.BanExpiresAt), sqlb.Bind(UserRole, &c.Role)}
}

// Paging bounds for the user list.
const (
	// DefaultPageSize is the page an admin screen gets when it names none
	// and the app set no auth.WithDefaultPageSize: one screenful of rows.
	//ds:def id=defaultpagesize-k5wq5psj owner=@khanakia stability=stable
	DefaultPageSize = 50
	// MaxPageSize caps a requested page, so one request cannot read the whole
	// user table; a larger limit is clamped rather than refused.
	//ds:def id=maxpagesize-9qpk2wp4 owner=@khanakia stability=stable
	MaxPageSize = 200
	// maxReasonLength fits the ban reason column on every engine: a text
	// column is VARCHAR(320) on MySQL, counted in characters.
	//ds:def id=maxreasonlength-s6upfze5 owner=@khanakia stability=stable
	maxReasonLength = 300
)

// Errors a client may see. Each carries a stable code for programmatic checks.
var (
	// ErrForbidden refuses a caller who is not an admin. It is checked before
	// the target is looked up, so it never reveals whether a user exists.
	ErrForbidden = auth.NewError("admin.forbidden", http.StatusForbidden, "Only an administrator can do this.")
	// ErrAdminTarget refuses to ban or impersonate an admin: a stolen admin
	// session must not be able to lock out or act as the other admins.
	// AllowImpersonatingAdmins lifts it for impersonation only.
	ErrAdminTarget = auth.NewError("admin.admin_target", http.StatusConflict, "Remove this user's admin rights first.")
	// ErrBannedTarget refuses to impersonate a banned user, whose sessions the
	// ban exists to stop.
	ErrBannedTarget = auth.NewError("admin.banned_target", http.StatusConflict, "This user is banned.")
	// ErrLastAdmin refuses to remove the last admin, which would leave nobody
	// able to grant the rights back over HTTP.
	ErrLastAdmin = auth.NewError("admin.last_admin", http.StatusConflict, "Keep at least one administrator.")
	// ErrBadSort refuses a users sort outside UserSortValues.
	ErrBadSort = auth.NewError("admin.bad_sort", http.StatusBadRequest, "This sort order does not exist.")
	// ErrBadFilter refuses a users filter that is neither FlagTrue, FlagFalse
	// nor empty.
	ErrBadFilter = auth.NewError("admin.bad_filter", http.StatusBadRequest, "A filter is true, false or absent.")
	// ErrBanned refuses a banned user at sign-in, on every sign-in method. It
	// is raised only after the credential was proven (the session is about to
	// be created), so it tells a stranger nothing: without the password, the
	// code or the link they never get this far. BannedMessage changes the text.
	ErrBanned = auth.NewError("admin.banned", http.StatusForbidden, DefaultBannedMessage)
	// ErrNoPasswordPlugin refuses set-password, and create-user with a
	// password, when no registered plugin can store one.
	ErrNoPasswordPlugin = auth.NewError("admin.no_password_plugin", http.StatusConflict, "No password plugin is registered.")
	// ErrNoEmailPlugin refuses set-email and create-user when no registered
	// plugin can give a user an email address.
	ErrNoEmailPlugin = auth.NewError("admin.no_email_plugin", http.StatusConflict, "No email plugin is registered.")
	// ErrEmailRequired refuses create-user without an address: a user with no
	// identifier could never sign in or be found.
	ErrEmailRequired = auth.NewError("admin.email_required", http.StatusBadRequest, "An email address is required.")
	// ErrNoAuditPlugin refuses the audit route when no audit log with a read
	// side (EventQuerier) is registered: there is no log to read.
	ErrNoAuditPlugin = auth.NewError("admin.no_audit_plugin", http.StatusConflict, "No audit plugin is registered.")
	// ErrBadSearchField refuses a search field outside SearchFieldValues.
	ErrBadSearchField = auth.NewError("admin.bad_search_field", http.StatusBadRequest, "This search field does not exist.")
	// ErrBadSearchOperator refuses a search operator outside
	// SearchOperatorValues.
	ErrBadSearchOperator = auth.NewError("admin.bad_search_operator", http.StatusBadRequest, "This search operator does not exist.")
	// ErrSearchValue refuses an empty search, which would be the plain list
	// under another name, and one longer than MaxSearchLength, which no
	// stored value can contain.
	ErrSearchValue = auth.NewError("admin.search_value", http.StatusBadRequest, "Search for one to 320 characters.")
	// ErrSelfTarget refuses an admin impersonating themselves once
	// AllowImpersonatingAdmins is on (without it, ErrAdminTarget answers
	// first): it shows nothing new and would only rotate their own session.
	ErrSelfTarget = auth.NewError("admin.self_target", http.StatusConflict, "You cannot do this to yourself.")
)

// Search bounds and its rate rule.
const (
	// MaxSearchLength is the longest search value, in characters: the widest
	// text column the search reads (an address in auth_identity.value) holds
	// 320 characters on MySQL, so a longer fragment can match nothing.
	//ds:def id=maxsearchlength-r7d4kq2n owner=@khanakia stability=stable
	MaxSearchLength = 320
	// DefaultSearchLimit and DefaultSearchWindow bound search-users per client
	// IP: 30 searches a minute is a person typing into a search box, and keeps
	// a stolen admin session from walking the user table by fragment at
	// machine speed. SearchRate replaces them. Go API calls carry no IP and
	// are not counted, as with every ByIP rule.
	//ds:def id=defaultsearchlimit-p3w8zn6c owner=@khanakia stability=stable
	DefaultSearchLimit  = 30
	DefaultSearchWindow = time.Minute
)

// DefaultBannedMessage is what a banned user reads at sign-in when
// BannedMessage is not configured.
//
//ds:def id=defaultbannedmessage-wjzk8uve owner=@khanakia stability=stable
const DefaultBannedMessage = "This account is banned."

// Ban describes a ban in force, for a BannedMessage function.
type Ban struct {
	UserID    string
	Reason    string
	BannedAt  time.Time
	ExpiresAt *time.Time
}

// PasswordSetter is what the admin plugin needs from a password plugin to set
// a user's password: the method `*password.Plugin` already has. Found through
// auth.PluginOf at Init, so the admin plugin imports no other module and an
// app registers nothing extra.
type PasswordSetter interface {
	auth.Plugin
	SetPassword(ctx context.Context, userID string, password auth.Token) error
}

// EmailSetter is what the admin plugin needs from an identifier plugin to give
// a user an address: `*email.Plugin` has it. Found through auth.PluginOf.
type EmailSetter interface {
	auth.Plugin
	SetFor(ctx context.Context, userID, address string, verified bool) error
}

// EventRecorder is what the admin plugin needs from an audit log to record a
// ban made from Go (BanFor), which no operation hook sees: the method
// `*audit.Plugin` already has. Found through auth.PluginOf at Init, so any
// audit implementation with this method is used, and an app without one
// records nothing extra.
type EventRecorder interface {
	auth.Plugin
	Record(ctx context.Context, e audit.Event) error
}

// EventQuerier is what the admin plugin needs from an audit log to serve the
// audit route: the method `*audit.Plugin` already has. Found through
// auth.PluginOf at Init; without one the route answers ErrNoAuditPlugin.
type EventQuerier interface {
	auth.Plugin
	Events(ctx context.Context, q audit.Query) (audit.Page, error)
}

// Plugin is the admin plugin. Build it with New; the zero value has no
// operations.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs auth.OptionErrors
	core    *auth.Auth

	// adminIDs are users who are admins without a grant row (AdminIDs).
	adminIDs map[string]bool
	// authorizer decides every permission (WithAuthorizer; the built-in
	// roles by default); adminRoles and defaultRole name roles it defines
	// (AdminRoles, DefaultRole).
	authorizer  Authorizer
	adminRoles  []string
	defaultRole string
	// defaultBanReason is stored when a ban names none (DefaultBanReason).
	defaultBanReason string
	// defaultBanTTL bounds a ban whose request names no duration; zero means
	// until unban (DefaultBanDuration).
	defaultBanTTL time.Duration
	// impersonationTTL is the length of an impersonation whose request names
	// no minutes; zero leaves it to the core cap (ImpersonationTTL).
	impersonationTTL time.Duration
	// bannedMessage composes the text of ErrBanned at sign-in; nil means
	// DefaultBannedMessage (BannedMessage).
	bannedMessage func(ctx context.Context, b Ban) string
	// passwords and emails are the registered plugins that can set a password
	// and an address, found at Init; nil when none is registered.
	passwords PasswordSetter
	emails    EmailSetter
	// recorder and querier are the registered audit log's write and read
	// sides, found at Init; nil when none is registered.
	recorder EventRecorder
	querier  EventQuerier
	// twoFactor is the registered second-factor plugin's admin side, found
	// at Init; nil when none is registered (TwoFactorManager).
	twoFactor TwoFactorManager
	// searchLimit and searchWindow are the ByIP rule on search-users
	// (SearchRate); the defaults are DefaultSearchLimit per
	// DefaultSearchWindow.
	searchLimit  int
	searchWindow time.Duration
	// impersonateAdmins lets an admin impersonate another admin
	// (AllowImpersonatingAdmins); false refuses with ErrAdminTarget.
	impersonateAdmins bool
	// editable is the app columns update-user's data may set, by name
	// (EditableColumns).
	editable map[string]EditableColumn

	allSessions       *auth.Op[AllSessionsRequest, AllSessionsResult]
	createUser        *auth.Op[CreateUserRequest, CreateUserResult]
	setPassword       *auth.Op[SetPasswordRequest, auth.Done]
	setEmail          *auth.Op[SetEmailRequest, auth.Done]
	audit             *auth.Op[audit.Query, audit.Page]
	updateUser        *auth.Op[UpdateUserRequest, auth.Done]
	sessions          *auth.Op[UserRequest, SessionsResult]
	revokeSession     *auth.Op[RevokeSessionRequest, auth.Done]
	removeUser        *auth.Op[UserRequest, auth.Done]
	users             *auth.Op[UsersRequest, UsersResult]
	searchUsers       *auth.Op[SearchUsersRequest, UsersResult]
	user              *auth.Op[UserRequest, UserDetail]
	ban               *auth.Op[BanRequest, auth.Done]
	unban             *auth.Op[UserRequest, auth.Done]
	revokeSessions    *auth.Op[UserRequest, auth.Done]
	setAdmin          *auth.Op[SetAdminRequest, auth.Done]
	impersonate       *auth.Op[ImpersonateRequest, ImpersonateResult]
	stopImpersonating *auth.Op[struct{}, StopResult]
	setRole           *auth.Op[SetRoleRequest, auth.Done]
	hasPermission     *auth.Op[PermissionRequest, PermissionResult]
	twoFactorOf       *auth.Op[UserRequest, TwoFactorResult]
	disableTwoFactor  *auth.Op[UserRequest, auth.Done]
	enableTwoFactor   *auth.Op[UserRequest, auth.Done]
	resetTwoFactor    *auth.Op[UserRequest, auth.Done]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

var (
	_ auth.ColumnExtender    = (*Plugin)(nil)
	_ auth.SessionChecker    = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.DataHooker        = (*Plugin)(nil)
	_ auth.RateLimiter       = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
)

// Option configures the plugin; pass options to New.
type Option func(*Plugin)

// AdminIDs makes the listed users admins without a grant row, for a deploy
// whose operators are fixed in configuration. They may still be granted and
// removed like anyone else; the list only adds to what admin_granted_at says.
// A listed user cannot be banned, impersonated or removed, like any admin.
func AdminIDs(ids ...string) Option {
	return func(p *Plugin) {
		for _, id := range ids {
			p.adminIDs[id] = true
		}
	}
}

// DefaultBanReason is stored when a ban request names no reason, so a list of
// banned users never shows an empty cell. It is cut like a given reason.
func DefaultBanReason(reason string) Option { return func(p *Plugin) { p.defaultBanReason = reason } }

// DefaultBanDuration bounds a ban whose request names no minutes: it lifts
// itself after d. Without it such a ban lasts until unban, which is today's
// behaviour and stays the default.
func DefaultBanDuration(d time.Duration) Option { return func(p *Plugin) { p.defaultBanTTL = d } }

// ImpersonationTTL is how long an impersonation lasts when the request names
// no minutes. The core still caps every impersonation at
// auth.MaxImpersonationTTL, so this can only shorten the default, never
// extend the cap.
func ImpersonationTTL(d time.Duration) Option { return func(p *Plugin) { p.impersonationTTL = d } }

// BannedMessage sets the text a banned user reads at sign-in, from the ban
// itself: "Banned for chargeback until 3 May", say. The error code stays
// admin.banned. An empty result falls back to DefaultBannedMessage, so a
// function that has nothing to say never produces a blank refusal.
func BannedMessage(fn func(ctx context.Context, b Ban) string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("admin.BannedMessage", fn) {
			return
		}
		p.bannedMessage = fn
	}
}

// SearchRate replaces the per-IP limit on search-users: at most limit searches
// per window from one client address. auth.New refuses a limit below one, so
// the search can be loosened but never left unlimited.
func SearchRate(limit int, window time.Duration) Option {
	return func(p *Plugin) { p.searchLimit, p.searchWindow = limit, window }
}

// AllowImpersonatingAdmins lets an admin impersonate another admin, which is
// refused by default (ErrAdminTarget). Everything else about impersonation
// stays: a fresh sign-in, the TTL and its cap, the audit record, no
// FreshSignIn operation while acting, and the way back to the admin's own
// session. The impersonation session cannot use the admin operations either,
// so acting as an admin never chains into acting as a third user.
//
// The risk is the reason it is opt-in: with it, one stolen admin session can
// act as every other admin, so a compromise of the least careful admin is a
// compromise of all of them. Turn it on only where every admin is equally
// trusted and an admin needs to see another admin's account as they see it.
func AllowImpersonatingAdmins() Option { return func(p *Plugin) { p.impersonateAdmins = true } }

// New builds the plugin. Who is an admin is data (admin_granted_at); the
// options only add fixed admins and defaults for bans and impersonations.
func New(opts ...Option) *Plugin {
	p := &Plugin{adminIDs: map[string]bool{}, searchLimit: DefaultSearchLimit, searchWindow: DefaultSearchWindow,
		authorizer: newDefaultAuthorizer(), adminRoles: []string{RoleAdmin}, defaultRole: RoleUser, editable: map[string]EditableColumn{}}
	for _, o := range opts {
		o(p)
	}
	p.allSessions = auth.Define(auth.OpInfo{ID: EndpointAllSessions, Kind: auth.Query, Require: auth.SignedIn, Path: "/all-sessions"}, p.doAllSessions)
	p.createUser = auth.Define(auth.OpInfo{ID: EndpointCreateUser, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/create-user"}, p.doCreateUser)
	p.setPassword = auth.Define(auth.OpInfo{ID: EndpointSetPassword, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/set-password"}, p.doSetPassword)
	p.setEmail = auth.Define(auth.OpInfo{ID: EndpointSetEmail, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/set-email"}, p.doSetEmail)
	p.audit = auth.Define(auth.OpInfo{ID: EndpointAudit, Kind: auth.Query, Require: auth.SignedIn, Path: "/audit"}, p.doAudit)
	p.updateUser = auth.Define(auth.OpInfo{ID: EndpointUpdateUser, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/update-user"}, p.doUpdateUser)
	p.sessions = auth.Define(auth.OpInfo{ID: EndpointSessions, Kind: auth.Query, Require: auth.SignedIn, Path: "/sessions"}, p.doSessions)
	p.revokeSession = auth.Define(auth.OpInfo{ID: EndpointRevokeSession, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/revoke-session"}, p.doRevokeSession)
	p.removeUser = auth.Define(auth.OpInfo{ID: EndpointRemoveUser, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/remove-user"}, p.doRemoveUser)
	p.users = auth.Define(auth.OpInfo{ID: EndpointUsers, Kind: auth.Query, Require: auth.SignedIn, Path: "/users"}, p.doUsers)
	p.searchUsers = auth.Define(auth.OpInfo{ID: EndpointSearchUsers, Kind: auth.Query, Require: auth.SignedIn, Path: "/search-users"}, p.doSearchUsers)
	p.user = auth.Define(auth.OpInfo{ID: EndpointUser, Kind: auth.Query, Require: auth.SignedIn, Path: "/user"}, p.doUser)
	p.ban = auth.Define(auth.OpInfo{ID: EndpointBan, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/ban"}, p.doBan)
	p.unban = auth.Define(auth.OpInfo{ID: EndpointUnban, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/unban"}, p.doUnban)
	p.revokeSessions = auth.Define(auth.OpInfo{ID: EndpointRevokeSessions, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/revoke-sessions"}, p.doRevokeSessions)
	p.setAdmin = auth.Define(auth.OpInfo{ID: EndpointSetAdmin, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/set-admin"}, p.doSetAdmin)
	p.impersonate = auth.Define(auth.OpInfo{ID: EndpointImpersonate, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/impersonate"}, p.doImpersonate)
	p.stopImpersonating = auth.Define(auth.OpInfo{ID: EndpointStopImpersonating, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/stop-impersonating"}, p.doStopImpersonating)
	p.setRole = auth.Define(auth.OpInfo{ID: EndpointSetRole, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/set-role"}, p.doSetRole)
	p.hasPermission = auth.Define(auth.OpInfo{ID: EndpointHasPermission, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/has-permission"}, p.doHasPermission)
	p.twoFactorOf = auth.Define(auth.OpInfo{ID: EndpointTwoFactor, Kind: auth.Query, Require: auth.SignedIn, Path: "/two-factor"}, p.doTwoFactor)
	p.disableTwoFactor = auth.Define(auth.OpInfo{ID: EndpointDisableTwoFactor, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/disable-two-factor"}, p.doDisableTwoFactor)
	p.enableTwoFactor = auth.Define(auth.OpInfo{ID: EndpointEnableTwoFactor, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/enable-two-factor"}, p.doEnableTwoFactor)
	p.resetTwoFactor = auth.Define(auth.OpInfo{ID: EndpointResetTwoFactor, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/reset-two-factor"}, p.doResetTwoFactor)
	return p
}

// Name identifies the plugin.
func (p *Plugin) Name() string { return PluginName }

// Init captures the core and finds the plugins that can set a password and
// an address. Their absence is not an error here: an app without passwords
// still gets every other admin operation, and set-password tells the caller.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	// Found by method set, so a plugin of this package whose Go API grew a
	// matching method would be found too, and would call itself: skip
	// ourselves, whatever the method names are.
	if ps, err := auth.PluginOf[PasswordSetter](a); err == nil && auth.Plugin(ps) != auth.Plugin(p) {
		p.passwords = ps
	}
	if es, err := auth.PluginOf[EmailSetter](a); err == nil && auth.Plugin(es) != auth.Plugin(p) {
		p.emails = es
	}
	if er, err := auth.PluginOf[EventRecorder](a); err == nil && auth.Plugin(er) != auth.Plugin(p) {
		p.recorder = er
	}
	if eq, err := auth.PluginOf[EventQuerier](a); err == nil && auth.Plugin(eq) != auth.Plugin(p) {
		p.querier = eq
	}
	if tf, err := auth.PluginOf[TwoFactorManager](a); err == nil && auth.Plugin(tf) != auth.Plugin(p) {
		p.twoFactor = tf
	}
	return nil
}

// Operations lists every operation.
func (p *Plugin) Operations() []auth.Operation {
	return []auth.Operation{p.users, p.searchUsers, p.user, p.ban, p.unban, p.revokeSessions, p.setAdmin, p.impersonate, p.stopImpersonating, p.updateUser, p.sessions, p.revokeSession, p.removeUser, p.createUser, p.setPassword, p.setEmail, p.audit, p.setRole, p.hasPermission, p.allSessions,
		p.twoFactorOf, p.disableTwoFactor, p.enableTwoFactor, p.resetTwoFactor}
}

// RateLimits puts the search-users rule (SearchRate) on the one admin
// operation that reads users by fragment.
func (p *Plugin) RateLimits() []auth.RateRule {
	return []auth.RateRule{{Match: EndpointSearchUsers, Key: auth.ByIP, Limit: p.searchLimit, Window: p.searchWindow}}
}

// DataHooks refuse to create a session for a banned user. The hook sits on
// the session write rather than on any sign-in operation, so it covers every
// method — password, code, link, passkey, OAuth, a pending second-factor
// session — and a method added later. It fires only after the method proved
// the credential, which is what keeps the refusal enumeration-safe: a
// stranger who does not hold the credential never reaches it, and sees the
// same wrong-credential answer as for any other account.
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{Session: auth.TableHooks[auth.Session]{BeforeCreate: p.refuseBanned}}
}

func (p *Plugin) refuseBanned(ctx context.Context, _ sqlb.DBTX, row *auth.Session) error {
	cols, err := p.columnsOf(ctx, row.UserID)
	if err != nil {
		return err
	}
	now := p.core.Now()
	if !isBanned(cols, now) {
		return nil
	}
	msg := ""
	if p.bannedMessage != nil {
		msg = p.bannedMessage(ctx, Ban{UserID: row.UserID, Reason: cols.BanReason, BannedAt: *cols.BannedAt, ExpiresAt: cols.BanExpiresAt})
	}
	if msg == "" {
		return ErrBanned
	}
	return &auth.Error{Code: ErrBanned.Code, Status: ErrBanned.Status, Message: msg}
}

// sqlEmptyString is the SQL literal default of a NOT NULL text column, so
// rows that existed before the column was added read as "" rather than failing
// the migration.
const sqlEmptyString = "''"

// Columns adds the admin and ban columns to auth_user.
func (p *Plugin) Columns() []auth.ColumnExtension {
	return []auth.ColumnExtension{
		{Table: auth.TableNameUser, Name: ColGrantedAt, Type: auth.ColumnTimestamp, Nullable: true},
		{Table: auth.TableNameUser, Name: ColBannedAt, Type: auth.ColumnTimestamp, Nullable: true},
		{Table: auth.TableNameUser, Name: ColBanReason, Type: auth.ColumnText, Default: sqlEmptyString},
		{Table: auth.TableNameUser, Name: ColBanExpiresAt, Type: auth.ColumnTimestamp, Nullable: true},
		{Table: auth.TableNameUser, Name: ColRole, Type: auth.ColumnText, Default: sqlEmptyString},
	}
}

// SessionPredicates refuses every session of a banned user. It is evaluated
// per lookup, so a ban with an expiry stops blocking the moment it passes.
//
//ds:def id=plugin-sessionpredicates-smtxeyuk owner=@khanakia stability=stable
func (p *Plugin) SessionPredicates() []sqlb.Predicate {
	return []sqlb.Predicate{notBanned(p.core.Now())}
}

// notBanned is true for a user with no ban, or a ban whose expiry has passed
// at now. It is the one definition of "banned" the plugin uses, in the session
// check, the users filter and the summary, so the three cannot disagree.
func notBanned(now time.Time) sqlb.Predicate {
	return sqlb.Or(sqlb.IsNull(BannedAt), sqlb.And(sqlb.IsNotNull(BanExpiresAt), sqlb.LessEq(BanExpiresAt, &now)))
}

// banned is the negation of notBanned.
func banned(now time.Time) sqlb.Predicate {
	return sqlb.And(sqlb.IsNotNull(BannedAt), sqlb.Or(sqlb.IsNull(BanExpiresAt), sqlb.Greater(BanExpiresAt, &now)))
}

// isBanned reports whether c describes a ban in force at now; the Go twin of
// banned, for a row already loaded.
func isBanned(c AdminColumns, now time.Time) bool {
	return c.BannedAt != nil && (c.BanExpiresAt == nil || c.BanExpiresAt.After(now))
}

// isAdmin reports whether userID is an admin: granted, listed by AdminIDs,
// or holding one of AdminRoles.
func (p *Plugin) isAdmin(userID string, c AdminColumns) bool {
	return c.AdminGrantedAt != nil || p.adminIDs[userID] || slices.ContainsFunc(splitRoles(c.Role), p.isAdminRole)
}

// Validate refuses a missing authorizer and role names it does not define.
func (p *Plugin) Validate(*auth.Config) error {
	// The plugin refuses its own SearchRate before the core's generic rate
	// check does, so the error names the option to fix.
	if p.searchLimit < 1 || p.searchWindow <= 0 {
		return fmt.Errorf("%w: admin.SearchRate(%d, %v): the limit and the window must both be positive",
			auth.ErrBadOperation, p.searchLimit, p.searchWindow)
	}
	return p.validateRoles()
}

// Grant makes userID an admin, from Go only. It is how the first admin is
// made; afterwards admins grant each other through set-admin.
//
//ds:def id=plugin-grant-x65z5qqa owner=@khanakia stability=stable
func (p *Plugin) Grant(ctx context.Context, userID string) error {
	if _, err := p.core.User(ctx, userID); err != nil {
		return err
	}
	now := p.core.Now()
	return auth.SetUserColumn(ctx, p.core, PluginName, userID, GrantedAt, &now)
}

func (p *Plugin) columnsOf(ctx context.Context, userID string) (AdminColumns, error) {
	var c AdminColumns
	err := p.core.LoadUserColumns(ctx, userID, Bindings(&c)...)
	return c, err
}

// UsersRequest pages through users. Query, when set, is an identifier (an
// address, a number, a handle) or a user id, matched exactly. A fragment
// search is search-users (SearchUsersRequest), a separate operation with its
// own rate rule, because matching fragments of addresses turns an admin
// session into an enumeration tool and that deserves its own budget.
type UsersRequest struct {
	Query string `json:"query,omitempty"`
	// Page starts at 1. Strings in JSON, because a Query operation's input
	// arrives as URL query values. Offset, when set, replaces Page: it is the
	// number of rows to skip, for a client that pages by offset.
	Page   int `json:"page,omitempty,string"`
	Limit  int `json:"limit,omitempty,string"`
	Offset int `json:"offset,omitempty,string"`
	// Sort is one of UserSortValues; empty means UserSortNewest, unless
	// SortBy is set.
	Sort UserSort `json:"sort,omitempty"`
	// SortBy and SortDirection sort by one user field: SortBy is one of
	// SortFieldValues, ascending unless SortDesc. SortBy and Sort
	// together are ErrBadSort.
	SortBy        SortField     `json:"sortBy,omitempty"`
	SortDirection SortDirection `json:"sortDirection,omitempty"`
	// Admin and Banned narrow the list to admins (or non-admins) and to users
	// whose ban is in force (or not). Empty means no filter.
	Admin  Flag `json:"admin,omitempty"`
	Banned Flag `json:"banned,omitempty"`
	// FilterField, FilterOperator and FilterValue are a single field
	// filter: the field defaults to FilterEmail and the operator to
	// FilterEq; nil FilterValue filters nothing (a field or operator that
	// does not exist is refused even then). in and not_in take values
	// joined by FilterListSeparator; a time is RFC 3339; a flag is true or
	// false.
	FilterField    FilterField    `json:"filterField,omitempty"`
	FilterOperator FilterOperator `json:"filterOperator,omitempty"`
	FilterValue    *string        `json:"filterValue,omitempty"`
}

// UserSort orders the users list. A closed set rather than a column name, so
// the list can never be sorted by a column the admin should not see.
type UserSort string

// Sort orders of the users list.
const (
	// UserSortNewest is the default: newest sign-ups first.
	UserSortNewest   UserSort = "created_desc"
	UserSortOldest   UserSort = "created_asc"
	UserSortNameAsc  UserSort = "name_asc"
	UserSortNameDesc UserSort = "name_desc"
)

// UserSortValues is the canonical list of sort orders.
var UserSortValues = []UserSort{UserSortNewest, UserSortOldest, UserSortNameAsc, UserSortNameDesc}

// Flag is a three-valued filter in a query string: FlagTrue, FlagFalse or
// empty for "do not filter". A string rather than *bool because the input
// arrives as URL query values.
type Flag string

// Flag values.
const (
	FlagTrue  Flag = "true"
	FlagFalse Flag = "false"
)

// FlagValues are the two set values; empty is the third state.
var FlagValues = []Flag{FlagTrue, FlagFalse}

// order returns the ORDER BY terms for s. The id is always the last term so
// pages are stable when two rows share a value.
func (s UserSort) order() ([]sqlb.OrderTerm, error) {
	switch s {
	case "", UserSortNewest:
		return []sqlb.OrderTerm{sqlb.OrderBy(auth.UserCreatedAt, sqlb.SortDesc), sqlb.OrderBy(auth.UserID, sqlb.SortAsc)}, nil
	case UserSortOldest:
		return []sqlb.OrderTerm{sqlb.OrderBy(auth.UserCreatedAt, sqlb.SortAsc), sqlb.OrderBy(auth.UserID, sqlb.SortAsc)}, nil
	case UserSortNameAsc:
		return []sqlb.OrderTerm{sqlb.OrderBy(auth.UserName, sqlb.SortAsc), sqlb.OrderBy(auth.UserID, sqlb.SortAsc)}, nil
	case UserSortNameDesc:
		return []sqlb.OrderTerm{sqlb.OrderBy(auth.UserName, sqlb.SortDesc), sqlb.OrderBy(auth.UserID, sqlb.SortAsc)}, nil
	}
	return nil, ErrBadSort
}

// predicate turns a flag into the predicate for the set state, or nil for
// the empty one.
func (f Flag) predicate(whenTrue, whenFalse sqlb.Predicate) (sqlb.Predicate, error) {
	switch f {
	case "":
		return nil, nil
	case FlagTrue:
		return whenTrue, nil
	case FlagFalse:
		return whenFalse, nil
	}
	return nil, ErrBadFilter
}

// UserSummary is one row of the list: only what an admin needs to pick a
// user, so a page of them leaks no identifiers.
type UserSummary struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
	Admin     bool      `json:"admin"`
	Banned    bool      `json:"banned"`
	// Email is the user's primary email address, or their earliest email
	// identity when none is primary yet (an address awaiting verification),
	// or "" when they have none. Loaded for the whole page in one query
	// (withEmails), never per row.
	Email string `json:"email"`
	// Roles is every role the user holds by rolesOf's rules: the stored
	// ones, the flag's admin role, or DefaultRole when they have none. Read
	// from the same row as the rest of the summary, so it costs no query.
	Roles []string `json:"roles"`
	// LastActiveAt is the user's most recent session activity, derived from
	// the sessions rather than kept in a column that every request would
	// write; nil when no session record is left. See lastActive for how far
	// back it reaches.
	LastActiveAt *time.Time `json:"lastActiveAt"`
}

// UsersResult is one page. Total counts every match, for a pager; Page and
// Limit are the values actually used after defaults and clamping.
type UsersResult struct {
	Users []UserSummary `json:"users"`
	Total int64         `json:"total"`
	Page  int           `json:"page"`
	Limit int           `json:"limit"`
	// Offset is the number of rows skipped, as actually used.
	Offset int `json:"offset"`
}

// UserRequest names a user, as the input of user, unban and revoke-sessions.
type UserRequest struct {
	UserID string `json:"userId"`
}

// TargetUserID names the user the request is about, for the audit log
// (audit.Targeted). Every admin request that names a user implements it, so an
// event's subject is the user acted on rather than the admin acting.
func (r UserRequest) TargetUserID() string          { return r.UserID }
func (r BanRequest) TargetUserID() string           { return r.UserID }
func (r UpdateUserRequest) TargetUserID() string    { return r.UserID }
func (r RevokeSessionRequest) TargetUserID() string { return r.UserID }
func (r SetAdminRequest) TargetUserID() string      { return r.UserID }
func (r SetPasswordRequest) TargetUserID() string   { return r.UserID }
func (r SetEmailRequest) TargetUserID() string      { return r.UserID }
func (r ImpersonateRequest) TargetUserID() string   { return r.UserID }

// UserDetail is one user with identities and live session count, for an
// admin deciding whether to ban or end sessions.
type UserDetail struct {
	User       UserSummary    `json:"user"`
	BanReason  string         `json:"banReason"`
	Identities []IdentityView `json:"identities"`
	Sessions   int            `json:"sessions"`
}

// IdentityView is one identity as an admin sees it.
type IdentityView struct {
	Kind     auth.IdentifierKindName `json:"kind"`
	Value    string                  `json:"value"`
	Verified bool                    `json:"verified"`
	Primary  bool                    `json:"primary"`
}

// BanRequest bans a user. Reason is cut to whole characters that fit the
// column on every engine rather than refused. Minutes, when positive, makes
// the ban lift itself after that long; zero means DefaultBanDuration, or
// until unban when none is configured.
type BanRequest struct {
	UserID  string `json:"userId"`
	Reason  string `json:"reason,omitempty"`
	Minutes int    `json:"minutes,omitempty"`
}

// UpdateUserRequest is the input of update-user. A nil field is left as it
// is; the same limits as the user's own profile update apply.
type UpdateUserRequest struct {
	UserID string  `json:"userId"`
	Name   *string `json:"name,omitempty"`
	Image  *string `json:"image,omitempty"`
	// Data is the data object: name and image (DataName,
	// DataImage, overriding the fields above), and the app columns declared
	// with EditableColumns. Any other key is ErrFieldNotEditable, an empty
	// object ErrNoUserData; nil sets only Name and Image.
	Data map[string]json.RawMessage `json:"data,omitempty"`
}

// RevokeSessionRequest names one session of a user, as the input of
// revoke-session. The user id is required so a session id alone, which the
// user's own list shows, cannot be used against another user.
type RevokeSessionRequest struct {
	UserID    string `json:"userId"`
	SessionID string `json:"sessionId"`
}

// SessionsResult is the output of sessions: another user's sessions as the
// user would see them, with Current always false.
type SessionsResult struct {
	Sessions []auth.SessionView `json:"sessions"`
}

// SetAdminRequest grants (Admin true) or removes admin rights. Either is a
// no-op when the user already has the requested state.
type SetAdminRequest struct {
	UserID string `json:"userId"`
	Admin  bool   `json:"admin"`
}

// CreateUserRequest is the input of create-user: a profile, one email
// address, and optionally a password. Email is required because a user with
// no identifier could never sign in or be found. Verified true marks the
// address verified and primary at once, for an admin who knows it is the
// person's; false sends the usual verify link. Password is optional: without
// one the user sets theirs through the forgot flow. The password is an
// auth.Token so a logged request never shows it.
type CreateUserRequest struct {
	Name     string     `json:"name,omitempty"`
	Image    string     `json:"image,omitempty"`
	Email    string     `json:"email"`
	Verified bool       `json:"verified,omitempty"`
	Password auth.Token `json:"password,omitempty"`
}

// CreateUserResult is the created user.
type CreateUserResult struct {
	User auth.UserView `json:"user"`
}

// SetPasswordRequest is the input of set-password. The password plugin's
// rules apply, every session of the user ends, and open reset links are spent,
// exactly as for password.SetPassword from Go.
type SetPasswordRequest struct {
	UserID   string     `json:"userId"`
	Password auth.Token `json:"password"`
}

// SetEmailRequest is the input of set-email; see CreateUserRequest.Verified.
type SetEmailRequest struct {
	UserID   string `json:"userId"`
	Email    string `json:"email"`
	Verified bool   `json:"verified,omitempty"`
}

// Users lists users, newest first, as the signed-in admin.
func (p *Plugin) Users(ctx context.Context, in UsersRequest) (UsersResult, error) {
	return p.users.Call(ctx, in)
}

// User shows one user, as the signed-in admin.
func (p *Plugin) User(ctx context.Context, userID string) (UserDetail, error) {
	return p.user.Call(ctx, UserRequest{UserID: userID})
}

// Ban bans a user and ends their sessions, as the signed-in admin with a
// fresh sign-in.
func (p *Plugin) Ban(ctx context.Context, userID, reason string) error {
	_, err := p.ban.Call(ctx, BanRequest{UserID: userID, Reason: reason})
	return err
}

// Unban lifts a ban and clears its reason. Sessions ended by the ban stay
// ended; sessions made while banned start working again.
func (p *Plugin) Unban(ctx context.Context, userID string) error {
	_, err := p.unban.Call(ctx, UserRequest{UserID: userID})
	return err
}

// RevokeSessions ends every session of a user without banning them, for a
// suspected stolen session.
func (p *Plugin) RevokeSessions(ctx context.Context, userID string) error {
	_, err := p.revokeSessions.Call(ctx, UserRequest{UserID: userID})
	return err
}

// SetAdmin grants or removes admin rights, as the signed-in admin; it
// refuses to remove the last admin.
func (p *Plugin) SetAdmin(ctx context.Context, userID string, admin bool) error {
	_, err := p.setAdmin.Call(ctx, SetAdminRequest{UserID: userID, Admin: admin})
	return err
}

// UpdateUser changes a user's name or image, as the signed-in admin with a
// fresh sign-in.
func (p *Plugin) UpdateUser(ctx context.Context, in UpdateUserRequest) error {
	_, err := p.updateUser.Call(ctx, in)
	return err
}

// Sessions lists a user's sessions, as the signed-in admin.
func (p *Plugin) Sessions(ctx context.Context, userID string) ([]auth.SessionView, error) {
	r, err := p.sessions.Call(ctx, UserRequest{UserID: userID})
	return r.Sessions, err
}

// RevokeSession ends one session of a user, as the signed-in admin with a
// fresh sign-in.
func (p *Plugin) RevokeSession(ctx context.Context, userID, sessionID string) error {
	_, err := p.revokeSession.Call(ctx, RevokeSessionRequest{UserID: userID, SessionID: sessionID})
	return err
}

// RemoveUser deletes a user and everything that references them, as the
// signed-in admin with a fresh sign-in. An admin must lose the rights first.
func (p *Plugin) RemoveUser(ctx context.Context, userID string) error {
	_, err := p.removeUser.Call(ctx, UserRequest{UserID: userID})
	return err
}

// CreateUser creates a user with an address and optionally a password, as the
// signed-in admin with a fresh sign-in.
func (p *Plugin) CreateUser(ctx context.Context, in CreateUserRequest) (auth.UserView, error) {
	r, err := p.createUser.Call(ctx, in)
	return r.User, err
}

// SetUserPassword sets a user's password, as the signed-in admin with a fresh
// sign-in. The user's sessions end: whoever holds them may not be the person
// the password is being set for.
func (p *Plugin) SetUserPassword(ctx context.Context, userID string, password auth.Token) error {
	_, err := p.setPassword.Call(ctx, SetPasswordRequest{UserID: userID, Password: password})
	return err
}

// SetUserEmail gives a user an address, as the signed-in admin with a fresh
// sign-in; verified makes it the primary address at once.
func (p *Plugin) SetUserEmail(ctx context.Context, in SetEmailRequest) error {
	_, err := p.setEmail.Call(ctx, in)
	return err
}

type userRow struct {
	u    auth.User
	cols AdminColumns
}

func (p *Plugin) summary(r userRow) UserSummary {
	return UserSummary{ID: r.u.ID, Name: r.u.Name, CreatedAt: r.u.CreatedAt, Admin: p.isAdmin(r.u.ID, r.cols), Banned: isBanned(r.cols, p.core.Now()),
		Roles: p.rolesOf(r.u.ID, r.cols)}
}

// decorate fills what a summary needs beyond the user row, the address and
// the last activity, for every summary at once: one query each, whatever the
// page size.
func (p *Plugin) decorate(ctx context.Context, users []UserSummary) error {
	if err := p.withEmails(ctx, users); err != nil {
		return err
	}
	return p.withLastActive(ctx, users)
}

// withEmails fills Email of every summary in users from one query over their
// email identities: the primary one, else the earliest created, so a user
// whose only address is unverified still shows it.
func (p *Plugin) withEmails(ctx context.Context, users []UserSummary) error {
	if len(users) == 0 {
		return nil
	}
	ids := make([]string, len(users))
	for i, u := range users {
		ids[i] = u.ID
	}
	type pick struct {
		value   string
		primary bool
		created time.Time
	}
	best := map[string]pick{}
	var (
		userID, value string
		primary       bool
		created       time.Time
	)
	q := p.core.Select().Columns(sqlb.Bind(auth.IdentityUserID, &userID), sqlb.Bind(auth.IdentityValue, &value),
		sqlb.Bind(auth.IdentityIsPrimary, &primary), sqlb.Bind(auth.IdentityCreatedAt, &created)).
		From(auth.TableIdentity).Where(sqlb.Eq(auth.IdentityKind, email.KindEmail), sqlb.In(auth.IdentityUserID, ids...))
	err := p.core.Each(ctx, q, func() error {
		cur, ok := best[userID]
		if !ok || (primary && !cur.primary) || (primary == cur.primary && created.Before(cur.created)) {
			best[userID] = pick{value: value, primary: primary, created: created}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i := range users {
		users[i].Email = best[users[i].ID].value
	}
	return nil
}

func (p *Plugin) doUsers(ctx context.Context, c *auth.Call, in UsersRequest) (UsersResult, error) {
	if err := p.require(ctx, c, ResourceUser, ActionList); err != nil {
		return UsersResult{}, err
	}
	var where []sqlb.Predicate
	if q := strings.TrimSpace(in.Query); q != "" {
		id := q
		if kind, value, err := c.Auth.DetectKind(q); err == nil {
			// Only "no such identity" falls back to treating the query as a
			// user id. Any other failure is the database's, and swallowing it
			// would show the admin an empty page for a user who exists.
			idn, err := c.Auth.FindIdentity(ctx, kind, value, false)
			switch {
			case err == nil:
				id = idn.UserID
			case !errors.Is(err, auth.ErrIdentityNotFound):
				return UsersResult{}, err
			}
		}
		where = append(where, sqlb.Eq(auth.UserID, id))
	}
	return p.list(ctx, c, in, where)
}

// list pages through users matching where plus in's admin and banned
// filters, in in's sort order. users and search-users share it, so the two
// page, sort, filter and count identically; in.Query is not read here.
func (p *Plugin) list(ctx context.Context, c *auth.Call, in UsersRequest, where []sqlb.Predicate) (UsersResult, error) {
	limit, page, offset := paging(c.Auth.Config(), in.Page, in.Limit, in.Offset)
	out := UsersResult{Users: []UserSummary{}, Page: page, Limit: limit, Offset: offset}
	order, err := sortOrder(in.Sort, in.SortBy, in.SortDirection)
	if err != nil {
		return UsersResult{}, err
	}

	now := c.Auth.Now()
	filter, err := p.filterPredicate(c.Auth.Engine(), now, in.FilterField, in.FilterOperator, in.FilterValue)
	if err != nil {
		return UsersResult{}, err
	}
	if filter != nil {
		where = append(where, filter)
	}
	for _, f := range []struct {
		flag                Flag
		whenTrue, whenFalse sqlb.Predicate
	}{
		{in.Admin, sqlb.IsNotNull(GrantedAt), sqlb.IsNull(GrantedAt)},
		{in.Banned, banned(now), notBanned(now)},
	} {
		pred, err := f.flag.predicate(f.whenTrue, f.whenFalse)
		if err != nil {
			return UsersResult{}, err
		}
		if pred != nil {
			where = append(where, pred)
		}
	}
	var r userRow
	q := c.Auth.Select().Columns(sqlb.Bindings(auth.UserBindings(&r.u), Bindings(&r.cols))...).From(auth.TableUser)
	if len(where) > 0 {
		q = q.Where(where...)
	}
	q = q.Order(order...).Limit(limit).Offset(offset)
	if err := p.core.Each(ctx, q, func() error { out.Users = append(out.Users, p.summary(r)); return nil }); err != nil {
		return UsersResult{}, err
	}
	if err := p.decorate(ctx, out.Users); err != nil {
		return UsersResult{}, err
	}
	cq := c.Auth.Select().Columns(sqlb.Bind(sqlb.Count(), &out.Total)).From(auth.TableUser)
	if len(where) > 0 {
		cq = cq.Where(where...)
	}
	return out, p.core.One(ctx, cq)
}

func (p *Plugin) load(ctx context.Context, userID string) (userRow, error) {
	u, err := p.core.User(ctx, userID)
	if err != nil {
		return userRow{}, err
	}
	cols, err := p.columnsOf(ctx, userID)
	return userRow{u: u, cols: cols}, err
}

func (p *Plugin) doUser(ctx context.Context, c *auth.Call, in UserRequest) (UserDetail, error) {
	if err := p.require(ctx, c, ResourceUser, ActionGet); err != nil {
		return UserDetail{}, err
	}
	r, err := p.load(ctx, in.UserID)
	if err != nil {
		return UserDetail{}, err
	}
	ids, err := c.Auth.Identities(ctx, in.UserID)
	if err != nil {
		return UserDetail{}, err
	}
	sessions, err := c.Auth.Sessions(ctx, in.UserID)
	if err != nil {
		return UserDetail{}, err
	}
	out := UserDetail{User: p.summary(r), BanReason: r.cols.BanReason, Identities: []IdentityView{}, Sessions: len(sessions)}
	one := []UserSummary{out.User}
	if err := p.decorate(ctx, one); err != nil {
		return UserDetail{}, err
	}
	out.User = one[0]
	for _, idn := range ids {
		out.Identities = append(out.Identities, IdentityView{Kind: idn.Kind, Value: idn.Value, Verified: idn.Verified(), Primary: idn.IsPrimary})
	}
	return out, nil
}

// doBan refuses to ban an admin, the caller included: an admin must be demoted
// first, so a single stolen admin session cannot lock every other admin out.
func (p *Plugin) doBan(ctx context.Context, c *auth.Call, in BanRequest) (auth.Done, error) {
	if err := p.require(ctx, c, ResourceUser, ActionBan); err != nil {
		return auth.Done{}, err
	}
	r, err := p.load(ctx, in.UserID)
	if err != nil {
		return auth.Done{}, err
	}
	if p.isAdmin(in.UserID, r.cols) {
		return auth.Done{}, ErrAdminTarget
	}
	now := c.Auth.Now()
	var expires *time.Time
	switch ttl := time.Duration(in.Minutes) * time.Minute; {
	case ttl > 0:
		t := now.Add(ttl)
		expires = &t
	case p.defaultBanTTL > 0:
		t := now.Add(p.defaultBanTTL)
		expires = &t
	}
	return auth.Done{OK: true}, p.applyBan(ctx, in.UserID, in.Reason, expires)
}

// applyBan writes the ban columns and ends the user's sessions; ban and
// BanFor share it so the two paths cannot drift. An empty reason is the
// default one; expires nil is permanent.
func (p *Plugin) applyBan(ctx context.Context, userID, reason string, expires *time.Time) error {
	if reason == "" {
		reason = p.defaultBanReason
	}
	reason = auth.TruncateRunes(reason, maxReasonLength)
	now := p.core.Now()
	if err := auth.SetUserColumn(ctx, p.core, PluginName, userID, BannedAt, &now); err != nil {
		return err
	}
	if err := auth.SetUserColumn(ctx, p.core, PluginName, userID, BanExpiresAt, expires); err != nil {
		return err
	}
	if err := auth.SetUserColumn(ctx, p.core, PluginName, userID, BanReason, reason); err != nil {
		return err
	}
	return p.core.EndUserSessions(ctx, userID, "", auth.SessionEndBanned)
}

// BanFor bans userID from Go only, like Grant from trusted code with no
// signed-in admin: an import carrying another system's bans, a job acting on
// a fraud signal. A zero until is permanent; otherwise the ban lifts at until
// (DefaultBanDuration does not apply, since the caller states the end). The
// user's sessions end, as with ban. An admin cannot be banned
// (ErrAdminTarget), an unknown user is auth.ErrUserNotFound. When an audit log
// is registered (EventRecorder) the ban is recorded under EndpointBan with no actor and
// the user as subject, in the same transaction. It runs in one transaction,
// or joins the one in ctx.
//
//ds:def id=plugin-banfor-m3x8vt5q owner=@khanakia stability=stable
func (p *Plugin) BanFor(ctx context.Context, userID, reason string, until time.Time) error {
	return p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		r, err := p.load(ctx, userID)
		if err != nil {
			return err
		}
		if p.isAdmin(userID, r.cols) {
			return ErrAdminTarget
		}
		var expires *time.Time
		if !until.IsZero() {
			expires = &until
		}
		if err := p.applyBan(ctx, userID, reason, expires); err != nil {
			return err
		}
		if p.recorder == nil {
			return nil
		}
		return p.recorder.Record(ctx, audit.Event{Op: EndpointBan, Plugin: PluginName, OK: true, SubjectID: userID})
	})
}

func (p *Plugin) doUnban(ctx context.Context, c *auth.Call, in UserRequest) (auth.Done, error) {
	if err := p.require(ctx, c, ResourceUser, ActionBan); err != nil {
		return auth.Done{}, err
	}
	if _, err := c.Auth.User(ctx, in.UserID); err != nil {
		return auth.Done{}, err
	}
	if err := auth.SetUserColumn(ctx, c.Auth, PluginName, in.UserID, BannedAt, (*time.Time)(nil)); err != nil {
		return auth.Done{}, err
	}
	if err := auth.SetUserColumn(ctx, c.Auth, PluginName, in.UserID, BanExpiresAt, (*time.Time)(nil)); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, auth.SetUserColumn(ctx, c.Auth, PluginName, in.UserID, BanReason, "")
}

// Audit pages through the audit log, as the signed-in admin; see audit.Query.
func (p *Plugin) Audit(ctx context.Context, q audit.Query) (audit.Page, error) {
	return p.audit.Call(ctx, q)
}

// doAudit reads the audit log (EventQuerier) for an admin. The log is the record of
// what admins did as much as what users did, so it is read-only here and
// there is no route that deletes from it.
func (p *Plugin) doAudit(ctx context.Context, c *auth.Call, q audit.Query) (audit.Page, error) {
	if err := p.require(ctx, c, ResourceUser, ActionList); err != nil {
		return audit.Page{}, err
	}
	if p.querier == nil {
		return audit.Page{}, ErrNoAuditPlugin
	}
	return p.querier.Events(ctx, q)
}

// doCreateUser creates the user through the core and gives it the address and
// the password through the plugins that own them, so every rule those
// plugins enforce (address uniqueness, one address per user, password
// strength, breached-password check) applies to an admin-created user too.
// The whole thing is one transaction: a refused password leaves no user.
func (p *Plugin) doCreateUser(ctx context.Context, c *auth.Call, in CreateUserRequest) (CreateUserResult, error) {
	if err := p.require(ctx, c, ResourceUser, ActionCreate); err != nil {
		return CreateUserResult{}, err
	}
	if p.emails == nil {
		return CreateUserResult{}, ErrNoEmailPlugin
	}
	if strings.TrimSpace(in.Email) == "" {
		return CreateUserResult{}, ErrEmailRequired
	}
	if in.Password != "" && p.passwords == nil {
		return CreateUserResult{}, ErrNoPasswordPlugin
	}
	u, err := c.Auth.CreateUser(ctx, auth.NewUser{Name: in.Name, Image: in.Image})
	if err != nil {
		return CreateUserResult{}, err
	}
	if err := p.emails.SetFor(ctx, u.ID, in.Email, in.Verified); err != nil {
		return CreateUserResult{}, err
	}
	if in.Password != "" {
		if err := p.passwords.SetPassword(ctx, u.ID, in.Password); err != nil {
			return CreateUserResult{}, err
		}
	}
	return CreateUserResult{User: auth.ViewOf(u)}, nil
}

// doSetPassword refuses to change an admin's password: a stolen admin session
// must not be able to take over the other admins' accounts. The target's own
// sessions end, as password.SetPassword promises.
func (p *Plugin) doSetPassword(ctx context.Context, c *auth.Call, in SetPasswordRequest) (auth.Done, error) {
	if err := p.require(ctx, c, ResourceUser, ActionSetPassword); err != nil {
		return auth.Done{}, err
	}
	if p.passwords == nil {
		return auth.Done{}, ErrNoPasswordPlugin
	}
	r, err := p.load(ctx, in.UserID)
	if err != nil {
		return auth.Done{}, err
	}
	if p.isAdmin(in.UserID, r.cols) {
		return auth.Done{}, ErrAdminTarget
	}
	return auth.Done{OK: true}, p.passwords.SetPassword(ctx, in.UserID, in.Password)
}

// doSetEmail gives a user an address through the email plugin, which applies
// its own rules. An admin's address cannot be changed here, for the reason
// doSetPassword gives: a verified address recovers the account.
func (p *Plugin) doSetEmail(ctx context.Context, c *auth.Call, in SetEmailRequest) (auth.Done, error) {
	if err := p.require(ctx, c, ResourceUser, ActionSetEmail); err != nil {
		return auth.Done{}, err
	}
	if p.emails == nil {
		return auth.Done{}, ErrNoEmailPlugin
	}
	r, err := p.load(ctx, in.UserID)
	if err != nil {
		return auth.Done{}, err
	}
	if p.isAdmin(in.UserID, r.cols) {
		return auth.Done{}, ErrAdminTarget
	}
	return auth.Done{OK: true}, p.emails.SetFor(ctx, in.UserID, in.Email, in.Verified)
}

// doUpdateUser edits a user's display fields through the core, so the same
// length and URL limits as the user's own profile update apply.
func (p *Plugin) doUpdateUser(ctx context.Context, c *auth.Call, in UpdateUserRequest) (auth.Done, error) {
	if err := p.require(ctx, c, ResourceUser, ActionUpdate); err != nil {
		return auth.Done{}, err
	}
	upd, writes, err := p.applyData(in)
	if err != nil {
		return auth.Done{}, err
	}
	if _, err := c.Auth.UpdateUser(ctx, in.UserID, upd); err != nil {
		return auth.Done{}, err
	}
	for _, w := range writes {
		if err := w(ctx, c.Auth, in.UserID); err != nil {
			return auth.Done{}, err
		}
	}
	return auth.Done{OK: true}, nil
}

// doSessions lists another user's sessions. Current is false on every row:
// the admin's own session is not among them.
func (p *Plugin) doSessions(ctx context.Context, c *auth.Call, in UserRequest) (SessionsResult, error) {
	if err := p.require(ctx, c, ResourceSession, ActionList); err != nil {
		return SessionsResult{}, err
	}
	if _, err := c.Auth.User(ctx, in.UserID); err != nil {
		return SessionsResult{}, err
	}
	list, err := c.Auth.Sessions(ctx, in.UserID)
	if err != nil {
		return SessionsResult{}, err
	}
	out := SessionsResult{Sessions: []auth.SessionView{}}
	for _, s := range list {
		out.Sessions = append(out.Sessions, auth.SessionView{ID: s.ID, Impersonated: s.ImpersonatedBy != nil, IP: s.IP, UserAgent: s.UserAgent, CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt})
	}
	return out, nil
}

// doRevokeSession ends one session of a user; the user id and the session id
// must belong together, which the core checks.
func (p *Plugin) doRevokeSession(ctx context.Context, c *auth.Call, in RevokeSessionRequest) (auth.Done, error) {
	if err := p.require(ctx, c, ResourceSession, ActionRevoke); err != nil {
		return auth.Done{}, err
	}
	if _, err := c.Auth.User(ctx, in.UserID); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, c.Auth.EndSession(ctx, in.UserID, in.SessionID, auth.SessionEndAdmin)
}

// doRemoveUser deletes a user. An admin cannot be removed, for the same
// reason one cannot be banned: a stolen admin session must not be able to
// erase the other admins.
func (p *Plugin) doRemoveUser(ctx context.Context, c *auth.Call, in UserRequest) (auth.Done, error) {
	if err := p.require(ctx, c, ResourceUser, ActionDelete); err != nil {
		return auth.Done{}, err
	}
	r, err := p.load(ctx, in.UserID)
	if err != nil {
		return auth.Done{}, err
	}
	if p.isAdmin(in.UserID, r.cols) {
		return auth.Done{}, ErrAdminTarget
	}
	return auth.Done{OK: true}, c.Auth.DeleteUser(ctx, in.UserID)
}

func (p *Plugin) doRevokeSessions(ctx context.Context, c *auth.Call, in UserRequest) (auth.Done, error) {
	if err := p.require(ctx, c, ResourceSession, ActionRevoke); err != nil {
		return auth.Done{}, err
	}
	if _, err := c.Auth.User(ctx, in.UserID); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, c.Auth.EndUserSessions(ctx, in.UserID, "", auth.SessionEndAdmin)
}

func (p *Plugin) admins(ctx context.Context) (int64, error) {
	var n int64
	q := p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(auth.TableUser).Where(sqlb.IsNotNull(GrantedAt))
	return n, p.core.One(ctx, q)
}

// doSetAdmin keeps at least one admin, so the last one cannot remove their
// own rights and leave the app with nobody who can grant them back.
func (p *Plugin) doSetAdmin(ctx context.Context, c *auth.Call, in SetAdminRequest) (auth.Done, error) {
	if err := p.require(ctx, c, ResourceUser, ActionSetRole); err != nil {
		return auth.Done{}, err
	}
	r, err := p.load(ctx, in.UserID)
	if err != nil {
		return auth.Done{}, err
	}
	// The flag and the roles move together (writeRoles): granting adds the
	// first admin role to the stored ones, revoking drops every admin role.
	stored := splitRoles(r.cols.Role)
	if in.Admin {
		if r.cols.AdminGrantedAt != nil && slices.ContainsFunc(stored, p.isAdminRole) {
			return auth.Done{OK: true}, nil
		}
		return auth.Done{OK: true}, p.writeRoles(ctx, in.UserID, append(stored, p.adminRoles[0]))
	}
	if r.cols.AdminGrantedAt == nil && !slices.ContainsFunc(stored, p.isAdminRole) {
		return auth.Done{OK: true}, nil
	}
	kept := slices.DeleteFunc(stored, p.isAdminRole)
	if len(kept) == 0 {
		kept = []string{p.defaultRole}
	}
	return auth.Done{OK: true}, p.writeRoles(ctx, in.UserID, kept)
}

// ImpersonateRequest names the user to act as. Minutes is optional and capped
// by auth.MaxImpersonationTTL.
type ImpersonateRequest struct {
	UserID  string `json:"userId"`
	Minutes int    `json:"minutes,omitempty"`
}

// ImpersonateResult is the user now being acted as. The session arrives as an
// effect, replacing the admin's own in the session cookie, while the admin's
// own session (under a new token) is bound to the client in the flow cookie,
// for stop-impersonating to re-issue. Token and AdminToken are for Go callers
// and bearer transports, never encoded into JSON.
type ImpersonateResult struct {
	User       auth.UserView `json:"user"`
	ExpiresAt  time.Time     `json:"expiresAt"`
	Token      auth.Token    `json:"-"`
	AdminToken auth.Token    `json:"-"`
}

// StopResult is the output of stop-impersonating. Restored is true when the
// admin's own session was re-issued; false means the client was signed out,
// because the flow binding was gone or the admin's session had ended.
type StopResult struct {
	OK       bool `json:"ok"`
	Restored bool `json:"restored"`
}

// ErrNotImpersonating is returned by stop-impersonating on an ordinary session.
var ErrNotImpersonating = auth.NewError("admin.not_impersonating", http.StatusConflict, "This session is not an impersonation.")

// Impersonate acts as another user, as the signed-in admin.
func (p *Plugin) Impersonate(ctx context.Context, in ImpersonateRequest) (ImpersonateResult, error) {
	return p.impersonate.Call(ctx, in)
}

// StopImpersonating ends the impersonation session in ctx and reports whether
// the admin's own session was re-issued (as an effect; see StopResult).
func (p *Plugin) StopImpersonating(ctx context.Context) (StopResult, error) {
	return p.stopImpersonating.Call(ctx, struct{}{})
}

// doImpersonate refuses the caller themselves, an admin target unless
// AllowImpersonatingAdmins, and a banned target; it logs who acted as whom,
// and records the admin on the session row. The new session can look but not
// change what proves the user's identity: the core refuses every FreshSignIn
// operation on it.
func (p *Plugin) doImpersonate(ctx context.Context, c *auth.Call, in ImpersonateRequest) (ImpersonateResult, error) {
	if err := p.require(ctx, c, ResourceUser, ActionImpersonate); err != nil {
		return ImpersonateResult{}, err
	}
	r, err := p.load(ctx, in.UserID)
	if err != nil {
		return ImpersonateResult{}, err
	}
	// The admin check comes first so the default answers an admin's own id
	// exactly as before (ErrAdminTarget); self only reaches ErrSelfTarget
	// when admins may be impersonated.
	switch {
	case p.isAdmin(in.UserID, r.cols) && !p.impersonateAdmins:
		may, err := p.callerMay(ctx, c, ResourceUser, ActionImpersonateAdmins)
		if err != nil {
			return ImpersonateResult{}, err
		}
		if !may {
			return ImpersonateResult{}, ErrAdminTarget
		}
		if in.UserID == c.User.ID {
			return ImpersonateResult{}, ErrSelfTarget
		}
	case in.UserID == c.User.ID:
		return ImpersonateResult{}, ErrSelfTarget
	}
	if isBanned(r.cols, c.Auth.Now()) {
		return ImpersonateResult{}, ErrBannedTarget
	}
	ttl := time.Duration(in.Minutes) * time.Minute
	if ttl <= 0 {
		ttl = p.impersonationTTL
	}
	// The admin's own session survives for the way back: its token is
	// rotated (the one in the admin's cookie dies with the cookie the
	// impersonation overwrites) and the new one is bound to the client in the
	// flow cookie, out of the session cookie's way. Someone who steals the
	// impersonation cookie alone holds a user session, not the admin's.
	adminTok, err := c.Auth.RotateSessionToken(ctx, c)
	if err != nil {
		return ImpersonateResult{}, err
	}
	sess, tok, err := c.Auth.CreateImpersonationSession(ctx, in.UserID, c.User.ID, c.Client, ttl)
	if err != nil {
		return ImpersonateResult{}, err
	}
	c.Auth.Logger().Warn("admin: impersonation started", "admin", c.User.ID, "user", in.UserID, "expires", sess.ExpiresAt)
	c.Effects.IssueSessionOf(sess, tok)
	c.Effects.BindFlow(adminTok, c.Session.ExpiresAt)
	return ImpersonateResult{User: auth.ViewOf(r.u), ExpiresAt: sess.ExpiresAt, Token: tok, AdminToken: adminTok}, nil
}

// doStopImpersonating ends the impersonation and, when the client still holds
// the admin's token in its flow binding and that session still belongs to the
// impersonating admin, re-issues it; otherwise the client is signed out as
// before. The admin session keeps its own creation time, so coming back never
// makes it fresh.
func (p *Plugin) doStopImpersonating(ctx context.Context, c *auth.Call, _ struct{}) (StopResult, error) {
	if c.Session.ImpersonatedBy == nil {
		return StopResult{}, ErrNotImpersonating
	}
	adminID := *c.Session.ImpersonatedBy
	if err := c.Auth.EndSession(ctx, c.User.ID, c.Session.ID, auth.SessionEndImpersonationStopped); err != nil {
		return StopResult{}, err
	}
	c.Auth.Logger().Warn("admin: impersonation ended", "admin", adminID, "user", c.User.ID)
	c.Effects.BindFlow("", time.Time{})
	if c.Flow != "" {
		s, u, _, err := c.Auth.ResolveSession(ctx, c.Flow)
		switch {
		case err == nil && u.ID == adminID:
			c.Effects.IssueSessionOf(*s, c.Flow)
			return StopResult{OK: true, Restored: true}, nil
		case err != nil && !errors.Is(err, auth.ErrSignedOut):
			return StopResult{}, err
		}
	}
	c.Effects.ClearSession()
	return StopResult{OK: true}, nil
}
