// Package scim is a SCIM 2.0 service provider (RFC 7643, RFC 7644): an
// identity provider such as Okta, Microsoft
// Entra or JumpCloud creates, updates, deactivates and deletes users and
// groups by calling the app, so a leaver loses access when IT disables them.
//
// The plugin serves /Users, /Groups and the discovery documents under the
// prefix the app mounts Handler at (conventionally /scim/v2), in SCIM's own
// media type and error schema. A caller is one connection (one IdP tenant)
// holding a bearer credential with scopes; every resource belongs to the
// connection that created it and is invisible to every other.
//
// A SCIM user is linked to one library user: created for it by default
// (ResolveUser decides otherwise), never matched to an existing user by
// email, because an IdP can assert any address. When every SCIM user linked
// to a library user is inactive or deleted, that user's sessions end and
// every later session lookup refuses them (the scim_deactivated_at column),
// until a connection reactivates them.
//
// Groups map to nothing in the core. A GroupMapper, if given, receives each
// group with its full membership as library user ids after every change, in
// the same transaction, so an organization or role system can follow the IdP
// without this package knowing its shape.
package scim

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity.
const PluginName = "scim"

// Table, alias and column names. Every table is scoped by connection_id.
const (
	TableNameUser   = "auth_scim_user"
	TableNameGroup  = "auth_scim_group"
	TableNameMember = "auth_scim_member"

	TableAliasUser   = "scu"
	TableAliasGroup  = "scg"
	TableAliasMember = "scm"

	ColID           = "id"
	ColConnectionID = "connection_id"
	ColUserID       = "user_id"
	ColIdentityID   = "identity_id"
	ColUserName     = "user_name"
	// ColUserNameKey and the other *_key columns hold the SHA-256 of the
	// compared form (lower-cased where SCIM compares case-insensitively), so
	// a 512-character userName fits a unique index on MySQL.
	ColUserNameKey    = "user_name_key"
	ColExternalID     = "external_id"
	ColExternalIDKey  = "external_id_key"
	ColActive         = "active"
	ColPrimaryEmail   = "primary_email"
	ColResource       = "resource"
	ColDisplayName    = "display_name"
	ColDisplayNameKey = "display_name_key"
	ColGroupID        = "group_id"
	ColSCIMUserID     = "scim_user_id"
	ColCreatedAt      = "created_at"
	ColUpdatedAt      = "updated_at"
	// ColRevision counts a SCIM user's writes: every write is conditional on
	// the revision it read, so a stale write fails instead of overwriting a
	// newer one, and meta.version (W/"n") lets an IdP send If-Match.
	ColRevision = "revision"

	// ColDeactivatedAt is the column this plugin adds to auth_user: set while
	// every SCIM user linked to the user is inactive or deleted.
	ColDeactivatedAt = "scim_deactivated_at"

	migrationName = "0001_scim"
)

// Tables.
var (
	TableUser   = sqlb.Table{Name: TableNameUser, Alias: TableAliasUser}
	TableGroup  = sqlb.Table{Name: TableNameGroup, Alias: TableAliasGroup}
	TableMember = sqlb.Table{Name: TableNameMember, Alias: TableAliasMember}
)

// Typed columns, for an app that reads provisioning state; writes go
// through the SCIM endpoints.
var (
	UserID           = sqlb.Col[string](TableUser, ColID)
	UserConnectionID = sqlb.Col[string](TableUser, ColConnectionID)
	UserUserID       = sqlb.Col[string](TableUser, ColUserID)
	UserIdentityID   = sqlb.Col[*string](TableUser, ColIdentityID)
	UserUserName     = sqlb.Col[string](TableUser, ColUserName)
	UserUserNameKey  = sqlb.Col[string](TableUser, ColUserNameKey)
	UserExternalID   = sqlb.Col[*string](TableUser, ColExternalID)
	UserExternalKey  = sqlb.Col[*string](TableUser, ColExternalIDKey)
	UserActive       = sqlb.Col[bool](TableUser, ColActive)
	UserPrimaryEmail = sqlb.Col[string](TableUser, ColPrimaryEmail)
	UserResource     = sqlb.Col[string](TableUser, ColResource)
	UserCreatedAt    = sqlb.Col[time.Time](TableUser, ColCreatedAt)
	UserUpdatedAt    = sqlb.Col[time.Time](TableUser, ColUpdatedAt)
	UserRevision     = sqlb.Col[int64](TableUser, ColRevision)

	GroupID           = sqlb.Col[string](TableGroup, ColID)
	GroupConnectionID = sqlb.Col[string](TableGroup, ColConnectionID)
	GroupDisplayName  = sqlb.Col[string](TableGroup, ColDisplayName)
	GroupDisplayKey   = sqlb.Col[string](TableGroup, ColDisplayNameKey)
	GroupExternalID   = sqlb.Col[*string](TableGroup, ColExternalID)
	GroupExternalKey  = sqlb.Col[*string](TableGroup, ColExternalIDKey)
	GroupCreatedAt    = sqlb.Col[time.Time](TableGroup, ColCreatedAt)
	GroupUpdatedAt    = sqlb.Col[time.Time](TableGroup, ColUpdatedAt)

	MemberGroupID      = sqlb.Col[string](TableMember, ColGroupID)
	MemberSCIMUserID   = sqlb.Col[string](TableMember, ColSCIMUserID)
	MemberConnectionID = sqlb.Col[string](TableMember, ColConnectionID)
	MemberUserID       = sqlb.Col[string](TableMember, ColUserID)
	MemberCreatedAt    = sqlb.Col[time.Time](TableMember, ColCreatedAt)

	// DeactivatedAt is the auth_user column this plugin owns.
	DeactivatedAt = sqlb.Col[*time.Time](auth.TableUser, ColDeactivatedAt)
)

// Limits.
const (
	// MaxPageSize is the most resources one list answers (SCIM_MAX_PAGE_SIZE).
	//ds:def id=scim-maxpagesize-6k2wq9mv owner=@khanakia stability=stable
	MaxPageSize = 100
	// MaxGroupMembers bounds one group (SCIM_MAX_GROUP_MEMBERS).
	//ds:def id=scim-maxgroupmembers-3n8xk5tq owner=@khanakia stability=stable
	MaxGroupMembers = 1000
	// MaxResourceSize bounds one serialized user, in bytes.
	//ds:def id=scim-maxresourcesize-9v4mz2kw owner=@khanakia stability=stable
	MaxResourceSize = 65535
	// maxBody bounds a request body: a group of MaxGroupMembers members is
	// the largest legitimate one.
	maxBody = 1 << 20
	// maxIDLength bounds a connection or credential id.
	maxIDLength = 255
)

// EndpointRequest is the operation every SCIM request passes through before
// it is served, so the core's rate rules apply to SCIM: by IP, and by
// connection (ByIdentifier). It is SelfServed, so no transport mounts it and
// no generated client or API reference lists it, and a call that did not
// come from Handler answers auth.ErrUnknownOperation; only Handler calls it. Override its limits with
// auth.WithRateRules(auth.RateRule{Match: scim.EndpointRequest, ...}).
const EndpointRequest auth.EndpointID = "scim.request"

// Default limits of EndpointRequest: an IdP's full sync of a few thousand
// users and their groups fits in a few minutes, and a token guesser waits.
const (
	//ds:def id=scim-defaultrequestlimit-7w3qn8kv owner=@khanakia stability=stable
	DefaultRequestLimit = 600
	//ds:def id=scim-defaultrequestwindow-2k9xm4wq owner=@khanakia stability=stable
	DefaultRequestWindow = time.Minute
)

// gateRequest is EndpointRequest's input: the authenticated connection,
// "" when authentication failed.
type gateRequest struct {
	Connection string `json:"-"`
}

// RateIdentifier counts per connection.
func (g gateRequest) RateIdentifier() string { return g.Connection }

// fromHandlerKey marks a call to EndpointRequest made by Handler.
type fromHandlerKey struct{}

// admit runs EndpointRequest for a request: the rate rules, the hooks.
func (p *Plugin) admit(ctx context.Context, connection string) error {
	_, err := p.gate.Call(context.WithValue(ctx, fromHandlerKey{}, true), gateRequest{Connection: connection})
	return err
}

// doGate admits the request; over a transport it does not exist.
func (p *Plugin) doGate(ctx context.Context, _ *auth.Call, _ gateRequest) (auth.Done, error) {
	if ok, _ := ctx.Value(fromHandlerKey{}).(bool); !ok {
		return auth.Done{}, auth.ErrUnknownOperation
	}
	return auth.Done{}, nil
}

// Operations lists EndpointRequest.
func (p *Plugin) Operations() []auth.Operation { return []auth.Operation{p.gate} }

// RateLimits bounds SCIM requests per IP and per connection.
func (p *Plugin) RateLimits() []auth.RateRule {
	return []auth.RateRule{
		{Match: EndpointRequest, Key: auth.ByIP, Limit: DefaultRequestLimit, Window: DefaultRequestWindow},
		{Match: EndpointRequest, Key: auth.ByIdentifier, Limit: DefaultRequestLimit, Window: DefaultRequestWindow},
	}
}

// Configuration errors from auth.New.
var (
	ErrNoConnections  = errors.New("scim: add a Connection or VerifyBearerToken, or no caller can authenticate")
	ErrBadConnection  = errors.New("scim: a connection id must be 1 to 255 characters, unique, and its credentials need an id and a token without whitespace")
	ErrDuplicateToken = errors.New("scim: two credentials share one token")
)

// Plugin is the SCIM plugin. Build it with New.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs     auth.OptionErrors
	connections []Connection
	verifier    func(ctx context.Context, r BearerRequest) (Principal, error)
	resolve     func(ctx context.Context, in ResolveInput) (Resolution, error)
	groups      GroupMapper
	trustEmails bool
	deleteUsers bool
	entraGroups bool
	onReconcile func(ctx context.Context, in ReconcileInput) error
	managed     *managedConfig
	roles       *RoleProjection
	gate        *auth.Op[gateRequest, auth.Done]
	core        *auth.Auth
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin.
type Option func(*Plugin)

// Connections registers static connections.
func Connections(cs ...Connection) Option {
	return func(p *Plugin) { p.connections = append(p.connections, cs...) }
}

// VerifyBearerToken authenticates a token no static credential holds: the
// app looks the token up
// in its own store and returns the connection and scopes, or
// ErrUnauthorized. It is asked only after every static credential missed.
func VerifyBearerToken(fn func(ctx context.Context, r BearerRequest) (Principal, error)) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("scim.VerifyBearerToken", fn) {
			return
		}
		p.verifier = fn
	}
}

// ResolveUser decides which library user a new SCIM user is linked to.
// Without it every new SCIM user gets a
// new library user. Linking to an existing user is the app's decision, made
// on evidence it trusts; the plugin never links by email itself.
func ResolveUser(fn func(ctx context.Context, in ResolveInput) (Resolution, error)) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("scim.ResolveUser", fn) {
			return
		}
		p.resolve = fn
	}
}

// WithGroupMapper receives every group change; see GroupMapper.
func WithGroupMapper(m GroupMapper) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("scim.WithGroupMapper", m) {
			return
		}
		p.groups = m
	}
}

// TrustEmails marks the primary email of a provisioned user verified. Off by
// default: the address is the IdP's assertion, and a verified address signs
// in by email and receives recovery mail. Turn it on only for connections
// whose IdP verifies addresses in domains the customer owns.
func TrustEmails() Option { return func(p *Plugin) { p.trustEmails = true } }

// DeleteUsers deletes the library user when the last SCIM user linked to it
// is deleted, instead of keeping the user deactivated. Off by default,
// because the user's data in the app may outlive the account.
func DeleteUsers() Option { return func(p *Plugin) { p.deleteUsers = true } }

// ReconcileUser runs fn whenever a library user's provisioning state is
// recomputed (after every write to a SCIM user linked to it), inside the
// request's transaction; an error rolls
// the request back. Use it to mirror the state into the app's own records.
func ReconcileUser(fn func(ctx context.Context, in ReconcileInput) error) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("scim.ReconcileUser", fn) {
			return
		}
		p.onReconcile = fn
	}
}

// ReconcileInput is a library user's provisioning state: Active while any
// linked SCIM user is active, Sources the number of linked SCIM users left.
type ReconcileInput struct {
	UserID  string
	Active  bool
	Sources int
}

// AcceptEntraLegacyGroupSchema accepts Microsoft Entra's legacy group schema
// marker on POST /Groups: exactly one
// EntraLegacyGroupSchema entry in schemas is dropped; a second one, or
// attributes under it, answer invalidValue. Off by default.
func AcceptEntraLegacyGroupSchema() Option { return func(p *Plugin) { p.entraGroups = true } }

// EntraLegacyGroupSchema is the marker AcceptEntraLegacyGroupSchema drops.
const EntraLegacyGroupSchema = "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group"

// ResolveInput is what ResolveUser is asked about.
type ResolveInput struct {
	ConnectionID string
	User         User
}

// Resolution is ResolveUser's answer: an empty UserID creates a new user; a
// UserID links the SCIM user to that existing library user, and Profile says
// whether the link writes that user's profile.
type Resolution struct {
	UserID string
	// Profile is the link profile mode: ProfilePreserve (or "")
	// never writes the linked user's name or email; ProfileManage makes this
	// SCIM user the user's one profile source, which writes them now and on
	// every replace. Ignored when UserID is empty, since a user the plugin
	// creates is always managed.
	Profile Profile
}

// Profile is a linked SCIM user's profile mode. A library user has at most
// one profile source across every connection: the SCIM user that created it,
// or the one linked with ProfileManage. A second ProfileManage link, or the
// revival of a deleted source while another holds the profile, is 409
// uniqueness ("Another SCIM source already manages this User profile").
// Deleting the source frees the profile for the next link
// (the hand-over).
type Profile string

// The profile modes.
const (
	ProfilePreserve Profile = "preserve"
	ProfileManage   Profile = "manage"
)

// ErrBadProfile is a Resolution whose Profile is neither mode: an app error,
// so the request fails (500) rather than guess which one was meant.
var ErrBadProfile = errors.New("scim: Resolution.Profile is ProfilePreserve, ProfileManage or empty")

// GroupMapper follows SCIM groups into the app's own grouping (an
// organization, a team, a role). Each method runs inside the SCIM request's
// transaction; an error fails the request and rolls the change back, so the
// IdP retries. Members are library user ids, the full current list, so an
// implementation can be idempotent.
//
//ds:def id=scim-groupmapper-7q4wn8kx owner=@khanakia stability=stable
type GroupMapper interface {
	SyncGroup(ctx context.Context, g GroupState) error
	DeleteGroup(ctx context.Context, connectionID, groupID string) error
}

// GroupState is one group as GroupMapper sees it.
type GroupState struct {
	ConnectionID string
	ID           string
	ExternalID   string
	DisplayName  string
	// UserIDs are the library users of the group's members.
	UserIDs []string
}

// Compile-time proof of each capability.
var (
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.Dependent         = (*Plugin)(nil)
	_ auth.TableOwner        = (*Plugin)(nil)
	_ auth.UserTableOwner    = (*Plugin)(nil)
	_ auth.TypedMigrator     = (*Plugin)(nil)
	_ auth.ColumnExtender    = (*Plugin)(nil)
	_ auth.SessionChecker    = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.RateLimiter       = (*Plugin)(nil)
)

// New builds the plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{}
	for _, o := range opts {
		o(p)
	}
	p.gate = auth.Define(auth.OpInfo{ID: EndpointRequest, Kind: auth.Query, Require: auth.Public, Path: "/request", SelfServed: true}, p.doGate)
	return p
}

// Name returns PluginName.
func (p *Plugin) Name() string { return PluginName }

// Requires names the email plugin: a provisioned user's primary email is an
// email identity.
func (p *Plugin) Requires() []string { return []string{email.PluginName} }

// Validate refuses a configuration no caller could authenticate with, and
// credentials that are ambiguous.
//
// The email identifier the provisioned users are addressed by needs no check
// here: Requires names the email plugin, which always registers it, and the
// core refuses a missing requirement before any Validate runs.
func (p *Plugin) Validate(c *auth.Config) error {
	if len(p.connections) == 0 && p.verifier == nil && p.managed == nil {
		return ErrNoConnections
	}
	ids, tokens := map[string]bool{}, map[string]bool{}
	for _, cn := range p.connections {
		if !validID(cn.ID) || ids[cn.ID] || strings.HasPrefix(cn.ID, managedConnPrefix+"_") || (cn.ProvisioningDomainID != "" && !validID(cn.ProvisioningDomainID)) {
			return fmt.Errorf("%w: scim.Connections: connection %q", ErrBadConnection, cn.ID)
		}
		ids[cn.ID] = true
		credIDs := map[string]bool{}
		for _, cr := range cn.Credentials {
			if !validID(cr.ID) || credIDs[cr.ID] || !validToken(cr.Token) || !validScopes(cr.Scopes) {
				return fmt.Errorf("%w: scim.Connections: connection %q credential %q", ErrBadConnection, cn.ID, cr.ID)
			}
			credIDs[cr.ID] = true
			if tokens[cr.Token] {
				return ErrDuplicateToken
			}
			tokens[cr.Token] = true
		}
	}
	return p.validManaged(c)
}

// Init captures the core handle.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	return nil
}

// Tables declares the three tables.
func (p *Plugin) Tables() []sqlb.Table {
	return []sqlb.Table{TableUser, TableGroup, TableMember, TableConnection, TableCredential, TableEvent, TableTombstone, TableGrant}
}

// UserTables declares the rows that belong to a library user, so DeleteUser
// removes the SCIM user and its memberships (no foreign key does, ADR-0002).
func (p *Plugin) UserTables() []auth.UserTable {
	return []auth.UserTable{{Table: TableMember, Column: ColUserID}, {Table: TableUser, Column: ColUserID}, {Table: TableTombstone, Column: ColUserID}, {Table: TableGrant, Column: ColUserID}}
}

// Columns adds scim_deactivated_at to auth_user.
func (p *Plugin) Columns() []auth.ColumnExtension {
	return []auth.ColumnExtension{{Table: auth.TableNameUser, Name: ColDeactivatedAt, Type: auth.ColumnTimestamp, Nullable: true}}
}

// ErrDeactivated refuses a session to a user the identity provider
// deactivated (every SCIM user linked to them is inactive), on every sign-in
// method, as admin's ErrBanned does for a banned user.
var ErrDeactivated = auth.NewError("scim.deactivated", http.StatusForbidden, "This account has been deactivated by your organization.")

// DataHooks refuse to create a session for a deactivated user. The hook sits
// on the session write, as admin's ban does, so it covers every sign-in
// method and a pending second-factor session, and it fires only after the
// method proved the credential: a stranger without the credential sees the
// ordinary wrong-credential answer, so the refusal reveals nothing to them.
// Without it a deactivated user's sign-in answered 200 with a session that
// SessionPredicates then refused on its first use.
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{Session: auth.TableHooks[auth.Session]{BeforeCreate: p.refuseDeactivated}}
}

func (p *Plugin) refuseDeactivated(ctx context.Context, _ sqlb.DBTX, row *auth.Session) error {
	var at *time.Time
	if err := p.core.LoadUserColumns(ctx, row.UserID, sqlb.Bind(DeactivatedAt, &at)); err != nil {
		return err
	}
	if at != nil {
		return ErrDeactivated
	}
	return nil
}

// SessionPredicates refuses every session of a deactivated user.
//
//ds:def id=scim-sessionpredicates-5w9kq3nt owner=@khanakia stability=stable
func (p *Plugin) SessionPredicates() []sqlb.Predicate {
	return []sqlb.Predicate{sqlb.IsNull(DeactivatedAt)}
}

// TypedMigrations creates the three tables.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	user, group, member := p.core.TableName(TableUser), p.core.TableName(TableGroup), p.core.TableName(TableMember)
	st := []string{
		"CREATE TABLE IF NOT EXISTS " + user + " (" +
			ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColConnectionID + " " + t.Key + " NOT NULL, " +
			ColUserID + " " + t.ID + " NOT NULL, " +
			ColIdentityID + " " + t.ID + " NULL, " +
			ColUserName + " " + t.Long + " NOT NULL, " +
			ColUserNameKey + " " + t.Key + " NOT NULL, " +
			ColExternalID + " " + t.Long + " NULL, " +
			ColExternalIDKey + " " + t.Key + " NULL, " +
			ColActive + " " + t.Bool + " NOT NULL, " +
			ColPrimaryEmail + " " + t.Value + " NOT NULL, " +
			ColResource + " " + t.Doc + " NOT NULL, " +
			ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
			ColUpdatedAt + " " + t.Timestamp + " NOT NULL, " +
			ColRevision + " " + t.Int + " NOT NULL, " +
			"UNIQUE (" + ColConnectionID + ", " + ColUserNameKey + "), " +
			"UNIQUE (" + ColConnectionID + ", " + ColExternalIDKey + "), " +
			"UNIQUE (" + ColConnectionID + ", " + ColUserID + "))" + t.TableSuffix,
		"CREATE TABLE IF NOT EXISTS " + group + " (" +
			ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColConnectionID + " " + t.Key + " NOT NULL, " +
			ColDisplayName + " " + t.Long + " NOT NULL, " +
			ColDisplayNameKey + " " + t.Key + " NOT NULL, " +
			ColExternalID + " " + t.Long + " NULL, " +
			ColExternalIDKey + " " + t.Key + " NULL, " +
			ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
			ColUpdatedAt + " " + t.Timestamp + " NOT NULL, " +
			"UNIQUE (" + ColConnectionID + ", " + ColDisplayNameKey + "), " +
			"UNIQUE (" + ColConnectionID + ", " + ColExternalIDKey + "))" + t.TableSuffix,
		"CREATE TABLE IF NOT EXISTS " + member + " (" +
			ColGroupID + " " + t.ID + " NOT NULL, " +
			ColSCIMUserID + " " + t.ID + " NOT NULL, " +
			ColConnectionID + " " + t.Key + " NOT NULL, " +
			ColUserID + " " + t.ID + " NOT NULL, " +
			ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
			"PRIMARY KEY (" + ColGroupID + ", " + ColSCIMUserID + "))" + t.TableSuffix,
	}
	st = append(append(st, p.managedMigration(t)...), p.tombstoneMigration(t), p.grantMigration(t))
	return []auth.Migration{{Owner: PluginName, Name: migrationName, Statements: st}}, nil
}

// Handler serves the SCIM endpoints. Mount it with the prefix stripped:
//
//	mux.Handle("/scim/v2/", http.StripPrefix("/scim/v2", p.Handler()))
//
// It answers /Users, /Users/{id}, /Groups, /Groups/{id}, and the public
// /ServiceProviderConfig, /Schemas and /ResourceTypes documents.
//
//ds:def id=scim-handler-2m6xv8qn owner=@khanakia stability=stable
func (p *Plugin) Handler() http.Handler { return http.HandlerFunc(p.serve) }
