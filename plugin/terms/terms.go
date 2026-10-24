// Package terms records which version of the terms each user accepted, and
// when, and lets the app refuse users who have not accepted the current one.
//
// A sign-up form accepts in the same request by sending the version in the
// TermsHeader header; a data hook on user creation reads it, so every sign-up
// method — password, code, link, provider — records acceptance without
// knowing this plugin exists. Users who signed up before a new version accept
// it with the accept operation.
//
// The latest acceptance sits on auth_user, for a cheap "has this user
// accepted" check; every acceptance is also kept, one row per version and
// time, in auth_terms_acceptance, read with History, for the record a
// regulator or a dispute asks for.
package terms

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity.
const PluginName = "terms"

// TermsHeader carries the version a sign-up form showed and the user ticked.
//
//ds:def id=termsheader-zzzc6jza owner=@khanakia stability=stable
const TermsHeader = "Terms-Version"

// EndpointAccept records acceptance of the current version.
//
//ds:def id=endpointaccept-7pkjepnw owner=@khanakia stability=stable
const EndpointAccept auth.EndpointID = "terms.accept"

// Columns this plugin adds to auth_user.
const (
	ColVersion    = "terms_version"
	ColAcceptedAt = "terms_accepted_at"
)

// The history table: one row per acceptance. The key is user, version and
// time, so a version accepted again after the current one changed back to it
// is a second row rather than a lost one. There is no foreign key (ADR-0002);
// DeleteUser removes a user's rows through UserTables.
const (
	//ds:def id=terms-tablenameacceptance-8wv3kq2n owner=@khanakia stability=stable
	TableNameAcceptance  = "auth_terms_acceptance"
	TableAliasAcceptance = "tma"

	ColAcceptanceUserID = "user_id"
	ColAcceptanceVer    = "version"
	ColAcceptanceAt     = "accepted_at"

	// migrationHistory creates the table and copies every acceptance already
	// on auth_user into it, so a deployment that had the plugin before the
	// table existed keeps the acceptances it recorded (2026-10-07).
	migrationHistory = "0001_terms_acceptance"
)

// TableAcceptance and its typed columns, for an app that reads or joins the
// history (reads are open; only the plugin writes).
var (
	TableAcceptance = sqlb.Table{Name: TableNameAcceptance, Alias: TableAliasAcceptance}

	AcceptanceUserID  = sqlb.Col[string](TableAcceptance, ColAcceptanceUserID)
	AcceptanceVersion = sqlb.Col[string](TableAcceptance, ColAcceptanceVer)
	AcceptanceAt      = sqlb.Col[time.Time](TableAcceptance, ColAcceptanceAt)
)

// Typed columns on auth_user, for an app that reports on acceptance in its own
// queries.
var (
	Version    = sqlb.Col[string](auth.TableUser, ColVersion)
	AcceptedAt = sqlb.Col[*time.Time](auth.TableUser, ColAcceptedAt)
)

// TermsColumns is this plugin's flat part of a composite user. Flat because
// the columns live on auth_user itself (ADR-0001); an empty TermsVersion means
// the user never accepted any version.
type TermsColumns struct {
	TermsVersion    string
	TermsAcceptedAt *time.Time
}

// Bindings binds TermsColumns, for a composite user query or LoadUserColumns.
func Bindings(c *TermsColumns) []sqlb.Binding {
	return []sqlb.Binding{sqlb.Bind(Version, &c.TermsVersion), sqlb.Bind(AcceptedAt, &c.TermsAcceptedAt)}
}

// Errors. The first two carry stable codes a client checks for.
var (
	// ErrNotAccepted answers a user who has not accepted the current
	// version; its message tells the client to show the terms.
	ErrNotAccepted = auth.NewError("terms.not_accepted", http.StatusForbidden, "Accept the current terms to continue.")
	// ErrStale refuses acceptance of a version other than the current one:
	// the page the user read is out of date.
	ErrStale = auth.NewError("terms.stale_version", http.StatusConflict, "The terms changed. Read the current version and accept again.")
	// ErrNoVersion fails auth.New when Current was not passed: a terms
	// plugin with no version would accept nothing and refuse everyone.
	ErrNoVersion = errors.New("terms: pass terms.Current with the version users must accept")
)

// Plugin records terms acceptance. Build it with New and Current.
type Plugin struct {
	current string
	core    *auth.Auth
	accept  *auth.Op[AcceptRequest, auth.Done]
}

// Current sets the version users must accept, such as "2026-09". Required.
// Any string works; it is compared exactly, so bumping it makes every user
// accept again.
func Current(version string) func(*Plugin) { return func(p *Plugin) { p.current = version } }

var (
	_ auth.ColumnExtender    = (*Plugin)(nil)
	_ auth.DataHooker        = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.TableOwner        = (*Plugin)(nil)
	_ auth.UserTableOwner    = (*Plugin)(nil)
	_ auth.TypedMigrator     = (*Plugin)(nil)
)

// New builds the plugin. Pass Current; auth.New fails with ErrNoVersion
// without it.
func New(opts ...func(*Plugin)) *Plugin {
	p := &Plugin{}
	for _, o := range opts {
		o(p)
	}
	p.accept = auth.Define(auth.OpInfo{ID: EndpointAccept, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/accept"}, p.doAccept)
	return p
}

// Name identifies the plugin.
func (p *Plugin) Name() string { return PluginName }

// Validate refuses a plugin built without Current.
func (p *Plugin) Validate(*auth.Config) error {
	if p.current == "" {
		return ErrNoVersion
	}
	return nil
}

// Init captures the core.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	return nil
}

// Tables declares the history table, so New can check its alias and an app
// can rename it.
func (p *Plugin) Tables() []sqlb.Table { return []sqlb.Table{TableAcceptance} }

// UserTables tells DeleteUser which rows are a user's: every history row, by
// user id.
func (p *Plugin) UserTables() []auth.UserTable {
	return []auth.UserTable{{Table: TableAcceptance, Column: ColAcceptanceUserID}}
}

// TypedMigrations creates the history table and backfills it from auth_user; the
// column migrations run before a plugin's own, so the columns exist by then.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	table := p.core.TableName(TableAcceptance)
	users := p.core.TableName(auth.TableUser)
	st := []string{
		"CREATE TABLE IF NOT EXISTS " + table + " (" +
			ColAcceptanceUserID + " " + t.ID + " NOT NULL, " +
			ColAcceptanceVer + " " + t.Text + " NOT NULL, " +
			ColAcceptanceAt + " " + t.Timestamp + " NOT NULL, " +
			"PRIMARY KEY (" + ColAcceptanceUserID + ", " + ColAcceptanceVer + ", " + ColAcceptanceAt + "))" + t.TableSuffix,
		"INSERT INTO " + table + " (" + ColAcceptanceUserID + ", " + ColAcceptanceVer + ", " + ColAcceptanceAt + ") " +
			"SELECT " + auth.ColUserID + ", " + ColVersion + ", " + ColAcceptedAt + " FROM " + users +
			" WHERE " + ColVersion + " <> " + sqlEmptyString + " AND " + ColAcceptedAt + " IS NOT NULL",
	}
	return []auth.Migration{{Owner: PluginName, Name: migrationHistory, Statements: st}}, nil
}

// Operations lists the plugin's operation.
func (p *Plugin) Operations() []auth.Operation { return []auth.Operation{p.accept} }

// sqlEmptyString is the SQL literal default of a NOT NULL text column: users
// who existed before the plugin read as having accepted no version.
const sqlEmptyString = "''"

// Columns adds the accepted version and time to auth_user.
func (p *Plugin) Columns() []auth.ColumnExtension {
	return []auth.ColumnExtension{
		{Table: auth.TableNameUser, Name: ColVersion, Type: auth.ColumnText, Default: sqlEmptyString},
		{Table: auth.TableNameUser, Name: ColAcceptedAt, Type: auth.ColumnTimestamp, Nullable: true},
	}
}

// DataHooks record acceptance for a user created by a request that sent the
// current version in TermsHeader. A stale version is not recorded: the user
// saw other terms than the ones in force.
//
//ds:def id=plugin-datahooks-vu9edt3a owner=@khanakia stability=stable
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{User: auth.TableHooks[auth.User]{
		AfterCreate: func(ctx context.Context, _ sqlb.DBTX, u *auth.User) error {
			if auth.RequestHeader(ctx, TermsHeader) != p.current {
				return nil
			}
			return p.record(ctx, u.ID)
		},
	}}
}

// record stores acceptance of the current version: the latest on auth_user
// and a history row. Accepting the version the user already accepted is a
// no-op, so the first acceptance's time stands and a double click adds no
// row.
func (p *Plugin) record(ctx context.Context, userID string) error {
	var c TermsColumns
	if err := p.core.LoadUserColumns(ctx, userID, Bindings(&c)...); err != nil {
		return err
	}
	if c.TermsVersion == p.current {
		return nil
	}
	now := p.core.Now()
	if err := auth.SetUserColumn(ctx, p.core, PluginName, userID, Version, p.current); err != nil {
		return err
	}
	if err := auth.SetUserColumn(ctx, p.core, PluginName, userID, AcceptedAt, &now); err != nil {
		return err
	}
	_, err := p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableAcceptance).Row(
		sqlb.Set(AcceptanceUserID, userID), sqlb.Set(AcceptanceVersion, p.current), sqlb.Set(AcceptanceAt, now)))
	if err != nil {
		return fmt.Errorf("terms: record acceptance: %w", err)
	}
	return nil
}

// Acceptance is one row of a user's history: a version and when it was
// accepted.
type Acceptance struct {
	Version    string    `json:"version"`
	AcceptedAt time.Time `json:"acceptedAt"`
}

// History returns every acceptance of userID, oldest first; never nil, so it
// encodes as []. Acceptances recorded before the history table existed are
// there too, copied from auth_user by the migration, but only the latest per
// user: earlier ones were overwritten before anything kept them.
//
//ds:def id=terms-history-6pw2nk8r owner=@khanakia stability=stable
func (p *Plugin) History(ctx context.Context, userID string) ([]Acceptance, error) {
	if p.core == nil {
		return nil, auth.ErrOperationNotWired
	}
	var row Acceptance
	q := p.core.Select().Columns(sqlb.Bind(AcceptanceVersion, &row.Version), sqlb.Bind(AcceptanceAt, &row.AcceptedAt)).
		From(TableAcceptance).Where(sqlb.Eq(AcceptanceUserID, userID)).
		Order(sqlb.OrderBy(AcceptanceAt, sqlb.SortAsc), sqlb.OrderBy(AcceptanceVersion, sqlb.SortAsc))
	out := []Acceptance{}
	err := p.core.Each(ctx, q, func() error {
		out = append(out, row)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("terms: read history: %w", err)
	}
	return out, nil
}

// AcceptRequest names the version the user read. A version other than the
// current one is refused, so a stale page cannot record acceptance of terms
// the user never saw.
type AcceptRequest struct {
	Version string `json:"version"`
}

// Accept records acceptance for the signed-in user.
func (p *Plugin) Accept(ctx context.Context, version string) error {
	_, err := p.accept.Call(ctx, AcceptRequest{Version: version})
	return err
}

func (p *Plugin) doAccept(ctx context.Context, c *auth.Call, in AcceptRequest) (auth.Done, error) {
	if in.Version != p.current {
		return auth.Done{}, ErrStale
	}
	return auth.Done{OK: true}, p.record(ctx, c.User.ID)
}

// Version is the version users must accept, for a form that shows it.
func (p *Plugin) Version() string { return p.current }

// Accepted reports whether userID accepted the current version.
//
//ds:def id=plugin-accepted-tac4udsa owner=@khanakia stability=stable
func (p *Plugin) Accepted(ctx context.Context, userID string) (bool, error) {
	var c TermsColumns
	if err := p.core.LoadUserColumns(ctx, userID, Bindings(&c)...); err != nil {
		return false, err
	}
	return c.TermsVersion == p.current, nil
}

// RequireCurrent is middleware that refuses a signed-in user who has not
// accepted the current version with ErrNotAccepted. It must be inside
// authhttp.Middleware and after RequireUser.
//
//ds:def id=plugin-requirecurrent-vdvad52z owner=@khanakia stability=stable
func (p *Plugin) RequireCurrent() func(http.Handler) http.Handler {
	return authhttp.RequireFunc(func(r *http.Request) error {
		u, ok := auth.CurrentUser(r.Context())
		if !ok {
			return auth.ErrSignedOut
		}
		yes, err := p.Accepted(r.Context(), u.ID)
		if err != nil {
			return err
		}
		if !yes {
			return ErrNotAccepted
		}
		return nil
	})
}
