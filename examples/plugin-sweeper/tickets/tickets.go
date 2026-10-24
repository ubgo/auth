// Package tickets is a plugin whose rows expire: a signed-in user mints a
// short-lived download ticket for a path of the app, and anyone holding the
// ticket is redirected to that path until it expires. It shows the two
// pieces a plugin with expiring rows needs and the others do not:
//
//   - effects: the mint operation hands the ticket over in a response header
//     (Effects.Header), never in the JSON body, and redeeming answers a
//     redirect (Effects.Redirect). The operation writes no HTTP itself, so
//     the same code runs from a Go call, where the effects are read back
//     with auth.RequestEffects.
//   - Sweeper: expired tickets are deleted by Auth.Sweep, from a scheduled
//     job or "myapp auth sweep", and counted under the plugin's name.
//
// It uses only exported API, so a plugin in your own repository can do
// everything it does.
package tickets

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Names the plugin registers. PluginName is the route prefix, the owner of
// the migration and the key Auth.Sweep reports the plugin's count under.
const (
	PluginName = "tickets"

	TableNameTicket  = "auth_ticket"
	TableAliasTicket = "tk"

	ColID        = "id"
	ColUserID    = "user_id"
	ColHash      = "hash"
	ColTarget    = "target"
	ColExpiresAt = "expires_at"

	// IDPrefix starts every ticket row id.
	IDPrefix = "tkt"
	// HeaderTicket is the response header the mint operation hands the
	// ticket over in. A header keeps the secret out of the JSON body, which
	// clients log; authhttp also exposes it to a cross-origin script.
	HeaderTicket = "Set-Download-Ticket"
)

// The operations, by id.
const (
	EndpointMint   auth.EndpointID = "tickets.mint"
	EndpointRedeem auth.EndpointID = "tickets.redeem"
)

// DefaultTTL is how long a ticket opens its target: long enough to start a
// download from another tab or device, short enough that a ticket pasted
// into a chat is dead by the time anyone else reads it.
//
//ds:def id=tickets-defaultttl-7kq2wm4n
const DefaultTTL = 5 * time.Minute

// MintLimit and MintWindow bound how many tickets one user mints, whatever
// address they come from: a ticket is cheap to ask for and a row to store.
const (
	MintLimit  = 20
	MintWindow = time.Hour
)

// Errors with stable codes. ErrInvalid answers an unknown and an expired
// ticket alike, so a caller learns nothing about which tickets exist.
var (
	ErrTargetInvalid = auth.NewError("tickets.target_invalid", http.StatusBadRequest, "The target must be a path on this site.")
	ErrInvalid       = auth.NewError("tickets.invalid", http.StatusNotFound, "This download link has expired or does not exist.")
	// ErrBadTTL is a configuration error: auth.New reports it.
	ErrBadTTL = errors.New("tickets: the ticket lifetime must be positive")
)

// The table and its typed columns.
var (
	TableTicket = sqlb.Table{Name: TableNameTicket, Alias: TableAliasTicket}
	ID          = sqlb.Col[string](TableTicket, ColID)
	UserID      = sqlb.Col[string](TableTicket, ColUserID)
	Hash        = sqlb.Col[[]byte](TableTicket, ColHash)
	Target      = sqlb.Col[string](TableTicket, ColTarget)
	ExpiresAt   = sqlb.Col[time.Time](TableTicket, ColExpiresAt)
)

// MintRequest is the input of tickets.mint.
type MintRequest struct {
	// Target is the app path the ticket opens, such as "/files/report.pdf".
	Target string `json:"target"`
}

// MintResult is the output of tickets.mint. The ticket itself is in the
// HeaderTicket header, not here.
type MintResult struct {
	ExpiresAt time.Time `json:"expiresAt"`
}

// RedeemRequest is the input of tickets.redeem.
type RedeemRequest struct {
	Ticket auth.WireToken `json:"ticket"`
}

// Option configures New.
type Option func(*Plugin)

// WithTTL sets how long a ticket opens its target.
func WithTTL(d time.Duration) Option { return func(p *Plugin) { p.ttl = d } }

// Plugin is the tickets plugin. Build it with New.
type Plugin struct {
	a   *auth.Auth
	ttl time.Duration

	mint   *auth.Op[MintRequest, MintResult]
	redeem *auth.Op[RedeemRequest, auth.Done]
}

// The optional interfaces this plugin implements, checked by the compiler.
var (
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.TableOwner        = (*Plugin)(nil)
	_ auth.UserTableOwner    = (*Plugin)(nil)
	_ auth.TypedMigrator     = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.Sweeper           = (*Plugin)(nil)
	_ auth.RateLimiter       = (*Plugin)(nil)
)

// New builds the plugin: minting needs a session; redeeming is public,
// because the ticket is the credential, and a GET, so a plain link works.
func New(opts ...Option) *Plugin {
	p := &Plugin{ttl: DefaultTTL}
	for _, o := range opts {
		o(p)
	}
	p.mint = auth.Define(auth.OpInfo{ID: EndpointMint, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/mint"}, p.doMint)
	p.redeem = auth.Define(auth.OpInfo{ID: EndpointRedeem, Kind: auth.Query, Require: auth.Public, Path: "/redeem"}, p.doRedeem)
	return p
}

// Name is the only method every plugin must have.
func (p *Plugin) Name() string { return PluginName }

// Init keeps the core handle; every statement runs through it.
func (p *Plugin) Init(a *auth.Auth) error {
	p.a = a
	return nil
}

// Validate refuses a lifetime under which no ticket would ever open.
func (p *Plugin) Validate(*auth.Config) error {
	if p.ttl <= 0 {
		return ErrBadTTL
	}
	return nil
}

// Tables declares the table and its alias.
func (p *Plugin) Tables() []sqlb.Table { return []sqlb.Table{TableTicket} }

// UserTables lets auth.DeleteUser delete a user's tickets with the user.
func (p *Plugin) UserTables() []auth.UserTable {
	return []auth.UserTable{{Table: TableTicket, Column: ColUserID}}
}

// TypedMigrations writes the table. The ticket is stored as its hash
// (auth.HashToken), so a leaked database opens no download; expires_at is
// indexed because Sweep deletes by it.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	table := p.a.TableName(TableTicket)
	return []auth.Migration{{Owner: PluginName, Name: "0001_tickets", Statements: []string{
		"CREATE TABLE IF NOT EXISTS " + table + " (" +
			ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColUserID + " " + t.ID + " NOT NULL, " +
			ColHash + " " + t.Hash + " NOT NULL UNIQUE, " +
			ColTarget + " " + t.Long + " NOT NULL, " +
			ColExpiresAt + " " + t.Timestamp + " NOT NULL)" + t.TableSuffix,
		"CREATE INDEX " + table + "_expires_idx ON " + table + " (" + ColExpiresAt + ")",
	}}}, nil
}

// Operations lists the routes: POST /auth/tickets/mint and
// GET /auth/tickets/redeem?ticket=….
func (p *Plugin) Operations() []auth.Operation { return []auth.Operation{p.mint, p.redeem} }

// RateLimits bounds minting per signed-in user. Neither ByIP nor
// ByIdentifier fits (the user is not typed into the input, and one user may
// use many addresses), so the rule is ByFunc: its KeyFunc names the user
// after the pipeline has loaded the session.
//
//ds:def id=tickets-ratelimits-5nq8wk3d
func (p *Plugin) RateLimits() []auth.RateRule {
	return []auth.RateRule{{
		Match: EndpointMint, Key: auth.ByFunc, Limit: MintLimit, Window: MintWindow,
		KeyFunc: func(_ context.Context, c *auth.Call) (string, error) { return c.User.ID, nil },
	}}
}

// Sweep deletes the tickets that expired before cutoff. Auth.Sweep calls it
// with now minus the app's retention, so a ticket is kept a while after it
// stops opening (a support person can still see it was minted) and then
// goes. It is one DELETE by an indexed column, safe to run from several
// instances at once.
//
//ds:def id=tickets-sweep-9mw4xq2k
func (p *Plugin) Sweep(ctx context.Context, cutoff time.Time) (int64, error) {
	return p.a.Exec(ctx, sqlb.NewDelete(p.a.Dialect()).From(TableTicket).Where(sqlb.Less(ExpiresAt, cutoff)))
}

// Mint is the Go API of tickets.mint: the same operation the route runs.
// The ticket reaches the caller as an effect; read it with
// auth.RequestEffects(ctx) when ctx came from Auth.WithRequest.
func (p *Plugin) Mint(ctx context.Context, target string) (MintResult, error) {
	return p.mint.Call(ctx, MintRequest{Target: target})
}

// doMint stores the hash of a new ticket and records the ticket itself as a
// header effect. The transport applies an effect only when the whole call
// succeeds, so a mint whose insert failed hands out no ticket.
//
//ds:def id=tickets-domint-6pz3nw8r
func (p *Plugin) doMint(ctx context.Context, c *auth.Call, in MintRequest) (MintResult, error) {
	if !strings.HasPrefix(in.Target, "/") || strings.HasPrefix(in.Target, "//") || strings.Contains(in.Target, `\`) {
		return MintResult{}, ErrTargetInvalid // only this site's paths: no open redirect
	}
	id, err := p.a.NewID(IDPrefix)
	if err != nil {
		return MintResult{}, err
	}
	ticket := auth.NewToken()
	expires := p.a.Now().Add(p.ttl)
	if _, err := p.a.Exec(ctx, sqlb.NewInsert(p.a.Dialect()).Into(TableTicket).Row(
		sqlb.Set(ID, id), sqlb.Set(UserID, c.User.ID), sqlb.Set(Hash, auth.HashToken(ticket)),
		sqlb.Set(Target, in.Target), sqlb.Set(ExpiresAt, expires),
	)); err != nil {
		return MintResult{}, err
	}
	c.Effects.Header(HeaderTicket, ticket.Reveal())
	return MintResult{ExpiresAt: expires}, nil
}

// doRedeem looks the ticket up by its hash and records a redirect to its
// target. An expired ticket that Sweep has not deleted yet is refused here,
// so how often the app sweeps changes storage, never behaviour.
//
//ds:def id=tickets-doredeem-2kd8vq5m
func (p *Plugin) doRedeem(ctx context.Context, c *auth.Call, in RedeemRequest) (auth.Done, error) {
	var target string
	var expires time.Time
	err := p.a.One(ctx, p.a.Select().Columns(sqlb.Bind(Target, &target), sqlb.Bind(ExpiresAt, &expires)).
		From(TableTicket).Where(sqlb.Eq(Hash, auth.HashToken(in.Ticket.Token()))))
	if errors.Is(err, sqlb.ErrNoRows) || (err == nil && !p.a.Now().Before(expires)) {
		return auth.Done{}, ErrInvalid
	}
	if err != nil {
		return auth.Done{}, err
	}
	c.Effects.Redirect(target)
	return auth.Done{OK: true}, nil
}
