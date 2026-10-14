// Package devices is a plugin with a table of its own: each user names the
// devices they trust. It shows the whole contract for a plugin table —
// declaring it (TableOwner), writing its DDL per engine (Migrator), reading
// and writing it through typed columns (Auth.Exec, One, Each) — and three
// operations of the three requirement levels a signed-in feature uses.
//
// It uses only exported API, so a plugin in your own repository can do
// everything it does.
package devices

import (
	"context"
	"errors"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Names the plugin registers. PluginName is the route prefix and the owner of
// the table's migration, so renaming it orphans that migration.
const (
	PluginName = "devices"

	// TableNameDevice carries the library's auth_ prefix, so "auth migrate
	// orphans" knows it is ours once the plugin is gone; TableAliasDevice
	// is what statements qualify its columns with, and auth.New refuses a
	// second plugin that claims it.
	TableNameDevice  = "auth_device"
	TableAliasDevice = "dv"

	ColID        = "id"
	ColUserID    = "user_id"
	ColName      = "name"
	ColCreatedAt = "created_at"

	// IDPrefix starts every device id, like the core's usr_ and ses_.
	IDPrefix = "dev"
)

// The operations, by id. Another plugin's hook names them with these.
//
//ds:def id=devices-endpoints-jkuxfrv8 owner=@khanakia stability=stable
const (
	EndpointAdd    auth.EndpointID = "devices.add"
	EndpointList   auth.EndpointID = "devices.list"
	EndpointRemove auth.EndpointID = "devices.remove"
)

// Limits. MaxNameLength keeps a name a label and not a message; DefaultMax
// bounds how many devices one user may hold, so a script cannot fill the
// table; the add rule bounds how fast one address may try.
const (
	MaxNameLength = 40
	DefaultMax    = 10
	addLimit      = 30
	addWindow     = time.Hour
)

// Errors with stable codes: a client matches the code, never the message,
// and the status is what HTTP answers.
//
//ds:def id=devices-errorgroup-k6gt8gtn owner=@khanakia stability=stable
var (
	ErrNameInvalid = auth.NewError("devices.name_invalid", http.StatusBadRequest, "Give the device a name of up to 40 characters.")
	ErrNameTaken   = auth.NewError("devices.name_taken", http.StatusConflict, "You already have a device with that name.")
	ErrTooMany     = auth.NewError("devices.too_many", http.StatusConflict, "Remove a device before adding another.")
	ErrNotFound    = auth.NewError("devices.not_found", http.StatusNotFound, "No such device.")
	// ErrBadMax is a configuration error: auth.New reports it, so a wrong
	// option fails the start instead of refusing every add.
	ErrBadMax = errors.New("devices: the device limit must be at least 1")
)

// The table and its typed columns. A column carries the Go type it holds, so
// comparing CreatedAt with a string does not compile.
var (
	//ds:def id=devices-columns-484sberx owner=@khanakia stability=stable
	TableDevice = sqlb.Table{Name: TableNameDevice, Alias: TableAliasDevice}
	ID          = sqlb.Col[string](TableDevice, ColID)
	UserID      = sqlb.Col[string](TableDevice, ColUserID)
	Name        = sqlb.Col[string](TableDevice, ColName)
	CreatedAt   = sqlb.Col[time.Time](TableDevice, ColCreatedAt)
)

// Device is one row, as every transport returns it.
type Device struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

// Bindings binds a row to d, for a query on TableDevice.
//
//ds:def id=devices-bindings-vwbmdb3p owner=@khanakia stability=stable
func Bindings(d *Device) []sqlb.Binding {
	return []sqlb.Binding{sqlb.Bind(ID, &d.ID), sqlb.Bind(Name, &d.Name), sqlb.Bind(CreatedAt, &d.CreatedAt)}
}

// AddRequest is the input of devices.add.
//
//ds:def id=devices-addrequest-6jx3zfcj owner=@khanakia stability=stable
type AddRequest struct {
	Name string `json:"name"`
}

// RemoveRequest is the input of devices.remove.
type RemoveRequest struct {
	ID string `json:"id"`
}

// ListResult is the output of devices.list.
type ListResult struct {
	Devices []Device `json:"devices"`
}

// Option configures New.
type Option func(*Plugin)

// WithMax sets how many devices one user may hold.
func WithMax(n int) Option { return func(p *Plugin) { p.max = n } }

// Plugin is the devices plugin. Build it with New.
type Plugin struct {
	a   *auth.Auth
	max int

	add    *auth.Op[AddRequest, auth.Done]
	list   *auth.Op[struct{}, ListResult]
	remove *auth.Op[RemoveRequest, auth.Done]
}

// The optional interfaces this plugin implements, checked by the compiler so
// a typo in a method signature fails the build instead of silently dropping a
// capability.
//
//ds:def id=devices-interfaces-hk26c8qn owner=@khanakia stability=stable
var (
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.TableOwner        = (*Plugin)(nil)
	_ auth.TypedMigrator     = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.RateLimiter       = (*Plugin)(nil)
)

// New builds the plugin and declares its operations: adding needs a session,
// listing is a read, removing needs a recent sign-in, because a stolen
// laptop must not be able to quietly drop the owner's other devices.
//
//ds:def id=devices-new-ebt28tw6 owner=@khanakia stability=stable
func New(opts ...Option) *Plugin {
	p := &Plugin{max: DefaultMax}
	for _, o := range opts {
		o(p)
	}
	p.add = auth.Define(auth.OpInfo{ID: EndpointAdd, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/add"}, p.doAdd)
	p.list = auth.Define(auth.OpInfo{ID: EndpointList, Kind: auth.Query, Require: auth.SignedIn, Path: "/list"}, p.doList)
	p.remove = auth.Define(auth.OpInfo{ID: EndpointRemove, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/remove"}, p.doRemove)
	return p
}

// Name is the only method every plugin must have.
//
//ds:def id=devices-name-zcbgc7tj owner=@khanakia stability=stable
func (p *Plugin) Name() string { return PluginName }

// Init keeps the core handle; every statement runs through it.
//
//ds:def id=devices-init-g27d2ft4 owner=@khanakia stability=stable
func (p *Plugin) Init(a *auth.Auth) error {
	p.a = a
	return nil
}

// Validate refuses a limit nobody could add a device under. It runs in
// auth.New, so the mistake is a failed start, not a mystery at run time.
//
//ds:def id=devices-validate-qx9nrmgv owner=@khanakia stability=stable
func (p *Plugin) Validate(*auth.Config) error {
	if p.max < 1 {
		return ErrBadMax
	}
	return nil
}

// Tables declares the table and its alias, so auth.New can refuse another
// plugin that picks the same alias before an ambiguous column ever renders.
//
//ds:def id=devices-tables-abyjw3he owner=@khanakia stability=stable
func (p *Plugin) Tables() []sqlb.Table { return []sqlb.Table{TableDevice} }

// UserTables tells the core that a device row belongs to the user in its
// user_id column, so auth.DeleteUser deletes a user's devices in the same
// transaction as the user. The library creates no foreign keys (ADR-0002), so
// this declaration is what removes the rows.
//
//ds:def id=devices-usertables-2hq7kx9m owner=@khanakia stability=stable
func (p *Plugin) UserTables() []auth.UserTable {
	return []auth.UserTable{{Table: TableDevice, Column: ColUserID}}
}

// TypedMigrations writes the table for the engine in the types it is handed:
// each engine's spelling of the types the core uses (auth.TypesFor), with
// the app's auth.WithSQLTypes overrides applied, so a device's user_id has
// the same type as the user id it holds. The table is named through
// the core (TableName), never by concatenating the TableNameDevice constant:
// the app may have given it another real name with auth.RenameTable or
// auth.WithTablePrefix, and the constant is only its label. There is no
// foreign key: UserTables tells the core which column holds the user, and
// DeleteUser removes a user's devices itself. The UNIQUE constraint is
// inline, which every engine accepts, so one user cannot name two devices
// alike.
//
//ds:def id=devices-migrations-kn89f6ym owner=@khanakia stability=stable
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	return []auth.Migration{{Owner: PluginName, Name: "0001_devices", Statements: []string{
		"CREATE TABLE IF NOT EXISTS " + p.a.TableName(TableDevice) + " (" +
			ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColUserID + " " + t.ID + " NOT NULL, " +
			ColName + " " + t.Text + " NOT NULL, " +
			ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
			"UNIQUE (" + ColUserID + ", " + ColName + "))" + t.TableSuffix,
	}}}, nil
}

// Operations lists the operations for every transport: POST /auth/devices/add,
// GET /auth/devices/list and POST /auth/devices/remove over HTTP.
//
//ds:def id=devices-operations-aq69swbp owner=@khanakia stability=stable
func (p *Plugin) Operations() []auth.Operation { return []auth.Operation{p.add, p.list, p.remove} }

// RateLimits bounds adding per address.
//
//ds:def id=devices-ratelimits-4gjqnrum owner=@khanakia stability=stable
func (p *Plugin) RateLimits() []auth.RateRule {
	return []auth.RateRule{{Match: EndpointAdd, Key: auth.ByIP, Limit: addLimit, Window: addWindow}}
}

// Add, List and Remove are the Go API: the same operations the routes run,
// through the same pipeline.
//
//ds:def id=devices-add-jykfexuf owner=@khanakia stability=stable
func (p *Plugin) Add(ctx context.Context, name string) error {
	_, err := p.add.Call(ctx, AddRequest{Name: name})
	return err
}

// List returns the signed-in user's devices.
func (p *Plugin) List(ctx context.Context) (ListResult, error) { return p.list.Call(ctx, struct{}{}) }

// Remove deletes one of the signed-in user's devices.
func (p *Plugin) Remove(ctx context.Context, id string) error {
	_, err := p.remove.Call(ctx, RemoveRequest{ID: id})
	return err
}

// doAdd runs inside the mutation's transaction: the count and the insert see
// the same state, and a failure after the insert rolls it back.
//
//ds:def id=devices-doadd-9uz3f877 owner=@khanakia stability=stable
func (p *Plugin) doAdd(ctx context.Context, c *auth.Call, in AddRequest) (auth.Done, error) {
	n := utf8.RuneCountInString(in.Name)
	if n == 0 || n > MaxNameLength {
		return auth.Done{}, ErrNameInvalid
	}
	var have int64
	if err := p.a.One(ctx, p.a.Select().Columns(sqlb.Bind(sqlb.Count(), &have)).From(TableDevice).Where(sqlb.Eq(UserID, c.User.ID))); err != nil {
		return auth.Done{}, err
	}
	if have >= int64(p.max) {
		return auth.Done{}, ErrTooMany
	}
	id, err := p.a.NewID(IDPrefix)
	if err != nil {
		return auth.Done{}, err
	}
	_, err = p.a.Exec(ctx, sqlb.NewInsert(p.a.Dialect()).Into(TableDevice).Row(
		sqlb.Set(ID, id), sqlb.Set(UserID, c.User.ID), sqlb.Set(Name, in.Name), sqlb.Set(CreatedAt, p.a.Now()),
	))
	if auth.IsUniqueViolation(err) {
		return auth.Done{}, ErrNameTaken
	}
	if err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

// doList reads the user's devices, oldest first, ties by id, so the order is
// the same on every engine.
//
//ds:def id=devices-dolist-z8ny3ckw owner=@khanakia stability=stable
func (p *Plugin) doList(ctx context.Context, c *auth.Call, _ struct{}) (ListResult, error) {
	var row Device
	out := ListResult{Devices: []Device{}}
	q := p.a.Select().Columns(Bindings(&row)...).From(TableDevice).
		Where(sqlb.Eq(UserID, c.User.ID)).
		Order(sqlb.OrderBy(CreatedAt, sqlb.SortAsc), sqlb.OrderBy(ID, sqlb.SortAsc))
	err := p.a.Each(ctx, q, func() error { out.Devices = append(out.Devices, row); return nil })
	return out, err
}

// doRemove deletes one device. The user id in the WHERE is what keeps
// removing by id safe: another user's id matches nothing.
//
//ds:def id=devices-doremove-625naawv owner=@khanakia stability=stable
func (p *Plugin) doRemove(ctx context.Context, c *auth.Call, in RemoveRequest) (auth.Done, error) {
	n, err := p.a.Exec(ctx, sqlb.NewDelete(p.a.Dialect()).From(TableDevice).Where(sqlb.Eq(ID, in.ID), sqlb.Eq(UserID, c.User.ID)))
	if err != nil {
		return auth.Done{}, err
	}
	if n == 0 {
		return auth.Done{}, ErrNotFound
	}
	return auth.Done{OK: true}, nil
}
