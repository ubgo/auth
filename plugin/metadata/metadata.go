// Package metadata keeps three JSON documents per user, the shape Clerk made
// familiar:
//
//   - public: the user reads it, only the backend writes it. A plan, a role
//     label, an onboarding step the server decided.
//   - private: only the backend reads and writes it. A billing customer id,
//     an internal note. No operation a user can call ever answers it.
//   - unsafe: the user reads and writes it, through a JSON merge patch
//     (RFC 7396), capped in size. UI preferences, a dismissed banner. The
//     name is the warning: never trust it for a decision.
//
// The documents live in a table of the plugin's own, one row per user,
// rather than as columns on auth_user, for two reasons. A column extension is
// a short value (VARCHAR(320) on MySQL), too small for a document; and every
// auth_user column is loaded with the user, so a private document there would
// travel with every request's user, one careless encode away from a browser.
// Here it is read only when asked for.
//
// Every document is a JSON object; anything else is refused, so a client can
// always read a key without first checking the type. A user with no row reads
// as three empty objects.
package metadata

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity: migration and table owner.
const PluginName = "metadata"

// Operation ids. The two user operations are always served; the admin pair
// only under WithAdmin.
const (
	// EndpointGet answers the signed-in user's public and unsafe documents.
	//ds:def id=metadata-endpointget-4kq9wm2x owner=@khanakia stability=stable
	EndpointGet auth.EndpointID = "metadata.get"
	// EndpointUpdate merges a patch into the signed-in user's unsafe
	// document.
	//ds:def id=metadata-endpointupdate-7nr3xk5q owner=@khanakia stability=stable
	EndpointUpdate auth.EndpointID = "metadata.update"
	// EndpointAdminGet answers all three documents of any user, for a caller
	// the Authorizer allows.
	EndpointAdminGet auth.EndpointID = "metadata.admin-get"
	// EndpointAdminUpdate merges patches into any of a user's three
	// documents, for a caller the Authorizer allows.
	EndpointAdminUpdate auth.EndpointID = "metadata.admin-update"
)

// Kind names one of the three documents.
type Kind string

// The three documents.
const (
	// Public is readable by the user, writable by the backend only.
	Public Kind = "public"
	// Private is the backend's alone.
	Private Kind = "private"
	// Unsafe is the user's to read and write.
	Unsafe Kind = "unsafe"
)

// KindValues is the canonical iteration order over kinds.
var KindValues = []Kind{Public, Private, Unsafe}

// Size bounds, in bytes of the compact JSON encoding.
const (
	// DefaultMaxSize bounds the public and the private document unless
	// WithMaxSize changes it. 8 KiB is Clerk's bound on a user's metadata,
	// and public travels with every session answer that includes it.
	//ds:def id=metadata-defaultmaxsize-3wq8kn6v owner=@khanakia stability=stable
	DefaultMaxSize = 8 << 10
	// DefaultUnsafeMaxSize bounds the unsafe document unless
	// WithUnsafeMaxSize changes it: smaller, because any user fills it.
	//ds:def id=metadata-defaultunsafemaxsize-9mk2wr4t owner=@khanakia stability=stable
	DefaultUnsafeMaxSize = 4 << 10
	// MaxSizeLimit is the largest bound an option accepts: authhttp refuses
	// a request body over 1 MiB, so a larger document could be stored from
	// Go but never sent back through an update.
	MaxSizeLimit = 1 << 20
)

// The update rate a user gets by default (WithUpdateRate): enough for a
// settings page saved on every change, too few to use the table as a store.
const (
	DefaultUpdateLimit  = 30
	DefaultUpdateWindow = time.Minute
)

// The documents table: one row per user that was ever written. There is no
// foreign key (ADR-0002); DeleteUser removes the row through UserTables.
const (
	//ds:def id=metadata-tablename-6vq3kx8w owner=@khanakia stability=stable
	TableNameMetadata  = "auth_user_metadata"
	TableAliasMetadata = "umd"

	ColUserID    = "user_id"
	ColPublic    = "public_metadata"
	ColPrivate   = "private_metadata"
	ColUnsafe    = "unsafe_metadata"
	ColUpdatedAt = "updated_at"

	migrationTable = "0001_user_metadata"
)

// TableMetadata and its typed columns, for an app that reads or joins the
// documents (reads are open; only the plugin writes).
var (
	TableMetadata = sqlb.Table{Name: TableNameMetadata, Alias: TableAliasMetadata}

	MetaUserID    = sqlb.Col[string](TableMetadata, ColUserID)
	MetaPublic    = sqlb.Col[string](TableMetadata, ColPublic)
	MetaPrivate   = sqlb.Col[string](TableMetadata, ColPrivate)
	MetaUnsafe    = sqlb.Col[string](TableMetadata, ColUnsafe)
	MetaUpdatedAt = sqlb.Col[time.Time](TableMetadata, ColUpdatedAt)
)

// emptyObject is what a document reads as before anything was written.
var emptyObject = json.RawMessage(`{}`)

// Errors. The coded ones reach a client.
var (
	// ErrInvalid refuses a document or patch that is not a JSON object.
	ErrInvalid = auth.NewError("metadata.invalid", http.StatusBadRequest, "Metadata must be a JSON object.")
	// ErrTooLarge refuses a document, or a patch, over the kind's bound.
	ErrTooLarge = auth.NewError("metadata.too_large", http.StatusRequestEntityTooLarge, "The metadata is too large.")
	// ErrForbidden answers an admin operation the Authorizer did not allow.
	ErrForbidden = auth.NewError("metadata.forbidden", http.StatusForbidden, "You may not manage this user's metadata.")
	// ErrUnknownKind is a programming error from the Go API: a Kind outside
	// KindValues.
	ErrUnknownKind = errors.New("metadata: unknown kind")
)

// Metadata is all three documents of a user. Only the Go API and the admin
// operations return it; a user's own operations answer UserMetadata, which
// has no Private field to fill by mistake.
type Metadata struct {
	Public  json.RawMessage `json:"public"`
	Private json.RawMessage `json:"private"`
	Unsafe  json.RawMessage `json:"unsafe"`
}

// UserMetadata is what the user may see: public and unsafe. It is also what
// SessionExtras puts in the session answer.
type UserMetadata struct {
	Public json.RawMessage `json:"public"`
	Unsafe json.RawMessage `json:"unsafe"`
}

// UpdateRequest is the input of metadata.update: a merge patch for the
// unsafe document (RFC 7396). A key set to null is removed; an object merges
// into the object under its key; anything else replaces the key's value. The
// input has no field for the other documents, and authhttp refuses unknown
// fields, so a user cannot even name them.
type UpdateRequest struct {
	Unsafe json.RawMessage `json:"unsafe"`
}

// AdminGetRequest is the input of metadata.admin-get.
type AdminGetRequest struct {
	UserID string `json:"userId"`
}

// AdminUpdateRequest is the input of metadata.admin-update: a merge patch per
// document; a document whose patch is absent is left as it is.
type AdminUpdateRequest struct {
	UserID  string          `json:"userId"`
	Public  json.RawMessage `json:"public,omitempty"`
	Private json.RawMessage `json:"private,omitempty"`
	Unsafe  json.RawMessage `json:"unsafe,omitempty"`
}

// UnsafeCheck inspects the unsafe document a user's update would store,
// after the merge and before the write, for an app that allows only some
// keys or shapes; an error refuses the update and is answered as returned,
// so return an *auth.Error to give the client a code.
type UnsafeCheck func(ctx context.Context, userID string, doc json.RawMessage) error

// Plugin keeps the three documents. Build it with New.
type Plugin struct {
	// optErrs collects what the options found while they ran (a nil
	// interface, a bound out of range); auth.New refuses to start while it
	// is not nil (auth.OptionChecker).
	optErrs auth.OptionErrors
	core    *auth.Auth

	maxSize       int
	unsafeMaxSize int
	updateLimit   int
	updateWindow  time.Duration
	unsafeCheck   UnsafeCheck
	authorizer    Authorizer

	get         *auth.Op[struct{}, UserMetadata]
	update      *auth.Op[UpdateRequest, UserMetadata]
	adminGet    *auth.Op[AdminGetRequest, Metadata]
	adminUpdate *auth.Op[AdminUpdateRequest, Metadata]
}

// Option configures the plugin; options are applied in order by New.
type Option func(*Plugin)

// OptionErr is every error the options recorded; see auth.OptionChecker.
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// WithMaxSize bounds the public and the private document, in bytes of
// compact JSON, between 2 and MaxSizeLimit. Default DefaultMaxSize.
func WithMaxSize(bytes int) Option {
	return func(p *Plugin) {
		if p.checkSize("metadata.WithMaxSize", bytes) {
			p.maxSize = bytes
		}
	}
}

// WithUnsafeMaxSize bounds the unsafe document, and every patch a user
// sends, in bytes of compact JSON, between 2 and MaxSizeLimit. Default
// DefaultUnsafeMaxSize.
func WithUnsafeMaxSize(bytes int) Option {
	return func(p *Plugin) {
		if p.checkSize("metadata.WithUnsafeMaxSize", bytes) {
			p.unsafeMaxSize = bytes
		}
	}
}

// checkSize records a bound outside [len("{}"), MaxSizeLimit] as an option
// error naming the option, and reports whether the bound is usable.
func (p *Plugin) checkSize(name string, n int) bool {
	if n < len(emptyObject) || n > MaxSizeLimit {
		p.optErrs.JoinOptionErr(fmt.Errorf("%s(%d): the bound must be between %d and %d bytes", name, n, len(emptyObject), MaxSizeLimit))
		return false
	}
	return true
}

// WithUpdateRate limits metadata.update to limit calls per user per window,
// through the core's rate limiter (the app's RateStore counts it). Default
// DefaultUpdateLimit per DefaultUpdateWindow.
func WithUpdateRate(limit int, window time.Duration) Option {
	return func(p *Plugin) {
		if limit < 1 || window <= 0 {
			p.optErrs.JoinOptionErr(fmt.Errorf("metadata.WithUpdateRate(%d, %s): needs a limit of 1 or more and a positive window", limit, window))
			return
		}
		p.updateLimit, p.updateWindow = limit, window
	}
}

// WithUnsafeCheck runs fn on every unsafe document a user's update would
// store; see UnsafeCheck. It does not run for the Go API or the admin
// operations, which are trusted.
func WithUnsafeCheck(fn UnsafeCheck) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("metadata.WithUnsafeCheck", fn) {
			return
		}
		p.unsafeCheck = fn
	}
}

// WithAdmin serves metadata.admin-get and metadata.admin-update, each call
// decided by a. Without it neither route exists: the backend writes public
// and private through the Go API only. Wire it to plugin/admin with an
// AuthorizerFunc that calls admin's HasPermission, or to any other model.
func WithAdmin(a Authorizer) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("metadata.WithAdmin", a) {
			return
		}
		p.authorizer = a
	}
}

var (
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.TableOwner        = (*Plugin)(nil)
	_ auth.UserTableOwner    = (*Plugin)(nil)
	_ auth.TypedMigrator     = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.RateLimiter       = (*Plugin)(nil)
	_ auth.OptionChecker     = (*Plugin)(nil)
)

// New builds the plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{maxSize: DefaultMaxSize, unsafeMaxSize: DefaultUnsafeMaxSize, updateLimit: DefaultUpdateLimit, updateWindow: DefaultUpdateWindow}
	for _, o := range opts {
		o(p)
	}
	p.get = auth.Define(auth.OpInfo{ID: EndpointGet, Kind: auth.Query, Require: auth.SignedIn, Path: "/get"}, p.doGet)
	p.update = auth.Define(auth.OpInfo{ID: EndpointUpdate, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/update"}, p.doUpdate)
	p.adminGet = auth.Define(auth.OpInfo{ID: EndpointAdminGet, Kind: auth.Query, Require: auth.SignedIn, Path: "/admin-get"}, p.doAdminGet)
	p.adminUpdate = auth.Define(auth.OpInfo{ID: EndpointAdminUpdate, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/admin-update"}, p.doAdminUpdate)
	return p
}

// Name returns PluginName.
func (p *Plugin) Name() string { return PluginName }

// Init captures the core handle every statement goes through.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	return nil
}

// Tables declares the documents table, so New can check its alias and an app
// can rename it.
func (p *Plugin) Tables() []sqlb.Table { return []sqlb.Table{TableMetadata} }

// UserTables tells DeleteUser which row is a user's.
func (p *Plugin) UserTables() []auth.UserTable {
	return []auth.UserTable{{Table: TableMetadata, Column: ColUserID}}
}

// TypedMigrations creates the table. The documents take the engine's Doc
// type (TEXT, MEDIUMTEXT on MySQL), which has no default on MySQL, so every
// insert writes all three.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	st := "CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableMetadata) + " (" +
		ColUserID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
		ColPublic + " " + t.Doc + " NOT NULL, " +
		ColPrivate + " " + t.Doc + " NOT NULL, " +
		ColUnsafe + " " + t.Doc + " NOT NULL, " +
		ColUpdatedAt + " " + t.Timestamp + " NOT NULL)" + t.TableSuffix
	return []auth.Migration{{Owner: PluginName, Name: migrationTable, Statements: []string{st}}}, nil
}

// Operations lists the user operations, and the admin pair under WithAdmin.
func (p *Plugin) Operations() []auth.Operation {
	ops := []auth.Operation{p.get, p.update}
	if p.authorizer != nil {
		ops = append(ops, p.adminGet, p.adminUpdate)
	}
	return ops
}

// RateLimits counts metadata.update per user (WithUpdateRate).
func (p *Plugin) RateLimits() []auth.RateRule {
	return []auth.RateRule{{Match: EndpointUpdate, Key: auth.ByFunc, KeyFunc: auth.UserRateKey, Limit: p.updateLimit, Window: p.updateWindow}}
}

// Get returns all three documents of userID; a user with no row reads as
// three empty objects, and an unknown user is auth.ErrUserNotFound.
//
//ds:def id=metadata-get-8wn4kq2r owner=@khanakia stability=stable
func (p *Plugin) Get(ctx context.Context, userID string) (Metadata, error) {
	if p.core == nil {
		return Metadata{}, auth.ErrOperationNotWired
	}
	m, found, err := p.read(ctx, userID)
	if err != nil {
		return Metadata{}, err
	}
	if !found {
		if _, err := p.core.User(ctx, userID); err != nil {
			return Metadata{}, err
		}
	}
	return m, nil
}

// PublicOf returns userID's public document alone, for a JWT claim or a
// server-rendered page.
//
//ds:def id=metadata-publicof-2kr7wn5m owner=@khanakia stability=stable
func (p *Plugin) PublicOf(ctx context.Context, userID string) (json.RawMessage, error) {
	m, err := p.Get(ctx, userID)
	return m.Public, err
}

// Set replaces document kind of userID with doc, which must be a JSON object
// within the kind's bound. A nil or empty doc stores {}.
//
//ds:def id=metadata-set-5tq8wk3n owner=@khanakia stability=stable
func (p *Plugin) Set(ctx context.Context, userID string, kind Kind, doc json.RawMessage) error {
	return p.write(ctx, userID, func(m *Metadata) error {
		cur, err := m.doc(kind)
		if err != nil {
			return err
		}
		if len(doc) == 0 {
			doc = emptyObject
		}
		obj, err := parseObject(doc)
		if err != nil {
			return err
		}
		*cur = encode(obj)
		return nil
	})
}

// Merge applies patch (RFC 7396) to document kind of userID and returns the
// document stored. The patch must be a JSON object; the result is bounded by
// the kind's size.
//
//ds:def id=metadata-merge-3vn9xq6k owner=@khanakia stability=stable
func (p *Plugin) Merge(ctx context.Context, userID string, kind Kind, patch json.RawMessage) (json.RawMessage, error) {
	var out json.RawMessage
	err := p.write(ctx, userID, func(m *Metadata) error {
		cur, err := m.doc(kind)
		if err != nil {
			return err
		}
		if err := mergeInto(cur, patch); err != nil {
			return err
		}
		out = *cur
		return nil
	})
	return out, err
}

// SessionExtras puts the user's public and unsafe documents in the session
// answer (GET /session) as an UserMetadata: pass it to auth.WithSessionExtras,
// or call it from the app's own extras function and nest the result. Private
// is never read by it.
//
//ds:def id=metadata-sessionextras-6mq2wk9t owner=@khanakia stability=stable
func (p *Plugin) SessionExtras(ctx context.Context, c *auth.Call) (any, error) {
	if c.User == nil {
		return nil, nil
	}
	return p.mine(ctx, c.User.ID)
}

// mine is what the user may see of their own documents.
func (p *Plugin) mine(ctx context.Context, userID string) (UserMetadata, error) {
	m, _, err := p.read(ctx, userID)
	if err != nil {
		return UserMetadata{}, err
	}
	return UserMetadata{Public: m.Public, Unsafe: m.Unsafe}, nil
}

func (p *Plugin) doGet(ctx context.Context, c *auth.Call, _ struct{}) (UserMetadata, error) {
	return p.mine(ctx, c.User.ID)
}

// doUpdate merges the user's patch into unsafe. The patch is bounded before
// it is parsed, and the result after the merge, so neither a huge patch nor
// many small ones grow the document past the bound.
func (p *Plugin) doUpdate(ctx context.Context, c *auth.Call, in UpdateRequest) (UserMetadata, error) {
	if len(in.Unsafe) > p.unsafeMaxSize {
		return UserMetadata{}, ErrTooLarge
	}
	var out UserMetadata
	err := p.write(ctx, c.User.ID, func(m *Metadata) error {
		if err := mergeInto(&m.Unsafe, in.Unsafe); err != nil {
			return err
		}
		if p.unsafeCheck != nil {
			if err := p.unsafeCheck(ctx, c.User.ID, m.Unsafe); err != nil {
				return err
			}
		}
		out = UserMetadata{Public: m.Public, Unsafe: m.Unsafe}
		return nil
	})
	return out, err
}

func (p *Plugin) doAdminGet(ctx context.Context, c *auth.Call, in AdminGetRequest) (Metadata, error) {
	if err := p.authorize(ctx, c, in.UserID, ActionRead); err != nil {
		return Metadata{}, err
	}
	return p.Get(ctx, in.UserID)
}

func (p *Plugin) doAdminUpdate(ctx context.Context, c *auth.Call, in AdminUpdateRequest) (Metadata, error) {
	if err := p.authorize(ctx, c, in.UserID, ActionWrite); err != nil {
		return Metadata{}, err
	}
	if _, err := p.core.User(ctx, in.UserID); err != nil {
		return Metadata{}, err
	}
	var out Metadata
	err := p.write(ctx, in.UserID, func(m *Metadata) error {
		for _, kp := range []struct {
			doc   *json.RawMessage
			patch json.RawMessage
		}{{&m.Public, in.Public}, {&m.Private, in.Private}, {&m.Unsafe, in.Unsafe}} {
			if kp.patch == nil {
				continue
			}
			if err := mergeInto(kp.doc, kp.patch); err != nil {
				return err
			}
		}
		out = *m
		return nil
	})
	return out, err
}

// doc returns the field of kind, or ErrUnknownKind.
func (m *Metadata) doc(kind Kind) (*json.RawMessage, error) {
	switch kind {
	case Public:
		return &m.Public, nil
	case Private:
		return &m.Private, nil
	case Unsafe:
		return &m.Unsafe, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownKind, kind)
}

// read loads userID's row; found is false when there is none, and m is then
// three empty objects.
func (p *Plugin) read(ctx context.Context, userID string) (m Metadata, found bool, err error) {
	var pub, priv, uns string
	q := p.core.Select().Columns(sqlb.Bind(MetaPublic, &pub), sqlb.Bind(MetaPrivate, &priv), sqlb.Bind(MetaUnsafe, &uns)).
		From(TableMetadata).Where(sqlb.Eq(MetaUserID, userID)).Limit(1)
	if err := p.core.One(ctx, q); err != nil {
		if errors.Is(err, sqlb.ErrNoRows) {
			return Metadata{Public: emptyObject, Private: emptyObject, Unsafe: emptyObject}, false, nil
		}
		return Metadata{}, false, fmt.Errorf("metadata: read: %w", err)
	}
	return Metadata{Public: json.RawMessage(pub), Private: json.RawMessage(priv), Unsafe: json.RawMessage(uns)}, true, nil
}

// write runs change on userID's documents and stores the result, in one
// transaction. The first statement touches the row (or creates it), which
// takes the row lock on Postgres and MySQL and the write lock on SQLite, so
// two concurrent merges apply one after the other rather than one losing the
// other's keys. Two first writes for one user can both find no row; the
// loser's insert is a unique violation, and the whole transaction is run
// again, once, when it finds the winner's row.
func (p *Plugin) write(ctx context.Context, userID string, change func(*Metadata) error) error {
	if p.core == nil {
		return auth.ErrOperationNotWired
	}
	err := p.writeOnce(ctx, userID, change)
	if auth.IsUniqueViolation(err) {
		err = p.writeOnce(ctx, userID, change)
	}
	return err
}

func (p *Plugin) writeOnce(ctx context.Context, userID string, change func(*Metadata) error) error {
	dialect := p.core.Dialect()
	return p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		now := p.core.Now()
		n, err := p.core.Exec(ctx, sqlb.NewUpdate(dialect).Table(TableMetadata).Set(sqlb.Set(MetaUpdatedAt, now)).Where(sqlb.Eq(MetaUserID, userID)))
		if err != nil {
			return fmt.Errorf("metadata: lock: %w", err)
		}
		if n == 0 {
			if _, err := p.core.User(ctx, userID); err != nil {
				return err
			}
			empty := string(emptyObject)
			if _, err := p.core.Exec(ctx, sqlb.NewInsert(dialect).Into(TableMetadata).Row(
				sqlb.Set(MetaUserID, userID), sqlb.Set(MetaPublic, empty), sqlb.Set(MetaPrivate, empty),
				sqlb.Set(MetaUnsafe, empty), sqlb.Set(MetaUpdatedAt, now))); err != nil {
				return err
			}
		}
		m, _, err := p.read(ctx, userID)
		if err != nil {
			return err
		}
		if err := change(&m); err != nil {
			return err
		}
		if err := p.bound(m); err != nil {
			return err
		}
		_, err = p.core.Exec(ctx, sqlb.NewUpdate(dialect).Table(TableMetadata).Set(
			sqlb.Set(MetaPublic, string(m.Public)), sqlb.Set(MetaPrivate, string(m.Private)),
			sqlb.Set(MetaUnsafe, string(m.Unsafe)), sqlb.Set(MetaUpdatedAt, now)).Where(sqlb.Eq(MetaUserID, userID)))
		if err != nil {
			return fmt.Errorf("metadata: write: %w", err)
		}
		return nil
	})
}

// bound refuses a document over its kind's size.
func (p *Plugin) bound(m Metadata) error {
	if len(m.Public) > p.maxSize || len(m.Private) > p.maxSize || len(m.Unsafe) > p.unsafeMaxSize {
		return ErrTooLarge
	}
	return nil
}

// mergeInto applies patch to *doc (RFC 7396) and stores the compact result.
func mergeInto(doc *json.RawMessage, patch json.RawMessage) error {
	pobj, err := parseObject(patch)
	if err != nil {
		return err
	}
	target, err := parseObject(*doc)
	if err != nil {
		// A stored document that is not an object was written outside the
		// plugin; the patch starts it over, as RFC 7396 does for a
		// non-object target.
		target = map[string]any{}
	}
	*doc = encode(mergePatch(target, pobj))
	return nil
}

// mergePatch is RFC 7396's MergePatch: a null removes the key, an object
// merges recursively, any other value replaces.
func mergePatch(target any, patch any) any {
	pm, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	tm, ok := target.(map[string]any)
	if !ok {
		tm = map[string]any{}
	}
	for k, v := range pm {
		if v == nil {
			delete(tm, k)
			continue
		}
		tm[k] = mergePatch(tm[k], v)
	}
	return tm
}

// parseObject decodes raw as one JSON object, keeping numbers exact
// (UseNumber), and refuses anything else, trailing data included, with
// ErrInvalid. A Decoder stops after the first value, so the next token must
// be the end of the input: More alone reports false for a stray "]".
func parseObject(raw json.RawMessage) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, ErrInvalid
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrInvalid
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, ErrInvalid
	}
	return obj, nil
}

// encode writes v as compact JSON with sorted keys, so equal documents are
// equal bytes; HTML characters are left as they are (no \u003c), since the
// documents are data, not markup.
//
// It returns no error because none can occur: v is always a tree that
// parseObject decoded (or mergePatch built from such trees), so it holds only
// map[string]any, []any, string, bool, json.Number and nil, and
// encoding/json encodes every one of those. Encode's only failures are an
// unsupported type, a cycle, a json.Number that is not a number, or a
// Marshaler error, and a decoded tree has none of them. Never pass it a
// value from anywhere else.
func encode(v any) json.RawMessage {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v) // cannot fail on a decoded tree; see above
	return json.RawMessage(bytes.TrimRight(b.Bytes(), "\n"))
}
