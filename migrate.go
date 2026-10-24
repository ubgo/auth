package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ubgo/sqlb"
	"github.com/ubgo/sqlb/render"
)

// Migration is one named change owned by the core or a plugin.
//
// Name is its identity for ever: the ledger remembers it by Owner and Name,
// and a Statement changed after it ran stops the next Migrate with
// ErrChecksumMismatch instead of being silently skipped or run again.
//
// Why the core has its own ledger rather than sqlb's contrib/migrate: when
// this was written that module required a sqlb tag that did not exist yet, and
// the core module still depends on the standard library and sqlb only, so
// importing contrib/migrate would add a requirement every consumer inherits.
// This ledger is deliberately small.
//
//ds:def id=core-migration-jfbu8by8 owner=@khanakia stability=stable
type Migration struct {
	// Owner is CorePluginName or the name of the plugin that ships it;
	// Migrations refuses a plugin migration that names another owner.
	Owner string
	// Name orders nothing; it only identifies. Prefix it with a number, as
	// "0001_tables", so a listing reads in the order it was written.
	Name string
	// Statements run in order, one ExecContext each, written for the engine
	// the migration was generated for.
	Statements []string
}

// Migrator is a plugin that ships migrations of its own tables. The statements
// must be written for the dialect it is given; a plugin that supports an engine
// it cannot write for returns ErrEngineNotSupported.
//
// The core calls Migrations only on an initialised plugin (after Init), and
// the plugin names every table through the Auth it was given there
// (a.TableName), never by concatenating a TableName constant, because the app
// may have renamed the table (RenameTable, WithTablePrefix) and the constant
// is only its label. A migration creates no foreign key and no cascade
// (ADR-0002): a table whose rows belong to a user is listed in UserTables
// instead, and DeleteUser removes the rows.
//
//ds:def id=core-migrator-2zu9w44h owner=@khanakia stability=stable
type Migrator interface {
	Migrations(engine string) ([]Migration, error)
}

// Ledger errors.
var (
	//ds:def id=core-errchecksum-brj9fryp owner=@khanakia stability=stable
	ErrChecksumMismatch   = errors.New("auth: a migration changed after it was applied")
	ErrEngineNotSupported = errors.New("auth: engine not supported")
)

// Engine names, as sqlb reports them.
const (
	EnginePostgres = render.DialectPostgres
	EngineMySQL    = render.DialectMySQL
	EngineSQLite   = render.DialectSQLite
)

// Engine returns the engine name of the configured dialect.
func (a *Auth) Engine() string { return render.DialectName(a.cfg.Dialect) }

// Migrations returns every migration in the order Migrate applies them: the
// core's, then for each plugin in list order its identity indexes, its column
// extensions and its own migrations.
//
// It refuses an engine the core cannot write DDL for with
// ErrEngineNotSupported, once, here; every generator below may then assume a
// supported engine.
func (a *Auth) Migrations() ([]Migration, error) {
	engine := a.Engine()
	if err := supported(engine); err != nil {
		return nil, err
	}
	out := a.coreMigrations(engine)
	if a.dbRates {
		out = append(out, a.rateLimitMigration(engine))
	}
	if a.outbox != nil {
		out = append(out, a.outboxMigration(engine))
	}
	for _, p := range a.plugins {
		if prov, ok := p.(IdentifierProvider); ok {
			for _, k := range prov.Identifiers() {
				if !k.Unique {
					continue
				}
				out = append(out, a.identityIndexMigration(engine, p.Name(), k))
			}
		}
		for _, c := range a.columns {
			if c.owner != p.Name() {
				continue
			}
			out = append(out, a.columnMigration(engine, c))
		}
		if ms, ok, err := a.pluginMigrations(engine, p); ok {
			if err != nil {
				return nil, fmt.Errorf("auth: plugin %q migrations: %w", p.Name(), err)
			}
			for _, m := range ms {
				if m.Owner != p.Name() {
					return nil, fmt.Errorf("auth: plugin %q ships a migration owned by %q", p.Name(), m.Owner)
				}
			}
			out = append(out, ms...)
		}
	}
	// The app's own columns come last, after every plugin's, as the app is
	// the last to be wired.
	for _, c := range a.columns {
		if c.owner == AppName {
			out = append(out, a.columnMigration(engine, c))
		}
	}
	return out, nil
}

// MigrationSQL returns every migration's statements as one script, for review
// or for an app that applies SQL with its own tool.
//
//ds:def id=core-migrationsql-8w4m33nv owner=@khanakia stability=stable
func (a *Auth) MigrationSQL() (string, error) {
	ms, err := a.Migrations()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, m := range ms {
		fmt.Fprintf(&b, "-- %s %s\n", m.Owner, m.Name)
		for _, st := range m.Statements {
			b.WriteString(st)
			b.WriteString(";\n")
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

// Checksum is a migration's identity in the ledger.
func (m Migration) Checksum() string {
	h := sha256.New()
	for _, st := range m.Statements {
		h.Write([]byte(st))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// migrationLockName serializes Migrate across processes.
const migrationLockName = "ubgo_auth_migrate"

// migrationLockKey is migrationLockName as the bigint key Postgres advisory
// locks take: the first eight bytes of its SHA-256, so every instance derives
// the same key with no configuration.
var migrationLockKey = func() int64 {
	sum := sha256.Sum256([]byte(migrationLockName))
	return int64(binary.BigEndian.Uint64(sum[:]))
}()

// ledgerTimeLayout is how applied_at is written. The ledger column is text on
// every engine (SQLTypes.Key), so the layout is fixed here instead of being
// left to each driver's rendering of a time.Time.
const ledgerTimeLayout = time.DateTime

// mysqlLockTimeoutSeconds is how long MySQL's GET_LOCK waits for another
// instance's Migrate to finish before giving up.
const mysqlLockTimeoutSeconds = 60

// Migrate applies every migration not yet in the ledger and returns their
// "owner/name" labels in order.
//
// One connection is pinned for the whole run, because the lock belongs to a
// connection. On Postgres and SQLite each migration and its ledger row commit
// together. MySQL commits every DDL statement on its own, so a failure part way
// through a migration there leaves its earlier statements applied and no
// ledger row; the error names the migration, and the operator repairs it by
// hand before running Migrate again.
//
//ds:def id=core-migrate-p4m2kwpk owner=@khanakia stability=stable
func (a *Auth) Migrate(ctx context.Context) ([]string, error) {
	ms, conn, err := a.migrationConn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	engine := a.Engine()
	unlock, err := lockMigrations(ctx, conn, engine)
	if err != nil {
		return nil, err
	}
	defer unlock()

	ledger := a.TableName(TableMigrations)
	applied, err := readLedger(ctx, conn, a.typesFor(engine), ledger)
	if err != nil {
		return nil, err
	}

	var done []string
	for _, m := range ms {
		key := m.Owner + "/" + m.Name
		if sum, ok := applied[key]; ok {
			if sum != m.Checksum() {
				return done, fmt.Errorf("%w: %s", ErrChecksumMismatch, key)
			}
			continue
		}
		if err := applyOne(ctx, conn, engine, ledger, m, a.now().Format(ledgerTimeLayout)); err != nil {
			return done, fmt.Errorf("auth: migration %s: %w", key, err)
		}
		done = append(done, key)
	}
	return done, nil
}

// MigrationState is one migration and whether the ledger has it.
//
//ds:def id=core-migrationstate-49ja73xz owner=@khanakia stability=stable
type MigrationState struct {
	Owner string
	Name  string
	// Applied is true when the ledger has a row for Owner and Name.
	Applied bool
	// Changed is true when the ledger has the migration with another
	// checksum: the next Migrate stops with ErrChecksumMismatch.
	Changed bool
}

// MigrationStatus compares every migration with the ledger without changing
// anything. A missing ledger means nothing is applied yet.
//
//ds:def id=core-migrationstatus-um9ygmfn owner=@khanakia stability=stable
func (a *Auth) MigrationStatus(ctx context.Context) ([]MigrationState, error) {
	ms, conn, err := a.migrationConn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	applied, err := readLedger(ctx, conn, a.typesFor(a.Engine()), a.TableName(TableMigrations))
	if err != nil {
		return nil, err
	}
	out := make([]MigrationState, 0, len(ms))
	for _, m := range ms {
		sum, ok := applied[m.Owner+"/"+m.Name]
		out = append(out, MigrationState{Owner: m.Owner, Name: m.Name, Applied: ok, Changed: ok && sum != m.Checksum()})
	}
	return out, nil
}

// applyOne runs one migration's statements and writes its ledger row: in one
// transaction where DDL is transactional, one statement at a time on MySQL,
// where every DDL statement commits by itself (see Migrate). ledger is the
// ledger table's real name.
func applyOne(ctx context.Context, conn *sql.Conn, engine, ledger string, m Migration, at string) error {
	insert := placeholders(engine, "INSERT INTO "+ledger+" (owner, name, checksum, applied_at) VALUES (?, ?, ?, ?)")
	if engine == EngineMySQL {
		for _, st := range m.Statements {
			if _, err := conn.ExecContext(ctx, st); err != nil {
				return err
			}
		}
		_, err := conn.ExecContext(ctx, insert, m.Owner, m.Name, m.Checksum(), at)
		return err
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, st := range m.Statements {
		if _, err := tx.ExecContext(ctx, st); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, insert, m.Owner, m.Name, m.Checksum(), at); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// migrationConn is the start Migrate and MigrationStatus share: every
// migration of this configuration, and one connection pinned for the run. The
// caller closes the connection.
func (a *Auth) migrationConn(ctx context.Context) ([]Migration, *sql.Conn, error) {
	if a.db == nil {
		return nil, nil, ErrNoDatabase
	}
	ms, err := a.Migrations()
	if err != nil {
		return nil, nil, err
	}
	conn, err := a.db.Conn(ctx)
	if err != nil {
		return nil, nil, err
	}
	return ms, conn, nil
}

// readLedger creates the ledger when it is missing, then returns the checksum
// of every applied migration by "owner/name". ledger is the ledger table's
// real name.
func readLedger(ctx context.Context, conn *sql.Conn, t SQLTypes, ledger string) (map[string]string, error) {
	if _, err := conn.ExecContext(ctx, ledgerDDL(t, ledger)); err != nil {
		return nil, fmt.Errorf("auth: create ledger: %w", err)
	}
	rows, err := conn.QueryContext(ctx, "SELECT owner, name, checksum FROM "+ledger)
	if err != nil {
		return nil, fmt.Errorf("auth: read ledger: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var owner, name, sum string
		if err := rows.Scan(&owner, &name, &sum); err != nil {
			return nil, err
		}
		out[owner+"/"+name] = sum
	}
	return out, rows.Err()
}

// lockMigrations takes the cross-process migration lock on conn and returns
// its release. A failed release is not reported: Migrate's own result is
// already decided when it runs, and both engines end the lock with the
// database session it belongs to at the latest.
func lockMigrations(ctx context.Context, conn *sql.Conn, engine string) (func(), error) {
	switch engine {
	case EnginePostgres:
		if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); err != nil {
			return nil, fmt.Errorf("auth: take migration lock: %w", err)
		}
		return func() {
			_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", migrationLockKey)
		}, nil
	case EngineMySQL:
		var got sql.NullInt64
		if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, ?)", migrationLockName, mysqlLockTimeoutSeconds).Scan(&got); err != nil {
			return nil, fmt.Errorf("auth: take migration lock: %w", err)
		}
		if !got.Valid || got.Int64 != 1 {
			return nil, fmt.Errorf("auth: another process holds the migration lock")
		}
		return func() { _, _ = conn.ExecContext(context.Background(), "SELECT RELEASE_LOCK(?)", migrationLockName) }, nil
	default:
		// SQLite, the only other engine Migrations accepts, has one writer at
		// a time already, and each migration runs in its own transaction, so
		// two processes cannot interleave one.
		return func() {}, nil
	}
}

// placeholders rewrites "?" to "$n" for Postgres. It is used only on the
// ledger's own fixed statements, which contain no "?" other than parameters.
func placeholders(engine, q string) string {
	if engine != EnginePostgres {
		return q
	}
	var b strings.Builder
	n := 0
	for _, r := range q {
		if r == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ledgerDDL creates the ledger table under its real name, in the types of
// the app's engine (typesFor).
func ledgerDDL(t SQLTypes, ledger string) string {
	return "CREATE TABLE IF NOT EXISTS " + ledger + " (owner " + t.Key + " NOT NULL, name " + t.Key +
		" NOT NULL, checksum " + t.Key + " NOT NULL, applied_at " + t.Key + " NOT NULL, PRIMARY KEY (owner, name))" + t.TableSuffix
}

// SQLTypes is each engine's spelling of the few types auth tables use, so a
// plugin writing its own migration uses the same spellings as the core.
//
//ds:def id=core-sqltypes-m9pb5g5x owner=@khanakia stability=stable
type SQLTypes struct {
	// ID is a column that holds a generated row id (Auth.NewID, or the
	// app's WithIDs generator) or refers to one: every primary key the
	// library generates, user_id, session_id, an organization's or a team's
	// id. Override it to give ids a native type (UUID on Postgres). A column
	// that may hold "" or a value the library did not generate (a provider's
	// client id, a JWT id, a connection name) is a Key instead, because a
	// native id type refuses those.
	ID string
	// Key is a short indexed text that is not a generated id: a kind, a
	// purpose, a status, an operation id, a slug, a provider's subject.
	Key string
	// Text is a short display string.
	Text string
	// Value is an identifier value or an address.
	Value string
	// Long is a URL, a user agent or free text up to a few kilobytes.
	Long string
	// Timestamp holds a UTC instant with at least microsecond precision.
	Timestamp string
	// Bool is a flag; MySQL spells it BOOLEAN, which is TINYINT(1).
	Bool string
	// Hash is a 32-byte digest.
	Hash string
	// Bytes is a short binary value such as a WebAuthn credential id, at most
	// 1024 bytes, and indexable on every engine.
	Bytes string
	// Doc is a large text value such as a JSON document, unindexed.
	Doc string
	// Int is a 64-bit integer: a counter or a numeric setting.
	Int string
	// TableSuffix ends every CREATE TABLE. On MySQL it sets the byte-exact
	// collation.
	TableSuffix string
}

// TypesFor returns the built-in spellings for engine. A plugin writing DDL
// should implement TypedMigrator and use the types it is handed instead,
// which carry the app's WithSQLTypes overrides.
func TypesFor(engine string) SQLTypes {
	switch engine {
	case EngineMySQL:
		// Every text column compares byte for byte (utf8mb4_bin, set on the
		// table): MySQL's default collation makes 'josé' equal 'jose' and
		// 'Ada' equal 'ada', which would merge two identities into one.
		return SQLTypes{
			ID: "VARCHAR(191)", Key: "VARCHAR(191)", Text: "VARCHAR(255)", Value: "VARCHAR(320)", Long: "VARCHAR(4096)",
			Timestamp: "DATETIME(6)", Bool: "BOOLEAN", Hash: "VARBINARY(32)", Int: "BIGINT",
			Bytes: "VARBINARY(1024)", Doc: "MEDIUMTEXT",
			TableSuffix: " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin",
		}
	case EngineSQLite:
		return SQLTypes{ID: "TEXT", Key: "TEXT", Text: "TEXT", Value: "TEXT", Long: "TEXT", Timestamp: "TIMESTAMP", Bool: "BOOLEAN", Hash: "BLOB", Int: "INTEGER", Bytes: "BLOB", Doc: "TEXT"}
	default:
		return SQLTypes{ID: "TEXT", Key: "TEXT", Text: "TEXT", Value: "TEXT", Long: "TEXT", Timestamp: "TIMESTAMPTZ", Bool: "BOOLEAN", Hash: "BYTEA", Int: "BIGINT", Bytes: "BYTEA", Doc: "TEXT"}
	}
}

// TypedMigrator is the upgrade of Migrator for a plugin whose DDL spells
// every type through the SQLTypes it is handed, which are TypesFor(engine)
// with the app's WithSQLTypes overrides applied. When a plugin implements
// it, Migrations calls it instead of Migrator's method. New refuses
// WithSQLTypes for the app's engine while any plugin implements only
// Migrator, because that plugin's tables would silently keep the built-in
// types beside core tables that changed (a UUID user id joined to a TEXT
// one fails on Postgres).
//
//ds:def id=core-typedmigrator-5rk8wd3n owner=@khanakia stability=stable
type TypedMigrator interface {
	TypedMigrations(engine string, t SQLTypes) ([]Migration, error)
}

// WithSQLTypes overrides column types for engine, for every table the core
// writes and every plugin that implements TypedMigrator: UUID ids on
// Postgres (SQLTypes{ID: "UUID"}, with WithIDs generating UUIDs), a wider
// Long on MySQL, a dialect-compatible spelling for an
// engine that speaks one of the three (CockroachDB as Postgres, MariaDB as
// MySQL, libSQL as SQLite). Only the fields set in t change; an empty field
// keeps the built-in spelling. Called again for the same engine, the later
// call wins field by field.
//
// It cannot add a fourth engine: the core's upserts, unique-violation
// detection and index statements are written per engine, and the sqlb
// dialect renders only Postgres, MySQL and SQLite, so New refuses any other
// engine name with ErrEngineNotSupported. The override must still store
// what the core writes: an id column typed UUID needs WithIDs to generate
// UUIDs.
//
//ds:def id=opt-withsqltypes-8pz4qm2k owner=@khanakia stability=stable
func WithSQLTypes(engine string, t SQLTypes) Option {
	return func(s *settings) {
		if s.sqlTypes == nil {
			s.sqlTypes = map[string]SQLTypes{}
		}
		s.sqlTypes[engine] = t.over(s.sqlTypes[engine])
	}
}

// over returns base with every non-empty field of t in place of its own.
func (t SQLTypes) over(base SQLTypes) SQLTypes {
	pick := func(v, b string) string {
		if v != "" {
			return v
		}
		return b
	}
	return SQLTypes{
		ID: pick(t.ID, base.ID), Key: pick(t.Key, base.Key), Text: pick(t.Text, base.Text), Value: pick(t.Value, base.Value),
		Long: pick(t.Long, base.Long), Timestamp: pick(t.Timestamp, base.Timestamp), Bool: pick(t.Bool, base.Bool),
		Hash: pick(t.Hash, base.Hash), Bytes: pick(t.Bytes, base.Bytes), Doc: pick(t.Doc, base.Doc),
		Int: pick(t.Int, base.Int), TableSuffix: pick(t.TableSuffix, base.TableSuffix),
	}
}

// SQLTypes returns the column types of the app's engine: TypesFor with the
// WithSQLTypes overrides applied. A plugin reaches the same value through
// TypedMigrator.
//
//ds:def id=core-auth-sqltypes-3hq7vn5x owner=@khanakia stability=stable
func (a *Auth) SQLTypes() SQLTypes { return a.typesFor(a.Engine()) }

// typesFor is TypesFor(engine) with the app's overrides for engine. An
// override that sets Key and not ID changes ID too: before ID existed, Key
// typed every id column, and an app that overrode it then must keep the
// same DDL.
func (a *Auth) typesFor(engine string) SQLTypes {
	o := a.sqlTypes[engine]
	if o.ID == "" {
		o.ID = o.Key
	}
	return o.over(TypesFor(engine))
}

// pluginMigrations returns p's own migrations for engine, through
// TypedMigrator when p implements it, else Migrator; ok is false when p has
// none.
func (a *Auth) pluginMigrations(engine string, p Plugin) ([]Migration, bool, error) {
	if tm, ok := p.(TypedMigrator); ok {
		ms, err := tm.TypedMigrations(engine, a.typesFor(engine))
		return ms, true, err
	}
	if mg, ok := p.(Migrator); ok {
		ms, err := mg.Migrations(engine)
		return ms, true, err
	}
	return nil, false, nil
}

// checkSQLTypes refuses WithSQLTypes for an engine the core cannot write
// DDL for, and, when it overrides the app's engine, any plugin that writes
// DDL without TypedMigrator; see TypedMigrator for why.
func (a *Auth) checkSQLTypes() error {
	for engine := range a.sqlTypes {
		if err := supported(engine); err != nil {
			return fmt.Errorf("WithSQLTypes: %w", err)
		}
	}
	if _, ok := a.sqlTypes[a.Engine()]; !ok {
		return nil
	}
	for _, p := range a.plugins {
		_, typed := p.(TypedMigrator)
		if _, untyped := p.(Migrator); untyped && !typed {
			return fmt.Errorf("%w: WithSQLTypes: plugin %q writes its tables with TypesFor and would keep the built-in types; it must implement auth.TypedMigrator", ErrBadOperation, p.Name())
		}
	}
	return nil
}

// CheckEngine returns ErrEngineNotSupported for an engine the core cannot
// write migrations for. Plugins call it first in Migrations.
func CheckEngine(engine string) error { return supported(engine) }

func supported(engine string) error {
	switch engine {
	case EnginePostgres, EngineMySQL, EngineSQLite:
		return nil
	}
	return fmt.Errorf("%w: %q", ErrEngineNotSupported, engine)
}

// Suffixes of the core's secondary index names, appended to the real name of
// the table they index, so two prefixed instances in one Postgres schema,
// where index names are schema-global, never collide.
const (
	indexSuffixUser    = "_user_idx"
	indexSuffixLookup  = "_lookup_idx"
	indexSuffixSubject = "_subject_idx"
	// indexSuffixPreviousToken names the index of the rotated-token lookup
	// (WithTokenRotation), created by its own migration, not coreIndexes:
	// the first migration's checksum is in every deployed ledger.
	indexSuffixPreviousToken = "_previous_token_idx"
)

// coreIndex is one secondary index of a core table: its table, the suffix of
// its name and its column list. One list feeds both the MySQL inline INDEX
// clauses and the other engines' CREATE INDEX statements, so the two cannot
// drift apart.
type coreIndex struct {
	table  sqlb.Table
	suffix string
	cols   string
}

// coreIndexes lists the core's secondary indexes in statement order.
var coreIndexes = []coreIndex{
	{TableCode, indexSuffixSubject, colCodeSubject + ", " + colCodePurpose},
	{TableIdentity, indexSuffixUser, ColIdentityUserID},
	{TableIdentity, indexSuffixLookup, ColIdentityKind + ", " + ColIdentityValue},
	{TableSession, indexSuffixUser, ColSessionUserID},
	{TableVerification, indexSuffixLookup, ColVerificationIdentifier + ", " + ColVerificationPurpose},
}

// coreIndexName is the real name of a core index.
func (a *Auth) coreIndexName(i coreIndex) string { return a.TableName(i.table) + i.suffix }

// coreIndexNames lists every core index's real name, for the identifier
// length check.
func (a *Auth) coreIndexNames() []string {
	out := make([]string, 0, len(coreIndexes))
	for _, i := range coreIndexes {
		out = append(out, a.coreIndexName(i))
	}
	return append(out, a.TableName(TableSession)+indexSuffixPreviousToken)
}

// coreMigrations creates the core tables. Written per engine rather than
// through a portable builder, because primary keys, foreign keys and partial
// indexes are engine constructs in sqlb today; the column names come from the
// same constants the queries use, and the integration tests run every core
// query against the result on all three engines, which is what catches drift.
// engine is one supported() accepts; Migrations checks that first. Every
// table is written under its real name (TableName).
func (a *Auth) coreMigrations(engine string) []Migration {
	t := a.typesFor(engine)
	ine := "IF NOT EXISTS "
	user, identity, session, verification, code := a.TableName(TableUser), a.TableName(TableIdentity), a.TableName(TableSession), a.TableName(TableVerification), a.TableName(TableCode)
	// mysqlIdx declares a table's indexes inside its CREATE TABLE: MySQL has
	// no CREATE INDEX IF NOT EXISTS. The other engines get them as separate
	// statements below.
	mysqlIdx := func(table sqlb.Table) string {
		if engine != EngineMySQL {
			return ""
		}
		var b strings.Builder
		for _, i := range coreIndexes {
			if i.table.Name == table.Name {
				b.WriteString(", INDEX " + a.coreIndexName(i) + " (" + i.cols + ")")
			}
		}
		return b.String()
	}

	st := []string{
		"CREATE TABLE " + ine + user + " (" +
			ColUserID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColUserName + " " + t.Text + " NOT NULL DEFAULT '', " +
			ColUserImage + " " + t.Long + " NOT NULL DEFAULT '', " +
			ColUserCreatedAt + " " + t.Timestamp + " NOT NULL, " +
			ColUserUpdatedAt + " " + t.Timestamp + " NOT NULL)" + t.TableSuffix,

		"CREATE TABLE " + ine + identity + " (" +
			ColIdentityID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColIdentityUserID + " " + t.ID + " NOT NULL, " +
			ColIdentityKind + " " + t.Key + " NOT NULL, " +
			ColIdentityValue + " " + t.Value + " NOT NULL, " +
			ColIdentityValueRaw + " " + t.Value + " NOT NULL DEFAULT '', " +
			ColIdentityVerifiedAt + " " + t.Timestamp + " NULL, " +
			ColIdentityIsPrimary + " " + t.Bool + " NOT NULL DEFAULT FALSE, " +
			ColIdentityScopeID + " " + t.Key + " NULL, " +
			ColIdentityCreatedAt + " " + t.Timestamp + " NOT NULL" + mysqlIdx(TableIdentity) + ")" + t.TableSuffix,

		"CREATE TABLE " + ine + session + " (" +
			ColSessionID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColSessionUserID + " " + t.ID + " NOT NULL, " +
			ColSessionTokenHash + " " + t.Hash + " NOT NULL UNIQUE, " +
			ColSessionExpiresAt + " " + t.Timestamp + " NOT NULL, " +
			ColSessionLastSeenAt + " " + t.Timestamp + " NOT NULL, " +
			ColSessionIP + " " + t.Text + " NOT NULL DEFAULT '', " +
			ColSessionUserAgent + " " + t.Long + " NOT NULL DEFAULT '', " +
			ColSessionCreatedAt + " " + t.Timestamp + " NOT NULL, " +
			ColSessionFactorPending + " " + t.Bool + " NOT NULL DEFAULT FALSE, " +
			ColSessionImpersonator + " " + t.ID + " NULL, " +
			ColSessionTransient + " " + t.Bool + " NOT NULL DEFAULT FALSE" + mysqlIdx(TableSession) + ")" + t.TableSuffix,

		"CREATE TABLE " + ine + verification + " (" +
			ColVerificationID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColVerificationIdentifier + " " + t.Key + " NOT NULL, " +
			ColVerificationPurpose + " " + t.Key + " NOT NULL, " +
			ColVerificationTokenHash + " " + t.Hash + " NOT NULL UNIQUE, " +
			ColVerificationExpiresAt + " " + t.Timestamp + " NOT NULL, " +
			ColVerificationConsumedAt + " " + t.Timestamp + " NULL, " +
			ColVerificationMeta + " " + t.Long + " NOT NULL DEFAULT '', " +
			ColVerificationCreatedAt + " " + t.Timestamp + " NOT NULL" + mysqlIdx(TableVerification) + ")" + t.TableSuffix,
	}
	st = append(st, "CREATE TABLE "+ine+code+" ("+
		colCodeID+" "+t.ID+" NOT NULL PRIMARY KEY, "+
		colCodeSubject+" "+t.Value+" NOT NULL, "+
		colCodePurpose+" "+t.Key+" NOT NULL, "+
		colCodeHash+" "+t.Hash+" NOT NULL, "+
		colCodeAttempts+" "+t.Int+" NOT NULL DEFAULT 0, "+
		colCodeExpiresAt+" "+t.Timestamp+" NOT NULL, "+
		colCodeCreatedAt+" "+t.Timestamp+" NOT NULL"+mysqlIdx(TableCode)+")"+t.TableSuffix)
	if engine != EngineMySQL {
		for _, i := range coreIndexes {
			st = append(st, "CREATE INDEX "+ine+a.coreIndexName(i)+" ON "+a.TableName(i.table)+" ("+i.cols+")")
		}
	}
	return []Migration{
		{Owner: CorePluginName, Name: coreTablesMigrationName, Statements: st},
		// A second migration rather than wider CREATE TABLEs: the first one's
		// checksum is in every deployed ledger, and changing its statements
		// would stop Migrate with ErrChecksumMismatch everywhere.
		{Owner: CorePluginName, Name: sessionLifetimesMigrationName, Statements: []string{
			"ALTER TABLE " + session + " ADD COLUMN " + ColSessionIdleSeconds + " " + t.Int + " NOT NULL DEFAULT 0",
			"ALTER TABLE " + session + " ADD COLUMN " + ColSessionRefreshSeconds + " " + t.Int + " NOT NULL DEFAULT 0",
			"ALTER TABLE " + session + " ADD COLUMN " + ColSessionMaxExpiresAt + " " + t.Timestamp + " NULL",
			"ALTER TABLE " + user + " ADD COLUMN " + ColUserSessionsValidAfter + " " + t.Timestamp + " NULL",
		}},
		{Owner: CorePluginName, Name: sessionRevokedMigrationName, Statements: []string{
			"ALTER TABLE " + session + " ADD COLUMN " + ColSessionRevokedAt + " " + t.Timestamp + " NULL",
		}},
		{Owner: CorePluginName, Name: sessionDataMigrationName, Statements: []string{
			"ALTER TABLE " + session + " ADD COLUMN " + ColSessionData + " " + t.Doc + " NULL",
		}},
		{Owner: CorePluginName, Name: codeSealedMigrationName, Statements: []string{
			"ALTER TABLE " + code + " ADD COLUMN " + colCodeSealed + " " + t.Long + " NULL",
		}},
		{Owner: CorePluginName, Name: sessionReauthMigrationName, Statements: []string{
			"ALTER TABLE " + session + " ADD COLUMN " + ColSessionReauthenticatedAt + " " + t.Timestamp + " NULL",
		}},
		{Owner: CorePluginName, Name: sessionTasksMigrationName, Statements: []string{
			"ALTER TABLE " + session + " ADD COLUMN " + ColSessionTasks + " " + t.Text + " NOT NULL DEFAULT ''",
		}},
		{Owner: CorePluginName, Name: sessionPreviousTokenMigrationName, Statements: []string{
			"ALTER TABLE " + session + " ADD COLUMN " + ColSessionPreviousTokenHash + " " + t.Hash + " NULL",
			"ALTER TABLE " + session + " ADD COLUMN " + ColSessionPreviousValidUntil + " " + t.Timestamp + " NULL",
			"CREATE INDEX " + a.TableName(TableSession) + indexSuffixPreviousToken + " ON " + session + " (" + ColSessionPreviousTokenHash + ")",
		}},
	}
}

// Names of the core's migrations. They are ledger keys, so they never change.
const (
	coreTablesMigrationName = "0001_core_tables"
	// sessionLifetimesMigrationName adds the per-session lifetime columns and
	// auth_user.sessions_valid_after (the sessions build, 2026-09-30).
	sessionLifetimesMigrationName = "0003_session_lifetimes"
	// sessionRevokedMigrationName adds auth_session.revoked_at for
	// WithSessionArchive (round 2 of the feature work, 2026-10-02).
	sessionRevokedMigrationName = "0004_session_revoked_at"
	// sessionDataMigrationName adds auth_session.data for per-session app
	// data (owner decision, 2026-10-03).
	sessionDataMigrationName = "0005_session_data"
	// codeSealedMigrationName adds auth_code.code_sealed for reusable
	// generated codes (CodeOptions.Reuse with Generate, round 20,
	// 2026-10-07).
	codeSealedMigrationName = "0006_code_sealed"
	// sessionReauthMigrationName adds auth_session.reauthenticated_at, so a
	// session becomes fresh again without a new sign-in (Reauthenticate,
	// 2026-10-12).
	sessionReauthMigrationName = "0007_session_reauthenticated_at"
	// sessionTasksMigrationName adds auth_session.pending_tasks for session
	// tasks (SessionTasker, 2026-10-13).
	sessionTasksMigrationName = "0008_session_tasks"
	// sessionPreviousTokenMigrationName adds the previous token hash and its
	// grace end for WithTokenRotation's reuse detection (2026-10-13).
	sessionPreviousTokenMigrationName = "0009_session_previous_token"
)

// The parts of an identity uniqueness index name,
// "<identity table>_<kind>_<mode>_uniq". Named because maxKindNameLength is
// derived from them: the longest mode is the one that bounds a kind name. The
// table part is the identity table's real name (identityIndexName).
const (
	identitySep         = "_"
	identityIndexSuffix = "_uniq"
	uniqueModeAll       = "all"
	uniqueModeVerified  = "verified"
	uniqueModeScoped    = "_scoped"
)

// maxIdentifierLength is the longest SQL identifier every engine keeps
// intact: Postgres truncates past 63 bytes without an error, MySQL refuses
// past 64, SQLite has no limit.
const maxIdentifierLength = 63

// maxKindNameLength is the longest kind name whose longest generated
// identifier, "auth_identity_<kind>_verified_scoped_uniq", fits
// maxIdentifierLength under the default table name. KindNamePattern alone
// allows 31 characters, which made that index name 66: Migrate failed on
// MySQL, and on Postgres two long kinds could truncate to one index name, so
// that the second "CREATE UNIQUE INDEX IF NOT EXISTS" silently created nothing
// and left the kind without its uniqueness rule. A renamed or prefixed
// identity table is checked against the same limit at New
// (checkDerivedIdentifiers).
const maxKindNameLength = maxIdentifierLength - len(TableNameIdentity) - len(identitySep) - len(identitySep+uniqueModeVerified+uniqueModeScoped) - len(identityIndexSuffix)

// uniqueMode is the mode part of an identity uniqueness index name and of its
// migration name: which rows the kind must be unique among.
func uniqueMode(k IdentifierKind) string {
	mode := uniqueModeAll
	if k.UniqueOnlyVerified {
		mode = uniqueModeVerified
	}
	if k.ScopedByTenant {
		mode += uniqueModeScoped
	}
	return mode
}

// identityIndexName is the real name of a kind's uniqueness index.
func (a *Auth) identityIndexName(k IdentifierKind) string {
	return a.TableName(TableIdentity) + identitySep + string(k.Name) + identitySep + uniqueMode(k) + identityIndexSuffix
}

// identityIndexMigration enforces one kind's uniqueness.
//
// Postgres and SQLite get a partial unique index: WHERE kind = '<kind>', plus
// verified_at IS NOT NULL when only verified rows must be unique. MySQL has no
// partial index, so it gets a stored generated column that holds the value
// only for rows that must be unique and NULL otherwise, with a plain unique
// index on it; NULLs never collide, which gives the same rule.
//
// The migration's name encodes the mode, so changing a kind from "unique among
// verified" to "unique among all" is a new migration and not an edited one.
// The name is a ledger key and stays the same whatever the table is called;
// the index and the table in the statements take their real names.
func (a *Auth) identityIndexMigration(engine, owner string, k IdentifierKind) Migration {
	mode := uniqueMode(k)
	name := "0000_identity_unique_" + string(k.Name) + "_" + mode
	idxName := a.identityIndexName(k)
	identity := a.TableName(TableIdentity)
	cond := ColIdentityKind + " = '" + string(k.Name) + "'"
	if k.UniqueOnlyVerified {
		cond += " AND " + ColIdentityVerifiedAt + " IS NOT NULL"
	}
	cols := ColIdentityValue
	if k.ScopedByTenant {
		cols = ColIdentityScopeID + ", " + ColIdentityValue
	}

	if engine == EngineMySQL {
		gen := string(k.Name) + "_" + mode + "_uniq_value"
		t := a.typesFor(engine)
		keyCols := gen
		if k.ScopedByTenant {
			keyCols = ColIdentityScopeID + ", " + gen
		}
		return Migration{Owner: owner, Name: name, Statements: []string{
			"ALTER TABLE " + identity + " ADD COLUMN " + gen + " " + t.Value +
				" GENERATED ALWAYS AS (CASE WHEN " + cond + " THEN " + ColIdentityValue + " END) STORED",
			"CREATE UNIQUE INDEX " + idxName + " ON " + identity + " (" + keyCols + ")",
		}}
	}
	return Migration{Owner: owner, Name: name, Statements: []string{
		"CREATE UNIQUE INDEX IF NOT EXISTS " + idxName + " ON " + identity + " (" + cols + ") WHERE " + cond,
	}}
}

// columnKeyIndexName is the real name of a unique column extension's index.
func (a *Auth) columnKeyIndexName(c ColumnExtension) string {
	return a.realTableName(c.Table) + "_" + c.Name + "_key"
}

// columnMigration adds one plugin column to a core table. c.Type is one of
// ColumnTypeValues: New refuses any other (collectColumns). c.Table is the
// table's label: the migration name keeps it, as a ledger key must, and the
// statements take the real name.
func (a *Auth) columnMigration(engine string, c ColumnExtension) Migration {
	t := a.typesFor(engine)
	table := a.realTableName(c.Table)
	var typ string
	switch c.Type {
	case ColumnText:
		typ = t.Value
	case ColumnTimestamp:
		typ = t.Timestamp
	case ColumnBool:
		typ = t.Bool
	case ColumnInt:
		typ = t.Int
	}
	def := ""
	if c.Default != "" {
		def = " DEFAULT " + c.Default
	}
	null := " NOT NULL"
	if c.Nullable {
		null = " NULL"
	}
	st := []string{"ALTER TABLE " + table + " ADD COLUMN " + c.Name + " " + typ + null + def}
	if c.Unique {
		st = append(st, "CREATE UNIQUE INDEX "+a.columnKeyIndexName(c)+" ON "+table+" ("+c.Name+")")
	}
	return Migration{Owner: c.owner, Name: "0000_column_" + c.Table + "_" + c.Name, Statements: st}
}
