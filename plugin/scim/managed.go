package scim

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// minHashSecretSize is the shortest credential hash secret accepted: 32 bytes,
// one SHA-256 block of key material, so a short app-supplied secret cannot
// weaken the HMAC that stores every managed SCIM credential.
const minHashSecretSize = 32

// Connection state: every connection that ever authenticated has a row,
// static, verified and managed alike, so a connection can be decommissioned
// and its provisioning domain cannot change under it. Managed connections
// also keep their credentials and an event log (scimManagedConnection,
// scimManagedCredential, scimManagedConnectionEvent).
const (
	TableNameConnection = "auth_scim_connection"
	TableNameCredential = "auth_scim_credential"
	TableNameEvent      = "auth_scim_event"

	TableAliasConnection = "scn"
	TableAliasCredential = "scr"
	TableAliasEvent      = "sce"

	ColProvisioningDomain = "provisioning_domain"
	ColManaged            = "managed"
	ColStatus             = "status"
	ColCreationRequestID  = "creation_request_id"
	ColCreatedBy          = "created_by"
	ColDecomStartedAt     = "decommission_started_at"
	ColDecommissionedAt   = "decommissioned_at"
	ColDecomCursor        = "decommission_cursor"
	ColReconciledUsers    = "reconciled_users"
	ColBatches            = "batches"
	ColDigest             = "digest"
	ColScopes             = "scopes"
	ColExpiresAt          = "expires_at"
	ColLastUsedAt         = "last_used_at"
	ColRevokedAt          = "revoked_at"
	ColRevokedBy          = "revoked_by"
	ColSequence           = "sequence"
	ColEventType          = "event_type"
	ColActorID            = "actor_id"
	ColCredentialID       = "credential_id"

	migrationNameManaged = "0002_scim_connections"
)

// Tables of connection state.
var (
	TableConnection = sqlb.Table{Name: TableNameConnection, Alias: TableAliasConnection}
	TableCredential = sqlb.Table{Name: TableNameCredential, Alias: TableAliasCredential}
	TableEvent      = sqlb.Table{Name: TableNameEvent, Alias: TableAliasEvent}
)

// Typed columns of the connection state.
var (
	ConnID           = sqlb.Col[string](TableConnection, ColID)
	ConnDomain       = sqlb.Col[string](TableConnection, ColProvisioningDomain)
	ConnManaged      = sqlb.Col[bool](TableConnection, ColManaged)
	ConnStatus       = sqlb.Col[ConnectionStatus](TableConnection, ColStatus)
	ConnCreationReq  = sqlb.Col[*string](TableConnection, ColCreationRequestID)
	ConnCreatedBy    = sqlb.Col[string](TableConnection, ColCreatedBy)
	ConnCreatedAt    = sqlb.Col[time.Time](TableConnection, ColCreatedAt)
	ConnDecomStarted = sqlb.Col[*time.Time](TableConnection, ColDecomStartedAt)
	ConnDecommission = sqlb.Col[*time.Time](TableConnection, ColDecommissionedAt)
	ConnDecomCursor  = sqlb.Col[string](TableConnection, ColDecomCursor)
	ConnReconciled   = sqlb.Col[int64](TableConnection, ColReconciledUsers)
	ConnBatches      = sqlb.Col[int64](TableConnection, ColBatches)

	CredID         = sqlb.Col[string](TableCredential, ColID)
	CredConnection = sqlb.Col[string](TableCredential, ColConnectionID)
	CredDigest     = sqlb.Col[[]byte](TableCredential, ColDigest)
	CredStatus     = sqlb.Col[CredentialStatus](TableCredential, ColStatus)
	CredScopes     = sqlb.Col[string](TableCredential, ColScopes)
	CredExpiresAt  = sqlb.Col[*time.Time](TableCredential, ColExpiresAt)
	CredCreatedAt  = sqlb.Col[time.Time](TableCredential, ColCreatedAt)
	CredCreatedBy  = sqlb.Col[string](TableCredential, ColCreatedBy)
	CredLastUsedAt = sqlb.Col[*time.Time](TableCredential, ColLastUsedAt)
	CredRevokedAt  = sqlb.Col[*time.Time](TableCredential, ColRevokedAt)
	CredRevokedBy  = sqlb.Col[*string](TableCredential, ColRevokedBy)

	EventID         = sqlb.Col[string](TableEvent, ColID)
	EventConnection = sqlb.Col[string](TableEvent, ColConnectionID)
	EventSequence   = sqlb.Col[int64](TableEvent, ColSequence)
	EventType       = sqlb.Col[EventKind](TableEvent, ColEventType)
	EventActor      = sqlb.Col[string](TableEvent, ColActorID)
	EventCredential = sqlb.Col[*string](TableEvent, ColCredentialID)
	EventCreatedAt  = sqlb.Col[time.Time](TableEvent, ColCreatedAt)
)

// ConnectionStatus is a connection's lifecycle state.
type ConnectionStatus string

// Connection statuses of a managed connection.
const (
	ConnectionActive          ConnectionStatus = "active"
	ConnectionDecommissioning ConnectionStatus = "decommissioning"
	ConnectionDecommissioned  ConnectionStatus = "decommissioned"
)

// CredentialStatus is a managed credential's state.
type CredentialStatus string

// Credential statuses.
const (
	CredentialActive         CredentialStatus = "active"
	CredentialRevoked        CredentialStatus = "revoked"
	CredentialDecommissioned CredentialStatus = "decommissioned"
)

// EventKind is a managed connection event.
type EventKind string

// Event kinds.
const (
	EventConnectionCreated         EventKind = "connection.created"
	EventCredentialIssued          EventKind = "credential.issued"
	EventCredentialRotated         EventKind = "credential.rotated"
	EventCredentialRevoked         EventKind = "credential.revoked"
	EventConnectionDecommissioning EventKind = "connection.decommissioning"
	EventConnectionDecommissioned  EventKind = "connection.decommissioned"
)

// Managed-connection limits.
const (
	// ManagedTokenPrefix starts every managed token; a token with it is
	// never handed to VerifyBearerToken.
	//ds:def id=scim-managedtokenprefix-8v3kq6wn owner=@khanakia stability=stable
	ManagedTokenPrefix = "scimt_"
	// managedConnPrefix and managedCredPrefix prefix generated ids; a static
	// connection id may not start with managedConnPrefix.
	managedConnPrefix = "scimc"
	managedCredPrefix = "scimk"
	// DefaultMaxActiveCredentials bounds overlapping credentials per
	// managed connection.
	//ds:def id=scim-defaultmaxactivecredentials-4n9wq2xt owner=@khanakia stability=stable
	DefaultMaxActiveCredentials = 5
	maxActiveCredentialsLimit   = 100
	// DefaultLastUsedWriteInterval spaces last_used_at writes, so a busy
	// IdP does not write the row on every request.
	DefaultLastUsedWriteInterval = 5 * time.Minute
	// maxEvents is how many events ConnectionEvents returns.
	maxEvents = 100
	// decommissionBatch is how many SCIM users one decommission step
	// reconciles in one transaction.
	decommissionBatch = 50
	// minCreationRequestID and maxCreationRequestID bound the idempotency key.
	minCreationRequestID = 16
	keyLabelCredentials  = "scim-credentials"
	// hashVersion prefixes a stored digest, so the digest scheme can change.
	hashVersion = "v1"
)

// Errors of the managed-connection API (Go only; never a SCIM answer).
var (
	ErrConnectionNotFound      = auth.NewError("scim.connection_not_found", http.StatusNotFound, "No such SCIM connection.")
	ErrCreationRequestConflict = auth.NewError("scim.creation_request_conflict", http.StatusConflict, "This creation request was already used.")
	ErrTooManyCredentials      = auth.NewError("scim.too_many_credentials", http.StatusConflict, "The connection has the most active credentials it may have.")
	ErrCredentialNotFound      = auth.NewError("scim.credential_not_found", http.StatusNotFound, "No such active credential.")
	ErrConnectionDecommission  = auth.NewError("scim.connection_decommissioned", http.StatusConflict, "The SCIM connection is decommissioned.")
	ErrManagedDisabled         = errors.New("scim: managed connections are off; pass scim.ManagedConnections")
	ErrBadManaged              = errors.New("scim: managed credential hash secret must be at least 32 bytes and max active credentials 1 to 100")
)

// managedConfig is ManagedConnections' settings.
type managedConfig struct {
	hashSecret []byte
	maxActive  int
	lastUsed   time.Duration
}

// ManagedOption configures managed connections.
type ManagedOption func(*managedConfig)

// CredentialHashSecret is the HMAC key managed tokens are digested with,
// at least 32 bytes. Without it the key
// is derived from auth.WithSecret.
func CredentialHashSecret(b []byte) ManagedOption { return func(c *managedConfig) { c.hashSecret = b } }

// MaxActiveCredentials overrides DefaultMaxActiveCredentials (1 to 100).
func MaxActiveCredentials(n int) ManagedOption { return func(c *managedConfig) { c.maxActive = n } }

// LastUsedWriteInterval overrides DefaultLastUsedWriteInterval; zero writes
// on every request.
func LastUsedWriteInterval(d time.Duration) ManagedOption {
	return func(c *managedConfig) { c.lastUsed = d }
}

// ManagedConnections turns on connections the app creates at run time with
// CreateManagedConnection, each with rotatable credentials and an event log.
// Their tokens start with
// ManagedTokenPrefix and are stored as HMAC-SHA256 digests only.
func ManagedConnections(opts ...ManagedOption) Option {
	return func(p *Plugin) {
		if auth.RefuseNilEach(&p.optErrs, "scim.ManagedConnections", opts) {
			return
		}
		c := &managedConfig{maxActive: DefaultMaxActiveCredentials, lastUsed: DefaultLastUsedWriteInterval}
		for _, o := range opts {
			o(c)
		}
		p.managed = c
	}
}

// ManagedConnection is a managed connection as the API answers it.
type ManagedConnection struct {
	ID                   string              `json:"id"`
	ProvisioningDomainID string              `json:"provisioningDomainId"`
	Status               ConnectionStatus    `json:"status"`
	CreatedAt            time.Time           `json:"createdAt"`
	CreatedBy            string              `json:"createdBy"`
	Credentials          []ManagedCredential `json:"credentials"`
}

// ManagedCredential is a managed credential without its token.
type ManagedCredential struct {
	ID         string           `json:"id"`
	Status     CredentialStatus `json:"status"`
	Scopes     []Scope          `json:"scopes"`
	ExpiresAt  *time.Time       `json:"expiresAt,omitempty"`
	CreatedAt  time.Time        `json:"createdAt"`
	CreatedBy  string           `json:"createdBy"`
	LastUsedAt *time.Time       `json:"lastUsedAt,omitempty"`
	RevokedAt  *time.Time       `json:"revokedAt,omitempty"`
}

// CreateManagedRequest is the input of CreateManagedConnection.
type CreateManagedRequest struct {
	// CreationRequestID makes the call idempotent-safe: 16 to 255
	// characters, never reused (ErrCreationRequestConflict).
	CreationRequestID    string
	ProvisioningDomainID string
	ActorID              string
	Scopes               []Scope
	ExpiresAt            *time.Time
}

// IssuedCredential is a new credential and its raw token, which is shown
// this once and never stored.
type IssuedCredential struct {
	Connection ManagedConnection
	Credential ManagedCredential
	Token      auth.Token
}

// Event is one entry of a managed connection's log.
type Event struct {
	Sequence     int64     `json:"sequence"`
	Type         EventKind `json:"type"`
	ActorID      string    `json:"actorId"`
	CredentialID string    `json:"credentialId,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`
}

// validManaged checks the managed settings in Validate.
func (p *Plugin) validManaged(c *auth.Config) error {
	if p.managed == nil {
		return nil
	}
	// Each setting is refused under its own option's name; ErrBadManaged
	// stays the sentinel for all of them.
	m := p.managed
	if m.maxActive < 1 || m.maxActive > maxActiveCredentialsLimit {
		return fmt.Errorf("%w: scim.MaxActiveCredentials(%d)", ErrBadManaged, m.maxActive)
	}
	if m.lastUsed < 0 {
		return fmt.Errorf("%w: scim.LastUsedWriteInterval(%v) is negative", ErrBadManaged, m.lastUsed)
	}
	if m.hashSecret == nil {
		keys, err := c.DeriveKeys(keyLabelCredentials)
		if err != nil {
			return fmt.Errorf("%w: neither scim.CredentialHashSecret nor auth.WithSecret gives a key", ErrBadManaged)
		}
		m.hashSecret = keys[0]
	}
	if len(m.hashSecret) < minHashSecretSize {
		return fmt.Errorf("%w: scim.CredentialHashSecret has %d bytes", ErrBadManaged, len(m.hashSecret))
	}
	return nil
}

// digest is the stored form of a managed token.
func (p *Plugin) digest(token string) []byte {
	m := hmac.New(sha256.New, p.managed.hashSecret)
	m.Write([]byte(hashVersion + "\x00" + token))
	return m.Sum(nil)
}

// managedAuth authenticates a managed token: its credential id is in the
// token, the digest is compared in constant time, and only an active
// credential of an active connection passes. A token whose digest matches
// but whose credential was decommissioned is told so (errDecommissioned);
// every other failure is errInvalidToken.
func (p *Plugin) managedAuth(ctx context.Context, raw string) (Principal, error) {
	rest := strings.TrimPrefix(raw, ManagedTokenPrefix)
	credID, _, ok := strings.Cut(rest, ".")
	if !ok || !strings.HasPrefix(credID, managedCredPrefix+"_") {
		return Principal{}, errInvalidToken
	}
	var c credRow
	err := p.core.One(ctx, p.core.Select().Columns(credBindings(&c)...).From(TableCredential).Where(sqlb.Eq(CredID, credID)))
	if errors.Is(err, sqlb.ErrNoRows) {
		return Principal{}, errInvalidToken
	}
	if err != nil {
		return Principal{}, err
	}
	if subtle.ConstantTimeCompare(p.digest(raw), c.digest) != 1 {
		return Principal{}, errInvalidToken
	}
	switch c.status {
	case CredentialActive:
	case CredentialDecommissioned:
		// The digest matched, so the caller holds the token: saying its
		// connection was retired tells it nothing a guesser could learn,
		// and tells the identity provider's operator to stop retrying, as
		// a static connection's tokens are told (errDecommissioned).
		return Principal{}, errDecommissioned
	default:
		// Revoked: the plain refusal, as for any token that never worked.
		return Principal{}, errInvalidToken
	}
	now := p.now()
	if c.lastUsed == nil || now.Sub(*c.lastUsed) >= p.managed.lastUsed {
		if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableCredential).Set(sqlb.Set(CredLastUsedAt, &now)).Where(sqlb.Eq(CredID, c.id))); err != nil {
			return Principal{}, err
		}
	}
	return Principal{ConnectionID: c.connectionID, CredentialID: c.id, Scopes: parseScopes(c.scopes), ExpiresAt: c.expiresAt, managed: true}, nil
}

// credRow is one credential row.
type credRow struct {
	id, connectionID, scopes, createdBy string
	digest                              []byte
	status                              CredentialStatus
	expiresAt, lastUsed, revokedAt      *time.Time
	revokedBy                           *string
	created                             time.Time
}

// credBindings scans a credRow.
func credBindings(c *credRow) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(CredID, &c.id), sqlb.Bind(CredConnection, &c.connectionID), sqlb.Bind(CredDigest, &c.digest), sqlb.Bind(CredStatus, &c.status),
		sqlb.Bind(CredScopes, &c.scopes), sqlb.Bind(CredExpiresAt, &c.expiresAt), sqlb.Bind(CredCreatedAt, &c.created),
		sqlb.Bind(CredCreatedBy, &c.createdBy), sqlb.Bind(CredLastUsedAt, &c.lastUsed), sqlb.Bind(CredRevokedAt, &c.revokedAt), sqlb.Bind(CredRevokedBy, &c.revokedBy),
	}
}

// view is the API form of a credential.
func (c credRow) view() ManagedCredential {
	return ManagedCredential{ID: c.id, Status: c.status, Scopes: parseScopes(c.scopes), ExpiresAt: c.expiresAt, CreatedAt: c.created,
		CreatedBy: c.createdBy, LastUsedAt: c.lastUsed, RevokedAt: c.revokedAt}
}

// parseScopes reads a stored scope list, all scopes when empty.
func parseScopes(s string) []Scope {
	var out []Scope
	for _, f := range strings.Fields(s) {
		out = append(out, Scope(f))
	}
	if len(out) == 0 {
		return ScopeValues
	}
	return out
}

// joinScopes is the stored form of a scope list.
func joinScopes(ss []Scope) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = string(s)
	}
	return strings.Join(parts, " ")
}

// connRow is one connection row.
type connRow struct {
	id, domain, createdBy, cursor string
	managed                       bool
	status                        ConnectionStatus
	creationReq                   *string
	created                       time.Time
	decomStarted, decommissioned  *time.Time
	reconciled, batches           int64
}

// connBindings scans a connRow.
func connBindings(c *connRow) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(ConnID, &c.id), sqlb.Bind(ConnDomain, &c.domain), sqlb.Bind(ConnManaged, &c.managed), sqlb.Bind(ConnStatus, &c.status),
		sqlb.Bind(ConnCreationReq, &c.creationReq), sqlb.Bind(ConnCreatedBy, &c.createdBy), sqlb.Bind(ConnCreatedAt, &c.created),
		sqlb.Bind(ConnDecomStarted, &c.decomStarted), sqlb.Bind(ConnDecommission, &c.decommissioned), sqlb.Bind(ConnDecomCursor, &c.cursor),
		sqlb.Bind(ConnReconciled, &c.reconciled), sqlb.Bind(ConnBatches, &c.batches),
	}
}

// loadConn loads a connection row.
func (p *Plugin) loadConn(ctx context.Context, id string) (connRow, bool, error) {
	var c connRow
	err := p.core.One(ctx, p.core.Select().Columns(connBindings(&c)...).From(TableConnection).Where(sqlb.Eq(ConnID, id)))
	if errors.Is(err, sqlb.ErrNoRows) {
		return connRow{}, false, nil
	}
	return c, err == nil, err
}

// bind records a connection on its first request and refuses one that is
// decommissioned, or whose provisioning domain changed.
func (p *Plugin) bind(ctx context.Context, pr Principal) error {
	c, ok, err := p.loadConn(ctx, pr.ConnectionID)
	if err != nil {
		return err
	}
	domain := pr.ProvisioningDomainID
	if domain == "" {
		domain = pr.ConnectionID
	}
	if pr.managed {
		domain = c.domain
	}
	if !ok {
		if pr.managed {
			return errInvalidToken
		}
		_, err := p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableConnection).Row(p.newConn(pr.ConnectionID, domain, false, nil, "")...))
		return err
	}
	if c.status != ConnectionActive {
		return errDecommissioned
	}
	if c.domain != domain {
		return errorf(http.StatusConflict, "", "The connection's provisioningDomainId cannot change")
	}
	return nil
}

// errDecommissioned answers every request of a decommissioned connection.
var errDecommissioned = errorf(http.StatusUnauthorized, "", "SCIM connection is decommissioned")

// newConn is the assignments of a new connection row.
func (p *Plugin) newConn(id, domain string, managed bool, creationReq *string, actor string) []sqlb.Assignment {
	return []sqlb.Assignment{
		sqlb.Set(ConnID, id), sqlb.Set(ConnDomain, domain), sqlb.Set(ConnManaged, managed), sqlb.Set(ConnStatus, ConnectionActive),
		sqlb.Set(ConnCreationReq, creationReq), sqlb.Set(ConnCreatedBy, actor), sqlb.Set(ConnCreatedAt, p.now()),
		sqlb.Set(ConnDecomStarted, nil), sqlb.Set(ConnDecommission, nil), sqlb.Set(ConnDecomCursor, ""),
		sqlb.Set(ConnReconciled, int64(0)), sqlb.Set(ConnBatches, int64(0)),
	}
}

// managedMigration creates the connection-state tables.
func (p *Plugin) managedMigration(t auth.SQLTypes) []string {
	return []string{
		"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableConnection) + " (" +
			ColID + " " + t.Key + " NOT NULL PRIMARY KEY, " +
			ColProvisioningDomain + " " + t.Key + " NOT NULL, " +
			ColManaged + " " + t.Bool + " NOT NULL, " +
			ColStatus + " " + t.Key + " NOT NULL, " +
			ColCreationRequestID + " " + t.Key + " NULL UNIQUE, " +
			ColCreatedBy + " " + t.Key + " NOT NULL, " +
			ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
			ColDecomStartedAt + " " + t.Timestamp + " NULL, " +
			ColDecommissionedAt + " " + t.Timestamp + " NULL, " +
			ColDecomCursor + " " + t.Key + " NOT NULL, " +
			ColReconciledUsers + " " + t.Int + " NOT NULL, " +
			ColBatches + " " + t.Int + " NOT NULL)" + t.TableSuffix,
		"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableCredential) + " (" +
			ColID + " " + t.Key + " NOT NULL PRIMARY KEY, " +
			ColConnectionID + " " + t.Key + " NOT NULL, " +
			ColDigest + " " + t.Hash + " NOT NULL, " +
			ColStatus + " " + t.Key + " NOT NULL, " +
			ColScopes + " " + t.Text + " NOT NULL, " +
			ColExpiresAt + " " + t.Timestamp + " NULL, " +
			ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
			ColCreatedBy + " " + t.Key + " NOT NULL, " +
			ColLastUsedAt + " " + t.Timestamp + " NULL, " +
			ColRevokedAt + " " + t.Timestamp + " NULL, " +
			ColRevokedBy + " " + t.Key + " NULL)" + t.TableSuffix,
		"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableEvent) + " (" +
			ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColConnectionID + " " + t.Key + " NOT NULL, " +
			ColSequence + " " + t.Int + " NOT NULL, " +
			ColEventType + " " + t.Key + " NOT NULL, " +
			ColActorID + " " + t.Key + " NOT NULL, " +
			ColCredentialID + " " + t.Key + " NULL, " +
			ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
			"UNIQUE (" + ColConnectionID + ", " + ColSequence + "))" + t.TableSuffix,
	}
}

// requireManaged refuses the managed API when the option is off.
func (p *Plugin) requireManaged() error {
	if p.managed == nil {
		return ErrManagedDisabled
	}
	return nil
}

// CreateManagedConnection creates a connection and its first credential.
// The token is returned once.
//
//ds:def id=scim-plugin-createmanagedconnection-6t2wn9qk owner=@khanakia stability=stable
func (p *Plugin) CreateManagedConnection(ctx context.Context, in CreateManagedRequest) (IssuedCredential, error) {
	if err := p.requireManaged(); err != nil {
		return IssuedCredential{}, err
	}
	if len(in.CreationRequestID) < minCreationRequestID || len(in.CreationRequestID) > maxIDLength || !validID(in.ProvisioningDomainID) || !validScopes(in.Scopes) {
		return IssuedCredential{}, auth.ErrBadRequest
	}
	var out IssuedCredential
	err := p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		var id string
		taken, err := p.exists(ctx, p.core.Select().Columns(sqlb.Bind(ConnID, &id)).From(TableConnection).Where(sqlb.Eq(ConnCreationReq, &in.CreationRequestID)).Limit(1))
		if err != nil {
			return err
		}
		if taken {
			return ErrCreationRequestConflict
		}
		if id, err = p.core.NewID(managedConnPrefix); err != nil {
			return err
		}
		if _, err := p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableConnection).Row(p.newConn(id, in.ProvisioningDomainID, true, &in.CreationRequestID, in.ActorID)...)); err != nil {
			return err
		}
		if err := p.event(ctx, id, EventConnectionCreated, in.ActorID, ""); err != nil {
			return err
		}
		cred, tok, err := p.issueCredential(ctx, id, in.ActorID, in.Scopes, in.ExpiresAt, EventCredentialIssued)
		if err != nil {
			return err
		}
		conn, err := p.managedView(ctx, id)
		out = IssuedCredential{Connection: conn, Credential: cred, Token: tok}
		return err
	})
	return out, err
}

// issueCredential stores a new credential for conn and logs kind.
func (p *Plugin) issueCredential(ctx context.Context, conn, actor string, scopes []Scope, expires *time.Time, kind EventKind) (ManagedCredential, auth.Token, error) {
	var n int64
	if err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableCredential).
		Where(sqlb.Eq(CredConnection, conn), sqlb.Eq(CredStatus, CredentialActive))); err != nil {
		return ManagedCredential{}, "", err
	}
	if n >= int64(p.managed.maxActive) {
		return ManagedCredential{}, "", ErrTooManyCredentials
	}
	id, err := p.core.NewID(managedCredPrefix)
	if err != nil {
		return ManagedCredential{}, "", err
	}
	tok := auth.Token(ManagedTokenPrefix + id + "." + auth.NewToken().Reveal())
	c := credRow{id: id, connectionID: conn, digest: p.digest(tok.Reveal()), status: CredentialActive, scopes: joinScopes(scopes),
		expiresAt: expires, created: p.now(), createdBy: actor}
	if _, err := p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableCredential).Row(
		sqlb.Set(CredID, c.id), sqlb.Set(CredConnection, conn), sqlb.Set(CredDigest, c.digest), sqlb.Set(CredStatus, c.status),
		sqlb.Set(CredScopes, c.scopes), sqlb.Set(CredExpiresAt, expires), sqlb.Set(CredCreatedAt, c.created), sqlb.Set(CredCreatedBy, actor),
		sqlb.Set(CredLastUsedAt, nil), sqlb.Set(CredRevokedAt, nil), sqlb.Set(CredRevokedBy, nil),
	)); err != nil {
		return ManagedCredential{}, "", err
	}
	return c.view(), tok, p.event(ctx, conn, kind, actor, id)
}

// event appends to a connection's log with the next sequence number.
func (p *Plugin) event(ctx context.Context, conn string, kind EventKind, actor, cred string) error {
	// Events are never deleted, so the count is the last sequence; the
	// unique (connection, sequence) key refuses a racing duplicate.
	var n int64
	if err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableEvent).Where(sqlb.Eq(EventConnection, conn))); err != nil {
		return err
	}
	seq := n + 1
	id, err := p.core.NewID("sce")
	if err != nil {
		return err
	}
	var credID *string
	if cred != "" {
		credID = &cred
	}
	_, err = p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableEvent).Row(
		sqlb.Set(EventID, id), sqlb.Set(EventConnection, conn), sqlb.Set(EventSequence, seq), sqlb.Set(EventType, kind),
		sqlb.Set(EventActor, actor), sqlb.Set(EventCredential, credID), sqlb.Set(EventCreatedAt, p.now()),
	))
	return err
}

// managedConn loads a managed connection of domain, or ErrConnectionNotFound
// (another tenant's connection is not found, never forbidden).
func (p *Plugin) managedConn(ctx context.Context, id, domain string) (connRow, error) {
	if err := p.requireManaged(); err != nil {
		return connRow{}, err
	}
	c, ok, err := p.loadConn(ctx, id)
	if err != nil {
		return connRow{}, err
	}
	if !ok || !c.managed || c.domain != domain {
		return connRow{}, ErrConnectionNotFound
	}
	return c, nil
}

// managedView is the API form of a managed connection with its credentials.
func (p *Plugin) managedView(ctx context.Context, id string) (ManagedConnection, error) {
	c, _, err := p.loadConn(ctx, id)
	if err != nil {
		return ManagedConnection{}, err
	}
	out := ManagedConnection{ID: c.id, ProvisioningDomainID: c.domain, Status: c.status, CreatedAt: c.created, CreatedBy: c.createdBy, Credentials: []ManagedCredential{}}
	var cr credRow
	err = p.core.Each(ctx, p.core.Select().Columns(credBindings(&cr)...).From(TableCredential).Where(sqlb.Eq(CredConnection, id)).
		Order(sqlb.OrderBy(CredCreatedAt, sqlb.SortAsc), sqlb.OrderBy(CredID, sqlb.SortAsc)),
		func() error { out.Credentials = append(out.Credentials, cr.view()); return nil })
	return out, err
}

// ManagedConnections lists a provisioning domain's managed connections,
// newest first.
func (p *Plugin) ManagedConnections(ctx context.Context, domain string) ([]ManagedConnection, error) {
	if err := p.requireManaged(); err != nil {
		return nil, err
	}
	var id string
	var ids []string
	if err := p.core.Each(ctx, p.core.Select().Columns(sqlb.Bind(ConnID, &id)).From(TableConnection).
		Where(sqlb.Eq(ConnDomain, domain), sqlb.Eq(ConnManaged, true)).
		Order(sqlb.OrderBy(ConnCreatedAt, sqlb.SortDesc), sqlb.OrderBy(ConnID, sqlb.SortDesc)),
		func() error { ids = append(ids, id); return nil }); err != nil {
		return nil, err
	}
	out := make([]ManagedConnection, 0, len(ids))
	for _, i := range ids {
		v, err := p.managedView(ctx, i)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// ManagedConnection returns one managed connection of domain.
func (p *Plugin) ManagedConnection(ctx context.Context, id, domain string) (ManagedConnection, error) {
	if _, err := p.managedConn(ctx, id, domain); err != nil {
		return ManagedConnection{}, err
	}
	return p.managedView(ctx, id)
}

// RotateCredential adds a credential beside the active ones: the IdP switches
// to the new token, then the old credential is revoked. Scopes and expiry are
// the new credential's.
func (p *Plugin) RotateCredential(ctx context.Context, id, domain, actor string, scopes []Scope, expires *time.Time) (IssuedCredential, error) {
	if !validScopes(scopes) {
		return IssuedCredential{}, auth.ErrBadRequest
	}
	var out IssuedCredential
	err := p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		c, err := p.managedConn(ctx, id, domain)
		if err != nil {
			return err
		}
		if c.status != ConnectionActive {
			return ErrConnectionDecommission
		}
		cred, tok, err := p.issueCredential(ctx, id, actor, scopes, expires, EventCredentialRotated)
		if err != nil {
			return err
		}
		conn, err := p.managedView(ctx, id)
		out = IssuedCredential{Connection: conn, Credential: cred, Token: tok}
		return err
	})
	return out, err
}

// RevokeCredential revokes one active credential.
func (p *Plugin) RevokeCredential(ctx context.Context, id, domain, credentialID, actor string) error {
	return p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		if _, err := p.managedConn(ctx, id, domain); err != nil {
			return err
		}
		now := p.now()
		n, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableCredential).
			Set(sqlb.Set(CredStatus, CredentialRevoked), sqlb.Set(CredRevokedAt, &now), sqlb.Set(CredRevokedBy, &actor)).
			Where(sqlb.Eq(CredID, credentialID), sqlb.Eq(CredConnection, id), sqlb.Eq(CredStatus, CredentialActive)))
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrCredentialNotFound
		}
		return p.event(ctx, id, EventCredentialRevoked, actor, credentialID)
	})
}

// ConnectionEvents returns the latest 100 events of a managed connection,
// ascending by sequence.
func (p *Plugin) ConnectionEvents(ctx context.Context, id, domain string) ([]Event, error) {
	if _, err := p.managedConn(ctx, id, domain); err != nil {
		return nil, err
	}
	var e Event
	var cred *string
	var out []Event
	err := p.core.Each(ctx, p.core.Select().Columns(sqlb.Bind(EventSequence, &e.Sequence), sqlb.Bind(EventType, &e.Type), sqlb.Bind(EventActor, &e.ActorID),
		sqlb.Bind(EventCredential, &cred), sqlb.Bind(EventCreatedAt, &e.CreatedAt)).From(TableEvent).Where(sqlb.Eq(EventConnection, id)).
		Order(sqlb.OrderBy(EventSequence, sqlb.SortDesc)).Limit(maxEvents),
		func() error {
			e.CredentialID = ""
			if cred != nil {
				e.CredentialID = *cred
			}
			out = append(out, e)
			return nil
		})
	slices.Reverse(out)
	return out, err
}
