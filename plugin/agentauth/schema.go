package agentauth

import (
	"context"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// The plugin's tables. No foreign keys (ADR-0002): UserTables names the
// user columns, so auth.DeleteUser removes a user's hosts, agents, grants
// and approval requests.
const (
	// TableNameHost holds hosts: the runtimes (an MCP client, a CLI, a
	// desktop app) that hold a key and register agents.
	TableNameHost  = "auth_agent_host"
	TableAliasHost = "aah"
	// TableNameAgent holds agents, each with its own public key.
	TableNameAgent  = "auth_agent"
	TableAliasAgent = "aag"
	// TableNameGrant holds capability grants, one row per capability and
	// constraint scope.
	TableNameGrant  = "auth_agent_grant"
	TableAliasGrant = "aagr"
	// TableNameApproval holds pending device-authorization requests.
	TableNameApproval  = "auth_agent_approval"
	TableAliasApproval = "aaap"
	// TableNameJTI records spent JWT ids until they expire, so each agent or
	// host JWT authenticates once on every server sharing the database.
	TableNameJTI  = "auth_agent_jti"
	TableAliasJTI = "aajt"
)

// Column names shared by several tables.
const (
	ColID          = "id"
	ColName        = "name"
	ColUserID      = "user_id"
	ColHostID      = "host_id"
	ColAgentID     = "agent_id"
	ColStatus      = "status"
	ColPublicKey   = "public_key"
	ColKid         = "kid"
	ColActivatedAt = "activated_at"
	ColExpiresAt   = "expires_at"
	ColLastUsedAt  = "last_used_at"
	ColCreatedAt   = "created_at"
	ColUpdatedAt   = "updated_at"
)

// Columns of one table each.
const (
	// ColDefaultCapabilities is a host's capability budget, a JSON array:
	// capabilities its agents receive without asking a user.
	ColDefaultCapabilities = "default_capabilities"
	// ColMode is an agent's mode, ModeDelegated or ModeAutonomous.
	ColMode = "mode"
	// ColMetadata is an agent's JSON object of display metadata, or NULL.
	ColMetadata = "metadata"
	// ColCapability is the capability a grant covers.
	ColCapability = "capability"
	// ColConstraints is a grant's JSON constraint object, or NULL for an
	// unrestricted grant.
	ColConstraints = "constraints"
	ColGrantedBy   = "granted_by"
	ColDeniedBy    = "denied_by"
	ColReason      = "reason"
	// ColMethod is an approval request's method, MethodDeviceAuthorization or
	// MethodCIBA.
	ColMethod = "method"
	// ColCapabilities is an approval request's capabilities, space-joined.
	ColCapabilities = "capabilities"
	// ColUserCodeHash is the SHA-256 of the normalized user code.
	ColUserCodeHash = "user_code_hash"
	// ColLoginHint is a CIBA request's login hint, as the agent sent it.
	ColLoginHint = "login_hint"
	// ColBindingMessage is the message shown to the user with a request.
	ColBindingMessage = "binding_message"
	// ColInterval is the polling interval in seconds the agent was told.
	ColInterval = "interval_seconds"
	// ColKind is what an approval request asks for: NULL for capabilities
	// (and the agent's registration), ApprovalKindClaim for the claim of an
	// autonomous agent. Approving a claim transfers the agent to the user,
	// so the two must never be confused.
	ColKind = "kind"
	// ColJWKSURL is the https URL of a host's or an agent's JWKS, used
	// instead of a stored key under AllowJWKSURLs: the signing key is the
	// one whose kid the JWT's header names.
	ColJWKSURL = "jwks_url"
	// ColEnrollmentHash is the SHA-256 of a host's one-time enrollment
	// token, NULL once the host enrolled (or for a host created with a key).
	ColEnrollmentHash = "enrollment_token_hash"
	// ColEnrollmentExpiresAt is when the enrollment token stops working.
	ColEnrollmentExpiresAt = "enrollment_token_expires_at"
)

// ApprovalKindClaim marks an approval request that claims an autonomous
// agent (ColKind).
const ApprovalKindClaim = "claim"

// Typed tables and columns.
var (
	TableHost       = sqlb.Table{Name: TableNameHost, Alias: TableAliasHost}
	HostID          = sqlb.Col[string](TableHost, ColID)
	HostName        = sqlb.Col[*string](TableHost, ColName)
	HostUser        = sqlb.Col[*string](TableHost, ColUserID)
	HostDefaultCaps = sqlb.Col[string](TableHost, ColDefaultCapabilities)
	HostPublicKey   = sqlb.Col[string](TableHost, ColPublicKey)
	HostKid         = sqlb.Col[string](TableHost, ColKid)
	HostStatusCol   = sqlb.Col[string](TableHost, ColStatus)
	HostActivated   = sqlb.Col[*time.Time](TableHost, ColActivatedAt)
	HostExpires     = sqlb.Col[*time.Time](TableHost, ColExpiresAt)
	HostLastUsed    = sqlb.Col[*time.Time](TableHost, ColLastUsedAt)
	HostCreated     = sqlb.Col[time.Time](TableHost, ColCreatedAt)
	HostUpdated     = sqlb.Col[time.Time](TableHost, ColUpdatedAt)
	HostJWKSURL     = sqlb.Col[*string](TableHost, ColJWKSURL)
	HostEnrollHash  = sqlb.Col[[]byte](TableHost, ColEnrollmentHash)
	HostEnrollUntil = sqlb.Col[*time.Time](TableHost, ColEnrollmentExpiresAt)

	TableAgent     = sqlb.Table{Name: TableNameAgent, Alias: TableAliasAgent}
	AgentID        = sqlb.Col[string](TableAgent, ColID)
	AgentName      = sqlb.Col[string](TableAgent, ColName)
	AgentUser      = sqlb.Col[*string](TableAgent, ColUserID)
	AgentHost      = sqlb.Col[string](TableAgent, ColHostID)
	AgentStatusCol = sqlb.Col[string](TableAgent, ColStatus)
	AgentMode      = sqlb.Col[string](TableAgent, ColMode)
	AgentPublicKey = sqlb.Col[string](TableAgent, ColPublicKey)
	AgentKid       = sqlb.Col[*string](TableAgent, ColKid)
	AgentLastUsed  = sqlb.Col[*time.Time](TableAgent, ColLastUsedAt)
	AgentActivated = sqlb.Col[*time.Time](TableAgent, ColActivatedAt)
	AgentExpires   = sqlb.Col[*time.Time](TableAgent, ColExpiresAt)
	AgentMetadata  = sqlb.Col[*string](TableAgent, ColMetadata)
	AgentCreated   = sqlb.Col[time.Time](TableAgent, ColCreatedAt)
	AgentUpdated   = sqlb.Col[time.Time](TableAgent, ColUpdatedAt)
	AgentJWKSURL   = sqlb.Col[*string](TableAgent, ColJWKSURL)

	TableGrant       = sqlb.Table{Name: TableNameGrant, Alias: TableAliasGrant}
	GrantID          = sqlb.Col[string](TableGrant, ColID)
	GrantAgent       = sqlb.Col[string](TableGrant, ColAgentID)
	GrantCapability  = sqlb.Col[string](TableGrant, ColCapability)
	GrantConstraints = sqlb.Col[*string](TableGrant, ColConstraints)
	GrantGrantedBy   = sqlb.Col[*string](TableGrant, ColGrantedBy)
	GrantDeniedBy    = sqlb.Col[*string](TableGrant, ColDeniedBy)
	GrantReason      = sqlb.Col[*string](TableGrant, ColReason)
	GrantStatusCol   = sqlb.Col[string](TableGrant, ColStatus)
	GrantExpires     = sqlb.Col[*time.Time](TableGrant, ColExpiresAt)
	GrantCreated     = sqlb.Col[time.Time](TableGrant, ColCreatedAt)
	GrantUpdated     = sqlb.Col[time.Time](TableGrant, ColUpdatedAt)

	TableApproval        = sqlb.Table{Name: TableNameApproval, Alias: TableAliasApproval}
	ApprovalID           = sqlb.Col[string](TableApproval, ColID)
	ApprovalMethod       = sqlb.Col[string](TableApproval, ColMethod)
	ApprovalAgent        = sqlb.Col[string](TableApproval, ColAgentID)
	ApprovalHost         = sqlb.Col[*string](TableApproval, ColHostID)
	ApprovalUser         = sqlb.Col[*string](TableApproval, ColUserID)
	ApprovalCapabilities = sqlb.Col[string](TableApproval, ColCapabilities)
	ApprovalStatusCol    = sqlb.Col[string](TableApproval, ColStatus)
	ApprovalCodeHash     = sqlb.Col[[]byte](TableApproval, ColUserCodeHash)
	ApprovalLoginHint    = sqlb.Col[*string](TableApproval, ColLoginHint)
	ApprovalBinding      = sqlb.Col[*string](TableApproval, ColBindingMessage)
	ApprovalInterval     = sqlb.Col[int64](TableApproval, ColInterval)
	ApprovalKind         = sqlb.Col[*string](TableApproval, ColKind)
	ApprovalExpires      = sqlb.Col[time.Time](TableApproval, ColExpiresAt)
	ApprovalCreated      = sqlb.Col[time.Time](TableApproval, ColCreatedAt)
	ApprovalUpdated      = sqlb.Col[time.Time](TableApproval, ColUpdatedAt)

	TableJTI   = sqlb.Table{Name: TableNameJTI, Alias: TableAliasJTI}
	JTIID      = sqlb.Col[string](TableJTI, ColID)
	JTIExpires = sqlb.Col[time.Time](TableJTI, ColExpiresAt)
)

// Migration names and index suffixes.
const (
	migrationTables = "0001_agent_auth"
	// migrationKind adds ColKind to approval requests, for claims.
	migrationKind = "0002_agent_approval_kind"
	// migrationLifecycle adds the columns of host enrollment and JWKS
	// keys (round p3r2).
	migrationLifecycle = "0003_agent_lifecycle"
	idxEnroll          = "_enroll_idx"
	idxUser            = "_user_idx"
	idxKid             = "_kid_idx"
	idxHost            = "_host_idx"
	idxAgent           = "_agent_idx"
)

// Tables declares the plugin's tables and their aliases.
func (p *Plugin) Tables() []sqlb.Table {
	return []sqlb.Table{TableHost, TableAgent, TableGrant, TableApproval, TableJTI}
}

// UserTables names every user column, so DeleteUser removes the user's
// hosts, agents, the grants they gave and their approval requests.
func (p *Plugin) UserTables() []auth.UserTable {
	return []auth.UserTable{
		{Table: TableHost, Column: ColUserID},
		{Table: TableAgent, Column: ColUserID},
		{Table: TableGrant, Column: ColGrantedBy},
		{Table: TableApproval, Column: ColUserID},
	}
}

// DataHooks delete a user's agents before the user (deleteUserAgents),
// which UserTables alone would leave behind.
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{User: auth.TableHooks[auth.User]{
		BeforeDelete: func(ctx context.Context, _ sqlb.DBTX, u *auth.User) error { return p.deleteUserAgents(ctx, u.ID) },
	}}
}

// TypedMigrations creates the tables for engine. A spent JWT id is a primary
// key, so a second insert of the same one fails on every engine.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	host, agent, grant, approval, jti := p.core.TableName(TableHost), p.core.TableName(TableAgent), p.core.TableName(TableGrant), p.core.TableName(TableApproval), p.core.TableName(TableJTI)
	var st []string
	table := func(name, cols string, indexes ...[2]string) {
		if engine == auth.EngineMySQL {
			for _, ix := range indexes {
				cols += ", INDEX " + name + ix[0] + " (" + ix[1] + ")"
			}
			st = append(st, "CREATE TABLE IF NOT EXISTS "+name+" ("+cols+")"+t.TableSuffix)
			return
		}
		st = append(st, "CREATE TABLE IF NOT EXISTS "+name+" ("+cols+")"+t.TableSuffix)
		for _, ix := range indexes {
			st = append(st, "CREATE INDEX IF NOT EXISTS "+name+ix[0]+" ON "+name+" ("+ix[1]+")")
		}
	}
	table(host, ColID+" "+t.ID+" NOT NULL PRIMARY KEY, "+
		ColName+" "+t.Text+" NULL, "+
		ColUserID+" "+t.ID+" NULL, "+
		ColDefaultCapabilities+" "+t.Doc+" NOT NULL, "+
		ColPublicKey+" "+t.Doc+" NOT NULL, "+
		ColKid+" "+t.Key+" NOT NULL, "+
		ColStatus+" "+t.Key+" NOT NULL, "+
		ColActivatedAt+" "+t.Timestamp+" NULL, "+
		ColExpiresAt+" "+t.Timestamp+" NULL, "+
		ColLastUsedAt+" "+t.Timestamp+" NULL, "+
		ColCreatedAt+" "+t.Timestamp+" NOT NULL, "+
		ColUpdatedAt+" "+t.Timestamp+" NOT NULL",
		[2]string{idxUser, ColUserID}, [2]string{idxKid, ColKid})
	table(agent, ColID+" "+t.ID+" NOT NULL PRIMARY KEY, "+
		ColName+" "+t.Text+" NOT NULL, "+
		ColUserID+" "+t.ID+" NULL, "+
		ColHostID+" "+t.ID+" NOT NULL, "+
		ColStatus+" "+t.Key+" NOT NULL, "+
		ColMode+" "+t.Key+" NOT NULL, "+
		ColPublicKey+" "+t.Doc+" NOT NULL, "+
		ColKid+" "+t.Key+" NULL, "+
		ColLastUsedAt+" "+t.Timestamp+" NULL, "+
		ColActivatedAt+" "+t.Timestamp+" NULL, "+
		ColExpiresAt+" "+t.Timestamp+" NULL, "+
		ColMetadata+" "+t.Doc+" NULL, "+
		ColCreatedAt+" "+t.Timestamp+" NOT NULL, "+
		ColUpdatedAt+" "+t.Timestamp+" NOT NULL",
		[2]string{idxUser, ColUserID}, [2]string{idxHost, ColHostID})
	table(grant, ColID+" "+t.ID+" NOT NULL PRIMARY KEY, "+
		ColAgentID+" "+t.ID+" NOT NULL, "+
		ColCapability+" "+t.Value+" NOT NULL, "+
		ColConstraints+" "+t.Doc+" NULL, "+
		ColGrantedBy+" "+t.ID+" NULL, "+
		ColDeniedBy+" "+t.ID+" NULL, "+
		ColReason+" "+t.Long+" NULL, "+
		ColStatus+" "+t.Key+" NOT NULL, "+
		ColExpiresAt+" "+t.Timestamp+" NULL, "+
		ColCreatedAt+" "+t.Timestamp+" NOT NULL, "+
		ColUpdatedAt+" "+t.Timestamp+" NOT NULL",
		[2]string{idxAgent, ColAgentID}, [2]string{idxUser, ColGrantedBy})
	table(approval, ColID+" "+t.ID+" NOT NULL PRIMARY KEY, "+
		ColMethod+" "+t.Key+" NOT NULL, "+
		ColAgentID+" "+t.ID+" NOT NULL, "+
		ColHostID+" "+t.ID+" NULL, "+
		ColUserID+" "+t.ID+" NULL, "+
		ColCapabilities+" "+t.Doc+" NOT NULL, "+
		ColStatus+" "+t.Key+" NOT NULL, "+
		ColUserCodeHash+" "+t.Hash+" NULL, "+
		ColLoginHint+" "+t.Text+" NULL, "+
		ColBindingMessage+" "+t.Long+" NULL, "+
		ColInterval+" "+t.Int+" NOT NULL, "+
		ColExpiresAt+" "+t.Timestamp+" NOT NULL, "+
		ColCreatedAt+" "+t.Timestamp+" NOT NULL, "+
		ColUpdatedAt+" "+t.Timestamp+" NOT NULL",
		[2]string{idxAgent, ColAgentID}, [2]string{idxUser, ColUserID})
	table(jti, ColID+" "+t.Key+" NOT NULL PRIMARY KEY, "+
		ColExpiresAt+" "+t.Timestamp+" NOT NULL")
	// The enrollment index follows each engine's style: MySQL adds it
	// with ALTER TABLE, as it declares the others inside CREATE TABLE.
	enrollIndex := "CREATE INDEX " + host + idxEnroll + " ON " + host + " (" + ColEnrollmentHash + ")"
	if engine == auth.EngineMySQL {
		enrollIndex = "ALTER TABLE " + host + " ADD INDEX " + host + idxEnroll + " (" + ColEnrollmentHash + ")"
	}
	return []auth.Migration{
		{Owner: PluginName, Name: migrationTables, Statements: st},
		{Owner: PluginName, Name: migrationKind, Statements: []string{
			"ALTER TABLE " + approval + " ADD COLUMN " + ColKind + " " + t.Key + " NULL",
		}},
		{Owner: PluginName, Name: migrationLifecycle, Statements: []string{
			"ALTER TABLE " + host + " ADD COLUMN " + ColJWKSURL + " " + t.Long + " NULL",
			"ALTER TABLE " + host + " ADD COLUMN " + ColEnrollmentHash + " " + t.Hash + " NULL",
			"ALTER TABLE " + host + " ADD COLUMN " + ColEnrollmentExpiresAt + " " + t.Timestamp + " NULL",
			"ALTER TABLE " + agent + " ADD COLUMN " + ColJWKSURL + " " + t.Long + " NULL",
			enrollIndex,
		}},
	}, nil
}
