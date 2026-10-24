package oauthprovider

import (
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// The plugin's tables. No foreign keys (ADR-0002): UserTables names the
// user columns, so auth.DeleteUser removes a user's rows.
const (
	//ds:def id=oauthprovider-tableclient-n4x8kq2v owner=@khanakia stability=stable
	TableNameClient  = "auth_oauth_client"
	TableAliasClient = "oac"
	//ds:def id=oauthprovider-tablecode-t6m3wp9z owner=@khanakia stability=stable
	TableNameCode  = "auth_oauth_code"
	TableAliasCode = "oaco"
	//ds:def id=oauthprovider-tabletoken-c2h7vb5r owner=@khanakia stability=stable
	TableNameToken  = "auth_oauth_token"
	TableAliasToken = "oat"
	//ds:def id=oauthprovider-tableconsent-y9q4kd3s owner=@khanakia stability=stable
	TableNameConsent  = "auth_oauth_consent"
	TableAliasConsent = "oacn"
)

// Column names shared by several tables.
const (
	ColID        = "id"
	ColClientID  = "client_id"
	ColUserID    = "user_id"
	ColScopes    = "scopes"
	ColCreatedAt = "created_at"
	ColUpdatedAt = "updated_at"
	ColSessionID = "session_id"
	ColAuthTime  = "auth_time"
)

// auth_oauth_client columns. The id is the client_id.
const (
	// ColSecretHash is the SHA-256 of the client secret; NULL for a public
	// client (token_endpoint_auth_method none).
	ColSecretHash   = "secret_hash"
	ColName         = "name"
	ColRedirectURIs = "redirect_uris"
	ColGrantTypes   = "grant_types"
	ColAuthMethod   = "auth_method"
	ColSkipConsent  = "skip_consent"
	ColRequirePKCE  = "require_pkce"
	// ColIntrospectAny lets the client introspect tokens issued to other
	// clients: a resource server. Set only from Go (CreateClient).
	ColIntrospectAny = "introspect_any"
	ColDisabledAt    = "disabled_at"
	ColClientURI     = "client_uri"
	ColLogoURI       = "logo_uri"
	ColContacts      = "contacts"
	ColTosURI        = "tos_uri"
	ColPolicyURI     = "policy_uri"
)

// auth_oauth_code columns.
const (
	ColCodeHash        = "code_hash"
	ColRedirectURI     = "redirect_uri"
	ColChallenge       = "code_challenge"
	ColChallengeMethod = "code_challenge_method"
	ColNonce           = "nonce"
	ColExpiresAt       = "expires_at"
	ColConsumedAt      = "consumed_at"
)

// auth_oauth_token columns. One row is one issuance: an access token and,
// with offline_access, its refresh token. FamilyID ties every row descended
// from one code (the code's id) or one client_credentials grant, so a
// replayed code or a reused refresh token revokes them all.
const (
	ColAccessHash       = "access_hash"
	ColRefreshHash      = "refresh_hash"
	ColFamilyID         = "family_id"
	ColAccessExpiresAt  = "access_expires_at"
	ColRefreshExpiresAt = "refresh_expires_at"
	ColRotatedAt        = "rotated_at"
	ColRevokedAt        = "revoked_at"
)

// Typed tables and columns.
var (
	TableClient   = sqlb.Table{Name: TableNameClient, Alias: TableAliasClient}
	ClientIDCol   = sqlb.Col[string](TableClient, ColID)
	ClientSecret  = sqlb.Col[[]byte](TableClient, ColSecretHash)
	ClientName    = sqlb.Col[string](TableClient, ColName)
	ClientRedirs  = sqlb.Col[string](TableClient, ColRedirectURIs)
	ClientScopes  = sqlb.Col[string](TableClient, ColScopes)
	ClientGrants  = sqlb.Col[string](TableClient, ColGrantTypes)
	ClientMethod  = sqlb.Col[string](TableClient, ColAuthMethod)
	ClientSkip    = sqlb.Col[bool](TableClient, ColSkipConsent)
	ClientPKCE    = sqlb.Col[bool](TableClient, ColRequirePKCE)
	ClientIntro   = sqlb.Col[bool](TableClient, ColIntrospectAny)
	ClientOwner   = sqlb.Col[*string](TableClient, ColUserID)
	ClientOff     = sqlb.Col[*time.Time](TableClient, ColDisabledAt)
	ClientURI     = sqlb.Col[*string](TableClient, ColClientURI)
	ClientLogo    = sqlb.Col[*string](TableClient, ColLogoURI)
	ClientContact = sqlb.Col[*string](TableClient, ColContacts)
	ClientTos     = sqlb.Col[*string](TableClient, ColTosURI)
	ClientPolicy  = sqlb.Col[*string](TableClient, ColPolicyURI)
	ClientCreated = sqlb.Col[time.Time](TableClient, ColCreatedAt)
	ClientUpdated = sqlb.Col[time.Time](TableClient, ColUpdatedAt)

	TableCode       = sqlb.Table{Name: TableNameCode, Alias: TableAliasCode}
	CodeID          = sqlb.Col[string](TableCode, ColID)
	CodeHash        = sqlb.Col[[]byte](TableCode, ColCodeHash)
	CodeClient      = sqlb.Col[string](TableCode, ColClientID)
	CodeUser        = sqlb.Col[string](TableCode, ColUserID)
	CodeSession     = sqlb.Col[string](TableCode, ColSessionID)
	CodeRedirect    = sqlb.Col[string](TableCode, ColRedirectURI)
	CodeScopes      = sqlb.Col[string](TableCode, ColScopes)
	CodeChallenge   = sqlb.Col[*string](TableCode, ColChallenge)
	CodeMethod      = sqlb.Col[*string](TableCode, ColChallengeMethod)
	CodeNonce       = sqlb.Col[*string](TableCode, ColNonce)
	CodeAuthTime    = sqlb.Col[time.Time](TableCode, ColAuthTime)
	CodeExpires     = sqlb.Col[time.Time](TableCode, ColExpiresAt)
	CodeConsumed    = sqlb.Col[*time.Time](TableCode, ColConsumedAt)
	CodeCreated     = sqlb.Col[time.Time](TableCode, ColCreatedAt)
	TableToken      = sqlb.Table{Name: TableNameToken, Alias: TableAliasToken}
	TokenID         = sqlb.Col[string](TableToken, ColID)
	TokenAccessHash = sqlb.Col[[]byte](TableToken, ColAccessHash)
	TokenRefresh    = sqlb.Col[[]byte](TableToken, ColRefreshHash)
	TokenFamily     = sqlb.Col[string](TableToken, ColFamilyID)
	TokenClient     = sqlb.Col[string](TableToken, ColClientID)
	TokenUser       = sqlb.Col[*string](TableToken, ColUserID)
	TokenSession    = sqlb.Col[*string](TableToken, ColSessionID)
	TokenScopes     = sqlb.Col[string](TableToken, ColScopes)
	// TokenRefreshNull is the refresh hash as a nullable column, for the
	// insert of a row without a refresh token.
	TokenRefreshNull    = sqlb.Col[*[]byte](TableToken, ColRefreshHash)
	TokenAccessExpires  = sqlb.Col[time.Time](TableToken, ColAccessExpiresAt)
	TokenRefreshExpires = sqlb.Col[*time.Time](TableToken, ColRefreshExpiresAt)
	TokenAuthTime       = sqlb.Col[*time.Time](TableToken, ColAuthTime)
	TokenCreated        = sqlb.Col[time.Time](TableToken, ColCreatedAt)
	TokenRotated        = sqlb.Col[*time.Time](TableToken, ColRotatedAt)
	TokenRevoked        = sqlb.Col[*time.Time](TableToken, ColRevokedAt)

	TableConsent   = sqlb.Table{Name: TableNameConsent, Alias: TableAliasConsent}
	ConsentID      = sqlb.Col[string](TableConsent, ColID)
	ConsentUser    = sqlb.Col[string](TableConsent, ColUserID)
	ConsentClient  = sqlb.Col[string](TableConsent, ColClientID)
	ConsentScopes  = sqlb.Col[string](TableConsent, ColScopes)
	ConsentCreated = sqlb.Col[time.Time](TableConsent, ColCreatedAt)
	ConsentUpdated = sqlb.Col[time.Time](TableConsent, ColUpdatedAt)
)

// Columns added by migration 0002.
const (
	// ColPostLogoutURIs are the client's registered RP-initiated logout
	// targets, newline-joined.
	ColPostLogoutURIs = "post_logout_redirect_uris"
	// ColEndSession lets the client end the user's session through the
	// end-session endpoint.
	ColEndSession = "end_session"
	// ColJWKS is the client's public key set (RFC 7517 JSON) for
	// private_key_jwt.
	ColJWKS = "jwks"
	// ColDiscovery names how a client row came to be: "" registered, "cimd"
	// fetched from its client_id URL.
	ColDiscovery = "discovery"
	// ColFetchedAt is when a CIMD client's document was last fetched.
	ColFetchedAt = "fetched_at"
	// ColResource is the RFC 8707 resource a code or token is bound to; ""
	// for none.
	ColResource = "resource"
	// ColSubjectType is the client's subject_type: NULL or "public", or
	// "pairwise" (migration 0003).
	ColSubjectType = "subject_type"
	// ColUserInfoClaims is the claim names an authorization request asked
	// for in its claims parameter, space-joined (migration 0004).
	ColUserInfoClaims = "userinfo_claims"
	// ColBackchannelURI and ColBackchannelSession are the client's
	// back-channel logout registration (migration 0005).
	ColBackchannelURI     = "backchannel_logout_uri"
	ColBackchannelSession = "backchannel_logout_session_required"
	// ColDPoPBound, ColDPoPJKT and ColJKT are DPoP (migration 0006): the
	// client's dpop_bound_access_tokens, a code's dpop_jkt, and the
	// thumbprint of the key a token is bound to.
	ColDPoPBound = "dpop_bound"
	ColDPoPJKT   = "dpop_jkt"
	ColJKT       = "jkt"
	// Migration 0008: the application type and the restricted fields.
	ColAppType       = "application_type"
	ColCCScopes      = "client_credentials_scopes"
	ColReferenceID   = "reference_id"
	ColSecretExpires = "client_secret_expires_at"
	// Migration 0009: a document client's freshness and validators.
	ColCIMDExpires = "cimd_expires_at"
	ColCIMDETag    = "cimd_etag"
	ColCIMDLastMod = "cimd_last_modified"
	// Migration 0010: RFC 7591 software identifiers, and a resource's
	// signing algorithm.
	ColSoftwareID        = "software_id"
	ColSoftwareVersion   = "software_version"
	ColSoftwareStatement = "software_statement"
	ColSigningAlg        = "signing_algorithm"
	// Migration 0012: the client certificate thumbprint a token is bound
	// to (RFC 8705), and the post-login reference of codes, tokens and
	// consents (reference_id, as on the client).
	ColX5T = "x5t_s256"
	// Migration 0013: the URL a private_key_jwt client publishes its key
	// set at, instead of an inline jwks.
	ColJWKSURI = "jwks_uri"
	// Migration 0014: an access token revoked on its own (its refresh token
	// kept, RevokeAccessTokenOnly), the encrypted replay of a rotation
	// (RefreshReplay), the resources a consent covers, a client-resource
	// link's metadata, a client secret kept encrypted
	// (EncryptClientSecrets), and a resource's signing key pin.
	ColAccessRevokedAt = "access_revoked_at"
	ColReplay          = "rotation_replay"
	ColReplayExpires   = "rotation_replay_expires_at"
	ColResources       = "resources"
	ColSecretEncrypted = "secret_encrypted"
	ColSigningKeyID    = "signing_key_id"
	ColPolicyVersion   = "policy_version"
	// TableNameAssertion records spent private_key_jwt assertion ids until
	// they expire, so one assertion authenticates once.
	//ds:def id=oauthprovider-tableassertion-v5k2np8w owner=@khanakia stability=stable
	TableNameAssertion  = "auth_oauth_assertion"
	TableAliasAssertion = "oaas"
)

var (
	ClientPostLogout        = sqlb.Col[*string](TableClient, ColPostLogoutURIs)
	ClientEndSession        = sqlb.Col[bool](TableClient, ColEndSession)
	ClientJWKS              = sqlb.Col[*string](TableClient, ColJWKS)
	ClientDiscovery         = sqlb.Col[*string](TableClient, ColDiscovery)
	ClientFetchedAt         = sqlb.Col[*time.Time](TableClient, ColFetchedAt)
	CodeResource            = sqlb.Col[*string](TableCode, ColResource)
	ClientSubject           = sqlb.Col[*string](TableClient, ColSubjectType)
	CodeClaims              = sqlb.Col[*string](TableCode, ColUserInfoClaims)
	TokenClaims             = sqlb.Col[*string](TableToken, ColUserInfoClaims)
	ConsentClaims           = sqlb.Col[*string](TableConsent, ColUserInfoClaims)
	ClientBackURI           = sqlb.Col[*string](TableClient, ColBackchannelURI)
	ClientBackSess          = sqlb.Col[bool](TableClient, ColBackchannelSession)
	ClientDPoP              = sqlb.Col[bool](TableClient, ColDPoPBound)
	CodeJKT                 = sqlb.Col[*string](TableCode, ColDPoPJKT)
	TokenJKT                = sqlb.Col[*string](TableToken, ColJKT)
	ClientAppType           = sqlb.Col[*string](TableClient, ColAppType)
	ClientCCScopes          = sqlb.Col[*string](TableClient, ColCCScopes)
	ClientRefID             = sqlb.Col[*string](TableClient, ColReferenceID)
	ClientMeta              = sqlb.Col[*string](TableClient, ColMetadata)
	ClientSecretExp         = sqlb.Col[*time.Time](TableClient, ColSecretExpires)
	ClientCIMDExpires       = sqlb.Col[*time.Time](TableClient, ColCIMDExpires)
	ClientCIMDETag          = sqlb.Col[*string](TableClient, ColCIMDETag)
	ClientCIMDLastMod       = sqlb.Col[*string](TableClient, ColCIMDLastMod)
	ClientSoftwareID        = sqlb.Col[*string](TableClient, ColSoftwareID)
	ClientSoftwareVersion   = sqlb.Col[*string](TableClient, ColSoftwareVersion)
	ClientSoftwareStatement = sqlb.Col[*string](TableClient, ColSoftwareStatement)
	TokenResource           = sqlb.Col[*string](TableToken, ColResource)
	// The binding and reference columns of migration 0012.
	TokenX5T = sqlb.Col[*string](TableToken, ColX5T)
	// ClientJWKSURI is migration 0013's jwks_uri.
	ClientJWKSURI = sqlb.Col[*string](TableClient, ColJWKSURI)
	// The columns of migration 0014.
	TokenAccessRevoked = sqlb.Col[*time.Time](TableToken, ColAccessRevokedAt)
	TokenReplay        = sqlb.Col[*string](TableToken, ColReplay)
	TokenReplayExpires = sqlb.Col[*time.Time](TableToken, ColReplayExpires)
	ConsentResources   = sqlb.Col[*string](TableConsent, ColResources)
	ClientSecretEnc    = sqlb.Col[*string](TableClient, ColSecretEncrypted)
	ResourceKeyID      = sqlb.Col[*string](TableResource, ColSigningKeyID)
	ResourceVersion    = sqlb.Col[int64](TableResource, ColPolicyVersion)
	LinkMeta           = sqlb.Col[*string](TableClientResource, ColMetadata)
	TokenRef           = sqlb.Col[*string](TableToken, ColReferenceID)
	CodeRef            = sqlb.Col[*string](TableCode, ColReferenceID)
	ConsentRef         = sqlb.Col[*string](TableConsent, ColReferenceID)

	TableAssertion   = sqlb.Table{Name: TableNameAssertion, Alias: TableAliasAssertion}
	AssertionID      = sqlb.Col[string](TableAssertion, ColID)
	AssertionExpires = sqlb.Col[time.Time](TableAssertion, ColExpiresAt)
)

// Migration names and index suffixes.
const (
	migrationTables = "0001_oauth_provider"
	migrationRound2 = "0002_oauth_provider_logout_resources_assertions"
	migrationRound3 = "0003_oauth_provider_subject_type"
	migrationRound4 = "0004_oauth_provider_userinfo_claims"
	migrationRound5 = "0005_oauth_provider_backchannel_logout"
	migrationRound6 = "0006_oauth_provider_dpop"
	// migrationClientFields sorts before the registry's 0007 by its body
	// only; names order nothing, each runs once.
	migrationClientFields    = "0008_oauth_provider_client_fields"
	migrationCIMDCache       = "0009_oauth_provider_cimd_cache"
	migrationSoftware        = "0010_oauth_provider_software"
	migrationResourceSigning = "0011_oauth_provider_resource_signing"
	migrationBinding         = "0012_oauth_provider_certificate_reference"
	migrationJWKSURI         = "0013_oauth_provider_jwks_uri"
	migrationRound14         = "0014_oauth_provider_revocation_replay_consent_resources"
	idxClientUser            = "_user_idx"
	idxTokenFamily           = "_family_idx"
	idxTokenUser             = "_user_idx"
	idxCodeUser              = "_user_idx"
	idxConsentPair           = "_pair_uq"
)

// Tables declares the four tables and their aliases.
func (p *Plugin) Tables() []sqlb.Table {
	return []sqlb.Table{TableClient, TableCode, TableToken, TableConsent, TableAssertion, TableResource, TableClientResource}
}

// UserTables names every user column, so DeleteUser removes the user's
// clients, codes, tokens and consents.
func (p *Plugin) UserTables() []auth.UserTable {
	return []auth.UserTable{
		{Table: TableClient, Column: ColUserID},
		{Table: TableCode, Column: ColUserID},
		{Table: TableToken, Column: ColUserID},
		{Table: TableConsent, Column: ColUserID},
	}
}

// TypedMigrations creates the four tables for engine. Every hash is UNIQUE, so a
// lookup by hash finds at most one row; a consent is unique per user and
// client.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	client, code, token, consent := p.core.TableName(TableClient), p.core.TableName(TableCode), p.core.TableName(TableToken), p.core.TableName(TableConsent)
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
	table(client, ColID+" "+t.Key+" NOT NULL PRIMARY KEY, "+
		ColSecretHash+" "+t.Hash+" NULL, "+
		ColName+" "+t.Text+" NOT NULL, "+
		ColRedirectURIs+" "+t.Doc+" NOT NULL, "+
		ColScopes+" "+t.Doc+" NOT NULL, "+
		ColGrantTypes+" "+t.Doc+" NOT NULL, "+
		ColAuthMethod+" "+t.Key+" NOT NULL, "+
		ColSkipConsent+" "+t.Bool+" NOT NULL, "+
		ColRequirePKCE+" "+t.Bool+" NOT NULL, "+
		ColIntrospectAny+" "+t.Bool+" NOT NULL, "+
		ColUserID+" "+t.ID+" NULL, "+
		ColDisabledAt+" "+t.Timestamp+" NULL, "+
		ColClientURI+" "+t.Doc+" NULL, "+
		ColLogoURI+" "+t.Doc+" NULL, "+
		ColContacts+" "+t.Doc+" NULL, "+
		ColTosURI+" "+t.Doc+" NULL, "+
		ColPolicyURI+" "+t.Doc+" NULL, "+
		ColCreatedAt+" "+t.Timestamp+" NOT NULL, "+
		ColUpdatedAt+" "+t.Timestamp+" NOT NULL",
		[2]string{idxClientUser, ColUserID})
	table(code, ColID+" "+t.ID+" NOT NULL PRIMARY KEY, "+
		ColCodeHash+" "+t.Hash+" NOT NULL UNIQUE, "+
		ColClientID+" "+t.Key+" NOT NULL, "+
		ColUserID+" "+t.ID+" NOT NULL, "+
		ColSessionID+" "+t.ID+" NOT NULL, "+
		ColRedirectURI+" "+t.Doc+" NOT NULL, "+
		ColScopes+" "+t.Doc+" NOT NULL, "+
		ColChallenge+" "+t.Key+" NULL, "+
		ColChallengeMethod+" "+t.Key+" NULL, "+
		ColNonce+" "+t.Doc+" NULL, "+
		ColAuthTime+" "+t.Timestamp+" NOT NULL, "+
		ColExpiresAt+" "+t.Timestamp+" NOT NULL, "+
		ColConsumedAt+" "+t.Timestamp+" NULL, "+
		ColCreatedAt+" "+t.Timestamp+" NOT NULL",
		[2]string{idxCodeUser, ColUserID})
	table(token, ColID+" "+t.ID+" NOT NULL PRIMARY KEY, "+
		ColAccessHash+" "+t.Hash+" NOT NULL UNIQUE, "+
		ColRefreshHash+" "+t.Hash+" NULL UNIQUE, "+
		ColFamilyID+" "+t.ID+" NOT NULL, "+
		ColClientID+" "+t.Key+" NOT NULL, "+
		ColUserID+" "+t.ID+" NULL, "+
		ColSessionID+" "+t.ID+" NULL, "+
		ColScopes+" "+t.Doc+" NOT NULL, "+
		ColAccessExpiresAt+" "+t.Timestamp+" NOT NULL, "+
		ColRefreshExpiresAt+" "+t.Timestamp+" NULL, "+
		ColAuthTime+" "+t.Timestamp+" NULL, "+
		ColCreatedAt+" "+t.Timestamp+" NOT NULL, "+
		ColRotatedAt+" "+t.Timestamp+" NULL, "+
		ColRevokedAt+" "+t.Timestamp+" NULL",
		[2]string{idxTokenFamily, ColFamilyID}, [2]string{idxTokenUser, ColUserID})
	table(consent, ColID+" "+t.ID+" NOT NULL PRIMARY KEY, "+
		ColUserID+" "+t.ID+" NOT NULL, "+
		ColClientID+" "+t.Key+" NOT NULL, "+
		ColScopes+" "+t.Doc+" NOT NULL, "+
		ColCreatedAt+" "+t.Timestamp+" NOT NULL, "+
		ColUpdatedAt+" "+t.Timestamp+" NOT NULL, "+
		"CONSTRAINT "+consent+idxConsentPair+" UNIQUE ("+ColUserID+", "+ColClientID+")")
	alter := func(table, col, typ string) string { return "ALTER TABLE " + table + " ADD COLUMN " + col + " " + typ }
	round2 := []string{
		alter(client, ColPostLogoutURIs, t.Doc+" NULL"),
		alter(client, ColEndSession, t.Bool+" NOT NULL DEFAULT FALSE"),
		alter(client, ColJWKS, t.Doc+" NULL"),
		alter(client, ColDiscovery, t.Key+" NULL"),
		alter(client, ColFetchedAt, t.Timestamp+" NULL"),
		alter(code, ColResource, t.Doc+" NULL"),
		alter(token, ColResource, t.Doc+" NULL"),
		"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableAssertion) + " (" + ColID + " " + t.Key + " NOT NULL PRIMARY KEY, " + ColExpiresAt + " " + t.Timestamp + " NOT NULL)" + t.TableSuffix,
	}
	return []auth.Migration{
		{Owner: PluginName, Name: migrationTables, Statements: st},
		{Owner: PluginName, Name: migrationRound2, Statements: round2},
		{Owner: PluginName, Name: migrationRound3, Statements: []string{alter(client, ColSubjectType, t.Key+" NULL")}},
		{Owner: PluginName, Name: migrationRound4, Statements: []string{
			alter(code, ColUserInfoClaims, t.Doc+" NULL"), alter(token, ColUserInfoClaims, t.Doc+" NULL"), alter(consent, ColUserInfoClaims, t.Doc+" NULL"),
		}},
		{Owner: PluginName, Name: migrationRound5, Statements: []string{
			alter(client, ColBackchannelURI, t.Doc+" NULL"), alter(client, ColBackchannelSession, t.Bool+" NOT NULL DEFAULT FALSE"),
		}},
		{Owner: PluginName, Name: migrationRound6, Statements: []string{
			alter(client, ColDPoPBound, t.Bool+" NOT NULL DEFAULT FALSE"), alter(code, ColDPoPJKT, t.Key+" NULL"), alter(token, ColJKT, t.Key+" NULL"),
		}},
		{Owner: PluginName, Name: migrationClientFields, Statements: []string{
			alter(client, ColAppType, t.Key+" NULL"), alter(client, ColCCScopes, t.Doc+" NULL"), alter(client, ColReferenceID, t.Key+" NULL"),
			alter(client, ColMetadata, t.Doc+" NULL"), alter(client, ColSecretExpires, t.Timestamp+" NULL"),
		}},
		{Owner: PluginName, Name: migrationCIMDCache, Statements: []string{
			alter(client, ColCIMDExpires, t.Timestamp+" NULL"), alter(client, ColCIMDETag, t.Doc+" NULL"), alter(client, ColCIMDLastMod, t.Text+" NULL"),
		}},
		{Owner: PluginName, Name: migrationSoftware, Statements: []string{
			alter(client, ColSoftwareID, t.Text+" NULL"), alter(client, ColSoftwareVersion, t.Text+" NULL"), alter(client, ColSoftwareStatement, t.Doc+" NULL"),
		}},
		{Owner: PluginName, Name: migrationRegistry, Statements: []string{
			"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableResource) + " (" + ColID + " " + t.Key + " NOT NULL PRIMARY KEY, " +
				ColIdentifier + " " + t.Doc + " NOT NULL, " + ColName + " " + t.Text + " NULL, " + ColAccessTTL + " " + t.Int + " NULL, " +
				ColRefreshTTL + " " + t.Int + " NULL, " + ColAllowedScopes + " " + t.Doc + " NULL, " + ColCustomClaims + " " + t.Doc + " NULL, " +
				ColDPoPRequired + " " + t.Bool + " NOT NULL, " + ColDisabled + " " + t.Bool + " NOT NULL, " + ColMetadata + " " + t.Doc + " NULL, " +
				ColCreatedAt + " " + t.Timestamp + " NOT NULL, " + ColUpdatedAt + " " + t.Timestamp + " NOT NULL)" + t.TableSuffix,
			"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableClientResource) + " (" + ColClientID + " " + t.Key + " NOT NULL, " +
				ColResourceID + " " + t.Key + " NOT NULL, " + ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
				"PRIMARY KEY (" + ColClientID + ", " + ColResourceID + "))" + t.TableSuffix,
		}},
		{Owner: PluginName, Name: migrationResourceSigning, Statements: []string{
			"ALTER TABLE " + p.core.TableName(TableResource) + " ADD COLUMN " + ColSigningAlg + " " + t.Key + " NULL",
		}},
		{Owner: PluginName, Name: migrationBinding, Statements: []string{
			alter(token, ColX5T, t.Key+" NULL"), alter(token, ColReferenceID, t.Key+" NULL"),
			alter(code, ColReferenceID, t.Key+" NULL"), alter(consent, ColReferenceID, t.Key+" NULL"),
		}},
		{Owner: PluginName, Name: migrationJWKSURI, Statements: []string{alter(client, ColJWKSURI, t.Doc+" NULL")}},
		{Owner: PluginName, Name: migrationRound14, Statements: []string{
			alter(token, ColAccessRevokedAt, t.Timestamp+" NULL"), alter(token, ColReplay, t.Doc+" NULL"), alter(token, ColReplayExpires, t.Timestamp+" NULL"),
			alter(consent, ColResources, t.Doc+" NULL"), alter(client, ColSecretEncrypted, t.Doc+" NULL"),
			alter(p.core.TableName(TableResource), ColSigningKeyID, t.Key+" NULL"), alter(p.core.TableName(TableResource), ColPolicyVersion, t.Int+" NOT NULL DEFAULT 1"), alter(p.core.TableName(TableClientResource), ColMetadata, t.Doc+" NULL"),
		}},
	}, nil
}
