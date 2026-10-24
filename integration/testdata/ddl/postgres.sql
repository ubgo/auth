-- core 0001_core_tables
CREATE TABLE IF NOT EXISTS auth_user (id TEXT NOT NULL PRIMARY KEY, name TEXT NOT NULL DEFAULT '', image TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS auth_identity (id TEXT NOT NULL PRIMARY KEY, user_id TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, value_raw TEXT NOT NULL DEFAULT '', verified_at TIMESTAMPTZ NULL, is_primary BOOLEAN NOT NULL DEFAULT FALSE, scope_id TEXT NULL, created_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS auth_session (id TEXT NOT NULL PRIMARY KEY, user_id TEXT NOT NULL, token_hash BYTEA NOT NULL UNIQUE, expires_at TIMESTAMPTZ NOT NULL, last_seen_at TIMESTAMPTZ NOT NULL, ip TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL, second_factor_pending BOOLEAN NOT NULL DEFAULT FALSE, impersonated_by TEXT NULL, transient BOOLEAN NOT NULL DEFAULT FALSE);
CREATE TABLE IF NOT EXISTS auth_verification (id TEXT NOT NULL PRIMARY KEY, identifier TEXT NOT NULL, purpose TEXT NOT NULL, token_hash BYTEA NOT NULL UNIQUE, expires_at TIMESTAMPTZ NOT NULL, consumed_at TIMESTAMPTZ NULL, meta TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS auth_code (id TEXT NOT NULL PRIMARY KEY, subject TEXT NOT NULL, purpose TEXT NOT NULL, code_hash BYTEA NOT NULL, attempts BIGINT NOT NULL DEFAULT 0, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL);
CREATE INDEX IF NOT EXISTS auth_code_subject_idx ON auth_code (subject, purpose);
CREATE INDEX IF NOT EXISTS auth_identity_user_idx ON auth_identity (user_id);
CREATE INDEX IF NOT EXISTS auth_identity_lookup_idx ON auth_identity (kind, value);
CREATE INDEX IF NOT EXISTS auth_session_user_idx ON auth_session (user_id);
CREATE INDEX IF NOT EXISTS auth_verification_lookup_idx ON auth_verification (identifier, purpose);

-- core 0003_session_lifetimes
ALTER TABLE auth_session ADD COLUMN idle_seconds BIGINT NOT NULL DEFAULT 0;
ALTER TABLE auth_session ADD COLUMN refresh_seconds BIGINT NOT NULL DEFAULT 0;
ALTER TABLE auth_session ADD COLUMN max_expires_at TIMESTAMPTZ NULL;
ALTER TABLE auth_user ADD COLUMN sessions_valid_after TIMESTAMPTZ NULL;

-- core 0004_session_revoked_at
ALTER TABLE auth_session ADD COLUMN revoked_at TIMESTAMPTZ NULL;

-- core 0005_session_data
ALTER TABLE auth_session ADD COLUMN data TEXT NULL;

-- core 0006_code_sealed
ALTER TABLE auth_code ADD COLUMN code_sealed TEXT NULL;

-- core 0007_session_reauthenticated_at
ALTER TABLE auth_session ADD COLUMN reauthenticated_at TIMESTAMPTZ NULL;

-- core 0008_session_tasks
ALTER TABLE auth_session ADD COLUMN pending_tasks TEXT NOT NULL DEFAULT '';

-- core 0009_session_previous_token
ALTER TABLE auth_session ADD COLUMN previous_token_hash BYTEA NULL;
ALTER TABLE auth_session ADD COLUMN previous_valid_until TIMESTAMPTZ NULL;
CREATE INDEX auth_session_previous_token_idx ON auth_session (previous_token_hash);

-- core 0002_rate_limit
CREATE TABLE IF NOT EXISTS auth_rate_limit (key_hash BYTEA NOT NULL PRIMARY KEY, hits BIGINT NOT NULL, expires_at TIMESTAMPTZ NOT NULL);

-- core 0003_delivery_outbox
CREATE TABLE IF NOT EXISTS auth_delivery_outbox (id TEXT NOT NULL PRIMARY KEY, payload TEXT NOT NULL, attempts BIGINT NOT NULL, next_attempt_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL);

-- email 0000_identity_unique_email_verified
CREATE UNIQUE INDEX IF NOT EXISTS auth_identity_email_verified_uniq ON auth_identity (value) WHERE kind = 'email' AND verified_at IS NOT NULL;

-- email 0000_column_auth_user_primary_email
ALTER TABLE auth_user ADD COLUMN primary_email TEXT NULL;

-- email 0000_column_auth_user_email_verified_at
ALTER TABLE auth_user ADD COLUMN email_verified_at TIMESTAMPTZ NULL;

-- password 0001_password
CREATE TABLE IF NOT EXISTS auth_password (user_id TEXT NOT NULL PRIMARY KEY, hash TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL);

-- password 0002_password_history
CREATE TABLE IF NOT EXISTS auth_password_history (id TEXT NOT NULL PRIMARY KEY, user_id TEXT NOT NULL, hash TEXT NOT NULL, seq BIGINT NOT NULL, created_at TIMESTAMPTZ NOT NULL);
CREATE INDEX IF NOT EXISTS auth_password_history_user_idx ON auth_password_history (user_id);

-- organization 0001_organization
CREATE TABLE IF NOT EXISTS auth_org (id TEXT NOT NULL PRIMARY KEY, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS auth_org_member (org_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL, joined_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (org_id, user_id));
CREATE TABLE IF NOT EXISTS auth_org_invite (id TEXT NOT NULL PRIMARY KEY, org_id TEXT NOT NULL, email TEXT NOT NULL, role TEXT NOT NULL, invited_by TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, accepted_at TIMESTAMPTZ NULL, created_at TIMESTAMPTZ NOT NULL);

-- organization 0002_organization_fields
ALTER TABLE auth_org ADD COLUMN logo TEXT NULL;
ALTER TABLE auth_org ADD COLUMN metadata TEXT NULL;
ALTER TABLE auth_org_invite ADD COLUMN status TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE auth_org_invite ADD COLUMN team_id TEXT NULL;
UPDATE auth_org_invite SET status = 'accepted' WHERE accepted_at IS NOT NULL;

-- organization 0003_organization_active
CREATE TABLE IF NOT EXISTS auth_org_active (session_id TEXT NOT NULL PRIMARY KEY, user_id TEXT NOT NULL, org_id TEXT NULL, team_id TEXT NULL, expires_at TIMESTAMPTZ NOT NULL);
CREATE INDEX IF NOT EXISTS auth_org_active_user_idx ON auth_org_active (user_id);

-- organization 0004_organization_teams
CREATE TABLE IF NOT EXISTS auth_org_team (id TEXT NOT NULL PRIMARY KEY, org_id TEXT NOT NULL, name TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS auth_org_team_member (team_id TEXT NOT NULL, user_id TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (team_id, user_id));

-- organization 0005_organization_roles
CREATE TABLE IF NOT EXISTS auth_org_role (id TEXT NOT NULL PRIMARY KEY, org_id TEXT NOT NULL, role TEXT NOT NULL, permission TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL, UNIQUE (org_id, role));

-- organization 0006_organization_invite_identifier
ALTER TABLE auth_org_invite ADD COLUMN identifier_kind TEXT NOT NULL DEFAULT 'email';
ALTER TABLE auth_org_invite ADD COLUMN identifier TEXT NOT NULL DEFAULT '';
UPDATE auth_org_invite SET identifier = email;

-- apikey 0001_api_key
CREATE TABLE IF NOT EXISTS auth_api_key (id TEXT NOT NULL PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, hint TEXT NOT NULL, key_hash BYTEA NOT NULL UNIQUE, scopes TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, last_used_at TIMESTAMPTZ NULL, expires_at TIMESTAMPTZ NULL);
CREATE INDEX IF NOT EXISTS auth_api_key_user_idx ON auth_api_key (user_id);

-- apikey 0002_api_key_limits
ALTER TABLE auth_api_key ADD COLUMN disabled_at TIMESTAMPTZ NULL;
ALTER TABLE auth_api_key ADD COLUMN metadata TEXT NULL;
ALTER TABLE auth_api_key ADD COLUMN rate_max BIGINT NOT NULL DEFAULT 0;
ALTER TABLE auth_api_key ADD COLUMN rate_window_seconds BIGINT NOT NULL DEFAULT 0;
ALTER TABLE auth_api_key ADD COLUMN rate_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE auth_api_key ADD COLUMN rate_window_start TIMESTAMPTZ NULL;
ALTER TABLE auth_api_key ADD COLUMN remaining BIGINT NULL;
ALTER TABLE auth_api_key ADD COLUMN refill_amount BIGINT NOT NULL DEFAULT 0;
ALTER TABLE auth_api_key ADD COLUMN refill_interval_seconds BIGINT NOT NULL DEFAULT 0;
ALTER TABLE auth_api_key ADD COLUMN last_refill_at TIMESTAMPTZ NULL;

-- apikey 0003_api_key_config
ALTER TABLE auth_api_key ADD COLUMN config_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE auth_api_key ADD COLUMN prefix TEXT NULL;
ALTER TABLE auth_api_key ADD COLUMN updated_at TIMESTAMPTZ NULL;
CREATE INDEX auth_api_key_config_idx ON auth_api_key (config_id);

-- apikey 0004_api_key_org
ALTER TABLE auth_api_key ADD COLUMN organization_id TEXT NULL;
ALTER TABLE auth_api_key ADD COLUMN permissions TEXT NULL;
CREATE INDEX auth_api_key_org_idx ON auth_api_key (organization_id);

-- twofactor 0000_column_auth_user_two_factor_enabled
ALTER TABLE auth_user ADD COLUMN two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- twofactor 0001_two_factor
CREATE TABLE IF NOT EXISTS auth_two_factor (user_id TEXT NOT NULL PRIMARY KEY, secret_sealed TEXT NOT NULL, confirmed_at TIMESTAMPTZ NULL, last_step BIGINT NOT NULL DEFAULT 0, failed_attempts BIGINT NOT NULL DEFAULT 0, locked_until TIMESTAMPTZ NULL, created_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS auth_two_factor_recovery (id TEXT NOT NULL PRIMARY KEY, user_id TEXT NOT NULL, code_hash BYTEA NOT NULL UNIQUE, used_at TIMESTAMPTZ NULL);

-- twofactor 0002_two_factor_method
ALTER TABLE auth_two_factor ADD COLUMN method TEXT NOT NULL DEFAULT 'totp';

-- twofactor 0003_two_factor_device
CREATE TABLE IF NOT EXISTS auth_two_factor_device (id TEXT NOT NULL PRIMARY KEY, user_id TEXT NOT NULL, token_hash BYTEA NOT NULL UNIQUE, user_agent TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL, last_used_at TIMESTAMPTZ NULL);
CREATE INDEX IF NOT EXISTS auth_two_factor_device_user_idx ON auth_two_factor_device (user_id);

-- twofactor 0004_two_factor_issuer_sealed_recovery
ALTER TABLE auth_two_factor ADD COLUMN issuer TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_two_factor_recovery ADD COLUMN code_sealed TEXT NOT NULL DEFAULT '';

-- twofactor 0005_two_factor_recovery_seq
ALTER TABLE auth_two_factor_recovery ADD COLUMN seq BIGINT NOT NULL DEFAULT 0;

-- twofactor 0006_two_factor_method_table
CREATE TABLE IF NOT EXISTS auth_two_factor_method (user_id TEXT NOT NULL, method TEXT NOT NULL, secret_sealed TEXT NOT NULL, issuer TEXT NOT NULL, last_step BIGINT NOT NULL DEFAULT 0, confirmed_at TIMESTAMPTZ NULL, created_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (user_id, method));

-- oauth 0001_account
CREATE TABLE IF NOT EXISTS auth_account (id TEXT NOT NULL PRIMARY KEY, user_id TEXT NOT NULL, provider TEXT NOT NULL, subject TEXT NOT NULL, email TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL, access_token_sealed TEXT NOT NULL DEFAULT '', refresh_token_sealed TEXT NOT NULL DEFAULT '', token_expires_at TIMESTAMPTZ NULL, UNIQUE (provider, subject));
CREATE INDEX IF NOT EXISTS auth_account_user_idx ON auth_account (user_id);

-- oauth 0002_account_id_token
ALTER TABLE auth_account ADD COLUMN id_token_sealed TEXT NULL;

-- oauth 0003_account_token_scope
ALTER TABLE auth_account ADD COLUMN token_scope TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_account ADD COLUMN refresh_token_expires_at TIMESTAMPTZ NULL;

-- oauth 0004_account_refresh_params
ALTER TABLE auth_account ADD COLUMN refresh_params_sealed TEXT NULL;

-- passkey 0001_passkey
CREATE TABLE IF NOT EXISTS auth_passkey (id TEXT NOT NULL PRIMARY KEY, user_id TEXT NOT NULL, credential_id BYTEA NOT NULL UNIQUE, credential_json TEXT NOT NULL, name TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, last_used_at TIMESTAMPTZ NULL);
CREATE INDEX IF NOT EXISTS auth_passkey_user_idx ON auth_passkey (user_id);

-- passkey 0002_passkey_security_key
CREATE TABLE IF NOT EXISTS auth_passkey_security_key (id TEXT NOT NULL PRIMARY KEY, user_id TEXT NOT NULL, credential_id BYTEA NOT NULL UNIQUE, credential_json TEXT NOT NULL, name TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, last_used_at TIMESTAMPTZ NULL);
CREATE INDEX IF NOT EXISTS auth_passkey_security_key_user_idx ON auth_passkey_security_key (user_id);

-- audit 0001_audit_event
CREATE TABLE IF NOT EXISTS audit_event (id TEXT NOT NULL PRIMARY KEY, at TIMESTAMPTZ NOT NULL, op TEXT NOT NULL, plugin TEXT NOT NULL, transport TEXT NOT NULL, ok BOOLEAN NOT NULL, code TEXT NOT NULL, actor_id TEXT NOT NULL, session_id TEXT NOT NULL, subject_id TEXT NOT NULL, impersonator_id TEXT NOT NULL, identifier TEXT NOT NULL, ip TEXT NOT NULL, user_agent TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_event_actor_idx ON audit_event (actor_id, at);
CREATE INDEX IF NOT EXISTS audit_event_subject_idx ON audit_event (subject_id, at);

-- audit 0002_audit_event_org
ALTER TABLE audit_event ADD COLUMN org_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS audit_event_org_idx ON audit_event (org_id, at);

-- audit 0003_audit_event_severity
ALTER TABLE audit_event ADD COLUMN severity TEXT NOT NULL DEFAULT 'info';
CREATE INDEX IF NOT EXISTS audit_event_severity_idx ON audit_event (severity, at);

-- emailchallenge 0001_email_challenge
CREATE TABLE IF NOT EXISTS auth_email_challenge (id TEXT NOT NULL PRIMARY KEY, identifier TEXT NOT NULL, approval_hash BYTEA NOT NULL UNIQUE, binding_hash BYTEA NOT NULL UNIQUE, status TEXT NOT NULL, name TEXT NOT NULL, scope TEXT NOT NULL, ip TEXT NOT NULL, user_agent TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, approved_at TIMESTAMPTZ NULL, created_at TIMESTAMPTZ NOT NULL);

-- invite 0001_invite
CREATE TABLE IF NOT EXISTS auth_invite (id TEXT NOT NULL PRIMARY KEY, token_hash BYTEA NOT NULL UNIQUE, created_by TEXT NOT NULL, email TEXT NULL, role TEXT NOT NULL, max_uses BIGINT NOT NULL, uses BIGINT NOT NULL, status TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS auth_invite_use (invite_id TEXT NOT NULL, user_id TEXT NOT NULL, used_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (invite_id, user_id));

-- referral 0001_referral
CREATE TABLE IF NOT EXISTS auth_referral_code (user_id TEXT NOT NULL PRIMARY KEY, code TEXT NOT NULL UNIQUE, created_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS auth_referral (id TEXT NOT NULL PRIMARY KEY, referrer_user_id TEXT NOT NULL, referred_user_id TEXT NOT NULL UNIQUE, code TEXT NOT NULL, status TEXT NOT NULL, completed_at TIMESTAMPTZ NULL, created_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS auth_referral_step (referral_id TEXT NOT NULL, step TEXT NOT NULL, metadata TEXT NOT NULL, completed_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (referral_id, step));

-- terms 0000_column_auth_user_terms_version
ALTER TABLE auth_user ADD COLUMN terms_version TEXT NOT NULL DEFAULT '';

-- terms 0000_column_auth_user_terms_accepted_at
ALTER TABLE auth_user ADD COLUMN terms_accepted_at TIMESTAMPTZ NULL;

-- terms 0001_terms_acceptance
CREATE TABLE IF NOT EXISTS auth_terms_acceptance (user_id TEXT NOT NULL, version TEXT NOT NULL, accepted_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (user_id, version, accepted_at));
INSERT INTO auth_terms_acceptance (user_id, version, accepted_at) SELECT id, terms_version, terms_accepted_at FROM auth_user WHERE terms_version <> '' AND terms_accepted_at IS NOT NULL;

-- sessiondata 0001_session_data
CREATE TABLE IF NOT EXISTS auth_session_data (session_id TEXT NOT NULL PRIMARY KEY, user_id TEXT NOT NULL, data TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
CREATE INDEX IF NOT EXISTS auth_session_data_user_idx ON auth_session_data (user_id);

-- device 0001_device_code
CREATE TABLE IF NOT EXISTS auth_device_code (id TEXT NOT NULL PRIMARY KEY, device_code_hash BYTEA NOT NULL UNIQUE, user_code_hash BYTEA NOT NULL UNIQUE, user_id TEXT NULL, client_id TEXT NOT NULL, scope TEXT NOT NULL, status TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, last_polled_at TIMESTAMPTZ NULL, polling_interval_ms BIGINT NOT NULL, grant_name TEXT NULL, resource TEXT NULL, created_at TIMESTAMPTZ NOT NULL);

-- sso 0001_sso_provider
CREATE TABLE IF NOT EXISTS auth_sso_provider (id TEXT NOT NULL PRIMARY KEY, provider_id TEXT NOT NULL UNIQUE, issuer TEXT NOT NULL, domain TEXT NOT NULL, organization_id TEXT NOT NULL DEFAULT '', user_id TEXT NOT NULL DEFAULT '', oidc_config TEXT NOT NULL, saml_config TEXT NOT NULL, domain_verified BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL);

-- sso 0002_sso_account
CREATE TABLE IF NOT EXISTS auth_sso_account (id TEXT NOT NULL PRIMARY KEY, user_id TEXT NOT NULL, provider_id TEXT NOT NULL, issuer TEXT NOT NULL, subject TEXT NOT NULL, email TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL, UNIQUE (provider_id, subject));
CREATE INDEX IF NOT EXISTS auth_sso_account_user_idx ON auth_sso_account (user_id);

-- sso 0003_sso_domain_token
ALTER TABLE auth_sso_provider ADD COLUMN domain_token TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_sso_provider ADD COLUMN domain_token_expires_at TIMESTAMPTZ NULL;
ALTER TABLE auth_sso_provider ADD COLUMN fields TEXT NULL;

-- scim 0000_column_auth_user_scim_deactivated_at
ALTER TABLE auth_user ADD COLUMN scim_deactivated_at TIMESTAMPTZ NULL;

-- scim 0001_scim
CREATE TABLE IF NOT EXISTS auth_scim_user (id TEXT NOT NULL PRIMARY KEY, connection_id TEXT NOT NULL, user_id TEXT NOT NULL, identity_id TEXT NULL, user_name TEXT NOT NULL, user_name_key TEXT NOT NULL, external_id TEXT NULL, external_id_key TEXT NULL, active BOOLEAN NOT NULL, primary_email TEXT NOT NULL, resource TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL, revision BIGINT NOT NULL, UNIQUE (connection_id, user_name_key), UNIQUE (connection_id, external_id_key), UNIQUE (connection_id, user_id));
CREATE TABLE IF NOT EXISTS auth_scim_group (id TEXT NOT NULL PRIMARY KEY, connection_id TEXT NOT NULL, display_name TEXT NOT NULL, display_name_key TEXT NOT NULL, external_id TEXT NULL, external_id_key TEXT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL, UNIQUE (connection_id, display_name_key), UNIQUE (connection_id, external_id_key));
CREATE TABLE IF NOT EXISTS auth_scim_member (group_id TEXT NOT NULL, scim_user_id TEXT NOT NULL, connection_id TEXT NOT NULL, user_id TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (group_id, scim_user_id));
CREATE TABLE IF NOT EXISTS auth_scim_connection (id TEXT NOT NULL PRIMARY KEY, provisioning_domain TEXT NOT NULL, managed BOOLEAN NOT NULL, status TEXT NOT NULL, creation_request_id TEXT NULL UNIQUE, created_by TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, decommission_started_at TIMESTAMPTZ NULL, decommissioned_at TIMESTAMPTZ NULL, decommission_cursor TEXT NOT NULL, reconciled_users BIGINT NOT NULL, batches BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS auth_scim_credential (id TEXT NOT NULL PRIMARY KEY, connection_id TEXT NOT NULL, digest BYTEA NOT NULL, status TEXT NOT NULL, scopes TEXT NOT NULL, expires_at TIMESTAMPTZ NULL, created_at TIMESTAMPTZ NOT NULL, created_by TEXT NOT NULL, last_used_at TIMESTAMPTZ NULL, revoked_at TIMESTAMPTZ NULL, revoked_by TEXT NULL);
CREATE TABLE IF NOT EXISTS auth_scim_event (id TEXT NOT NULL PRIMARY KEY, connection_id TEXT NOT NULL, sequence BIGINT NOT NULL, event_type TEXT NOT NULL, actor_id TEXT NOT NULL, credential_id TEXT NULL, created_at TIMESTAMPTZ NOT NULL, UNIQUE (connection_id, sequence));
CREATE TABLE IF NOT EXISTS auth_scim_tombstone (connection_id TEXT NOT NULL, external_id_key TEXT NOT NULL, user_id TEXT NOT NULL, identity_id TEXT NULL, deleted_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (connection_id, external_id_key));
CREATE TABLE IF NOT EXISTS auth_scim_grant (connection_id TEXT NOT NULL, group_id TEXT NOT NULL, scim_user_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (group_id, scim_user_id, role));

-- oauthprovider 0001_oauth_provider
CREATE TABLE IF NOT EXISTS auth_oauth_client (id TEXT NOT NULL PRIMARY KEY, secret_hash BYTEA NULL, name TEXT NOT NULL, redirect_uris TEXT NOT NULL, scopes TEXT NOT NULL, grant_types TEXT NOT NULL, auth_method TEXT NOT NULL, skip_consent BOOLEAN NOT NULL, require_pkce BOOLEAN NOT NULL, introspect_any BOOLEAN NOT NULL, user_id TEXT NULL, disabled_at TIMESTAMPTZ NULL, client_uri TEXT NULL, logo_uri TEXT NULL, contacts TEXT NULL, tos_uri TEXT NULL, policy_uri TEXT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
CREATE INDEX IF NOT EXISTS auth_oauth_client_user_idx ON auth_oauth_client (user_id);
CREATE TABLE IF NOT EXISTS auth_oauth_code (id TEXT NOT NULL PRIMARY KEY, code_hash BYTEA NOT NULL UNIQUE, client_id TEXT NOT NULL, user_id TEXT NOT NULL, session_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, scopes TEXT NOT NULL, code_challenge TEXT NULL, code_challenge_method TEXT NULL, nonce TEXT NULL, auth_time TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL, consumed_at TIMESTAMPTZ NULL, created_at TIMESTAMPTZ NOT NULL);
CREATE INDEX IF NOT EXISTS auth_oauth_code_user_idx ON auth_oauth_code (user_id);
CREATE TABLE IF NOT EXISTS auth_oauth_token (id TEXT NOT NULL PRIMARY KEY, access_hash BYTEA NOT NULL UNIQUE, refresh_hash BYTEA NULL UNIQUE, family_id TEXT NOT NULL, client_id TEXT NOT NULL, user_id TEXT NULL, session_id TEXT NULL, scopes TEXT NOT NULL, access_expires_at TIMESTAMPTZ NOT NULL, refresh_expires_at TIMESTAMPTZ NULL, auth_time TIMESTAMPTZ NULL, created_at TIMESTAMPTZ NOT NULL, rotated_at TIMESTAMPTZ NULL, revoked_at TIMESTAMPTZ NULL);
CREATE INDEX IF NOT EXISTS auth_oauth_token_family_idx ON auth_oauth_token (family_id);
CREATE INDEX IF NOT EXISTS auth_oauth_token_user_idx ON auth_oauth_token (user_id);
CREATE TABLE IF NOT EXISTS auth_oauth_consent (id TEXT NOT NULL PRIMARY KEY, user_id TEXT NOT NULL, client_id TEXT NOT NULL, scopes TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL, CONSTRAINT auth_oauth_consent_pair_uq UNIQUE (user_id, client_id));

-- oauthprovider 0002_oauth_provider_logout_resources_assertions
ALTER TABLE auth_oauth_client ADD COLUMN post_logout_redirect_uris TEXT NULL;
ALTER TABLE auth_oauth_client ADD COLUMN end_session BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE auth_oauth_client ADD COLUMN jwks TEXT NULL;
ALTER TABLE auth_oauth_client ADD COLUMN discovery TEXT NULL;
ALTER TABLE auth_oauth_client ADD COLUMN fetched_at TIMESTAMPTZ NULL;
ALTER TABLE auth_oauth_code ADD COLUMN resource TEXT NULL;
ALTER TABLE auth_oauth_token ADD COLUMN resource TEXT NULL;
CREATE TABLE IF NOT EXISTS auth_oauth_assertion (id TEXT NOT NULL PRIMARY KEY, expires_at TIMESTAMPTZ NOT NULL);

-- oauthprovider 0003_oauth_provider_subject_type
ALTER TABLE auth_oauth_client ADD COLUMN subject_type TEXT NULL;

-- oauthprovider 0004_oauth_provider_userinfo_claims
ALTER TABLE auth_oauth_code ADD COLUMN userinfo_claims TEXT NULL;
ALTER TABLE auth_oauth_token ADD COLUMN userinfo_claims TEXT NULL;
ALTER TABLE auth_oauth_consent ADD COLUMN userinfo_claims TEXT NULL;

-- oauthprovider 0005_oauth_provider_backchannel_logout
ALTER TABLE auth_oauth_client ADD COLUMN backchannel_logout_uri TEXT NULL;
ALTER TABLE auth_oauth_client ADD COLUMN backchannel_logout_session_required BOOLEAN NOT NULL DEFAULT FALSE;

-- oauthprovider 0006_oauth_provider_dpop
ALTER TABLE auth_oauth_client ADD COLUMN dpop_bound BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE auth_oauth_code ADD COLUMN dpop_jkt TEXT NULL;
ALTER TABLE auth_oauth_token ADD COLUMN jkt TEXT NULL;

-- oauthprovider 0008_oauth_provider_client_fields
ALTER TABLE auth_oauth_client ADD COLUMN application_type TEXT NULL;
ALTER TABLE auth_oauth_client ADD COLUMN client_credentials_scopes TEXT NULL;
ALTER TABLE auth_oauth_client ADD COLUMN reference_id TEXT NULL;
ALTER TABLE auth_oauth_client ADD COLUMN metadata TEXT NULL;
ALTER TABLE auth_oauth_client ADD COLUMN client_secret_expires_at TIMESTAMPTZ NULL;

-- oauthprovider 0009_oauth_provider_cimd_cache
ALTER TABLE auth_oauth_client ADD COLUMN cimd_expires_at TIMESTAMPTZ NULL;
ALTER TABLE auth_oauth_client ADD COLUMN cimd_etag TEXT NULL;
ALTER TABLE auth_oauth_client ADD COLUMN cimd_last_modified TEXT NULL;

-- oauthprovider 0010_oauth_provider_software
ALTER TABLE auth_oauth_client ADD COLUMN software_id TEXT NULL;
ALTER TABLE auth_oauth_client ADD COLUMN software_version TEXT NULL;
ALTER TABLE auth_oauth_client ADD COLUMN software_statement TEXT NULL;

-- oauthprovider 0007_oauth_provider_resources
CREATE TABLE IF NOT EXISTS auth_oauth_resource (id TEXT NOT NULL PRIMARY KEY, identifier TEXT NOT NULL, name TEXT NULL, access_token_ttl BIGINT NULL, refresh_token_ttl BIGINT NULL, allowed_scopes TEXT NULL, custom_claims TEXT NULL, dpop_required BOOLEAN NOT NULL, disabled BOOLEAN NOT NULL, metadata TEXT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS auth_oauth_client_resource (client_id TEXT NOT NULL, resource_id TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (client_id, resource_id));

-- oauthprovider 0011_oauth_provider_resource_signing
ALTER TABLE auth_oauth_resource ADD COLUMN signing_algorithm TEXT NULL;

-- oauthprovider 0012_oauth_provider_certificate_reference
ALTER TABLE auth_oauth_token ADD COLUMN x5t_s256 TEXT NULL;
ALTER TABLE auth_oauth_token ADD COLUMN reference_id TEXT NULL;
ALTER TABLE auth_oauth_code ADD COLUMN reference_id TEXT NULL;
ALTER TABLE auth_oauth_consent ADD COLUMN reference_id TEXT NULL;

-- oauthprovider 0013_oauth_provider_jwks_uri
ALTER TABLE auth_oauth_client ADD COLUMN jwks_uri TEXT NULL;

-- oauthprovider 0014_oauth_provider_revocation_replay_consent_resources
ALTER TABLE auth_oauth_token ADD COLUMN access_revoked_at TIMESTAMPTZ NULL;
ALTER TABLE auth_oauth_token ADD COLUMN rotation_replay TEXT NULL;
ALTER TABLE auth_oauth_token ADD COLUMN rotation_replay_expires_at TIMESTAMPTZ NULL;
ALTER TABLE auth_oauth_consent ADD COLUMN resources TEXT NULL;
ALTER TABLE auth_oauth_client ADD COLUMN secret_encrypted TEXT NULL;
ALTER TABLE auth_oauth_resource ADD COLUMN signing_key_id TEXT NULL;
ALTER TABLE auth_oauth_resource ADD COLUMN policy_version BIGINT NOT NULL DEFAULT 1;
ALTER TABLE auth_oauth_client_resource ADD COLUMN metadata TEXT NULL;

-- agentauth 0001_agent_auth
CREATE TABLE IF NOT EXISTS auth_agent_host (id TEXT NOT NULL PRIMARY KEY, name TEXT NULL, user_id TEXT NULL, default_capabilities TEXT NOT NULL, public_key TEXT NOT NULL, kid TEXT NOT NULL, status TEXT NOT NULL, activated_at TIMESTAMPTZ NULL, expires_at TIMESTAMPTZ NULL, last_used_at TIMESTAMPTZ NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
CREATE INDEX IF NOT EXISTS auth_agent_host_user_idx ON auth_agent_host (user_id);
CREATE INDEX IF NOT EXISTS auth_agent_host_kid_idx ON auth_agent_host (kid);
CREATE TABLE IF NOT EXISTS auth_agent (id TEXT NOT NULL PRIMARY KEY, name TEXT NOT NULL, user_id TEXT NULL, host_id TEXT NOT NULL, status TEXT NOT NULL, mode TEXT NOT NULL, public_key TEXT NOT NULL, kid TEXT NULL, last_used_at TIMESTAMPTZ NULL, activated_at TIMESTAMPTZ NULL, expires_at TIMESTAMPTZ NULL, metadata TEXT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
CREATE INDEX IF NOT EXISTS auth_agent_user_idx ON auth_agent (user_id);
CREATE INDEX IF NOT EXISTS auth_agent_host_idx ON auth_agent (host_id);
CREATE TABLE IF NOT EXISTS auth_agent_grant (id TEXT NOT NULL PRIMARY KEY, agent_id TEXT NOT NULL, capability TEXT NOT NULL, constraints TEXT NULL, granted_by TEXT NULL, denied_by TEXT NULL, reason TEXT NULL, status TEXT NOT NULL, expires_at TIMESTAMPTZ NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
CREATE INDEX IF NOT EXISTS auth_agent_grant_agent_idx ON auth_agent_grant (agent_id);
CREATE INDEX IF NOT EXISTS auth_agent_grant_user_idx ON auth_agent_grant (granted_by);
CREATE TABLE IF NOT EXISTS auth_agent_approval (id TEXT NOT NULL PRIMARY KEY, method TEXT NOT NULL, agent_id TEXT NOT NULL, host_id TEXT NULL, user_id TEXT NULL, capabilities TEXT NOT NULL, status TEXT NOT NULL, user_code_hash BYTEA NULL, login_hint TEXT NULL, binding_message TEXT NULL, interval_seconds BIGINT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
CREATE INDEX IF NOT EXISTS auth_agent_approval_agent_idx ON auth_agent_approval (agent_id);
CREATE INDEX IF NOT EXISTS auth_agent_approval_user_idx ON auth_agent_approval (user_id);
CREATE TABLE IF NOT EXISTS auth_agent_jti (id TEXT NOT NULL PRIMARY KEY, expires_at TIMESTAMPTZ NOT NULL);

-- agentauth 0002_agent_approval_kind
ALTER TABLE auth_agent_approval ADD COLUMN kind TEXT NULL;

-- agentauth 0003_agent_lifecycle
ALTER TABLE auth_agent_host ADD COLUMN jwks_url TEXT NULL;
ALTER TABLE auth_agent_host ADD COLUMN enrollment_token_hash BYTEA NULL;
ALTER TABLE auth_agent_host ADD COLUMN enrollment_token_expires_at TIMESTAMPTZ NULL;
ALTER TABLE auth_agent ADD COLUMN jwks_url TEXT NULL;
CREATE INDEX auth_agent_host_enroll_idx ON auth_agent_host (enrollment_token_hash);

