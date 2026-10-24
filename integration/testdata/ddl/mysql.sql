-- core 0001_core_tables
CREATE TABLE IF NOT EXISTS auth_user (id VARCHAR(191) NOT NULL PRIMARY KEY, name VARCHAR(255) NOT NULL DEFAULT '', image VARCHAR(4096) NOT NULL DEFAULT '', created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_identity (id VARCHAR(191) NOT NULL PRIMARY KEY, user_id VARCHAR(191) NOT NULL, kind VARCHAR(191) NOT NULL, value VARCHAR(320) NOT NULL, value_raw VARCHAR(320) NOT NULL DEFAULT '', verified_at DATETIME(6) NULL, is_primary BOOLEAN NOT NULL DEFAULT FALSE, scope_id VARCHAR(191) NULL, created_at DATETIME(6) NOT NULL, INDEX auth_identity_user_idx (user_id), INDEX auth_identity_lookup_idx (kind, value)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_session (id VARCHAR(191) NOT NULL PRIMARY KEY, user_id VARCHAR(191) NOT NULL, token_hash VARBINARY(32) NOT NULL UNIQUE, expires_at DATETIME(6) NOT NULL, last_seen_at DATETIME(6) NOT NULL, ip VARCHAR(255) NOT NULL DEFAULT '', user_agent VARCHAR(4096) NOT NULL DEFAULT '', created_at DATETIME(6) NOT NULL, second_factor_pending BOOLEAN NOT NULL DEFAULT FALSE, impersonated_by VARCHAR(191) NULL, transient BOOLEAN NOT NULL DEFAULT FALSE, INDEX auth_session_user_idx (user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_verification (id VARCHAR(191) NOT NULL PRIMARY KEY, identifier VARCHAR(191) NOT NULL, purpose VARCHAR(191) NOT NULL, token_hash VARBINARY(32) NOT NULL UNIQUE, expires_at DATETIME(6) NOT NULL, consumed_at DATETIME(6) NULL, meta VARCHAR(4096) NOT NULL DEFAULT '', created_at DATETIME(6) NOT NULL, INDEX auth_verification_lookup_idx (identifier, purpose)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_code (id VARCHAR(191) NOT NULL PRIMARY KEY, subject VARCHAR(320) NOT NULL, purpose VARCHAR(191) NOT NULL, code_hash VARBINARY(32) NOT NULL, attempts BIGINT NOT NULL DEFAULT 0, expires_at DATETIME(6) NOT NULL, created_at DATETIME(6) NOT NULL, INDEX auth_code_subject_idx (subject, purpose)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- core 0003_session_lifetimes
ALTER TABLE auth_session ADD COLUMN idle_seconds BIGINT NOT NULL DEFAULT 0;
ALTER TABLE auth_session ADD COLUMN refresh_seconds BIGINT NOT NULL DEFAULT 0;
ALTER TABLE auth_session ADD COLUMN max_expires_at DATETIME(6) NULL;
ALTER TABLE auth_user ADD COLUMN sessions_valid_after DATETIME(6) NULL;

-- core 0004_session_revoked_at
ALTER TABLE auth_session ADD COLUMN revoked_at DATETIME(6) NULL;

-- core 0005_session_data
ALTER TABLE auth_session ADD COLUMN data MEDIUMTEXT NULL;

-- core 0006_code_sealed
ALTER TABLE auth_code ADD COLUMN code_sealed VARCHAR(4096) NULL;

-- core 0007_session_reauthenticated_at
ALTER TABLE auth_session ADD COLUMN reauthenticated_at DATETIME(6) NULL;

-- core 0008_session_tasks
ALTER TABLE auth_session ADD COLUMN pending_tasks VARCHAR(255) NOT NULL DEFAULT '';

-- core 0009_session_previous_token
ALTER TABLE auth_session ADD COLUMN previous_token_hash VARBINARY(32) NULL;
ALTER TABLE auth_session ADD COLUMN previous_valid_until DATETIME(6) NULL;
CREATE INDEX auth_session_previous_token_idx ON auth_session (previous_token_hash);

-- core 0002_rate_limit
CREATE TABLE IF NOT EXISTS auth_rate_limit (key_hash VARBINARY(32) NOT NULL PRIMARY KEY, hits BIGINT NOT NULL, expires_at DATETIME(6) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- core 0003_delivery_outbox
CREATE TABLE IF NOT EXISTS auth_delivery_outbox (id VARCHAR(191) NOT NULL PRIMARY KEY, payload MEDIUMTEXT NOT NULL, attempts BIGINT NOT NULL, next_attempt_at DATETIME(6) NOT NULL, created_at DATETIME(6) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- email 0000_identity_unique_email_verified
ALTER TABLE auth_identity ADD COLUMN email_verified_uniq_value VARCHAR(320) GENERATED ALWAYS AS (CASE WHEN kind = 'email' AND verified_at IS NOT NULL THEN value END) STORED;
CREATE UNIQUE INDEX auth_identity_email_verified_uniq ON auth_identity (email_verified_uniq_value);

-- email 0000_column_auth_user_primary_email
ALTER TABLE auth_user ADD COLUMN primary_email VARCHAR(320) NULL;

-- email 0000_column_auth_user_email_verified_at
ALTER TABLE auth_user ADD COLUMN email_verified_at DATETIME(6) NULL;

-- password 0001_password
CREATE TABLE IF NOT EXISTS auth_password (user_id VARCHAR(191) NOT NULL PRIMARY KEY, hash VARCHAR(255) NOT NULL, updated_at DATETIME(6) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- password 0002_password_history
CREATE TABLE IF NOT EXISTS auth_password_history (id VARCHAR(191) NOT NULL PRIMARY KEY, user_id VARCHAR(191) NOT NULL, hash VARCHAR(255) NOT NULL, seq BIGINT NOT NULL, created_at DATETIME(6) NOT NULL, INDEX auth_password_history_user_idx (user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- organization 0001_organization
CREATE TABLE IF NOT EXISTS auth_org (id VARCHAR(191) NOT NULL PRIMARY KEY, slug VARCHAR(191) NOT NULL UNIQUE, name VARCHAR(255) NOT NULL, created_at DATETIME(6) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_org_member (org_id VARCHAR(191) NOT NULL, user_id VARCHAR(191) NOT NULL, role VARCHAR(191) NOT NULL, joined_at DATETIME(6) NOT NULL, PRIMARY KEY (org_id, user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_org_invite (id VARCHAR(191) NOT NULL PRIMARY KEY, org_id VARCHAR(191) NOT NULL, email VARCHAR(320) NOT NULL, role VARCHAR(191) NOT NULL, invited_by VARCHAR(191) NOT NULL, expires_at DATETIME(6) NOT NULL, accepted_at DATETIME(6) NULL, created_at DATETIME(6) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- organization 0002_organization_fields
ALTER TABLE auth_org ADD COLUMN logo VARCHAR(4096) NULL;
ALTER TABLE auth_org ADD COLUMN metadata MEDIUMTEXT NULL;
ALTER TABLE auth_org_invite ADD COLUMN status VARCHAR(191) NOT NULL DEFAULT 'pending';
ALTER TABLE auth_org_invite ADD COLUMN team_id VARCHAR(191) NULL;
UPDATE auth_org_invite SET status = 'accepted' WHERE accepted_at IS NOT NULL;

-- organization 0003_organization_active
CREATE TABLE IF NOT EXISTS auth_org_active (session_id VARCHAR(191) NOT NULL PRIMARY KEY, user_id VARCHAR(191) NOT NULL, org_id VARCHAR(191) NULL, team_id VARCHAR(191) NULL, expires_at DATETIME(6) NOT NULL, INDEX auth_org_active_user_idx (user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- organization 0004_organization_teams
CREATE TABLE IF NOT EXISTS auth_org_team (id VARCHAR(191) NOT NULL PRIMARY KEY, org_id VARCHAR(191) NOT NULL, name VARCHAR(255) NOT NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_org_team_member (team_id VARCHAR(191) NOT NULL, user_id VARCHAR(191) NOT NULL, created_at DATETIME(6) NOT NULL, PRIMARY KEY (team_id, user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- organization 0005_organization_roles
CREATE TABLE IF NOT EXISTS auth_org_role (id VARCHAR(191) NOT NULL PRIMARY KEY, org_id VARCHAR(191) NOT NULL, role VARCHAR(191) NOT NULL, permission MEDIUMTEXT NOT NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL, UNIQUE (org_id, role)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- organization 0006_organization_invite_identifier
ALTER TABLE auth_org_invite ADD COLUMN identifier_kind VARCHAR(191) NOT NULL DEFAULT 'email';
ALTER TABLE auth_org_invite ADD COLUMN identifier VARCHAR(320) NOT NULL DEFAULT '';
UPDATE auth_org_invite SET identifier = email;

-- apikey 0001_api_key
CREATE TABLE IF NOT EXISTS auth_api_key (id VARCHAR(191) NOT NULL PRIMARY KEY, user_id VARCHAR(191) NOT NULL, name VARCHAR(255) NOT NULL, hint VARCHAR(191) NOT NULL, key_hash VARBINARY(32) NOT NULL UNIQUE, scopes VARCHAR(4096) NOT NULL, created_at DATETIME(6) NOT NULL, last_used_at DATETIME(6) NULL, expires_at DATETIME(6) NULL, INDEX auth_api_key_user_idx (user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- apikey 0002_api_key_limits
ALTER TABLE auth_api_key ADD COLUMN disabled_at DATETIME(6) NULL;
ALTER TABLE auth_api_key ADD COLUMN metadata VARCHAR(4096) NULL;
ALTER TABLE auth_api_key ADD COLUMN rate_max BIGINT NOT NULL DEFAULT 0;
ALTER TABLE auth_api_key ADD COLUMN rate_window_seconds BIGINT NOT NULL DEFAULT 0;
ALTER TABLE auth_api_key ADD COLUMN rate_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE auth_api_key ADD COLUMN rate_window_start DATETIME(6) NULL;
ALTER TABLE auth_api_key ADD COLUMN remaining BIGINT NULL;
ALTER TABLE auth_api_key ADD COLUMN refill_amount BIGINT NOT NULL DEFAULT 0;
ALTER TABLE auth_api_key ADD COLUMN refill_interval_seconds BIGINT NOT NULL DEFAULT 0;
ALTER TABLE auth_api_key ADD COLUMN last_refill_at DATETIME(6) NULL;

-- apikey 0003_api_key_config
ALTER TABLE auth_api_key ADD COLUMN config_id VARCHAR(191) NOT NULL DEFAULT 'default';
ALTER TABLE auth_api_key ADD COLUMN prefix VARCHAR(191) NULL;
ALTER TABLE auth_api_key ADD COLUMN updated_at DATETIME(6) NULL;
CREATE INDEX auth_api_key_config_idx ON auth_api_key (config_id);

-- apikey 0004_api_key_org
ALTER TABLE auth_api_key ADD COLUMN organization_id VARCHAR(191) NULL;
ALTER TABLE auth_api_key ADD COLUMN permissions VARCHAR(4096) NULL;
CREATE INDEX auth_api_key_org_idx ON auth_api_key (organization_id);

-- twofactor 0000_column_auth_user_two_factor_enabled
ALTER TABLE auth_user ADD COLUMN two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- twofactor 0001_two_factor
CREATE TABLE IF NOT EXISTS auth_two_factor (user_id VARCHAR(191) NOT NULL PRIMARY KEY, secret_sealed VARCHAR(255) NOT NULL, confirmed_at DATETIME(6) NULL, last_step BIGINT NOT NULL DEFAULT 0, failed_attempts BIGINT NOT NULL DEFAULT 0, locked_until DATETIME(6) NULL, created_at DATETIME(6) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_two_factor_recovery (id VARCHAR(191) NOT NULL PRIMARY KEY, user_id VARCHAR(191) NOT NULL, code_hash VARBINARY(32) NOT NULL UNIQUE, used_at DATETIME(6) NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- twofactor 0002_two_factor_method
ALTER TABLE auth_two_factor ADD COLUMN method VARCHAR(255) NOT NULL DEFAULT 'totp';

-- twofactor 0003_two_factor_device
CREATE TABLE IF NOT EXISTS auth_two_factor_device (id VARCHAR(191) NOT NULL PRIMARY KEY, user_id VARCHAR(191) NOT NULL, token_hash VARBINARY(32) NOT NULL UNIQUE, user_agent VARCHAR(255) NOT NULL, created_at DATETIME(6) NOT NULL, expires_at DATETIME(6) NOT NULL, last_used_at DATETIME(6) NULL, INDEX auth_two_factor_device_user_idx (user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- twofactor 0004_two_factor_issuer_sealed_recovery
ALTER TABLE auth_two_factor ADD COLUMN issuer VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE auth_two_factor_recovery ADD COLUMN code_sealed VARCHAR(4096) NOT NULL DEFAULT '';

-- twofactor 0005_two_factor_recovery_seq
ALTER TABLE auth_two_factor_recovery ADD COLUMN seq BIGINT NOT NULL DEFAULT 0;

-- twofactor 0006_two_factor_method_table
CREATE TABLE IF NOT EXISTS auth_two_factor_method (user_id VARCHAR(191) NOT NULL, method VARCHAR(191) NOT NULL, secret_sealed VARCHAR(255) NOT NULL, issuer VARCHAR(255) NOT NULL, last_step BIGINT NOT NULL DEFAULT 0, confirmed_at DATETIME(6) NULL, created_at DATETIME(6) NOT NULL, PRIMARY KEY (user_id, method)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- oauth 0001_account
CREATE TABLE IF NOT EXISTS auth_account (id VARCHAR(191) NOT NULL PRIMARY KEY, user_id VARCHAR(191) NOT NULL, provider VARCHAR(191) NOT NULL, subject VARCHAR(191) NOT NULL, email VARCHAR(320) NOT NULL DEFAULT '', created_at DATETIME(6) NOT NULL, access_token_sealed VARCHAR(4096) NOT NULL DEFAULT '', refresh_token_sealed VARCHAR(4096) NOT NULL DEFAULT '', token_expires_at DATETIME(6) NULL, UNIQUE (provider, subject), INDEX auth_account_user_idx (user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- oauth 0002_account_id_token
ALTER TABLE auth_account ADD COLUMN id_token_sealed MEDIUMTEXT NULL;

-- oauth 0003_account_token_scope
ALTER TABLE auth_account ADD COLUMN token_scope VARCHAR(4096) NOT NULL DEFAULT '';
ALTER TABLE auth_account ADD COLUMN refresh_token_expires_at DATETIME(6) NULL;

-- oauth 0004_account_refresh_params
ALTER TABLE auth_account ADD COLUMN refresh_params_sealed MEDIUMTEXT NULL;

-- passkey 0001_passkey
CREATE TABLE IF NOT EXISTS auth_passkey (id VARCHAR(191) NOT NULL PRIMARY KEY, user_id VARCHAR(191) NOT NULL, credential_id VARBINARY(1024) NOT NULL UNIQUE, credential_json MEDIUMTEXT NOT NULL, name VARCHAR(255) NOT NULL, created_at DATETIME(6) NOT NULL, last_used_at DATETIME(6) NULL, INDEX auth_passkey_user_idx (user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- passkey 0002_passkey_security_key
CREATE TABLE IF NOT EXISTS auth_passkey_security_key (id VARCHAR(191) NOT NULL PRIMARY KEY, user_id VARCHAR(191) NOT NULL, credential_id VARBINARY(1024) NOT NULL UNIQUE, credential_json MEDIUMTEXT NOT NULL, name VARCHAR(255) NOT NULL, created_at DATETIME(6) NOT NULL, last_used_at DATETIME(6) NULL, INDEX auth_passkey_security_key_user_idx (user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- audit 0001_audit_event
CREATE TABLE IF NOT EXISTS audit_event (id VARCHAR(191) NOT NULL PRIMARY KEY, at DATETIME(6) NOT NULL, op VARCHAR(191) NOT NULL, plugin VARCHAR(191) NOT NULL, transport VARCHAR(191) NOT NULL, ok BOOLEAN NOT NULL, code VARCHAR(191) NOT NULL, actor_id VARCHAR(191) NOT NULL, session_id VARCHAR(191) NOT NULL, subject_id VARCHAR(191) NOT NULL, impersonator_id VARCHAR(191) NOT NULL, identifier VARCHAR(320) NOT NULL, ip VARCHAR(191) NOT NULL, user_agent VARCHAR(4096) NOT NULL, INDEX audit_event_actor_idx (actor_id, at), INDEX audit_event_subject_idx (subject_id, at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- audit 0002_audit_event_org
ALTER TABLE audit_event ADD COLUMN org_id VARCHAR(191) NOT NULL DEFAULT '';
CREATE INDEX audit_event_org_idx ON audit_event (org_id, at);

-- audit 0003_audit_event_severity
ALTER TABLE audit_event ADD COLUMN severity VARCHAR(191) NOT NULL DEFAULT 'info';
CREATE INDEX audit_event_severity_idx ON audit_event (severity, at);

-- emailchallenge 0001_email_challenge
CREATE TABLE IF NOT EXISTS auth_email_challenge (id VARCHAR(191) NOT NULL PRIMARY KEY, identifier VARCHAR(4096) NOT NULL, approval_hash VARBINARY(32) NOT NULL UNIQUE, binding_hash VARBINARY(32) NOT NULL UNIQUE, status VARCHAR(191) NOT NULL, name VARCHAR(255) NOT NULL, scope VARCHAR(255) NOT NULL, ip VARCHAR(255) NOT NULL, user_agent VARCHAR(4096) NOT NULL, expires_at DATETIME(6) NOT NULL, approved_at DATETIME(6) NULL, created_at DATETIME(6) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- invite 0001_invite
CREATE TABLE IF NOT EXISTS auth_invite (id VARCHAR(191) NOT NULL PRIMARY KEY, token_hash VARBINARY(32) NOT NULL UNIQUE, created_by VARCHAR(191) NOT NULL, email VARCHAR(320) NULL, role VARCHAR(255) NOT NULL, max_uses BIGINT NOT NULL, uses BIGINT NOT NULL, status VARCHAR(191) NOT NULL, expires_at DATETIME(6) NOT NULL, created_at DATETIME(6) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_invite_use (invite_id VARCHAR(191) NOT NULL, user_id VARCHAR(191) NOT NULL, used_at DATETIME(6) NOT NULL, PRIMARY KEY (invite_id, user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- referral 0001_referral
CREATE TABLE IF NOT EXISTS auth_referral_code (user_id VARCHAR(191) NOT NULL PRIMARY KEY, code VARCHAR(191) NOT NULL UNIQUE, created_at DATETIME(6) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_referral (id VARCHAR(191) NOT NULL PRIMARY KEY, referrer_user_id VARCHAR(191) NOT NULL, referred_user_id VARCHAR(191) NOT NULL UNIQUE, code VARCHAR(191) NOT NULL, status VARCHAR(191) NOT NULL, completed_at DATETIME(6) NULL, created_at DATETIME(6) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_referral_step (referral_id VARCHAR(191) NOT NULL, step VARCHAR(191) NOT NULL, metadata VARCHAR(4096) NOT NULL, completed_at DATETIME(6) NOT NULL, PRIMARY KEY (referral_id, step)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- terms 0000_column_auth_user_terms_version
ALTER TABLE auth_user ADD COLUMN terms_version VARCHAR(320) NOT NULL DEFAULT '';

-- terms 0000_column_auth_user_terms_accepted_at
ALTER TABLE auth_user ADD COLUMN terms_accepted_at DATETIME(6) NULL;

-- terms 0001_terms_acceptance
CREATE TABLE IF NOT EXISTS auth_terms_acceptance (user_id VARCHAR(191) NOT NULL, version VARCHAR(255) NOT NULL, accepted_at DATETIME(6) NOT NULL, PRIMARY KEY (user_id, version, accepted_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
INSERT INTO auth_terms_acceptance (user_id, version, accepted_at) SELECT id, terms_version, terms_accepted_at FROM auth_user WHERE terms_version <> '' AND terms_accepted_at IS NOT NULL;

-- sessiondata 0001_session_data
CREATE TABLE IF NOT EXISTS auth_session_data (session_id VARCHAR(191) NOT NULL PRIMARY KEY, user_id VARCHAR(191) NOT NULL, data MEDIUMTEXT NOT NULL, expires_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL, INDEX auth_session_data_user_idx (user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- device 0001_device_code
CREATE TABLE IF NOT EXISTS auth_device_code (id VARCHAR(191) NOT NULL PRIMARY KEY, device_code_hash VARBINARY(32) NOT NULL UNIQUE, user_code_hash VARBINARY(32) NOT NULL UNIQUE, user_id VARCHAR(191) NULL, client_id VARCHAR(191) NOT NULL, scope VARCHAR(4096) NOT NULL, status VARCHAR(191) NOT NULL, expires_at DATETIME(6) NOT NULL, last_polled_at DATETIME(6) NULL, polling_interval_ms BIGINT NOT NULL, grant_name VARCHAR(191) NULL, resource VARCHAR(4096) NULL, created_at DATETIME(6) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- sso 0001_sso_provider
CREATE TABLE IF NOT EXISTS auth_sso_provider (id VARCHAR(191) NOT NULL PRIMARY KEY, provider_id VARCHAR(191) NOT NULL UNIQUE, issuer VARCHAR(4096) NOT NULL, domain VARCHAR(4096) NOT NULL, organization_id VARCHAR(191) NOT NULL DEFAULT '', user_id VARCHAR(191) NOT NULL DEFAULT '', oidc_config MEDIUMTEXT NOT NULL, saml_config MEDIUMTEXT NOT NULL, domain_verified BOOLEAN NOT NULL DEFAULT FALSE, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- sso 0002_sso_account
CREATE TABLE IF NOT EXISTS auth_sso_account (id VARCHAR(191) NOT NULL PRIMARY KEY, user_id VARCHAR(191) NOT NULL, provider_id VARCHAR(191) NOT NULL, issuer VARCHAR(4096) NOT NULL, subject VARCHAR(191) NOT NULL, email VARCHAR(320) NOT NULL DEFAULT '', created_at DATETIME(6) NOT NULL, UNIQUE (provider_id, subject), INDEX auth_sso_account_user_idx (user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- sso 0003_sso_domain_token
ALTER TABLE auth_sso_provider ADD COLUMN domain_token VARCHAR(320) NOT NULL DEFAULT '';
ALTER TABLE auth_sso_provider ADD COLUMN domain_token_expires_at DATETIME(6) NULL;
ALTER TABLE auth_sso_provider ADD COLUMN fields MEDIUMTEXT NULL;

-- scim 0000_column_auth_user_scim_deactivated_at
ALTER TABLE auth_user ADD COLUMN scim_deactivated_at DATETIME(6) NULL;

-- scim 0001_scim
CREATE TABLE IF NOT EXISTS auth_scim_user (id VARCHAR(191) NOT NULL PRIMARY KEY, connection_id VARCHAR(191) NOT NULL, user_id VARCHAR(191) NOT NULL, identity_id VARCHAR(191) NULL, user_name VARCHAR(4096) NOT NULL, user_name_key VARCHAR(191) NOT NULL, external_id VARCHAR(4096) NULL, external_id_key VARCHAR(191) NULL, active BOOLEAN NOT NULL, primary_email VARCHAR(320) NOT NULL, resource MEDIUMTEXT NOT NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL, revision BIGINT NOT NULL, UNIQUE (connection_id, user_name_key), UNIQUE (connection_id, external_id_key), UNIQUE (connection_id, user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_scim_group (id VARCHAR(191) NOT NULL PRIMARY KEY, connection_id VARCHAR(191) NOT NULL, display_name VARCHAR(4096) NOT NULL, display_name_key VARCHAR(191) NOT NULL, external_id VARCHAR(4096) NULL, external_id_key VARCHAR(191) NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL, UNIQUE (connection_id, display_name_key), UNIQUE (connection_id, external_id_key)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_scim_member (group_id VARCHAR(191) NOT NULL, scim_user_id VARCHAR(191) NOT NULL, connection_id VARCHAR(191) NOT NULL, user_id VARCHAR(191) NOT NULL, created_at DATETIME(6) NOT NULL, PRIMARY KEY (group_id, scim_user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_scim_connection (id VARCHAR(191) NOT NULL PRIMARY KEY, provisioning_domain VARCHAR(191) NOT NULL, managed BOOLEAN NOT NULL, status VARCHAR(191) NOT NULL, creation_request_id VARCHAR(191) NULL UNIQUE, created_by VARCHAR(191) NOT NULL, created_at DATETIME(6) NOT NULL, decommission_started_at DATETIME(6) NULL, decommissioned_at DATETIME(6) NULL, decommission_cursor VARCHAR(191) NOT NULL, reconciled_users BIGINT NOT NULL, batches BIGINT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_scim_credential (id VARCHAR(191) NOT NULL PRIMARY KEY, connection_id VARCHAR(191) NOT NULL, digest VARBINARY(32) NOT NULL, status VARCHAR(191) NOT NULL, scopes VARCHAR(255) NOT NULL, expires_at DATETIME(6) NULL, created_at DATETIME(6) NOT NULL, created_by VARCHAR(191) NOT NULL, last_used_at DATETIME(6) NULL, revoked_at DATETIME(6) NULL, revoked_by VARCHAR(191) NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_scim_event (id VARCHAR(191) NOT NULL PRIMARY KEY, connection_id VARCHAR(191) NOT NULL, sequence BIGINT NOT NULL, event_type VARCHAR(191) NOT NULL, actor_id VARCHAR(191) NOT NULL, credential_id VARCHAR(191) NULL, created_at DATETIME(6) NOT NULL, UNIQUE (connection_id, sequence)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_scim_tombstone (connection_id VARCHAR(191) NOT NULL, external_id_key VARCHAR(191) NOT NULL, user_id VARCHAR(191) NOT NULL, identity_id VARCHAR(191) NULL, deleted_at DATETIME(6) NOT NULL, PRIMARY KEY (connection_id, external_id_key)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_scim_grant (connection_id VARCHAR(191) NOT NULL, group_id VARCHAR(191) NOT NULL, scim_user_id VARCHAR(191) NOT NULL, user_id VARCHAR(191) NOT NULL, role VARCHAR(191) NOT NULL, created_at DATETIME(6) NOT NULL, PRIMARY KEY (group_id, scim_user_id, role)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- oauthprovider 0001_oauth_provider
CREATE TABLE IF NOT EXISTS auth_oauth_client (id VARCHAR(191) NOT NULL PRIMARY KEY, secret_hash VARBINARY(32) NULL, name VARCHAR(255) NOT NULL, redirect_uris MEDIUMTEXT NOT NULL, scopes MEDIUMTEXT NOT NULL, grant_types MEDIUMTEXT NOT NULL, auth_method VARCHAR(191) NOT NULL, skip_consent BOOLEAN NOT NULL, require_pkce BOOLEAN NOT NULL, introspect_any BOOLEAN NOT NULL, user_id VARCHAR(191) NULL, disabled_at DATETIME(6) NULL, client_uri MEDIUMTEXT NULL, logo_uri MEDIUMTEXT NULL, contacts MEDIUMTEXT NULL, tos_uri MEDIUMTEXT NULL, policy_uri MEDIUMTEXT NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL, INDEX auth_oauth_client_user_idx (user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_oauth_code (id VARCHAR(191) NOT NULL PRIMARY KEY, code_hash VARBINARY(32) NOT NULL UNIQUE, client_id VARCHAR(191) NOT NULL, user_id VARCHAR(191) NOT NULL, session_id VARCHAR(191) NOT NULL, redirect_uri MEDIUMTEXT NOT NULL, scopes MEDIUMTEXT NOT NULL, code_challenge VARCHAR(191) NULL, code_challenge_method VARCHAR(191) NULL, nonce MEDIUMTEXT NULL, auth_time DATETIME(6) NOT NULL, expires_at DATETIME(6) NOT NULL, consumed_at DATETIME(6) NULL, created_at DATETIME(6) NOT NULL, INDEX auth_oauth_code_user_idx (user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_oauth_token (id VARCHAR(191) NOT NULL PRIMARY KEY, access_hash VARBINARY(32) NOT NULL UNIQUE, refresh_hash VARBINARY(32) NULL UNIQUE, family_id VARCHAR(191) NOT NULL, client_id VARCHAR(191) NOT NULL, user_id VARCHAR(191) NULL, session_id VARCHAR(191) NULL, scopes MEDIUMTEXT NOT NULL, access_expires_at DATETIME(6) NOT NULL, refresh_expires_at DATETIME(6) NULL, auth_time DATETIME(6) NULL, created_at DATETIME(6) NOT NULL, rotated_at DATETIME(6) NULL, revoked_at DATETIME(6) NULL, INDEX auth_oauth_token_family_idx (family_id), INDEX auth_oauth_token_user_idx (user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_oauth_consent (id VARCHAR(191) NOT NULL PRIMARY KEY, user_id VARCHAR(191) NOT NULL, client_id VARCHAR(191) NOT NULL, scopes MEDIUMTEXT NOT NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL, CONSTRAINT auth_oauth_consent_pair_uq UNIQUE (user_id, client_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- oauthprovider 0002_oauth_provider_logout_resources_assertions
ALTER TABLE auth_oauth_client ADD COLUMN post_logout_redirect_uris MEDIUMTEXT NULL;
ALTER TABLE auth_oauth_client ADD COLUMN end_session BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE auth_oauth_client ADD COLUMN jwks MEDIUMTEXT NULL;
ALTER TABLE auth_oauth_client ADD COLUMN discovery VARCHAR(191) NULL;
ALTER TABLE auth_oauth_client ADD COLUMN fetched_at DATETIME(6) NULL;
ALTER TABLE auth_oauth_code ADD COLUMN resource MEDIUMTEXT NULL;
ALTER TABLE auth_oauth_token ADD COLUMN resource MEDIUMTEXT NULL;
CREATE TABLE IF NOT EXISTS auth_oauth_assertion (id VARCHAR(191) NOT NULL PRIMARY KEY, expires_at DATETIME(6) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- oauthprovider 0003_oauth_provider_subject_type
ALTER TABLE auth_oauth_client ADD COLUMN subject_type VARCHAR(191) NULL;

-- oauthprovider 0004_oauth_provider_userinfo_claims
ALTER TABLE auth_oauth_code ADD COLUMN userinfo_claims MEDIUMTEXT NULL;
ALTER TABLE auth_oauth_token ADD COLUMN userinfo_claims MEDIUMTEXT NULL;
ALTER TABLE auth_oauth_consent ADD COLUMN userinfo_claims MEDIUMTEXT NULL;

-- oauthprovider 0005_oauth_provider_backchannel_logout
ALTER TABLE auth_oauth_client ADD COLUMN backchannel_logout_uri MEDIUMTEXT NULL;
ALTER TABLE auth_oauth_client ADD COLUMN backchannel_logout_session_required BOOLEAN NOT NULL DEFAULT FALSE;

-- oauthprovider 0006_oauth_provider_dpop
ALTER TABLE auth_oauth_client ADD COLUMN dpop_bound BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE auth_oauth_code ADD COLUMN dpop_jkt VARCHAR(191) NULL;
ALTER TABLE auth_oauth_token ADD COLUMN jkt VARCHAR(191) NULL;

-- oauthprovider 0008_oauth_provider_client_fields
ALTER TABLE auth_oauth_client ADD COLUMN application_type VARCHAR(191) NULL;
ALTER TABLE auth_oauth_client ADD COLUMN client_credentials_scopes MEDIUMTEXT NULL;
ALTER TABLE auth_oauth_client ADD COLUMN reference_id VARCHAR(191) NULL;
ALTER TABLE auth_oauth_client ADD COLUMN metadata MEDIUMTEXT NULL;
ALTER TABLE auth_oauth_client ADD COLUMN client_secret_expires_at DATETIME(6) NULL;

-- oauthprovider 0009_oauth_provider_cimd_cache
ALTER TABLE auth_oauth_client ADD COLUMN cimd_expires_at DATETIME(6) NULL;
ALTER TABLE auth_oauth_client ADD COLUMN cimd_etag MEDIUMTEXT NULL;
ALTER TABLE auth_oauth_client ADD COLUMN cimd_last_modified VARCHAR(255) NULL;

-- oauthprovider 0010_oauth_provider_software
ALTER TABLE auth_oauth_client ADD COLUMN software_id VARCHAR(255) NULL;
ALTER TABLE auth_oauth_client ADD COLUMN software_version VARCHAR(255) NULL;
ALTER TABLE auth_oauth_client ADD COLUMN software_statement MEDIUMTEXT NULL;

-- oauthprovider 0007_oauth_provider_resources
CREATE TABLE IF NOT EXISTS auth_oauth_resource (id VARCHAR(191) NOT NULL PRIMARY KEY, identifier MEDIUMTEXT NOT NULL, name VARCHAR(255) NULL, access_token_ttl BIGINT NULL, refresh_token_ttl BIGINT NULL, allowed_scopes MEDIUMTEXT NULL, custom_claims MEDIUMTEXT NULL, dpop_required BOOLEAN NOT NULL, disabled BOOLEAN NOT NULL, metadata MEDIUMTEXT NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_oauth_client_resource (client_id VARCHAR(191) NOT NULL, resource_id VARCHAR(191) NOT NULL, created_at DATETIME(6) NOT NULL, PRIMARY KEY (client_id, resource_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- oauthprovider 0011_oauth_provider_resource_signing
ALTER TABLE auth_oauth_resource ADD COLUMN signing_algorithm VARCHAR(191) NULL;

-- oauthprovider 0012_oauth_provider_certificate_reference
ALTER TABLE auth_oauth_token ADD COLUMN x5t_s256 VARCHAR(191) NULL;
ALTER TABLE auth_oauth_token ADD COLUMN reference_id VARCHAR(191) NULL;
ALTER TABLE auth_oauth_code ADD COLUMN reference_id VARCHAR(191) NULL;
ALTER TABLE auth_oauth_consent ADD COLUMN reference_id VARCHAR(191) NULL;

-- oauthprovider 0013_oauth_provider_jwks_uri
ALTER TABLE auth_oauth_client ADD COLUMN jwks_uri MEDIUMTEXT NULL;

-- oauthprovider 0014_oauth_provider_revocation_replay_consent_resources
ALTER TABLE auth_oauth_token ADD COLUMN access_revoked_at DATETIME(6) NULL;
ALTER TABLE auth_oauth_token ADD COLUMN rotation_replay MEDIUMTEXT NULL;
ALTER TABLE auth_oauth_token ADD COLUMN rotation_replay_expires_at DATETIME(6) NULL;
ALTER TABLE auth_oauth_consent ADD COLUMN resources MEDIUMTEXT NULL;
ALTER TABLE auth_oauth_client ADD COLUMN secret_encrypted MEDIUMTEXT NULL;
ALTER TABLE auth_oauth_resource ADD COLUMN signing_key_id VARCHAR(191) NULL;
ALTER TABLE auth_oauth_resource ADD COLUMN policy_version BIGINT NOT NULL DEFAULT 1;
ALTER TABLE auth_oauth_client_resource ADD COLUMN metadata MEDIUMTEXT NULL;

-- agentauth 0001_agent_auth
CREATE TABLE IF NOT EXISTS auth_agent_host (id VARCHAR(191) NOT NULL PRIMARY KEY, name VARCHAR(255) NULL, user_id VARCHAR(191) NULL, default_capabilities MEDIUMTEXT NOT NULL, public_key MEDIUMTEXT NOT NULL, kid VARCHAR(191) NOT NULL, status VARCHAR(191) NOT NULL, activated_at DATETIME(6) NULL, expires_at DATETIME(6) NULL, last_used_at DATETIME(6) NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL, INDEX auth_agent_host_user_idx (user_id), INDEX auth_agent_host_kid_idx (kid)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_agent (id VARCHAR(191) NOT NULL PRIMARY KEY, name VARCHAR(255) NOT NULL, user_id VARCHAR(191) NULL, host_id VARCHAR(191) NOT NULL, status VARCHAR(191) NOT NULL, mode VARCHAR(191) NOT NULL, public_key MEDIUMTEXT NOT NULL, kid VARCHAR(191) NULL, last_used_at DATETIME(6) NULL, activated_at DATETIME(6) NULL, expires_at DATETIME(6) NULL, metadata MEDIUMTEXT NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL, INDEX auth_agent_user_idx (user_id), INDEX auth_agent_host_idx (host_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_agent_grant (id VARCHAR(191) NOT NULL PRIMARY KEY, agent_id VARCHAR(191) NOT NULL, capability VARCHAR(320) NOT NULL, constraints MEDIUMTEXT NULL, granted_by VARCHAR(191) NULL, denied_by VARCHAR(191) NULL, reason VARCHAR(4096) NULL, status VARCHAR(191) NOT NULL, expires_at DATETIME(6) NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL, INDEX auth_agent_grant_agent_idx (agent_id), INDEX auth_agent_grant_user_idx (granted_by)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_agent_approval (id VARCHAR(191) NOT NULL PRIMARY KEY, method VARCHAR(191) NOT NULL, agent_id VARCHAR(191) NOT NULL, host_id VARCHAR(191) NULL, user_id VARCHAR(191) NULL, capabilities MEDIUMTEXT NOT NULL, status VARCHAR(191) NOT NULL, user_code_hash VARBINARY(32) NULL, login_hint VARCHAR(255) NULL, binding_message VARCHAR(4096) NULL, interval_seconds BIGINT NOT NULL, expires_at DATETIME(6) NOT NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL, INDEX auth_agent_approval_agent_idx (agent_id), INDEX auth_agent_approval_user_idx (user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_agent_jti (id VARCHAR(191) NOT NULL PRIMARY KEY, expires_at DATETIME(6) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- agentauth 0002_agent_approval_kind
ALTER TABLE auth_agent_approval ADD COLUMN kind VARCHAR(191) NULL;

-- agentauth 0003_agent_lifecycle
ALTER TABLE auth_agent_host ADD COLUMN jwks_url VARCHAR(4096) NULL;
ALTER TABLE auth_agent_host ADD COLUMN enrollment_token_hash VARBINARY(32) NULL;
ALTER TABLE auth_agent_host ADD COLUMN enrollment_token_expires_at DATETIME(6) NULL;
ALTER TABLE auth_agent ADD COLUMN jwks_url VARCHAR(4096) NULL;
ALTER TABLE auth_agent_host ADD INDEX auth_agent_host_enroll_idx (enrollment_token_hash);

