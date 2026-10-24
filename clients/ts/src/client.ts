// Generated from the operation list of github.com/ubgo/auth (authhttp.TypeScriptClient). Do not edit.

import type { AnyPlugin, AuthClient, ClientOptions, EmptyInput, Fill, Op, Plugin } from "./runtime.ts";
import { createClient } from "./runtime.ts";

/** The JSON of Go type admin.AllSessionsRequest. */
export interface AdminAllSessionsRequest {
  userId?: string;
  page?: string;
  limit?: string;
  offset?: string;
}

/** The JSON of Go type admin.AllSessionsResult. */
export interface AdminAllSessionsResult {
  sessions: AdminFleetSession[] | null;
  total: number;
  page: number;
  limit: number;
  offset: number;
}

/** The JSON of Go type admin.BanRequest. */
export interface AdminBanRequest {
  userId: string;
  reason?: string;
  minutes?: number;
}

/** The JSON of Go type admin.CreateUserRequest. */
export interface AdminCreateUserRequest {
  name?: string;
  image?: string;
  email: string;
  verified?: boolean;
  password?: string;
}

/** The JSON of Go type admin.CreateUserResult. */
export interface AdminCreateUserResult {
  user: AuthUserView;
}

/** The JSON of Go type admin.FleetSession. */
export interface AdminFleetSession {
  id: string;
  userId: string;
  impersonated: boolean;
  ip: string;
  userAgent: string;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
}

/** The JSON of Go type admin.IdentityView. */
export interface AdminIdentityView {
  kind: string;
  value: string;
  verified: boolean;
  primary: boolean;
}

/** The JSON of Go type admin.ImpersonateRequest. */
export interface AdminImpersonateRequest {
  userId: string;
  minutes?: number;
}

/** The JSON of Go type admin.ImpersonateResult. */
export interface AdminImpersonateResult {
  user: AuthUserView;
  expiresAt: string;
}

/** The JSON of Go type admin.PermissionRequest. */
export interface AdminPermissionRequest {
  userId?: string;
  permissions: { [key: string]: string[] | null } | null;
  connector?: string;
}

/** The JSON of Go type admin.PermissionResult. */
export interface AdminPermissionResult {
  success: boolean;
}

/** The JSON of Go type admin.RevokeSessionRequest. */
export interface AdminRevokeSessionRequest {
  userId: string;
  sessionId: string;
}

/** The JSON of Go type admin.SearchUsersRequest. */
export interface AdminSearchUsersRequest {
  value: string;
  field?: string;
  operator?: string;
  page?: string;
  limit?: string;
  offset?: string;
  sort?: string;
  sortBy?: string;
  sortDirection?: string;
  admin?: string;
  banned?: string;
  filterField?: string;
  filterOperator?: string;
  filterValue?: string | null;
}

/** The JSON of Go type admin.SessionsResult. */
export interface AdminSessionsResult {
  sessions: AuthSessionView[] | null;
}

/** The JSON of Go type admin.SetAdminRequest. */
export interface AdminSetAdminRequest {
  userId: string;
  admin: boolean;
}

/** The JSON of Go type admin.SetEmailRequest. */
export interface AdminSetEmailRequest {
  userId: string;
  email: string;
  verified?: boolean;
}

/** The JSON of Go type admin.SetPasswordRequest. */
export interface AdminSetPasswordRequest {
  userId: string;
  password: string;
}

/** The JSON of Go type admin.SetRoleRequest. */
export interface AdminSetRoleRequest {
  userId: string;
  role: string[] | null;
}

/** The JSON of Go type admin.StopResult. */
export interface AdminStopResult {
  ok: boolean;
  restored: boolean;
}

/** The JSON of Go type admin.TwoFactorResult. */
export interface AdminTwoFactorResult {
  enrolled: boolean;
  enabled: boolean;
  method: string;
}

/** The JSON of Go type admin.UpdateUserRequest. */
export interface AdminUpdateUserRequest {
  userId: string;
  name?: string | null;
  image?: string | null;
  data?: { [key: string]: unknown } | null;
}

/** The JSON of Go type admin.UserDetail. */
export interface AdminUserDetail {
  user: AdminUserSummary;
  banReason: string;
  identities: AdminIdentityView[] | null;
  sessions: number;
}

/** The JSON of Go type admin.UserRequest. */
export interface AdminUserRequest {
  userId: string;
}

/** The JSON of Go type admin.UserSummary. */
export interface AdminUserSummary {
  id: string;
  name: string;
  createdAt: string;
  admin: boolean;
  banned: boolean;
  email: string;
  roles: string[] | null;
  lastActiveAt: string | null;
}

/** The JSON of Go type admin.UsersRequest. */
export interface AdminUsersRequest {
  query?: string;
  page?: string;
  limit?: string;
  offset?: string;
  sort?: string;
  sortBy?: string;
  sortDirection?: string;
  admin?: string;
  banned?: string;
  filterField?: string;
  filterOperator?: string;
  filterValue?: string | null;
}

/** The JSON of Go type admin.UsersResult. */
export interface AdminUsersResult {
  users: AdminUserSummary[] | null;
  total: number;
  page: number;
  limit: number;
  offset: number;
}

/** The JSON of Go type anonymous.SignInRequest. */
export interface AnonymousSignInRequest {
  remember?: boolean | null;
}

/** The JSON of Go type anonymous.SignInResult. */
export interface AnonymousSignInResult {
  user: AuthUserView;
}

/** The JSON of Go type apikey.CreateRequest. */
export interface ApikeyCreateRequest {
  configId?: string;
  name?: string;
  scopes?: string[] | null;
  prefix?: string;
  expiresInDays?: number;
  expiresIn?: number;
  metadata?: unknown;
  organizationId?: string;
}

/** The JSON of Go type apikey.CreateResult. */
export interface ApikeyCreateResult {
  key: ApikeyKey;
  secret: string;
}

/** The JSON of Go type apikey.GetRequest. */
export interface ApikeyGetRequest {
  id: string;
  configId?: string;
}

/** The JSON of Go type apikey.Key. */
export interface ApikeyKey {
  id: string;
  configId: string;
  name?: string;
  prefix: string;
  hint: string;
  scopes: string[] | null;
  createdAt: string;
  lastUsedAt: string | null;
  expiresAt: string | null;
  disabled: boolean;
  metadata: unknown;
  organizationId: string;
  permissions: { [key: string]: string[] | null } | null;
  limits: unknown;
  updatedAt: string | null;
}

/** The JSON of Go type apikey.ListRequest. */
export interface ApikeyListRequest {
  configId?: string;
  organizationId?: string;
  limit?: string;
  offset?: string;
  sortBy?: string;
  sort?: string;
}

/** The JSON of Go type apikey.ListResult. */
export interface ApikeyListResult {
  keys: ApikeyKey[] | null;
  total: number;
  limit: number;
  offset: number;
}

/** The JSON of Go type apikey.RevokeRequest. */
export interface ApikeyRevokeRequest {
  id: string;
  configId?: string;
}

/** The JSON of Go type apikey.UpdateRequest. */
export interface ApikeyUpdateRequest {
  id: string;
  configId?: string;
  name?: string | null;
  expiresInDays?: number | null;
  expiresIn?: number | null;
  disabled?: boolean | null;
  metadata?: unknown;
  scopes?: string[] | null;
}

/** The JSON of Go type audit.Event. */
export interface AuditEvent {
  id: string;
  at: string;
  op: string;
  plugin: string;
  transport: string;
  ok: boolean;
  code?: string;
  actorId?: string;
  sessionId?: string;
  subjectId?: string;
  impersonatorId?: string;
  identifier?: string;
  ip?: string;
  userAgent?: string;
  orgId?: string;
  severity: string;
  type: string;
}

/** The JSON of Go type audit.MyQuery. */
export interface AuditMyQuery {
  type?: string;
  orgId?: string;
  page?: string;
  limit?: string;
}

/** The JSON of Go type audit.Page. */
export interface AuditPage {
  events: AuditEvent[] | null;
  total: number;
  page: number;
  limit: number;
}

/** The JSON of Go type audit.Query. */
export interface AuditQuery {
  userId?: string;
  identifier?: string;
  op?: string;
  orgId?: string;
  type?: string;
  severity?: string;
  minSeverity?: string;
  page?: string;
  limit?: string;
}

/** The JSON of Go type auth.ConfirmDeleteAccountRequest. */
export interface AuthConfirmDeleteAccountRequest {
  token: string;
}

/** The JSON of Go type auth.DeleteAccountResult. */
export interface AuthDeleteAccountResult {
  deleted: boolean;
  confirmationSent: boolean;
}

/** The JSON of Go type auth.DeviceSessionRequest. */
export interface AuthDeviceSessionRequest {
  id: string;
}

/** The JSON of Go type auth.DeviceSessionView. */
export interface AuthDeviceSessionView {
  id: string;
  user: AuthUserView;
  active: boolean;
  expiresAt: string;
  extras?: unknown;
}

/** The JSON of Go type auth.DeviceSessionsResult. */
export interface AuthDeviceSessionsResult {
  sessions: AuthDeviceSessionView[] | null;
}

/** The JSON of Go type auth.Done. */
export interface AuthDone {
  ok: boolean;
}

/** The JSON of Go type auth.ProfileRequest. */
export interface AuthProfileRequest {
  name?: string | null;
  image?: string | null;
  fields?: { [key: string]: unknown } | null;
}

/** The JSON of Go type auth.Reauthentication. */
export interface AuthReauthentication {
  fresh: boolean;
  freshUntil?: string | null;
  secondFactorRequired: boolean;
  ticket?: string;
}

/** The JSON of Go type auth.RevokeSessionRequest. */
export interface AuthRevokeSessionRequest {
  id: string;
}

/** The JSON of Go type auth.SessionResult. */
export interface AuthSessionResult {
  user: AuthUserView;
  expiresAt: string;
  extras?: unknown;
  needsRefresh?: boolean;
  tasks?: string[] | null;
}

/** The JSON of Go type auth.SessionView. */
export interface AuthSessionView {
  id: string;
  current: boolean;
  impersonated: boolean;
  ip: string;
  userAgent: string;
  createdAt: string;
  lastSeenAt: string;
}

/** The JSON of Go type auth.SessionsResult. */
export interface AuthSessionsResult {
  sessions: AuthSessionView[] | null;
}

/** The JSON of Go type auth.UserView. */
export interface AuthUserView {
  id: string;
  name: string;
  image: string;
}

/** The JSON of Go type deviceauth.CodeRequest. */
export interface DeviceauthCodeRequest {
  client_id: string;
  scope?: string;
  client_secret?: string;
  client_assertion?: string;
  client_assertion_type?: string;
  resource?: string;
}

/** The JSON of Go type deviceauth.CodeResult. */
export interface DeviceauthCodeResult {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

/** The JSON of Go type deviceauth.DecisionRequest. */
export interface DeviceauthDecisionRequest {
  userCode: string;
}

/** The JSON of Go type deviceauth.DecisionResult. */
export interface DeviceauthDecisionResult {
  success: boolean;
}

/** The JSON of Go type deviceauth.TokenRequest. */
export interface DeviceauthTokenRequest {
  grant_type: string;
  device_code: string;
  client_id: string;
}

/** The JSON of Go type deviceauth.TokenResult. */
export interface DeviceauthTokenResult {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
}

/** The JSON of Go type deviceauth.VerifyRequest. */
export interface DeviceauthVerifyRequest {
  user_code: string;
}

/** The JSON of Go type deviceauth.VerifyResult. */
export interface DeviceauthVerifyResult {
  user_code: string;
  status: string;
  client_id?: string;
  scope?: string;
  resource?: string;
  owned: boolean;
}

/** The JSON of Go type email.Address. */
export interface EmailAddress {
  email: string;
  verified: boolean;
  primary: boolean;
}

/** The JSON of Go type email.AddressCodeRequest. */
export interface EmailAddressCodeRequest {
  email: string;
  code: string;
}

/** The JSON of Go type email.AddressRequest. */
export interface EmailAddressRequest {
  email: string;
  metadata?: { [key: string]: string } | null;
}

/** The JSON of Go type email.CheckCodeRequest. */
export interface EmailCheckCodeRequest {
  kind: string;
  email: string;
  code: string;
}

/** The JSON of Go type email.CodeRequest. */
export interface EmailCodeRequest {
  email: string;
  code: string;
  name?: string;
  image?: string;
  fields?: { [key: string]: unknown } | null;
}

/** The JSON of Go type email.CodeSignInResult. */
export interface EmailCodeSignInResult {
  user: AuthUserView;
  created: boolean;
  secondFactorRequired: boolean;
}

/** The JSON of Go type email.ListResult. */
export interface EmailListResult {
  addresses: EmailAddress[] | null;
}

/** The JSON of Go type email.TokenRequest. */
export interface EmailTokenRequest {
  token: string;
}

/** The JSON of Go type email.VerifyResult. */
export interface EmailVerifyResult {
  email: string;
  signedIn?: boolean;
  secondFactorRequired?: boolean;
}

/** The JSON of Go type emailchallenge.ContextResult. */
export interface EmailchallengeContextResult {
  state: string;
  identifier?: string;
  ipAddress?: string;
  userAgent?: string;
  expiresAt?: string | null;
}

/** The JSON of Go type emailchallenge.Result. */
export interface EmailchallengeResult {
  state?: string;
  pollToken?: string;
  expiresAt?: string | null;
  user?: AuthUserView | null;
  created?: boolean;
  secondFactorRequired?: boolean;
}

/** The JSON of Go type emailchallenge.StartOrToken. */
export interface EmailchallengeStartOrToken {
  identifier?: string;
  name?: string;
  pollToken?: string;
  otp?: string;
  token?: string;
}

/** The JSON of Go type emailchallenge.TokenRequest. */
export interface EmailchallengeTokenRequest {
  token: string;
  pollToken?: string;
}

/** The JSON of Go type handoff.GenerateRequest. */
export interface HandoffGenerateRequest {
  challenge?: string;
}

/** The JSON of Go type handoff.GenerateResult. */
export interface HandoffGenerateResult {
  token: string;
  expiresAt: string;
}

/** The JSON of Go type handoff.VerifyRequest. */
export interface HandoffVerifyRequest {
  token: string;
  verifier?: string;
}

/** The JSON of Go type handoff.VerifyResult. */
export interface HandoffVerifyResult {
  user: AuthUserView;
}

/** The JSON of Go type invite.ActivateResult. */
export interface InviteActivateResult {
  action: string;
}

/** The JSON of Go type invite.Created. */
export interface InviteCreated {
  id: string;
  token?: string;
  url?: string;
  expiresAt: string;
}

/** The JSON of Go type invite.IDRequest. */
export interface InviteIDRequest {
  id: string;
}

/** The JSON of Go type invite.Invite. */
export interface InviteInvite {
  id: string;
  email?: string;
  role?: string;
  maxUses: number;
  uses: number;
  status: string;
  expiresAt: string;
  createdAt: string;
}

/** The JSON of Go type invite.ListRequest. */
export interface InviteListRequest {
  limit?: number;
  offset?: number;
}

/** The JSON of Go type invite.ListResult. */
export interface InviteListResult {
  invites: InviteInvite[] | null;
  total: number;
}

/** The JSON of Go type invite.Request. */
export interface InviteRequest {
  email?: string;
  role?: string;
  maxUses?: number;
  expiresIn?: number;
}

/** The JSON of Go type invite.TokenRequest. */
export interface InviteTokenRequest {
  token: string;
}

/** The JSON of Go type invite.View. */
export interface InviteView {
  status: string;
  expiresAt: string;
  role?: string;
  inviterName?: string;
  private: boolean;
}

/** The JSON of Go type jwt.JWK. */
export interface JwtJWK {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
  kid: string;
  use: string;
  alg: string;
}

/** The JSON of Go type jwt.JWKS. */
export interface JwtJWKS {
  keys: JwtJWK[] | null;
}

/** The JSON of Go type jwt.TemplateRequest. */
export interface JwtTemplateRequest {
  template: string;
}

/** The JSON of Go type jwt.TokenResult. */
export interface JwtTokenResult {
  token: string;
  expiresAt: string;
}

/** The JSON of Go type ldap.SignInRequest. */
export interface LdapSignInRequest {
  username: string;
  password: string;
}

/** The JSON of Go type ldap.SignInResult. */
export interface LdapSignInResult {
  user: AuthUserView;
  created: boolean;
  linked: boolean;
  secondFactorRequired: boolean;
}

/** The JSON of Go type magiclink.SendRequest. */
export interface MagiclinkSendRequest {
  identifier: string;
  name?: string;
  metadata?: { [key: string]: string } | null;
  callbackURL?: string;
  newUserCallbackURL?: string;
  errorCallbackURL?: string;
}

/** The JSON of Go type magiclink.SignInRequest. */
export interface MagiclinkSignInRequest {
  token: string;
}

/** The JSON of Go type magiclink.SignInResult. */
export interface MagiclinkSignInResult {
  user: AuthUserView;
  created: boolean;
  secondFactorRequired: boolean;
}

/** The JSON of Go type metadata.AdminGetRequest. */
export interface MetadataAdminGetRequest {
  userId: string;
}

/** The JSON of Go type metadata.AdminUpdateRequest. */
export interface MetadataAdminUpdateRequest {
  userId: string;
  public?: unknown;
  private?: unknown;
  unsafe?: unknown;
}

/** The JSON of Go type metadata.Metadata. */
export interface MetadataMetadata {
  public: unknown;
  private: unknown;
  unsafe: unknown;
}

/** The JSON of Go type metadata.UpdateRequest. */
export interface MetadataUpdateRequest {
  unsafe: unknown;
}

/** The JSON of Go type metadata.UserMetadata. */
export interface MetadataUserMetadata {
  public: unknown;
  unsafe: unknown;
}

/** The JSON of Go type oauth.AccessTokenRequest. */
export interface OauthAccessTokenRequest {
  provider: string;
}

/** The JSON of Go type oauth.AccessTokenResult. */
export interface OauthAccessTokenResult {
  accessToken: string;
  accessTokenExpiresAt: string | null;
  scopes: string[] | null;
  idToken?: string;
}

/** The JSON of Go type oauth.Account. */
export interface OauthAccount {
  id: string;
  provider: string;
  email: string;
  createdAt: string;
  scopes: string[] | null;
}

/** The JSON of Go type oauth.AccountsResult. */
export interface OauthAccountsResult {
  accounts: OauthAccount[] | null;
}

/** The JSON of Go type oauth.CallbackRequest. */
export interface OauthCallbackRequest {
  code?: string;
  state: string;
  error?: string;
  error_description?: string;
  scope?: string;
  authuser?: string;
  prompt?: string;
  hd?: string;
  iss?: string;
  user?: string;
  device_id?: string;
}

/** The JSON of Go type oauth.CallbackResult. */
export interface OauthCallbackResult {
  user: AuthUserView;
  created: boolean;
  linked: boolean;
  redirectTo: string;
  secondFactorRequired: boolean;
  emailVerificationRequired?: boolean;
  data: string;
  reauthentication?: AuthReauthentication | null;
}

/** The JSON of Go type oauth.IDTokenRequest. */
export interface OauthIDTokenRequest {
  idToken: string;
  nonce?: string;
  signUp?: boolean;
  accessToken?: string;
}

/** The JSON of Go type oauth.LogoutRequest. */
export interface OauthLogoutRequest {
  provider?: string;
  returnTo?: string;
}

/** The JSON of Go type oauth.LogoutResult. */
export interface OauthLogoutResult {
  url: string;
}

/** The JSON of Go type oauth.ProviderInfo. */
export interface OauthProviderInfo {
  id: string;
  name: string;
}

/** The JSON of Go type oauth.ProvidersResult. */
export interface OauthProvidersResult {
  providers: OauthProviderInfo[] | null;
}

/** The JSON of Go type oauth.ReauthenticateIDTokenRequest. */
export interface OauthReauthenticateIDTokenRequest {
  provider: string;
  idToken: string;
  nonce?: string;
  accessToken?: string;
}

/** The JSON of Go type oauth.ReauthenticateRequest. */
export interface OauthReauthenticateRequest {
  provider: string;
  returnTo?: string;
  errorTo?: string;
  prompt?: string;
  loginHint?: string;
}

/** The JSON of Go type oauth.StartRequest. */
export interface OauthStartRequest {
  returnTo?: string;
  link?: string;
  prompt?: string;
  loginHint?: string;
  scopes?: string;
  params?: string;
  data?: string;
  errorTo?: string;
  newUserTo?: string;
  signUp?: string;
}

/** The JSON of Go type oauth.StartResult. */
export interface OauthStartResult {
  url: string;
}

/** The JSON of Go type oauth.UnlinkRequest. */
export interface OauthUnlinkRequest {
  provider: string;
  accountId?: string;
}

/** The JSON of Go type oauthprovider.AuthorizeResult. */
export interface OauthproviderAuthorizeResult {
  redirect_to: string;
}

/** The JSON of Go type oauthprovider.Client. */
export interface OauthproviderClient {
  client_name: string;
  redirect_uris: string[] | null;
  grant_types: string[] | null;
  response_types: string[] | null;
  token_endpoint_auth_method: string;
  scope: string;
  client_uri?: string;
  logo_uri?: string;
  tos_uri?: string;
  policy_uri?: string;
  contacts?: string[] | null;
  post_logout_redirect_uris?: string[] | null;
  jwks?: unknown;
  jwks_uri?: string;
  subject_type?: string;
  backchannel_logout_uri?: string;
  backchannel_logout_session_required?: boolean;
  dpop_bound_access_tokens?: boolean;
  resources?: string[] | null;
  application_type?: string;
  software_id?: string;
  software_version?: string;
  software_statement?: string;
  client_credentials_scopes?: string[] | null;
  client_id: string;
  public: boolean;
  skip_consent: boolean;
  require_pkce: boolean;
  introspect_any: boolean;
  client_secret_expires_at?: string | null;
  reference_id?: string;
  metadata?: unknown;
  enable_end_session: boolean;
  disabled: boolean;
  owner_id?: string;
  created_at: string;
  updated_at: string;
}

/** The JSON of Go type oauthprovider.ClientIDRequest. */
export interface OauthproviderClientIDRequest {
  client_id: string;
}

/** The JSON of Go type oauthprovider.ClientList. */
export interface OauthproviderClientList {
  clients: OauthproviderClient[] | null;
}

/** The JSON of Go type oauthprovider.ClientMetadata. */
export interface OauthproviderClientMetadata {
  client_name?: string;
  redirect_uris: string[] | null;
  grant_types?: string[] | null;
  response_types?: string[] | null;
  token_endpoint_auth_method?: string;
  scope?: string;
  client_uri?: string;
  logo_uri?: string;
  tos_uri?: string;
  policy_uri?: string;
  contacts?: string[] | null;
  post_logout_redirect_uris?: string[] | null;
  jwks?: unknown;
  jwks_uri?: string;
  subject_type?: string;
  backchannel_logout_uri?: string;
  backchannel_logout_session_required?: boolean;
  dpop_bound_access_tokens?: boolean;
  resources?: string[] | null;
  application_type?: string;
  software_id?: string;
  software_version?: string;
  software_statement?: string;
  client_credentials_scopes?: string[] | null;
}

/** The JSON of Go type oauthprovider.Consent. */
export interface OauthproviderConsent {
  id: string;
  client_id: string;
  client_name: string;
  scopes: string[] | null;
  resources?: string[] | null;
  created_at: string;
  updated_at: string;
}

/** The JSON of Go type oauthprovider.ConsentIDRequest. */
export interface OauthproviderConsentIDRequest {
  id: string;
}

/** The JSON of Go type oauthprovider.ConsentList. */
export interface OauthproviderConsentList {
  consents: OauthproviderConsent[] | null;
}

/** The JSON of Go type oauthprovider.ConsentRequest. */
export interface OauthproviderConsentRequest {
  oauth_query: string;
  accept: boolean;
  scope?: string;
  claims?: unknown;
}

/** The JSON of Go type oauthprovider.ContinueRequest. */
export interface OauthproviderContinueRequest {
  oauth_query: string;
  selected?: boolean;
  created?: boolean;
  post_login?: boolean;
}

/** The JSON of Go type oauthprovider.PreloginRequest. */
export interface OauthproviderPreloginRequest {
  client_id: string;
  oauth_query: string;
}

/** The JSON of Go type oauthprovider.PublicClient. */
export interface OauthproviderPublicClient {
  client_id: string;
  client_name: string;
  client_uri?: string;
  logo_uri?: string;
  tos_uri?: string;
  policy_uri?: string;
  contacts?: string[] | null;
}

/** The JSON of Go type oauthprovider.Registration. */
export interface OauthproviderRegistration {
  client_name: string;
  redirect_uris: string[] | null;
  grant_types: string[] | null;
  response_types: string[] | null;
  token_endpoint_auth_method: string;
  scope: string;
  client_uri?: string;
  logo_uri?: string;
  tos_uri?: string;
  policy_uri?: string;
  contacts?: string[] | null;
  post_logout_redirect_uris?: string[] | null;
  jwks?: unknown;
  jwks_uri?: string;
  subject_type?: string;
  backchannel_logout_uri?: string;
  backchannel_logout_session_required?: boolean;
  dpop_bound_access_tokens?: boolean;
  resources?: string[] | null;
  application_type?: string;
  software_id?: string;
  software_version?: string;
  software_statement?: string;
  client_credentials_scopes?: string[] | null;
  client_id: string;
  public: boolean;
  skip_consent: boolean;
  require_pkce: boolean;
  introspect_any: boolean;
  client_secret_expires_at: number;
  reference_id?: string;
  metadata?: unknown;
  enable_end_session: boolean;
  disabled: boolean;
  owner_id?: string;
  created_at: string;
  updated_at: string;
  client_secret?: string;
  client_id_issued_at: number;
}

/** The JSON of Go type oauthprovider.UpdateClientRequest. */
export interface OauthproviderUpdateClientRequest {
  client_id: string;
  metadata: OauthproviderClientMetadata;
  client_credentials_scopes?: string[] | null;
}

/** The JSON of Go type oauthprovider.UpdateConsentRequest. */
export interface OauthproviderUpdateConsentRequest {
  id: string;
  scope: string;
}

/** The JSON of Go type organization.AcceptRequest. */
export interface OrganizationAcceptRequest {
  inviteId: string;
}

/** The JSON of Go type organization.ActiveResult. */
export interface OrganizationActiveResult {
  activeOrganizationId: string | null;
  activeTeamId: string | null;
  organization?: OrganizationOrg | null;
}

/** The JSON of Go type organization.AddDomainRequest. */
export interface OrganizationAddDomainRequest {
  orgId?: string;
  domain: string;
  enrollmentMode?: string;
  role?: string;
}

/** The JSON of Go type organization.CreateRequest. */
export interface OrganizationCreateRequest {
  name: string;
  slug: string;
  logo?: string | null;
  metadata?: unknown;
  keepCurrentActiveOrganization?: boolean;
  fields?: { [key: string]: unknown } | null;
}

/** The JSON of Go type organization.CreateRoleRequest. */
export interface OrganizationCreateRoleRequest {
  orgId?: string;
  role: string;
  permission: { [key: string]: string[] | null } | null;
  fields?: { [key: string]: unknown } | null;
}

/** The JSON of Go type organization.CreateTeamRequest. */
export interface OrganizationCreateTeamRequest {
  orgId?: string;
  name: string;
  fields?: { [key: string]: unknown } | null;
}

/** The JSON of Go type organization.DomainRequest. */
export interface OrganizationDomainRequest {
  domainId: string;
}

/** The JSON of Go type organization.DomainSuggestion. */
export interface OrganizationDomainSuggestion {
  domainId: string;
  orgId: string;
  orgName: string;
  orgSlug: string;
  domain: string;
  requested: boolean;
}

/** The JSON of Go type organization.DomainsRequest. */
export interface OrganizationDomainsRequest {
  orgId?: string;
}

/** The JSON of Go type organization.DomainsResult. */
export interface OrganizationDomainsResult {
  domains: OrganizationOrgDomain[] | null;
}

/** The JSON of Go type organization.FullOrg. */
export interface OrganizationFullOrg {
  id: string;
  slug: string;
  name: string;
  logo?: string | null;
  metadata?: unknown;
  createdAt: string;
  fields?: { [key: string]: unknown } | null;
  members: OrganizationMemberView[] | null;
  invitations: OrganizationInvitation[] | null;
  teams?: OrganizationTeam[] | null;
}

/** The JSON of Go type organization.GetRequest. */
export interface OrganizationGetRequest {
  orgId?: string;
  orgSlug?: string;
  membersLimit?: string;
}

/** The JSON of Go type organization.Invitation. */
export interface OrganizationInvitation {
  id: string;
  orgId: string;
  email: string;
  kind: string;
  identifier: string;
  role: string;
  status: string;
  inviterId: string;
  teamId?: string | null;
  expiresAt: string;
  createdAt: string;
  fields?: { [key: string]: unknown } | null;
}

/** The JSON of Go type organization.InvitationsResult. */
export interface OrganizationInvitationsResult {
  invitations: OrganizationInvitation[] | null;
}

/** The JSON of Go type organization.Invite. */
export interface OrganizationInvite {
  id: string;
  orgId: string;
  orgName: string;
  email: string;
  kind: string;
  identifier: string;
  role: string;
  expiresAt: string;
}

/** The JSON of Go type organization.InviteRequest. */
export interface OrganizationInviteRequest {
  orgId?: string;
  email?: string;
  kind?: string;
  identifier?: string;
  role: string;
  teamId?: string;
  resend?: boolean;
  fields?: { [key: string]: unknown } | null;
}

/** The JSON of Go type organization.InvitesResult. */
export interface OrganizationInvitesResult {
  invites: OrganizationInvite[] | null;
}

/** The JSON of Go type organization.ListResult. */
export interface OrganizationListResult {
  orgs: OrganizationOrgWithRole[] | null;
}

/** The JSON of Go type organization.MemberRequest. */
export interface OrganizationMemberRequest {
  orgId?: string;
  userId?: string;
  email?: string;
  kind?: string;
  identifier?: string;
}

/** The JSON of Go type organization.MemberView. */
export interface OrganizationMemberView {
  user: AuthUserView;
  role: string;
  joinedAt: string;
  fields?: { [key: string]: unknown } | null;
}

/** The JSON of Go type organization.MembersResult. */
export interface OrganizationMembersResult {
  members: OrganizationMemberView[] | null;
  total: number;
  page: number;
  limit: number;
}

/** The JSON of Go type organization.MembershipRequest. */
export interface OrganizationMembershipRequest {
  id: string;
  orgId: string;
  domainId: string;
  domain: string;
  user: AuthUserView;
  status: string;
  createdAt: string;
}

/** The JSON of Go type organization.MembershipRequestsResult. */
export interface OrganizationMembershipRequestsResult {
  requests: OrganizationMembershipRequest[] | null;
}

/** The JSON of Go type organization.Org. */
export interface OrganizationOrg {
  id: string;
  slug: string;
  name: string;
  logo?: string | null;
  metadata?: unknown;
  createdAt: string;
  fields?: { [key: string]: unknown } | null;
}

/** The JSON of Go type organization.OrgDomain. */
export interface OrganizationOrgDomain {
  id: string;
  orgId: string;
  domain: string;
  enrollmentMode: string;
  role: string;
  verified: boolean;
  verifiedAt?: string | null;
  recordName: string;
  recordValue: string;
  createdAt: string;
}

/** The JSON of Go type organization.OrgRequest. */
export interface OrganizationOrgRequest {
  orgId?: string;
  page?: string;
  limit?: string;
  sortBy?: string;
  sortDirection?: string;
  filterField?: string;
  filterOperator?: string;
  filterValue?: string;
}

/** The JSON of Go type organization.OrgRole. */
export interface OrganizationOrgRole {
  id: string;
  orgId: string;
  role: string;
  permission: { [key: string]: string[] | null } | null;
  createdAt: string;
  updatedAt: string;
  fields?: { [key: string]: unknown } | null;
}

/** The JSON of Go type organization.OrgUpdate. */
export interface OrganizationOrgUpdate {
  name?: string | null;
  slug?: string | null;
  logo?: string | null;
  metadata?: unknown;
  fields?: { [key: string]: unknown } | null;
}

/** The JSON of Go type organization.OrgWithRole. */
export interface OrganizationOrgWithRole {
  id: string;
  slug: string;
  name: string;
  logo?: string | null;
  metadata?: unknown;
  createdAt: string;
  fields?: { [key: string]: unknown } | null;
  role: string;
}

/** The JSON of Go type organization.PermissionRequest. */
export interface OrganizationPermissionRequest {
  orgId?: string;
  permissions: { [key: string]: string[] | null } | null;
  connector?: string;
}

/** The JSON of Go type organization.PermissionResult. */
export interface OrganizationPermissionResult {
  success: boolean;
}

/** The JSON of Go type organization.RequestIDRequest. */
export interface OrganizationRequestIDRequest {
  requestId: string;
}

/** The JSON of Go type organization.RoleRequest. */
export interface OrganizationRoleRequest {
  orgId?: string;
  roleId?: string;
  roleName?: string;
}

/** The JSON of Go type organization.RoleResult. */
export interface OrganizationRoleResult {
  role: string;
}

/** The JSON of Go type organization.RoleUpdate. */
export interface OrganizationRoleUpdate {
  roleName?: string | null;
  permission?: { [key: string]: string[] | null } | null;
  fields?: { [key: string]: unknown } | null;
}

/** The JSON of Go type organization.RolesResult. */
export interface OrganizationRolesResult {
  roles: OrganizationOrgRole[] | null;
}

/** The JSON of Go type organization.SetActiveRequest. */
export interface OrganizationSetActiveRequest {
  orgId?: string;
  orgSlug?: string;
}

/** The JSON of Go type organization.SetRoleRequest. */
export interface OrganizationSetRoleRequest {
  orgId?: string;
  userId: string;
  role: string;
}

/** The JSON of Go type organization.SlugRequest. */
export interface OrganizationSlugRequest {
  slug: string;
}

/** The JSON of Go type organization.SlugResult. */
export interface OrganizationSlugResult {
  slug: string;
  available: boolean;
}

/** The JSON of Go type organization.SuggestionsResult. */
export interface OrganizationSuggestionsResult {
  suggestions: OrganizationDomainSuggestion[] | null;
}

/** The JSON of Go type organization.Team. */
export interface OrganizationTeam {
  id: string;
  orgId: string;
  name: string;
  createdAt: string;
  updatedAt: string;
  memberCount: number;
  fields?: { [key: string]: unknown } | null;
}

/** The JSON of Go type organization.TeamMember. */
export interface OrganizationTeamMember {
  teamId: string;
  user: AuthUserView;
  createdAt: string;
}

/** The JSON of Go type organization.TeamMemberRequest. */
export interface OrganizationTeamMemberRequest {
  teamId: string;
  userId: string;
}

/** The JSON of Go type organization.TeamMembersResult. */
export interface OrganizationTeamMembersResult {
  members: OrganizationTeamMember[] | null;
}

/** The JSON of Go type organization.TeamRequest. */
export interface OrganizationTeamRequest {
  teamId: string;
}

/** The JSON of Go type organization.TeamUpdate. */
export interface OrganizationTeamUpdate {
  name?: string | null;
  fields?: { [key: string]: unknown } | null;
}

/** The JSON of Go type organization.TeamsResult. */
export interface OrganizationTeamsResult {
  teams: OrganizationTeam[] | null;
}

/** The JSON of Go type organization.UpdateDomainRequest. */
export interface OrganizationUpdateDomainRequest {
  domainId: string;
  enrollmentMode?: string | null;
  role?: string | null;
}

/** The JSON of Go type organization.UpdateRequest. */
export interface OrganizationUpdateRequest {
  orgId?: string;
  data: OrganizationOrgUpdate;
}

/** The JSON of Go type organization.UpdateRoleRequest. */
export interface OrganizationUpdateRoleRequest {
  orgId?: string;
  roleId?: string;
  roleName?: string;
  data: OrganizationRoleUpdate;
}

/** The JSON of Go type organization.UpdateTeamRequest. */
export interface OrganizationUpdateTeamRequest {
  teamId: string;
  data: OrganizationTeamUpdate;
}

/** The JSON of Go type passkey.BeginResult. */
export interface PasskeyBeginResult {
  ceremony: string;
  options: unknown;
}

/** The JSON of Go type passkey.FinishRequest. */
export interface PasskeyFinishRequest {
  ceremony: string;
  credential: unknown;
  name?: string;
}

/** The JSON of Go type passkey.ListResult. */
export interface PasskeyListResult {
  passkeys: PasskeyPasskey[] | null;
}

/** The JSON of Go type passkey.Passkey. */
export interface PasskeyPasskey {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
  aaguid: string;
  backedUp: boolean;
  transports: string[] | null;
  extensions?: unknown;
}

/** The JSON of Go type passkey.ReauthFinishRequest. */
export interface PasskeyReauthFinishRequest {
  ceremony: string;
  credential: unknown;
}

/** The JSON of Go type passkey.RegisterBeginRequest. */
export interface PasskeyRegisterBeginRequest {
  authenticatorAttachment?: string;
}

/** The JSON of Go type passkey.RemoveRequest. */
export interface PasskeyRemoveRequest {
  id: string;
}

/** The JSON of Go type passkey.RenameRequest. */
export interface PasskeyRenameRequest {
  id: string;
  name: string;
}

/** The JSON of Go type passkey.SignInResult. */
export interface PasskeySignInResult {
  user: AuthUserView;
  secondFactorRequired?: boolean;
  extensions?: unknown;
}

/** The JSON of Go type passkey.SignUpBeginRequest. */
export interface PasskeySignUpBeginRequest {
  identifier: string;
  name?: string;
  authenticatorAttachment?: string;
}

/** The JSON of Go type passkey.SignUpResult. */
export interface PasskeySignUpResult {
  user: AuthUserView;
  passkey: PasskeyPasskey;
  verificationRequired: boolean;
}

/** The JSON of Go type password.ChangeRequest. */
export interface PasswordChangeRequest {
  current: string;
  new: string;
  revokeOtherSessions?: boolean | null;
}

/** The JSON of Go type password.ForgotRequest. */
export interface PasswordForgotRequest {
  identifier: string;
  redirectTo?: string;
}

/** The JSON of Go type password.ForgotResult. */
export interface PasswordForgotResult {
  status: string;
}

/** The JSON of Go type password.ReauthenticateRequest. */
export interface PasswordReauthenticateRequest {
  password: string;
}

/** The JSON of Go type password.ResetRequest. */
export interface PasswordResetRequest {
  token: string;
  password: string;
}

/** The JSON of Go type password.SignInRequest. */
export interface PasswordSignInRequest {
  identifier: string;
  password: string;
  remember?: boolean | null;
}

/** The JSON of Go type password.SignInResult. */
export interface PasswordSignInResult {
  user: AuthUserView;
  verificationRequired: boolean;
  secondFactorRequired: boolean;
}

/** The JSON of Go type password.SignUpRequest. */
export interface PasswordSignUpRequest {
  identifier: string;
  password: string;
  name?: string;
  image?: string;
  remember?: boolean | null;
  username?: string;
  displayUsername?: string;
  fields?: { [key: string]: unknown } | null;
}

/** The JSON of Go type password.VerifyRequest. */
export interface PasswordVerifyRequest {
  password: string;
}

/** The JSON of Go type phone.ChangeResult. */
export interface PhoneChangeResult {
  phone: string;
}

/** The JSON of Go type phone.CodeRequest. */
export interface PhoneCodeRequest {
  phone: string;
  code: string;
}

/** The JSON of Go type phone.ListResult. */
export interface PhoneListResult {
  numbers: PhoneNumber[] | null;
}

/** The JSON of Go type phone.Number. */
export interface PhoneNumber {
  phone: string;
  verified: boolean;
  primary: boolean;
}

/** The JSON of Go type phone.NumberRequest. */
export interface PhoneNumberRequest {
  phone: string;
}

/** The JSON of Go type phone.SignInRequest. */
export interface PhoneSignInRequest {
  phone: string;
  code: string;
  fields?: { [key: string]: unknown } | null;
}

/** The JSON of Go type phone.SignInResult. */
export interface PhoneSignInResult {
  user: AuthUserView;
  created: boolean;
  secondFactorRequired: boolean;
}

/** The JSON of Go type pow.Challenge. */
export interface PowChallenge {
  challenge: string;
  difficulty: number;
  algorithm: string;
  expiresAt: string;
}

/** The JSON of Go type referral.CodeRequest. */
export interface ReferralCodeRequest {
  code: string;
}

/** The JSON of Go type referral.Dashboard. */
export interface ReferralDashboard {
  code: string;
  stats: ReferralStats;
}

/** The JSON of Go type referral.ListRequest. */
export interface ReferralListRequest {
  limit?: number;
  offset?: number;
}

/** The JSON of Go type referral.ListResult. */
export interface ReferralListResult {
  code: string;
  referrals: ReferralReferral[] | null;
  total: number;
  limit: number;
  offset: number;
}

/** The JSON of Go type referral.Progress. */
export interface ReferralProgress {
  requiredSteps: string[] | null;
  completedSteps: string[] | null;
  remainingSteps: string[] | null;
  completed: number;
  total: number;
  isCompleted: boolean;
}

/** The JSON of Go type referral.Referral. */
export interface ReferralReferral {
  id: string;
  status: string;
  completedAt: string | null;
  createdAt: string;
  progress: ReferralProgress;
  referredUser: ReferralReferredUser;
}

/** The JSON of Go type referral.ReferredUser. */
export interface ReferralReferredUser {
  id: string;
  name: string;
  email: string;
  image?: string;
}

/** The JSON of Go type referral.Stats. */
export interface ReferralStats {
  total: number;
  completed: number;
  pending: number;
  joinedToday: number;
}

/** The JSON of Go type siwe.LinkRequest. */
export interface SiweLinkRequest {
  message: string;
  signature: string;
}

/** The JSON of Go type siwe.NonceRequest. */
export interface SiweNonceRequest {
  walletAddress: string;
  chainId: number;
}

/** The JSON of Go type siwe.NonceResult. */
export interface SiweNonceResult {
  nonce: string;
}

/** The JSON of Go type siwe.SignInResult. */
export interface SiweSignInResult {
  user: AuthUserView;
  wallet: SiweWallet;
  created: boolean;
  secondFactorRequired: boolean;
}

/** The JSON of Go type siwe.UnlinkRequest. */
export interface SiweUnlinkRequest {
  id: string;
}

/** The JSON of Go type siwe.VerifyRequest. */
export interface SiweVerifyRequest {
  message: string;
  signature: string;
  walletAddress?: string;
  chainId?: number;
  email?: string;
}

/** The JSON of Go type siwe.Wallet. */
export interface SiweWallet {
  id: string;
  address: string;
  chainId: number;
  primary: boolean;
  createdAt: string;
  lastUsedAt?: string | null;
}

/** The JSON of Go type siwe.WalletsResult. */
export interface SiweWalletsResult {
  wallets: SiweWallet[] | null;
}

/** The JSON of Go type terms.AcceptRequest. */
export interface TermsAcceptRequest {
  version: string;
}

/** The JSON of Go type twofactor.CodeRequest. */
export interface TwofactorCodeRequest {
  code: string;
  trustDevice?: boolean;
  disableSession?: boolean;
  password?: string;
  method?: string;
  securityKey?: TwofactorSecurityKeyResponse | null;
}

/** The JSON of Go type twofactor.DevicesResult. */
export interface TwofactorDevicesResult {
  devices: TwofactorTrustedDevice[] | null;
}

/** The JSON of Go type twofactor.EnrollRequest. */
export interface TwofactorEnrollRequest {
  method?: string;
  issuer?: string;
  password?: string;
  proof?: TwofactorFactorProof | null;
}

/** The JSON of Go type twofactor.EnrollResult. */
export interface TwofactorEnrollResult {
  method: string;
  secret?: string;
  url?: string;
  enabled: boolean;
  recoveryCodes?: string[] | null;
}

/** The JSON of Go type twofactor.Factor. */
export interface TwofactorFactor {
  method: string;
  id?: string;
  name?: string;
  primary?: boolean;
  createdAt: string;
  lastUsedAt?: string | null;
}

/** The JSON of Go type twofactor.FactorProof. */
export interface TwofactorFactorProof {
  method?: string;
  code?: string;
  securityKey?: TwofactorSecurityKeyResponse | null;
}

/** The JSON of Go type twofactor.ForgetDeviceRequest. */
export interface TwofactorForgetDeviceRequest {
  id?: string;
  all?: boolean;
}

/** The JSON of Go type twofactor.PasswordRequest. */
export interface TwofactorPasswordRequest {
  password?: string;
}

/** The JSON of Go type twofactor.ReauthenticateRequest. */
export interface TwofactorReauthenticateRequest {
  code: string;
  ticket: string;
  method?: string;
  securityKey?: TwofactorSecurityKeyResponse | null;
}

/** The JSON of Go type twofactor.RecoveryCodes. */
export interface TwofactorRecoveryCodes {
  codes: string[] | null;
}

/** The JSON of Go type twofactor.RemoveFactorRequest. */
export interface TwofactorRemoveFactorRequest {
  method: string;
  id?: string;
  proof: TwofactorFactorProof;
  password?: string;
}

/** The JSON of Go type twofactor.RemoveFactorResult. */
export interface TwofactorRemoveFactorResult {
  enabled: boolean;
}

/** The JSON of Go type twofactor.SecurityKey. */
export interface TwofactorSecurityKey {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
  aaguid?: string;
  transports: string[] | null;
}

/** The JSON of Go type twofactor.SecurityKeyChallenge. */
export interface TwofactorSecurityKeyChallenge {
  ceremony: string;
  options: unknown;
}

/** The JSON of Go type twofactor.SecurityKeyRegisterBeginRequest. */
export interface TwofactorSecurityKeyRegisterBeginRequest {
  authenticatorAttachment?: string;
  password?: string;
}

/** The JSON of Go type twofactor.SecurityKeyRegisterFinishRequest. */
export interface TwofactorSecurityKeyRegisterFinishRequest {
  ceremony: string;
  credential: unknown;
  name?: string;
  proof?: TwofactorFactorProof | null;
}

/** The JSON of Go type twofactor.SecurityKeyRegistered. */
export interface TwofactorSecurityKeyRegistered {
  key: TwofactorSecurityKey;
  recoveryCodes: string[] | null;
}

/** The JSON of Go type twofactor.SecurityKeyResponse. */
export interface TwofactorSecurityKeyResponse {
  ceremony: string;
  credential: unknown;
}

/** The JSON of Go type twofactor.Status. */
export interface TwofactorStatus {
  enabled: boolean;
  method?: string;
  methods: string[] | null;
  trustDevices: boolean;
  factors: TwofactorFactor[] | null;
}

/** The JSON of Go type twofactor.TOTPURIResult. */
export interface TwofactorTOTPURIResult {
  totpURI: string;
}

/** The JSON of Go type twofactor.TrustedDevice. */
export interface TwofactorTrustedDevice {
  id: string;
  userAgent: string;
  createdAt: string;
  expiresAt: string;
  lastUsedAt: string | null;
  current: boolean;
}

/** The JSON of Go type username.Availability. */
export interface UsernameAvailability {
  available: boolean;
}

/** The JSON of Go type username.Request. */
export interface UsernameRequest {
  username: string;
  displayUsername?: string;
}

/** The JSON of Go type username.Result. */
export interface UsernameResult {
  username: string;
}

/** The operations of the core (sessions, profile, account); its methods sit on the client's root. */
export type CoreOps = {
  /** `POST /account/delete` (core.account-delete), requires fresh_sign_in. */
  readonly accountDelete: Op<EmptyInput, AuthDeleteAccountResult>;
  /** `POST /account/delete/confirm` (core.account-delete-confirm), requires public. */
  readonly accountDeleteConfirm: Op<AuthConfirmDeleteAccountRequest, AuthDone>;
  /** `GET /device-sessions` (core.device-sessions), requires signed_in. */
  readonly deviceSessions: Op<EmptyInput, AuthDeviceSessionsResult>;
  /** `POST /device-sessions/revoke` (core.device-sessions-revoke), requires signed_in. */
  readonly deviceSessionsRevoke: Op<AuthDeviceSessionRequest, AuthDone>;
  /** `POST /device-sessions/switch` (core.device-sessions-switch), requires signed_in. */
  readonly deviceSessionsSwitch: Op<AuthDeviceSessionRequest, AuthDone>;
  /** `POST /profile` (core.profile), requires signed_in. */
  readonly profile: Op<AuthProfileRequest, AuthUserView>;
  /** `GET /session` (core.session), requires signed_in. */
  readonly session: Op<EmptyInput, AuthSessionResult>;
  /** `POST /session/refresh` (core.session-refresh), requires signed_in. */
  readonly sessionRefresh: Op<EmptyInput, AuthSessionResult>;
  /** `GET /sessions` (core.sessions), requires signed_in. */
  readonly sessions: Op<EmptyInput, AuthSessionsResult>;
  /** `POST /sessions/revoke` (core.sessions-revoke), requires signed_in. */
  readonly sessionsRevoke: Op<AuthRevokeSessionRequest, AuthDone>;
  /** `POST /sign-out` (core.sign-out), requires signed_in. */
  readonly signOut: Op<EmptyInput, AuthDone>;
  /** `POST /sign-out-all` (core.sign-out-all), requires signed_in. */
  readonly signOutAll: Op<EmptyInput, AuthDone>;
};

/** The core's operation table, which every client has. */
export const coreOps: CoreOps = {
  accountDelete: { id: "core.account-delete", method: "POST", path: "/account/delete" },
  accountDeleteConfirm: { id: "core.account-delete-confirm", method: "POST", path: "/account/delete/confirm" },
  deviceSessions: { id: "core.device-sessions", method: "GET", path: "/device-sessions" },
  deviceSessionsRevoke: { id: "core.device-sessions-revoke", method: "POST", path: "/device-sessions/revoke" },
  deviceSessionsSwitch: { id: "core.device-sessions-switch", method: "POST", path: "/device-sessions/switch" },
  profile: { id: "core.profile", method: "POST", path: "/profile" },
  session: { id: "core.session", method: "GET", path: "/session" },
  sessionRefresh: { id: "core.session-refresh", method: "POST", path: "/session/refresh" },
  sessions: { id: "core.sessions", method: "GET", path: "/sessions" },
  sessionsRevoke: { id: "core.sessions-revoke", method: "POST", path: "/sessions/revoke" },
  signOut: { id: "core.sign-out", method: "POST", path: "/sign-out", endsSession: true },
  signOutAll: { id: "core.sign-out-all", method: "POST", path: "/sign-out-all", endsSession: true },
};

/**
 * Builds a client: the core's methods on the root, and one namespace per plugin in `options.plugins`.
 * A plugin left out has no namespace, so calling it is a compile error. E is the session extras'
 * type, inferred from `options.sessionExtras`.
 */
export function createAuthClient<const P extends readonly AnyPlugin[] = [], E = unknown>(options: ClientOptions<P, E>): AuthClient<CoreOps, P, E> {
  return createClient(coreOps, options);
}

/** The operations of the admin plugin. */
export type AdminOps = {
  /** `GET /admin/all-sessions` (admin.all-sessions), requires signed_in. */
  readonly allSessions: Op<AdminAllSessionsRequest, AdminAllSessionsResult>;
  /** `GET /admin/audit` (admin.audit), requires signed_in. */
  readonly audit: Op<AuditQuery, AuditPage>;
  /** `POST /admin/ban` (admin.ban), requires fresh_sign_in. */
  readonly ban: Op<AdminBanRequest, AuthDone>;
  /** `POST /admin/create-user` (admin.create-user), requires fresh_sign_in. */
  readonly createUser: Op<AdminCreateUserRequest, AdminCreateUserResult>;
  /** `POST /admin/disable-two-factor` (admin.disable-two-factor), requires fresh_sign_in. */
  readonly disableTwoFactor: Op<AdminUserRequest, AuthDone>;
  /** `POST /admin/enable-two-factor` (admin.enable-two-factor), requires fresh_sign_in. */
  readonly enableTwoFactor: Op<AdminUserRequest, AuthDone>;
  /** `POST /admin/has-permission` (admin.has-permission), requires signed_in. */
  readonly hasPermission: Op<AdminPermissionRequest, AdminPermissionResult>;
  /** `POST /admin/impersonate` (admin.impersonate), requires fresh_sign_in. */
  readonly impersonate: Op<AdminImpersonateRequest, AdminImpersonateResult>;
  /** `POST /admin/remove-user` (admin.remove-user), requires fresh_sign_in. */
  readonly removeUser: Op<AdminUserRequest, AuthDone>;
  /** `POST /admin/reset-two-factor` (admin.reset-two-factor), requires fresh_sign_in. */
  readonly resetTwoFactor: Op<AdminUserRequest, AuthDone>;
  /** `POST /admin/revoke-session` (admin.revoke-session), requires fresh_sign_in. */
  readonly revokeSession: Op<AdminRevokeSessionRequest, AuthDone>;
  /** `POST /admin/revoke-sessions` (admin.revoke-sessions), requires fresh_sign_in. */
  readonly revokeSessions: Op<AdminUserRequest, AuthDone>;
  /** `GET /admin/search-users` (admin.search-users), requires signed_in. */
  readonly searchUsers: Op<AdminSearchUsersRequest, AdminUsersResult>;
  /** `GET /admin/sessions` (admin.sessions), requires signed_in. */
  readonly sessions: Op<AdminUserRequest, AdminSessionsResult>;
  /** `POST /admin/set-admin` (admin.set-admin), requires fresh_sign_in. */
  readonly setAdmin: Op<AdminSetAdminRequest, AuthDone>;
  /** `POST /admin/set-email` (admin.set-email), requires fresh_sign_in. */
  readonly setEmail: Op<AdminSetEmailRequest, AuthDone>;
  /** `POST /admin/set-password` (admin.set-password), requires fresh_sign_in. */
  readonly setPassword: Op<AdminSetPasswordRequest, AuthDone>;
  /** `POST /admin/set-role` (admin.set-role), requires fresh_sign_in. */
  readonly setRole: Op<AdminSetRoleRequest, AuthDone>;
  /** `POST /admin/stop-impersonating` (admin.stop-impersonating), requires signed_in. */
  readonly stopImpersonating: Op<EmptyInput, AdminStopResult>;
  /** `GET /admin/two-factor` (admin.two-factor), requires signed_in. */
  readonly twoFactor: Op<AdminUserRequest, AdminTwoFactorResult>;
  /** `POST /admin/unban` (admin.unban), requires fresh_sign_in. */
  readonly unban: Op<AdminUserRequest, AuthDone>;
  /** `POST /admin/update-user` (admin.update-user), requires fresh_sign_in. */
  readonly updateUser: Op<AdminUpdateUserRequest, AuthDone>;
  /** `GET /admin/user` (admin.user), requires signed_in. */
  readonly user: Op<AdminUserRequest, AdminUserDetail>;
  /** `GET /admin/users` (admin.users), requires signed_in. */
  readonly users: Op<AdminUsersRequest, AdminUsersResult>;
};

/** Enables the admin plugin's methods as `client.admin`. */
export function admin(): Plugin<"admin", AdminOps> {
  return { name: "admin", ops: {
    allSessions: { id: "admin.all-sessions", method: "GET", path: "/admin/all-sessions" },
    audit: { id: "admin.audit", method: "GET", path: "/admin/audit" },
    ban: { id: "admin.ban", method: "POST", path: "/admin/ban" },
    createUser: { id: "admin.create-user", method: "POST", path: "/admin/create-user" },
    disableTwoFactor: { id: "admin.disable-two-factor", method: "POST", path: "/admin/disable-two-factor" },
    enableTwoFactor: { id: "admin.enable-two-factor", method: "POST", path: "/admin/enable-two-factor" },
    hasPermission: { id: "admin.has-permission", method: "POST", path: "/admin/has-permission" },
    impersonate: { id: "admin.impersonate", method: "POST", path: "/admin/impersonate" },
    removeUser: { id: "admin.remove-user", method: "POST", path: "/admin/remove-user" },
    resetTwoFactor: { id: "admin.reset-two-factor", method: "POST", path: "/admin/reset-two-factor" },
    revokeSession: { id: "admin.revoke-session", method: "POST", path: "/admin/revoke-session" },
    revokeSessions: { id: "admin.revoke-sessions", method: "POST", path: "/admin/revoke-sessions" },
    searchUsers: { id: "admin.search-users", method: "GET", path: "/admin/search-users" },
    sessions: { id: "admin.sessions", method: "GET", path: "/admin/sessions" },
    setAdmin: { id: "admin.set-admin", method: "POST", path: "/admin/set-admin" },
    setEmail: { id: "admin.set-email", method: "POST", path: "/admin/set-email" },
    setPassword: { id: "admin.set-password", method: "POST", path: "/admin/set-password" },
    setRole: { id: "admin.set-role", method: "POST", path: "/admin/set-role" },
    stopImpersonating: { id: "admin.stop-impersonating", method: "POST", path: "/admin/stop-impersonating" },
    twoFactor: { id: "admin.two-factor", method: "GET", path: "/admin/two-factor" },
    unban: { id: "admin.unban", method: "POST", path: "/admin/unban" },
    updateUser: { id: "admin.update-user", method: "POST", path: "/admin/update-user" },
    user: { id: "admin.user", method: "GET", path: "/admin/user" },
    users: { id: "admin.users", method: "GET", path: "/admin/users" },
  } };
}

/** The operations of the anonymous plugin. */
export type AnonymousOps = {
  /** `POST /anonymous/delete` (anonymous.delete), requires signed_in. */
  readonly delete: Op<EmptyInput, AuthDone>;
  /** `POST /anonymous/sign-in` (anonymous.sign-in), requires public. */
  readonly signIn: Op<AnonymousSignInRequest, AnonymousSignInResult>;
};

/** Enables the anonymous plugin's methods as `client.anonymous`. */
export function anonymous(): Plugin<"anonymous", AnonymousOps> {
  return { name: "anonymous", ops: {
    delete: { id: "anonymous.delete", method: "POST", path: "/anonymous/delete" },
    signIn: { id: "anonymous.sign-in", method: "POST", path: "/anonymous/sign-in", signIn: true },
  } };
}

/** The operations of the apikey plugin. */
export type ApikeyOps = {
  /** `POST /apikey/create` (apikey.create), requires fresh_sign_in. */
  readonly create: Op<ApikeyCreateRequest, ApikeyCreateResult>;
  /** `GET /apikey/get` (apikey.get), requires signed_in. */
  readonly get: Op<ApikeyGetRequest, ApikeyKey>;
  /** `GET /apikey/list` (apikey.list), requires signed_in. */
  readonly list: Op<ApikeyListRequest, ApikeyListResult>;
  /** `POST /apikey/revoke` (apikey.revoke), requires signed_in. */
  readonly revoke: Op<ApikeyRevokeRequest, AuthDone>;
  /** `POST /apikey/update` (apikey.update), requires fresh_sign_in. */
  readonly update: Op<ApikeyUpdateRequest, ApikeyKey>;
};

/** Enables the apikey plugin's methods as `client.apikey`. */
export function apikey(): Plugin<"apikey", ApikeyOps> {
  return { name: "apikey", ops: {
    create: { id: "apikey.create", method: "POST", path: "/apikey/create" },
    get: { id: "apikey.get", method: "GET", path: "/apikey/get" },
    list: { id: "apikey.list", method: "GET", path: "/apikey/list" },
    revoke: { id: "apikey.revoke", method: "POST", path: "/apikey/revoke" },
    update: { id: "apikey.update", method: "POST", path: "/apikey/update" },
  } };
}

/** The operations of the audit plugin. */
export type AuditOps = {
  /** `GET /audit/my-events` (audit.my-events), requires signed_in. */
  readonly myEvents: Op<AuditMyQuery, AuditPage>;
};

/** Enables the audit plugin's methods as `client.audit`. */
export function audit(): Plugin<"audit", AuditOps> {
  return { name: "audit", ops: {
    myEvents: { id: "audit.my-events", method: "GET", path: "/audit/my-events" },
  } };
}

/** The operations of the device plugin. */
export type DeviceOps = {
  /** `POST /device/approve` (device.approve), requires signed_in. */
  readonly approve: Op<DeviceauthDecisionRequest, DeviceauthDecisionResult>;
  /** `POST /device/code` (device.code), requires public. */
  readonly code: Op<DeviceauthCodeRequest, DeviceauthCodeResult>;
  /** `POST /device/deny` (device.deny), requires signed_in. */
  readonly deny: Op<DeviceauthDecisionRequest, DeviceauthDecisionResult>;
  /** `POST /device/token` (device.token), requires public. */
  readonly token: Op<DeviceauthTokenRequest, DeviceauthTokenResult>;
  /** `GET /device/verify` (device.verify), requires public. */
  readonly verify: Op<DeviceauthVerifyRequest, DeviceauthVerifyResult>;
};

/** Enables the device plugin's methods as `client.device`. */
export function device(): Plugin<"device", DeviceOps> {
  return { name: "device", ops: {
    approve: { id: "device.approve", method: "POST", path: "/device/approve" },
    code: { id: "device.code", method: "POST", path: "/device/code" },
    deny: { id: "device.deny", method: "POST", path: "/device/deny" },
    token: { id: "device.token", method: "POST", path: "/device/token", signIn: true },
    verify: { id: "device.verify", method: "GET", path: "/device/verify" },
  } };
}

/** The operations of the email plugin. */
export type EmailOps = {
  /** `POST /email/add` (email.add), requires signed_in. */
  readonly add: Op<EmailAddressRequest, AuthDone>;
  /** `POST /email/change` (email.change), requires fresh_sign_in. */
  readonly change: Op<EmailAddressRequest, AuthDone>;
  /** `POST /email/check-code` (email.check-code), requires public. */
  readonly checkCode: Op<EmailCheckCodeRequest, AuthDone>;
  /** `POST /email/confirm-change` (email.confirm-change), requires public. */
  readonly confirmChange: Op<EmailTokenRequest, EmailVerifyResult>;
  /** `POST /email/confirm-change-code` (email.confirm-change-code), requires signed_in. */
  readonly confirmChangeCode: Op<EmailAddressCodeRequest, EmailVerifyResult>;
  /** `GET /email/list` (email.list), requires signed_in. */
  readonly list: Op<EmptyInput, EmailListResult>;
  /** `POST /email/make-primary` (email.make-primary), requires fresh_sign_in. */
  readonly makePrimary: Op<EmailAddressRequest, AuthDone>;
  /** `POST /email/remove` (email.remove), requires fresh_sign_in. */
  readonly remove: Op<EmailAddressRequest, AuthDone>;
  /** `POST /email/resend` (email.resend), requires public. */
  readonly resend: Op<EmailAddressRequest, AuthDone>;
  /** `POST /email/send-code` (email.send-code), requires public. */
  readonly sendCode: Op<EmailAddressRequest, AuthDone>;
  /** `POST /email/sign-in-code` (email.sign-in-code), requires public. */
  readonly signInCode: Op<EmailCodeRequest, EmailCodeSignInResult>;
  /** `POST /email/undo-change` (email.undo-change), requires public. */
  readonly undoChange: Op<EmailTokenRequest, AuthDone>;
  /** `POST /email/verify` (email.verify), requires public. */
  readonly verify: Op<EmailTokenRequest, EmailVerifyResult>;
  /** `POST /email/verify-code` (email.verify-code), requires public. */
  readonly verifyCode: Op<EmailAddressCodeRequest, EmailVerifyResult>;
};

/** Enables the email plugin's methods as `client.email`. */
export function email(): Plugin<"email", EmailOps> {
  return { name: "email", ops: {
    add: { id: "email.add", method: "POST", path: "/email/add" },
    change: { id: "email.change", method: "POST", path: "/email/change" },
    checkCode: { id: "email.check-code", method: "POST", path: "/email/check-code" },
    confirmChange: { id: "email.confirm-change", method: "POST", path: "/email/confirm-change" },
    confirmChangeCode: { id: "email.confirm-change-code", method: "POST", path: "/email/confirm-change-code" },
    list: { id: "email.list", method: "GET", path: "/email/list" },
    makePrimary: { id: "email.make-primary", method: "POST", path: "/email/make-primary" },
    remove: { id: "email.remove", method: "POST", path: "/email/remove" },
    resend: { id: "email.resend", method: "POST", path: "/email/resend" },
    sendCode: { id: "email.send-code", method: "POST", path: "/email/send-code" },
    signInCode: { id: "email.sign-in-code", method: "POST", path: "/email/sign-in-code", signIn: true },
    undoChange: { id: "email.undo-change", method: "POST", path: "/email/undo-change" },
    verify: { id: "email.verify", method: "POST", path: "/email/verify" },
    verifyCode: { id: "email.verify-code", method: "POST", path: "/email/verify-code" },
  } };
}

/** The operations of the emailchallenge plugin. */
export type EmailchallengeOps = {
  /** `POST /emailchallenge/approve` (emailchallenge.approve), requires public. */
  readonly approve: Op<EmailchallengeStartOrToken, EmailchallengeResult>;
  /** `GET /emailchallenge/context` (emailchallenge.context), requires public. */
  readonly context: Op<EmailchallengeTokenRequest, EmailchallengeContextResult>;
  /** `POST /emailchallenge/poll` (emailchallenge.poll), requires public. */
  readonly poll: Op<EmailchallengeStartOrToken, EmailchallengeResult>;
  /** `POST /emailchallenge/start` (emailchallenge.start), requires public. */
  readonly start: Op<EmailchallengeStartOrToken, EmailchallengeResult>;
  /** `POST /emailchallenge/verify-otp` (emailchallenge.verify-otp), requires public. */
  readonly verifyOtp: Op<EmailchallengeStartOrToken, EmailchallengeResult>;
};

/** Enables the emailchallenge plugin's methods as `client.emailchallenge`. */
export function emailchallenge(): Plugin<"emailchallenge", EmailchallengeOps> {
  return { name: "emailchallenge", ops: {
    approve: { id: "emailchallenge.approve", method: "POST", path: "/emailchallenge/approve" },
    context: { id: "emailchallenge.context", method: "GET", path: "/emailchallenge/context" },
    poll: { id: "emailchallenge.poll", method: "POST", path: "/emailchallenge/poll" },
    start: { id: "emailchallenge.start", method: "POST", path: "/emailchallenge/start" },
    verifyOtp: { id: "emailchallenge.verify-otp", method: "POST", path: "/emailchallenge/verify-otp", signIn: true },
  } };
}

/** The operations of the handoff plugin. */
export type HandoffOps = {
  /** `POST /handoff/generate` (handoff.generate), requires signed_in. */
  readonly generate: Op<HandoffGenerateRequest, HandoffGenerateResult>;
  /** `POST /handoff/verify` (handoff.verify), requires public. */
  readonly verify: Op<HandoffVerifyRequest, HandoffVerifyResult>;
};

/** Enables the handoff plugin's methods as `client.handoff`. */
export function handoff(): Plugin<"handoff", HandoffOps> {
  return { name: "handoff", ops: {
    generate: { id: "handoff.generate", method: "POST", path: "/handoff/generate" },
    verify: { id: "handoff.verify", method: "POST", path: "/handoff/verify", signIn: true },
  } };
}

/** The operations of the invite plugin. */
export type InviteOps = {
  /** `POST /invite/activate` (invite.activate), requires public. */
  readonly activate: Op<InviteTokenRequest, InviteActivateResult>;
  /** `POST /invite/cancel` (invite.cancel), requires signed_in. */
  readonly cancel: Op<InviteIDRequest, AuthDone>;
  /** `POST /invite/create` (invite.create), requires signed_in. */
  readonly create: Op<InviteRequest, InviteCreated>;
  /** `GET /invite/get` (invite.get), requires public. */
  readonly get: Op<InviteTokenRequest, InviteView>;
  /** `GET /invite/list` (invite.list), requires signed_in. */
  readonly list: Op<InviteListRequest, InviteListResult>;
  /** `POST /invite/reject` (invite.reject), requires signed_in. */
  readonly reject: Op<InviteTokenRequest, AuthDone>;
};

/** Enables the invite plugin's methods as `client.invite`. */
export function invite(): Plugin<"invite", InviteOps> {
  return { name: "invite", ops: {
    activate: { id: "invite.activate", method: "POST", path: "/invite/activate" },
    cancel: { id: "invite.cancel", method: "POST", path: "/invite/cancel" },
    create: { id: "invite.create", method: "POST", path: "/invite/create" },
    get: { id: "invite.get", method: "GET", path: "/invite/get" },
    list: { id: "invite.list", method: "GET", path: "/invite/list" },
    reject: { id: "invite.reject", method: "POST", path: "/invite/reject" },
  } };
}

/** The operations of the jwt plugin. */
export type JwtOps = {
  /** `GET /jwt/jwks` (jwt.jwks), requires public. */
  readonly jwks: Op<EmptyInput, JwtJWKS>;
  /** `POST /jwt/template` (jwt.template), requires signed_in. */
  readonly template: Op<JwtTemplateRequest, JwtTokenResult>;
  /** `POST /jwt/token` (jwt.token), requires signed_in. */
  readonly token: Op<EmptyInput, JwtTokenResult>;
};

/** Enables the jwt plugin's methods as `client.jwt`. */
export function jwt(): Plugin<"jwt", JwtOps> {
  return { name: "jwt", ops: {
    jwks: { id: "jwt.jwks", method: "GET", path: "/jwt/jwks" },
    template: { id: "jwt.template", method: "POST", path: "/jwt/template" },
    token: { id: "jwt.token", method: "POST", path: "/jwt/token" },
  } };
}

/** The operations of the ldap plugin. */
export type LdapOps = {
  /** `POST /ldap/sign-in` (ldap.sign-in), requires public. */
  readonly signIn: Op<LdapSignInRequest, LdapSignInResult>;
};

/** Enables the ldap plugin's methods as `client.ldap`. */
export function ldap(): Plugin<"ldap", LdapOps> {
  return { name: "ldap", ops: {
    signIn: { id: "ldap.sign-in", method: "POST", path: "/ldap/sign-in", signIn: true },
  } };
}

/** The operations of the magiclink plugin. */
export type MagiclinkOps = {
  /** `POST /magiclink/send` (magiclink.send), requires public. */
  readonly send: Op<MagiclinkSendRequest, AuthDone>;
  /** `POST /magiclink/sign-in` (magiclink.sign-in), requires public. */
  readonly signIn: Op<MagiclinkSignInRequest, MagiclinkSignInResult>;
};

/** Enables the magiclink plugin's methods as `client.magiclink`. */
export function magiclink(): Plugin<"magiclink", MagiclinkOps> {
  return { name: "magiclink", ops: {
    send: { id: "magiclink.send", method: "POST", path: "/magiclink/send" },
    signIn: { id: "magiclink.sign-in", method: "POST", path: "/magiclink/sign-in", signIn: true },
  } };
}

/** The operations of the metadata plugin. */
export type MetadataOps = {
  /** `GET /metadata/admin-get` (metadata.admin-get), requires signed_in. */
  readonly adminGet: Op<MetadataAdminGetRequest, MetadataMetadata>;
  /** `POST /metadata/admin-update` (metadata.admin-update), requires fresh_sign_in. */
  readonly adminUpdate: Op<MetadataAdminUpdateRequest, MetadataMetadata>;
  /** `GET /metadata/get` (metadata.get), requires signed_in. */
  readonly get: Op<EmptyInput, MetadataUserMetadata>;
  /** `POST /metadata/update` (metadata.update), requires signed_in. */
  readonly update: Op<MetadataUpdateRequest, MetadataUserMetadata>;
};

/** Enables the metadata plugin's methods as `client.metadata`. */
export function metadata(): Plugin<"metadata", MetadataOps> {
  return { name: "metadata", ops: {
    adminGet: { id: "metadata.admin-get", method: "GET", path: "/metadata/admin-get" },
    adminUpdate: { id: "metadata.admin-update", method: "POST", path: "/metadata/admin-update" },
    get: { id: "metadata.get", method: "GET", path: "/metadata/get" },
    update: { id: "metadata.update", method: "POST", path: "/metadata/update" },
  } };
}

/** The operations of the oauth plugin. */
export type OauthOps = {
  /** `POST /oauth/access-token` (oauth.access_token), requires signed_in. */
  readonly accessToken: Op<OauthAccessTokenRequest, OauthAccessTokenResult>;
  /** `GET /oauth/accounts` (oauth.accounts), requires signed_in. */
  readonly accounts: Op<EmptyInput, OauthAccountsResult>;
  /** `GET /oauth/github/callback` (oauth.github-callback), requires public. */
  readonly githubCallback: Op<OauthCallbackRequest, OauthCallbackResult>;
  /** `POST /oauth/github/id-token` (oauth.github-id-token), requires public. */
  readonly githubIdToken: Op<OauthIDTokenRequest, OauthCallbackResult>;
  /** `POST /oauth/github/logout` (oauth.github-logout), requires signed_in. */
  readonly githubLogout: Op<OauthLogoutRequest, OauthLogoutResult>;
  /** `GET /oauth/github/start` (oauth.github-start), requires public. */
  readonly githubStart: Op<OauthStartRequest, OauthStartResult>;
  /** `GET /oauth/google/callback` (oauth.google-callback), requires public. */
  readonly googleCallback: Op<OauthCallbackRequest, OauthCallbackResult>;
  /** `POST /oauth/google/id-token` (oauth.google-id-token), requires public. */
  readonly googleIdToken: Op<OauthIDTokenRequest, OauthCallbackResult>;
  /** `POST /oauth/google/logout` (oauth.google-logout), requires signed_in. */
  readonly googleLogout: Op<OauthLogoutRequest, OauthLogoutResult>;
  /** `GET /oauth/google/start` (oauth.google-start), requires public. */
  readonly googleStart: Op<OauthStartRequest, OauthStartResult>;
  /** `POST /oauth/logout` (oauth.logout), requires signed_in. */
  readonly logout: Op<OauthLogoutRequest, OauthLogoutResult>;
  /** `GET /oauth/providers` (oauth.providers), requires public. */
  readonly providers: Op<EmptyInput, OauthProvidersResult>;
  /** `POST /oauth/reauthenticate` (oauth.reauthenticate), requires signed_in. */
  readonly reauthenticate: Op<OauthReauthenticateRequest, OauthStartResult>;
  /** `POST /oauth/reauthenticate-id-token` (oauth.reauthenticate-id-token), requires signed_in. */
  readonly reauthenticateIdToken: Op<OauthReauthenticateIDTokenRequest, AuthReauthentication>;
  /** `POST /oauth/unlink` (oauth.unlink), requires fresh_sign_in. */
  readonly unlink: Op<OauthUnlinkRequest, AuthDone>;
};

/** Enables the oauth plugin's methods as `client.oauth`. */
export function oauth(): Plugin<"oauth", OauthOps> {
  return { name: "oauth", ops: {
    accessToken: { id: "oauth.access_token", method: "POST", path: "/oauth/access-token" },
    accounts: { id: "oauth.accounts", method: "GET", path: "/oauth/accounts" },
    githubCallback: { id: "oauth.github-callback", method: "GET", path: "/oauth/github/callback", signIn: true },
    githubIdToken: { id: "oauth.github-id-token", method: "POST", path: "/oauth/github/id-token", signIn: true },
    githubLogout: { id: "oauth.github-logout", method: "POST", path: "/oauth/github/logout" },
    githubStart: { id: "oauth.github-start", method: "GET", path: "/oauth/github/start" },
    googleCallback: { id: "oauth.google-callback", method: "GET", path: "/oauth/google/callback", signIn: true },
    googleIdToken: { id: "oauth.google-id-token", method: "POST", path: "/oauth/google/id-token", signIn: true },
    googleLogout: { id: "oauth.google-logout", method: "POST", path: "/oauth/google/logout" },
    googleStart: { id: "oauth.google-start", method: "GET", path: "/oauth/google/start" },
    logout: { id: "oauth.logout", method: "POST", path: "/oauth/logout" },
    providers: { id: "oauth.providers", method: "GET", path: "/oauth/providers" },
    reauthenticate: { id: "oauth.reauthenticate", method: "POST", path: "/oauth/reauthenticate" },
    reauthenticateIdToken: { id: "oauth.reauthenticate-id-token", method: "POST", path: "/oauth/reauthenticate-id-token" },
    unlink: { id: "oauth.unlink", method: "POST", path: "/oauth/unlink" },
  } };
}

/** The operations of the oauthprovider plugin. */
export type OauthproviderOps = {
  /** `POST /oauthprovider/consent` (oauthprovider.consent), requires signed_in. */
  readonly consent: Op<Fill<OauthproviderConsentRequest, "oauth_query">, OauthproviderAuthorizeResult>;
  /** `POST /oauthprovider/continue` (oauthprovider.continue), requires signed_in. */
  readonly continue: Op<Fill<OauthproviderContinueRequest, "oauth_query">, OauthproviderAuthorizeResult>;
  /** `POST /oauthprovider/create-client` (oauthprovider.create_client), requires fresh_sign_in. */
  readonly createClient: Op<OauthproviderClientMetadata, OauthproviderRegistration>;
  /** `POST /oauthprovider/delete-client` (oauthprovider.delete_client), requires signed_in. */
  readonly deleteClient: Op<OauthproviderClientIDRequest, AuthDone>;
  /** `GET /oauthprovider/client` (oauthprovider.get_client), requires signed_in. */
  readonly getClient: Op<OauthproviderClientIDRequest, OauthproviderClient>;
  /** `GET /oauthprovider/get-consent` (oauthprovider.get_consent), requires signed_in. */
  readonly getConsent: Op<OauthproviderConsentIDRequest, OauthproviderConsent>;
  /** `GET /oauthprovider/clients` (oauthprovider.list_clients), requires signed_in. */
  readonly listClients: Op<EmptyInput, OauthproviderClientList>;
  /** `GET /oauthprovider/consents` (oauthprovider.list_consents), requires signed_in. */
  readonly listConsents: Op<EmptyInput, OauthproviderConsentList>;
  /** `GET /oauthprovider/public-client` (oauthprovider.public_client), requires signed_in. */
  readonly publicClient: Op<OauthproviderClientIDRequest, OauthproviderPublicClient>;
  /** `POST /oauthprovider/public-client-prelogin` (oauthprovider.public_client_prelogin), requires public. */
  readonly publicClientPrelogin: Op<Fill<OauthproviderPreloginRequest, "oauth_query">, OauthproviderPublicClient>;
  /** `POST /oauthprovider/revoke-consent` (oauthprovider.revoke_consent), requires signed_in. */
  readonly revokeConsent: Op<OauthproviderClientIDRequest, AuthDone>;
  /** `POST /oauthprovider/rotate-secret` (oauthprovider.rotate_secret), requires fresh_sign_in. */
  readonly rotateSecret: Op<OauthproviderClientIDRequest, OauthproviderRegistration>;
  /** `POST /oauthprovider/update-client` (oauthprovider.update_client), requires fresh_sign_in. */
  readonly updateClient: Op<OauthproviderUpdateClientRequest, OauthproviderClient>;
  /** `POST /oauthprovider/update-consent` (oauthprovider.update_consent), requires signed_in. */
  readonly updateConsent: Op<OauthproviderUpdateConsentRequest, OauthproviderConsent>;
};

/** Enables the oauthprovider plugin's methods as `client.oauthprovider`. */
export function oauthprovider(): Plugin<"oauthprovider", OauthproviderOps> {
  return { name: "oauthprovider", ops: {
    consent: { id: "oauthprovider.consent", method: "POST", path: "/oauthprovider/consent", fill: { oauth_query: "oauthQuery" } },
    continue: { id: "oauthprovider.continue", method: "POST", path: "/oauthprovider/continue", fill: { oauth_query: "oauthQuery" } },
    createClient: { id: "oauthprovider.create_client", method: "POST", path: "/oauthprovider/create-client" },
    deleteClient: { id: "oauthprovider.delete_client", method: "POST", path: "/oauthprovider/delete-client" },
    getClient: { id: "oauthprovider.get_client", method: "GET", path: "/oauthprovider/client" },
    getConsent: { id: "oauthprovider.get_consent", method: "GET", path: "/oauthprovider/get-consent" },
    listClients: { id: "oauthprovider.list_clients", method: "GET", path: "/oauthprovider/clients" },
    listConsents: { id: "oauthprovider.list_consents", method: "GET", path: "/oauthprovider/consents" },
    publicClient: { id: "oauthprovider.public_client", method: "GET", path: "/oauthprovider/public-client" },
    publicClientPrelogin: { id: "oauthprovider.public_client_prelogin", method: "POST", path: "/oauthprovider/public-client-prelogin", fill: { oauth_query: "oauthQuery" } },
    revokeConsent: { id: "oauthprovider.revoke_consent", method: "POST", path: "/oauthprovider/revoke-consent" },
    rotateSecret: { id: "oauthprovider.rotate_secret", method: "POST", path: "/oauthprovider/rotate-secret" },
    updateClient: { id: "oauthprovider.update_client", method: "POST", path: "/oauthprovider/update-client" },
    updateConsent: { id: "oauthprovider.update_consent", method: "POST", path: "/oauthprovider/update-consent" },
  } };
}

/** The operations of the organization plugin. */
export type OrganizationOps = {
  /** `POST /organization/accept` (organization.accept), requires signed_in. */
  readonly accept: Op<OrganizationAcceptRequest, OrganizationOrg>;
  /** `POST /organization/accept-suggestion` (organization.accept-suggestion), requires signed_in. */
  readonly acceptSuggestion: Op<OrganizationDomainRequest, OrganizationMembershipRequest>;
  /** `GET /organization/active` (organization.active), requires signed_in. */
  readonly active: Op<EmptyInput, OrganizationActiveResult>;
  /** `POST /organization/add-domain` (organization.add-domain), requires signed_in. */
  readonly addDomain: Op<OrganizationAddDomainRequest, OrganizationOrgDomain>;
  /** `POST /organization/add-team-member` (organization.add-team-member), requires signed_in. */
  readonly addTeamMember: Op<OrganizationTeamMemberRequest, AuthDone>;
  /** `POST /organization/approve-membership-request` (organization.approve-membership-request), requires signed_in. */
  readonly approveMembershipRequest: Op<OrganizationRequestIDRequest, AuthDone>;
  /** `POST /organization/cancel-invitation` (organization.cancel), requires signed_in. */
  readonly cancel: Op<OrganizationAcceptRequest, AuthDone>;
  /** `GET /organization/check-slug` (organization.check-slug), requires signed_in. */
  readonly checkSlug: Op<OrganizationSlugRequest, OrganizationSlugResult>;
  /** `POST /organization/create` (organization.create), requires signed_in. */
  readonly create: Op<OrganizationCreateRequest, OrganizationOrg>;
  /** `POST /organization/create-role` (organization.create-role), requires signed_in. */
  readonly createRole: Op<OrganizationCreateRoleRequest, OrganizationOrgRole>;
  /** `POST /organization/create-team` (organization.create-team), requires signed_in. */
  readonly createTeam: Op<OrganizationCreateTeamRequest, OrganizationTeam>;
  /** `POST /organization/delete` (organization.delete), requires signed_in. */
  readonly delete: Op<OrganizationOrgRequest, AuthDone>;
  /** `POST /organization/delete-role` (organization.delete-role), requires signed_in. */
  readonly deleteRole: Op<OrganizationRoleRequest, AuthDone>;
  /** `GET /organization/domain-suggestions` (organization.domain-suggestions), requires signed_in. */
  readonly domainSuggestions: Op<EmptyInput, OrganizationSuggestionsResult>;
  /** `GET /organization/get-organization` (organization.get), requires signed_in. */
  readonly get: Op<OrganizationGetRequest, OrganizationOrg>;
  /** `GET /organization/get-full-organization` (organization.get-full), requires signed_in. */
  readonly getFull: Op<OrganizationGetRequest, OrganizationFullOrg>;
  /** `GET /organization/get-role` (organization.get-role), requires signed_in. */
  readonly getRole: Op<OrganizationRoleRequest, OrganizationOrgRole>;
  /** `POST /organization/has-permission` (organization.has-permission), requires signed_in. */
  readonly hasPermission: Op<OrganizationPermissionRequest, OrganizationPermissionResult>;
  /** `GET /organization/invite` (organization.invitation), requires signed_in. */
  readonly invitation: Op<OrganizationAcceptRequest, OrganizationInvite>;
  /** `POST /organization/invite` (organization.invite), requires signed_in. */
  readonly invite: Op<OrganizationInviteRequest, AuthDone>;
  /** `GET /organization/invites` (organization.invites), requires signed_in. */
  readonly invites: Op<EmptyInput, OrganizationInvitesResult>;
  /** `GET /organization/list` (organization.list), requires signed_in. */
  readonly list: Op<EmptyInput, OrganizationListResult>;
  /** `GET /organization/list-domains` (organization.list-domains), requires signed_in. */
  readonly listDomains: Op<OrganizationDomainsRequest, OrganizationDomainsResult>;
  /** `GET /organization/list-invitations` (organization.list-invitations), requires signed_in. */
  readonly listInvitations: Op<OrganizationOrgRequest, OrganizationInvitationsResult>;
  /** `GET /organization/list-membership-requests` (organization.list-membership-requests), requires signed_in. */
  readonly listMembershipRequests: Op<OrganizationDomainsRequest, OrganizationMembershipRequestsResult>;
  /** `GET /organization/list-roles` (organization.list-roles), requires signed_in. */
  readonly listRoles: Op<OrganizationOrgRequest, OrganizationRolesResult>;
  /** `GET /organization/list-team-members` (organization.list-team-members), requires signed_in. */
  readonly listTeamMembers: Op<OrganizationTeamRequest, OrganizationTeamMembersResult>;
  /** `GET /organization/list-teams` (organization.list-teams), requires signed_in. */
  readonly listTeams: Op<OrganizationOrgRequest, OrganizationTeamsResult>;
  /** `GET /organization/list-user-teams` (organization.list-user-teams), requires signed_in. */
  readonly listUserTeams: Op<EmptyInput, OrganizationTeamsResult>;
  /** `GET /organization/members` (organization.members), requires signed_in. */
  readonly members: Op<OrganizationOrgRequest, OrganizationMembersResult>;
  /** `POST /organization/reject-invitation` (organization.reject), requires signed_in. */
  readonly reject: Op<OrganizationAcceptRequest, AuthDone>;
  /** `POST /organization/reject-membership-request` (organization.reject-membership-request), requires signed_in. */
  readonly rejectMembershipRequest: Op<OrganizationRequestIDRequest, AuthDone>;
  /** `POST /organization/remove-domain` (organization.remove-domain), requires signed_in. */
  readonly removeDomain: Op<OrganizationDomainRequest, AuthDone>;
  /** `POST /organization/remove-member` (organization.remove-member), requires signed_in. */
  readonly removeMember: Op<OrganizationMemberRequest, AuthDone>;
  /** `POST /organization/remove-team` (organization.remove-team), requires signed_in. */
  readonly removeTeam: Op<OrganizationTeamRequest, AuthDone>;
  /** `POST /organization/remove-team-member` (organization.remove-team-member), requires signed_in. */
  readonly removeTeamMember: Op<OrganizationTeamMemberRequest, AuthDone>;
  /** `GET /organization/role` (organization.role), requires signed_in. */
  readonly role: Op<OrganizationOrgRequest, OrganizationRoleResult>;
  /** `POST /organization/set-active` (organization.set-active), requires signed_in. */
  readonly setActive: Op<OrganizationSetActiveRequest, OrganizationActiveResult>;
  /** `POST /organization/set-active-team` (organization.set-active-team), requires signed_in. */
  readonly setActiveTeam: Op<OrganizationTeamRequest, OrganizationActiveResult>;
  /** `POST /organization/set-role` (organization.set-role), requires signed_in. */
  readonly setRole: Op<OrganizationSetRoleRequest, AuthDone>;
  /** `POST /organization/update` (organization.update), requires signed_in. */
  readonly update: Op<OrganizationUpdateRequest, OrganizationOrg>;
  /** `POST /organization/update-domain` (organization.update-domain), requires signed_in. */
  readonly updateDomain: Op<OrganizationUpdateDomainRequest, OrganizationOrgDomain>;
  /** `POST /organization/update-role` (organization.update-role), requires signed_in. */
  readonly updateRole: Op<OrganizationUpdateRoleRequest, OrganizationOrgRole>;
  /** `POST /organization/update-team` (organization.update-team), requires signed_in. */
  readonly updateTeam: Op<OrganizationUpdateTeamRequest, OrganizationTeam>;
  /** `POST /organization/verify-domain` (organization.verify-domain), requires signed_in. */
  readonly verifyDomain: Op<OrganizationDomainRequest, OrganizationOrgDomain>;
};

/** Enables the organization plugin's methods as `client.organization`. */
export function organization(): Plugin<"organization", OrganizationOps> {
  return { name: "organization", ops: {
    accept: { id: "organization.accept", method: "POST", path: "/organization/accept" },
    acceptSuggestion: { id: "organization.accept-suggestion", method: "POST", path: "/organization/accept-suggestion" },
    active: { id: "organization.active", method: "GET", path: "/organization/active" },
    addDomain: { id: "organization.add-domain", method: "POST", path: "/organization/add-domain" },
    addTeamMember: { id: "organization.add-team-member", method: "POST", path: "/organization/add-team-member" },
    approveMembershipRequest: { id: "organization.approve-membership-request", method: "POST", path: "/organization/approve-membership-request" },
    cancel: { id: "organization.cancel", method: "POST", path: "/organization/cancel-invitation" },
    checkSlug: { id: "organization.check-slug", method: "GET", path: "/organization/check-slug" },
    create: { id: "organization.create", method: "POST", path: "/organization/create" },
    createRole: { id: "organization.create-role", method: "POST", path: "/organization/create-role" },
    createTeam: { id: "organization.create-team", method: "POST", path: "/organization/create-team" },
    delete: { id: "organization.delete", method: "POST", path: "/organization/delete" },
    deleteRole: { id: "organization.delete-role", method: "POST", path: "/organization/delete-role" },
    domainSuggestions: { id: "organization.domain-suggestions", method: "GET", path: "/organization/domain-suggestions" },
    get: { id: "organization.get", method: "GET", path: "/organization/get-organization" },
    getFull: { id: "organization.get-full", method: "GET", path: "/organization/get-full-organization" },
    getRole: { id: "organization.get-role", method: "GET", path: "/organization/get-role" },
    hasPermission: { id: "organization.has-permission", method: "POST", path: "/organization/has-permission" },
    invitation: { id: "organization.invitation", method: "GET", path: "/organization/invite" },
    invite: { id: "organization.invite", method: "POST", path: "/organization/invite" },
    invites: { id: "organization.invites", method: "GET", path: "/organization/invites" },
    list: { id: "organization.list", method: "GET", path: "/organization/list" },
    listDomains: { id: "organization.list-domains", method: "GET", path: "/organization/list-domains" },
    listInvitations: { id: "organization.list-invitations", method: "GET", path: "/organization/list-invitations" },
    listMembershipRequests: { id: "organization.list-membership-requests", method: "GET", path: "/organization/list-membership-requests" },
    listRoles: { id: "organization.list-roles", method: "GET", path: "/organization/list-roles" },
    listTeamMembers: { id: "organization.list-team-members", method: "GET", path: "/organization/list-team-members" },
    listTeams: { id: "organization.list-teams", method: "GET", path: "/organization/list-teams" },
    listUserTeams: { id: "organization.list-user-teams", method: "GET", path: "/organization/list-user-teams" },
    members: { id: "organization.members", method: "GET", path: "/organization/members" },
    reject: { id: "organization.reject", method: "POST", path: "/organization/reject-invitation" },
    rejectMembershipRequest: { id: "organization.reject-membership-request", method: "POST", path: "/organization/reject-membership-request" },
    removeDomain: { id: "organization.remove-domain", method: "POST", path: "/organization/remove-domain" },
    removeMember: { id: "organization.remove-member", method: "POST", path: "/organization/remove-member" },
    removeTeam: { id: "organization.remove-team", method: "POST", path: "/organization/remove-team" },
    removeTeamMember: { id: "organization.remove-team-member", method: "POST", path: "/organization/remove-team-member" },
    role: { id: "organization.role", method: "GET", path: "/organization/role" },
    setActive: { id: "organization.set-active", method: "POST", path: "/organization/set-active" },
    setActiveTeam: { id: "organization.set-active-team", method: "POST", path: "/organization/set-active-team" },
    setRole: { id: "organization.set-role", method: "POST", path: "/organization/set-role" },
    update: { id: "organization.update", method: "POST", path: "/organization/update" },
    updateDomain: { id: "organization.update-domain", method: "POST", path: "/organization/update-domain" },
    updateRole: { id: "organization.update-role", method: "POST", path: "/organization/update-role" },
    updateTeam: { id: "organization.update-team", method: "POST", path: "/organization/update-team" },
    verifyDomain: { id: "organization.verify-domain", method: "POST", path: "/organization/verify-domain" },
  } };
}

/** The operations of the passkey plugin. */
export type PasskeyOps = {
  /** `GET /passkey/list` (passkey.list), requires signed_in. */
  readonly list: Op<EmptyInput, PasskeyListResult>;
  /** `POST /passkey/login-begin` (passkey.login-begin), requires public. */
  readonly loginBegin: Op<EmptyInput, PasskeyBeginResult>;
  /** `POST /passkey/login-finish` (passkey.login-finish), requires public. */
  readonly loginFinish: Op<PasskeyFinishRequest, PasskeySignInResult>;
  /** `POST /passkey/reauthenticate-begin` (passkey.reauthenticate-begin), requires signed_in. */
  readonly reauthenticateBegin: Op<EmptyInput, PasskeyBeginResult>;
  /** `POST /passkey/reauthenticate-finish` (passkey.reauthenticate-finish), requires signed_in. */
  readonly reauthenticateFinish: Op<PasskeyReauthFinishRequest, AuthReauthentication>;
  /** `POST /passkey/register-begin` (passkey.register-begin), requires fresh_sign_in. */
  readonly registerBegin: Op<PasskeyRegisterBeginRequest, PasskeyBeginResult>;
  /** `POST /passkey/register-finish` (passkey.register-finish), requires fresh_sign_in. */
  readonly registerFinish: Op<PasskeyFinishRequest, PasskeyPasskey>;
  /** `POST /passkey/remove` (passkey.remove), requires fresh_sign_in. */
  readonly remove: Op<PasskeyRemoveRequest, AuthDone>;
  /** `POST /passkey/rename` (passkey.rename), requires signed_in. */
  readonly rename: Op<PasskeyRenameRequest, AuthDone>;
  /** `POST /passkey/sign-up-begin` (passkey.sign-up-begin), requires public. */
  readonly signUpBegin: Op<PasskeySignUpBeginRequest, PasskeyBeginResult>;
  /** `POST /passkey/sign-up-finish` (passkey.sign-up-finish), requires public. */
  readonly signUpFinish: Op<PasskeyFinishRequest, PasskeySignUpResult>;
};

/** Enables the passkey plugin's methods as `client.passkey`. */
export function passkey(): Plugin<"passkey", PasskeyOps> {
  return { name: "passkey", ops: {
    list: { id: "passkey.list", method: "GET", path: "/passkey/list" },
    loginBegin: { id: "passkey.login-begin", method: "POST", path: "/passkey/login-begin" },
    loginFinish: { id: "passkey.login-finish", method: "POST", path: "/passkey/login-finish", signIn: true },
    reauthenticateBegin: { id: "passkey.reauthenticate-begin", method: "POST", path: "/passkey/reauthenticate-begin" },
    reauthenticateFinish: { id: "passkey.reauthenticate-finish", method: "POST", path: "/passkey/reauthenticate-finish" },
    registerBegin: { id: "passkey.register-begin", method: "POST", path: "/passkey/register-begin" },
    registerFinish: { id: "passkey.register-finish", method: "POST", path: "/passkey/register-finish" },
    remove: { id: "passkey.remove", method: "POST", path: "/passkey/remove" },
    rename: { id: "passkey.rename", method: "POST", path: "/passkey/rename" },
    signUpBegin: { id: "passkey.sign-up-begin", method: "POST", path: "/passkey/sign-up-begin" },
    signUpFinish: { id: "passkey.sign-up-finish", method: "POST", path: "/passkey/sign-up-finish" },
  } };
}

/** The operations of the password plugin. */
export type PasswordOps = {
  /** `POST /password/change` (password.change), requires fresh_sign_in. */
  readonly change: Op<PasswordChangeRequest, AuthDone>;
  /** `POST /password/forgot` (password.forgot), requires public. */
  readonly forgot: Op<PasswordForgotRequest, PasswordForgotResult>;
  /** `POST /password/reauthenticate` (password.reauthenticate), requires signed_in. */
  readonly reauthenticate: Op<PasswordReauthenticateRequest, AuthReauthentication>;
  /** `POST /password/reset` (password.reset), requires public. */
  readonly reset: Op<PasswordResetRequest, AuthDone>;
  /** `POST /password/sign-in` (password.sign-in), requires public. */
  readonly signIn: Op<PasswordSignInRequest, PasswordSignInResult>;
  /** `POST /password/sign-up` (password.sign-up), requires public. */
  readonly signUp: Op<PasswordSignUpRequest, PasswordSignInResult>;
  /** `POST /password/verify` (password.verify), requires signed_in. */
  readonly verify: Op<PasswordVerifyRequest, AuthDone>;
};

/** Enables the password plugin's methods as `client.password`. */
export function password(): Plugin<"password", PasswordOps> {
  return { name: "password", ops: {
    change: { id: "password.change", method: "POST", path: "/password/change" },
    forgot: { id: "password.forgot", method: "POST", path: "/password/forgot" },
    reauthenticate: { id: "password.reauthenticate", method: "POST", path: "/password/reauthenticate" },
    reset: { id: "password.reset", method: "POST", path: "/password/reset" },
    signIn: { id: "password.sign-in", method: "POST", path: "/password/sign-in", signIn: true },
    signUp: { id: "password.sign-up", method: "POST", path: "/password/sign-up" },
    verify: { id: "password.verify", method: "POST", path: "/password/verify" },
  } };
}

/** The operations of the phone plugin. */
export type PhoneOps = {
  /** `POST /phone/add` (phone.add), requires signed_in. */
  readonly add: Op<PhoneNumberRequest, AuthDone>;
  /** `POST /phone/change` (phone.change), requires fresh_sign_in. */
  readonly change: Op<PhoneNumberRequest, AuthDone>;
  /** `POST /phone/confirm-change` (phone.confirm-change), requires signed_in. */
  readonly confirmChange: Op<PhoneCodeRequest, PhoneChangeResult>;
  /** `GET /phone/list` (phone.list), requires signed_in. */
  readonly list: Op<EmptyInput, PhoneListResult>;
  /** `POST /phone/make-primary` (phone.make-primary), requires fresh_sign_in. */
  readonly makePrimary: Op<PhoneNumberRequest, AuthDone>;
  /** `POST /phone/remove` (phone.remove), requires fresh_sign_in. */
  readonly remove: Op<PhoneNumberRequest, AuthDone>;
  /** `POST /phone/resend` (phone.resend), requires signed_in. */
  readonly resend: Op<PhoneNumberRequest, AuthDone>;
  /** `POST /phone/send-code` (phone.send-code), requires public. */
  readonly sendCode: Op<PhoneNumberRequest, AuthDone>;
  /** `POST /phone/sign-in` (phone.sign-in), requires public. */
  readonly signIn: Op<PhoneSignInRequest, PhoneSignInResult>;
  /** `POST /phone/verify` (phone.verify), requires signed_in. */
  readonly verify: Op<PhoneCodeRequest, AuthDone>;
};

/** Enables the phone plugin's methods as `client.phone`. */
export function phone(): Plugin<"phone", PhoneOps> {
  return { name: "phone", ops: {
    add: { id: "phone.add", method: "POST", path: "/phone/add" },
    change: { id: "phone.change", method: "POST", path: "/phone/change" },
    confirmChange: { id: "phone.confirm-change", method: "POST", path: "/phone/confirm-change" },
    list: { id: "phone.list", method: "GET", path: "/phone/list" },
    makePrimary: { id: "phone.make-primary", method: "POST", path: "/phone/make-primary" },
    remove: { id: "phone.remove", method: "POST", path: "/phone/remove" },
    resend: { id: "phone.resend", method: "POST", path: "/phone/resend" },
    sendCode: { id: "phone.send-code", method: "POST", path: "/phone/send-code" },
    signIn: { id: "phone.sign-in", method: "POST", path: "/phone/sign-in", signIn: true },
    verify: { id: "phone.verify", method: "POST", path: "/phone/verify" },
  } };
}

/** The operations of the pow plugin. */
export type PowOps = {
  /** `POST /pow/challenge` (pow.challenge), requires public. */
  readonly challenge: Op<EmptyInput, PowChallenge>;
};

/** Enables the pow plugin's methods as `client.pow`. */
export function pow(): Plugin<"pow", PowOps> {
  return { name: "pow", ops: {
    challenge: { id: "pow.challenge", method: "POST", path: "/pow/challenge" },
  } };
}

/** The operations of the referral plugin. */
export type ReferralOps = {
  /** `GET /referral/dashboard` (referral.dashboard), requires signed_in. */
  readonly dashboard: Op<EmptyInput, ReferralDashboard>;
  /** `GET /referral/list` (referral.list), requires signed_in. */
  readonly list: Op<ReferralListRequest, ReferralListResult>;
  /** `POST /referral/remember` (referral.remember), requires public. */
  readonly remember: Op<ReferralCodeRequest, AuthDone>;
};

/** Enables the referral plugin's methods as `client.referral`. */
export function referral(): Plugin<"referral", ReferralOps> {
  return { name: "referral", ops: {
    dashboard: { id: "referral.dashboard", method: "GET", path: "/referral/dashboard" },
    list: { id: "referral.list", method: "GET", path: "/referral/list" },
    remember: { id: "referral.remember", method: "POST", path: "/referral/remember" },
  } };
}

/** The operations of the siwe plugin. */
export type SiweOps = {
  /** `POST /siwe/link` (siwe.link), requires fresh_sign_in. */
  readonly link: Op<SiweLinkRequest, SiweWallet>;
  /** `POST /siwe/nonce` (siwe.nonce), requires public. */
  readonly nonce: Op<SiweNonceRequest, SiweNonceResult>;
  /** `POST /siwe/unlink` (siwe.unlink), requires fresh_sign_in. */
  readonly unlink: Op<SiweUnlinkRequest, AuthDone>;
  /** `POST /siwe/verify` (siwe.verify), requires public. */
  readonly verify: Op<SiweVerifyRequest, SiweSignInResult>;
  /** `GET /siwe/wallets` (siwe.wallets), requires signed_in. */
  readonly wallets: Op<EmptyInput, SiweWalletsResult>;
};

/** Enables the siwe plugin's methods as `client.siwe`. */
export function siwe(): Plugin<"siwe", SiweOps> {
  return { name: "siwe", ops: {
    link: { id: "siwe.link", method: "POST", path: "/siwe/link" },
    nonce: { id: "siwe.nonce", method: "POST", path: "/siwe/nonce" },
    unlink: { id: "siwe.unlink", method: "POST", path: "/siwe/unlink" },
    verify: { id: "siwe.verify", method: "POST", path: "/siwe/verify", signIn: true },
    wallets: { id: "siwe.wallets", method: "GET", path: "/siwe/wallets" },
  } };
}

/** The operations of the terms plugin. */
export type TermsOps = {
  /** `POST /terms/accept` (terms.accept), requires signed_in. */
  readonly accept: Op<TermsAcceptRequest, AuthDone>;
};

/** Enables the terms plugin's methods as `client.terms`. */
export function terms(): Plugin<"terms", TermsOps> {
  return { name: "terms", ops: {
    accept: { id: "terms.accept", method: "POST", path: "/terms/accept" },
  } };
}

/** The operations of the twofactor plugin. */
export type TwofactorOps = {
  /** `POST /twofactor/check` (twofactor.check), requires signed_in. */
  readonly check: Op<TwofactorCodeRequest, AuthDone>;
  /** `POST /twofactor/confirm` (twofactor.confirm), requires fresh_sign_in. */
  readonly confirm: Op<TwofactorCodeRequest, TwofactorRecoveryCodes>;
  /** `GET /twofactor/devices` (twofactor.devices), requires signed_in. */
  readonly devices: Op<EmptyInput, TwofactorDevicesResult>;
  /** `POST /twofactor/disable` (twofactor.disable), requires fresh_sign_in. */
  readonly disable: Op<TwofactorCodeRequest, AuthDone>;
  /** `POST /twofactor/enroll` (twofactor.enroll), requires fresh_sign_in. */
  readonly enroll: Op<TwofactorEnrollRequest, TwofactorEnrollResult>;
  /** `POST /twofactor/devices/forget` (twofactor.forget-device), requires fresh_sign_in. */
  readonly forgetDevice: Op<TwofactorForgetDeviceRequest, AuthDone>;
  /** `POST /twofactor/reauthenticate` (twofactor.reauthenticate), requires signed_in. */
  readonly reauthenticate: Op<TwofactorReauthenticateRequest, AuthReauthentication>;
  /** `POST /twofactor/recovery-codes` (twofactor.recovery-codes), requires fresh_sign_in. */
  readonly recoveryCodes: Op<TwofactorCodeRequest, TwofactorRecoveryCodes>;
  /** `POST /twofactor/remove-factor` (twofactor.remove-factor), requires fresh_sign_in. */
  readonly removeFactor: Op<TwofactorRemoveFactorRequest, TwofactorRemoveFactorResult>;
  /** `POST /twofactor/security-key/challenge` (twofactor.security-key-challenge), requires signed_in_or_pending. */
  readonly securityKeyChallenge: Op<EmptyInput, TwofactorSecurityKeyChallenge>;
  /** `POST /twofactor/security-key/register-begin` (twofactor.security-key-register-begin), requires fresh_sign_in. */
  readonly securityKeyRegisterBegin: Op<TwofactorSecurityKeyRegisterBeginRequest, TwofactorSecurityKeyChallenge>;
  /** `POST /twofactor/security-key/register-finish` (twofactor.security-key-register-finish), requires fresh_sign_in. */
  readonly securityKeyRegisterFinish: Op<TwofactorSecurityKeyRegisterFinishRequest, TwofactorSecurityKeyRegistered>;
  /** `POST /twofactor/send` (twofactor.send), requires signed_in_or_pending. */
  readonly send: Op<EmptyInput, AuthDone>;
  /** `GET /twofactor/status` (twofactor.status), requires signed_in_or_pending. */
  readonly status: Op<EmptyInput, TwofactorStatus>;
  /** `POST /twofactor/totp-uri` (twofactor.totp-uri), requires fresh_sign_in. */
  readonly totpUri: Op<TwofactorPasswordRequest, TwofactorTOTPURIResult>;
  /** `POST /twofactor/verify` (twofactor.verify), requires pending_second_factor. */
  readonly verify: Op<TwofactorCodeRequest, AuthDone>;
  /** `POST /twofactor/recovery-codes/view` (twofactor.view-recovery-codes), requires fresh_sign_in. */
  readonly viewRecoveryCodes: Op<TwofactorPasswordRequest, TwofactorRecoveryCodes>;
};

/** Enables the twofactor plugin's methods as `client.twofactor`. */
export function twofactor(): Plugin<"twofactor", TwofactorOps> {
  return { name: "twofactor", ops: {
    check: { id: "twofactor.check", method: "POST", path: "/twofactor/check" },
    confirm: { id: "twofactor.confirm", method: "POST", path: "/twofactor/confirm" },
    devices: { id: "twofactor.devices", method: "GET", path: "/twofactor/devices" },
    disable: { id: "twofactor.disable", method: "POST", path: "/twofactor/disable" },
    enroll: { id: "twofactor.enroll", method: "POST", path: "/twofactor/enroll" },
    forgetDevice: { id: "twofactor.forget-device", method: "POST", path: "/twofactor/devices/forget" },
    reauthenticate: { id: "twofactor.reauthenticate", method: "POST", path: "/twofactor/reauthenticate" },
    recoveryCodes: { id: "twofactor.recovery-codes", method: "POST", path: "/twofactor/recovery-codes" },
    removeFactor: { id: "twofactor.remove-factor", method: "POST", path: "/twofactor/remove-factor" },
    securityKeyChallenge: { id: "twofactor.security-key-challenge", method: "POST", path: "/twofactor/security-key/challenge" },
    securityKeyRegisterBegin: { id: "twofactor.security-key-register-begin", method: "POST", path: "/twofactor/security-key/register-begin" },
    securityKeyRegisterFinish: { id: "twofactor.security-key-register-finish", method: "POST", path: "/twofactor/security-key/register-finish" },
    send: { id: "twofactor.send", method: "POST", path: "/twofactor/send" },
    status: { id: "twofactor.status", method: "GET", path: "/twofactor/status" },
    totpUri: { id: "twofactor.totp-uri", method: "POST", path: "/twofactor/totp-uri" },
    verify: { id: "twofactor.verify", method: "POST", path: "/twofactor/verify" },
    viewRecoveryCodes: { id: "twofactor.view-recovery-codes", method: "POST", path: "/twofactor/recovery-codes/view" },
  } };
}

/** The operations of the username plugin. */
export type UsernameOps = {
  /** `GET /username/available` (username.available), requires public. */
  readonly available: Op<UsernameRequest, UsernameAvailability>;
  /** `POST /username/set` (username.set), requires signed_in. */
  readonly set: Op<UsernameRequest, UsernameResult>;
};

/** Enables the username plugin's methods as `client.username`. */
export function username(): Plugin<"username", UsernameOps> {
  return { name: "username", ops: {
    available: { id: "username.available", method: "GET", path: "/username/available" },
    set: { id: "username.set", method: "POST", path: "/username/set" },
  } };
}
