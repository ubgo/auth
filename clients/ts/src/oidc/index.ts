// @ubgo/auth-client/oidc: the public surface. Import from here only; nothing
// else in src/ is part of the API.

export { createOidcClient, type OidcClient, type SessionGate, type OptionalSession, type ProtectedHandler } from "./client.ts";
export {
  SCOPE_OPENID,
  DEFAULT_SCOPES,
  RESERVED_AUTH_PARAMS,
  DEFAULT_HTTP_TIMEOUT_MS,
  type ReservedAuthParam,
  type AuthParams,
  type OidcClientOptions,
  type OidcClientBaseOptions,
  type ClientCredentials,
  type SessionSealing,
} from "./options.ts";

export { OidcErrorCode, OIDC_ERROR_CODES, OidcClientError, isOidcError } from "./errors.ts";
export { secret, REDACTED, type Secret } from "./secret.ts";

export {
  Claim,
  MapReason,
  MAP_REASONS,
  claimString,
  claimBool,
  claimStrings,
  defaultUser,
  type JsonValue,
  type Claims,
  type Identity,
  type User,
  type MapUserInput,
  type MapUserCommon,
  type UserMapper,
} from "./identity.ts";
export { Decision, DECISIONS, type AuthorizeInput, type Authorizer } from "./authorize.ts";

export {
  cookieStore,
  memoryStore,
  logoutTargetMatches,
  encodeSession,
  decodeSession,
  DEFAULT_IDLE_LIFETIME_MS,
  DEFAULT_ABSOLUTE_LIFETIME_MS,
  type Tokens,
  type Session,
  type StoreContext,
  type SessionStore,
  type RevokingSessionStore,
  type LogoutTarget,
  type Lifetimes,
} from "./session.ts";
export { secretSealer, MIN_SECRET_BYTES, type Sealer, type SecretSealerKeys } from "./seal.ts";
export {
  SameSite,
  SAME_SITE_VALUES,
  HOST_PREFIX,
  SECURE_PREFIX,
  DEFAULT_COOKIE_NAME,
  FLOW_COOKIE_SUFFIX,
  type CookieOptions,
} from "./cookie.ts";

export {
  recheckByRefresh,
  recheckByIntrospection,
  recheckByUserInfo,
  recheckBackchannelOnly,
  DEFAULT_RECHECK_INTERVAL_MS,
  RECHECK_EVERY_REQUEST,
  DEFAULT_OUTAGE_GRACE_MS,
  NO_OUTAGE_GRACE,
  type RecheckInput,
  type RecheckResult,
  type Rechecker,
} from "./recheck.ts";
export {
  clientSecretBasic,
  clientSecretPost,
  publicClient,
  ID_TOKEN_ALGORITHMS,
  TokenTypeHint,
  TOKEN_TYPE_HINTS,
  type IdTokenAlgorithm,
  type ProviderMetadata,
  type ClientAuth,
  type ClientAuthRequest,
  type Provider,
  type RefreshInput,
  type Refreshed,
  type IntrospectInput,
  type Introspection,
  type UserInfoInput,
} from "./provider.ts";

export {
  RefusalKind,
  REFUSAL_KINDS,
  RefusalReason,
  REFUSAL_REASONS,
  defaultResponder,
  refusalStatus,
  isPageRequest,
  type Refusal,
  type Responder,
} from "./respond.ts";
export {
  pathsUnder,
  returnToRequested,
  returnToFixed,
  returnToAllowed,
  DEFAULT_ROUTE_PREFIX,
  PARAM_RETURN_TO,
  type SameSitePath,
  type Paths,
  type ReturnInput,
  type ReturnPolicy,
} from "./routes.ts";
export { EventKind, EVENT_KINDS, type EventCommon, type OidcEvent, type Observer } from "./observe.ts";
export type { Logger, LogFn } from "./log.ts";
