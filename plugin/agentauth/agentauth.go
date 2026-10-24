// Package agentauth lets AI agents authenticate to the app with their own
// keys and act for a user under capabilities the user granted. It
// implements the Agent Auth Protocol (agentauthprotocol.com).
//
// Two kinds of caller hold keys. A host is the runtime an agent lives in (an
// MCP client, a CLI, a desktop app); it signs "host+jwt" tokens and registers
// agents. An agent has its own Ed25519 (or P-256) key pair and signs a short
// "agent+jwt" for every request. A user approves an agent and its
// capabilities with a user code (the device_authorization method), and the
// agent then calls the execute endpoint, which checks its grants and the
// grants' constraints before the app's ExecuteFunc runs.
//
// The protocol endpoints are served by Plugin.Handler in the protocol's JSON
// shape; each one is a self-served auth operation underneath (auth.OpInfo
// .SelfServed), so it runs the same pipeline as every other operation: rate
// limits, hooks, tracing. The user's operations (approving an agent,
// creating a host) are ordinary operations every transport mounts under
// /agentauth.
//
// Security rules, each pinned by a test: a JWT's typ, signature, audience,
// expiry and age are checked, and the algorithm comes from the stored key,
// never from the token; every JWT carries a jti that authenticates once,
// recorded in the database so the rule holds across servers; a revoked,
// pending, rejected or expired agent authenticates nothing; a capability
// executes only under an active, unexpired grant whose constraints allow the
// arguments; a user code is compared as a SHA-256 digest in constant time.
package agentauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity, and the segment its user
// operations are served under.
const PluginName = "agentauth"

// Operation ids. The self-served ones are served by Handler at the protocol
// paths; the others by every transport, under /agentauth.
const (
	EndpointConfiguration      auth.EndpointID = "agentauth.configuration"
	EndpointRegister           auth.EndpointID = "agentauth.register"
	EndpointSession            auth.EndpointID = "agentauth.session"
	EndpointRevoke             auth.EndpointID = "agentauth.revoke"
	EndpointStatus             auth.EndpointID = "agentauth.status"
	EndpointIntrospect         auth.EndpointID = "agentauth.introspect"
	EndpointListCapabilities   auth.EndpointID = "agentauth.list_capabilities"
	EndpointDescribeCapability auth.EndpointID = "agentauth.describe_capability"
	EndpointRequestCapability  auth.EndpointID = "agentauth.request_capability"
	EndpointExecute            auth.EndpointID = "agentauth.execute"
	EndpointRotateHostKey      auth.EndpointID = "agentauth.rotate_host_key"
	EndpointApproveCapability  auth.EndpointID = "agentauth.approve_capability"
	EndpointCreateHost         auth.EndpointID = "agentauth.create_host"
	EndpointCIBAAuthorize      auth.EndpointID = "agentauth.ciba_authorize"
	EndpointPendingApprovals   auth.EndpointID = "agentauth.pending_approvals"
	EndpointRevokeHost         auth.EndpointID = "agentauth.revoke_host"
	EndpointRevokeCapability   auth.EndpointID = "agentauth.revoke_capability"
	EndpointClaim              auth.EndpointID = "agentauth.claim"
	EndpointUpdateAgent        auth.EndpointID = "agentauth.update_agent"
	EndpointReactivate         auth.EndpointID = "agentauth.reactivate"
	EndpointRotateAgentKey     auth.EndpointID = "agentauth.rotate_agent_key"
	EndpointUpdateHost         auth.EndpointID = "agentauth.update_host"
	EndpointEnrollHost         auth.EndpointID = "agentauth.enroll_host"
)

// Protocol paths, under the issuer's path.
const (
	PathConfiguration      = "/agent-configuration"
	PathRegister           = "/agent/register"
	PathSession            = "/agent/session"
	PathRevoke             = "/agent/revoke"
	PathStatus             = "/agent/status"
	PathIntrospect         = "/agent/introspect"
	PathListCapabilities   = "/capability/list"
	PathDescribeCapability = "/capability/describe"
	PathRequestCapability  = "/agent/request-capability"
	PathExecute            = "/capability/execute"
	PathRotateHostKey      = "/host/rotate-key"
	// PathCIBAAuthorize is the CIBA backchannel authentication endpoint
	// (protocol section 9.2), called with a host JWT.
	PathCIBAAuthorize = "/agent/ciba/authorize"
	// PathRevokeHost revokes a host and every agent under it (protocol
	// section 6.10), with a host JWT or a signed-in owner.
	PathRevokeHost = "/host/revoke"
	// PathRevokeCapability revokes capabilities of one agent without
	// revoking the agent.
	PathRevokeCapability = "/agent/revoke-capability"
	// PathClaim starts the claim of an autonomous agent (protocol section
	// 3.4), with a host JWT.
	PathClaim = "/agent/claim"
	// PathReactivate reactivates an expired agent (protocol section 6.6),
	// with a host JWT.
	PathReactivate = "/agent/reactivate"
	// PathRotateAgentKey replaces an agent's key (protocol section 6.8),
	// with a host JWT.
	PathRotateAgentKey = "/agent/rotate-key"
	// PathEnrollHost binds a key to a host created for enrollment
	// (protocol section 3.2), with the one-time enrollment token.
	PathEnrollHost = "/host/enroll"
	// WellKnownConfiguration is the discovery document's well-known path
	// (protocol section 5.1), served at the root of the issuer's host.
	WellKnownConfiguration = "/.well-known/agent-configuration"
)

// Mode is how an agent acts: for a user who approved it, or on its own.
type Mode string

// Modes.
const (
	// ModeDelegated acts for the user who approved the agent.
	ModeDelegated Mode = "delegated"
	// ModeAutonomous acts on its own, under its host's capability budget,
	// until a user claims the host.
	ModeAutonomous Mode = "autonomous"
)

// ModeValues is every mode, and the default of Modes.
var ModeValues = []Mode{ModeDelegated, ModeAutonomous}

// AgentStatus is an agent's lifecycle state.
type AgentStatus string

// Agent states.
const (
	AgentActive   AgentStatus = "active"
	AgentPending  AgentStatus = "pending"
	AgentExpired  AgentStatus = "expired"
	AgentRevoked  AgentStatus = "revoked"
	AgentRejected AgentStatus = "rejected"
	AgentClaimed  AgentStatus = "claimed"
)

// HostStatus is a host's lifecycle state.
type HostStatus string

// Host states.
const (
	HostActive  HostStatus = "active"
	HostPending HostStatus = "pending"
	HostRevoked HostStatus = "revoked"
	// HostPendingEnrollment is a host created without a key, waiting for
	// a device to enroll with its one-time token (EnrollHost). It
	// authenticates nothing.
	HostPendingEnrollment HostStatus = "pending_enrollment"
)

// GrantStatus is a capability grant's state.
type GrantStatus string

// Grant states. GrantConsumed is a single-use grant spent by
// Execution.ConsumeGrant.
const (
	GrantActive   GrantStatus = "active"
	GrantPending  GrantStatus = "pending"
	GrantDenied   GrantStatus = "denied"
	GrantRevoked  GrantStatus = "revoked"
	GrantConsumed GrantStatus = "consumed"
)

// ApprovalStatus is an approval request's state.
type ApprovalStatus string

// Approval request states.
const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalDenied   ApprovalStatus = "denied"
)

// Approval methods (protocol section 9).
const (
	// MethodDeviceAuthorization: the agent shows the user a code and a
	// URL, and the signed-in user enters the code on the app's approval
	// page.
	MethodDeviceAuthorization = "device_authorization"
	// MethodCIBA: client-initiated backchannel authentication, in poll
	// mode. The request is addressed to a known user, who sees it in the
	// pending_approvals list (the app may notify them from the
	// approval.created event) and answers it by its approval id; the agent
	// polls /agent/status.
	MethodCIBA = "ciba"
)

// ApprovalMethodValues is every approval method, and the default of
// ApprovalMethods, in the default order.
var ApprovalMethodValues = []string{MethodCIBA, MethodDeviceAuthorization}

// Approval actions.
const (
	ActionApprove = "approve"
	ActionDeny    = "deny"
)

// Key algorithms, by JWK curve name as the protocol names them.
const (
	AlgEd25519 = "Ed25519"
	AlgP256    = "P-256"
)

// supportedAlgorithms is every algorithm AllowedKeyAlgorithms may name.
var supportedAlgorithms = []string{AlgEd25519, AlgP256}

// Defaults. Each has an option.
const (
	// DefaultJWTMaxAge is the oldest an agent or host JWT may be, from iat.
	DefaultJWTMaxAge = 60 * time.Second
	// DefaultAgentSessionTTL is the sliding idle lifetime of an agent: each
	// authenticated request extends it.
	DefaultAgentSessionTTL = time.Hour
	// DefaultAgentMaxLifetime caps an agent's life from its activation.
	DefaultAgentMaxLifetime = 24 * time.Hour
	// DefaultMaxAgentsPerUser is how many active agents one user may have.
	DefaultMaxAgentsPerUser = 25
	// DefaultDeviceAuthorizationPage is where the approval answer sends the
	// user; the app serves the page.
	DefaultDeviceAuthorizationPage = "/device/capabilities"
	// DefaultApprovalTTL is how long a user code is valid.
	DefaultApprovalTTL = 5 * time.Minute
	// DefaultApprovalInterval is the polling interval the agent is told.
	DefaultApprovalInterval = 5 * time.Second
	// DefaultPresenceTTL is how long a WebAuthn approval challenge stays
	// valid.
	DefaultPresenceTTL = 5 * time.Minute
	// clockSkew is added to the jti record's lifetime and to the future a
	// token's iat may name, for servers whose clocks differ.
	clockSkew = 30 * time.Second
	// protocolVersion is the discovery document's version.
	protocolVersion = "1.0-draft"
	// defaultProviderName and defaultDescription name the provider in
	// discovery when the app sets neither.
	defaultProviderName = "agent-auth"
	defaultDescription  = "Agent Auth enabled service"
)

// Display limits, protocol section 8.10.
const (
	maxNameRunes    = 200
	maxReasonRunes  = 500
	maxBindingRunes = 500
	maxCapabilities = 100
)

// Errors. The part after "agentauth." is the protocol's error code, which
// Handler answers as {"error": code, "message": message}.
var (
	ErrInvalidRequest            = auth.NewError("agentauth.invalid_request", http.StatusBadRequest, "Malformed request, missing required fields, or invalid parameter types.")
	ErrInvalidJWT                = auth.NewError("agentauth.invalid_jwt", http.StatusUnauthorized, "JWT is invalid, expired, or signature failed.")
	ErrJTIReplay                 = auth.NewError("agentauth.jti_replay", http.StatusUnauthorized, "JWT has already been used.")
	ErrRequestBindingMismatch    = auth.NewError("agentauth.request_binding_mismatch", http.StatusUnauthorized, "Request binding does not match the JWT.")
	ErrInvalidPublicKey          = auth.NewError("agentauth.invalid_public_key", http.StatusBadRequest, "Public key is invalid or malformed.")
	ErrUnsupportedAlgorithm      = auth.NewError("agentauth.unsupported_algorithm", http.StatusBadRequest, "Key algorithm is not in the server's supported set.")
	ErrUnsupportedMode           = auth.NewError("agentauth.unsupported_mode", http.StatusBadRequest, "Requested mode is not supported by this server.")
	ErrAuthenticationRequired    = auth.NewError("agentauth.authentication_required", http.StatusUnauthorized, "An agent JWT, a host JWT or a signed-in user is required.")
	ErrUnauthorized              = auth.NewError("agentauth.unauthorized", http.StatusForbidden, "Caller is not authorized for this operation.")
	ErrAgentNotFound             = auth.NewError("agentauth.agent_not_found", http.StatusNotFound, "Agent not found.")
	ErrAgentRevoked              = auth.NewError("agentauth.agent_revoked", http.StatusForbidden, "Agent has been revoked.")
	ErrAgentPending              = auth.NewError("agentauth.agent_pending", http.StatusForbidden, "Agent is still pending approval.")
	ErrAgentRejected             = auth.NewError("agentauth.agent_rejected", http.StatusForbidden, "Agent registration was denied.")
	ErrAgentClaimed              = auth.NewError("agentauth.agent_claimed", http.StatusForbidden, "Agent has been claimed and is no longer active.")
	ErrAgentExpired              = auth.NewError("agentauth.agent_expired", http.StatusUnauthorized, "Agent session has expired.")
	ErrAbsoluteLifetimeExceeded  = auth.NewError("agentauth.absolute_lifetime_exceeded", http.StatusForbidden, "Agent's absolute lifetime has elapsed.")
	ErrAgentExists               = auth.NewError("agentauth.agent_exists", http.StatusConflict, "An agent with this public key is already registered.")
	ErrAgentLimitReached         = auth.NewError("agentauth.agent_limit_reached", http.StatusBadRequest, "Maximum number of active agents per user reached.")
	ErrAutonomousOwnerRequired   = auth.NewError("agentauth.autonomous_owner_required", http.StatusUnauthorized, "Autonomous agents require an owner to be resolved.")
	ErrHostNotFound              = auth.NewError("agentauth.host_not_found", http.StatusNotFound, "Host not found.")
	ErrHostRevoked               = auth.NewError("agentauth.host_revoked", http.StatusForbidden, "Host has been revoked.")
	ErrHostAlreadyLinked         = auth.NewError("agentauth.host_already_linked", http.StatusConflict, "Host is already linked to a different user.")
	ErrDynamicHostRegistration   = auth.NewError("agentauth.dynamic_host_registration_disabled", http.StatusForbidden, "Dynamic host registration is disabled: enable AllowDynamicHostRegistration, or create the host first with the create_host operation.")
	ErrInvalidCapabilities       = auth.NewError("agentauth.invalid_capabilities", http.StatusBadRequest, "One or more requested capability names don't exist.")
	ErrCapabilityBlocked         = auth.NewError("agentauth.capability_blocked", http.StatusBadRequest, "One or more requested capabilities are blocked by server policy.")
	ErrCapabilityNotFound        = auth.NewError("agentauth.capability_not_found", http.StatusNotFound, "Capability does not exist.")
	ErrAlreadyGranted            = auth.NewError("agentauth.already_granted", http.StatusConflict, "All requested capabilities are already granted.")
	ErrCapabilityNotGranted      = auth.NewError("agentauth.capability_not_granted", http.StatusForbidden, "Agent does not have an active grant for this capability.")
	ErrGrantRevoked              = auth.NewError("agentauth.grant_revoked", http.StatusForbidden, "Capability grant has been revoked.")
	ErrConstraintViolated        = auth.NewError("agentauth.constraint_violated", http.StatusForbidden, "One or more capability constraints were violated.")
	ErrUnknownConstraintOperator = auth.NewError("agentauth.unknown_constraint_operator", http.StatusBadRequest, "Constraint contains an unrecognized operator.")
	ErrExecuteNotConfigured      = auth.NewError("agentauth.execute_not_configured", http.StatusNotImplemented, "Server has not configured a capability execution handler.")
	ErrApprovalNotFound          = auth.NewError("agentauth.capability_request_not_found", http.StatusNotFound, "Capability request not found.")
	ErrApprovalResolved          = auth.NewError("agentauth.capability_request_already_resolved", http.StatusPreconditionFailed, "Capability request has already been resolved.")
	ErrApprovalOwnerMismatch     = auth.NewError("agentauth.capability_request_owner_mismatch", http.StatusForbidden, "Capability request does not belong to this user.")
	ErrInvalidUserCode           = auth.NewError("agentauth.invalid_user_code", http.StatusForbidden, "The user code is missing or does not match.")
	ErrApprovalExpired           = auth.NewError("agentauth.approval_expired", http.StatusForbidden, "The approval request has expired.")
	ErrEnrollmentTokenInvalid    = auth.NewError("agentauth.enrollment_token_invalid", http.StatusUnauthorized, "The enrollment token is invalid or was already used.")
	ErrEnrollmentTokenExpired    = auth.NewError("agentauth.enrollment_token_expired", http.StatusUnauthorized, "The enrollment token has expired.")
	ErrJWKSURLsDisabled          = auth.NewError("agentauth.jwks_url_disabled", http.StatusBadRequest, "This server does not accept JWKS URLs; send a public key.")
	ErrInvalidJWKSURL            = auth.NewError("agentauth.invalid_jwks_url", http.StatusBadRequest, "The JWKS URL must be a public https URL.")
)

// Configuration errors, returned by auth.New.
var (
	ErrBadIssuer     = errors.New("agentauth: Issuer is an absolute https URL (http only for a loopback host) with no query or fragment")
	ErrBadAlgorithm  = errors.New("agentauth: AllowedKeyAlgorithms names only Ed25519 and P-256, and at least one")
	ErrBadMode       = errors.New("agentauth: Modes names only delegated and autonomous, and at least one")
	ErrBadDuration   = errors.New("agentauth: JWTMaxAge and EnrollmentTokenTTL are positive, and no lifetime is negative")
	ErrBadCapability = errors.New("agentauth: a capability has a unique, non-empty name without whitespace, an absolute location URL when it has one, and a known approval strength")
	ErrBadApproval   = errors.New("agentauth: ApprovalMethods names only ciba and device_authorization, and at least one")
	ErrNoPresence    = errors.New("agentauth: a capability needs WebAuthn approval, so ProofOfPresence must be set")
)

// Capability is one thing an agent may do, protocol section 4.
type Capability struct {
	// Name is the identifier agents request and execute. Unique.
	Name string `json:"name"`
	// Description says what it does, for the agent and the approving user.
	Description string `json:"description"`
	// Location is the absolute URL where the capability executes when it is
	// not the execute endpoint; an agent JWT for it names it as aud.
	Location string `json:"location,omitempty"`
	// Input and Output are JSON Schemas of the arguments and of the result.
	Input  json.RawMessage `json:"input,omitempty"`
	Output json.RawMessage `json:"output,omitempty"`
	// RequiredConstraints are argument fields an agent must constrain when
	// it requests the capability (protocol section 2.13).
	RequiredConstraints []string `json:"-"`
	// GrantTTL is how long a grant of it lasts; zero never expires.
	GrantTTL time.Duration `json:"-"`
	// ApprovalStrength is what approving it takes (protocol section
	// 8.11); empty is StrengthSession.
	ApprovalStrength ApprovalStrength `json:"approval_strength,omitempty"`
}

// ApprovalStrength is what a user must show to approve a capability.
type ApprovalStrength string

// Approval strengths.
const (
	// StrengthNone marks a capability that needs no user interaction; it
	// is informational: the host's budget is what
	// grants without asking.
	StrengthNone ApprovalStrength = "none"
	// StrengthSession needs a signed-in user (device authorization or
	// CIBA). The default.
	StrengthSession ApprovalStrength = "session"
	// StrengthWebAuthn needs a WebAuthn assertion with user verification
	// on top of the session: proof that a person, not an agent driving
	// the browser, approved. Needs ProofOfPresence.
	StrengthWebAuthn ApprovalStrength = "webauthn"
)

// ApprovalStrengthValues is every strength.
var ApprovalStrengthValues = []ApprovalStrength{StrengthNone, StrengthSession, StrengthWebAuthn}

// ExecuteFunc runs a capability for an agent. The
// plugin has checked the agent and the grant before it is called. Its
// result is sent to the agent as {"data": result}; it is any because each
// capability's result has its own shape and goes straight to the JSON
// encoder. An *auth.Error it returns reaches the agent as it is; any other
// error is an internal error.
type ExecuteFunc func(ctx context.Context, ex Execution) (any, error)

// AutonomousUserFunc names the user an autonomous agent on an unclaimed host
// acts as. Nil, or a nil user, refuses
// the agent with ErrAutonomousOwnerRequired.
type AutonomousUserFunc func(ctx context.Context, hostID, agentID string) (*SessionUser, error)

// Plugin is the Agent Auth provider. Build it with New.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs         auth.OptionErrors
	issuer          string
	providerName    string
	description     string
	modes           []Mode
	capabilities    []Capability
	onExecute       ExecuteFunc
	algorithms      []string
	jwtMaxAge       time.Duration
	sessionTTL      time.Duration
	maxLifetime     time.Duration
	absolute        time.Duration
	maxAgents       int
	blocked         []string
	dynamicHosts    bool
	hostDefaults    []string
	hostDefaultsFn  HostCapabilitiesFunc
	devicePage      string
	approvalMethods []string
	resolveMethod   ApprovalMethodFunc
	trustProxy      bool
	presence        PresenceVerifier
	requireAuthList bool
	autonomousUser  AutonomousUserFunc
	// onEvent is OnEvent.
	onEvent EventFunc
	// jwksAllowed is AllowJWKSURLs, jwksClient JWKSClient (the guarded
	// client by default), jwks the fetched key sets.
	jwksAllowed bool
	jwksClient  *http.Client
	jwks        jwksCache
	// enrollTTL is EnrollmentTokenTTL.
	enrollTTL time.Duration

	core *auth.Auth

	configuration *auth.Op[struct{}, Configuration]
	register      *auth.Op[RegisterRequest, RegisterResult]
	session       *auth.Op[Bearer, AgentSession]
	revoke        *auth.Op[RevokeRequest, RevokeResult]
	status        *auth.Op[StatusRequest, AgentStatusView]
	introspect    *auth.Op[IntrospectRequest, Introspection]
	listCaps      *auth.Op[ListCapabilitiesRequest, CapabilityList]
	describeCap   *auth.Op[DescribeCapabilityRequest, CapabilityView]
	requestCap    *auth.Op[RequestCapabilityRequest, RequestCapabilityResult]
	execute       *auth.Op[ExecuteRequest, ExecuteResult]
	rotateHostKey *auth.Op[RotateHostKeyRequest, RotateHostKeyResult]
	approve       *auth.Op[ApproveRequest, ApproveResult]
	createHost    *auth.Op[CreateHostRequest, CreateHostResult]
	cibaAuthorize *auth.Op[CIBAAuthorizeRequest, CIBAAuthorizeResult]
	pending       *auth.Op[struct{}, PendingApprovals]
	revokeHost    *auth.Op[RevokeHostRequest, RevokeHostResult]
	revokeCap     *auth.Op[RevokeCapabilityRequest, RevokeCapabilityResult]
	claim         *auth.Op[ClaimRequest, ClaimResult]
	updateAgent   *auth.Op[UpdateAgentRequest, UpdateAgentResult]
	reactivate    *auth.Op[ReactivateRequest, AgentStatusView]
	rotateAgent   *auth.Op[RotateAgentKeyRequest, RotateAgentKeyResult]
	updateHost    *auth.Op[UpdateHostRequest, UpdateHostResult]
	enrollHost    *auth.Op[EnrollHostRequest, EnrollHostResult]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin; pass options to New.
type Option func(*Plugin)

// Issuer is the base URL of the protocol endpoints and the JWT audience,
// such as "https://app.example.com/api/agent". Empty (the default) is the
// app's auth.WithBaseURL.
func Issuer(iss string) Option { return func(p *Plugin) { p.issuer = strings.TrimSuffix(iss, "/") } }

// ProviderName and ProviderDescription fill the discovery document.
func ProviderName(name string) Option { return func(p *Plugin) { p.providerName = name } }

// ProviderDescription is the discovery document's description.
func ProviderDescription(d string) Option { return func(p *Plugin) { p.description = d } }

// Modes narrows ModeValues.
func Modes(modes ...Mode) Option { return func(p *Plugin) { p.modes = modes } }

// Capabilities is the catalogue agents may request. With a catalogue, a
// request for a name outside it is refused (ErrInvalidCapabilities); with
// none, any name is accepted.
func Capabilities(caps ...Capability) Option { return func(p *Plugin) { p.capabilities = caps } }

// OnExecute runs capabilities for the execute endpoint. Without it the
// endpoint answers ErrExecuteNotConfigured, and capabilities with a
// Location run on the app's own routes, which verify the agent with
// Plugin.VerifyAgentRequest.
func OnExecute(fn ExecuteFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("agentauth.OnExecute", fn) {
			return
		}
		p.onExecute = fn
	}
}

// AllowedKeyAlgorithms narrows the key algorithms agents and hosts may use,
// by JWK curve name. The default is Ed25519 only.
func AllowedKeyAlgorithms(algs ...string) Option { return func(p *Plugin) { p.algorithms = algs } }

// JWTMaxAge overrides DefaultJWTMaxAge.
func JWTMaxAge(d time.Duration) Option { return func(p *Plugin) { p.jwtMaxAge = d } }

// AgentSessionTTL overrides DefaultAgentSessionTTL; zero disables it.
func AgentSessionTTL(d time.Duration) Option { return func(p *Plugin) { p.sessionTTL = d } }

// AgentMaxLifetime overrides DefaultAgentMaxLifetime; zero disables it.
func AgentMaxLifetime(d time.Duration) Option { return func(p *Plugin) { p.maxLifetime = d } }

// AbsoluteLifetime refuses an agent this long after its creation, whatever
// happened since. Zero (the default) disables it.
func AbsoluteLifetime(d time.Duration) Option { return func(p *Plugin) { p.absolute = d } }

// MaxAgentsPerUser overrides DefaultMaxAgentsPerUser; zero disables it.
func MaxAgentsPerUser(n int) Option { return func(p *Plugin) { p.maxAgents = n } }

// BlockedCapabilities can never be granted. A trailing ".*" blocks a family.
func BlockedCapabilities(names ...string) Option { return func(p *Plugin) { p.blocked = names } }

// AllowDynamicHostRegistration lets an unknown host register agents with a
// host JWT that carries its own public key. A significant trust decision,
// off by default: without it, a host must first be created by a signed-in
// user (create_host).
func AllowDynamicHostRegistration() Option { return func(p *Plugin) { p.dynamicHosts = true } }

// DefaultHostCapabilities is the budget a dynamically registered or claimed
// host receives, and a host created without default_capabilities:
// capabilities its agents get without asking a user.
func DefaultHostCapabilities(names ...string) Option {
	return func(p *Plugin) { p.hostDefaults, p.hostDefaultsFn = names, nil }
}

// HostCapabilitiesContext is what a HostCapabilitiesFunc decides from.
type HostCapabilitiesContext struct {
	// Mode is the registering agent's mode; empty when a user creates or
	// claims the host.
	Mode Mode
	// UserID is the host's owner, nil for a host nobody owns yet.
	UserID *string
	// HostID is empty for a host about to be created.
	HostID   string
	HostName string
}

// HostCapabilitiesFunc computes a host's budget per host, the function form
// of the default host capabilities.
type HostCapabilitiesFunc func(ctx context.Context, hc HostCapabilitiesContext) ([]string, error)

// DefaultHostCapabilitiesFunc computes the budget per host instead of
// DefaultHostCapabilities' fixed list. Its names are checked against the
// catalogue like any other.
func DefaultHostCapabilitiesFunc(fn HostCapabilitiesFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("agentauth.DefaultHostCapabilitiesFunc", fn) {
			return
		}
		p.hostDefaults, p.hostDefaultsFn = nil, fn
	}
}

// hostBudget is the default budget for hc.
func (p *Plugin) hostBudget(ctx context.Context, hc HostCapabilitiesContext) ([]string, error) {
	if p.hostDefaultsFn == nil {
		return p.hostDefaults, nil
	}
	names, err := p.hostDefaultsFn(ctx, hc)
	if err != nil {
		return nil, err
	}
	reqs := make([]CapabilityRequest, 0, len(names))
	for _, n := range names {
		reqs = append(reqs, CapabilityRequest{Name: n})
	}
	if err := p.checkCapabilityNames(reqs); err != nil {
		return nil, err
	}
	return names, nil
}

// TrustProxy builds the URL a token's htu claim is compared with from
// X-Forwarded-Proto and X-Forwarded-Host, for a server behind a reverse
// proxy that terminates TLS. Off by default:
// enable it only when the proxy overwrites both headers. The accepted
// audiences never come from the request, so this cannot widen them.
func TrustProxy() Option { return func(p *Plugin) { p.trustProxy = true } }

// DeviceAuthorizationPage overrides DefaultDeviceAuthorizationPage: a path
// on the issuer's origin or an absolute URL. The page receives agent_id and
// code, and posts them to the approve_capability operation.
func DeviceAuthorizationPage(u string) Option { return func(p *Plugin) { p.devicePage = u } }

// RequireAuthForCapabilities makes listing and describing capabilities
// need an agent or host JWT.
func RequireAuthForCapabilities() Option { return func(p *Plugin) { p.requireAuthList = true } }

// AutonomousUser sets the AutonomousUserFunc.
func AutonomousUser(fn AutonomousUserFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("agentauth.AutonomousUser", fn) {
			return
		}
		p.autonomousUser = fn
	}
}

var (
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.TypedMigrator     = (*Plugin)(nil)
	_ auth.TableOwner        = (*Plugin)(nil)
	_ auth.UserTableOwner    = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.Sweeper           = (*Plugin)(nil)
)

// New builds the plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{
		modes: ModeValues, algorithms: []string{AlgEd25519}, jwtMaxAge: DefaultJWTMaxAge,
		sessionTTL: DefaultAgentSessionTTL, maxLifetime: DefaultAgentMaxLifetime, maxAgents: DefaultMaxAgentsPerUser,
		devicePage: DefaultDeviceAuthorizationPage, providerName: defaultProviderName, description: defaultDescription,
		approvalMethods: ApprovalMethodValues, enrollTTL: DefaultEnrollmentTokenTTL,
	}
	for _, o := range opts {
		o(p)
	}
	self := func(id auth.EndpointID, kind auth.OpKind, path string) auth.OpInfo {
		return auth.OpInfo{ID: id, Kind: kind, Require: auth.Public, Path: path, SelfServed: true}
	}
	p.configuration = auth.Define(self(EndpointConfiguration, auth.Query, PathConfiguration), p.doConfiguration)
	p.register = auth.Define(self(EndpointRegister, auth.Mutation, PathRegister), p.doRegister)
	p.session = auth.Define(self(EndpointSession, auth.Query, PathSession), p.doSession)
	p.revoke = auth.Define(self(EndpointRevoke, auth.Mutation, PathRevoke), p.doRevoke)
	p.status = auth.Define(self(EndpointStatus, auth.Query, PathStatus), p.doStatus)
	p.introspect = auth.Define(self(EndpointIntrospect, auth.Mutation, PathIntrospect), p.doIntrospect)
	p.listCaps = auth.Define(self(EndpointListCapabilities, auth.Query, PathListCapabilities), p.doListCapabilities)
	p.describeCap = auth.Define(self(EndpointDescribeCapability, auth.Query, PathDescribeCapability), p.doDescribeCapability)
	p.requestCap = auth.Define(self(EndpointRequestCapability, auth.Mutation, PathRequestCapability), p.doRequestCapability)
	p.execute = auth.Define(self(EndpointExecute, auth.Mutation, PathExecute), p.doExecute)
	p.rotateHostKey = auth.Define(self(EndpointRotateHostKey, auth.Mutation, PathRotateHostKey), p.doRotateHostKey)
	p.approve = auth.Define(auth.OpInfo{ID: EndpointApproveCapability, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/approve-capability"}, p.doApprove)
	p.createHost = auth.Define(auth.OpInfo{ID: EndpointCreateHost, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/create-host"}, p.doCreateHost)
	p.cibaAuthorize = auth.Define(self(EndpointCIBAAuthorize, auth.Mutation, PathCIBAAuthorize), p.doCIBAAuthorize)
	p.pending = auth.Define(auth.OpInfo{ID: EndpointPendingApprovals, Kind: auth.Query, Require: auth.SignedIn, Path: "/pending-approvals"}, p.doPendingApprovals)
	p.revokeHost = auth.Define(self(EndpointRevokeHost, auth.Mutation, PathRevokeHost), p.doRevokeHost)
	p.revokeCap = auth.Define(self(EndpointRevokeCapability, auth.Mutation, PathRevokeCapability), p.doRevokeCapability)
	p.claim = auth.Define(self(EndpointClaim, auth.Mutation, PathClaim), p.doClaim)
	p.updateAgent = auth.Define(auth.OpInfo{ID: EndpointUpdateAgent, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/update-agent"}, p.doUpdateAgent)
	p.reactivate = auth.Define(self(EndpointReactivate, auth.Mutation, PathReactivate), p.doReactivate)
	p.rotateAgent = auth.Define(self(EndpointRotateAgentKey, auth.Mutation, PathRotateAgentKey), p.doRotateAgentKey)
	p.updateHost = auth.Define(auth.OpInfo{ID: EndpointUpdateHost, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/update-host"}, p.doUpdateHost)
	p.enrollHost = auth.Define(self(EndpointEnrollHost, auth.Mutation, PathEnrollHost), p.doEnrollHost)
	return p
}

// Name is PluginName.
func (p *Plugin) Name() string { return PluginName }

// Operations lists every operation; the self-served ones are wired but
// mounted only by Handler.
func (p *Plugin) Operations() []auth.Operation {
	return []auth.Operation{
		p.configuration, p.register, p.session, p.revoke, p.status, p.introspect, p.listCaps,
		p.describeCap, p.requestCap, p.execute, p.rotateHostKey, p.approve, p.createHost,
		p.cibaAuthorize, p.pending, p.revokeHost, p.revokeCap, p.claim, p.updateAgent,
		p.reactivate, p.rotateAgent, p.updateHost, p.enrollHost,
	}
}

// Validate checks the issuer, the algorithms, the modes, the lifetimes and
// the catalogue.
func (p *Plugin) Validate(*auth.Config) error {
	if p.issuer != "" && !validIssuer(p.issuer) {
		return fmt.Errorf("%w: %q", ErrBadIssuer, p.issuer)
	}
	if len(p.algorithms) == 0 {
		return ErrBadAlgorithm
	}
	for _, a := range p.algorithms {
		if !slices.Contains(supportedAlgorithms, a) {
			return fmt.Errorf("%w: %q", ErrBadAlgorithm, a)
		}
	}
	if len(p.modes) == 0 {
		return ErrBadMode
	}
	for _, m := range p.modes {
		if !slices.Contains(ModeValues, m) {
			return fmt.Errorf("%w: %q", ErrBadMode, m)
		}
	}
	// Each setting is checked on its own, so the error names the option to
	// fix; ErrBadDuration stays the sentinel for all of them.
	for _, d := range []struct {
		option string
		bad    bool
		value  any
	}{
		{"agentauth.JWTMaxAge", p.jwtMaxAge <= 0, p.jwtMaxAge},
		{"agentauth.EnrollmentTokenTTL", p.enrollTTL <= 0, p.enrollTTL},
		{"agentauth.AgentSessionTTL", p.sessionTTL < 0, p.sessionTTL},
		{"agentauth.AgentMaxLifetime", p.maxLifetime < 0, p.maxLifetime},
		{"agentauth.AbsoluteLifetime", p.absolute < 0, p.absolute},
		{"agentauth.MaxAgentsPerUser", p.maxAgents < 0, p.maxAgents},
	} {
		if d.bad {
			return fmt.Errorf("%w: %s(%v)", ErrBadDuration, d.option, d.value)
		}
	}
	if len(p.approvalMethods) == 0 {
		return ErrBadApproval
	}
	for _, m := range p.approvalMethods {
		if !slices.Contains(ApprovalMethodValues, m) {
			return fmt.Errorf("%w: %q", ErrBadApproval, m)
		}
	}
	seen := map[string]bool{}
	for _, c := range p.capabilities {
		if c.Name == "" || strings.ContainsAny(c.Name, " \t\n") || seen[c.Name] || c.GrantTTL < 0 ||
			(c.ApprovalStrength != "" && !slices.Contains(ApprovalStrengthValues, c.ApprovalStrength)) {
			return fmt.Errorf("%w: agentauth.Capabilities: %q", ErrBadCapability, c.Name)
		}
		if c.ApprovalStrength == StrengthWebAuthn && p.presence == nil {
			return fmt.Errorf("%w: agentauth.Capabilities: %q", ErrNoPresence, c.Name)
		}
		seen[c.Name] = true
		if c.Location != "" {
			if u, err := url.Parse(c.Location); err != nil || !u.IsAbs() || u.Host == "" {
				return fmt.Errorf("%w: agentauth.Capabilities: %q location %q", ErrBadCapability, c.Name, c.Location)
			}
		}
	}
	return nil
}

// validIssuer needs an absolute https URL (http for a loopback host) with a
// host and no query, fragment or user information.
func validIssuer(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && isLoopback(u.Hostname()))
}

// isLoopback reports a host name development serves on.
func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// Init captures the core and fills the issuer from the base URL.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	if p.jwksAllowed {
		a.Logger().Warn(WarnJWKSURLs)
		if p.jwksClient == nil {
			p.jwksClient = guardedJWKSClient()
		}
	}
	if p.issuer == "" {
		p.issuer = strings.TrimSuffix(a.BaseURL(context.Background()), "/")
		if !validIssuer(p.issuer) {
			return fmt.Errorf("%w: the base URL %q", ErrBadIssuer, p.issuer)
		}
	}
	return nil
}

// IssuerURL is the issuer the plugin serves under: Issuer, or the base URL.
func (p *Plugin) IssuerURL() string { return p.issuer }

// Sweep deletes spent JWT ids and approval requests that have expired.
func (p *Plugin) Sweep(ctx context.Context, cutoff time.Time) (int64, error) {
	n, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableJTI).Where(sqlb.Less(JTIExpires, cutoff)))
	if err != nil {
		return n, err
	}
	m, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableApproval).Where(sqlb.Less(ApprovalExpires, cutoff)))
	return n + m, err
}

// capability returns the catalogue entry named name.
func (p *Plugin) capability(name string) (Capability, bool) {
	for _, c := range p.capabilities {
		if c.Name == name {
			return c, true
		}
	}
	return Capability{}, false
}

// Configuration is the discovery document, protocol section 5.1.
type Configuration struct {
	Version         string            `json:"version"`
	ProviderName    string            `json:"provider_name"`
	Description     string            `json:"description"`
	Issuer          string            `json:"issuer"`
	DefaultLocation string            `json:"default_location"`
	Algorithms      []string          `json:"algorithms"`
	Modes           []Mode            `json:"modes"`
	ApprovalMethods []string          `json:"approval_methods"`
	Endpoints       map[string]string `json:"endpoints"`
}

// Configuration returns the discovery document.
func (p *Plugin) Configuration(ctx context.Context) (Configuration, error) {
	return p.configuration.Call(ctx, struct{}{})
}

func (p *Plugin) doConfiguration(context.Context, *auth.Call, struct{}) (Configuration, error) {
	paths := map[string]string{
		"register": PathRegister, "capabilities": PathListCapabilities, "describe_capability": PathDescribeCapability,
		"execute": PathExecute, "request_capability": PathRequestCapability, "status": PathStatus,
		"revoke": PathRevoke, "rotate_host_key": PathRotateHostKey, "introspect": PathIntrospect,
		"revoke_host": PathRevokeHost, "revoke_capability": PathRevokeCapability,
		"reactivate": PathReactivate, "rotate_agent_key": PathRotateAgentKey, "enroll_host": PathEnrollHost,
	}
	if slices.Contains(p.approvalMethods, MethodCIBA) {
		paths["ciba_authorize"] = PathCIBAAuthorize
	}
	if slices.Contains(p.modes, ModeAutonomous) {
		paths["claim"] = PathClaim
	}
	endpoints := make(map[string]string, len(paths))
	for k, path := range paths {
		endpoints[k] = p.issuer + path
	}
	return Configuration{
		Version: protocolVersion, ProviderName: p.providerName, Description: p.description, Issuer: p.issuer,
		DefaultLocation: p.issuer + PathExecute, Algorithms: p.algorithms, Modes: p.modes,
		ApprovalMethods: p.approvalMethods, Endpoints: endpoints,
	}, nil
}
