// Package deviceauth is the device authorization grant (RFC 8628): a client
// that cannot open a browser (a CLI, a TV, an IoT box) asks for a device code
// and a short user code, shows the user code and a link, and polls while the
// user signs in on another device and approves. The approval ends with a
// session of the approving user on the polling client.
//
// The flow, as five operations under the plugin name "device":
//
//	POST /device/code     the client gets device_code, user_code, the links, expires_in and interval
//	GET  /device/verify   the approval page checks a user code; a signed-in caller claims it
//	POST /device/approve  the claiming user approves
//	POST /device/deny     or denies
//	POST /device/token    the client polls: authorization_pending, slow_down, expired_token,
//	                      access_denied, or the session (access_token, token_type Bearer)
//
// Both codes are stored as SHA-256 hashes, so a database read hands nobody a
// pending approval, and a code is found by its hash alone. The approved row is
// spent by a conditional delete, so two polls racing for one approval end with
// one session. The error codes RFC 8628 names are answered in its own shape by
// CodeHandler and TokenHandler; the default authhttp.Handler answers the same
// operations in the library's error JSON.
package deviceauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity and its route prefix, so the
// routes are /device/code, /device/token, /device/approve.
const PluginName = "device"

// Operation ids, exported so a hook or a rate rule can name them.
const (
	EndpointCode    auth.EndpointID = "device.code"
	EndpointToken   auth.EndpointID = "device.token"
	EndpointVerify  auth.EndpointID = "device.verify"
	EndpointApprove auth.EndpointID = "device.approve"
	EndpointDeny    auth.EndpointID = "device.deny"
)

// GrantType is the grant_type a poll must send (RFC 8628 §3.4).
//
//ds:def id=deviceauth-granttype-7m3kq9wd owner=@khanakia stability=stable
const GrantType = "urn:ietf:params:oauth:grant-type:device_code"

// TokenType is the token_type of a successful poll: the session token is a
// bearer credential.
const TokenType = "Bearer"

// Defaults.
const (
	// DefaultExpiresIn is how long a device code can be approved and polled:
	// long enough to find a phone and sign in, short enough that a code
	// photographed off a screen is soon worthless.
	//ds:def id=deviceauth-defaultexpiresin-4p8wn2xk owner=@khanakia stability=stable
	DefaultExpiresIn = 30 * time.Minute
	// DefaultInterval is the least time between two polls; a faster poll
	// answers slow_down.
	//ds:def id=deviceauth-defaultinterval-9t2vk5qm owner=@khanakia stability=stable
	DefaultInterval = 5 * time.Second
	// SlowDownStep is what RFC 8628 §3.5 adds to the interval each time a
	// client polls too fast, "for this and all subsequent requests".
	//ds:def id=deviceauth-slowdownstep-3k8xq2nv owner=@khanakia stability=stable
	SlowDownStep = 5 * time.Second
	// DefaultDeviceCodeLength is 40 characters of [A-Za-z0-9], about 238
	// bits: the device code is the credential the poller holds.
	//ds:def id=deviceauth-defaultdevicecodelength-6w3mz8rq owner=@khanakia stability=stable
	DefaultDeviceCodeLength = 40
	// DefaultUserCodeLength is 8 characters of UserCodeAlphabet, 40 bits: a
	// person types it, and the verify rate limit and the code's short life
	// bound guessing.
	//ds:def id=deviceauth-defaultusercodelength-2n7kv4xp owner=@khanakia stability=stable
	DefaultUserCodeLength = 8
	// MaxCodeLength bounds both codes and a generator's output: 191 is the
	// longest key MySQL indexes in utf8mb4.
	//ds:def id=deviceauth-maxcodelength-8r4tw6zn owner=@khanakia stability=stable
	MaxCodeLength = 191
	// DefaultVerificationURI is the approval page, relative to the base URL.
	//ds:def id=deviceauth-defaultverificationuri-5q9xm3kt owner=@khanakia stability=stable
	DefaultVerificationURI = "/device"
	// verifyLimit verifications per IP per code lifetime, the rate rule on
	// /device: the user types one code, maybe twice; a loop
	// guessing 40-bit codes is a script.
	verifyLimit = 5
	// codeAttempts is how many fresh code pairs a request draws before it
	// answers server_error, when a generator keeps returning a code that is
	// still in use.
	codeAttempts = 3
	// maxScopeLength and maxClientIDLength fit the columns on every engine.
	maxScopeLength    = 4096
	maxClientIDLength = 191
)

// UserCodeAlphabet is the default user code alphabet: upper-case letters and
// digits without 0, O, 1 and I, which a person misreads.
//
//ds:def id=deviceauth-usercodealphabet-7v2qn8mk owner=@khanakia stability=stable
const UserCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// deviceCodeAlphabet is the default device code alphabet.
const deviceCodeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// Status is the state of a device code.
type Status string

// Statuses. A code starts pending, is approved or denied once, and is deleted
// by the poll that reads the decision.
const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
)

// StatusValues is the canonical iteration order over statuses.
var StatusValues = []Status{StatusPending, StatusApproved, StatusDenied}

// Table, alias and column names.
const (
	TableNameCode  = "auth_device_code"
	TableAliasCode = "dac"

	ColID              = "id"
	ColDeviceCodeHash  = "device_code_hash"
	ColUserCodeHash    = "user_code_hash"
	ColUserID          = "user_id"
	ColClientID        = "client_id"
	ColScope           = "scope"
	ColStatus          = "status"
	ColExpiresAt       = "expires_at"
	ColLastPolledAt    = "last_polled_at"
	ColPollingInterval = "polling_interval_ms"
	ColCreatedAt       = "created_at"
	// ColGrant names the Grant a code was issued through ("" for the
	// standalone flow); ColResource is its RFC 8707 resource.
	ColGrant    = "grant_name"
	ColResource = "resource"

	migrationName = "0001_device_code"
)

// TableCode is the device code table. Reads are open: an admin page may list
// pending approvals; writes go through the operations.
var TableCode = sqlb.Table{Name: TableNameCode, Alias: TableAliasCode}

// Typed columns of TableCode.
var (
	CodeID              = sqlb.Col[string](TableCode, ColID)
	CodeDeviceCodeHash  = sqlb.Col[[]byte](TableCode, ColDeviceCodeHash)
	CodeUserCodeHash    = sqlb.Col[[]byte](TableCode, ColUserCodeHash)
	CodeUserID          = sqlb.Col[*string](TableCode, ColUserID)
	CodeClientID        = sqlb.Col[string](TableCode, ColClientID)
	CodeScope           = sqlb.Col[string](TableCode, ColScope)
	CodeStatus          = sqlb.Col[Status](TableCode, ColStatus)
	CodeExpiresAt       = sqlb.Col[time.Time](TableCode, ColExpiresAt)
	CodeLastPolledAt    = sqlb.Col[*time.Time](TableCode, ColLastPolledAt)
	CodePollingInterval = sqlb.Col[int64](TableCode, ColPollingInterval)
	CodeCreatedAt       = sqlb.Col[time.Time](TableCode, ColCreatedAt)
	CodeGrant           = sqlb.Col[*string](TableCode, ColGrant)
	CodeResource        = sqlb.Col[*string](TableCode, ColResource)
)

// Configuration errors from auth.New.
var (
	ErrBadExpiresIn = errors.New("deviceauth: WithExpiresIn needs a positive duration")
	ErrBadInterval  = errors.New("deviceauth: WithInterval needs a positive duration")
	ErrBadLength    = fmt.Errorf("deviceauth: code lengths must be 1 to %d", MaxCodeLength)
	ErrBadLimit     = errors.New("deviceauth: WithVerifyLimit needs a positive limit and window")
)

// Request errors. Each is mapped to the RFC 8628 error code CodeHandler and
// TokenHandler answer (RFCErrorCode).
var (
	// ErrInvalidRequest is a missing client_id, a repeated parameter, a value
	// too long for its column, or a UserID set anywhere but Code.
	ErrInvalidRequest = auth.NewError("device.invalid_request", http.StatusBadRequest, "The request is missing a parameter or has a bad one.")
	// ErrUnsupportedGrantType is a poll with a grant_type other than GrantType.
	ErrUnsupportedGrantType = auth.NewError("device.unsupported_grant_type", http.StatusBadRequest, "The grant type is not supported.")
	// ErrInvalidClient is a client ValidateClient refused when asking for a code.
	ErrInvalidClient = auth.NewError("device.invalid_client", http.StatusBadRequest, "The client is not allowed to use device authorization.")
	// ErrInvalidDeviceCode is an unknown device code, a client that is not
	// the one the code was issued to, or a poll that lost the race for one
	// approval.
	ErrInvalidDeviceCode = auth.NewError("device.invalid_device_code", http.StatusBadRequest, "The device code is not valid.")
	// ErrExpiredDeviceCode is a poll after the code expired; the row is deleted.
	ErrExpiredDeviceCode = auth.NewError("device.expired_device_code", http.StatusBadRequest, "The device code has expired.")
	// ErrAuthorizationPending is a poll before the user decided.
	ErrAuthorizationPending = auth.NewError("device.authorization_pending", http.StatusBadRequest, "The user has not approved the request yet.")
	// ErrPollingTooFrequently is a poll within the interval; the interval
	// grows by SlowDownStep.
	ErrPollingTooFrequently = auth.NewError("device.polling_too_frequently", http.StatusBadRequest, "Polling too often. Wait longer between requests.")
	// ErrAccessDenied is a poll after the user denied; the row is deleted.
	ErrAccessDenied = auth.NewError("device.access_denied", http.StatusBadRequest, "The user denied the request.")
	// ErrNotOwner is an approve or deny by a user other than the one who
	// claimed the code.
	ErrNotOwner = auth.NewError("device.not_owner", http.StatusForbidden, "This code belongs to another account.")
	// ErrInvalidUserCode is an unknown user code on the approval page.
	ErrInvalidUserCode = auth.NewError("device.invalid_user_code", http.StatusBadRequest, "This code is not valid. Check it and try again.")
	// ErrExpiredUserCode is a user code past its expiry on the approval page.
	ErrExpiredUserCode = auth.NewError("device.expired_user_code", http.StatusBadRequest, "This code has expired. Start again on your device.")
	// ErrAlreadyProcessed is an approve or deny of a code already decided.
	ErrAlreadyProcessed = auth.NewError("device.already_processed", http.StatusBadRequest, "This code was already used.")
	// ErrNotClaimed is an approve or deny of a code no one has opened on the
	// approval page yet (GET verify while signed in claims it).
	ErrNotClaimed = auth.NewError("device.not_claimed", http.StatusBadRequest, "Open this code on the approval page first.")
	// ErrServerError is a generator that kept returning codes in use or too
	// long, or an approved code whose user is gone.
	ErrServerError = auth.NewError("device.server_error", http.StatusInternalServerError, "The request could not be completed.")
)

// Plugin is the device authorization plugin. Build it with New.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs        auth.OptionErrors
	expiresIn      time.Duration
	interval       time.Duration
	deviceLen      int
	userLen        int
	genDevice      Generator
	genUser        Generator
	validateClient func(ctx context.Context, clientID string) (bool, error)
	onRequest      func(ctx context.Context, clientID, scope string) error
	verifyURI      string
	verifyIP       limit
	grant          Grant
	core           *auth.Auth

	code    *auth.Op[CodeRequest, CodeResult]
	token   *auth.Op[TokenRequest, TokenResult]
	verify  *auth.Op[VerifyRequest, VerifyResult]
	approve *auth.Op[DecisionRequest, DecisionResult]
	deny    *auth.Op[DecisionRequest, DecisionResult]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// limit is one rate rule's numbers.
type limit struct {
	n      int
	window time.Duration
}

// Generator returns a new code (a device code or a user code). A result longer
// than MaxCodeLength fails the request.
type Generator func(ctx context.Context) (string, error)

// Option configures the plugin.
type Option func(*Plugin)

// WithExpiresIn overrides DefaultExpiresIn.
func WithExpiresIn(d time.Duration) Option { return func(p *Plugin) { p.expiresIn = d } }

// WithInterval overrides DefaultInterval.
func WithInterval(d time.Duration) Option { return func(p *Plugin) { p.interval = d } }

// DeviceCodeLength overrides DefaultDeviceCodeLength (1 to MaxCodeLength).
func DeviceCodeLength(n int) Option { return func(p *Plugin) { p.deviceLen = n } }

// UserCodeLength overrides DefaultUserCodeLength (1 to MaxCodeLength).
func UserCodeLength(n int) Option { return func(p *Plugin) { p.userLen = n } }

// GenerateDeviceCode replaces the random device code. Risk: the device code
// is the poller's credential; a guessable generator signs in whoever guesses.
func GenerateDeviceCode(fn Generator) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("deviceauth.GenerateDeviceCode", fn) {
			return
		}
		p.genDevice = fn
	}
}

// GenerateUserCode replaces the random user code. A custom code is matched
// exactly; only codes of the default alphabet are normalized (NormalizeUserCode).
func GenerateUserCode(fn Generator) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("deviceauth.GenerateUserCode", fn) {
			return
		}
		p.genUser = fn
	}
}

// ValidateClient allows only the client ids fn accepts: a refused id answers
// invalid_client at /device/code and invalid_grant at /device/token. Without it
// every client id is accepted.
func ValidateClient(fn func(ctx context.Context, clientID string) (bool, error)) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("deviceauth.ValidateClient", fn) {
			return
		}
		p.validateClient = fn
	}
}

// OnDeviceAuthRequest runs fn on every code request before a code is drawn;
// an error fails the request.
func OnDeviceAuthRequest(fn func(ctx context.Context, clientID, scope string) error) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("deviceauth.OnDeviceAuthRequest", fn) {
			return
		}
		p.onRequest = fn
	}
}

// VerificationURI overrides DefaultVerificationURI, the page a user opens. An
// absolute URL is used as is; a relative one is resolved against the
// request's base URL.
func VerificationURI(u string) Option { return func(p *Plugin) { p.verifyURI = u } }

// WithVerifyLimit replaces the default of 5 verifications per IP per code
// lifetime.
func WithVerifyLimit(n int, window time.Duration) Option {
	return func(p *Plugin) { p.verifyIP = limit{n, window} }
}

// Grant is an extension that issues codes on behalf of another token endpoint
// (an OAuth provider). It authorizes each /device/code request instead of
// ValidateClient (authenticating a confidential client, checking scope and
// resource) and names itself in the Binding; a code bound to a grant is
// redeemed only through Redeem with that name, never for a session at
// /device/token. A Binding with an empty Grant leaves the request to the
// standalone flow.
//
//ds:def id=deviceauth-grant-7k3qm9wv owner=@khanakia stability=stable
type Grant interface {
	AuthorizeCode(ctx context.Context, c *auth.Call, in CodeRequest) (Binding, error)
}

// Binding is a Grant's decision for one code request.
type Binding struct {
	Grant    string
	Resource string
	// Scope, when set, is the scope stored on the device code in place of
	// the requested one: the grant's narrowed scopes (a resource's
	// allowlist), so the approval page shows what will be granted.
	Scope string
}

// WithGrant installs a Grant; only one device authorization integration is
// allowed.
func WithGrant(g Grant) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("deviceauth.WithGrant", g) {
			return
		}
		p.grant = g
	}
}

// Compile-time proof of each capability.
var (
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.RateLimiter       = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.TableOwner        = (*Plugin)(nil)
	_ auth.UserTableOwner    = (*Plugin)(nil)
	_ auth.TypedMigrator     = (*Plugin)(nil)
	_ auth.Sweeper           = (*Plugin)(nil)
)

// New builds the plugin with the defaults above.
func New(opts ...Option) *Plugin {
	p := &Plugin{
		expiresIn: DefaultExpiresIn, interval: DefaultInterval,
		deviceLen: DefaultDeviceCodeLength, userLen: DefaultUserCodeLength,
		verifyURI: DefaultVerificationURI,
	}
	for _, o := range opts {
		o(p)
	}
	if p.verifyIP.n == 0 && p.verifyIP.window == 0 {
		p.verifyIP = limit{verifyLimit, p.expiresIn}
	}
	p.code = auth.Define(auth.OpInfo{ID: EndpointCode, Kind: auth.Mutation, Require: auth.Public, Path: "/code"}, p.doCode)
	p.token = auth.Define(auth.OpInfo{ID: EndpointToken, Kind: auth.Mutation, Require: auth.Public, Path: "/token", SignIn: true}, p.doToken)
	p.verify = auth.Define(auth.OpInfo{ID: EndpointVerify, Kind: auth.Query, Require: auth.Public, Path: "/verify"}, p.doVerify)
	p.approve = auth.Define(auth.OpInfo{ID: EndpointApprove, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/approve"}, p.decide(StatusApproved))
	p.deny = auth.Define(auth.OpInfo{ID: EndpointDeny, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/deny"}, p.decide(StatusDenied))
	return p
}

// Name returns PluginName.
func (p *Plugin) Name() string { return PluginName }

// Validate refuses lifetimes and lengths nobody could use.
func (p *Plugin) Validate(*auth.Config) error {
	switch {
	case p.expiresIn <= 0:
		return ErrBadExpiresIn
	case p.interval <= 0:
		return ErrBadInterval
	case p.deviceLen < 1 || p.deviceLen > MaxCodeLength:
		return fmt.Errorf("%w: deviceauth.DeviceCodeLength(%d)", ErrBadLength, p.deviceLen)
	case p.userLen < 1 || p.userLen > MaxCodeLength:
		return fmt.Errorf("%w: deviceauth.UserCodeLength(%d)", ErrBadLength, p.userLen)
	case p.verifyIP.n < 1 || p.verifyIP.window <= 0:
		return ErrBadLimit
	}
	return nil
}

// Init captures the core handle.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	return nil
}

// Tables declares the device code table.
func (p *Plugin) Tables() []sqlb.Table { return []sqlb.Table{TableCode} }

// UserTables declares that a claimed code belongs to its user, so DeleteUser
// removes it (no foreign key does, ADR-0002).
func (p *Plugin) UserTables() []auth.UserTable {
	return []auth.UserTable{{Table: TableCode, Column: ColUserID}}
}

// Operations lists the five operations.
func (p *Plugin) Operations() []auth.Operation {
	return []auth.Operation{p.code, p.token, p.verify, p.approve, p.deny}
}

// RateLimits bounds user-code guessing on the approval page, the rule on
// /device. Polling is bounded by slow_down instead, and the device
// code is too long to guess.
func (p *Plugin) RateLimits() []auth.RateRule {
	return []auth.RateRule{{Match: EndpointVerify, Key: auth.ByIP, Limit: p.verifyIP.n, Window: p.verifyIP.window}}
}

// TypedMigrations creates the device code table.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	st := []string{
		"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableCode) + " (" +
			ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColDeviceCodeHash + " " + t.Hash + " NOT NULL UNIQUE, " +
			ColUserCodeHash + " " + t.Hash + " NOT NULL UNIQUE, " +
			ColUserID + " " + t.ID + " NULL, " +
			ColClientID + " " + t.Key + " NOT NULL, " +
			ColScope + " " + t.Long + " NOT NULL, " +
			ColStatus + " " + t.Key + " NOT NULL, " +
			ColExpiresAt + " " + t.Timestamp + " NOT NULL, " +
			ColLastPolledAt + " " + t.Timestamp + " NULL, " +
			ColPollingInterval + " " + t.Int + " NOT NULL, " +
			ColGrant + " " + t.Key + " NULL, " +
			ColResource + " " + t.Long + " NULL, " +
			ColCreatedAt + " " + t.Timestamp + " NOT NULL)" + t.TableSuffix,
	}
	return []auth.Migration{{Owner: PluginName, Name: migrationName, Statements: st}}, nil
}

// Sweep deletes codes that expired before cutoff; a poll deletes the ones it
// sees expire, and this catches the clients that stopped polling.
func (p *Plugin) Sweep(ctx context.Context, cutoff time.Time) (int64, error) {
	return p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableCode).Where(sqlb.Less(CodeExpiresAt, cutoff)))
}

// CodeRequest is the input of /device/code. UserID pre-binds the code to one
// user: only that user may approve or deny it, and no claim is needed. It
// is set from Go (Code) only, because it is meant for server-side use and a
// client has no business naming a user: it is not part of the wire (json:"-"),
// so no transport decodes it, the generated clients never offer it, and the RFC
// handlers ignore a user_id parameter as RFC 6749 section 3.2 says to treat an
// unrecognized one. An operation reached any other way than Code
// (Operation.Invoke with a decoder that sets it) is still refused with
// ErrInvalidRequest.
//
//ds:def id=deviceauth-coderequest-3w8nk5qv owner=@khanakia stability=stable
type CodeRequest struct {
	ClientID string `json:"client_id"`
	Scope    string `json:"scope,omitempty"`
	UserID   string `json:"-"`
	// Confidential-client credentials and the RFC 8707 resource, read only
	// by a Grant (WithGrant); the standalone flow ignores them.
	ClientSecret        string `json:"client_secret,omitempty"`
	ClientAssertion     string `json:"client_assertion,omitempty"`
	ClientAssertionType string `json:"client_assertion_type,omitempty"`
	Resource            string `json:"resource,omitempty"`
}

// CodeResult is the answer of /device/code, RFC 8628 §3.2. The device code
// is the poller's credential and goes to that client only; the user code is
// what the user types. Durations are whole seconds.
//
//ds:def id=deviceauth-coderesult-8k2xm4wr owner=@khanakia stability=stable
type CodeResult struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// TokenRequest is a poll of /device/token, RFC 8628 §3.4.
//
//ds:def id=deviceauth-tokenrequest-6n4qw8km owner=@khanakia stability=stable
type TokenRequest struct {
	GrantType  string `json:"grant_type"`
	DeviceCode string `json:"device_code"`
	ClientID   string `json:"client_id"`
}

// TokenResult is the answer of an approved poll, RFC 6749 §5.1: the new
// session's token, carried in the body because handing it to a client with
// no cookie jar is the operation's purpose. A cookie or bearer header is set
// as well, as on every sign-in.
//
//ds:def id=deviceauth-tokenresult-2v9kt5xq owner=@khanakia stability=stable
type TokenResult struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	// UserID is the signed-in user, for a Go caller; not part of the RFC answer.
	UserID string `json:"-"`
}

// VerifyRequest is the input of the approval page's lookup.
type VerifyRequest struct {
	UserCode string `json:"user_code"`
}

// VerifyResult is what the approval page shows. ClientID and Scope are given
// only to the user the code belongs to, so a stranger who types a code learns
// nothing about the client that asked.
//
//ds:def id=deviceauth-verifyresult-5m8qz3wn owner=@khanakia stability=stable
type VerifyResult struct {
	UserCode string `json:"user_code"`
	Status   Status `json:"status"`
	ClientID string `json:"client_id,omitempty"`
	Scope    string `json:"scope,omitempty"`
	// Resource is the RFC 8707 resource of a code issued through a Grant.
	Resource string `json:"resource,omitempty"`
	// Owned is true when the code belongs to the caller: claimed now, or
	// earlier, or pre-bound.
	Owned bool `json:"owned"`
}

// DecisionRequest is the input of approve and deny.
type DecisionRequest struct {
	UserCode string `json:"userCode"`
}

// DecisionResult is the answer of approve and deny.
type DecisionResult struct {
	Success bool `json:"success"`
}

// Code asks for a device code from Go, through the same operation as the
// route. Only this path may set UserID.
//
//ds:def id=deviceauth-plugin-code-4x7wn2kq owner=@khanakia stability=stable
func (p *Plugin) Code(ctx context.Context, in CodeRequest) (CodeResult, error) {
	return p.code.Call(context.WithValue(ctx, fromGoKey{}, true), in)
}

// Token polls for the session from Go.
func (p *Plugin) Token(ctx context.Context, in TokenRequest) (TokenResult, error) {
	return p.token.Call(ctx, in)
}

// Verify looks a user code up, claiming it for the signed-in caller.
func (p *Plugin) Verify(ctx context.Context, userCode string) (VerifyResult, error) {
	return p.verify.Call(ctx, VerifyRequest{UserCode: userCode})
}

// Approve approves a claimed code as the signed-in caller.
func (p *Plugin) Approve(ctx context.Context, userCode string) error {
	_, err := p.approve.Call(ctx, DecisionRequest{UserCode: userCode})
	return err
}

// Deny denies a claimed code as the signed-in caller.
func (p *Plugin) Deny(ctx context.Context, userCode string) error {
	_, err := p.deny.Call(ctx, DecisionRequest{UserCode: userCode})
	return err
}

// fromGoKey marks a ctx that reached the code operation through Code.
type fromGoKey struct{}

// hashCode is the stored form of a code. A plain SHA-256 is enough: the
// device code has ~238 bits, and the user code lives minutes behind a rate
// limit; the hash keeps a database read from handing out live codes.
func hashCode(code string) []byte {
	h := sha256.Sum256([]byte(code))
	return h[:]
}

// row is one device code as the operations read it.
type row struct {
	id, clientID, scope string
	userID              *string
	status              Status
	expiresAt           time.Time
	lastPolledAt        *time.Time
	grant, resource     *string
	intervalMS          int64
}

// find loads the row whose code hash matches.
func (p *Plugin) find(ctx context.Context, col sqlb.Expr[[]byte], hash []byte) (row, bool, error) {
	var r row
	q := p.core.Select().Columns(
		sqlb.Bind(CodeID, &r.id), sqlb.Bind(CodeClientID, &r.clientID), sqlb.Bind(CodeScope, &r.scope),
		sqlb.Bind(CodeUserID, &r.userID), sqlb.Bind(CodeStatus, &r.status), sqlb.Bind(CodeExpiresAt, &r.expiresAt),
		sqlb.Bind(CodeLastPolledAt, &r.lastPolledAt), sqlb.Bind(CodePollingInterval, &r.intervalMS),
		sqlb.Bind(CodeGrant, &r.grant), sqlb.Bind(CodeResource, &r.resource),
	).From(TableCode).Where(sqlb.Eq(col, hash)).Limit(1)
	if err := p.core.One(ctx, q); err != nil {
		if errors.Is(err, sqlb.ErrNoRows) {
			return row{}, false, nil
		}
		return row{}, false, err
	}
	return r, true, nil
}

// doCode issues a code pair.
func (p *Plugin) doCode(ctx context.Context, c *auth.Call, in CodeRequest) (CodeResult, error) {
	fromGo, _ := ctx.Value(fromGoKey{}).(bool)
	if in.UserID != "" && !fromGo {
		return CodeResult{}, ErrInvalidRequest
	}
	if in.ClientID == "" || len(in.ClientID) > maxClientIDLength || len(in.Scope) > maxScopeLength {
		return CodeResult{}, ErrInvalidRequest
	}
	var bound Binding
	if p.grant != nil {
		b, err := p.grant.AuthorizeCode(ctx, c, in)
		if err != nil {
			return CodeResult{}, err
		}
		bound = b
	}
	if bound.Grant == "" {
		if err := p.checkClient(ctx, in.ClientID, ErrInvalidClient); err != nil {
			return CodeResult{}, err
		}
	}
	if p.onRequest != nil {
		if err := p.onRequest(ctx, in.ClientID, in.Scope); err != nil {
			return CodeResult{}, err
		}
	}
	if in.UserID != "" {
		if _, err := c.Auth.User(ctx, in.UserID); err != nil {
			return CodeResult{}, err
		}
	}
	device, user, err := p.drawCodes(ctx)
	if err != nil {
		return CodeResult{}, err
	}
	id, err := c.Auth.NewID("dvc")
	if err != nil {
		return CodeResult{}, err
	}
	now := c.Auth.Now()
	var owner *string
	if in.UserID != "" {
		owner = &in.UserID
	}
	ins := sqlb.NewInsert(c.Auth.Dialect()).Into(TableCode).Row(
		sqlb.Set(CodeID, id), sqlb.Set(CodeDeviceCodeHash, hashCode(device)), sqlb.Set(CodeUserCodeHash, hashCode(p.normalize(user))),
		sqlb.Set(CodeUserID, owner), sqlb.Set(CodeClientID, in.ClientID), sqlb.Set(CodeScope, boundScope(in.Scope, bound)),
		sqlb.Set(CodeStatus, StatusPending), sqlb.Set(CodeExpiresAt, now.Add(p.expiresIn)),
		sqlb.Set(CodeLastPolledAt, nil), sqlb.Set(CodePollingInterval, p.interval.Milliseconds()), sqlb.Set(CodeCreatedAt, now),
		sqlb.Set(CodeGrant, optional(bound.Grant)), sqlb.Set(CodeResource, optional(bound.Resource)),
	)
	if _, err := c.Auth.Exec(ctx, ins); err != nil {
		return CodeResult{}, err
	}
	c.Effects.Header("Cache-Control", "no-store")
	base := p.verificationURI(ctx)
	return CodeResult{
		DeviceCode: device, UserCode: user,
		VerificationURI: base, VerificationURIComplete: withUserCode(base, user),
		ExpiresIn: int(p.expiresIn / time.Second), Interval: int(p.interval / time.Second),
	}, nil
}

// checkClient runs ValidateClient, answering refused for an id it rejects.
func (p *Plugin) checkClient(ctx context.Context, clientID string, refused error) error {
	if p.validateClient == nil {
		return nil
	}
	ok, err := p.validateClient(ctx, clientID)
	if err != nil {
		return err
	}
	if !ok {
		return refused
	}
	return nil
}

// drawCodes draws a code pair whose hashes no row holds yet, up to
// codeAttempts times. The check runs before the insert because a failed
// insert aborts the whole transaction on Postgres, so a unique violation
// cannot be caught and retried; the default codes never collide in practice,
// a custom generator might.
func (p *Plugin) drawCodes(ctx context.Context) (device, user string, err error) {
	for range codeAttempts {
		if device, err = p.generate(ctx, p.genDevice, deviceCodeAlphabet, p.deviceLen); err != nil {
			return "", "", err
		}
		if user, err = p.generate(ctx, p.genUser, UserCodeAlphabet, p.userLen); err != nil {
			return "", "", err
		}
		var n int64
		q := p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableCode).Where(sqlb.Or(
			sqlb.Eq(CodeDeviceCodeHash, hashCode(device)), sqlb.Eq(CodeUserCodeHash, hashCode(p.normalize(user))),
		))
		if err := p.core.One(ctx, q); err != nil {
			return "", "", err
		}
		if n == 0 {
			return device, user, nil
		}
	}
	return "", "", ErrServerError
}

// generate runs a custom generator, or draws n characters of alphabet.
func (p *Plugin) generate(ctx context.Context, fn Generator, alphabet string, n int) (string, error) {
	if fn == nil {
		return randomString(alphabet, n), nil
	}
	s, err := fn(ctx)
	if err != nil {
		return "", fmt.Errorf("deviceauth: generate code: %w", err)
	}
	if s == "" || len(s) > MaxCodeLength {
		return "", ErrServerError
	}
	return s, nil
}

// normalize is the form a user code is hashed in: NormalizeUserCode for the
// default alphabet, the code as typed for a custom generator's.
func (p *Plugin) normalize(code string) string {
	if p.genUser != nil {
		return code
	}
	return NormalizeUserCode(code)
}

// NormalizeUserCode upper-cases a default-alphabet user code and drops every
// character outside its alphabet, so "wdjb-mjht" and "WDJB MJHT" match
// WDJBMJHT.
//
//ds:def id=deviceauth-normalizeusercode-9q3wk7xm owner=@khanakia stability=stable
func NormalizeUserCode(code string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(code) {
		if strings.ContainsRune(UserCodeAlphabet, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// verificationURI resolves the page link against the request's base URL.
func (p *Plugin) verificationURI(ctx context.Context) string {
	u, err := url.Parse(p.verifyURI)
	if err != nil || u.IsAbs() {
		return p.verifyURI
	}
	base, err := url.Parse(p.core.BaseURL(ctx))
	if err != nil || !base.IsAbs() {
		return p.verifyURI
	}
	return base.ResolveReference(u).String()
}

// withUserCode is RFC 8628's verification_uri_complete: the page link with
// the user code in its query.
func withUserCode(link, code string) string {
	u, err := url.Parse(link)
	if err != nil {
		return link
	}
	q := u.Query()
	q.Set("user_code", code)
	u.RawQuery = q.Encode()
	return u.String()
}

// doToken is the session redemption at /device/token.
func (p *Plugin) doToken(ctx context.Context, c *auth.Call, in TokenRequest) (TokenResult, error) {
	if in.GrantType != GrantType {
		return TokenResult{}, ErrUnsupportedGrantType
	}
	red, err := p.redeem(ctx, in.DeviceCode, in.ClientID, "")
	if err != nil {
		return TokenResult{}, err
	}
	// The approving session passed every factor, so the new one skips the
	// second factor, as a hand-off does.
	s, tok, err := c.Auth.CreateMultiFactorSession(ctx, red.UserID, c.Client)
	if err != nil {
		return TokenResult{}, err
	}
	c.Effects.IssueSessionOf(s, tok)
	c.Effects.Header("Cache-Control", "no-store")
	return TokenResult{
		AccessToken: tok.Reveal(), TokenType: TokenType,
		ExpiresIn: max(0, int(s.ExpiresAt.Sub(c.Auth.Now())/time.Second)), Scope: red.Scope, UserID: red.UserID,
	}, nil
}

// Redemption is an approved device code, spent: the user who approved it,
// the scope and the resource it was issued for.
//
//ds:def id=deviceauth-redemption-5w2kq8xn owner=@khanakia stability=stable
type Redemption struct {
	UserID   string
	Scope    string
	Resource string
}

// Redeem runs the polling state machine for a Grant's own token endpoint:
// the same answers as /device/token (ErrAuthorizationPending,
// ErrPollingTooFrequently, ErrExpiredDeviceCode, ErrAccessDenied,
// ErrInvalidDeviceCode), and, for an approved code issued through the Grant
// named grant, the spent code's Redemption. A code issued through another
// grant, or the standalone flow, is ErrInvalidDeviceCode. It must run inside
// the caller's operation (its context), whose transaction the spend joins.
//
//ds:def id=deviceauth-plugin-redeem-3n8vk2qw owner=@khanakia stability=stable
func (p *Plugin) Redeem(ctx context.Context, deviceCode, clientID, grant string) (Redemption, error) {
	if grant == "" {
		return Redemption{}, ErrInvalidRequest
	}
	return p.redeem(ctx, deviceCode, clientID, grant)
}

// redeem is the polling state machine shared by /device/token (grant "")
// and Redeem.
func (p *Plugin) redeem(ctx context.Context, deviceCode, clientID, grant string) (Redemption, error) {
	if deviceCode == "" || clientID == "" {
		return Redemption{}, ErrInvalidRequest
	}
	r, ok, err := p.find(ctx, CodeDeviceCodeHash, hashCode(deviceCode))
	if err != nil {
		return Redemption{}, err
	}
	// A code is redeemed only where it was issued: an OAuth-bound code
	// never yields a session at /device/token, nor a standalone one tokens.
	if !ok || r.clientID != clientID || deref(r.grant) != grant {
		return Redemption{}, ErrInvalidDeviceCode
	}
	if grant == "" {
		if err := p.checkClient(ctx, clientID, ErrInvalidDeviceCode); err != nil {
			return Redemption{}, err
		}
	}
	d := p.core.Dialect()
	now := p.core.Now()
	if !now.Before(r.expiresAt) {
		p.afterTx(ctx, sqlb.NewDelete(d).From(TableCode).Where(sqlb.Eq(CodeID, r.id)))
		return Redemption{}, ErrExpiredDeviceCode
	}
	interval := time.Duration(r.intervalMS) * time.Millisecond
	if r.lastPolledAt != nil && now.Sub(*r.lastPolledAt) < interval {
		// RFC 8628 §3.5: the interval grows for this and every later poll.
		// Written after the transaction, which the error rolls back.
		p.afterTx(ctx, sqlb.NewUpdate(d).Table(TableCode).
			Set(sqlb.Set(CodeLastPolledAt, &now), sqlb.Set(CodePollingInterval, (interval+SlowDownStep).Milliseconds())).
			Where(sqlb.Eq(CodeID, r.id)))
		return Redemption{}, ErrPollingTooFrequently
	}
	switch r.status {
	case StatusPending:
		p.afterTx(ctx, sqlb.NewUpdate(d).Table(TableCode).Set(sqlb.Set(CodeLastPolledAt, &now)).Where(sqlb.Eq(CodeID, r.id)))
		return Redemption{}, ErrAuthorizationPending
	case StatusDenied:
		p.afterTx(ctx, sqlb.NewDelete(d).From(TableCode).Where(sqlb.Eq(CodeID, r.id)))
		return Redemption{}, ErrAccessDenied
	case StatusApproved:
	default:
		return Redemption{}, ErrServerError
	}
	if r.userID == nil {
		return Redemption{}, ErrServerError
	}
	// The conditional delete is the claim: of two polls racing for one
	// approval, only the one whose delete removed the row gets a session.
	n, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableCode).Where(sqlb.Eq(CodeID, r.id), sqlb.Eq(CodeStatus, StatusApproved)))
	if err != nil {
		return Redemption{}, err
	}
	if n != 1 {
		return Redemption{}, ErrInvalidDeviceCode
	}
	if _, err := p.core.User(ctx, *r.userID); err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			return Redemption{}, ErrServerError
		}
		return Redemption{}, err
	}
	return Redemption{UserID: *r.userID, Scope: r.scope, Resource: deref(r.resource)}, nil
}

// optional is a non-empty value, nil for an empty one.
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// deref is *s, "" for nil.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// afterTx runs a write once the call's transaction ends, committed or not:
// the poll's error rolls the transaction back, and the poll time, the grown
// interval and the deletion of a spent row must still land.
func (p *Plugin) afterTx(ctx context.Context, s auth.Statement) {
	p.core.AfterTx(ctx, func(ctx context.Context) {
		if _, err := p.core.Exec(ctx, s); err != nil {
			p.core.Logger().Error("deviceauth: record poll", "error", err)
		}
	})
}

// signedIn returns the caller's user id when a full, non-API-key session is
// present, the only kind that may claim a code.
func signedIn(c *auth.Call) (string, bool) {
	if c.Session == nil || c.User == nil || c.Session.SecondFactorPending || c.Session.APIKeyID != "" {
		return "", false
	}
	return c.User.ID, true
}

// doVerify looks a user code up and, for a signed-in caller, claims a pending
// unbound code atomically.
func (p *Plugin) doVerify(ctx context.Context, c *auth.Call, in VerifyRequest) (VerifyResult, error) {
	code := p.normalize(in.UserCode)
	if code == "" {
		return VerifyResult{}, ErrInvalidUserCode
	}
	r, ok, err := p.find(ctx, CodeUserCodeHash, hashCode(code))
	if err != nil {
		return VerifyResult{}, err
	}
	if !ok {
		return VerifyResult{}, ErrInvalidUserCode
	}
	if !c.Auth.Now().Before(r.expiresAt) {
		return VerifyResult{}, ErrExpiredUserCode
	}
	out := VerifyResult{UserCode: in.UserCode, Status: r.status}
	uid, signed := signedIn(c)
	if !signed {
		return out, nil
	}
	if r.userID == nil && r.status == StatusPending {
		n, err := c.Auth.Exec(ctx, sqlb.NewUpdate(c.Auth.Dialect()).Table(TableCode).Set(sqlb.Set(CodeUserID, &uid)).
			Where(sqlb.Eq(CodeID, r.id), sqlb.IsNull(CodeUserID), sqlb.Eq(CodeStatus, StatusPending)))
		if err != nil {
			return VerifyResult{}, err
		}
		if n == 1 {
			r.userID = &uid
		}
	}
	if r.userID != nil && *r.userID == uid {
		out.Owned, out.ClientID, out.Scope, out.Resource = true, r.clientID, r.scope, deref(r.resource)
	}
	return out, nil
}

// decide returns approve or deny: the code must be pending, claimed and the
// caller's, and the update repeats each condition, so a decision races
// nothing.
func (p *Plugin) decide(to Status) func(context.Context, *auth.Call, DecisionRequest) (DecisionResult, error) {
	return func(ctx context.Context, c *auth.Call, in DecisionRequest) (DecisionResult, error) {
		code := p.normalize(in.UserCode)
		if code == "" {
			return DecisionResult{}, ErrInvalidUserCode
		}
		r, ok, err := p.find(ctx, CodeUserCodeHash, hashCode(code))
		if err != nil {
			return DecisionResult{}, err
		}
		switch {
		case !ok:
			return DecisionResult{}, ErrInvalidUserCode
		case !c.Auth.Now().Before(r.expiresAt):
			return DecisionResult{}, ErrExpiredUserCode
		case r.status != StatusPending:
			return DecisionResult{}, ErrAlreadyProcessed
		case r.userID == nil:
			return DecisionResult{}, ErrNotClaimed
		case *r.userID != c.User.ID:
			return DecisionResult{}, ErrNotOwner
		}
		n, err := c.Auth.Exec(ctx, sqlb.NewUpdate(c.Auth.Dialect()).Table(TableCode).Set(sqlb.Set(CodeStatus, to)).
			Where(sqlb.Eq(CodeID, r.id), sqlb.Eq(CodeStatus, StatusPending), sqlb.Eq(CodeUserID, &c.User.ID)))
		if err != nil {
			return DecisionResult{}, err
		}
		if n != 1 {
			return DecisionResult{}, ErrAlreadyProcessed
		}
		return DecisionResult{Success: true}, nil
	}
}

// boundScope is the scope a device code stores: the grant's narrowed scope
// when it set one, the requested scope otherwise.
func boundScope(requested string, b Binding) string {
	if b.Scope != "" {
		return b.Scope
	}
	return requested
}
