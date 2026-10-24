// Package passkey signs users in with passkeys (WebAuthn discoverable
// credentials), and lets a signed-in user add and remove them.
//
// It is a separate module because it wraps github.com/go-webauthn/webauthn,
// whose CBOR, JWT and TPM dependencies no app without passkeys should
// inherit. The WebAuthn protocol lives in that library; this plugin owns the
// storage, the ceremonies' state, and the rules: a ceremony is a single-use
// core verification token, user verification is required, and a passkey
// sign-in is multi-factor by itself.
package passkey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity. It owns the plugin's rows in
// the migration ledger and its tables and columns, so renaming it would make
// the next migrate see a new plugin; it never changes.
const PluginName = "passkey"

// Operation ids, the permanent names hooks, rate rules and transports address
// the plugin's operations by.
const (
	EndpointRegisterBegin  auth.EndpointID = "passkey.register-begin"
	EndpointRegisterFinish auth.EndpointID = "passkey.register-finish"
	EndpointLoginBegin     auth.EndpointID = "passkey.login-begin"
	EndpointLoginFinish    auth.EndpointID = "passkey.login-finish"
	EndpointList           auth.EndpointID = "passkey.list"
	EndpointRemove         auth.EndpointID = "passkey.remove"
	EndpointRename         auth.EndpointID = "passkey.rename"
	// EndpointSignUpBegin and EndpointSignUpFinish create an account with a
	// passkey as its first credential, with no session; they exist only
	// with WithSignUp.
	EndpointSignUpBegin  auth.EndpointID = "passkey.sign-up-begin"
	EndpointSignUpFinish auth.EndpointID = "passkey.sign-up-finish"
)

// Operation paths under the auth mount. Unexported because a transport reads
// them from each operation's OpInfo, never by name.
const (
	pathRegisterBegin  = "/register-begin"
	pathRegisterFinish = "/register-finish"
	pathLoginBegin     = "/login-begin"
	pathLoginFinish    = "/login-finish"
	pathList           = "/list"
	pathRemove         = "/remove"
	pathRename         = "/rename"
	pathSignUpBegin    = "/sign-up-begin"
	pathSignUpFinish   = "/sign-up-finish"
)

// Ceremony purposes. A register ceremony's Identifier is the user id; a login
// ceremony's is empty, because a discoverable login does not know the user
// until the authenticator answers, or the signed-in user's id under
// AllowCredentialsForSession. Meta is the JSON of webauthn.SessionData.
const (
	PurposeRegister auth.Purpose = "passkey.register"
	PurposeLogin    auth.Purpose = "passkey.login"
	// PurposeSignUp is a passkey-first sign-up ceremony. Its Identifier is
	// the id the new user will have, minted at begin so the authenticator's
	// user handle equals the user id; Meta is the JSON of signUpMeta.
	PurposeSignUp auth.Purpose = "passkey.sign-up"
)

// The plugin's table: one row per registered passkey, looked up by user for
// the list and by credential id (unique) at sign-in.
const (
	//ds:def id=tablenamepasskey-euzk3h7u owner=@khanakia stability=stable
	TableNamePasskey  = "auth_passkey"
	TableAliasPasskey = "pk"
	ColID             = "id"
	ColUserID         = "user_id"
	ColCredentialID   = "credential_id"
	// ColCredential holds the whole webauthn.Credential as JSON: public key,
	// sign count, flags, attestation. The library owns its shape and can read
	// its older forms, so the plugin does not split it into columns.
	ColCredential = "credential_json"
	ColName       = "name"
	ColCreatedAt  = "created_at"
	ColLastUsedAt = "last_used_at"
)

// Typed columns, for an app that reads the table (reads are open; only the
// plugin writes it).
var (
	TablePasskey = sqlb.Table{Name: TableNamePasskey, Alias: TableAliasPasskey}
	PasskeyID    = sqlb.Col[string](TablePasskey, ColID)
	UserID       = sqlb.Col[string](TablePasskey, ColUserID)
	CredentialID = sqlb.Col[[]byte](TablePasskey, ColCredentialID)
	Credential   = sqlb.Col[string](TablePasskey, ColCredential)
	Name         = sqlb.Col[string](TablePasskey, ColName)
	CreatedAt    = sqlb.Col[time.Time](TablePasskey, ColCreatedAt)
	LastUsedAt   = sqlb.Col[*time.Time](TablePasskey, ColLastUsedAt)
)

const (
	idPrefix = "pky"
	// maxNameLength bounds a passkey's label; longer names are cut. 64
	// characters is a device name with room to spare, and short enough to
	// lay out in a list.
	maxNameLength = 64
	// indexUserSuffix, after the table's real name, names the index on
	// user_id that the list reads.
	indexUserSuffix = "_user_idx"
)

// DefaultDisplayName is the app name the browser's passkey prompt shows
// without DisplayName.
//
//ds:def id=defaultdisplayname-tx633s6x owner=@khanakia stability=stable
const DefaultDisplayName = "App"

// Rate limit on login-begin, the one public operation that writes: every call
// stores a ceremony row. A real sign-in needs one ceremony, and a retry or two
// after a cancelled prompt; 30 a minute per IP leaves room for an office
// behind one address while bounding how fast one client can fill the table.
const (
	//ds:def id=loginbeginiplimit-n9fa89bj owner=@khanakia stability=stable
	loginBeginIPLimit  = 30
	loginBeginIPWindow = time.Minute
	// signUpIPLimit bounds passkey-first sign-up per IP, like password
	// sign-up: every finished ceremony creates an account.
	//ds:def id=passkey-signupiplimit-w8qm3kd2 owner=@khanakia stability=stable
	signUpIPLimit  = 10
	signUpIPWindow = time.Hour
)

// Requirement is a WebAuthn requirement level, for the resident-key and
// user-verification choices of AuthenticatorSelection.
type Requirement string

// The three WebAuthn requirement levels (WebAuthn §5.4.6, §5.8.6).
const (
	RequirementRequired    Requirement = "required"
	RequirementPreferred   Requirement = "preferred"
	RequirementDiscouraged Requirement = "discouraged"
)

// RequirementValues is the canonical iteration order over requirement levels.
var RequirementValues = []Requirement{RequirementRequired, RequirementPreferred, RequirementDiscouraged}

// Selection is what the relying party asks of an authenticator. An empty
// field keeps the plugin's default, RequirementRequired for both levels and
// any attachment. A request's own AuthenticatorAttachment still narrows the
// attachment per registration.
//
//ds:def id=passkey-selection-6tq2nw8k owner=@khanakia stability=stable
type Selection struct {
	// ResidentKey asks for a discoverable credential, the kind a sign-in
	// with no identifier can find. Below required, a passkey may be
	// non-discoverable and then signs in only under
	// AllowCredentialsForSession, which names it to the browser.
	ResidentKey Requirement
	// UserVerification asks for a PIN or a biometric. Below required, a
	// sign-in whose authenticator did not verify the user is one factor:
	// it goes through the second-factor step like a password.
	UserVerification Requirement
	// Attachment is AttachmentPlatform or AttachmentCrossPlatform, or ""
	// for either.
	Attachment string
}

// DefaultCeremonyTTL is how long a user has to touch the authenticator.
//
//ds:def id=defaultceremonyttl-whet8mch owner=@khanakia stability=stable
const DefaultCeremonyTTL = 5 * time.Minute

// Errors. The *auth.Error values are what a client sees; ErrNoRelyingParty is
// a configuration mistake auth.New refuses at start-up.
var (
	ErrCeremonyInvalid = auth.NewError("passkey.ceremony_invalid", http.StatusBadRequest, "This passkey request has expired. Try again.")
	ErrPasskeyInvalid  = auth.NewError("passkey.invalid", http.StatusUnauthorized, "This passkey could not be verified.")
	ErrNotFound        = auth.NewError("passkey.not_found", http.StatusNotFound, "Not found.")
	// ErrAttachmentInvalid: RegisterBeginRequest.AuthenticatorAttachment is
	// not one of the two WebAuthn values.
	ErrAttachmentInvalid = auth.NewError("passkey.attachment_invalid", http.StatusBadRequest, "Choose platform or cross-platform.")
	ErrNoRelyingParty    = errors.New("passkey: needs auth.WithBaseURL or passkey.RelyingParty")
	// ErrSignUpNeedsKind: WithSignUp needs an identifier plugin, or a
	// sign-up could name no address and no user could ever be contacted.
	ErrSignUpNeedsKind = errors.New("passkey: WithSignUp needs an identifier plugin (email, phone or username)")
	// ErrExtensionsInvalid: RegistrationExtensions or
	// AuthenticationExtensions holds a value JSON cannot encode, which every
	// ceremony would fail on.
	ErrExtensionsInvalid = errors.New("passkey: RegistrationExtensions and AuthenticationExtensions must hold JSON values")
	// ErrSelectionInvalid: AuthenticatorSelection named a level or an
	// attachment WebAuthn does not define, which every browser would reject
	// at the first ceremony.
	ErrSelectionInvalid = errors.New("passkey: AuthenticatorSelection levels are required, preferred or discouraged, the attachment platform or cross-platform")
)

// Extensions are WebAuthn client extension inputs, keyed by extension
// identifier ("credProps", "prf", "largeBlob", …), as the browser receives
// them in the options. The value shapes belong to each extension's
// specification and are JSON, so this is the protocol library's own open
// type rather than a struct per extension; the plugin passes it through
// unread.
//
//ds:def id=extensions-5nq8tv2k owner=@khanakia stability=stable
type Extensions = protocol.AuthenticationExtensions

// Plugin is the passkey sign-in method. Build it with New and pass it to
// auth.WithPlugins; its Go methods and its HTTP routes run the same operations.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs     auth.OptionErrors
	displayName string
	accountName AccountNameFunc
	rpID        string
	origins     []string
	ttl         time.Duration
	// regExt and authExt are sent with every registration and assertion
	// options; signUp turns the public sign-up ceremony on.
	regExt  Extensions
	authExt Extensions
	signUp  bool
	// sel is AuthenticatorSelection's choice; allowForSession names the
	// signed-in user's passkeys at login-begin.
	sel             Selection
	allowForSession bool
	// conveyance, mds and the AAGUID lists are the authenticator policy
	// (policy.go); the lists hold normalized AAGUIDs after Validate.
	conveyance   Conveyance
	mds          MetadataProvider
	allowAAGUIDs []string
	denyAAGUIDs  []string
	wa           *webauthn.WebAuthn
	core         *auth.Auth

	registerBegin  *auth.Op[RegisterBeginRequest, BeginResult]
	registerFinish *auth.Op[FinishRequest, Passkey]
	loginBegin     *auth.Op[struct{}, BeginResult]
	loginFinish    *auth.Op[FinishRequest, SignInResult]
	reauthBegin    *auth.Op[struct{}, BeginResult]
	reauthFinish   *auth.Op[ReauthFinishRequest, auth.Reauthentication]
	list           *auth.Op[struct{}, ListResult]
	remove         *auth.Op[RemoveRequest, auth.Done]
	rename         *auth.Op[RenameRequest, auth.Done]
	signUpBegin    *auth.Op[SignUpBeginRequest, BeginResult]
	signUpFinish   *auth.Op[FinishRequest, SignUpResult]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin; pass options to New.
type Option func(*Plugin)

// DisplayName is the app name the browser shows in the passkey prompt. It is
// not stored with the passkey, so it can change at any time.
func DisplayName(name string) Option { return func(p *Plugin) { p.displayName = name } }

// AccountNameFunc names a user's account in a new passkey, such as their email
// address: the name the device shows when it offers the passkey. It receives
// the core, so it can read what the plugin cannot know (a.Identities) without
// the app capturing its *auth.Auth before auth.New has returned it. An empty
// result falls back to the user id. It runs at registration only: the device
// stores the name with the passkey, so a later change of address does not
// rename passkeys already made.
//
//ds:def id=accountnamefunc-n7ra6rnc owner=@khanakia stability=stable
type AccountNameFunc func(ctx context.Context, a *auth.Auth, u auth.User) string

// AccountName sets how a new passkey names the account. Without it the name
// is the user id, which is stable and never an address, but means nothing to
// a person choosing between passkeys.
func AccountName(fn AccountNameFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("passkey.AccountName", fn) {
			return
		}
		p.accountName = fn
	}
}

// RelyingParty overrides the relying party id and the allowed origins, which
// otherwise come from the host of auth.WithBaseURL and the trusted origins.
// Without origins, the BaseURL's origin and the trusted origins are used.
// A passkey is bound to its relying party id for good: changing it later
// strands every registered passkey.
//
//ds:def id=relyingparty-2pap47ws owner=@khanakia stability=stable
func RelyingParty(id string, origins ...string) Option {
	return func(p *Plugin) { p.rpID, p.origins = id, origins }
}

// WithCeremonyTTL overrides DefaultCeremonyTTL, how long a begun ceremony can
// be finished. After it the ceremony is ErrCeremonyInvalid.
func WithCeremonyTTL(d time.Duration) Option { return func(p *Plugin) { p.ttl = d } }

// RegistrationExtensions adds WebAuthn extensions to every registration's
// options (register-begin and sign-up-begin): {"credProps": true} to learn
// whether the credential is discoverable, "prf" or "largeBlob" for apps that
// derive keys or store data on the authenticator. The browser's results
// come back in Passkey.Extensions at finish, unread by the plugin.
func RegistrationExtensions(ext Extensions) Option { return func(p *Plugin) { p.regExt = ext } }

// AuthenticationExtensions adds WebAuthn extensions to every sign-in's
// assertion options (login-begin). The results come back in
// SignInResult.Extensions at login-finish.
func AuthenticationExtensions(ext Extensions) Option { return func(p *Plugin) { p.authExt = ext } }

// WithSignUp adds passkey-first registration: a public ceremony that creates
// the account with a passkey as its first credential, so a user never has a
// password. Off by default, because it is a public route that creates
// accounts; it is bounded per IP like password sign-up, and the account
// exists only after a verified attestation, which no script can forge. It
// needs an identifier plugin, so the new user has an address to show and to
// verify.
func WithSignUp() Option { return func(p *Plugin) { p.signUp = true } }

// AuthenticatorSelection replaces what the plugin asks of an authenticator.
// The default asks for a discoverable credential and user verification on
// every ceremony, which is what lets a passkey sign-in count as two factors
// and skip the second step.
//
// Lowering either keeps sign-in safe rather than pretending: a sign-in whose
// assertion does not carry the user-verified flag is one factor, so a user
// with a second factor gets a pending session and secondFactorRequired; and
// a non-discoverable passkey cannot be found by the identifier-free sign-in,
// so it signs in only under AllowCredentialsForSession.
//
//ds:def id=passkey-authenticatorselection-3wk8qz5n owner=@khanakia stability=stable
func AuthenticatorSelection(s Selection) Option { return func(p *Plugin) { p.sel = s } }

// AllowCredentialsForSession makes login-begin name the signed-in user's own
// passkeys, with their transports, in allowCredentials when a session
// exists: a re-authentication then offers only that user's
// passkeys, the browser knows how to reach each (usb, nfc, ble, internal,
// hybrid), and a non-discoverable passkey can be used at all. The finish is
// checked against that user. Without a session, or with no passkey, the
// sign-in stays discoverable. Off by default, so a signed-in browser can
// still sign in to another account with that account's passkey.
//
//ds:def id=passkey-allowcredentialsforsession-9mr4xt2v owner=@khanakia stability=stable
func AllowCredentialsForSession() Option { return func(p *Plugin) { p.allowForSession = true } }

var (
	_ auth.SignInMethod      = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.TypedMigrator     = (*Plugin)(nil)
	_ auth.TableOwner        = (*Plugin)(nil)
	_ auth.UserTableOwner    = (*Plugin)(nil)
	_ auth.CredentialCounter = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.RateLimiter       = (*Plugin)(nil)
	_ auth.DataHooker        = (*Plugin)(nil)
)

// New builds the plugin. The relying party comes from auth.WithBaseURL unless
// RelyingParty names it.
func New(opts ...Option) *Plugin {
	p := &Plugin{displayName: DefaultDisplayName, ttl: DefaultCeremonyTTL}
	for _, o := range opts {
		o(p)
	}
	p.registerBegin = auth.Define(auth.OpInfo{ID: EndpointRegisterBegin, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: pathRegisterBegin}, p.doRegisterBegin)
	p.registerFinish = auth.Define(auth.OpInfo{ID: EndpointRegisterFinish, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: pathRegisterFinish}, p.doRegisterFinish)
	p.loginBegin = auth.Define(auth.OpInfo{ID: EndpointLoginBegin, Kind: auth.Mutation, Require: auth.Public, Path: pathLoginBegin}, p.doLoginBegin)
	p.loginFinish = auth.Define(auth.OpInfo{ID: EndpointLoginFinish, Kind: auth.Mutation, Require: auth.Public, Path: pathLoginFinish, SignIn: true}, p.doLoginFinish)
	p.list = auth.Define(auth.OpInfo{ID: EndpointList, Kind: auth.Query, Require: auth.SignedIn, Path: pathList}, p.doList)
	p.remove = auth.Define(auth.OpInfo{ID: EndpointRemove, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: pathRemove}, p.doRemove)
	p.rename = auth.Define(auth.OpInfo{ID: EndpointRename, Kind: auth.Mutation, Require: auth.SignedIn, Path: pathRename}, p.doRename)
	p.signUpBegin = auth.Define(auth.OpInfo{ID: EndpointSignUpBegin, Kind: auth.Mutation, Require: auth.Public, Path: pathSignUpBegin}, p.doSignUpBegin)
	p.signUpFinish = auth.Define(auth.OpInfo{ID: EndpointSignUpFinish, Kind: auth.Mutation, Require: auth.Public, Path: pathSignUpFinish}, p.doSignUpFinish)
	p.defineReauth()
	return p
}

// Name is PluginName, the plugin's permanent identity in the migration ledger.
func (p *Plugin) Name() string { return PluginName }

// SignsIn reports that a passkey is a way in, so auth.New counts the plugin
// as a sign-in method and the core refuses to remove a user's last one.
func (p *Plugin) SignsIn() bool { return true }

// Tables declares the plugin's table, so auth.New can refuse another plugin
// claiming the same name or alias.
func (p *Plugin) Tables() []sqlb.Table { return []sqlb.Table{TablePasskey, TableSecurityKey} }

// UserTables declares that auth_passkey and auth_passkey_security_key rows
// belong to the user in user_id, so DeleteUser removes them (no foreign key
// does, ADR-0002).
func (p *Plugin) UserTables() []auth.UserTable {
	return []auth.UserTable{{Table: TablePasskey, Column: ColUserID}, {Table: TableSecurityKey, Column: ColUserID}}
}

// Operations lists register (begin, finish), login (begin, finish),
// re-authentication (begin, finish), list, remove and rename, and sign-up (begin, finish) with WithSignUp.
func (p *Plugin) Operations() []auth.Operation {
	ops := []auth.Operation{p.registerBegin, p.registerFinish, p.loginBegin, p.loginFinish, p.reauthBegin, p.reauthFinish, p.list, p.remove, p.rename}
	if p.signUp {
		ops = append(ops, p.signUpBegin, p.signUpFinish)
	}
	return ops
}

// RateLimits bounds login-begin per IP (loginBeginIPLimit a minute), the
// re-authentication ceremony per IP and per user (reauthRules) and, with
// WithSignUp, sign-up-begin (signUpIPLimit an hour). The other operations
// need a signed-in user or a ceremony from a begin, so these rules bound
// every anonymous write the plugin makes.
func (p *Plugin) RateLimits() []auth.RateRule {
	rules := append([]auth.RateRule{{Match: EndpointLoginBegin, Key: auth.ByIP, Limit: loginBeginIPLimit, Window: loginBeginIPWindow}}, reauthRules()...)
	if p.signUp {
		rules = append(rules, auth.RateRule{Match: EndpointSignUpBegin, Key: auth.ByIP, Limit: signUpIPLimit, Window: signUpIPWindow})
	}
	return rules
}

// Validate needs a relying party: an explicit one, or a BaseURL to take it
// from. Without one no ceremony could ever verify. WithSignUp also needs an
// identifier kind to hold the new user's address.
func (p *Plugin) Validate(c *auth.Config) error {
	if !validSelection(p.sel) {
		return ErrSelectionInvalid
	}
	if err := p.validatePolicy(); err != nil {
		return err
	}
	if p.rpID == "" && c.BaseURL == "" {
		return ErrNoRelyingParty
	}
	if p.signUp && len(c.Identifiers) == 0 {
		return ErrSignUpNeedsKind
	}
	// The extensions go into every ceremony's options and stored state, so
	// a value JSON cannot hold (a NaN, a channel) would fail them all.
	for _, ext := range []Extensions{p.regExt, p.authExt} {
		if _, err := json.Marshal(ext); err != nil {
			return fmt.Errorf("%w: %v", ErrExtensionsInvalid, err)
		}
	}
	return nil
}

// Init builds the WebAuthn relying party. User verification (PIN or
// biometric) is required on every ceremony: it is what makes a passkey
// sign-in multi-factor, so the plugin may skip the SecondFactor plugins.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	cfg := a.Config()
	if p.rpID == "" {
		u, err := url.Parse(cfg.BaseURL)
		if err != nil || u.Hostname() == "" {
			return ErrNoRelyingParty
		}
		p.rpID = u.Hostname()
	}
	// An id given without origins takes the app's own origins; with neither,
	// every ceremony would fail, so start-up fails instead.
	if len(p.origins) == 0 && cfg.BaseURL != "" {
		p.origins = append([]string{auth.OriginOf(cfg.BaseURL)}, cfg.TrustedOrigins...)
	}
	if len(p.origins) == 0 {
		return ErrNoRelyingParty
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID: p.rpID, RPDisplayName: p.displayName, RPOrigins: p.origins,
		AttestationPreference: protocol.ConveyancePreference(p.conveyancePreference()),
		MDS:                   p.mds,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.AuthenticatorAttachment(p.sel.Attachment),
			ResidentKey:             protocol.ResidentKeyRequirement(p.residentKey()),
			RequireResidentKey:      requireResidentKey(p.residentKey()),
			UserVerification:        protocol.UserVerificationRequirement(p.userVerification()),
		},
	})
	if err != nil {
		// The id and origins come from RelyingParty or, left out, from
		// auth.WithBaseURL, so the refusal names both places to fix.
		return fmt.Errorf("passkey: RelyingParty(%q, %q) or auth.WithBaseURL: %w", p.rpID, p.origins, err)
	}
	p.wa = wa
	return nil
}

// residentKey and userVerification are the selection's levels, defaulting
// to RequirementRequired.
func (p *Plugin) residentKey() Requirement      { return orRequired(p.sel.ResidentKey) }
func (p *Plugin) userVerification() Requirement { return orRequired(p.sel.UserVerification) }

// requireResidentKey is WebAuthn Level 1's requireResidentKey flag, which
// older browsers read instead of residentKey: true only for required.
func requireResidentKey(r Requirement) *bool {
	if r == RequirementRequired {
		return protocol.ResidentKeyRequired()
	}
	return protocol.ResidentKeyNotRequired()
}

func orRequired(r Requirement) Requirement {
	if r == "" {
		return RequirementRequired
	}
	return r
}

// validSelection reports whether every set field of s is a WebAuthn value.
func validSelection(s Selection) bool {
	for _, r := range []Requirement{s.ResidentKey, s.UserVerification} {
		if r != "" && !slices.Contains(RequirementValues, r) {
			return false
		}
	}
	switch s.Attachment {
	case "", AttachmentPlatform, AttachmentCrossPlatform:
		return true
	}
	return false
}

// TypedMigrations creates auth_passkey and its user index for engine, then
// the security-key table (securitykey.go). MySQL has no
// CREATE INDEX IF NOT EXISTS, so there the index is declared inside the
// CREATE TABLE, which already has IF NOT EXISTS.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	table := p.core.TableName(TablePasskey)
	indexUser := table + indexUserSuffix
	create := "CREATE TABLE IF NOT EXISTS " + table + " (" +
		ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
		ColUserID + " " + t.ID + " NOT NULL, " +
		ColCredentialID + " " + t.Bytes + " NOT NULL UNIQUE, " +
		ColCredential + " " + t.Doc + " NOT NULL, " +
		ColName + " " + t.Text + " NOT NULL, " +
		ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
		ColLastUsedAt + " " + t.Timestamp + " NULL"
	st := []string{}
	if engine == auth.EngineMySQL {
		st = append(st, create+", INDEX "+indexUser+" ("+ColUserID+"))"+t.TableSuffix)
	} else {
		st = append(st, create+")"+t.TableSuffix, "CREATE INDEX IF NOT EXISTS "+indexUser+" ON "+table+" ("+ColUserID+")")
	}
	return []auth.Migration{{Owner: PluginName, Name: "0001_passkey", Statements: st}, p.securityKeyMigration(engine, t)}, nil
}

// RegisterBeginRequest is the optional input of register-begin.
type RegisterBeginRequest struct {
	// AuthenticatorAttachment restricts the kind of authenticator the browser
	// offers: "platform" (the device's own, Face ID, Windows Hello) or
	// "cross-platform" (a security key, a phone). Empty lets the browser
	// offer both, which is the usual choice.
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
}

// Authenticator attachments, the two values WebAuthn defines.
const (
	AttachmentPlatform      = string(protocol.Platform)
	AttachmentCrossPlatform = string(protocol.CrossPlatform)
)

// SignUpBeginRequest starts a passkey-first sign-up: the identifier the new
// account will hold (an email address, phone number or username one of the
// identifier plugins accepts), the user's display name, and optionally the
// authenticator kind, as on RegisterBeginRequest.
type SignUpBeginRequest struct {
	Identifier              string `json:"identifier"`
	Name                    string `json:"name,omitempty"`
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
}

// SignUpResult is the output of sign-up-finish: the new user, their first
// passkey, and either a session (Token, for Go callers and bearer clients)
// or VerificationRequired when the identifier's kind demands verification
// before the first sign-in, exactly as password sign-up behaves.
type SignUpResult struct {
	User                 auth.UserView `json:"user"`
	Passkey              Passkey       `json:"passkey"`
	VerificationRequired bool          `json:"verificationRequired"`
	Token                auth.Token    `json:"-"`
}

// signUpMeta is what a sign-up ceremony carries between begin and finish:
// the WebAuthn session and the account the user asked for.
type signUpMeta struct {
	Session    webauthn.SessionData `json:"session"`
	Identifier string               `json:"identifier"`
	Name       string               `json:"name"`
}

// BeginResult starts a ceremony. The client passes Options to
// navigator.credentials.create or .get, and sends Ceremony back with the
// authenticator's answer. Ceremony is a single-use handle, like an OAuth
// state, so it is sent in the clear.
type BeginResult struct {
	Ceremony string          `json:"ceremony"`
	Options  json.RawMessage `json:"options"`
}

// FinishRequest completes a ceremony. Credential is the JSON the browser's
// PublicKeyCredential serializes to.
//
//ds:def id=finishrequest-ghejkurt owner=@khanakia stability=stable
type FinishRequest struct {
	Ceremony   string          `json:"ceremony"`
	Credential json.RawMessage `json:"credential"`
	// Name labels a new passkey in the list, such as "MacBook". Register only.
	Name string `json:"name,omitempty"`
}

// Passkey is one row of the list: what a settings page shows. The credential
// itself never leaves the plugin; AAGUID, BackedUp and Transports are read
// from it.
type Passkey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	// AAGUID identifies the authenticator model (1Password, Windows Hello…)
	// as a UUID string; AuthenticatorName turns it into a label. Empty, or
	// all zeros, when the authenticator declined to say, which Apple devices
	// do under the default attestation.
	AAGUID string `json:"aaguid"`
	// BackedUp reports whether the passkey is synced by the platform (iCloud
	// Keychain, Google Password Manager) rather than bound to one device.
	BackedUp bool `json:"backedUp"`
	// Transports are the ways the authenticator reported it can be reached
	// ("internal", "usb", "hybrid"…), for a settings page's icon.
	Transports []string `json:"transports"`
	// Extensions are the browser's client extension results from the
	// registration that made this passkey (RegistrationExtensions), as JSON,
	// set only on the Passkey that register-finish or sign-up-finish
	// returns; the list does not keep them.
	Extensions json.RawMessage `json:"extensions,omitempty"`
}

// ListResult is the output of list, oldest passkey first.
type ListResult struct {
	Passkeys []Passkey `json:"passkeys"`
}

// RemoveRequest names a passkey of the signed-in user by its id.
type RemoveRequest struct {
	ID string `json:"id"`
}

// RenameRequest gives a passkey of the signed-in user a new label.
type RenameRequest struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// SignInResult is the output of login-finish. Token is for Go callers and
// bearer transports, never encoded into JSON.
type SignInResult struct {
	User  auth.UserView `json:"user"`
	Token auth.Token    `json:"-"`
	// SecondFactorRequired is true when the authenticator did not verify
	// the user (possible only below RequirementRequired, see
	// AuthenticatorSelection) and the user has a second factor: the session
	// is pending until that step passes.
	SecondFactorRequired bool `json:"secondFactorRequired,omitempty"`
	// Extensions are the browser's client extension results for the
	// assertion (AuthenticationExtensions), as JSON; empty when there are
	// none.
	Extensions json.RawMessage `json:"extensions,omitempty"`
}

// RegisterBegin starts adding a passkey for the signed-in user. The user's
// existing passkeys are excluded, so an authenticator that already holds one
// is not registered twice.
func (p *Plugin) RegisterBegin(ctx context.Context) (BeginResult, error) {
	return p.registerBegin.Call(ctx, RegisterBeginRequest{})
}

// RegisterBeginWith is RegisterBegin with a request, to restrict the
// authenticator kind.
func (p *Plugin) RegisterBeginWith(ctx context.Context, in RegisterBeginRequest) (BeginResult, error) {
	return p.registerBegin.Call(ctx, in)
}

// RegisterFinish verifies the authenticator's answer and stores the new
// passkey. A ceremony works once, and only for the user who began it.
func (p *Plugin) RegisterFinish(ctx context.Context, in FinishRequest) (Passkey, error) {
	return p.registerFinish.Call(ctx, in)
}

// LoginBegin starts a discoverable passkey sign-in: no identifier is asked
// for, the authenticator offers the passkeys it holds for this site.
func (p *Plugin) LoginBegin(ctx context.Context) (BeginResult, error) {
	return p.loginBegin.Call(ctx, struct{}{})
}

// LoginFinish verifies the authenticator's answer and signs the user in.
//
//ds:def id=plugin-loginfinish-f3wwymqp owner=@khanakia stability=stable
func (p *Plugin) LoginFinish(ctx context.Context, in FinishRequest) (SignInResult, error) {
	return p.loginFinish.Call(ctx, in)
}

// List returns the signed-in user's passkeys, oldest first.
func (p *Plugin) List(ctx context.Context) ([]Passkey, error) {
	r, err := p.list.Call(ctx, struct{}{})
	return r.Passkeys, err
}

// Remove deletes a passkey, unless it is the last way into the account.
func (p *Plugin) Remove(ctx context.Context, id string) error {
	_, err := p.remove.Call(ctx, RemoveRequest{ID: id})
	return err
}

// SignUpBegin starts a passkey-first sign-up (WithSignUp): no session, no
// password; the account is created at SignUpFinish from a verified
// attestation. The identifier is checked against the identifier plugins
// before any ceremony starts.
func (p *Plugin) SignUpBegin(ctx context.Context, in SignUpBeginRequest) (BeginResult, error) {
	return p.signUpBegin.Call(ctx, in)
}

// SignUpFinish verifies the authenticator's answer, creates the user with
// the identifier and the passkey, and signs them in unless the identifier's
// kind requires verification first.
func (p *Plugin) SignUpFinish(ctx context.Context, in FinishRequest) (SignUpResult, error) {
	return p.signUpFinish.Call(ctx, in)
}

// Rename relabels one of the signed-in user's passkeys; the name is cut to the
// same length as at registration. An id that is not the user's is ErrNotFound.
func (p *Plugin) Rename(ctx context.Context, id, name string) error {
	_, err := p.rename.Call(ctx, RenameRequest{ID: id, Name: name})
	return err
}

// waUser adapts a user and their passkeys to webauthn.User. The user handle
// is the user id: opaque, stable, and never an email address, as the
// specification asks.
type waUser struct {
	u     auth.User
	creds []webauthn.Credential
	// name is the account name from AccountName, set for a registration;
	// empty means the user id.
	name string
}

// WebAuthnID is the user handle: the user id, which the authenticator returns
// at sign-in so the plugin knows whose passkey answered.
func (w *waUser) WebAuthnID() []byte { return []byte(w.u.ID) }

// WebAuthnName is the account name the authenticator stores: the AccountName
// result, or the id, because the plugin does not know which identifier the
// app shows.
func (w *waUser) WebAuthnName() string {
	if w.name != "" {
		return w.name
	}
	return w.u.ID
}

// WebAuthnDisplayName is what the passkey prompt shows: the user's name, or
// the account name when the name is empty, because the specification needs
// one.
func (w *waUser) WebAuthnDisplayName() string {
	if w.u.Name != "" {
		return w.u.Name
	}
	return w.WebAuthnName()
}

// WebAuthnCredentials are the user's registered passkeys.
func (w *waUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

// credentials reads userID's stored credentials. A row that does not decode is
// an error naming the row, not a silently shorter list: a skipped credential
// would let the same authenticator register twice.
func (p *Plugin) credentials(ctx context.Context, userID string) ([]webauthn.Credential, error) {
	var id, doc string
	sel := p.core.Select().Columns(sqlb.Bind(PasskeyID, &id), sqlb.Bind(Credential, &doc)).From(TablePasskey).
		Where(sqlb.Eq(UserID, userID)).Order(sqlb.OrderBy(CreatedAt, sqlb.SortAsc))
	var out []webauthn.Credential
	err := p.core.Each(ctx, sel, func() error {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(doc), &c); err != nil {
			return fmt.Errorf("passkey: stored credential %s: %w", id, err)
		}
		out = append(out, c)
		return nil
	})
	return out, err
}

// waUserOf loads userID and their passkeys as the WebAuthn library's user.
func (p *Plugin) waUserOf(ctx context.Context, userID string) (*waUser, error) {
	u, err := p.core.User(ctx, userID)
	if err != nil {
		return nil, err
	}
	creds, err := p.credentials(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &waUser{u: u, creds: creds}, nil
}

// ceremonyOptions is what a ceremony hands the browser: creation options for
// registration, assertion options for sign-in.
type ceremonyOptions interface {
	*protocol.CredentialCreation | *protocol.CredentialAssertion
}

// begin stores the ceremony's session data as a single-use token and returns
// it with the options for the browser.
func begin[O ceremonyOptions](ctx context.Context, p *Plugin, purpose auth.Purpose, identifier string, options O, session *webauthn.SessionData) (BeginResult, error) {
	return beginMeta(ctx, p, purpose, identifier, options, session)
}

// beginMeta is begin with any JSON-encodable ceremony state, for the sign-up
// ceremony that carries more than the WebAuthn session.
func beginMeta[O ceremonyOptions](ctx context.Context, p *Plugin, purpose auth.Purpose, identifier string, options O, state any) (BeginResult, error) {
	// Validate refused extensions JSON cannot hold, and nothing else in a
	// ceremony's state or options is anything but strings, bytes, numbers
	// and structs of them, so both always marshal.
	meta, _ := json.Marshal(state)
	opts, _ := json.Marshal(options)
	tok, err := p.core.IssueVerification(ctx, purpose, identifier, p.ttl, string(meta))
	if err != nil {
		return BeginResult{}, err
	}
	return BeginResult{Ceremony: tok.Reveal(), Options: opts}, nil
}

// finish spends a ceremony token and returns its session data.
func (p *Plugin) finish(ctx context.Context, purpose auth.Purpose, ceremony string) (auth.Verification, webauthn.SessionData, error) {
	v, err := p.core.ConsumeVerification(ctx, purpose, auth.Token(ceremony))
	if errors.Is(err, auth.ErrTokenInvalid) {
		return v, webauthn.SessionData{}, ErrCeremonyInvalid
	}
	if err != nil {
		return v, webauthn.SessionData{}, err
	}
	var s webauthn.SessionData
	if err := json.Unmarshal([]byte(v.Meta), &s); err != nil {
		return v, webauthn.SessionData{}, fmt.Errorf("passkey: ceremony data: %w", err)
	}
	return v, s, nil
}

// selection is the relying party's authenticator selection, narrowed to one
// attachment when the request asks for it; a value WebAuthn does not define
// is ErrAttachmentInvalid.
func (p *Plugin) selection(attachment string) (protocol.AuthenticatorSelection, error) {
	selection := p.wa.Config.AuthenticatorSelection
	switch attachment {
	case "":
	case AttachmentPlatform, AttachmentCrossPlatform:
		selection.AuthenticatorAttachment = protocol.AuthenticatorAttachment(attachment)
	default:
		return selection, ErrAttachmentInvalid
	}
	return selection, nil
}

// registrationOptions are the options every registration ceremony sends:
// the selection, and the configured extensions when there are any.
func (p *Plugin) registrationOptions(selection protocol.AuthenticatorSelection, exclude []protocol.CredentialDescriptor) []webauthn.RegistrationOption {
	opts := []webauthn.RegistrationOption{webauthn.WithExclusions(exclude), webauthn.WithAuthenticatorSelection(selection)}
	if len(p.regExt) > 0 {
		opts = append(opts, webauthn.WithExtensions(p.regExt))
	}
	return opts
}

// extensionResults encodes the browser's client extension results, or
// returns nil when there are none so the field is omitted. The results were
// decoded from the browser's JSON, so they always encode again.
func extensionResults(out protocol.AuthenticationExtensionsClientOutputs) json.RawMessage {
	if len(out) == 0 {
		return nil
	}
	b, _ := json.Marshal(out)
	return b
}

func (p *Plugin) doRegisterBegin(ctx context.Context, c *auth.Call, in RegisterBeginRequest) (BeginResult, error) {
	selection, err := p.selection(in.AuthenticatorAttachment)
	if err != nil {
		return BeginResult{}, err
	}
	w, err := p.waUserOf(ctx, c.User.ID)
	if err != nil {
		return BeginResult{}, err
	}
	if p.accountName != nil {
		w.name = p.accountName(ctx, p.core, w.u)
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(w.creds))
	for _, cr := range w.creds {
		exclude = append(exclude, cr.Descriptor())
	}
	creation, session, err := p.wa.BeginRegistration(w, p.registrationOptions(selection, exclude)...)
	if err != nil {
		return BeginResult{}, fmt.Errorf("passkey: begin registration: %w", err)
	}
	return begin(ctx, p, PurposeRegister, c.User.ID, creation, session)
}

// doSignUpBegin starts a ceremony for an account that does not exist yet. The
// user id is minted here, because the authenticator stores the user handle
// with the passkey and login looks the user up by it: the id the handle
// names must be the id the account gets at finish.
func (p *Plugin) doSignUpBegin(ctx context.Context, c *auth.Call, in SignUpBeginRequest) (BeginResult, error) {
	selection, err := p.selection(in.AuthenticatorAttachment)
	if err != nil {
		return BeginResult{}, err
	}
	// A value no identifier plugin accepts fails here, before the user
	// touches an authenticator for nothing.
	if _, _, err := c.Auth.DetectKind(in.Identifier); err != nil {
		return BeginResult{}, err
	}
	id, err := c.Auth.NewID(auth.IDPrefixUser)
	if err != nil {
		return BeginResult{}, err
	}
	w := &waUser{u: auth.User{ID: id, Name: in.Name}, name: in.Identifier}
	creation, session, err := p.wa.BeginRegistration(w, p.registrationOptions(selection, nil)...)
	if err != nil {
		return BeginResult{}, fmt.Errorf("passkey: begin sign-up: %w", err)
	}
	return beginMeta(ctx, p, PurposeSignUp, id, creation, signUpMeta{Session: *session, Identifier: in.Identifier, Name: in.Name})
}

// signUpIDKey carries the pre-minted user id of a sign-up ceremony to the
// User BeforeCreate hook, so the account gets the id the authenticator
// already holds as its user handle. The context is the one place an id can
// travel from doSignUpFinish to a hook the core calls: the hook cannot
// take parameters, and a field on the plugin would race between sign-ups.
type signUpIDKey struct{}

func withSignUpID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, signUpIDKey{}, id)
}

// DataHooks sets a new user's id to the sign-up ceremony's pre-minted id
// when the creating context carries one, and touches nothing else: every
// other CreateUser in the process has no id in its context and gets the
// core's.
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{User: auth.TableHooks[auth.User]{
		BeforeCreate: func(ctx context.Context, _ sqlb.DBTX, row *auth.User) error {
			if id, ok := ctx.Value(signUpIDKey{}).(string); ok && id != "" {
				row.ID = id
			}
			return nil
		},
	}}
}

// doSignUpFinish creates the account from a verified attestation. The
// identifier follows password sign-up's rule for a value someone already
// verified: the owner is told and this sign-up still succeeds as a separate,
// unverified account, so the answer reveals nothing about who has one. A
// kind with RequireVerified issues no session.
func (p *Plugin) doSignUpFinish(ctx context.Context, c *auth.Call, in FinishRequest) (SignUpResult, error) {
	v, err := c.Auth.ConsumeVerification(ctx, PurposeSignUp, auth.Token(in.Ceremony))
	if errors.Is(err, auth.ErrTokenInvalid) {
		return SignUpResult{}, ErrCeremonyInvalid
	}
	if err != nil {
		return SignUpResult{}, err
	}
	var meta signUpMeta
	if err := json.Unmarshal([]byte(v.Meta), &meta); err != nil {
		return SignUpResult{}, fmt.Errorf("passkey: ceremony data: %w", err)
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(in.Credential))
	if err != nil {
		return SignUpResult{}, ErrPasskeyInvalid
	}
	w := &waUser{u: auth.User{ID: v.Identifier, Name: meta.Name}, name: meta.Identifier}
	cred, err := p.wa.CreateCredential(w, meta.Session, parsed)
	if err != nil {
		c.Auth.Logger().Info("passkey: sign-up refused", "error", err)
		return SignUpResult{}, ErrPasskeyInvalid
	}
	kind, _, err := c.Auth.DetectKind(meta.Identifier)
	if err != nil {
		return SignUpResult{}, err
	}
	k, _ := c.Auth.Config().Identifier(kind)
	if k.Verifiable {
		owner, err := c.Auth.FindIdentity(ctx, kind, meta.Identifier, true)
		switch {
		case err == nil:
			if err := c.Auth.Deliver(ctx, owner, auth.Message{Purpose: auth.PurposeSignUpAttempt}); err != nil && !errors.Is(err, auth.ErrNoDeliverer) {
				return SignUpResult{}, err
			}
		case !errors.Is(err, auth.ErrIdentityNotFound):
			return SignUpResult{}, err
		}
	}
	u, err := c.Auth.CreateUser(withSignUpID(ctx, v.Identifier), auth.NewUser{Name: meta.Name})
	if err != nil {
		return SignUpResult{}, err
	}
	if u.ID != v.Identifier {
		// The hook did not run: another plugin's BeforeCreate changed the id,
		// or the plugin is registered in a way that skips its data hooks.
		// A user whose id is not the authenticator's handle could never sign
		// in with this passkey, so the sign-up fails rather than storing it.
		return SignUpResult{}, fmt.Errorf("passkey: sign-up user id %s is not the ceremony's %s", u.ID, v.Identifier)
	}
	if _, err := c.Auth.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: kind, Raw: meta.Identifier}); err != nil {
		return SignUpResult{}, err
	}
	pk, err := p.insert(ctx, c, u.ID, cred, in.Name, parsed.ClientExtensionResults)
	if err != nil {
		return SignUpResult{}, err
	}
	out := SignUpResult{User: auth.ViewOf(u), Passkey: pk}
	if k.RequireVerified && k.Verifiable {
		out.VerificationRequired = true
		return out, nil
	}
	sess, tok, err := c.Auth.CreateMultiFactorSession(ctx, u.ID, c.Client)
	if err != nil {
		return SignUpResult{}, err
	}
	c.Effects.IssueSessionOf(sess, tok)
	out.Token = tok
	return out, nil
}

func (p *Plugin) doRegisterFinish(ctx context.Context, c *auth.Call, in FinishRequest) (Passkey, error) {
	v, session, err := p.finish(ctx, PurposeRegister, in.Ceremony)
	if err != nil {
		return Passkey{}, err
	}
	if v.Identifier != c.User.ID {
		return Passkey{}, ErrCeremonyInvalid
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(in.Credential))
	if err != nil {
		return Passkey{}, ErrPasskeyInvalid
	}
	w, err := p.waUserOf(ctx, c.User.ID)
	if err != nil {
		return Passkey{}, err
	}
	cred, err := p.wa.CreateCredential(w, session, parsed)
	if err != nil {
		c.Auth.Logger().Info("passkey: registration refused", "error", err)
		return Passkey{}, ErrPasskeyInvalid
	}
	return p.insert(ctx, c, c.User.ID, cred, in.Name, parsed.ClientExtensionResults)
}

// insert stores a verified credential as userID's passkey. A credential id
// already stored (the same authenticator registered twice, or by another
// user) is ErrPasskeyInvalid like any other refusal; an authenticator the
// AAGUID policy refuses is ErrAuthenticatorNotAllowed before anything is written.
func (p *Plugin) insert(ctx context.Context, c *auth.Call, userID string, cred *webauthn.Credential, label string, ext protocol.AuthenticationExtensionsClientOutputs) (Passkey, error) {
	if err := p.checkAuthenticator(ctx, cred); err != nil {
		return Passkey{}, err
	}
	doc, _ := json.Marshal(cred) // a webauthn.Credential is bytes, strings and numbers
	results := extensionResults(ext)
	id, err := c.Auth.NewID(idPrefix)
	if err != nil {
		return Passkey{}, err
	}
	name := auth.TruncateRunes(label, maxNameLength)
	now := c.Auth.Now()
	ins := sqlb.NewInsert(c.Auth.Dialect()).Into(TablePasskey).Row(
		sqlb.Set(PasskeyID, id), sqlb.Set(UserID, userID), sqlb.Set(CredentialID, cred.ID),
		sqlb.Set(Credential, string(doc)), sqlb.Set(Name, name), sqlb.Set(CreatedAt, now),
	)
	if _, err := p.core.Exec(ctx, ins); err != nil {
		if auth.IsUniqueViolation(err) {
			return Passkey{}, ErrPasskeyInvalid
		}
		return Passkey{}, err
	}
	return Passkey{ID: id, Name: name, CreatedAt: now, Extensions: results}, nil
}

func (p *Plugin) doLoginBegin(ctx context.Context, c *auth.Call, _ struct{}) (BeginResult, error) {
	opts := []webauthn.LoginOption{webauthn.WithUserVerification(protocol.UserVerificationRequirement(p.userVerification()))}
	if len(p.authExt) > 0 {
		opts = append(opts, webauthn.WithAssertionExtensions(p.authExt))
	}
	if p.allowForSession && c.User != nil {
		w, err := p.waUserOf(ctx, c.User.ID)
		if err != nil {
			return BeginResult{}, err
		}
		if len(w.creds) > 0 {
			// BeginLogin names every credential of w with its transports.
			assertion, session, err := p.wa.BeginLogin(w, opts...)
			if err != nil {
				return BeginResult{}, fmt.Errorf("passkey: begin login: %w", err)
			}
			return begin(ctx, p, PurposeLogin, c.User.ID, assertion, session)
		}
	}
	assertion, session, err := p.wa.BeginDiscoverableLogin(opts...)
	if err != nil {
		return BeginResult{}, fmt.Errorf("passkey: begin login: %w", err)
	}
	return begin(ctx, p, PurposeLogin, "", assertion, session)
}

// doLoginFinish verifies the assertion and signs the user in: with a full
// session when the authenticator verified the user (always, under the
// default RequirementRequired), since the passkey is then two factors on its
// own; otherwise as a single-factor sign-in (SessionOptions.SingleFactor),
// which is pending when the user has a second factor the policy asks for
// (twofactor's DefaultPolicy does). A ceremony begun for a named user (AllowCredentialsForSession)
// is checked against that user. Every failure is the same ErrPasskeyInvalid.
func (p *Plugin) doLoginFinish(ctx context.Context, c *auth.Call, in FinishRequest) (SignInResult, error) {
	_, session, err := p.finish(ctx, PurposeLogin, in.Ceremony)
	if err != nil {
		return SignInResult{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(in.Credential))
	if err != nil {
		return SignInResult{}, ErrPasskeyInvalid
	}
	var found *waUser
	var lookupErr error
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		w, err := p.waUserOf(ctx, string(userHandle))
		if err != nil {
			lookupErr = err
			return nil, err
		}
		found = w
		return w, nil
	}
	var cred *webauthn.Credential
	if len(session.UserID) > 0 {
		var w webauthn.User
		if w, err = handler(nil, session.UserID); err == nil {
			cred, err = p.wa.ValidateLogin(w, session, parsed)
		}
	} else {
		_, cred, err = p.wa.ValidatePasskeyLogin(handler, session, parsed)
	}
	// A user handle naming nobody is a refused passkey like any other. A read
	// that failed is the server's failure: reported as ErrPasskeyInvalid it
	// would tell the user their passkey is bad and hide the outage in an
	// info log.
	if lookupErr != nil && !errors.Is(lookupErr, auth.ErrUserNotFound) {
		return SignInResult{}, lookupErr
	}
	if err != nil || found == nil {
		c.Auth.Logger().Info("passkey: sign-in refused", "error", err)
		return SignInResult{}, ErrPasskeyInvalid
	}
	// A counter that went backwards means the credential was cloned.
	if cred.Authenticator.CloneWarning {
		c.Auth.Logger().Warn("passkey: clone warning, sign-in refused", "user", found.u.ID)
		return SignInResult{}, ErrPasskeyInvalid
	}
	if err := p.touch(ctx, found.u.ID, cred); err != nil {
		return SignInResult{}, err
	}
	results := extensionResults(parsed.ClientExtensionResults)
	var sess auth.Session
	var tok auth.Token
	if parsed.Response.AuthenticatorData.Flags.HasUserVerified() {
		sess, tok, err = c.Auth.CreateMultiFactorSession(ctx, found.u.ID, c.Client)
	} else {
		sess, tok, err = c.Auth.CreateSessionWithOptions(ctx, found.u.ID, c.Client, auth.SessionOptions{SingleFactor: true})
	}
	if err != nil {
		return SignInResult{}, err
	}
	c.Effects.IssueSessionOf(sess, tok)
	return SignInResult{User: auth.ViewOf(found.u), Token: tok, Extensions: results, SecondFactorRequired: sess.SecondFactorPending}, nil
}

// touch stores the updated credential (sign count, flags) and the use time on
// the row the library verified: the user's row with that credential id, which
// is unique, so the update matches exactly one row.
func (p *Plugin) touch(ctx context.Context, userID string, cred *webauthn.Credential) error {
	doc, _ := json.Marshal(cred) // a webauthn.Credential is bytes, strings and numbers
	now := p.core.Now()
	upd := sqlb.NewUpdate(p.core.Dialect()).Table(TablePasskey).
		Set(sqlb.Set(Credential, string(doc)), sqlb.Set(LastUsedAt, &now)).
		Where(sqlb.Eq(UserID, userID), sqlb.Eq(CredentialID, cred.ID))
	_, err := p.core.Exec(ctx, upd)
	return err
}

// listPasskeys returns userID's passkeys, oldest first; an empty list, never
// nil, so it encodes as []. The authenticator details come from the stored
// credential, so a row that does not decode is an error naming it.
func (p *Plugin) listPasskeys(ctx context.Context, userID string) ([]Passkey, error) {
	var row Passkey
	var doc string
	sel := p.core.Select().Columns(sqlb.Bind(PasskeyID, &row.ID), sqlb.Bind(Name, &row.Name), sqlb.Bind(CreatedAt, &row.CreatedAt), sqlb.Bind(LastUsedAt, &row.LastUsedAt), sqlb.Bind(Credential, &doc)).
		From(TablePasskey).Where(sqlb.Eq(UserID, userID)).Order(sqlb.OrderBy(CreatedAt, sqlb.SortAsc))
	out := []Passkey{}
	err := p.core.Each(ctx, sel, func() error {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(doc), &c); err != nil {
			return fmt.Errorf("passkey: stored credential %s: %w", row.ID, err)
		}
		pk := row
		pk.AAGUID = aaguidString(c.Authenticator.AAGUID)
		pk.BackedUp = c.Flags.BackupState
		pk.Transports = make([]string, 0, len(c.Transport))
		for _, t := range c.Transport {
			pk.Transports = append(pk.Transports, string(t))
		}
		out = append(out, pk)
		return nil
	})
	return out, err
}

// aaguidLen is the AAGUID's size: a 128-bit UUID.
const aaguidLen = 16

// aaguidString formats a raw AAGUID as the lowercase UUID string the AAGUID
// registries use; "" for an authenticator that sent none or all zeros.
func aaguidString(raw []byte) string {
	if len(raw) != aaguidLen || allZero(raw) {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
}

// allZero reports whether every byte of b is zero: an authenticator that does
// not disclose its model sends an AAGUID of sixteen zero bytes.
func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// doRename relabels the passkey when it is the user's; the UPDATE's user_id
// condition makes another user's id a miss, reported as ErrNotFound like an
// unknown one.
func (p *Plugin) doRename(ctx context.Context, c *auth.Call, in RenameRequest) (auth.Done, error) {
	upd := sqlb.NewUpdate(c.Auth.Dialect()).Table(TablePasskey).Set(sqlb.Set(Name, auth.TruncateRunes(in.Name, maxNameLength))).
		Where(sqlb.Eq(PasskeyID, in.ID), sqlb.Eq(UserID, c.User.ID))
	n, err := p.core.Exec(ctx, upd)
	if err != nil {
		return auth.Done{}, err
	}
	if n != 1 {
		return auth.Done{}, ErrNotFound
	}
	return auth.Done{OK: true}, nil
}

func (p *Plugin) doList(ctx context.Context, c *auth.Call, _ struct{}) (ListResult, error) {
	list, err := p.listPasskeys(ctx, c.User.ID)
	return ListResult{Passkeys: list}, err
}

func (p *Plugin) doRemove(ctx context.Context, c *auth.Call, in RemoveRequest) (auth.Done, error) {
	list, err := p.listPasskeys(ctx, c.User.ID)
	if err != nil {
		return auth.Done{}, err
	}
	// Only the user's own passkeys are found, so another user's id is
	// ErrNotFound, the same as an id that does not exist.
	if !slices.ContainsFunc(list, func(pk Passkey) bool { return pk.ID == in.ID }) {
		return auth.Done{}, ErrNotFound
	}
	if err := c.Auth.CheckRemovable(ctx, c.User.ID, "", in.ID); err != nil {
		return auth.Done{}, err
	}
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(c.Auth.Dialect()).From(TablePasskey).Where(sqlb.Eq(PasskeyID, in.ID))); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

// SignInCredentials counts a user's passkeys for the core's last-way-in check,
// leaving out exceptID, the one about to be removed.
func (p *Plugin) SignInCredentials(ctx context.Context, userID, exceptID string) (int, error) {
	list, err := p.listPasskeys(ctx, userID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, pk := range list {
		if pk.ID != exceptID {
			n++
		}
	}
	return n, nil
}

// commonAuthenticatorNames maps the AAGUIDs of the most common passkey
// providers to the names people know them by, so a passkey list can say
// "1Password" when the user did not name it. Deliberately small and not
// authoritative: an unknown AAGUID is "", never a guess. The names follow the
// community registry at
// https://github.com/passkeydeveloper/passkey-authenticator-aaguids.
var commonAuthenticatorNames = map[string]string{
	"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
	"fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "Apple Passwords",
	"dd4ec289-e01d-41c9-bb89-70fa845d4bf2": "iCloud Keychain (Managed)",
	"08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
	"9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
	"6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
	"bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
	"d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",
	"531126d6-e717-415c-9320-3d9aa6981239": "Dashlane",
	"b78a0a55-6ef8-d246-a042-ba0f6d55050c": "LastPass",
	"b84e4048-15dc-4dd0-8640-f4f60813c8af": "NordPass",
	"50726f74-6f6e-5061-7373-50726f746f6e": "Proton Pass",
	"0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6": "Keeper",
	"53414d53-554e-4700-0000-000000000000": "Samsung Pass",
}

// AuthenticatorName returns the provider name for a Passkey.AAGUID, or "" when
// it is unknown or empty, so a settings page can show
// `pk.Name`, else `AuthenticatorName(pk.AAGUID)`, else "Passkey". Case and
// surrounding spaces do not matter.
func AuthenticatorName(aaguid string) string {
	return commonAuthenticatorNames[strings.ToLower(strings.TrimSpace(aaguid))]
}
