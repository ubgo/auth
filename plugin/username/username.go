// Package username adds handle-based identity to the auth core.
//
// Like the phone plugin it stores nothing of its own: a username is an
// identifier and lives in the core's shared auth_identity table. What this
// package adds is the policy a handle needs and an email address does not —
// reserved names, and the rule about what happens to a handle after a rename.
package username

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// PluginName is the stable identity of this plugin.
const PluginName = "username"

// KindUsername is the identifier kind this plugin registers. It is stored in
// every auth_identity row this plugin owns, so it never changes.
const KindUsername auth.IdentifierKindName = "username"

// Operation ids, exported so a hook or a rate rule can name them. They are
// wire names, stable across releases.
const (
	EndpointSet       auth.EndpointID = "username.set"
	EndpointAvailable auth.EndpointID = "username.available"
)

// Handle length bounds. Short handles invite squatting and long ones break
// layouts; both ends are product choices made explicit.
const (
	//ds:def id=minlength-x3pjevmb owner=@khanakia stability=stable
	MinLength = 2
	//ds:def id=maxlength-xnr4ndys owner=@khanakia stability=stable
	MaxLength = 39
)

// The available route's default rate limit, per client IP. The route is
// public and answers "taken" or "free" for any handle, so without a limit of
// its own one client could walk a dictionary and list every account; the
// numbers leave room for a sign-up form that checks as the user types.
const (
	//ds:def id=username-availablelimit-6tq2nw8k owner=@khanakia stability=stable
	DefaultAvailableLimit = 30
	//ds:def id=username-availablewindow-3hv7mc5p owner=@khanakia stability=stable
	DefaultAvailableWindow = time.Minute
)

// ErrReserved refuses a handle on the reserved list. It reads "not available"
// rather than "reserved" so it gives nothing away about the list.
var (
	ErrReserved = auth.NewError("username.reserved", http.StatusConflict, "This username is not available.")
	// ErrImmutable refuses a rename under Immutable(): the handle was set
	// once and the product decided it stays.
	ErrImmutable = auth.NewError("username.immutable", http.StatusConflict, "Your username cannot be changed.")
	// ErrBadLength is a configuration error from auth.New: Length was given
	// bounds nobody could satisfy.
	ErrBadLength = errors.New("username: Length needs 1 <= min <= max")
	// ErrBadAvailableLimit is a configuration error from auth.New:
	// WithAvailableLimit was given a limit below one or a window of zero.
	ErrBadAvailableLimit = errors.New("username: WithAvailableLimit needs a limit of one or more and a positive window")
	// ErrDisplayInvalid refuses a display form (Request.DisplayUsername)
	// that DisplayValidator rejected, or that does not normalize to the
	// handle it is shown for.
	//ds:def id=username-errdisplayinvalid-4kq8wz2m owner=@khanakia stability=stable
	ErrDisplayInvalid = auth.NewError("username.display_invalid", http.StatusBadRequest, "This display username is not valid for the username.")
)

// TableAliasIdentity is this plugin's alias for the shared identity table.
// Distinct from every other plugin's alias because a composite user query joins
// that table once per identifier kind.
//
//ds:def id=tablealiasidentity-r7attc8r owner=@khanakia stability=stable
const TableAliasIdentity = "uni"

// TableIdentity is the core identity table under this plugin's alias.
var TableIdentity = sqlb.Table{Name: auth.TableNameIdentity, Alias: TableAliasIdentity}

// Typed columns on the identity table under this plugin's alias, for
// UserJoin, Of and ByHandleQuery; the core's columns, qualified by "uni".
var (
	IdentityUserID    = sqlb.Col[string](TableIdentity, auth.ColIdentityUserID)
	IdentityKind      = sqlb.Col[auth.IdentifierKindName](TableIdentity, auth.ColIdentityKind)
	IdentityValue     = sqlb.Col[string](TableIdentity, auth.ColIdentityValue)
	IdentityValueRaw  = sqlb.Col[string](TableIdentity, auth.ColIdentityValueRaw)
	IdentityIsPrimary = sqlb.Col[bool](TableIdentity, auth.ColIdentityIsPrimary)
	IdentityCreatedAt = sqlb.Col[time.Time](TableIdentity, auth.ColIdentityCreatedAt)
)

// Data is this plugin's contribution to a user, shaped as a nested edge.
//
// Handle is the normalized lowercase form used for lookup and uniqueness.
// Display is what the user typed, so a handle shown back to them keeps its
// original casing. Both are empty when the user has no handle.
//
// Nested rather than flattened for the same reason as the phone plugin's: a
// handle lives in auth_identity, not in auth_user, and the Go shape follows the
// schema so a reader can see the join boundary.
//
//ds:def id=data-te6h9jmx
type Data struct {
	Handle  string
	Display string
}

// Exists reports whether the user has claimed a handle. The LEFT join yields a
// zero-valued Data rather than an absent one, so absence has to be asked for.
func (d *Data) Exists() bool { return d.Handle != "" }

// DefaultReserved is the baseline set of handles a deployment must not hand
// out.
//
// Why this list exists at all: the moment handles appear in URLs, every handle
// competes with every route. A user who claims "settings" makes /settings
// ambiguous, and a user who claims "admin" or "support" can impersonate the
// operator in any context where a handle is shown without qualification. This
// is the minimum; a deployment adds its own route names.
//
//ds:def id=defaultreserved-d6zzfhmd
var DefaultReserved = []string{
	"admin", "administrator", "root", "support", "help", "about", "api",
	"auth", "login", "logout", "signup", "register", "settings", "account",
	"billing", "security", "system", "static", "assets", "www", "mail",
}

// Plugin adds username identity. Build it with New: the zero value has no
// kind, no reserved list and no operations.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs  auth.OptionErrors
	kind     auth.IdentifierKind
	reserved map[string]struct{}
	// minLen, maxLen and chars make up the kind's Validate: the length
	// bounds and the character rule, each replaceable by an option.
	minLen, maxLen int
	chars          func(normalized string) error
	immutable      bool
	noAvailability bool
	// availLimit and availWindow are the available route's ByIP rule.
	availLimit  int
	availWindow time.Duration
	// displayValid, displayNorm and displayAfterNorm make up the display
	// rule (DisplayForm); nil means no extra rule and no rewriting.
	displayValid     func(display string) error
	displayNorm      func(display string) string
	displayAfterNorm bool
	core             *auth.Auth

	set       *auth.Op[Request, Result]
	available *auth.Op[Request, Availability]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin; options are applied in order by New.
type Option func(*Plugin)

// Login allows handles in sign-in, beside or instead of an email address.
func Login() Option { return func(p *Plugin) { p.kind = auth.ApplyKind(p.kind, auth.Login()) } }

// ScopedByTenant makes handles unique per tenant, for an app where each
// tenant has its own namespace; see auth.WithScope.
func ScopedByTenant() Option {
	return func(p *Plugin) { p.kind = auth.ApplyKind(p.kind, auth.ScopedByTenant()) }
}

// Length replaces MinLength and MaxLength, the bounds on a handle's length
// after normalization. auth.New refuses min below 1 or max below min.
func Length(min, max int) Option { return func(p *Plugin) { p.minLen, p.maxLen = min, max } }

// WithValidator replaces the character rule (ValidateChars) for the normalized
// handle; the length bounds still apply. A rule that allows "@" or a leading
// "+" breaks the one sign-in field that tells a handle from an address or a
// number, so keep those out.
func WithValidator(fn func(normalized string) error) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("username.WithValidator", fn) {
			return
		}
		p.chars = fn
	}
}

// WithNormalizer replaces Normalize (trim and lowercase), for an app that
// folds look-alike characters or keeps case. The reserved list is still
// matched on the trimmed, lowercased form.
func WithNormalizer(fn func(raw string) (string, error)) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("username.WithNormalizer", fn) {
			return
		}
		p.kind.Normalize = fn
	}
}

// Immutable makes a handle permanent: set refuses with ErrImmutable once the
// user has one. Pick it when handles appear in URLs other people have saved.
func Immutable() Option { return func(p *Plugin) { p.immutable = true } }

// WithoutAvailability leaves the public available route out, for an app that
// would rather not let anyone probe which handles exist.
func WithoutAvailability() Option { return func(p *Plugin) { p.noAvailability = true } }

// WithAvailableLimit replaces the available route's default rate limit
// (DefaultAvailableLimit per DefaultAvailableWindow), counted per client IP
// and apart from every other route's. Lower it for a product whose handles
// are private; raise it for a form that checks on every keystroke. An app's
// auth.WithRateRules for EndpointAvailable still replaces it.
func WithAvailableLimit(n int, window time.Duration) Option {
	return func(p *Plugin) { p.availLimit, p.availWindow = n, window }
}

// DisplayValidator adds a rule for the display form a client sends beside
// the handle (Request.DisplayUsername): an error refuses the request with
// ErrDisplayInvalid. It runs on the display form as sent, or on its
// DisplayNormalizer result under ValidateDisplayAfterNormalization. The
// display form must also normalize to the handle whatever this rule says;
// see DisplayForm.
//
//ds:def id=username-displayvalidator-7nm3qx5k owner=@khanakia stability=stable
func DisplayValidator(fn func(display string) error) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("username.DisplayValidator", fn) {
			return
		}
		p.displayValid = fn
	}
}

// DisplayNormalizer rewrites the display form before it is stored (say,
// collapsing spaces or NFC-normalizing). By default the display form is kept
// as sent. The rewritten form must still normalize to the handle.
//
//ds:def id=username-displaynormalizer-2wq9kt6r owner=@khanakia stability=stable
func DisplayNormalizer(fn func(display string) string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("username.DisplayNormalizer", fn) {
			return
		}
		p.displayNorm = fn
	}
}

// ValidateDisplayAfterNormalization runs DisplayValidator on the
// DisplayNormalizer result instead of the form as sent.
func ValidateDisplayAfterNormalization() Option {
	return func(p *Plugin) { p.displayAfterNorm = true }
}

// Reserved adds handles to the reserved set, on top of DefaultReserved.
//
// Additive rather than replacing, because a deployment adding its own route
// names almost never intends to also release "admin" — and if the option
// replaced the defaults, that release would be silent.
func Reserved(names ...string) Option {
	return func(p *Plugin) {
		for _, n := range names {
			p.reserved[fold(n)] = struct{}{}
		}
	}
}

var (
	_ auth.IdentifierProvider = (*Plugin)(nil)
	_ auth.OperationProvider  = (*Plugin)(nil)
	_ auth.DataHooker         = (*Plugin)(nil)
	_ auth.TableOwner         = (*Plugin)(nil)
	_ auth.Initializer        = (*Plugin)(nil)
	_ auth.Validator          = (*Plugin)(nil)
	_ auth.RateLimiter        = (*Plugin)(nil)
)

// New builds the plugin. A handle is always unique over every row: it has no
// verification, so "unique among verified" would mean not unique at all.
func New(opts ...Option) *Plugin {
	p := &Plugin{
		kind:     auth.IdentifierKind{Name: KindUsername, Unique: true, Normalize: Normalize},
		reserved: make(map[string]struct{}, len(DefaultReserved)),
		minLen:   MinLength,
		maxLen:   MaxLength,
		chars:    ValidateChars,

		availLimit:  DefaultAvailableLimit,
		availWindow: DefaultAvailableWindow,
	}
	for _, n := range DefaultReserved {
		p.reserved[n] = struct{}{}
	}
	for _, o := range opts {
		o(p)
	}
	p.kind.Validate = validateWith(p.minLen, p.maxLen, p.chars)
	p.set = auth.Define(auth.OpInfo{ID: EndpointSet, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/set"}, p.doSet)
	p.available = auth.Define(auth.OpInfo{ID: EndpointAvailable, Kind: auth.Query, Require: auth.Public, Path: "/available"}, p.doAvailable)
	return p
}

// Name returns PluginName, the key the core registers this plugin under.
func (p *Plugin) Name() string { return PluginName }

// Tables declares the aliased identity table, so auth.New can reject another
// plugin claiming the same alias.
func (p *Plugin) Tables() []sqlb.Table { return []sqlb.Table{TableIdentity} }

// Identifiers registers the username kind with the core, which from then on
// owns its uniqueness check.
func (p *Plugin) Identifiers() []auth.IdentifierKind { return []auth.IdentifierKind{p.kind} }

// Init captures the core handle Of builds its query with.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	return nil
}

// Operations lists set, and available unless WithoutAvailability left it out.
func (p *Plugin) Operations() []auth.Operation {
	if p.noAvailability {
		return []auth.Operation{p.set}
	}
	return []auth.Operation{p.set, p.available}
}

// Validate refuses length bounds nobody could satisfy, so a typo in Length
// fails auth.New rather than every set.
func (p *Plugin) Validate(*auth.Config) error {
	if p.minLen < 1 || p.maxLen < p.minLen {
		return ErrBadLength
	}
	if p.availLimit < 1 || p.availWindow <= 0 {
		return ErrBadAvailableLimit
	}
	return nil
}

// RateLimits gives the available route its own ByIP limit, so probing which
// handles exist is bounded however the app sets its blanket limit. Nothing
// when WithoutAvailability left the route out.
func (p *Plugin) RateLimits() []auth.RateRule {
	if p.noAvailability {
		return nil
	}
	return []auth.RateRule{{Match: EndpointAvailable, Key: auth.ByIP, Limit: p.availLimit, Window: p.availWindow}}
}

// DataHooks refuse a reserved handle however the identity is created.
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{Identity: auth.TableHooks[auth.Identity]{
		BeforeCreate: func(_ context.Context, _ sqlb.DBTX, row *auth.Identity) error {
			if row.Kind == KindUsername && p.IsReserved(row.Value) {
				return ErrReserved
			}
			return nil
		},
	}}
}

// Normalize lowercases and trims a handle. The typed spelling survives in
// Identity.ValueRaw for display.
//
// The error is always nil; the signature is the auth.IdentifierKind contract.
// Code in this package calls fold directly so it has no error path to ignore.
func Normalize(raw string) (string, error) { return fold(raw), nil }

// fold is the normal form of a handle.
func fold(raw string) string { return strings.ToLower(strings.TrimSpace(raw)) }

// Validate checks length and characters: lowercase letters, digits, "-" and
// "_", starting with a letter. The leading letter keeps a handle from ever
// looking like a phone number, and the missing "@" from looking like an
// address, so one sign-in field can tell the three apart.
func Validate(v string) error { return validateWith(MinLength, MaxLength, ValidateChars)(v) }

// validateWith builds a kind validator from length bounds and a character
// rule; New uses it with the plugin's options, Validate with the defaults.
func validateWith(minLen, maxLen int, chars func(string) error) func(string) error {
	return func(v string) error {
		if n := len(v); n < minLen || n > maxLen {
			return errors.New("username: wrong length")
		}
		return chars(v)
	}
}

// ValidateChars is the default character rule of Validate, without the length
// bounds: lowercase letters, digits, "-" and "_", starting with a letter.
func ValidateChars(v string) error {
	for i, r := range v {
		if i == 0 && !unicode.IsLower(r) {
			return errors.New("username: must start with a letter")
		}
		if !(r >= 'a' && r <= 'z') && !unicode.IsDigit(r) && r != '-' && r != '_' {
			return errors.New("username: letters, digits, - and _ only")
		}
	}
	return nil
}

// IsReserved reports whether a handle is withheld. The argument is normalized
// first so a check against "Admin" behaves like a check against "admin".
func (p *Plugin) IsReserved(handle string) bool {
	_, found := p.reserved[fold(handle)]
	return found
}

// Request names a handle as the user typed it; the display form keeps its
// casing, the stored form is normalized. DisplayUsername, optional, is the
// form to show instead of the one typed, such as "AdaLovelace" for the handle
// "adalovelace"; see DisplayForm.
type Request struct {
	Username        string `json:"username"`
	DisplayUsername string `json:"displayUsername,omitempty"`
}

// Result is the handle now set, in its normalized form.
//
//ds:def id=result-acs7f84u
type Result struct {
	Username string `json:"username"`
}

// Availability answers whether a handle can be claimed. Handles are public by
// nature, so answering is not an enumeration leak.
//
//ds:def id=availability-2u9y8jqf
type Availability struct {
	Available bool `json:"available"`
}

// Set claims a handle for the signed-in user, replacing the old one.
//
//ds:def id=plugin-set-chbnx53c
func (p *Plugin) Set(ctx context.Context, handle string) (Result, error) {
	return p.set.Call(ctx, Request{Username: handle})
}

// SetWithDisplay is Set with a display form other than the handle as typed;
// see DisplayForm.
func (p *Plugin) SetWithDisplay(ctx context.Context, handle, display string) (Result, error) {
	return p.set.Call(ctx, Request{Username: handle, DisplayUsername: display})
}

// DisplayForm returns the form stored and shown for handle (Data.Display):
// handle as typed when display is empty, otherwise display after
// DisplayNormalizer and DisplayValidator.
//
// One rule is not configurable: the display form must normalize to the same
// handle. Data.Display is shown wherever the handle is, so a display form
// free of the handle would let "joe" be shown as "admin", around the
// reserved list and the uniqueness the handle exists for. DisplayValidator is
// the place for a stricter rule.
//
//ds:def id=username-displayform-6vk2mr8t owner=@khanakia stability=stable
func (p *Plugin) DisplayForm(handle, display string) (string, error) {
	if display == "" {
		return handle, nil
	}
	shown := display
	if p.displayNorm != nil {
		shown = p.displayNorm(display)
	}
	if p.displayValid != nil {
		checked := display
		if p.displayAfterNorm {
			checked = shown
		}
		if err := p.displayValid(checked); err != nil {
			return "", ErrDisplayInvalid
		}
	}
	want, err := p.kind.Normalize(handle)
	if err != nil {
		return "", err
	}
	got, err := p.kind.Normalize(shown)
	if err != nil || got != want {
		return "", ErrDisplayInvalid
	}
	return shown, nil
}

// Available reports whether a handle can be claimed now. The answer can be
// stale by the time Set runs; the unique index is the authority.
//
//ds:def id=plugin-available-ejr8ztwd
func (p *Plugin) Available(ctx context.Context, handle string) (bool, error) {
	r, err := p.available.Call(ctx, Request{Username: handle})
	return r.Available, err
}

// Claim gives userID the handle as part of a larger operation, such as a
// password sign-up that takes a username in the same body. It applies every
// rule Set applies — normalization, length, characters, the reserved list,
// uniqueness — and refuses a user who already has a handle with ErrImmutable
// under Immutable(), or replaces it otherwise.
//
// It is not an operation of its own: the caller is one (the password
// plugin's sign-up), already inside the pipeline and its transaction, so the
// handle and the account commit or roll back together. From outside an
// operation use Set.
//
//ds:def id=plugin-claim-2v8xk7qn owner=@khanakia stability=stable
func (p *Plugin) Claim(ctx context.Context, userID, handle string) error {
	return p.ClaimWithDisplay(ctx, userID, handle, "")
}

// ClaimWithDisplay is Claim with a display form other than the handle as
// typed (a sign-up body's displayUsername); see DisplayForm.
func (p *Plugin) ClaimWithDisplay(ctx context.Context, userID, handle, display string) error {
	if p.core == nil {
		return auth.ErrOperationNotWired
	}
	ids, err := p.core.Identities(ctx, userID)
	if err != nil {
		return err
	}
	_, err = p.replaceHandle(ctx, userID, ids, handle, display)
	return err
}

// replaceHandle creates the new handle identity and removes the user's old
// ones; Set and Claim share it so the rename rule lives once. The identity's
// raw value is the display form, which normalizes to the handle by
// DisplayForm's rule, so the stored handle is the same either way.
func (p *Plugin) replaceHandle(ctx context.Context, userID string, ids []auth.Identity, handle, display string) (auth.Identity, error) {
	if p.immutable && hasHandle(ids) {
		return auth.Identity{}, ErrImmutable
	}
	raw, err := p.DisplayForm(handle, display)
	if err != nil {
		return auth.Identity{}, err
	}
	created, err := p.core.CreateIdentity(ctx, auth.NewIdentity{UserID: userID, Kind: KindUsername, Raw: raw, Verified: true, Primary: true})
	if err != nil {
		return auth.Identity{}, err
	}
	for _, idn := range ids {
		if idn.Kind == KindUsername {
			if err := p.core.DeleteIdentity(ctx, userID, idn.ID); err != nil {
				return auth.Identity{}, err
			}
		}
	}
	return created, nil
}

func (p *Plugin) doSet(ctx context.Context, c *auth.Call, in Request) (Result, error) {
	ids, err := c.Auth.Identities(ctx, c.User.ID)
	if err != nil {
		return Result{}, err
	}
	created, err := p.replaceHandle(ctx, c.User.ID, ids, in.Username, in.DisplayUsername)
	if err != nil {
		return Result{}, err
	}
	return Result{Username: created.Value}, nil
}

func (p *Plugin) doAvailable(ctx context.Context, c *auth.Call, in Request) (Availability, error) {
	v, err := c.Auth.Normalize(KindUsername, in.Username)
	if err != nil || p.IsReserved(v) {
		return Availability{}, nil
	}
	_, err = c.Auth.FindIdentity(ctx, KindUsername, v, false)
	if errors.Is(err, auth.ErrIdentityNotFound) {
		return Availability{Available: true}, nil
	}
	return Availability{}, err
}

// hasHandle reports whether ids holds a username identity.
func hasHandle(ids []auth.Identity) bool {
	for _, idn := range ids {
		if idn.Kind == KindUsername {
			return true
		}
	}
	return false
}

// UserJoin brings the handle into a composite user query; see the
// package-level UserJoin.
func (p *Plugin) UserJoin() sqlb.Join { return UserJoin() }

// UserJoin is the package-level form for an application assembling a composite
// destination.
//
// LEFT because a user need not have a handle, and constrained by kind because
// the identity table holds every identifier kind in one place.
func UserJoin() sqlb.Join {
	return sqlb.Join{
		Type:  sqlb.JoinLeft,
		Table: TableIdentity,
		On: []sqlb.Predicate{
			sqlb.EqExpr(IdentityUserID, auth.UserID),
			sqlb.Eq(IdentityKind, KindUsername),
		},
	}
}

// UserBindings binds this plugin's columns to dst, flattening the LEFT join's nulls
// to empty strings.
func UserBindings(dst *Data) []sqlb.Binding {
	empty := sqlb.Literal[string]("''")
	return []sqlb.Binding{
		sqlb.Bind(sqlb.Coalesce(IdentityValue, empty), &dst.Handle),
		sqlb.Bind(sqlb.Coalesce(IdentityValueRaw, empty), &dst.Display),
	}
}

// Of builds the standalone lookup for one user's handle. It fails with
// auth.ErrPluginNotRegistered when a is not wired with this plugin.
func Of(a *auth.Auth, userID string, dst *Data) (sqlb.Query, error) {
	p, err := auth.PluginOf[*Plugin](a)
	if err != nil {
		return sqlb.Query{}, err
	}
	return p.core.Select().
		Columns(UserBindings(dst)...).
		From(TableIdentity).
		Where(
			sqlb.Eq(IdentityUserID, userID),
			sqlb.Eq(IdentityKind, KindUsername),
		).
		Build()
}

// ByHandleQuery resolves a user from a handle.
//
// The handle is normalized in Go and compared exactly. Handles are stored in
// the same normal form, so the exact comparison finds them and uses the plain
// unique index; a SQL lower() would add a second folding rule that differs
// between engines. See auth.Auth.FindIdentity.
//
//ds:def id=byhandlequery-avta9z5p
func ByHandleQuery(a *auth.Auth, rawHandle string, dst *auth.User) (sqlb.Query, error) {
	return a.Select().
		Columns(auth.UserBindings(dst)...).
		From(auth.TableUser).
		Join(sqlb.Join{
			Type:  sqlb.JoinInner,
			Table: TableIdentity,
			On: []sqlb.Predicate{
				sqlb.EqExpr(IdentityUserID, auth.UserID),
				sqlb.Eq(IdentityKind, KindUsername),
			},
		}).
		Where(sqlb.Eq(IdentityValue, fold(rawHandle))).
		Build()
}
