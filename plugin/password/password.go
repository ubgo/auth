// Package password is the password sign-in method: argon2id hashes in its own
// auth_password table, sign-up, sign-in with any sign-in identifier,
// forgotten-password reset through whatever recovery channel the user has, and
// change.
//
// It has no email code and no SMS code. It asks the core for the user behind
// an identifier and for a recovery channel, so it works the same in an
// email-first, phone-first or handle-only app.
package password

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity. It owns the plugin's rows in
// the migration ledger and its tables and columns, so renaming it would make
// the next migrate see a new plugin; it never changes.
const PluginName = "password"

// Operation ids, the permanent names hooks, rate rules and transports address
// the plugin's operations by.
const (
	EndpointSignUp auth.EndpointID = "password.sign-up"
	EndpointSignIn auth.EndpointID = "password.sign-in"
	EndpointForgot auth.EndpointID = "password.forgot"
	EndpointReset  auth.EndpointID = "password.reset"
	EndpointChange auth.EndpointID = "password.change"
	EndpointVerify auth.EndpointID = "password.verify"
	// EndpointReauthenticate proves the signed-in user's password on the
	// session they hold and makes it fresh again (auth.Reauthenticate),
	// instead of a new sign-in that would create a second session.
	EndpointReauthenticate auth.EndpointID = "password.reauthenticate"
	// EndpointResetCode resets the password with a one-time code instead of
	// a link; it replaces EndpointReset under ResetByCode.
	EndpointResetCode auth.EndpointID = "password.reset-code"
)

// Operation paths under the auth mount. Unexported because a transport reads
// them from each operation's OpInfo, never by name.
const (
	pathSignUp    = "/sign-up"
	pathSignIn    = "/sign-in"
	pathForgot    = "/forgot"
	pathReset     = "/reset"
	pathChange    = "/change"
	pathVerify    = "/verify"
	pathReauth    = "/reauthenticate"
	pathResetCode = "/reset-code"
)

// PurposeResetToken is the verification purpose of a reset link. Its
// Identifier is the user id.
const PurposeResetToken auth.Purpose = "password.reset"

// PurposeResetCode is the one-time-code purpose of a reset code (ResetByCode).
// Its subject is the user id, so a code is only ever checked against the
// account it was issued for.
const PurposeResetCode auth.Purpose = "password.reset_code"

// The plugin's table: one row per user who has a password, keyed by the user
// id, so "has a password" is a primary-key lookup.
const (
	//ds:def id=tablenamepassword-wn2mjcwy owner=@khanakia stability=stable
	TableNamePassword  = "auth_password"
	TableAliasPassword = "pw"
	ColUserID          = "user_id"
	ColHash            = "hash"
	// ColUpdatedAt is when the password was last set: sign-up, change,
	// reset, change-expired, SetPassword or ImportHash. The re-hash at
	// sign-in replaces the hash and keeps this time, so it is the password's
	// age, which ExpireAfter reads.
	ColUpdatedAt = "updated_at"
)

// TablePassword and its typed columns, for an app that reads the table (reads
// are open; only the plugin writes it).
var (
	TablePassword = sqlb.Table{Name: TableNamePassword, Alias: TableAliasPassword}
	UserID        = sqlb.Col[string](TablePassword, ColUserID)
	Hash          = sqlb.Col[string](TablePassword, ColHash)
	UpdatedAt     = sqlb.Col[time.Time](TablePassword, ColUpdatedAt)
)

// Length limits. The maximum bounds the work one request can ask of argon2;
// NIST asks that at least 64 characters be allowed.
const (
	// DefaultMinLength is NIST SP 800-63B's minimum for a user-chosen
	// password. It counts characters, not bytes.
	//ds:def id=defaultminlength-8nyr776x owner=@khanakia stability=stable
	DefaultMinLength = 8
	// DefaultMaxLength is in bytes: it bounds the input argon2 hashes, which
	// is what the limit protects. 256 bytes is 64 four-byte characters, the
	// NIST floor for the maximum.
	//ds:def id=defaultmaxlength-zux6j6ma owner=@khanakia stability=stable
	DefaultMaxLength = 256
	// DefaultResetTTL: one hour, long enough to find the mail.
	//ds:def id=defaultresetttl-2vkb6wb9 owner=@khanakia stability=stable
	DefaultResetTTL = time.Hour
)

// DefaultResetPage is the app page a reset link opens; it reads the token from
// the query and POSTs it with the new password to password.reset.
//
//ds:def id=defaultresetpage-368asg23 owner=@khanakia stability=stable
const DefaultResetPage = "/reset-password"

// resetTokenParam is the query parameter of DefaultResetPage that carries the
// reset token.
const resetTokenParam = "token"

// Rate limits. Sign-in is bounded per IP (a spray across accounts) and per
// account (guessing one password from many IPs); sign-up per IP and per
// identifier (flooding one address with notices); forgot per account, because
// every call can send mail.
const (
	//ds:def id=signiniplimit-a4yqscxz owner=@khanakia stability=stable
	signInIPLimit  = 20
	signInIPWindow = time.Minute
	//ds:def id=signinaccountlimit-yz756w5r owner=@khanakia stability=stable
	signInAccountLimit  = 5
	signInAccountWindow = 15 * time.Minute
	//ds:def id=signupiplimit-q4rubgct owner=@khanakia stability=stable
	signUpIPLimit  = 10
	signUpIPWindow = time.Hour
	//ds:def id=signupidlimit-f3u8bpzw owner=@khanakia stability=stable
	signUpIDLimit  = 5
	signUpIDWindow = time.Hour
	//ds:def id=forgotlimit-5j2x9w6c owner=@khanakia stability=stable
	forgotLimit  = 3
	forgotWindow = time.Hour
	// resetCodeLimit bounds reset-code per account: the core's attempt cap
	// spends a code after a few wrong guesses, and this bounds how many codes
	// an hour one account can be guessed at from any number of addresses.
	//ds:def id=resetcodelimit-9m3kx2vq owner=@khanakia stability=stable
	resetCodeLimit  = 10
	resetCodeWindow = time.Hour
	// verifyIPLimit bounds password.verify like sign-in: it runs the same
	// argon2 check, and a signed-in client must not get a cheaper oracle.
	//ds:def id=verifyiplimit-57x9qjkf owner=@khanakia stability=stable
	verifyIPLimit  = signInIPLimit
	verifyIPWindow = signInIPWindow
	// reauthIPLimit and reauthAccountLimit bound password.reauthenticate as
	// sign-in is bounded, per address and per account (the signed-in user):
	// it is the same argon2 guess, and a stolen session must not get more
	// guesses at the password than a stranger at the sign-in form.
	//ds:def id=password-reauthlimits-6wq3nx8p owner=@khanakia stability=stable
	reauthIPLimit       = signInIPLimit
	reauthIPWindow      = signInIPWindow
	reauthAccountLimit  = signInAccountLimit
	reauthAccountWindow = signInAccountWindow
)

// Errors. The *auth.Error values are what a client sees; the plain errors are
// configuration mistakes auth.New refuses at start-up.
var (
	ErrInvalidCredentials = auth.NewError("password.invalid_credentials", http.StatusUnauthorized, "The sign-in details are not right.")
	ErrTooShort           = auth.NewError("password.too_short", http.StatusBadRequest, "Choose a longer password.")
	ErrTooLong            = auth.NewError("password.too_long", http.StatusBadRequest, "Choose a shorter password.")
	ErrWeak               = auth.NewError("password.weak", http.StatusBadRequest, "Choose a stronger password.")
	ErrBreached           = auth.NewError("password.breached", http.StatusBadRequest, "This password has appeared in a data breach. Choose another one.")

	// ErrNoUsernames: a sign-up body carried a username, but no
	// UsernameClaimer (the username plugin) is wired, so there is nothing to
	// claim it with.
	ErrNoUsernames = auth.NewError("password.no_usernames", http.StatusBadRequest, "Usernames are not available.")
	// ErrHashUnrecognized refuses ImportHash with a string that neither the
	// Hasher nor any AcceptLegacyHashes verifier recognizes, so a botched
	// export fails at import time rather than as a server error at the
	// user's first sign-in.
	ErrHashUnrecognized = auth.NewError("password.hash_unrecognized", http.StatusBadRequest, "The password hash is in no recognized format.")
	// ErrHasPassword refuses ImportHash for a user who already has a
	// password: an import must never silently replace a credential the user
	// set here; SetPassword is the deliberate replacement.
	ErrHasPassword = auth.NewError("password.has_password", http.StatusConflict, "This user already has a password.")
	// ErrRedirectInvalid refuses a forgot request whose redirectTo is not a
	// page of this site or of an origin the deployment trusts
	// (auth.Auth.TrustsReturnURL), or is a custom scheme or loopback return,
	// which may carry nothing secret; also a site path when there is no
	// auth.WithBaseURL to make it absolute. It depends on the input only, so
	// it says nothing about whether an account exists.
	//ds:def id=errredirectinvalid-password-6pk3wq8n owner=@khanakia stability=stable
	ErrRedirectInvalid = auth.NewError("password.redirect_invalid", http.StatusBadRequest, "This page cannot receive a reset link.")

	ErrNoLoginKind  = errors.New("password: no identifier can sign in; add one with Login(), for example email.New(email.Login())")
	ErrNoRecovery   = errors.New("password: no identifier can recover an account; add one with Recover(), for example email.New(email.Recover()), or pass password.WithoutRecovery()")
	ErrNoResetLinks = errors.New("password: reset links need auth.WithBaseURL or password.ResetLinks")
	// ErrBadLengths refuses a MaxLength under 1 or under MinLength, and a
	// negative MinLength: with MaxLength(0) every sign-up answered
	// password.too_long, a zero limit that looked like a working setting.
	ErrBadLengths = errors.New("password: MinLength must be 0 or more, and MaxLength at least 1 and at least MinLength")
)

// BreachChecker reports whether a password is known from a breach, such as a
// client of the Have I Been Pwned range API (package hibp). An interface so an
// app can use a local list or another service instead.
//
//ds:def id=breachchecker-qa5hp5a3 owner=@khanakia stability=stable
type BreachChecker interface {
	Breached(ctx context.Context, password string) (bool, error)
}

// BreachMessenger is an optional upgrade of a BreachChecker that words the
// refusal itself (package hibp's WithMessage). A non-empty BreachedMessage
// replaces ErrBreached's message; the code (password.breached) and the status
// never change, so a client matching codes sees no difference, and a
// WithMessages catalogue entry for the code still wins in its locale.
//
//ds:def id=breachmessenger-7kx2qm9v owner=@khanakia stability=stable
type BreachMessenger interface {
	BreachedMessage() string
}

// Plugin is the password sign-in method. Build it with New and pass it to
// auth.WithPlugins; its Go methods and its HTTP routes run the same operations.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs        auth.OptionErrors
	minLen, maxLen int
	// stuffing is GuardCredentialStuffing, or nil.
	stuffing *stuffingGuard
	params   Argon2Params
	// hasher makes every new hash and verifies its own format; legacy
	// verifiers are tried, in order, for stored strings it does not
	// recognize, and a match of theirs is re-hashed with hasher.
	hasher     Hasher
	legacy     []Verifier
	noRecovery bool
	// byCode makes forgot send a one-time code and replaces the link reset
	// with reset-code.
	byCode        bool
	noSignUp      bool
	noSessionAtUp bool
	resetTTL      time.Duration
	links         func(t auth.Token) string
	// keepOnReset and keepOnChange keep sessions alive: a reset
	// leaves every session alive, a change leaves the other sessions alive
	// unless the request asks to revoke them.
	keepOnReset  bool
	keepOnChange bool
	breached     BreachChecker
	policies     []func(pw string) error
	// history is how many passwords a new one may not match, counting the
	// current one (History); 0 is off.
	history int
	// expireAfter is how long a password lasts (ExpireAfter); 0 is forever.
	expireAfter time.Duration

	// dummy is a real hash of a random value, checked when an identifier
	// matches nobody, so an unknown account costs the same argon2 work as a
	// wrong password.
	dummy string
	core  *auth.Auth

	signUp *auth.Op[SignUpRequest, SignInResult]
	signIn *auth.Op[SignInRequest, SignInResult]
	forgot *auth.Op[ForgotRequest, ForgotResult]
	reset  *auth.Op[ResetRequest, auth.Done]
	change *auth.Op[ChangeRequest, auth.Done]
	verify *auth.Op[VerifyRequest, auth.Done]
	reauth *auth.Op[ReauthenticateRequest, auth.Reauthentication]
	// resetCode exists under ResetByCode in place of reset.
	resetCode *auth.Op[ResetCodeRequest, auth.Done]
	// changeExpired exists under ExpireAfter.
	changeExpired *auth.Op[ChangeExpiredRequest, SignInResult]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin; pass options to New.
type Option func(*Plugin)

// MinLength sets the shortest password accepted, in characters. It applies to
// new passwords only; an existing shorter one still signs in.
func MinLength(n int) Option { return func(p *Plugin) { p.minLen = n } }

// MaxLength sets the longest password accepted, in bytes. Sign-in refuses a
// longer one before hashing, so the limit also bounds the argon2 work an
// anonymous request can cause.
func MaxLength(n int) Option { return func(p *Plugin) { p.maxLen = n } }

// Argon2 sets the hash cost. Existing hashes with other parameters are
// replaced at the user's next successful sign-in.
func Argon2(params Argon2Params) Option { return func(p *Plugin) { p.params = params } }

// WithHasher replaces argon2id as the algorithm new and re-hashed passwords
// are stored with: an HSM, a key-derivation service, or your own parameters
// behind the Hasher interface. Stored hashes the new Hasher does not recognize
// (yesterday's argon2id strings, say) keep verifying only if a verifier for
// them is listed in AcceptLegacyHashes; pass password.Argon2id{Params: …}
// there to keep the old ones working. With WithHasher, Argon2 has no effect.
func WithHasher(h Hasher) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("password.WithHasher", h) {
			return
		}
		p.hasher = h
	}
}

// Hasher returns the hasher the plugin makes and checks hashes with (the
// WithHasher one, else Argon2id with the plugin's parameters), for a hook or
// plugin that must hash a secret under the same policy, never a weaker one of
// its own.
//
//ds:def id=password-hasher-accessor-6kq3wn8x owner=@khanakia stability=stable
func (p *Plugin) Hasher() Hasher { return p.hasher }

// AcceptLegacyHashes verifies stored hashes in other formats, for a user base
// imported from another stack: Bcrypt() for Rails, Laravel and Spring,
// Scrypt(BetterAuthScrypt) for hexsalt:hexkey scrypt hashes, DjangoPBKDF2()
// for Django, or any Verifier of your own. A legacy hash is checked at
// sign-in, change and verify, and replaced with the Hasher's hash at the next
// successful sign-in, so the old format disappears one user at a time without
// a reset for anyone. Verifiers are asked in the order given; the first that
// Recognizes a stored string decides.
func AcceptLegacyHashes(v ...Verifier) Option {
	return func(p *Plugin) {
		if auth.RefuseNilEach(&p.optErrs, "password.AcceptLegacyHashes", v) {
			return
		}
		p.legacy = append(p.legacy, v...)
	}
}

// WithoutRecovery is the named way to run without password reset. The safe
// configuration is the default; this one has a name you must type.
func WithoutRecovery() Option { return func(p *Plugin) { p.noRecovery = true } }

// ResetByCode makes forgot send a one-time code instead of a link, and
// replaces the reset operation with reset-code, which takes the identifier,
// the code and the new password. For a phone-first app, where a link in a
// text is awkward, or a flow that keeps the user on the same screen. The code
// goes out through the same recovery channel the link would (an address or a
// number the user verified), lives ResetTTL, and is spent by the core's
// attempt cap after a few wrong guesses. No base URL or ResetLinks is needed.
func ResetByCode() Option { return func(p *Plugin) { p.byCode = true } }

// WithoutSignUp removes the sign-up operation: accounts are created some other
// way (an invite, an admin, a social sign-in) and only sign in with a
// password here. The route does not exist, so a client gets 404 rather than a
// refusal that hints at a hidden feature.
func WithoutSignUp() Option { return func(p *Plugin) { p.noSignUp = true } }

// SignUpWithoutSession makes sign-up create the account and issue no session:
// the result carries the user and no token, and the client signs in as a
// separate step. For an app that wants an explicit first sign-in, or a
// sign-up form that is not the sign-in form. An identifier kind with
// RequireVerified() already behaves this way.
func SignUpWithoutSession() Option { return func(p *Plugin) { p.noSessionAtUp = true } }

// ResetTTL overrides DefaultResetTTL, how long a reset link works. Every other
// open link is spent when one is used, so a longer TTL does not widen what a
// leaked old mail can do after a reset.
func ResetTTL(d time.Duration) Option { return func(p *Plugin) { p.resetTTL = d } }

// ResetLinks builds the reset URL. It must open a page of the app that POSTs
// the token with the new password: a link that performed the reset on GET
// would be spent by mail scanners that prefetch links. Without it the link is
// BaseURL + DefaultResetPage + "?token=…".
func ResetLinks(fn func(t auth.Token) string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("password.ResetLinks", fn) {
			return
		}
		p.links = fn
	}
}

// KeepSessionsOnReset leaves every session of the account alive after a
// reset. By default a reset signs out every session, because a reset is so
// often the answer to a stolen account: under this option a thief who already
// holds a session keeps it after the owner resets. Open reset links are still
// spent and the other plugins still hear that the credential changed
// (two-factor forgets its trusted devices).
//
//ds:def id=keepsessionsonreset-3vq8nk2w owner=@khanakia stability=stable
func KeepSessionsOnReset() Option { return func(p *Plugin) { p.keepOnReset = true } }

// KeepSessionsOnChange makes a password change leave the user's other
// sessions alive unless the request sets revokeOtherSessions to true. By
// default a change signs out every other session and
// ChangeRequest.RevokeOtherSessions cannot turn that off: a client must not
// be able to weaken the response to a stolen account. The same risk as
// KeepSessionsOnReset applies.
//
//ds:def id=keepsessionsonchange-8mx4qt5r owner=@khanakia stability=stable
func KeepSessionsOnChange() Option { return func(p *Plugin) { p.keepOnChange = true } }

// Policy adds a rule every new password must pass, such as a company
// requirement. Length is the rule that matters most and is always checked
// first; a policy that fails returns its own *auth.Error or, for any other
// error, ErrWeak.
func Policy(fn func(pw string) error) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("password.Policy", fn) {
			return
		}
		p.policies = append(p.policies, fn)
	}
}

// RequireClasses asks for characters from at least n of four classes:
// lowercase, uppercase, digits, and everything else. NIST advises length
// over such rules; this exists because some products must have them.
func RequireClasses(n int) Option {
	return Policy(func(pw string) error {
		var lower, upper, digit, other bool
		for _, r := range pw {
			switch {
			case unicode.IsLower(r):
				lower = true
			case unicode.IsUpper(r):
				upper = true
			case unicode.IsDigit(r):
				digit = true
			default:
				other = true
			}
		}
		count := 0
		for _, b := range []bool{lower, upper, digit, other} {
			if b {
				count++
			}
		}
		if count < n {
			return ErrWeak
		}
		return nil
	})
}

// CheckBreached refuses new passwords the checker reports as breached. A
// checker error fails the sign-up, reset or change with that error; the hibp
// checker's FailOpen is the named way to prefer availability.
func CheckBreached(c BreachChecker) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("password.CheckBreached", c) {
			return
		}
		p.breached = c
	}
}

var (
	_ auth.SignInMethod      = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.TypedMigrator     = (*Plugin)(nil)
	_ auth.TableOwner        = (*Plugin)(nil)
	_ auth.UserTableOwner    = (*Plugin)(nil)
	_ auth.RateLimiter       = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
)

// New builds the plugin. The safe configuration is the default: recovery on,
// OWASP argon2 cost, NIST lengths.
func New(opts ...Option) *Plugin {
	p := &Plugin{minLen: DefaultMinLength, maxLen: DefaultMaxLength, params: DefaultArgon2, resetTTL: DefaultResetTTL}
	for _, o := range opts {
		o(p)
	}
	if p.hasher == nil {
		p.hasher = Argon2id{Params: p.params}
	}
	p.signUp = auth.Define(auth.OpInfo{ID: EndpointSignUp, Kind: auth.Mutation, Require: auth.Public, Path: pathSignUp}, p.doSignUp)
	p.signIn = auth.Define(auth.OpInfo{ID: EndpointSignIn, Kind: auth.Mutation, Require: auth.Public, Path: pathSignIn, SignIn: true}, p.doSignIn)
	p.forgot = auth.Define(auth.OpInfo{ID: EndpointForgot, Kind: auth.Mutation, Require: auth.Public, Path: pathForgot}, p.doForgot)
	p.reset = auth.Define(auth.OpInfo{ID: EndpointReset, Kind: auth.Mutation, Require: auth.Public, Path: pathReset}, p.doReset)
	p.change = auth.Define(auth.OpInfo{ID: EndpointChange, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: pathChange}, p.doChange)
	p.verify = auth.Define(auth.OpInfo{ID: EndpointVerify, Kind: auth.Mutation, Require: auth.SignedIn, Path: pathVerify}, p.doVerify)
	p.reauth = auth.Define(auth.OpInfo{ID: EndpointReauthenticate, Kind: auth.Mutation, Require: auth.SignedIn, Path: pathReauth}, p.doReauthenticate)
	p.resetCode = auth.Define(auth.OpInfo{ID: EndpointResetCode, Kind: auth.Mutation, Require: auth.Public, Path: pathResetCode}, p.doResetCode)
	p.changeExpired = auth.Define(auth.OpInfo{ID: EndpointChangeExpired, Kind: auth.Mutation, Require: auth.Public, Path: pathChangeExpired, SignIn: true}, p.doChangeExpired)
	return p
}

// Name is PluginName, the plugin's permanent identity in the migration ledger
// and in column ownership.
func (p *Plugin) Name() string { return PluginName }

// SignsIn reports that a password is a way in, so auth.New counts the plugin
// as a sign-in method and the core refuses to remove a user's last one.
func (p *Plugin) SignsIn() bool { return true }

// Tables declares the plugin's tables, so auth.New can refuse another plugin
// claiming the same name or alias; the history table only under History.
func (p *Plugin) Tables() []sqlb.Table {
	if p.history > 0 {
		return []sqlb.Table{TablePassword, TablePasswordHistory}
	}
	return []sqlb.Table{TablePassword}
}

// UserTables declares that auth_password rows (and, under History,
// auth_password_history rows) belong to the user in user_id, so DeleteUser
// removes them (no foreign key does, ADR-0002).
func (p *Plugin) UserTables() []auth.UserTable {
	out := []auth.UserTable{{Table: TablePassword, Column: ColUserID}}
	if p.history > 0 {
		out = append(out, auth.UserTable{Table: TablePasswordHistory, Column: ColHistoryUserID})
	}
	return out
}

// Validate refuses a configuration where nobody could sign in or recover.
func (p *Plugin) Validate(c *auth.Config) error {
	if p.minLen < 0 || p.maxLen < 1 || p.maxLen < p.minLen {
		return fmt.Errorf("%w (MinLength %d, MaxLength %d)", ErrBadLengths, p.minLen, p.maxLen)
	}
	if err := p.validatePolicies(); err != nil {
		return err
	}
	if p.stuffing != nil {
		if err := p.stuffing.validate(c); err != nil {
			return err
		}
	}
	if len(c.LoginKinds()) == 0 {
		return ErrNoLoginKind
	}
	if p.noRecovery {
		return nil
	}
	if len(c.RecoveryKinds()) == 0 {
		return ErrNoRecovery
	}
	if !p.byCode && p.links == nil && c.BaseURL == "" {
		return ErrNoResetLinks
	}
	return nil
}

// Init computes the dummy hash with the configured Hasher and fills the
// default reset link. The dummy comes from the Hasher, not from argon2
// directly, so an unknown account costs exactly what a wrong password on a
// current hash costs whatever the algorithm is.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	dummy, err := p.hasher.Hash(Secret(rand.Text()))
	if err != nil {
		return err
	}
	p.dummy = dummy
	if p.stuffing != nil {
		if err := p.stuffing.init(a); err != nil {
			return err
		}
	}
	if p.links == nil && !p.byCode {
		base := strings.TrimSuffix(a.Config().BaseURL, "/")
		p.links = func(t auth.Token) string {
			return base + DefaultResetPage + "?" + url.Values{resetTokenParam: {t.Reveal()}}.Encode()
		}
	}
	return nil
}

// Operations lists every operation; sign-up exists unless WithoutSignUp, and
// forgot and reset (or reset-code under ResetByCode) only with recovery.
func (p *Plugin) Operations() []auth.Operation {
	ops := []auth.Operation{p.signIn, p.change, p.verify, p.reauth}
	if !p.noSignUp {
		ops = append(ops, p.signUp)
	}
	if p.expireAfter > 0 {
		ops = append(ops, p.changeExpired)
	}
	switch {
	case p.noRecovery:
	case p.byCode:
		ops = append(ops, p.forgot, p.resetCode)
	default:
		ops = append(ops, p.forgot, p.reset)
	}
	return ops
}

// RateLimits bounds guessing and mail; the forgot rule exists only with
// recovery, because the operation does.
//
//ds:def id=password-ratelimits-k2sm7ztg owner=@khanakia stability=stable
func (p *Plugin) RateLimits() []auth.RateRule {
	rules := []auth.RateRule{
		{Match: EndpointSignIn, Key: auth.ByIP, Limit: signInIPLimit, Window: signInIPWindow},
		{Match: EndpointSignIn, Key: auth.ByIdentifier, Limit: signInAccountLimit, Window: signInAccountWindow},
		{Match: EndpointVerify, Key: auth.ByIP, Limit: verifyIPLimit, Window: verifyIPWindow},
		{Match: EndpointReauthenticate, Key: auth.ByIP, Limit: reauthIPLimit, Window: reauthIPWindow},
		{Match: EndpointReauthenticate, Key: auth.ByFunc, Limit: reauthAccountLimit, Window: reauthAccountWindow, KeyFunc: auth.UserRateKey},
	}
	if !p.noSignUp {
		rules = append(rules,
			auth.RateRule{Match: EndpointSignUp, Key: auth.ByIP, Limit: signUpIPLimit, Window: signUpIPWindow},
			auth.RateRule{Match: EndpointSignUp, Key: auth.ByIdentifier, Limit: signUpIDLimit, Window: signUpIDWindow},
		)
	}
	if p.expireAfter > 0 {
		// change-expired checks a password, so it is bounded like sign-in.
		rules = append(rules,
			auth.RateRule{Match: EndpointChangeExpired, Key: auth.ByIP, Limit: signInIPLimit, Window: signInIPWindow},
			auth.RateRule{Match: EndpointChangeExpired, Key: auth.ByIdentifier, Limit: signInAccountLimit, Window: signInAccountWindow},
		)
	}
	if !p.noRecovery {
		rules = append(rules, auth.RateRule{Match: EndpointForgot, Key: auth.ByIdentifier, Limit: forgotLimit, Window: forgotWindow})
	}
	if !p.noRecovery && p.byCode {
		rules = append(rules,
			auth.RateRule{Match: EndpointResetCode, Key: auth.ByIP, Limit: signInIPLimit, Window: signInIPWindow},
			auth.RateRule{Match: EndpointResetCode, Key: auth.ByIdentifier, Limit: resetCodeLimit, Window: resetCodeWindow},
		)
	}
	return rules
}

// TypedMigrations creates auth_password for engine, and refuses an engine the core
// does not know. The table is named through the core, which knows what the
// app called it (auth.RenameTable, auth.WithTablePrefix).
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	ms := []auth.Migration{{Owner: PluginName, Name: "0001_password", Statements: []string{
		"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TablePassword) + " (" +
			ColUserID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColHash + " " + t.Text + " NOT NULL, " +
			ColUpdatedAt + " " + t.Timestamp + " NOT NULL)" + t.TableSuffix,
	}}}
	if p.history > 0 {
		ms = append(ms, p.historyMigration(engine, t))
	}
	return ms, nil
}

// Secret is a password as it travels through the plugin. It is auth.Token's
// redacted string: every formatting path, slog and JSON encoding print
// "[redacted]", so a logged request struct never shows a password. Read it
// only with Reveal. JSON decoding into it works like a plain string.
type Secret = auth.Token

// UsernameClaimer is what sign-up needs to claim SignUpRequest.Username for
// the new account: the method `*username.Plugin` already has. Found through
// auth.PluginOf when a sign-up carries a username, so this plugin imports no
// identifier plugin and an app's own handle scheme can take the claim. It is
// called inside the sign-up transaction: an error fails the whole sign-up.
// display is SignUpRequest.DisplayUsername, "" when none was sent.
type UsernameClaimer interface {
	auth.Plugin
	ClaimWithDisplay(ctx context.Context, userID, handle, display string) error
}

// SignUpRequest is the input of sign-up.
type SignUpRequest struct {
	Identifier string `json:"identifier"`
	Password   Secret `json:"password"`
	// Name is the display name; optional, an account without one has "".
	Name string `json:"name,omitempty"`
	// Image is the user's picture URL, optional; it can also be set later
	// through the core profile operation.
	Image string `json:"image,omitempty"`
	// Remember is the "remember me" box, as on SignInRequest: nil or true
	// keeps the session past the browser, false makes it transient. Ignored
	// when no session is issued.
	Remember *bool `json:"remember,omitempty"`
	// Username, optional, claims a handle for the new account in the same
	// transaction, through the registered UsernameClaimer (the username
	// plugin's ClaimWithDisplay), so an email-plus-handle sign-up is one
	// call: a taken or reserved handle fails the whole sign-up and no half
	// account is left. ErrNoUsernames when no UsernameClaimer is wired.
	Username string `json:"username,omitempty"`
	// DisplayUsername, optional, is the form of Username to show
	// (displayUsername), checked by the claimer's display
	// rules (the username plugin's DisplayForm). Ignored without Username.
	DisplayUsername string `json:"displayUsername,omitempty"`
	// Fields sets other auth_user columns of the new account: only the
	// columns auth.WithSignUpFields names, each of its declared JSON type.
	// Anything else is auth.ErrFieldInvalid (400) before any row is written.
	// The values go through the core's column writer, in the sign-up
	// transaction. The same columns may also be sent as top-level keys; one
	// sent both ways is auth.ErrFieldInvalid.
	Fields auth.Fields `json:"fields,omitempty"`
	// top holds the top-level keys of a JSON body that are not fields of
	// this struct, for auth.Auth.MergeFields; never set from Go.
	top auth.Fields
}

// UnmarshalJSON keeps the top-level keys that are not the request's own, so
// sign-up fields may sit beside identifier and password; auth.Auth.MergeFields
// then refuses any that is not a declared column.
func (r *SignUpRequest) UnmarshalJSON(data []byte) error {
	type plain SignUpRequest
	var p plain
	top, err := auth.SplitBody(data, &p)
	if err != nil {
		return err
	}
	*r = SignUpRequest(p)
	r.top = top
	return nil
}

// RateIdentifier counts sign-ups per identifier, so one address cannot be
// flooded with sign-up attempts from many IPs.
func (r SignUpRequest) RateIdentifier() string { return foldKey(r.Identifier) }

// SignInRequest is the input of sign-in.
//
//ds:def id=signinrequest-w2xepzbx owner=@khanakia stability=stable
type SignInRequest struct {
	Identifier string `json:"identifier"`
	Password   Secret `json:"password"`
	// Remember is the "remember me" box. Nil means remember, the usual
	// default; false makes a transient session that ends with the browser.
	Remember *bool `json:"remember,omitempty"`
}

// RateIdentifier counts sign-in attempts per account.
func (r SignInRequest) RateIdentifier() string { return foldKey(r.Identifier) }

// SignInResult is the output of sign-up and sign-in.
//
// Token is the raw session token for Go callers and bearer clients. It is
// never encoded into a JSON body: a cookie client must not see it in a
// response a script can read, and a bearer transport adds it explicitly.
//
//ds:def id=signinresult-ucfp8fef owner=@khanakia stability=stable
type SignInResult struct {
	User auth.UserView `json:"user"`
	// VerificationRequired is true when sign-up created the account but the
	// identifier must be verified before the first sign-in; no session was
	// issued.
	VerificationRequired bool `json:"verificationRequired"`
	// SecondFactorRequired is true when the session is pending: the client
	// must pass the user's second factor before it signs anyone in.
	SecondFactorRequired bool       `json:"secondFactorRequired"`
	Token                auth.Token `json:"-"`
}

// ForgotRequest is the input of forgot.
type ForgotRequest struct {
	Identifier string `json:"identifier"`
	// RedirectTo, optional, is the page the reset link opens instead of the
	// configured one: a path of this site or a URL on a trusted origin, given
	// the token as the "token" query parameter, the page then POSTs it to
	// reset. Anything else is ErrRedirectInvalid. Ignored under ResetByCode,
	// which sends no link.
	RedirectTo string `json:"redirectTo,omitempty"`
}

// RateIdentifier counts reset requests per account.
func (r ForgotRequest) RateIdentifier() string { return foldKey(r.Identifier) }

// ForgotResult is the same for every input, so the answer never reveals
// whether an account exists.
type ForgotResult struct {
	Status string `json:"status"`
}

// ForgotStatus is the one answer forgot ever gives.
//
//ds:def id=forgotstatus-cjmdfztt owner=@khanakia stability=stable
const ForgotStatus = "check_your_inbox"

// ResetRequest is the input of reset: the token from the reset link and the new
// password.
type ResetRequest struct {
	Token    auth.WireToken `json:"token"`
	Password Secret         `json:"password"`
}

// ResetCodeRequest is the input of reset-code (ResetByCode): the identifier
// the code was sent for, the code, and the new password.
type ResetCodeRequest struct {
	Identifier string `json:"identifier"`
	Code       string `json:"code"`
	Password   Secret `json:"password"`
}

// RateIdentifier counts reset-code attempts per account.
func (r ResetCodeRequest) RateIdentifier() string { return foldKey(r.Identifier) }

// VerifyRequest is the input of verify: the signed-in user's own password.
type VerifyRequest struct {
	Password Secret `json:"password"`
}

// ReauthenticateRequest is the input of reauthenticate: the signed-in user's
// own password.
type ReauthenticateRequest struct {
	Password Secret `json:"password"`
}

// ChangeRequest is the input of change. Current may be empty for an account
// that has no password yet, such as one created through a social provider.
type ChangeRequest struct {
	Current Secret `json:"current"`
	New     Secret `json:"new"`
	// RevokeOtherSessions asks to sign out the other sessions. It is read
	// only under KeepSessionsOnChange, where true signs out the other
	// sessions; without that option every change signs them out, and false
	// changes nothing.
	RevokeOtherSessions *bool `json:"revokeOtherSessions,omitempty"`
}

func foldKey(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// SignUp creates an account with a password.
func (p *Plugin) SignUp(ctx context.Context, in SignUpRequest) (SignInResult, error) {
	return p.signUp.Call(ctx, in)
}

// SignIn checks a password and starts a session.
//
//ds:def id=plugin-signin-25e2758f owner=@khanakia stability=stable
func (p *Plugin) SignIn(ctx context.Context, in SignInRequest) (SignInResult, error) {
	return p.signIn.Call(ctx, in)
}

// Forgot sends a reset link when the account exists, and answers the same
// either way.
func (p *Plugin) Forgot(ctx context.Context, identifier string) (ForgotResult, error) {
	return p.forgot.Call(ctx, ForgotRequest{Identifier: identifier})
}

// ForgotWith is Forgot with the whole request, such as a RedirectTo page the
// reset link opens.
func (p *Plugin) ForgotWith(ctx context.Context, in ForgotRequest) (ForgotResult, error) {
	return p.forgot.Call(ctx, in)
}

// Reset spends a reset token and sets a new password.
func (p *Plugin) Reset(ctx context.Context, in ResetRequest) error {
	_, err := p.reset.Call(ctx, in)
	return err
}

// ResetWithCode spends a reset code sent by Forgot under ResetByCode and sets
// a new password. An unknown identifier and a wrong, expired or spent code
// are all auth.ErrCodeInvalid.
func (p *Plugin) ResetWithCode(ctx context.Context, in ResetCodeRequest) error {
	_, err := p.resetCode.Call(ctx, in)
	return err
}

// Change sets a new password for the signed-in user.
func (p *Plugin) Change(ctx context.Context, in ChangeRequest) error {
	_, err := p.change.Call(ctx, in)
	return err
}

// Verify checks the signed-in user's password without changing anything, for
// an app step that wants the password typed again (showing a recovery key,
// deleting the account). Wrong, or no password on the account, is
// ErrInvalidCredentials; a user without a password costs the same argon2 work
// as a wrong one. It is rate limited per IP like sign-in.
func (p *Plugin) Verify(ctx context.Context, password Secret) error {
	_, err := p.verify.Call(ctx, VerifyRequest{Password: password})
	return err
}

// Reauthenticate checks the signed-in user's password and makes their current
// session fresh again for FreshSignIn operations, without a new session or
// token. When the user's second factor is due (asked as at a password
// sign-in), the session is not fresh yet: the result carries a ticket for the
// second factor's re-authentication operation. A wrong password is
// ErrInvalidCredentials and leaves the session as it was.
func (p *Plugin) Reauthenticate(ctx context.Context, password Secret) (auth.Reauthentication, error) {
	return p.reauth.Call(ctx, ReauthenticateRequest{Password: password})
}

// SetPassword sets or replaces userID's password from server code, with no
// current password and no session: an admin resetting a locked-out user, an
// import, a support flow. It has no route, because any client-reachable form
// of it is account takeover. The new password passes the same rules as
// sign-up, every open reset link is spent, and every session of the user is
// signed out, since the person holding them may not be the one the password
// is being set for. It runs in one transaction, or joins the one in ctx.
func (p *Plugin) SetPassword(ctx context.Context, userID string, password Secret) error {
	if err := p.checkNew(ctx, password); err != nil {
		return err
	}
	hash, err := p.hasher.Hash(password)
	if err != nil {
		return err
	}
	return p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		stored, err := p.load(ctx, userID)
		has := err == nil
		if err != nil && !errors.Is(err, sqlb.ErrNoRows) {
			return err
		}
		if !has {
			// A user id nobody has must fail here, not as a foreign-key error
			// from the insert.
			if _, err := p.core.User(ctx, userID); err != nil {
				return err
			}
		}
		if err := p.replace(ctx, userID, password, hash, stored, has); err != nil {
			return err
		}
		if err := p.core.ConsumeAllVerifications(ctx, PurposeResetToken, userID); err != nil {
			return err
		}
		if err := p.core.EndUserSessions(ctx, userID, "", auth.SessionEndPasswordSet); err != nil {
			return err
		}
		return p.core.CredentialChanged(ctx, userID)
	})
}

// ImportHash stores a hash from another system as userID's password, from Go
// only: the user keeps signing in with their old password, which the Hasher or
// an AcceptLegacyHashes verifier checks and the plugin re-hashes at that
// sign-in. It is how an import writes auth_password without touching the
// table by hand. The string must be in a format the configuration verifies
// (ErrHashUnrecognized otherwise), the user must exist (auth.ErrUserNotFound)
// and must have no password yet (ErrHasPassword). No session ends, nothing is
// sent, and no rule of new passwords applies: the hash is not a password. It
// runs in one transaction, or joins the one in ctx.
//
//ds:def id=plugin-importhash-k2v7mq3x owner=@khanakia stability=stable
func (p *Plugin) ImportHash(ctx context.Context, userID string, hash string) error {
	if !p.recognizes(hash) {
		return ErrHashUnrecognized
	}
	return p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		if _, err := p.core.User(ctx, userID); err != nil {
			return err
		}
		switch _, err := p.load(ctx, userID); {
		case err == nil:
			return ErrHasPassword
		case !errors.Is(err, sqlb.ErrNoRows):
			return err
		}
		return p.store(ctx, userID, hash, true)
	})
}

// recognizes reports whether checkPassword would verify a stored string: the
// Hasher's own format or one of the legacy verifiers'.
func (p *Plugin) recognizes(encoded string) bool {
	if p.hasher.Recognizes(encoded) {
		return true
	}
	for _, v := range p.legacy {
		if v.Recognizes(encoded) {
			return true
		}
	}
	return false
}

// HasPassword reports whether the user has a password, such as to show "set a
// password" instead of "change password" to a user who signed up through a
// social provider. A database failure is an error, never a false.
//
//ds:def id=plugin-haspassword-t7q6avak owner=@khanakia stability=stable
func (p *Plugin) HasPassword(ctx context.Context, userID string) (bool, error) {
	_, err := p.load(ctx, userID)
	if errors.Is(err, sqlb.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (p *Plugin) checkNew(ctx context.Context, pw Secret) error {
	n := utf8.RuneCountInString(pw.Reveal())
	switch {
	case n < p.minLen:
		return ErrTooShort
	case len(pw) > p.maxLen:
		return ErrTooLong
	}
	for _, policy := range p.policies {
		if err := policy(pw.Reveal()); err != nil {
			var ae *auth.Error
			if errors.As(err, &ae) {
				return err
			}
			return ErrWeak
		}
	}
	if p.breached != nil {
		bad, err := p.breached.Breached(ctx, pw.Reveal())
		if err != nil {
			return err
		}
		if bad {
			p.emitCompromised(ctx)
			return p.breachedError()
		}
	}
	return nil
}

// emitCompromised reports a refused breached password to the security stream.
// It is the single place every password check (sign-up, change, reset, admin
// set) passes through, so any BreachChecker feeds the stream with no wiring of
// its own and the event is emitted once per check call. It carries only the
// kind and the operation: no password, no hash prefix, which would let a sink
// narrow the password down. The account is not named because a sign-up has none
// yet and the check does not receive one.
func (p *Plugin) emitCompromised(ctx context.Context) {
	if p.core == nil {
		return // a checker run before Init (a unit test) has no stream to report to
	}
	e := auth.SecurityEvent{Kind: auth.SecurityCompromisedPassword, Severity: auth.SeverityWarn, Outcome: auth.RateOutcomeBlocked, Plugin: PluginName}
	if info, ok := auth.OperationOf(ctx); ok {
		e.Op = info.ID
	}
	p.core.EmitSecurity(e)
}

// breachedError is ErrBreached, worded by the checker when it is a
// BreachMessenger with a message. The copy keeps the code, so errors.Is
// still matches ErrBreached, and is not declared through auth.NewError, so
// the code keeps one registered message.
func (p *Plugin) breachedError() error {
	m, ok := p.breached.(BreachMessenger)
	if !ok || m.BreachedMessage() == "" {
		return ErrBreached
	}
	return &auth.Error{Code: ErrBreached.Code, Status: ErrBreached.Status, Message: m.BreachedMessage()}
}

// doSignUp creates the user, the identity and the password in one
// transaction. When the identifier already belongs to a verified account, the
// owner is told and the sign-up still succeeds as a separate, unverified
// account: that account can never verify the value, because the unique index
// refuses it, and the caller learns nothing about who has an account.
func (p *Plugin) doSignUp(ctx context.Context, c *auth.Call, in SignUpRequest) (SignInResult, error) {
	if err := p.checkNew(ctx, in.Password); err != nil {
		return SignInResult{}, err
	}
	fields, err := c.Auth.MergeFields(in.Fields, in.top)
	if err != nil {
		return SignInResult{}, err
	}
	if err := c.Auth.CheckFields(fields); err != nil {
		return SignInResult{}, err
	}
	kind, _, err := c.Auth.DetectKind(in.Identifier)
	if err != nil {
		return SignInResult{}, err
	}
	k, _ := c.Auth.Config().Identifier(kind)
	if k.Verifiable {
		owner, err := c.Auth.FindIdentity(ctx, kind, in.Identifier, true)
		switch {
		case err == nil:
			// A kind whose plugin cannot deliver has no way to tell the owner.
			// The sign-up must still answer as it does for a free value, or
			// the difference would reveal that the account exists.
			if err := c.Auth.Deliver(ctx, owner, auth.Message{Purpose: auth.PurposeSignUpAttempt}); err != nil && !errors.Is(err, auth.ErrNoDeliverer) {
				return SignInResult{}, err
			}
		case !errors.Is(err, auth.ErrIdentityNotFound):
			return SignInResult{}, err
		}
	}
	hash, err := p.hasher.Hash(in.Password)
	if err != nil {
		return SignInResult{}, err
	}
	u, err := c.Auth.CreateUser(ctx, auth.NewUser{Name: in.Name, Image: in.Image})
	if err != nil {
		return SignInResult{}, err
	}
	if _, err := c.Auth.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: kind, Raw: in.Identifier}); err != nil {
		return SignInResult{}, err
	}
	if err := c.Auth.SetFields(ctx, u.ID, fields); err != nil {
		return SignInResult{}, err
	}
	if in.Username != "" {
		un, err := auth.PluginOf[UsernameClaimer](c.Auth)
		if err != nil {
			if errors.Is(err, auth.ErrPluginNotRegistered) {
				return SignInResult{}, ErrNoUsernames
			}
			return SignInResult{}, err
		}
		if err := un.ClaimWithDisplay(ctx, u.ID, in.Username, in.DisplayUsername); err != nil {
			return SignInResult{}, err
		}
	}
	if err := p.store(ctx, u.ID, hash, true); err != nil {
		return SignInResult{}, err
	}
	if k.RequireVerified && k.Verifiable {
		return SignInResult{User: auth.ViewOf(u), VerificationRequired: true}, nil
	}
	if p.noSessionAtUp {
		return SignInResult{User: auth.ViewOf(u)}, nil
	}
	return p.startSession(ctx, c, u, auth.SessionOptions{Transient: in.Remember != nil && !*in.Remember})
}

// doVerify is enumeration-safe in time like sign-in: a user without a password
// is checked against the dummy hash. It never re-hashes, because it changes
// nothing.
func (p *Plugin) doVerify(ctx context.Context, c *auth.Call, in VerifyRequest) (auth.Done, error) {
	if err := p.checkOwn(ctx, c.User.ID, in.Password); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

// checkOwn checks userID's password, enumeration-safe in time: a user
// without a password is checked against the dummy hash. It never re-hashes,
// because it changes nothing. Wrong, too long or no password is
// ErrInvalidCredentials.
func (p *Plugin) checkOwn(ctx context.Context, userID string, password Secret) error {
	if len(password) > p.maxLen {
		return ErrInvalidCredentials
	}
	stored, err := p.load(ctx, userID)
	found := err == nil
	if err != nil {
		if !errors.Is(err, sqlb.ErrNoRows) {
			return err
		}
		stored = p.dummy
	}
	ok, _, err := p.checkPassword(password, stored)
	if err != nil {
		return err
	}
	if !ok || !found {
		return ErrInvalidCredentials
	}
	return nil
}

// doReauthenticate checks the password exactly as verify does, then lets the
// core refresh the session or ask for the second factor. A refused password
// is reported to the security stream; it ends nothing.
func (p *Plugin) doReauthenticate(ctx context.Context, c *auth.Call, in ReauthenticateRequest) (auth.Reauthentication, error) {
	if err := c.Auth.CanReauthenticate(c); err != nil {
		return auth.Reauthentication{}, err
	}
	if err := p.checkOwn(ctx, c.User.ID, in.Password); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			c.Auth.ReportReauthFailure(c)
		}
		return auth.Reauthentication{}, err
	}
	return c.Auth.Reauthenticate(ctx, c, auth.ReauthAttempt{})
}

// doSignIn is enumeration-safe in answer and in time: an unknown identifier,
// an account without a password and a wrong password all run one argon2 check
// and return ErrInvalidCredentials. Only a correct password learns that the
// identifier still needs verification.
func (p *Plugin) doSignIn(ctx context.Context, c *auth.Call, in SignInRequest) (SignInResult, error) {
	if len(in.Password) > p.maxLen {
		return SignInResult{}, ErrInvalidCredentials
	}
	if p.stuffing != nil {
		if err := p.stuffing.check(ctx, in.Password); err != nil {
			return SignInResult{}, err
		}
	}
	idn, kind, err := c.Auth.FindSignInIdentity(ctx, in.Identifier)
	if err != nil && !errors.Is(err, auth.ErrIdentityNotFound) && !errors.Is(err, auth.ErrIdentifierInvalid) {
		return SignInResult{}, err
	}
	stored := p.dummy
	found := false
	var setAt time.Time
	if err == nil {
		h, at, lerr := p.loadSet(ctx, idn.UserID)
		switch {
		case lerr == nil:
			stored, setAt, found = h, at, true
		case !errors.Is(lerr, sqlb.ErrNoRows):
			return SignInResult{}, lerr
		}
	}
	ok, rehash, err := p.checkPassword(in.Password, stored)
	if err != nil {
		return SignInResult{}, err
	}
	if !ok || !found {
		if p.stuffing != nil {
			p.stuffing.failed(ctx, in.Password)
		}
		return SignInResult{}, ErrInvalidCredentials
	}
	if kind.RequireVerified && !idn.Verified() {
		// The right password, an unverified identifier: the identifier's plugin
		// may send the verification again (email.ResendOnSignIn and the like).
		// It runs after this transaction ended (AfterTx), because the refusal
		// below rolls the transaction back and would take the plugin's token
		// row and its queued mail with it. A kind that cannot send is not an
		// error, and a failure to send must not change the answer, which
		// stays ErrNotVerified.
		c.Auth.AfterTx(ctx, func(ctx context.Context) {
			if err := c.Auth.SendVerification(ctx, idn); err != nil && !errors.Is(err, auth.ErrNoVerificationSender) {
				c.Auth.Logger().Error("password: resend verification at sign-in", "error", err)
			}
		})
		return SignInResult{}, auth.ErrNotVerified
	}
	if p.expired(setAt) {
		// The right password, past ExpireAfter: no session, and nothing is
		// re-hashed, because the client's next call replaces the password.
		return SignInResult{}, ErrExpired
	}
	if rehash {
		// A legacy hash, or an argon2id hash with yesterday's cost: this is
		// the one moment the plaintext is in hand, so it is stored again with
		// the current Hasher.
		h, err := p.hasher.Hash(in.Password)
		if err != nil {
			return SignInResult{}, err
		}
		if err := p.rehash(ctx, idn.UserID, h); err != nil {
			return SignInResult{}, err
		}
	}
	u, err := c.Auth.User(ctx, idn.UserID)
	if err != nil {
		return SignInResult{}, err
	}
	return p.startSession(ctx, c, u, auth.SessionOptions{Transient: in.Remember != nil && !*in.Remember})
}

func (p *Plugin) startSession(ctx context.Context, c *auth.Call, u auth.User, o auth.SessionOptions) (SignInResult, error) {
	sess, tok, err := c.Auth.CreateSessionWithOptions(ctx, u.ID, c.Client, o)
	if err != nil {
		return SignInResult{}, err
	}
	c.Effects.IssueSessionOf(sess, tok)
	return SignInResult{User: auth.ViewOf(u), Token: tok, SecondFactorRequired: sess.SecondFactorPending}, nil
}

// doForgot answers ForgotStatus for every input. The link goes only to a
// verified recovery identity of the account, never to the value typed, so an
// unverified row someone else added cannot receive it.
func (p *Plugin) doForgot(ctx context.Context, c *auth.Call, in ForgotRequest) (ForgotResult, error) {
	done := ForgotResult{Status: ForgotStatus}
	links, err := p.linksFor(in.RedirectTo)
	if err != nil {
		return ForgotResult{}, err
	}
	idn, _, err := c.Auth.FindSignInIdentity(ctx, in.Identifier)
	if errors.Is(err, auth.ErrIdentityNotFound) || errors.Is(err, auth.ErrIdentifierInvalid) {
		return done, nil
	}
	if err != nil {
		return ForgotResult{}, err
	}
	msg := auth.Message{Purpose: auth.PurposeReset}
	if p.byCode {
		// A code instead of a link: the identifier plugins' reset templates
		// render Message.Code when Link is empty.
		code, err := c.Auth.IssueCode(ctx, PurposeResetCode, idn.UserID, p.resetTTL)
		if err != nil {
			return ForgotResult{}, err
		}
		msg.Code = code
	} else {
		tok, err := c.Auth.IssueVerification(ctx, PurposeResetToken, idn.UserID, p.resetTTL, "")
		if err != nil {
			return ForgotResult{}, err
		}
		msg.Link = links(tok)
	}
	err = c.Auth.DeliverRecovery(ctx, idn.UserID, msg)
	if err != nil && !errors.Is(err, auth.ErrNoRecoveryChannel) {
		return ForgotResult{}, err
	}
	return done, nil
}

// redirectSchemes are the schemes a RedirectTo URL may use: a reset token
// goes only to a web page. TrustsReturnURL also accepts custom schemes and
// loopback addresses for native apps, whose returns may carry nothing
// secret, since another app can claim the scheme or the port.
var redirectSchemes = []string{"https", "http"}

// linksFor returns the link builder for one forgot request: the configured
// one when redirectTo is empty or no link is sent (ResetByCode), otherwise
// redirectTo, made absolute against the base URL, with the token added to
// its query.
func (p *Plugin) linksFor(redirectTo string) (func(auth.Token) string, error) {
	if redirectTo == "" || p.byCode {
		return p.links, nil
	}
	if !p.core.TrustsReturnURL(redirectTo) {
		return nil, ErrRedirectInvalid
	}
	target := redirectTo
	if strings.HasPrefix(target, "/") {
		base := strings.TrimSuffix(p.core.Config().BaseURL, "/")
		if base == "" {
			return nil, ErrRedirectInvalid
		}
		target = base + target
	}
	u, err := url.Parse(target)
	if err != nil || !slices.Contains(redirectSchemes, strings.ToLower(u.Scheme)) || isLoopbackHost(u.Hostname()) {
		return nil, ErrRedirectInvalid
	}
	return func(t auth.Token) string {
		q := u.Query()
		q.Set(resetTokenParam, t.Reveal())
		v := *u
		v.RawQuery = q.Encode()
		return v.String()
	}, nil
}

// isLoopbackHost reports whether host is a loopback address literal, which
// TrustsReturnURL accepts on any port under auth.WithLoopbackReturn.
func isLoopbackHost(host string) bool {
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap().IsLoopback()
}

// doResetCode is doReset with a code: the identifier names the account, the
// core checks the code against it (single use, attempt-capped), and an
// unknown identifier answers exactly as a wrong code does, so the route tells
// a stranger nothing about who has an account.
func (p *Plugin) doResetCode(ctx context.Context, c *auth.Call, in ResetCodeRequest) (auth.Done, error) {
	if err := p.checkNew(ctx, in.Password); err != nil {
		return auth.Done{}, err
	}
	idn, _, err := c.Auth.FindSignInIdentity(ctx, in.Identifier)
	if errors.Is(err, auth.ErrIdentityNotFound) || errors.Is(err, auth.ErrIdentifierInvalid) {
		return auth.Done{}, auth.ErrCodeInvalid
	}
	if err != nil {
		return auth.Done{}, err
	}
	if err := c.Auth.CheckCode(ctx, PurposeResetCode, idn.UserID, in.Code, 0); err != nil {
		return auth.Done{}, err
	}
	return p.finishReset(ctx, c, idn.UserID, in.Password)
}

// doReset sets the password, spends every other reset link and signs out every
// session: a reset is often the answer to a stolen account.
func (p *Plugin) doReset(ctx context.Context, c *auth.Call, in ResetRequest) (auth.Done, error) {
	if err := p.checkNew(ctx, in.Password); err != nil {
		return auth.Done{}, err
	}
	v, err := c.Auth.ConsumeVerification(ctx, PurposeResetToken, in.Token.Token())
	if err != nil {
		return auth.Done{}, err
	}
	return p.finishReset(ctx, c, v.Identifier, in.Password)
}

// finishReset is the tail both resets share: store the new hash, spend every
// other open reset link, sign out every session, and tell the other plugins.
func (p *Plugin) finishReset(ctx context.Context, c *auth.Call, userID string, pw Secret) (auth.Done, error) {
	hash, err := p.hasher.Hash(pw)
	if err != nil {
		return auth.Done{}, err
	}
	stored, err := p.load(ctx, userID)
	has := err == nil
	if err != nil && !errors.Is(err, sqlb.ErrNoRows) {
		return auth.Done{}, err
	}
	if err := p.replace(ctx, userID, pw, hash, stored, has); err != nil {
		return auth.Done{}, err
	}
	if err := c.Auth.ConsumeAllVerifications(ctx, PurposeResetToken, userID); err != nil {
		return auth.Done{}, err
	}
	if !p.keepOnReset {
		if err := c.Auth.EndUserSessions(ctx, userID, "", auth.SessionEndPasswordReset); err != nil {
			return auth.Done{}, err
		}
	}
	// Other plugins hear that the credential changed: the two-factor plugin
	// forgets the user's trusted devices, since a reset is the answer to a
	// stolen account and a device trusted before it must not outlive it.
	if err := c.Auth.CredentialChanged(ctx, userID); err != nil {
		return auth.Done{}, err
	}
	if !p.keepOnReset {
		c.Effects.ClearSession()
	}
	return auth.Done{OK: true}, nil
}

// doChange needs a fresh session and the current password, signs out every
// other session, and spends every open reset link: a link requested before
// the change must not undo it.
func (p *Plugin) doChange(ctx context.Context, c *auth.Call, in ChangeRequest) (auth.Done, error) {
	if err := p.checkNew(ctx, in.New); err != nil {
		return auth.Done{}, err
	}
	stored, err := p.load(ctx, c.User.ID)
	has := err == nil
	if err != nil && !errors.Is(err, sqlb.ErrNoRows) {
		return auth.Done{}, err
	}
	if has {
		ok, _, err := p.checkPassword(in.Current, stored)
		if err != nil {
			return auth.Done{}, err
		}
		if !ok {
			return auth.Done{}, ErrInvalidCredentials
		}
	}
	hash, err := p.hasher.Hash(in.New)
	if err != nil {
		return auth.Done{}, err
	}
	if err := p.replace(ctx, c.User.ID, in.New, hash, stored, has); err != nil {
		return auth.Done{}, err
	}
	if err := c.Auth.ConsumeAllVerifications(ctx, PurposeResetToken, c.User.ID); err != nil {
		return auth.Done{}, err
	}
	if p.revokeOnChange(in) {
		if err := c.Auth.EndUserSessions(ctx, c.User.ID, c.Session.ID, auth.SessionEndPasswordChanged); err != nil {
			return auth.Done{}, err
		}
	}
	if err := c.Auth.CredentialChanged(ctx, c.User.ID); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

// revokeOnChange decides whether a change signs out the other sessions:
// always by default, and under KeepSessionsOnChange only when the request
// asks for it.
func (p *Plugin) revokeOnChange(in ChangeRequest) bool {
	if !p.keepOnChange {
		return true
	}
	return in.RevokeOtherSessions != nil && *in.RevokeOtherSessions
}

// load returns userID's stored hash, or sqlb.ErrNoRows when the user has no
// password.
func (p *Plugin) load(ctx context.Context, userID string) (string, error) {
	var h string
	err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(Hash, &h)).From(TablePassword).Where(sqlb.Eq(UserID, userID)).Limit(1))
	return h, err
}

// store writes the plugin's own row; insert for a new one, update otherwise.
// Two statements rather than an upsert because the three engines spell upsert
// three ways and this is not a hot path.
func (p *Plugin) store(ctx context.Context, userID, hash string, insert bool) error {
	d := p.core.Dialect()
	now := p.core.Now()
	if insert {
		_, err := p.core.Exec(ctx, sqlb.NewInsert(d).Into(TablePassword).Row(sqlb.Set(UserID, userID), sqlb.Set(Hash, hash), sqlb.Set(UpdatedAt, now)))
		return err
	}
	_, err := p.core.Exec(ctx, sqlb.NewUpdate(d).Table(TablePassword).Set(sqlb.Set(Hash, hash), sqlb.Set(UpdatedAt, now)).Where(sqlb.Eq(UserID, userID)))
	return err
}

// rehash replaces the stored hash of the same password with the current
// Hasher's, and keeps updated_at: the password did not change, so its age,
// which ExpireAfter reads, must not either.
func (p *Plugin) rehash(ctx context.Context, userID, hash string) error {
	_, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TablePassword).Set(sqlb.Set(Hash, hash)).Where(sqlb.Eq(UserID, userID)))
	return err
}
