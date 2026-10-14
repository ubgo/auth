// Package twofactor adds TOTP second factors (authenticator apps) with
// single-use recovery codes.
//
// It uses only core mechanisms any plugin has: a column on auth_user
// (two_factor_enabled, so "is it on" costs no join), tables of its own, the
// SecondFactor interface that makes sign-in sessions pending, and a
// PendingSecondFactor operation that promotes the session. No sign-in plugin
// knows it exists.
package twofactor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity. It owns the plugin's rows in
// the migration ledger and its tables and columns, so renaming it would make
// the next migrate see a new plugin; it never changes.
const PluginName = "twofactor"

// Operation ids, the permanent names hooks, rate rules and transports address
// the plugin's operations by.
const (
	EndpointEnroll  auth.EndpointID = "twofactor.enroll"
	EndpointConfirm auth.EndpointID = "twofactor.confirm"
	EndpointDisable auth.EndpointID = "twofactor.disable"
	EndpointVerify  auth.EndpointID = "twofactor.verify"
	// EndpointRecoveryCodes replaces the user's recovery codes.
	EndpointRecoveryCodes auth.EndpointID = "twofactor.recovery-codes"
	// EndpointSend mails or texts a one-time code to a user whose factor is
	// MethodDelivered, for the sign-in step and before disable or regenerate.
	EndpointSend auth.EndpointID = "twofactor.send"
	// EndpointStatus tells a client whether the user has a confirmed factor
	// and which method it uses, so the page after a pending sign-in shows
	// the right form (code from the app, or "we sent you a code") without
	// probing send and reading ErrNotCodeMethod.
	EndpointStatus auth.EndpointID = "twofactor.status"
	// EndpointCheck checks a code for a signed-in user without touching the
	// session: a step-up before a sensitive action (better-auth's verify on
	// an already signed-in session). Same lockout and rate rule as verify.
	EndpointCheck auth.EndpointID = "twofactor.check"
	// EndpointReauthenticate is the second step of a re-authentication: a
	// current code or a recovery code plus the ticket the first step
	// (password.reauthenticate, passkey.reauthenticate-finish) answered with,
	// after which the signed-in session is fresh again. Same lockout as
	// verify.
	EndpointReauthenticate auth.EndpointID = "twofactor.reauthenticate"
	// EndpointTOTPURI re-reads the otpauth:// URI of the user's
	// authenticator-app factor (better-auth's get-totp-uri). It exists only
	// with ReadableTOTPURI.
	EndpointTOTPURI auth.EndpointID = "twofactor.totp-uri"
	// EndpointViewRecoveryCodes shows the user's unused recovery codes again
	// (better-auth's view-backup-codes). It exists only with
	// RecoveryCodeStorage(StoreEncrypted), since hashed codes cannot be shown.
	EndpointViewRecoveryCodes auth.EndpointID = "twofactor.view-recovery-codes"
)

// Operation paths under the auth mount. Unexported because a transport reads
// them from each operation's OpInfo, never by name.
const (
	pathEnroll  = "/enroll"
	pathConfirm = "/confirm"
	pathDisable = "/disable"
	pathVerify  = "/verify"
	// pathRecoveryCodes is the regenerate operation's path.
	pathRecoveryCodes = "/recovery-codes"
	pathSend          = "/send"
	pathStatus        = "/status"
	pathCheck         = "/check"
	pathReauth        = "/reauthenticate"
	pathTOTPURI       = "/totp-uri"
	// pathViewRecoveryCodes sits under the regenerate path: same codes, read
	// instead of replaced.
	pathViewRecoveryCodes = "/recovery-codes/view"
)

// Method is how a user's second factor produces codes.
//
//ds:def id=method-k3d8vq2m owner=@khanakia stability=stable
type Method string

// The two methods. MethodTOTP is the default and what Enroll without a method
// means, so existing clients see no change. MethodDelivered exists only when the
// plugin was built with DeliveredCodes().
const (
	// MethodTOTP: an authenticator app computes the codes from a shared
	// secret (RFC 6238).
	MethodTOTP Method = "totp"
	// MethodDelivered: the server mails or texts a one-time code to a verified
	// identity of the user at each sign-in. Weaker than TOTP (it trusts the
	// mailbox or the phone network), and the only second factor for users
	// who will not install an app.
	MethodDelivered Method = "delivered"
)

// MethodValues is the canonical iteration order over methods.
var MethodValues = []Method{MethodTOTP, MethodDelivered, MethodSecurityKey}

// PurposeCode is the message purpose of a delivered second-factor code, and
// the purpose of its core one-time code; the subject of the code is the user
// id. Delivering plugins word it with the message's DefaultSubject and
// DefaultText unless the app's templates handle the purpose.
//
//ds:def id=purposecode-f9j2wt6x owner=@khanakia stability=stable
const PurposeCode auth.Purpose = "twofactor.code"

// Tables and columns. auth_two_factor holds one factor per user, created
// unconfirmed by enroll and confirmed by confirm; auth_two_factor_recovery
// holds the hashes of the user's single-use recovery codes.
const (
	//ds:def id=tablenamefactor-qk9j7b3v owner=@khanakia stability=stable
	TableNameFactor  = "auth_two_factor"
	TableAliasFactor = "tf"
	//ds:def id=tablenamerecovery-74y7xq39 owner=@khanakia stability=stable
	TableNameRecovery = "auth_two_factor_recovery"
	TableAliasRecover = "tfr"

	ColUserID      = "user_id"
	ColSecret      = "secret_sealed"
	ColConfirmedAt = "confirmed_at"
	ColLastStep    = "last_step"
	ColFailures    = "failed_attempts"
	ColLockedUntil = "locked_until"
	ColCreatedAt   = "created_at"
	// ColMethod is the factor's Method; "totp" for every row made before the
	// column existed, which is what its default says.
	ColMethod = "method"
	// ColIssuer is the issuer the user enrolled with when EnrollRequest named
	// one (better-auth's per-call issuer); "" means the plugin's Issuer, and
	// is what every row made before the column existed holds.
	ColIssuer = "issuer"

	ColRecoveryID   = "id"
	ColRecoveryUser = "user_id"
	ColRecoveryHash = "code_hash"
	ColRecoveryUsed = "used_at"
	// ColRecoverySealed holds the code itself, sealed, under
	// RecoveryCodeStorage(StoreEncrypted) so view-recovery-codes can show it;
	// "" under the default hashed storage and once the code is used.
	ColRecoverySealed = "code_sealed"
	// ColRecoverySeq is a code's place in the set as it was handed out
	// (0, 1, 2, …), so view-recovery-codes shows the set in the order the
	// user printed it. The id is random and cannot order it. Every row made
	// before the column existed holds 0, and those sort by id: a stable
	// order, though not the original one.
	ColRecoverySeq = "seq"

	// ColEnabled is the column this plugin adds to auth_user.
	//ds:def id=colenabled-n2n83a62 owner=@khanakia stability=stable
	ColEnabled = "two_factor_enabled"
)

// Typed columns, for an app that reads the tables (reads are open; only the
// plugin writes them).
var (
	TableFactor   = sqlb.Table{Name: TableNameFactor, Alias: TableAliasFactor}
	TableRecovery = sqlb.Table{Name: TableNameRecovery, Alias: TableAliasRecover}

	FactorUserID      = sqlb.Col[string](TableFactor, ColUserID)
	FactorSecret      = sqlb.Col[string](TableFactor, ColSecret)
	FactorConfirmedAt = sqlb.Col[*time.Time](TableFactor, ColConfirmedAt)
	FactorLastStep    = sqlb.Col[int64](TableFactor, ColLastStep)
	FactorFailures    = sqlb.Col[int](TableFactor, ColFailures)
	FactorLockedUntil = sqlb.Col[*time.Time](TableFactor, ColLockedUntil)
	FactorCreatedAt   = sqlb.Col[time.Time](TableFactor, ColCreatedAt)
	FactorMethod      = sqlb.Col[string](TableFactor, ColMethod)
	FactorIssuer      = sqlb.Col[string](TableFactor, ColIssuer)

	RecoveryID   = sqlb.Col[string](TableRecovery, ColRecoveryID)
	RecoveryUser = sqlb.Col[string](TableRecovery, ColRecoveryUser)
	RecoveryHash = sqlb.Col[[]byte](TableRecovery, ColRecoveryHash)
	RecoveryUsed = sqlb.Col[*time.Time](TableRecovery, ColRecoveryUsed)
	// RecoverySealed is the sealed code under StoreEncrypted, "" otherwise.
	RecoverySealed = sqlb.Col[string](TableRecovery, ColRecoverySealed)
	// RecoverySeq is the code's place in its set; see ColRecoverySeq.
	RecoverySeq = sqlb.Col[int](TableRecovery, ColRecoverySeq)

	// Enabled is two_factor_enabled on auth_user, for a composite user.
	Enabled = sqlb.Col[bool](auth.TableUser, ColEnabled)
)

// TwoFactorColumns is this plugin's flat part of a composite user: embed it in
// the app's user struct and load it with Bindings, so "is two-factor on" comes
// with the user row and costs no join.
type TwoFactorColumns struct {
	TwoFactorEnabled bool
}

// Bindings binds c's fields to their auth_user columns, for auth's
// LoadUserColumns or a hand-written select of the user.
//
//ds:def id=bindings-hdjx6phm owner=@khanakia stability=stable
func Bindings(c *TwoFactorColumns) []sqlb.Binding {
	return []sqlb.Binding{sqlb.Bind(Enabled, &c.TwoFactorEnabled)}
}

// Defaults and limits.
const (
	// DefaultIssuer is the app name authenticator apps show without Issuer.
	//ds:def id=defaultissuer-enheudet owner=@khanakia stability=stable
	DefaultIssuer = "App"
	// DefaultRecoveryCodes is how many single-use codes confirm hands out:
	// enough for years of lost phones, few enough to print on one card.
	//ds:def id=defaultrecoverycodes-qp2yzv4v owner=@khanakia stability=stable
	DefaultRecoveryCodes = 10
	// MaxFailures wrong codes lock the factor for LockDuration. A six-digit
	// code accepts 3 of a million values per window, so the lock is what
	// makes guessing hopeless, from any number of IPs.
	//ds:def id=maxfailures-dyu8kjqs owner=@khanakia stability=stable
	MaxFailures = 5
	//ds:def id=lockduration-mh4x5jpc owner=@khanakia stability=stable
	LockDuration = 15 * time.Minute
	// DefaultRecoveryCodeLength is a recovery code's length in base32
	// characters: 16 characters carry 80 bits, far beyond what the lockout
	// lets anyone guess, and read as four groups of four.
	//ds:def id=defaultrecoverycodelength-trh532bc owner=@khanakia stability=stable
	DefaultRecoveryCodeLength = 16
	// MinRecoveryCodeLength is the shortest RecoveryCodeLength accepted: 8
	// base32 characters are 40 bits, which the lockout still makes hopeless
	// to guess but a shorter code would not be.
	//ds:def id=minrecoverycodelength-k2frj7m4 owner=@khanakia stability=stable
	MinRecoveryCodeLength = 8
	// recoveryBitsPerChar is base32: five bits per character.
	recoveryBitsPerChar = 5
	// recoveryGroupLen splits a code into groups of four characters, the
	// XXXX-XXXX-XXXX-XXXX form people copy without losing their place.
	recoveryGroupLen = 4
	idPrefixRecovery = "tfr"
	// codeIPLimit bounds the code-taking operations per IP a minute. The
	// account lockout is the real brake against guessing; this bounds how
	// many database rows a spray from one address can touch.
	//ds:def id=codeiplimit-398tymcc owner=@khanakia stability=stable
	codeIPLimit  = 30
	codeIPWindow = time.Minute
	// reauthAccountLimit bounds twofactor.reauthenticate per signed-in user,
	// beside the per-IP rule every code operation has: the lockout already
	// stops guessing after MaxFailures, and this keeps a stolen session from
	// spending tickets at full speed from many addresses.
	//ds:def id=twofactor-reauthaccountlimit-3kd8wq5n owner=@khanakia stability=stable
	reauthAccountLimit  = 10
	reauthAccountWindow = 15 * time.Minute
	// sendIPLimit bounds send per IP: every call costs a mail or a text, and
	// the pending-session TTL already bounds how long one sign-in can keep
	// asking. Ten in ten minutes leaves room for an office behind one address.
	//ds:def id=sendiplimit-7qx3nm8w owner=@khanakia stability=stable
	sendIPLimit  = 10
	sendIPWindow = 10 * time.Minute
	// DefaultCodeTTL is how long a delivered code works: long enough for a
	// slow mailbox, short enough that an intercepted message is stale.
	//ds:def id=defaultcodettl-2wq9hz5r owner=@khanakia stability=stable
	DefaultCodeTTL = 5 * time.Minute
	// codeTTLMinutes words the expiry in the default message text.
	minutesPerCode = time.Minute
	// MaxIssuerLength bounds a per-enrolment EnrollRequest.Issuer, in bytes:
	// long enough for any product name, short enough that a client cannot
	// store an essay in the factor row or the user's authenticator app.
	//ds:def id=maxissuerlength-r7u2kd9w owner=@khanakia stability=stable
	MaxIssuerLength = 64
)

// Errors. The *auth.Error values are what a client sees; ErrNoEncryptionKey is
// a configuration mistake auth.New refuses at start-up.
var (
	ErrCodeInvalid    = auth.NewError("twofactor.code_invalid", http.StatusBadRequest, "This code is not right.")
	ErrLocked         = auth.NewError("twofactor.locked", http.StatusTooManyRequests, "Too many wrong codes. Wait and try again.")
	ErrAlreadyEnabled = auth.NewError("twofactor.already_enabled", http.StatusConflict, "Two-factor sign-in is already on.")
	// ErrSecretInvalid refuses ImportTOTP with a secret that is not base32
	// or decodes to fewer than MinImportSecretBytes.
	ErrSecretInvalid = auth.NewError("twofactor.secret_invalid", http.StatusBadRequest, "The TOTP secret is not valid.")
	ErrNotEnrolled   = auth.NewError("twofactor.not_enrolled", http.StatusConflict, "Start two-factor setup first.")
	// ErrMethodInvalid: Enroll named a method that is not one of MethodValues,
	// or one the plugin was not built with (MethodDelivered without
	// DeliveredCodes(), MethodTOTP with WithoutTOTP()).
	ErrMethodInvalid = auth.NewError("twofactor.method_invalid", http.StatusBadRequest, "Choose an available two-factor method.")
	// ErrNoChannel: MethodDelivered needs a verified email address or phone number
	// whose plugin can deliver, and the user has none.
	ErrNoChannel = auth.NewError("twofactor.no_channel", http.StatusConflict, "Verify an email address or phone number first.")
	// ErrNotCodeMethod: send was called for a user whose factor is an
	// authenticator app; there is nothing to send.
	ErrNotCodeMethod   = auth.NewError("twofactor.not_code_method", http.StatusConflict, "Your authenticator app has the code.")
	ErrNoEncryptionKey = errors.New("twofactor: pass twofactor.WithEncryptionKey with a 32-byte key, or auth.WithSecret")
	// ErrNoMethod: WithoutTOTP() without DeliveredCodes() leaves no way to
	// enrol.
	ErrNoMethod       = errors.New("twofactor: WithoutTOTP needs DeliveredCodes, or nobody can enrol")
	ErrBadCodeTTL     = errors.New("twofactor: CodeTTL must be positive")
	ErrBadDigits      = errors.New("twofactor: Digits must be 6 or 8")
	ErrBadPeriod      = errors.New("twofactor: Period must be a positive number of whole seconds")
	ErrBadRecoveryLen = errors.New("twofactor: RecoveryCodeLength must be at least MinRecoveryCodeLength")
	ErrBadLockout     = errors.New("twofactor: Lockout needs at least one allowed failure and a positive duration")
	// ErrBadRecoveryCodes is returned by confirm or regenerate when a
	// RecoveryCodeGenerator handed back no codes, an empty one or a duplicate.
	ErrBadRecoveryCodes = errors.New("twofactor: RecoveryCodeGenerator returned no codes, an empty code or a duplicate")
	// ErrIssuerInvalid refuses an EnrollRequest.Issuer longer than
	// MaxIssuerLength, or holding a colon (it separates the issuer from the
	// account in the otpauth label, so an app would split the name wrongly)
	// or a control character.
	ErrIssuerInvalid = auth.NewError("twofactor.issuer_invalid", http.StatusBadRequest, "The issuer name is not valid.")
	// ErrSecretUnreadable answers an operation whose stored secret will not
	// open: a TOTP secret on verify, check, disable, recovery-codes or
	// totp-uri, or a sealed recovery code on view-recovery-codes. The key it
	// was sealed with was dropped from the ring, the app secret changed
	// without keeping the previous one, or a Sealer's key service is down.
	// That is the server's fault, not the code's, so it is never counted as a
	// wrong code and never locks the factor; a recovery code still passes,
	// because it is checked by its hash, which the message says. The cause is
	// logged for the operator and stays wrapped for errors.Is
	// (auth.ErrSealedCorrupt, a KMS error); the client sees only this code.
	// Every operation that meets it runs for a caller who already proved the
	// first factor, so it tells nobody whether an account exists.
	ErrSecretUnreadable = auth.NewError("twofactor.secret_unreadable", http.StatusServiceUnavailable, "Two-factor codes cannot be checked right now. A recovery code still works; otherwise contact support.")
)

// What openSealed was asked to open, for the operator's log line.
const (
	sealedTOTPSecret   = "totp secret"
	sealedRecoveryCode = "recovery code"
)

// openSealed opens a value the plugin sealed for userID with s (the TOTP
// secrets' ring or the recovery codes'). A value that will not open is
// logged at error level, naming what it was and whose, because only the
// operator can fix it (restore the previous key, or reset the user's
// factor), and is answered as ErrSecretUnreadable wrapping the cause:
// before this, the raw cause reached the transport as auth.internal, a bare
// 500 nobody could act on.
func (p *Plugin) openSealed(ctx context.Context, s auth.Sealer, what, sealed, userID string) ([]byte, error) {
	plain, err := s.Open(ctx, sealed, userID)
	if err != nil {
		p.core.Logger().Error("twofactor: a sealed value does not open", "what", what, "user", userID, "error", err)
		return nil, fmt.Errorf("%w: %w", ErrSecretUnreadable, err)
	}
	return plain, nil
}

// Plugin is the TOTP second factor. Build it with New and pass it to
// auth.WithPlugins; any sign-in method's sessions become pending for a user
// with a confirmed factor.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs auth.OptionErrors
	key     []byte
	// sealer is WithSealer's value, nil without it.
	sealer auth.Sealer
	// ring seals and opens TOTP secrets: the explicit key, WithSealer's or
	// auth.WithSealer's Sealer, or the keys derived from the app's secret
	// (auth.KeyLabelTwoFactor), current first so a secret rotation keeps old
	// enrolments opening. Built by Validate.
	ring         auth.Sealer
	issuer       string
	label        LabelFunc
	recovery     int
	recoveryLen  int
	recoveryGen  func() []string
	digits       int
	period       time.Duration
	maxFailures  int
	lockDuration time.Duration
	// totp and delivered say which methods a user may enrol; codeTTL is how
	// long a delivered code works.
	totp      bool
	delivered bool
	codeTTL   time.Duration
	// trustAge is how long a trusted device skips the factor; 0 means the
	// feature is off (TrustDevices turns it on).
	trustAge time.Duration
	// skipVerify turns a factor on at enroll (SkipVerificationOnEnable).
	skipVerify bool
	// policy decides, for a user with a confirmed factor, whether a sign-in
	// asks for it (WithPolicy); nil is DefaultPolicy.
	policy Policy
	// readableURI registers totp-uri (ReadableTOTPURI); requirePassword makes
	// the settings operations ask for the password (RequirePassword).
	readableURI     bool
	requirePassword bool
	// passwords is the password plugin, found at Init, that checks the
	// password totp-uri and RequirePassword ask for; nil without one.
	passwords PasswordChecker
	// recoveryStore is how recovery codes are kept; recoveryRing seals them
	// under StoreEncrypted (built by Validate).
	recoveryStore RecoveryStorage
	recoveryRing  auth.Sealer
	// keys stores security keys (WithSecurityKeys); nil without them.
	keys SecurityKeyStore
	// enrolRule makes a session pending auth.TaskSetupMFA (RequireEnrolment);
	// nil declares no task.
	enrolRule EnrolmentRule
	core      *auth.Auth

	enroll  *auth.Op[EnrollRequest, EnrollResult]
	confirm *auth.Op[CodeRequest, RecoveryCodes]
	disable *auth.Op[CodeRequest, auth.Done]
	verify  *auth.Op[CodeRequest, auth.Done]
	regen   *auth.Op[CodeRequest, RecoveryCodes]
	send    *auth.Op[struct{}, auth.Done]
	status  *auth.Op[struct{}, Status]
	devices *auth.Op[struct{}, DevicesResult]
	forget  *auth.Op[ForgetDeviceRequest, auth.Done]
	check   *auth.Op[CodeRequest, auth.Done]
	reauth  *auth.Op[ReauthenticateRequest, auth.Reauthentication]
	uri     *auth.Op[PasswordRequest, TOTPURIResult]
	view    *auth.Op[PasswordRequest, RecoveryCodes]

	skChallenge  *auth.Op[struct{}, SecurityKeyChallenge]
	skRegBegin   *auth.Op[SecurityKeyRegisterBeginRequest, SecurityKeyChallenge]
	skRegFinish  *auth.Op[SecurityKeyRegisterFinishRequest, SecurityKeyRegistered]
	removeFactor *auth.Op[RemoveFactorRequest, RemoveFactorResult]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin; pass options to New.
type Option func(*Plugin)

// WithEncryptionKey sets the AES-256 key that seals TOTP secrets at rest.
// Required unless the app set auth.WithSecret, in which case the key is
// derived from it under auth.KeyLabelTwoFactor and a rotation of the secret
// keeps every enrolment opening. Losing the key disables every enrolled
// factor; users then sign in with a recovery code.
func WithEncryptionKey(key []byte) Option { return func(p *Plugin) { p.key = key } }

// WithSealer seals TOTP secrets and StoreEncrypted recovery codes with s, for
// an app whose keys live in a KMS or HSM rather than in process memory.
// WithEncryptionKey still wins for TOTP secrets; without either the plugin
// uses auth.WithSealer's Sealer, then keys derived from auth.WithSecret. A
// nil s is the same as not passing the option. Values already stored stay
// readable only through a Sealer that opens them: switching from the
// derived keys to a KMS needs the old values re-enrolled or a Sealer that
// falls back to auth.RingSealer for them.
//
//ds:def id=twofactor-withsealer-7rq2mz4k owner=@khanakia stability=stable
func WithSealer(s auth.Sealer) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("twofactor.WithSealer", s) {
			return
		}
		p.sealer = s
	}
}

// buildRing settles what seals TOTP secrets, first match wins: the explicit
// key, WithSealer's Sealer, auth.WithSealer's, or the keys derived from every
// secret the app passed, current first.
func (p *Plugin) buildRing(cfg *auth.Config) error {
	if p.key == nil {
		if s := firstSealer(p.sealer, cfg.Sealer()); s != nil {
			p.ring = s
			return nil
		}
	}
	keys := [][]byte{p.key}
	if p.key == nil {
		derived, err := cfg.DeriveKeys(auth.KeyLabelTwoFactor)
		if err != nil {
			return ErrNoEncryptionKey
		}
		keys = derived
	}
	ring, err := auth.NewKeyRing(keys[0], keys[1:]...)
	if err != nil {
		return ErrNoEncryptionKey
	}
	p.ring = auth.RingSealer(ring)
	return nil
}

// firstSealer returns the first non-nil Sealer, or nil.
func firstSealer(ss ...auth.Sealer) auth.Sealer {
	for _, s := range ss {
		if s != nil {
			return s
		}
	}
	return nil
}

// Issuer names the app in authenticator apps. It is written into the app at
// enrollment, so changing it later relabels nothing already enrolled.
func Issuer(name string) Option { return func(p *Plugin) { p.issuer = name } }

// LabelFunc names a user's account on their device. It receives the core, so
// it can read what the plugin cannot know, such as the user's email address
// through a.Identities, without the app capturing its *auth.Auth in a closure
// before auth.New has returned it. An empty result falls back to the default.
//
//ds:def id=labelfunc-tkkszqw2 owner=@khanakia stability=stable
type LabelFunc func(ctx context.Context, a *auth.Auth, u auth.User) string

// AccountLabel sets the account name an authenticator app shows next to the
// issuer, such as the user's email address. The plugin does not depend on the
// email plugin, so it cannot pick one itself; without this option, or when fn
// returns "", the label is the user's name, or the user id when the name is
// empty.
func AccountLabel(fn LabelFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("twofactor.AccountLabel", fn) {
			return
		}
		p.label = fn
	}
}

// RecoveryCodeCount overrides DefaultRecoveryCodes. It applies at the next
// confirm or regenerate; codes already handed out keep working.
func RecoveryCodeCount(n int) Option { return func(p *Plugin) { p.recovery = n } }

// RecoveryCodeLength overrides DefaultRecoveryCodeLength, in base32
// characters; at least MinRecoveryCodeLength. Codes are still shown in groups
// of four. Applies at the next confirm or regenerate.
func RecoveryCodeLength(n int) Option { return func(p *Plugin) { p.recoveryLen = n } }

// RecoveryCodeGenerator replaces the random codes with the app's own, for a
// house format or words. fn returns the codes as the user will see them;
// they are compared after trimming, upper-casing and removing dashes and
// spaces, so a code is accepted however the user types it. Only their hashes
// are stored. Empty or duplicate codes fail the confirm with
// ErrBadRecoveryCodes.
func RecoveryCodeGenerator(fn func() []string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("twofactor.RecoveryCodeGenerator", fn) {
			return
		}
		p.recoveryGen = fn
	}
}

// WithDigits sets the code length, 6 (Digits) or 8 (LongDigits). It is written
// into the authenticator app at enrolment, so changing it later breaks every
// enrolled user's app.
func WithDigits(n int) Option { return func(p *Plugin) { p.digits = n } }

// WithPeriod sets the time step, in whole seconds; the default is Step. Like
// WithDigits it is written into the app at enrolment, and changing it later breaks
// enrolled apps.
func WithPeriod(d time.Duration) Option { return func(p *Plugin) { p.period = d } }

// Lockout sets how many wrong codes in a row lock the factor and for how
// long; the defaults are MaxFailures and LockDuration. A six-digit code
// accepts 3 of a million values per step, so the lock is what makes guessing
// hopeless: raise maxFailures with care.
func Lockout(maxFailures int, d time.Duration) Option {
	return func(p *Plugin) { p.maxFailures, p.lockDuration = maxFailures, d }
}

// DeliveredCodes lets users enrol MethodDelivered: a one-time code mailed or
// texted to a verified identity at each sign-in, through the identifier
// plugins' delivery (email.WithMailer, phone.WithSMS). Off by default, because
// a code in a mailbox is a weaker factor than an authenticator app; turn it
// on for users who will not install one. The sign-in step then has a send
// operation (EndpointSend) before verify.
func DeliveredCodes() Option { return func(p *Plugin) { p.delivered = true } }

// WithoutTOTP removes the authenticator-app method: Enroll with MethodTOTP is
// ErrMethodInvalid, and a plugin without DeliveredCodes is refused by
// auth.New (ErrNoMethod). Factors already enrolled with TOTP keep working.
func WithoutTOTP() Option { return func(p *Plugin) { p.totp = false } }

// CodeTTL overrides DefaultCodeTTL, how long a delivered code works. The
// length of the code is the core's (auth.WithCodeLength).
func CodeTTL(d time.Duration) Option { return func(p *Plugin) { p.codeTTL = d } }

// SkipVerificationOnEnable turns a factor on at enroll, without the first
// code confirm asks for: better-auth's skipVerificationOnEnable. Enroll then
// answers Enabled with the recovery codes (the only time they are shown), and
// signs out every other session as confirm does. A delivered-code factor
// sends no first code, like better-auth's method "otp"; the user still needs
// a verified identity (ErrNoChannel otherwise).
//
// Off by default, and riskier: nothing proves the authenticator app holds
// the secret, so a user who mis-scanned the QR code is locked out at the next
// sign-in until they use a recovery code, and a delivered-code user whose
// mailbox or phone does not receive codes is locked out the same way. Turn
// it on only where the app shows the recovery codes prominently.
func SkipVerificationOnEnable() Option { return func(p *Plugin) { p.skipVerify = true } }

// PolicyRequest is what a Policy decides on: the sign-in (the user, the
// client, the operation and sign-in method, such as "password", "oauth" or
// "sso") and whether the request carries a device the user trusted
// (TrustDevices; always false without it). A struct, so fields can be added
// without breaking a policy.
type PolicyRequest struct {
	auth.SignInAttempt
	DeviceTrusted bool
}

// Policy decides whether a sign-in of a user who has a confirmed factor asks
// for it: true creates a pending session, false a full one. It is consulted
// only for such a user, because a factor cannot be asked of someone who has
// none; making a user enrol is the app's own rule, not a sign-in policy. An
// error requires the factor: a policy that cannot decide fails closed.
type Policy func(ctx context.Context, in PolicyRequest) (bool, error)

// CredentialSignIns are the operations after which DefaultPolicy asks for
// the factor: the sign-ins that prove a password. They are this library's
// equivalents of the routes better-auth's twoFactor plugin hooks
// (v1.7.7: /sign-in/email, /sign-in/username and /sign-in/phone-number, all
// password sign-ins; here one operation takes any identifier kind), plus
// the expired-password change, which signs in with a password too and
// would otherwise skip the factor, and the password re-authentication of a
// signed-in session (auth.Reauthenticate), which asks what a password
// sign-in asks, so a stolen session plus a leaked password cannot reach the
// fresh window without the code. The ids are strings because the password
// plugin is a module of its own; an integration test fails on an id no
// operation has.
//
//ds:def id=twofactor-credentialsignins-6pw2kq9m owner=@khanakia stability=stable
var CredentialSignIns = []auth.EndpointID{"password.sign-in", "password.change-expired", "password.reauthenticate"}

// DefaultPolicy is the policy without WithPolicy, better-auth's rule: ask
// for the factor after a password sign-in (CredentialSignIns), and after a
// sign-in that names no operation (a direct CreateSession from Go, which
// cannot say how the user proved who they are), except from a trusted
// device. It also asks after a sign-in whose method reports it proved one
// factor (SignInAttempt.SingleFactor): a passkey whose authenticator did not
// verify the user proves possession only. An OAuth, SSO, magic link,
// one-time-code or user-verified passkey sign-in does not ask: with those
// methods turned on, a user with a factor can sign in without it.
// AskEverySignIn asks after every method instead. A custom policy can call
// DefaultPolicy for the cases it does not decide.
//
//ds:def id=twofactor-defaultpolicy-4hn8wq3t owner=@khanakia stability=stable
func DefaultPolicy(_ context.Context, in PolicyRequest) (bool, error) {
	if in.DeviceTrusted {
		return false, nil
	}
	return in.SingleFactor || in.Operation == "" || slices.Contains(CredentialSignIns, in.Operation), nil
}

// AskEverySignIn is the policy that asks for the factor after every sign-in,
// whatever the method (OAuth, SSO, magic link and one-time codes included),
// except from a trusted device: WithPolicy(AskEverySignIn) for an app whose
// second factor must not depend on how the user signed in. It was the
// default before DefaultPolicy followed better-auth.
//
//ds:def id=twofactor-askeverysignin-9tk3vn7w owner=@khanakia stability=stable
func AskEverySignIn(_ context.Context, in PolicyRequest) (bool, error) {
	return !in.DeviceTrusted, nil
}

// WithPolicy replaces DefaultPolicy, for an app whose rule depends on the
// sign-in: ask after every method (AskEverySignIn), always ask an admin
// even after OAuth or on a trusted device, or ask only from an unknown
// network. For example, better-auth's rule for everyone but admins, who are
// asked after every method:
//
//	twofactor.WithPolicy(func(ctx context.Context, in twofactor.PolicyRequest) (bool, error) {
//		if isAdmin(ctx, in.UserID) {
//			return twofactor.AskEverySignIn(ctx, in)
//		}
//		return twofactor.DefaultPolicy(ctx, in)
//	})
//
// A nil policy keeps DefaultPolicy.
func WithPolicy(fn Policy) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("twofactor.WithPolicy", fn) {
			return
		}
		p.policy = fn
	}
}

var (
	_ auth.SecondFactor          = (*Plugin)(nil)
	_ auth.SecondFactorForSignIn = (*Plugin)(nil)
	_ auth.OperationProvider     = (*Plugin)(nil)
	_ auth.ColumnExtender        = (*Plugin)(nil)
	_ auth.TypedMigrator         = (*Plugin)(nil)
	_ auth.TableOwner            = (*Plugin)(nil)
	_ auth.UserTableOwner        = (*Plugin)(nil)
	_ auth.Validator             = (*Plugin)(nil)
	_ auth.Initializer           = (*Plugin)(nil)
	_ auth.RateLimiter           = (*Plugin)(nil)
	_ auth.Sweeper               = (*Plugin)(nil)
	_ auth.CredentialListener    = (*Plugin)(nil)
)

// New builds the plugin. WithEncryptionKey is required; auth.New refuses the
// plugin without it.
func New(opts ...Option) *Plugin {
	p := &Plugin{
		issuer: DefaultIssuer, recovery: DefaultRecoveryCodes, recoveryLen: DefaultRecoveryCodeLength,
		digits: Digits, period: Step, maxFailures: MaxFailures, lockDuration: LockDuration,
		totp: true, codeTTL: DefaultCodeTTL, recoveryStore: StoreHashed,
	}
	for _, o := range opts {
		o(p)
	}
	p.enroll = auth.Define(auth.OpInfo{ID: EndpointEnroll, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: pathEnroll}, p.doEnroll)
	p.send = auth.Define(auth.OpInfo{ID: EndpointSend, Kind: auth.Mutation, Require: auth.SignedInOrPending, Path: pathSend}, p.doSend)
	p.status = auth.Define(auth.OpInfo{ID: EndpointStatus, Kind: auth.Query, Require: auth.SignedInOrPending, Path: pathStatus}, p.doStatus)
	p.devices = auth.Define(auth.OpInfo{ID: EndpointDevices, Kind: auth.Query, Require: auth.SignedIn, Path: pathDevices}, p.doDevices)
	p.forget = auth.Define(auth.OpInfo{ID: EndpointForgetDevice, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: pathForgetDevice}, p.doForgetDevice)
	p.confirm = auth.Define(auth.OpInfo{ID: EndpointConfirm, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: pathConfirm}, p.doConfirm)
	p.disable = auth.Define(auth.OpInfo{ID: EndpointDisable, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: pathDisable}, p.doDisable)
	p.verify = auth.Define(auth.OpInfo{ID: EndpointVerify, Kind: auth.Mutation, Require: auth.PendingSecondFactor, Path: pathVerify, SignIn: true}, p.doVerify)
	p.regen = auth.Define(auth.OpInfo{ID: EndpointRecoveryCodes, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: pathRecoveryCodes}, p.doRegenerate)
	p.check = auth.Define(auth.OpInfo{ID: EndpointCheck, Kind: auth.Mutation, Require: auth.SignedIn, Path: pathCheck}, p.doCheck)
	p.reauth = auth.Define(auth.OpInfo{ID: EndpointReauthenticate, Kind: auth.Mutation, Require: auth.SignedIn, Path: pathReauth}, p.doReauthenticate)
	// Both read a secret back, so both are mutations: the password travels in
	// a POST body, and nothing caches or logs the answer as a GET's would be.
	p.uri = auth.Define(auth.OpInfo{ID: EndpointTOTPURI, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: pathTOTPURI}, p.doTOTPURI)
	p.view = auth.Define(auth.OpInfo{ID: EndpointViewRecoveryCodes, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: pathViewRecoveryCodes}, p.doViewRecoveryCodes)
	p.defineFactorOps()
	return p
}

// Name is PluginName, the plugin's permanent identity in the migration ledger
// and in column ownership.
func (p *Plugin) Name() string { return PluginName }

// Tables declares the plugin's tables, so auth.New can refuse another plugin
// claiming the same name or alias.
func (p *Plugin) Tables() []sqlb.Table {
	return []sqlb.Table{TableFactor, TableRecovery, TableDevice, TableMethod}
}

// UserTables declares that the factor, further-factor, recovery-code and trusted-device rows
// belong to the user in their user_id column, so DeleteUser removes them (no
// foreign key does, ADR-0002).
func (p *Plugin) UserTables() []auth.UserTable {
	return []auth.UserTable{{Table: TableFactor, Column: ColUserID}, {Table: TableRecovery, Column: ColRecoveryUser}, {Table: TableDevice, Column: ColDeviceUser}, {Table: TableMethod, Column: ColUserID}}
}

// Validate requires an encryption key of auth.SealKeySize bytes, or the app's
// secret to derive one from: without either no secret could be stored, and
// every enrollment would fail at run time.
func (p *Plugin) Validate(cfg *auth.Config) error {
	if err := p.buildRing(cfg); err != nil {
		return err
	}
	if err := p.buildRecoveryRing(cfg); err != nil {
		return err
	}
	switch {
	case p.digits != Digits && p.digits != LongDigits:
		return fmt.Errorf("%w: twofactor.WithDigits(%d)", ErrBadDigits, p.digits)
	case p.period < time.Second || p.period%time.Second != 0:
		return fmt.Errorf("%w: twofactor.WithPeriod(%v)", ErrBadPeriod, p.period)
	case p.recoveryLen < MinRecoveryCodeLength:
		return ErrBadRecoveryLen
	case p.maxFailures < 1 || p.lockDuration <= 0:
		return ErrBadLockout
	case !p.totp && !p.delivered:
		return ErrNoMethod
	case p.codeTTL <= 0:
		return ErrBadCodeTTL
	case p.trustAge < 0 || p.trustAge > MaxTrustedDeviceAge:
		return ErrBadTrustAge
	}
	return nil
}

// Methods lists the methods a user may enrol with this configuration, in
// MethodValues order, for a settings page that offers the choice.
func (p *Plugin) Methods() []Method {
	out := make([]Method, 0, len(MethodValues))
	if p.totp {
		out = append(out, MethodTOTP)
	}
	if p.delivered {
		out = append(out, MethodDelivered)
	}
	if p.keys != nil {
		out = append(out, MethodSecurityKey)
	}
	return out
}

// Init captures the core, which the plugin's reads and writes go through,
// and finds the password plugin that checks the password totp-uri and
// RequirePassword ask for. Its absence is not an error: without passwords
// every user is passwordless, and the fresh session is the proof.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	if pc, err := auth.PluginOf[PasswordChecker](a); err == nil && auth.Plugin(pc) != auth.Plugin(p) {
		p.passwords = pc
	}
	return nil
}

// Operations lists enroll, confirm, disable, verify, check, recovery-codes,
// status and remove-factor; send when DeliveredCodes is on (without the
// method the route would only ever answer ErrNotCodeMethod); devices and
// forget-device when TrustDevices is; totp-uri with ReadableTOTPURI;
// view-recovery-codes with StoreEncrypted; the security-key challenge and
// registration with WithSecurityKeys.
func (p *Plugin) Operations() []auth.Operation {
	ops := []auth.Operation{p.enroll, p.confirm, p.disable, p.verify, p.check, p.reauth, p.regen, p.status, p.removeFactor}
	if p.keys != nil {
		ops = append(ops, p.skChallenge, p.skRegBegin, p.skRegFinish)
	}
	if p.readableURI {
		ops = append(ops, p.uri)
	}
	if p.recoveryStore == StoreEncrypted {
		ops = append(ops, p.view)
	}
	if p.delivered {
		ops = append(ops, p.send)
	}
	if p.trustAge > 0 {
		ops = append(ops, p.devices, p.forget)
	}
	return ops
}

// RateLimits bounds every operation that takes a code or reads a secret back
// per IP (codeIPLimit a minute), and send (sendIPLimit per sendIPWindow)
// because every send costs a message. The lockout, not these rules, is what
// stops guessing; they stop a spray from one address from reaching the
// database at full speed. A rule naming an operation that is not registered
// is refused by auth.New, so totp-uri and view-recovery-codes get theirs only
// when they exist.
func (p *Plugin) RateLimits() []auth.RateRule {
	ids := []auth.EndpointID{EndpointConfirm, EndpointDisable, EndpointVerify, EndpointCheck, EndpointReauthenticate, EndpointRecoveryCodes, EndpointRemoveFactor}
	if p.keys != nil {
		ids = append(ids, EndpointSecurityKeyChallenge, EndpointSecurityKeyRegisterFinish)
	}
	if p.readableURI {
		ids = append(ids, EndpointTOTPURI)
	}
	if p.recoveryStore == StoreEncrypted {
		ids = append(ids, EndpointViewRecoveryCodes)
	}
	rules := make([]auth.RateRule, 0, len(ids)+2)
	for _, id := range ids {
		rules = append(rules, auth.RateRule{Match: id, Key: auth.ByIP, Limit: codeIPLimit, Window: codeIPWindow})
	}
	rules = append(rules, auth.RateRule{Match: EndpointReauthenticate, Key: auth.ByFunc, Limit: reauthAccountLimit, Window: reauthAccountWindow, KeyFunc: auth.UserRateKey})
	if p.delivered {
		rules = append(rules, auth.RateRule{Match: EndpointSend, Key: auth.ByIP, Limit: sendIPLimit, Window: sendIPWindow})
	}
	return rules
}

// Columns adds two_factor_enabled to auth_user, default false, which is what
// SecondFactorRequired reads.
func (p *Plugin) Columns() []auth.ColumnExtension {
	return []auth.ColumnExtension{{Table: auth.TableNameUser, Name: ColEnabled, Type: auth.ColumnBool, Default: enabledDefault}}
}

// TypedMigrations creates the two tables for engine, and refuses an engine the core
// does not know.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	factor := p.core.TableName(TableFactor)
	return []auth.Migration{{Owner: PluginName, Name: "0001_two_factor", Statements: []string{
		"CREATE TABLE IF NOT EXISTS " + factor + " (" +
			ColUserID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColSecret + " " + t.Text + " NOT NULL, " +
			ColConfirmedAt + " " + t.Timestamp + " NULL, " +
			ColLastStep + " " + t.Int + " NOT NULL DEFAULT 0, " +
			ColFailures + " " + t.Int + " NOT NULL DEFAULT 0, " +
			ColLockedUntil + " " + t.Timestamp + " NULL, " +
			ColCreatedAt + " " + t.Timestamp + " NOT NULL)" + t.TableSuffix,
		"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableRecovery) + " (" +
			ColRecoveryID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColRecoveryUser + " " + t.ID + " NOT NULL, " +
			ColRecoveryHash + " " + t.Hash + " NOT NULL UNIQUE, " +
			ColRecoveryUsed + " " + t.Timestamp + " NULL)" + t.TableSuffix,
	}}, {Owner: PluginName, Name: "0002_two_factor_method", Statements: []string{
		// Rows made before the column existed are authenticator-app factors,
		// which is what the default says. The three engines spell ADD COLUMN
		// with a DEFAULT the same way.
		"ALTER TABLE " + factor + " ADD COLUMN " + ColMethod + " " + t.Text + " NOT NULL DEFAULT '" + string(MethodTOTP) + "'",
	}}, p.deviceMigration(engine, t), {Owner: PluginName, Name: "0004_two_factor_issuer_sealed_recovery", Statements: []string{
		// "" means the plugin's Issuer and no sealed copy: what every row
		// made before these columns existed had.
		"ALTER TABLE " + factor + " ADD COLUMN " + ColIssuer + " " + t.Text + " NOT NULL DEFAULT ''",
		"ALTER TABLE " + p.core.TableName(TableRecovery) + " ADD COLUMN " + ColRecoverySealed + " " + t.Long + " NOT NULL DEFAULT ''",
	}}, {Owner: PluginName, Name: "0005_two_factor_recovery_seq", Statements: []string{
		// 0 for every existing code: those then sort by id, which is stable.
		"ALTER TABLE " + p.core.TableName(TableRecovery) + " ADD COLUMN " + ColRecoverySeq + " " + t.Int + " NOT NULL DEFAULT 0",
	}}, p.methodMigration(t)}, nil
}

// enabledDefault is two_factor_enabled's SQL default: every existing user
// starts without a factor. FALSE is spelled the same by all three engines.
const enabledDefault = "FALSE"

// SecondFactorRequired reports whether userID has a confirmed factor and the
// request is not from a device the user trusted (TrustDevices). It reads the
// plugin's own column on auth_user, so the usual check costs one indexed
// read; only an enabled user with a device token on the request costs the
// device lookup. With WithPolicy it asks the policy, with a sign-in that
// names no method; CreateSession calls SecondFactorRequiredForSignIn instead.
func (p *Plugin) SecondFactorRequired(ctx context.Context, userID string) (bool, error) {
	return p.SecondFactorRequiredForSignIn(ctx, auth.SignInAttempt{UserID: userID})
}

// SecondFactorRequiredForSignIn is SecondFactorRequired for one sign-in,
// decided by the Policy (DefaultPolicy unless WithPolicy) for a user with a
// confirmed factor.
func (p *Plugin) SecondFactorRequiredForSignIn(ctx context.Context, in auth.SignInAttempt) (bool, error) {
	var c TwoFactorColumns
	if err := p.core.LoadUserColumns(ctx, in.UserID, Bindings(&c)...); err != nil {
		return false, err
	}
	if !c.TwoFactorEnabled {
		return false, nil
	}
	req := PolicyRequest{SignInAttempt: in}
	if p.trustAge > 0 {
		trusted, err := p.deviceTrusted(ctx, in.UserID)
		if err != nil {
			return false, err
		}
		req.DeviceTrusted = trusted
	}
	policy := p.policy
	if policy == nil {
		policy = DefaultPolicy
	}
	ask, err := policy(ctx, req)
	if err != nil {
		p.core.Logger().Warn("twofactor: policy failed; asking for the factor", "error", err)
		return true, nil
	}
	return ask, nil
}

// CodeRequest carries a TOTP code or a recovery code. Spaces around it and
// dashes inside it are ignored, and case does not matter.
type CodeRequest struct {
	Code string `json:"code"`
	// TrustDevice, on verify, asks to skip the second factor on this device
	// for the TrustDevices age. Refused (ErrTrustDisabled) when the plugin
	// was built without TrustDevices, and with DisableSession
	// (ErrTrustNeedsSession); ignored by the other operations.
	TrustDevice bool `json:"trustDevice,omitempty"`
	// DisableSession, on verify, checks the code and leaves the session
	// pending: better-auth's disableSession. The code is spent and counted
	// like any other; nobody is signed in. A signed-in user's step-up check
	// is the check operation (CheckCode) instead.
	DisableSession bool `json:"disableSession,omitempty"`
	// Password is the user's password, on disable and recovery-codes, when
	// the plugin was built with RequirePassword and the user has one;
	// ignored otherwise.
	Password auth.Token `json:"password,omitempty"`
	// Method is the factor the user picked at the challenge: the code
	// method Code is from, or MethodSecurityKey with SecurityKey set. ""
	// means the user's first code factor, which is the only one a user
	// enrolled before factors could be combined has. A method the user does
	// not have is ErrFactorNotEnrolled. A recovery code passes with "" or
	// any code method. On confirm it names the enrolment being confirmed.
	Method Method `json:"method,omitempty"`
	// SecurityKey is the assertion answering security-key-challenge, with
	// Method MethodSecurityKey.
	SecurityKey *SecurityKeyResponse `json:"securityKey,omitempty"`
}

// proof is the factor a CodeRequest presents.
func (in CodeRequest) proof() FactorProof {
	return FactorProof{Method: in.Method, Code: in.Code, SecurityKey: in.SecurityKey}
}

// Status is the output of status. Enabled is false until confirm, so a factor
// enrolled but never confirmed does not count. Method is set only when
// Enabled. Methods and TrustDevices describe the configuration, so one call
// tells a page what it may offer: the methods a user may enrol, and whether
// verify accepts CodeRequest.TrustDevice.
type Status struct {
	Enabled bool   `json:"enabled"`
	Method  Method `json:"method,omitempty"`
	// Methods are the methods a user may enrol with this configuration, in
	// MethodValues order (the Methods function).
	Methods []Method `json:"methods"`
	// TrustDevices is true when the plugin was built with TrustDevices, so
	// the verify form may offer "remember this device".
	TrustDevices bool `json:"trustDevices"`
	// Factors are the user's confirmed factors when Enabled, the primary
	// code factor first, then further code factors, then security keys: a
	// challenge page offers one of them. Empty while off.
	Factors []Factor `json:"factors"`
}

// EnrollRequest chooses the method. Empty means MethodTOTP, so a client
// written before methods existed sends no body and gets what it always got.
type EnrollRequest struct {
	Method Method `json:"method,omitempty"`
	// Issuer names the app in this user's authenticator app instead of the
	// plugin's Issuer: better-auth's per-call issuer, for one deployment
	// serving several brands. It is stored with the factor, so totp-uri
	// shows the same name later. At most MaxIssuerLength bytes, no colon, no
	// control character (ErrIssuerInvalid); "" means the plugin's Issuer.
	// Ignored for MethodDelivered, which has no authenticator app.
	Issuer string `json:"issuer,omitempty"`
	// Password is the user's password when the plugin was built with
	// RequirePassword and the user has one; ignored otherwise.
	Password auth.Token `json:"password,omitempty"`
	// Proof is a current factor, needed to add a method beside factors that
	// are on (ErrProofRequired without it). Ignored for a first factor.
	Proof *FactorProof `json:"proof,omitempty"`
}

// EnrollResult is what the app shows. For MethodTOTP: a QR code (URL) and the
// text to type (Secret). For MethodDelivered: Secret and URL are empty, and the
// first code is already on its way to the user's verified identity. Either
// way the factor stays off until Confirm proves the user receives codes.
type EnrollResult struct {
	Method Method `json:"method"`
	Secret string `json:"secret,omitempty"`
	URL    string `json:"url,omitempty"`
	// Enabled is true when SkipVerificationOnEnable turned the factor on at
	// once; RecoveryCodes are then the user's codes, shown this once, and
	// there is no confirm step.
	Enabled       bool     `json:"enabled"`
	RecoveryCodes []string `json:"recoveryCodes,omitempty"`
}

// RecoveryCodes are shown at confirm or regenerate. Only their hashes are
// stored, unless RecoveryCodeStorage(StoreEncrypted) keeps a sealed copy that
// view-recovery-codes can show again.
type RecoveryCodes struct {
	Codes []string `json:"codes"`
}

// Enroll starts setup for the signed-in user, replacing any unconfirmed
// enrollment. It fails with ErrAlreadyEnabled when a factor is on: turning it
// off needs a code, and a fresh enrollment would bypass that. With
// SkipVerificationOnEnable the factor is on when it returns.
func (p *Plugin) Enroll(ctx context.Context) (EnrollResult, error) {
	return p.enroll.Call(ctx, EnrollRequest{})
}

// EnrollWith is Enroll with a chosen method, issuer or password.
// MethodDelivered sends the first code at once; a method the plugin was not
// built with is ErrMethodInvalid.
func (p *Plugin) EnrollWith(ctx context.Context, in EnrollRequest) (EnrollResult, error) {
	return p.enroll.Call(ctx, in)
}

// Send mails or texts a one-time code to the user of the session in ctx, for
// a factor enrolled with MethodDelivered: at the sign-in step (a pending
// session) and before disable or regenerate on a signed-in one; the
// operation accepts either (auth.SignedInOrPending). A TOTP user is
// ErrNotCodeMethod. Each call replaces the open code.
func (p *Plugin) Send(ctx context.Context) error {
	_, err := p.send.Call(ctx, struct{}{})
	return err
}

// MinImportSecretBytes is the shortest TOTP secret ImportTOTP accepts: 80
// bits, the 16-character base32 secrets the oldest authenticator deployments
// issued. RFC 4226 recommends 160 bits (what Enroll makes), but an import
// that refused shorter real secrets would lock those users out of a factor
// they already use.
const MinImportSecretBytes = 10

// ImportTOTP enrols userID with a TOTP secret from another system (its base32
// form, as Supabase's auth.mfa_factors.secret or the otpauth URL's secret
// parameter), from Go only. The row is confirmed at once and two_factor_enabled
// is set, exactly as a confirmed Enroll leaves them, so the user's next
// sign-in asks for the code their existing app shows. No recovery codes are
// made (there is nobody to show them to; the user regenerates a set from
// settings). Refused: a secret that is not base32 or shorter than
// MinImportSecretBytes (ErrSecretInvalid), a user already enrolled
// (ErrAlreadyEnabled), an unknown user (auth.ErrUserNotFound), and a plugin
// built WithoutTOTP (ErrMethodInvalid). An unconfirmed enrolment in progress
// is replaced. It runs in one transaction, or joins the one in ctx.
//
//ds:def id=plugin-importtotp-h8n4rw2c owner=@khanakia stability=stable
func (p *Plugin) ImportTOTP(ctx context.Context, userID string, secret string) error {
	if !p.totp {
		return ErrMethodInvalid
	}
	raw, err := decodeSecret(secret)
	if err != nil {
		return err
	}
	return p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		if _, err := p.core.User(ctx, userID); err != nil {
			return err
		}
		row, err := p.load(ctx, userID)
		switch {
		case err == nil && row.confirmedAt != nil:
			return ErrAlreadyEnabled
		case err != nil && !errors.Is(err, ErrNotEnrolled):
			return err
		}
		sealed, err := p.ring.Seal(ctx, raw, userID)
		if err != nil {
			return err
		}
		d := p.core.Dialect()
		now := p.core.Now()
		if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableFactor).Where(sqlb.Eq(FactorUserID, userID))); err != nil {
			return err
		}
		ins := sqlb.NewInsert(d).Into(TableFactor).Row(
			sqlb.Set(FactorUserID, userID), sqlb.Set(FactorSecret, sealed), sqlb.Set(FactorLastStep, int64(0)),
			sqlb.Set(FactorFailures, 0), sqlb.Set(FactorCreatedAt, now), sqlb.Set(FactorConfirmedAt, &now), sqlb.Set(FactorMethod, string(MethodTOTP)),
		)
		if _, err := p.core.Exec(ctx, ins); err != nil {
			return err
		}
		return auth.SetUserColumn(ctx, p.core, PluginName, userID, Enabled, true)
	})
}

// decodeSecret reads a base32 TOTP secret as other systems write it: any
// case, spaces or dashes between groups, with or without padding.
func decodeSecret(s string) ([]byte, error) {
	clean := strings.NewReplacer(" ", "", "-", "", "=", "").Replace(strings.ToUpper(strings.TrimSpace(s)))
	raw, err := secretEncoding.DecodeString(clean)
	if err != nil || len(raw) < MinImportSecretBytes {
		return nil, ErrSecretInvalid
	}
	return raw, nil
}

// Status reports the second-factor state of the user in ctx: a pending
// sign-in asks it to learn which form to show, a settings page whether the
// factor is on. Nothing in it is secret: a pending session exists only after
// the first factor was proven, and a signed-in user may always see their own
// settings.
func (p *Plugin) Status(ctx context.Context) (Status, error) {
	return p.status.Call(ctx, struct{}{})
}

// Confirm checks the first code and turns the factor on. It returns the
// recovery codes, the only time they are shown, and signs out every other
// session, since those were created without the factor.
func (p *Plugin) Confirm(ctx context.Context, code string) (RecoveryCodes, error) {
	return p.confirm.Call(ctx, CodeRequest{Code: code})
}

// Disable turns the factor off; it needs a current code or a recovery code.
func (p *Plugin) Disable(ctx context.Context, code string) error {
	return p.DisableWith(ctx, CodeRequest{Code: code})
}

// DisableWith is Disable with the full request, to pass the password
// RequirePassword asks for.
func (p *Plugin) DisableWith(ctx context.Context, in CodeRequest) error {
	_, err := p.disable.Call(ctx, in)
	return err
}

// Verify passes the second factor for the pending session in ctx. VerifyWith
// with DisableSession checks the code without promoting the session; a
// signed-in step-up is CheckCode.
//
//ds:def id=plugin-verify-c25qunwp owner=@khanakia stability=stable
func (p *Plugin) Verify(ctx context.Context, code string) error {
	_, err := p.verify.Call(ctx, CodeRequest{Code: code})
	return err
}

// VerifyWith is Verify with the full request, to trust the device
// (CodeRequest.TrustDevice) after the code passes.
func (p *Plugin) VerifyWith(ctx context.Context, in CodeRequest) error {
	_, err := p.verify.Call(ctx, in)
	return err
}

// RegenerateRecoveryCodes replaces every recovery code of the signed-in user
// with a new set and returns it, the only time the new codes are shown. It
// needs a fresh session and a current app code or an unused recovery code,
// like disable: whoever asks for new codes must be able to pass the factor.
func (p *Plugin) RegenerateRecoveryCodes(ctx context.Context, code string) (RecoveryCodes, error) {
	return p.RegenerateRecoveryCodesWith(ctx, CodeRequest{Code: code})
}

// RegenerateRecoveryCodesWith is RegenerateRecoveryCodes with the full
// request, to pass the password RequirePassword asks for.
func (p *Plugin) RegenerateRecoveryCodesWith(ctx context.Context, in CodeRequest) (RecoveryCodes, error) {
	return p.regen.Call(ctx, in)
}

type factorRow struct {
	// extra marks a further factor read from auth_two_factor_method; its
	// failures and lockedUntil are the primary row's, which are shared.
	extra       bool
	createdAt   time.Time
	secret      string
	confirmedAt *time.Time
	lastStep    int64
	failures    int
	lockedUntil *time.Time
	method      string
	issuer      string
}

// load returns userID's factor, or ErrNotEnrolled when there is none.
func (p *Plugin) load(ctx context.Context, userID string) (factorRow, error) {
	var r factorRow
	sel := p.core.Select().Columns(
		sqlb.Bind(FactorSecret, &r.secret), sqlb.Bind(FactorConfirmedAt, &r.confirmedAt),
		sqlb.Bind(FactorLastStep, &r.lastStep), sqlb.Bind(FactorFailures, &r.failures), sqlb.Bind(FactorLockedUntil, &r.lockedUntil),
		sqlb.Bind(FactorMethod, &r.method), sqlb.Bind(FactorIssuer, &r.issuer),
	).From(TableFactor).Where(sqlb.Eq(FactorUserID, userID)).Limit(1)
	if err := p.core.One(ctx, sel); err != nil {
		if errors.Is(err, sqlb.ErrNoRows) {
			return r, ErrNotEnrolled
		}
		return r, err
	}
	return r, nil
}

// method resolves an EnrollRequest's method against the configuration: empty
// is TOTP, and a method that is unknown or switched off is ErrMethodInvalid.
func (p *Plugin) method(m Method) (Method, error) {
	switch {
	case m == "" && p.totp, m == MethodTOTP && p.totp:
		return MethodTOTP, nil
	case m == MethodDelivered && p.delivered:
		return MethodDelivered, nil
	}
	// MethodSecurityKey is enrolled through security-key-register-begin.
	return "", ErrMethodInvalid
}

func (p *Plugin) doEnroll(ctx context.Context, c *auth.Call, in EnrollRequest) (EnrollResult, error) {
	method, err := p.method(in.Method)
	if err != nil {
		return EnrollResult{}, err
	}
	issuer := ""
	if method == MethodTOTP {
		if issuer, err = checkIssuer(in.Issuer); err != nil {
			return EnrollResult{}, err
		}
	}
	if err := p.checkPassword(ctx, c.User.ID, in.Password, p.requirePassword); err != nil {
		return EnrollResult{}, err
	}
	row, err := p.load(ctx, c.User.ID)
	switch {
	case err != nil && !errors.Is(err, ErrNotEnrolled):
		return EnrollResult{}, err
	case err == nil && row.confirmedAt != nil:
		// A confirmed factor that DisableFor paused may be replaced: the
		// user sees two-factor as off. Its trusted devices go with it, so
		// none of them skips the factor that replaces it.
		on, err := p.enabledFor(ctx, c.User.ID)
		if err != nil {
			return EnrollResult{}, err
		}
		if on {
			return p.enrollAdditional(ctx, c, in, method, issuer, row)
		}
		// The paused factor goes with every factor beside it.
		if err := p.wipeFactors(ctx, c.User.ID, false); err != nil {
			return EnrollResult{}, err
		}
	}
	// A code factor has no secret: the row's secret column is empty and the
	// codes live in the core's auth_code table while they are open.
	var secret []byte
	sealed := ""
	if method == MethodTOTP {
		secret = make([]byte, secretBytes)
		rand.Read(secret) // never fails since Go 1.24: it crashes the program instead
		var err error
		if sealed, err = p.ring.Seal(ctx, secret, c.User.ID); err != nil {
			return EnrollResult{}, err
		}
	}
	d := c.Auth.Dialect()
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableFactor).Where(sqlb.Eq(FactorUserID, c.User.ID))); err != nil {
		return EnrollResult{}, err
	}
	ins := sqlb.NewInsert(d).Into(TableFactor).Row(
		sqlb.Set(FactorUserID, c.User.ID), sqlb.Set(FactorSecret, sealed), sqlb.Set(FactorLastStep, int64(0)),
		sqlb.Set(FactorFailures, 0), sqlb.Set(FactorCreatedAt, c.Auth.Now()), sqlb.Set(FactorMethod, string(method)),
		sqlb.Set(FactorIssuer, issuer),
	)
	if _, err := p.core.Exec(ctx, ins); err != nil {
		return EnrollResult{}, err
	}
	out := EnrollResult{Method: method}
	if method == MethodTOTP {
		out.Secret = secretEncoding.EncodeToString(secret)
		out.URL = otpauthURL(p.issuerFor(issuer), p.accountLabel(ctx, *c.User), secret, p.digits, p.period)
	}
	if p.skipVerify {
		// No first code: a delivered factor must still have somewhere to
		// send the next one, or the user could never sign in again.
		if method == MethodDelivered {
			if err := p.hasChannel(ctx, c.User.ID); err != nil {
				return EnrollResult{}, err
			}
		}
		codes, err := p.turnOn(ctx, c)
		if err != nil {
			return EnrollResult{}, err
		}
		out.Enabled, out.RecoveryCodes = true, codes
		return out, nil
	}
	if method == MethodDelivered {
		// The first code goes out now, so confirm proves the user receives
		// them; a user with nowhere to send it cannot enrol this method.
		if err := p.sendCode(ctx, c.User.ID); err != nil {
			return EnrollResult{}, err
		}
	}
	return out, nil
}

// issuerFor is the issuer an enrolment shows: its own, or the plugin's.
func (p *Plugin) issuerFor(stored string) string {
	if stored != "" {
		return stored
	}
	return p.issuer
}

// checkIssuer validates a per-enrolment issuer and returns it trimmed; ""
// stays "" (the plugin's Issuer applies).
func checkIssuer(in string) (string, error) {
	out := strings.TrimSpace(in)
	if len(out) > MaxIssuerLength || strings.ContainsRune(out, ':') || strings.ContainsFunc(out, unicode.IsControl) {
		return "", ErrIssuerInvalid
	}
	return out, nil
}

// hasChannel is ErrNoChannel unless userID has a verified identity a code
// could go to. It cannot know a deliverer exists without delivering, so it
// checks what it can: SkipVerificationOnEnable trades that proof away.
func (p *Plugin) hasChannel(ctx context.Context, userID string) error {
	ids, err := p.core.Identities(ctx, userID)
	if err != nil {
		return err
	}
	for _, idn := range ids {
		if idn.Verified() {
			return nil
		}
	}
	return ErrNoChannel
}

// sendCode issues a one-time code for userID and delivers it to the first
// verified identity, primary first, whose plugin can deliver. Delivery is
// queued until the transaction commits, like every message. No such identity
// is ErrNoChannel.
func (p *Plugin) sendCode(ctx context.Context, userID string) error {
	ids, err := p.core.Identities(ctx, userID)
	if err != nil {
		return err
	}
	// Primary identities first, so the code goes where the user expects it.
	sort.SliceStable(ids, func(i, j int) bool { return ids[i].IsPrimary && !ids[j].IsPrimary })
	code, err := p.core.IssueCode(ctx, PurposeCode, userID, p.codeTTL)
	if err != nil {
		return err
	}
	msg := auth.Message{
		Purpose: PurposeCode, Code: code,
		DefaultSubject: codeSubject,
		DefaultText:    fmt.Sprintf(codeTextFormat, code, int(p.codeTTL/minutesPerCode)),
	}
	for _, idn := range ids {
		if !idn.Verified() {
			continue
		}
		err := p.core.Deliver(ctx, idn, msg)
		if errors.Is(err, auth.ErrNoDeliverer) {
			continue
		}
		return err
	}
	return ErrNoChannel
}

// Default wording of a delivered code, used by the identifier plugins when
// the app's templates do not handle PurposeCode.
const (
	codeSubject    = "Your sign-in code"
	codeTextFormat = "Your code is %s. It expires in %d minutes."
)

// doSend sends a code to a confirmed MethodDelivered factor's user. The pending
// sign-in step and a signed-in user about to disable or regenerate both use
// it; enroll sends its own first code.
func (p *Plugin) doSend(ctx context.Context, c *auth.Call, _ struct{}) (auth.Done, error) {
	row, err := p.load(ctx, c.User.ID)
	if err != nil {
		return auth.Done{}, err
	}
	if row.confirmedAt == nil {
		return auth.Done{}, ErrNotEnrolled
	}
	// The delivered factor may be the primary or a further one.
	if _, err := p.deliveredFactor(ctx, c.User.ID, row); err != nil {
		return auth.Done{}, err
	}
	if row.lockedUntil != nil && c.Auth.Now().Before(*row.lockedUntil) {
		return auth.Done{}, ErrLocked
	}
	if err := p.sendCode(ctx, c.User.ID); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

// doStatus answers for the user of a full or pending session. ErrNotEnrolled
// and an unconfirmed enrolment both mean "off": the client needs the same form
// either way (none).
func (p *Plugin) doStatus(ctx context.Context, c *auth.Call, _ struct{}) (Status, error) {
	out := Status{Methods: p.Methods(), TrustDevices: p.trustAge > 0, Factors: []Factor{}}
	row, err := p.load(ctx, c.User.ID)
	if errors.Is(err, ErrNotEnrolled) {
		return out, nil
	}
	if err != nil {
		return Status{}, err
	}
	if row.confirmedAt == nil {
		return out, nil
	}
	// A factor DisableFor paused is off as far as the user can tell: sign-in
	// does not ask for it, and enroll replaces it.
	on, err := p.enabledFor(ctx, c.User.ID)
	if err != nil {
		return Status{}, err
	}
	if !on {
		return out, nil
	}
	out.Enabled = true
	out.Method = Method(row.method)
	if out.Factors, err = p.factorList(ctx, c.User.ID, row); err != nil {
		return Status{}, err
	}
	return out, nil
}

// deliveredFactor is userID's confirmed delivered-code factor, or
// ErrNotCodeMethod when they have none.
func (p *Plugin) deliveredFactor(ctx context.Context, userID string, primary factorRow) (factorRow, error) {
	f, ok, err := p.codeFactor(ctx, userID, primary, MethodDelivered)
	if errors.Is(err, ErrFactorNotEnrolled) || (err == nil && !ok) {
		return factorRow{}, ErrNotCodeMethod
	}
	return f, err
}

func (p *Plugin) accountLabel(ctx context.Context, u auth.User) string {
	if p.label != nil {
		if l := p.label(ctx, p.core, u); l != "" {
			return l
		}
	}
	if u.Name != "" {
		return u.Name
	}
	return u.ID
}

func (p *Plugin) doConfirm(ctx context.Context, c *auth.Call, in CodeRequest) (RecoveryCodes, error) {
	row, err := p.load(ctx, c.User.ID)
	if err != nil {
		return RecoveryCodes{}, err
	}
	if row.confirmedAt != nil {
		return p.confirmAdditional(ctx, c.User.ID, row, in)
	}
	if err := p.checkCurrent(ctx, c.User.ID, row, normalizeCode(in.Code)); err != nil {
		return RecoveryCodes{}, err
	}
	codes, err := p.turnOn(ctx, c)
	if err != nil {
		return RecoveryCodes{}, err
	}
	return RecoveryCodes{Codes: codes}, nil
}

// turnOn confirms the call user's enrolled factor, sets two_factor_enabled,
// makes the recovery codes and signs out every other session: confirm after
// its code, enroll under SkipVerificationOnEnable.
func (p *Plugin) turnOn(ctx context.Context, c *auth.Call) ([]string, error) {
	now := c.Auth.Now()
	upd := sqlb.NewUpdate(c.Auth.Dialect()).Table(TableFactor).Set(sqlb.Set(FactorConfirmedAt, &now)).
		Where(sqlb.Eq(FactorUserID, c.User.ID))
	if _, err := p.core.Exec(ctx, upd); err != nil {
		return nil, err
	}
	if err := auth.SetUserColumn(ctx, c.Auth, PluginName, c.User.ID, Enabled, true); err != nil {
		return nil, err
	}
	codes, err := p.newRecoveryCodes(ctx, c.User.ID)
	if err != nil {
		return nil, err
	}
	// Turning a factor on ends every other session: they were created without it.
	if err := c.Auth.EndUserSessions(ctx, c.User.ID, c.Session.ID, auth.SessionEndCredentialChanged); err != nil {
		return nil, err
	}
	// A session that had to enrol (RequireEnrolment) is usable from now,
	// under a new token.
	if err := p.completeEnrolment(ctx, c); err != nil {
		return nil, err
	}
	return codes, nil
}

func (p *Plugin) doDisable(ctx context.Context, c *auth.Call, in CodeRequest) (auth.Done, error) {
	if err := p.checkPassword(ctx, c.User.ID, in.Password, p.requirePassword); err != nil {
		return auth.Done{}, err
	}
	if err := p.pass(ctx, c.User.ID, in.proof()); err != nil {
		return auth.Done{}, err
	}
	// Every factor goes, with the recovery codes and the trusted devices:
	// with the factor off, there is nothing to skip.
	if err := p.turnOff(ctx, c); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

// doRegenerate checks a code, then replaces the recovery codes.
func (p *Plugin) doRegenerate(ctx context.Context, c *auth.Call, in CodeRequest) (RecoveryCodes, error) {
	if err := p.checkPassword(ctx, c.User.ID, in.Password, p.requirePassword); err != nil {
		return RecoveryCodes{}, err
	}
	if err := p.pass(ctx, c.User.ID, in.proof()); err != nil {
		return RecoveryCodes{}, err
	}
	codes, err := p.newRecoveryCodes(ctx, c.User.ID)
	if err != nil {
		return RecoveryCodes{}, err
	}
	return RecoveryCodes{Codes: codes}, nil
}

func (p *Plugin) doVerify(ctx context.Context, c *auth.Call, in CodeRequest) (auth.Done, error) {
	// Checked before the code, so a client learns about the missing feature
	// without spending a code on it.
	if in.TrustDevice && p.trustAge == 0 {
		return auth.Done{}, ErrTrustDisabled
	}
	// A device is trusted for a sign-in; with no sign-in there is nothing
	// to remember it for.
	if in.TrustDevice && in.DisableSession {
		return auth.Done{}, ErrTrustNeedsSession
	}
	if err := p.pass(ctx, c.Session.UserID, in.proof()); err != nil {
		return auth.Done{}, err
	}
	if in.DisableSession {
		return auth.Done{OK: true}, nil
	}
	if _, err := c.Auth.PromoteSession(ctx, c); err != nil {
		return auth.Done{}, err
	}
	if in.TrustDevice {
		if err := p.trustDevice(ctx, c, c.Session.UserID); err != nil {
			return auth.Done{}, err
		}
	}
	return auth.Done{OK: true}, nil
}

// pass accepts a factor of a user whose factor is confirmed: a current
// code of the code factor in.Method names (the first one when empty), an
// unused recovery code, or a security-key assertion. A factor the user does
// not have is ErrFactorNotEnrolled, before anything is tried.
func (p *Plugin) pass(ctx context.Context, userID string, in FactorProof) error {
	row, err := p.load(ctx, userID)
	if err != nil {
		return err
	}
	if row.confirmedAt == nil {
		return ErrNotEnrolled
	}
	switch {
	case in.Method == MethodSecurityKey:
		return p.passKey(ctx, userID, row, in.SecurityKey)
	case in.Method != "" && !isCodeMethod(in.Method):
		return ErrMethodInvalid
	}
	f, ok, err := p.codeFactor(ctx, userID, row, in.Method)
	if err != nil {
		return err
	}
	normalized := normalizeCode(in.Code)
	// A user whose factors are all security keys has recovery codes only.
	if !ok || len(normalized) != p.codeLength(f) {
		return p.useRecoveryCode(ctx, userID, row, normalized)
	}
	return p.checkCurrent(ctx, userID, f, normalized)
}

// codeLength is how long a current code of this factor is: the TOTP digits,
// or the core's code length for a delivered code. A typed value of any other
// length is tried as a recovery code.
func (p *Plugin) codeLength(row factorRow) int {
	if Method(row.method) == MethodDelivered {
		return p.core.Config().CodeLength
	}
	return p.digits
}

// checkCurrent checks a current code by the factor's method.
func (p *Plugin) checkCurrent(ctx context.Context, userID string, row factorRow, normalized string) error {
	if Method(row.method) == MethodDelivered {
		return p.checkDelivered(ctx, userID, row, normalized)
	}
	return p.checkTOTP(ctx, userID, row, normalized)
}

// checkDelivered spends the open delivered code through the core, which
// makes it single use and counts its own attempts; the plugin's lockout
// counts the failure too, so TOTP and delivered codes lock the same way. A
// success clears the failure count and the lock, as a TOTP success does.
func (p *Plugin) checkDelivered(ctx context.Context, userID string, row factorRow, in string) error {
	now := p.core.Now()
	if row.lockedUntil != nil && now.Before(*row.lockedUntil) {
		return ErrLocked
	}
	err := p.core.CheckCode(ctx, PurposeCode, userID, in, 0)
	if errors.Is(err, auth.ErrCodeInvalid) {
		p.countFailure(ctx, userID, row.failures)
		return ErrCodeInvalid
	}
	if err != nil {
		return err
	}
	upd := sqlb.NewUpdate(p.core.Dialect()).Table(TableFactor).
		Set(sqlb.Set(FactorFailures, 0), sqlb.Set(FactorLockedUntil, (*time.Time)(nil))).
		Where(sqlb.Eq(FactorUserID, userID))
	_, err = p.core.Exec(ctx, upd)
	return err
}

// normalizeCode is how a typed code is compared: trimmed, upper-cased, with
// dashes and inner spaces removed, so grouping and case never matter.
func normalizeCode(in string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(in)))
}

// checkTOTP accepts a code within Skew steps of now that is newer than the
// last accepted step, so a code seen over a shoulder cannot be used again.
// Every failure is counted after the transaction ends (AfterTx), because the
// failed call rolls back and a rolled-back count is no count.
func (p *Plugin) checkTOTP(ctx context.Context, userID string, row factorRow, in string) error {
	now := p.core.Now()
	if row.lockedUntil != nil && now.Before(*row.lockedUntil) {
		return ErrLocked
	}
	secret, err := p.openSealed(ctx, p.ring, sealedTOTPSecret, row.secret, userID)
	if err != nil {
		return err
	}
	current := stepAt(now, p.period)
	matched := int64(-1)
	for s := current - Skew; s <= current+Skew; s++ {
		if subtle.ConstantTimeCompare([]byte(code(secret, s, p.digits)), []byte(in)) == 1 && s > row.lastStep {
			matched = s
		}
	}
	if matched < 0 {
		p.countFailure(ctx, userID, row.failures)
		return ErrCodeInvalid
	}
	if row.extra {
		return p.acceptExtraStep(ctx, userID, row, matched)
	}
	// The step condition makes a replay race harmless: of two requests with
	// one code, one moves last_step and the other matches nothing.
	upd := sqlb.NewUpdate(p.core.Dialect()).Table(TableFactor).
		Set(sqlb.Set(FactorLastStep, matched), sqlb.Set(FactorFailures, 0), sqlb.Set(FactorLockedUntil, (*time.Time)(nil))).
		Where(sqlb.Eq(FactorUserID, userID), sqlb.Less(FactorLastStep, matched))
	n, err := p.core.Exec(ctx, upd)
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrCodeInvalid
	}
	return nil
}

// acceptExtraStep records a further TOTP factor's accepted step, under the
// same step condition as the primary's, and clears the shared lockout.
func (p *Plugin) acceptExtraStep(ctx context.Context, userID string, row factorRow, matched int64) error {
	d := p.core.Dialect()
	upd := sqlb.NewUpdate(d).Table(TableMethod).Set(sqlb.Set(MethodLastStep, matched)).
		Where(sqlb.Eq(MethodUserID, userID), sqlb.Eq(MethodKind, row.method), sqlb.Less(MethodLastStep, matched))
	n, err := p.core.Exec(ctx, upd)
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrCodeInvalid
	}
	unlock := sqlb.NewUpdate(d).Table(TableFactor).
		Set(sqlb.Set(FactorFailures, 0), sqlb.Set(FactorLockedUntil, (*time.Time)(nil))).
		Where(sqlb.Eq(FactorUserID, userID))
	_, err = p.core.Exec(ctx, unlock)
	return err
}

func (p *Plugin) countFailure(ctx context.Context, userID string, before int) {
	// The increment is atomic in SQL; the lock decision reads the count the
	// caller loaded, so under a burst of parallel guesses the lock may land a
	// guess or two late. It still lands, and every guess is counted.
	set := []sqlb.Assignment{sqlb.SetExpr(FactorFailures, sqlb.Add(FactorFailures, sqlb.Literal[int]("1")))}
	if before+1 >= p.maxFailures {
		until := p.core.Now().Add(p.lockDuration)
		set = []sqlb.Assignment{sqlb.Set(FactorLockedUntil, &until), sqlb.Set(FactorFailures, 0)}
		// The lock itself is the event, once per lock: the refusals that follow
		// (ErrLocked) are not repeated into the stream.
		e := auth.SecurityEvent{
			Kind: auth.SecurityLockout, Severity: auth.SeverityWarn, Outcome: auth.RateOutcomeBlocked, UserID: userID,
			Attrs: map[string]string{auth.AttrFailures: strconv.Itoa(before + 1), auth.AttrWindow: p.lockDuration.String()},
		}
		if info, ok := auth.OperationOf(ctx); ok {
			e.Op = info.ID
		}
		p.core.EmitSecurity(e)
	}
	upd := sqlb.NewUpdate(p.core.Dialect()).Table(TableFactor).Set(set...).Where(sqlb.Eq(FactorUserID, userID))
	p.core.AfterTx(ctx, func(ctx context.Context) {
		// ctx here carries no transaction (AfterTx runs after it ended),
		// so Exec writes on the database handle.
		if _, err := p.core.Exec(ctx, upd); err != nil {
			p.core.Logger().Error("twofactor: count failed attempt", "error", err)
		}
	})
}

// recoveryEncoding is base32 without padding, uppercase, easy to type.
var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// newRecoveryCodes replaces every recovery code of userID and returns the new
// ones as the user sees them. Only the hashes of their normalized forms are
// stored, plus a sealed copy under StoreEncrypted.
func (p *Plugin) newRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	codes, err := p.generateRecoveryCodes()
	if err != nil {
		return nil, err
	}
	d := p.core.Dialect()
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableRecovery).Where(sqlb.Eq(RecoveryUser, userID))); err != nil {
		return nil, err
	}
	for seq, c := range codes {
		id, err := p.core.NewID(idPrefixRecovery)
		if err != nil {
			return nil, err
		}
		sealed, err := p.sealRecovery(ctx, c, userID)
		if err != nil {
			return nil, err
		}
		ins := sqlb.NewInsert(d).Into(TableRecovery).Row(
			sqlb.Set(RecoveryID, id), sqlb.Set(RecoveryUser, userID), sqlb.Set(RecoveryHash, hashRecovery(normalizeCode(c))),
			sqlb.Set(RecoverySealed, sealed), sqlb.Set(RecoverySeq, seq),
		)
		if _, err := p.core.Exec(ctx, ins); err != nil {
			return nil, err
		}
	}
	return codes, nil
}

// generateRecoveryCodes returns the codes to hand out: the app's, checked for
// emptiness and duplicates (a duplicate would otherwise fail the unique index
// as an opaque database error), or random base32 of recoveryLen characters in
// groups of four.
func (p *Plugin) generateRecoveryCodes() ([]string, error) {
	if p.recoveryGen != nil {
		codes := p.recoveryGen()
		if len(codes) == 0 {
			return nil, ErrBadRecoveryCodes
		}
		seen := make(map[string]bool, len(codes))
		for _, c := range codes {
			n := normalizeCode(c)
			if n == "" || seen[n] {
				return nil, ErrBadRecoveryCodes
			}
			seen[n] = true
		}
		return codes, nil
	}
	codes := make([]string, 0, p.recovery)
	// Enough random bytes for recoveryLen base32 characters, rounded up.
	b := make([]byte, (p.recoveryLen*recoveryBitsPerChar+7)/8)
	for range p.recovery {
		rand.Read(b) // never fails since Go 1.24: it crashes the program instead
		raw := recoveryEncoding.EncodeToString(b)[:p.recoveryLen]
		codes = append(codes, groupRecoveryCode(raw))
	}
	return codes, nil
}

// groupRecoveryCode writes raw as groups of recoveryGroupLen joined by dashes.
// pass strips the dashes again, so the grouping is only for the reader.
func groupRecoveryCode(raw string) string {
	var b strings.Builder
	for i := 0; i < len(raw); i += recoveryGroupLen {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(raw[i:min(i+recoveryGroupLen, len(raw))])
	}
	return b.String()
}

func hashRecovery(normalized string) []byte {
	h := sha256.Sum256([]byte(normalized))
	return h[:]
}

// useRecoveryCode spends one recovery code. The code has at least 40 bits
// (MinRecoveryCodeLength), so a lookup by its hash is safe, unlike a six-digit
// code; the UPDATE's used_at condition makes it single use under concurrency.
// A wrong code counts as a failure.
func (p *Plugin) useRecoveryCode(ctx context.Context, userID string, row factorRow, normalized string) error {
	now := p.core.Now()
	if row.lockedUntil != nil && now.Before(*row.lockedUntil) {
		return ErrLocked
	}
	// A used code's sealed copy goes with it: view shows unused codes only,
	// and a code that opens nothing need not be recoverable from the row.
	upd := sqlb.NewUpdate(p.core.Dialect()).Table(TableRecovery).Set(sqlb.Set(RecoveryUsed, &now), sqlb.Set(RecoverySealed, "")).
		Where(sqlb.Eq(RecoveryUser, userID), sqlb.Eq(RecoveryHash, hashRecovery(normalized)), sqlb.IsNull(RecoveryUsed))
	n, err := p.core.Exec(ctx, upd)
	if err != nil {
		return err
	}
	if n != 1 {
		p.countFailure(ctx, userID, row.failures)
		return ErrCodeInvalid
	}
	return nil
}
