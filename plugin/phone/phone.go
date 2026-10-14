// Package phone registers the phone identifier kind (E.164 numbers), verifies
// numbers with SMS codes, and can sign users in — and up — with a code alone.
//
// A number is a row of the core auth_identity table, so one uniqueness policy
// and one verified check cover it with every other kind. The codes are the
// core's one-time codes (auth.IssueCode, auth.CheckCode), shared with the
// email plugin, so the attempt counter and single use live in one place.
package phone

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity.
const PluginName = "phone"

// KindPhone is the identifier kind this plugin registers. It is stored in
// every auth_identity row this plugin owns, so it never changes.
const KindPhone auth.IdentifierKindName = "phone"

// Operation ids, exported so a hook or a rate rule can name them. They are
// wire names, stable across releases.
const (
	EndpointAdd           auth.EndpointID = "phone.add"
	EndpointVerify        auth.EndpointID = "phone.verify"
	EndpointResend        auth.EndpointID = "phone.resend"
	EndpointRemove        auth.EndpointID = "phone.remove"
	EndpointSendCode      auth.EndpointID = "phone.send-code"
	EndpointSignIn        auth.EndpointID = "phone.sign-in"
	EndpointChange        auth.EndpointID = "phone.change"
	EndpointConfirmChange auth.EndpointID = "phone.confirm-change"
	// EndpointList and EndpointMakePrimary are registered only under
	// Multiple: with one number per account there is nothing to list or
	// choose between.
	EndpointList        auth.EndpointID = "phone.list"
	EndpointMakePrimary auth.EndpointID = "phone.make-primary"
)

// TableAliasIdentity is this plugin's alias for the shared core identity
// table; a composite user query joins that table once per identifier kind,
// and each occurrence needs its own alias.
//
//ds:def id=tablealiasidentity-gkbddkfy owner=@khanakia stability=stable
const TableAliasIdentity = "phi"

// Code purposes. The subject of a verify code is the identity id; of a
// sign-in code, the normalized number, because the account may not exist; of
// a change code, the user id and the new number (changeSubject), because no
// row exists for the new number until the code is checked.
const (
	PurposeVerifyCode auth.Purpose = "phone.verify"
	PurposeSignInCode auth.Purpose = "phone.sign_in"
	PurposeChangeCode auth.Purpose = "phone.change"
)

// TableIdentity is the core identity table under this plugin's alias.
var TableIdentity = sqlb.Table{Name: auth.TableNameIdentity, Alias: TableAliasIdentity}

// Typed columns on the identity table under this plugin's alias, for
// UserJoin and Of; the same columns as the core's, qualified by "phi".
var (
	IdentityUserID     = sqlb.Col[string](TableIdentity, auth.ColIdentityUserID)
	IdentityKind       = sqlb.Col[auth.IdentifierKindName](TableIdentity, auth.ColIdentityKind)
	IdentityValue      = sqlb.Col[string](TableIdentity, auth.ColIdentityValue)
	IdentityValueRaw   = sqlb.Col[string](TableIdentity, auth.ColIdentityValueRaw)
	IdentityVerifiedAt = sqlb.Col[*time.Time](TableIdentity, auth.ColIdentityVerifiedAt)
	IdentityIsPrimary  = sqlb.Col[bool](TableIdentity, auth.ColIdentityIsPrimary)
)

// Data is the phone plugin's contribution to a user, shaped as a nested edge:
// a number lives in auth_identity, not auth_user, so it reads as
// u.Phone.Number (ADR-0001). Every field is empty when the user has no number.
//
//ds:def id=data-crzjpnsx
type Data struct {
	Number     string
	NumberRaw  string
	VerifiedAt *time.Time
	IsPrimary  bool
}

// Exists reports whether the user has a phone identity at all. The LEFT join
// yields a zero Data rather than an absent one, so absence has to be asked for.
func (d *Data) Exists() bool { return d.Number != "" }

// Verified reports whether the number has been proven by a code. Only a
// verified number signs in or receives recovery texts.
func (d *Data) Verified() bool { return d.VerifiedAt != nil }

// SMSSender delivers a text message. The app implements it over its provider,
// so the library depends on nobody's SDK.
//
//ds:def id=smssender-up76xsft
type SMSSender interface {
	Send(ctx context.Context, to, text string) error
}

// MetadataSender is an SMSSender that also wants the metadata a sending
// operation attached to the message (auth.Message.Metadata), such as an
// invite id a magic link was requested with. Optional: a sender without it
// gets the text alone, and the library calls SendWithMetadata only when the
// message carries metadata.
//
//ds:def id=metadatasender-8k4tw2pr owner=@khanakia stability=stable
type MetadataSender interface {
	SMSSender
	SendWithMetadata(ctx context.Context, to, text string, metadata map[string]string) error
}

// SMSFunc adapts a function to SMSSender, for an app whose sender is a
// closure over its provider's client.
type SMSFunc func(ctx context.Context, to, text string) error

// Send calls f, so a closure satisfies SMSSender without a named type.
func (f SMSFunc) Send(ctx context.Context, to, text string) error { return f(ctx, to, text) }

// Verifier is a provider's own verification service, such as Twilio Verify:
// it makes the code, texts it and checks it, so the library never sees the
// code. Send starts a verification for the number; Check reports a wrong,
// expired or exhausted code as ErrCodeInvalid and any other failure as its
// own error, which fails the operation rather than refusing the user.
//
// With a Verifier (WithVerifier) the plugin issues no code of its own for
// verify, sign-in and change: the provider's attempt counter and lifetime
// apply instead of WithMaxAttempts and WithCodeTTL. The rate limits on
// sending still apply, because every Send costs money. Other messages (a
// reset link, a sign-in link) still go through the SMSSender.
//
//ds:def id=verifier-4p8wm2kt owner=@khanakia stability=stable
type Verifier interface {
	Send(ctx context.Context, number string) error
	Check(ctx context.Context, number, code string) error
}

// Code defaults. The TTL is short because an SMS arrives in seconds; the
// attempt cap exists because a six-digit code is a million guesses, nothing to
// a script and everything to a counter.
const (
	//ds:def id=defaultcodettl-38ny9rrh owner=@khanakia stability=stable
	DefaultCodeTTL = 10 * time.Minute
	//ds:def id=defaultmaxattempts-9thd5u9b owner=@khanakia stability=stable
	DefaultMaxAttempts = 5
)

// E.164 bounds: the shortest plausible international number and the maximum.
const (
	//ds:def id=mindigits-s68ve98t owner=@khanakia stability=stable
	MinDigits = 7
	//ds:def id=maxdigits-9yc3z2gc owner=@khanakia stability=stable
	MaxDigits = 15
)

// Rate limits: codes cost money and annoy the owner of the number.
const (
	// sendCodeLimit texts per number per sendCodeWindow: one retry for a
	// slow carrier and one more, no more, because each costs the app money.
	//ds:def id=sendcodelimit-9ruwtqm6 owner=@khanakia stability=stable
	sendCodeLimit = 3
	//ds:def id=sendcodewindow-jsdvm8be owner=@khanakia stability=stable
	sendCodeWindow = 10 * time.Minute
	// signInLimit guesses per number per signInWindow. The per-code attempt
	// cap is the real bound; this stops a script rotating fresh codes.
	//ds:def id=signinlimit-au8682ay owner=@khanakia stability=stable
	signInLimit = 10
	//ds:def id=signinwindow-qhjx7nzq owner=@khanakia stability=stable
	signInWindow = 15 * time.Minute
	// sendCodeIPLimit texts per IP per sendCodeIPWin bounds SMS pumping from
	// one client across many numbers; an office behind one NAT still fits.
	//ds:def id=sendcodeiplimit-u8vu8fht owner=@khanakia stability=stable
	sendCodeIPLimit = 20
	//ds:def id=sendcodeipwin-xtxsnfxc owner=@khanakia stability=stable
	sendCodeIPWin = time.Hour
)

// Errors. ErrCodeInvalid and ErrHasNumber reach the user; ErrNoSMS and
// ErrCodeNoLogin are configuration errors auth.New returns, so a setup that
// could never text a code fails at start.
var (
	// ErrCodeInvalid is the core's one-time-code error, re-exported so a
	// caller of this package need not import the core to match it.
	ErrCodeInvalid = auth.ErrCodeInvalid
	ErrHasNumber   = auth.NewError("phone.has_number", http.StatusConflict, "This account already has a phone number. Remove it first.")
	ErrNoSMS       = errors.New("phone: no SMS sender; pass phone.WithSMS")
	ErrCodeNoLogin = errors.New("phone: SignInWithCode needs Login()")
)

// Plugin is the phone identifier plugin. Build it with New: the zero value
// has no kind, no templates and no operations.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs    auth.OptionErrors
	kind       auth.IdentifierKind
	sms        SMSSender
	verifier   Verifier
	codeTTL    time.Duration
	maxTries   int
	codeSignIn bool
	// multiple allows several numbers per user (Multiple).
	multiple bool
	// resendOnSignIn makes SendVerification text a fresh code.
	resendOnSignIn bool
	templates      func(m auth.Message) string
	prefixes       []string
	rangeRules     []rangeLimit
	localized      map[string]func(m auth.Message) string
	// genCode (GenerateCode) makes every texted code; nil draws digits.
	genCode CodeGenerator
	core    *auth.Auth

	add           *auth.Op[NumberRequest, auth.Done]
	verify        *auth.Op[CodeRequest, auth.Done]
	resend        *auth.Op[NumberRequest, auth.Done]
	remove        *auth.Op[NumberRequest, auth.Done]
	sendCode      *auth.Op[NumberRequest, auth.Done]
	signIn        *auth.Op[SignInRequest, SignInResult]
	change        *auth.Op[NumberRequest, auth.Done]
	confirmChange *auth.Op[CodeRequest, ChangeResult]
	list          *auth.Op[struct{}, ListResult]
	makePrimary   *auth.Op[NumberRequest, auth.Done]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin; options are applied in order by New.
type Option func(*Plugin)

// Login allows numbers in sign-in. auth.New then requires them unique, since
// a login box cannot pick between two users.
func Login() Option { return kindOpt(auth.Login()) }

// Recover allows numbers to receive recovery messages. Only a verified
// number receives one.
func Recover() Option { return kindOpt(auth.Recover()) }

// Contact makes numbers contact information only: several users may share
// one, and it neither signs in nor recovers.
func Contact() Option { return kindOpt(auth.Contact()) }

// ScopedByTenant makes numbers unique per tenant, for an app where one
// person has a separate account in each; see auth.WithScope.
func ScopedByTenant() Option { return kindOpt(auth.ScopedByTenant()) }

// RequireVerified refuses sign-in through an unverified number, which could
// be anybody's claim.
func RequireVerified() Option { return func(p *Plugin) { p.kind.RequireVerified = true } }

// SignInWithCode enables sign-in, and sign-up, with an SMS code alone.
//
//ds:def id=signinwithcode-ff4rs52a
func SignInWithCode() Option { return func(p *Plugin) { p.codeSignIn = true } }

// Multiple allows several numbers per user, one of them primary: the one
// texts go to and the one a composite user query shows. Add accepts a second
// number instead of ErrHasNumber, a confirmed change adds the new number as
// primary and keeps the others, verifying a number makes it primary only
// when the user has no verified primary yet, and the list and make-primary
// routes are registered. Removing the primary promotes another verified
// number, so texts keep a destination.
//
//ds:def id=phone-multiple-5rk2pw8c owner=@khanakia stability=stable
func Multiple() Option { return func(p *Plugin) { p.multiple = true } }

// ResendOnSignIn makes SendVerification text a fresh verify code, so a
// password sign-in refused because the number is unverified (RequireVerified)
// gets a code again without a separate resend. Off, nothing is sent.
func ResendOnSignIn() Option { return func(p *Plugin) { p.resendOnSignIn = true } }

// WithSMS sets how text messages are sent. Required: auth.New fails with
// ErrNoSMS without it, because no number could ever be verified.
func WithSMS(s SMSSender) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("phone.WithSMS", s) {
			return
		}
		p.sms = s
	}
}

// WithVerifier delegates making, texting and checking codes to a provider's
// verification service; see Verifier. WithSMS is still required for the
// messages that are not codes.
func WithVerifier(v Verifier) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("phone.WithVerifier", v) {
			return
		}
		p.verifier = v
	}
}

// WithCodeTTL overrides DefaultCodeTTL. The default text states the TTL
// set here.
func WithCodeTTL(d time.Duration) Option { return func(p *Plugin) { p.codeTTL = d } }

// WithMaxAttempts overrides DefaultMaxAttempts, the wrong guesses one code
// survives before it is spent.
func WithMaxAttempts(n int) Option { return func(p *Plugin) { p.maxTries = n } }

// TemplatesByLocale adds translations, picked by auth.PickLocale; a message
// in a language with none uses the templates set by Templates, or the English
// defaults. The library ships no translations.
//
// The choice is made at delivery, so the order of this option and Templates
// does not matter.
func TemplatesByLocale(byLocale map[string]func(m auth.Message) string) Option {
	return func(p *Plugin) { p.localized = byLocale }
}

// WithNormalizer replaces Normalize, for an app whose users type numbers
// without the country code; contrib/phonenumbers has one built on
// libphonenumber. The result must be E.164 ("+" and digits): it is what is
// stored, compared and texted.
func WithNormalizer(fn func(raw string) (string, error)) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("phone.WithNormalizer", fn) {
			return
		}
		p.kind.Normalize = fn
	}
}

// WithValidator replaces Validate, such as a country-aware check that a
// number can exist. AllowPrefixes still applies on top of it.
func WithValidator(fn func(normalized string) error) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("phone.WithValidator", fn) {
			return
		}
		p.kind.Validate = fn
	}
}

// AllowPrefixes accepts only numbers that start with one of prefixes, such as
// "+1" and "+44". Every other number is refused on every path — sign-up, add,
// code sign-in — as an invalid identifier. It is the first defence against
// SMS pumping, where bots request codes for expensive numbers abroad.
//
//ds:def id=allowprefixes-6vkybvny
func AllowPrefixes(prefixes ...string) Option {
	return func(p *Plugin) { p.prefixes = append(p.prefixes, prefixes...) }
}

// LimitRange counts code requests per number range: the first digits of the
// number, "+" included. LimitRange(6, 20, time.Hour) allows 20 codes an hour
// to all numbers starting "+15550", however many numbers and IPs a bot uses.
// It adds to the per-number and per-IP limits, never replaces them.
//
//ds:def id=limitrange-7938uwbz
func LimitRange(digits, limit int, window time.Duration) Option {
	return func(p *Plugin) { p.rangeRules = append(p.rangeRules, rangeLimit{digits, limit, window}) }
}

// rangeLimit is one LimitRange rule.
type rangeLimit struct {
	digits int
	limit  int
	window time.Duration
}

// Templates replaces the default English texts, for every locale
// TemplatesByLocale does not cover. It must include m.Code or m.Link.
//
//ds:def id=templates-gq5vs7yv
func Templates(fn func(m auth.Message) string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("phone.Templates", fn) {
			return
		}
		p.templates = fn
	}
}

func kindOpt(o auth.KindOption) Option { return func(p *Plugin) { p.kind = auth.ApplyKind(p.kind, o) } }

var (
	_ auth.IdentifierProvider = (*Plugin)(nil)
	_ auth.Deliverer          = (*Plugin)(nil)
	_ auth.SignInMethod       = (*Plugin)(nil)
	_ auth.OperationProvider  = (*Plugin)(nil)
	_ auth.DataHooker         = (*Plugin)(nil)
	_ auth.TableOwner         = (*Plugin)(nil)
	_ auth.RateLimiter        = (*Plugin)(nil)
	_ auth.Validator          = (*Plugin)(nil)
	_ auth.Initializer        = (*Plugin)(nil)
	_ auth.VerificationSender = (*Plugin)(nil)
)

// New builds the plugin. With no options a number is unique among verified
// rows and verifiable, but neither signs in nor recovers.
func New(opts ...Option) *Plugin {
	p := &Plugin{
		kind: auth.IdentifierKind{
			Name: KindPhone, Unique: true, UniqueOnlyVerified: true, Verifiable: true,
			Normalize: Normalize, Validate: Validate,
		},
		codeTTL: DefaultCodeTTL, maxTries: DefaultMaxAttempts,
	}
	for _, o := range opts {
		o(p)
	}
	if p.templates == nil {
		// Built after the options so the text states the configured TTL.
		p.templates = defaultTemplate(p.codeTTL)
	}
	if len(p.prefixes) > 0 {
		allowed, base := p.prefixes, p.kind.Validate
		p.kind.Validate = func(v string) error {
			if err := base(v); err != nil {
				return err
			}
			for _, pre := range allowed {
				if strings.HasPrefix(v, pre) {
					return nil
				}
			}
			return errors.New("phone: number outside the allowed prefixes")
		}
	}
	p.add = auth.Define(auth.OpInfo{ID: EndpointAdd, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/add"}, p.doAdd)
	p.verify = auth.Define(auth.OpInfo{ID: EndpointVerify, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/verify"}, p.doVerify)
	p.resend = auth.Define(auth.OpInfo{ID: EndpointResend, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/resend"}, p.doResend)
	p.remove = auth.Define(auth.OpInfo{ID: EndpointRemove, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/remove"}, p.doRemove)
	p.sendCode = auth.Define(auth.OpInfo{ID: EndpointSendCode, Kind: auth.Mutation, Require: auth.Public, Path: "/send-code"}, p.doSendCode)
	p.signIn = auth.Define(auth.OpInfo{ID: EndpointSignIn, Kind: auth.Mutation, Require: auth.Public, Path: "/sign-in", SignIn: true}, p.doSignIn)
	p.change = auth.Define(auth.OpInfo{ID: EndpointChange, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/change"}, p.doChange)
	p.confirmChange = auth.Define(auth.OpInfo{ID: EndpointConfirmChange, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/confirm-change"}, p.doConfirmChange)
	p.list = auth.Define(auth.OpInfo{ID: EndpointList, Kind: auth.Query, Require: auth.SignedIn, Path: "/list"}, p.doList)
	p.makePrimary = auth.Define(auth.OpInfo{ID: EndpointMakePrimary, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/make-primary"}, p.doMakePrimary)
	return p
}

// Name returns PluginName, the key the core registers this plugin under.
func (p *Plugin) Name() string { return PluginName }

// SignsIn reports whether code sign-in is on, which is what counts as a way
// in for the core's "someone can sign in" check.
func (p *Plugin) SignsIn() bool { return p.codeSignIn && p.kind.CanLogin }

// Tables declares the aliased identity table, so auth.New can reject another
// plugin claiming the same alias.
func (p *Plugin) Tables() []sqlb.Table { return []sqlb.Table{TableIdentity} }

// Identifiers registers the phone kind with the core, which from then on
// owns its uniqueness and verified checks.
func (p *Plugin) Identifiers() []auth.IdentifierKind { return []auth.IdentifierKind{p.kind} }

// Validate refuses a setup that could never text a code, that turns on code
// sign-in for a kind that cannot sign in, or whose LimitRange could not count.
func (p *Plugin) Validate(*auth.Config) error {
	if p.sms == nil {
		return ErrNoSMS
	}
	if p.codeSignIn && !p.kind.CanLogin {
		return ErrCodeNoLogin
	}
	if p.genCode != nil && p.verifier != nil {
		return ErrGenerateWithVerifier
	}
	// A range rule is refused here, under its option's name, before the
	// core's generic rate check would refuse it without one. Digits below
	// one would put every number in one bucket, or slice out of range.
	for _, rl := range p.rangeRules {
		if rl.digits < 1 || rl.limit < 1 || rl.window <= 0 {
			return fmt.Errorf("%w: phone.LimitRange(%d, %d, %v): the digits, the limit and the window must all be positive",
				auth.ErrBadOperation, rl.digits, rl.limit, rl.window)
		}
	}
	return nil
}

// Init captures the core handle the operations and hooks call.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	return nil
}

// Operations lists the operations; code sign-in only when enabled, so an app
// without it exposes no route that texts codes to strangers.
func (p *Plugin) Operations() []auth.Operation {
	ops := []auth.Operation{p.add, p.verify, p.resend, p.remove, p.change, p.confirmChange}
	if p.multiple {
		ops = append(ops, p.list, p.makePrimary)
	}
	if p.SignsIn() {
		ops = append(ops, p.sendCode, p.signIn)
	}
	return ops
}

// RateLimits bounds codes sent and guessed, per number, per IP, and per
// number range when LimitRange is set, because every text costs money.
func (p *Plugin) RateLimits() []auth.RateRule {
	rules := []auth.RateRule{
		{Match: EndpointResend, Key: auth.ByIdentifier, Limit: sendCodeLimit, Window: sendCodeWindow},
		{Match: EndpointAdd, Key: auth.ByIdentifier, Limit: sendCodeLimit, Window: sendCodeWindow},
		{Match: EndpointChange, Key: auth.ByIdentifier, Limit: sendCodeLimit, Window: sendCodeWindow},
		{Match: EndpointConfirmChange, Key: auth.ByIdentifier, Limit: signInLimit, Window: signInWindow},
	}
	for _, rl := range p.rangeRules {
		digits := rl.digits
		derive := func(v string) string {
			if len(v) < digits {
				return v
			}
			return v[:digits]
		}
		for _, id := range []auth.EndpointID{EndpointAdd, EndpointResend, EndpointChange} {
			rules = append(rules, auth.RateRule{Match: id, Key: auth.ByIdentifier, Limit: rl.limit, Window: rl.window, Derive: derive})
		}
		if p.SignsIn() {
			rules = append(rules, auth.RateRule{Match: EndpointSendCode, Key: auth.ByIdentifier, Limit: rl.limit, Window: rl.window, Derive: derive})
		}
	}
	if p.SignsIn() {
		rules = append(rules,
			auth.RateRule{Match: EndpointSendCode, Key: auth.ByIdentifier, Limit: sendCodeLimit, Window: sendCodeWindow},
			auth.RateRule{Match: EndpointSendCode, Key: auth.ByIP, Limit: sendCodeIPLimit, Window: sendCodeIPWin},
			auth.RateRule{Match: EndpointSignIn, Key: auth.ByIdentifier, Limit: signInLimit, Window: signInWindow},
		)
	}
	return rules
}

// Normalize reduces a number to "+" and digits. Without it "+1 (555) 0100"
// and "+15550100" would be two rows and the unique index would prevent
// nothing. A number must be typed with its country code: guessing a country
// is a product decision, made by WithNormalizer-style wrapping in the app.
func Normalize(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "+") {
		return "", errors.New("phone: must start with + and the country code")
	}
	var b strings.Builder
	b.WriteByte('+')
	for _, r := range raw[1:] {
		switch {
		case unicode.IsDigit(r) && r < unicode.MaxASCII:
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '(' || r == ')' || r == '.':
		default:
			return "", fmt.Errorf("phone: unexpected character %q", r)
		}
	}
	return b.String(), nil
}

// Validate checks the digit count of a normalized number against the E.164
// bounds; it cannot tell whether the number exists (see WithValidator).
func Validate(v string) error {
	if d := len(v) - 1; d < MinDigits || d > MaxDigits {
		return fmt.Errorf("phone: %d digits, want %d to %d", d, MinDigits, MaxDigits)
	}
	return nil
}

// DefaultTemplate is the default English text for codes that live
// DefaultCodeTTL. The plugin's own default states its configured TTL instead,
// so WithCodeTTL never leaves a text promising the wrong lifetime; an app that
// passes DefaultTemplate to Templates with another TTL should write its own.
func DefaultTemplate(m auth.Message) string { return defaultTemplate(DefaultCodeTTL)(m) }

// defaultTemplate is DefaultTemplate for codes that live ttl.
func defaultTemplate(ttl time.Duration) func(m auth.Message) string {
	expiry := expiryText(ttl)
	return func(m auth.Message) string { return englishText(m, expiry) }
}

// expiryText says how long a code lives in whole minutes, rounded down so the
// text never promises more time than the code has.
func expiryText(ttl time.Duration) string {
	switch n := int(ttl / time.Minute); n {
	case 0:
		return "It expires in under a minute."
	case 1:
		return "It expires in 1 minute."
	default:
		return fmt.Sprintf("It expires in %d minutes.", n)
	}
}

// englishText renders m; expiry is the sentence a code message ends with.
func englishText(m auth.Message, expiry string) string {
	switch m.Purpose {
	case auth.PurposeVerify, auth.PurposeSignInCode:
		return "Your code is " + m.Code + ". " + expiry
	case auth.PurposeReset:
		// A reset by code (the password plugin's ResetByCode) carries a code
		// instead of a link; its lifetime is the password plugin's, so no expiry
		// sentence is promised here.
		if m.Code != "" && m.Link == "" {
			return "Your password reset code is " + m.Code + "."
		}
		return "Reset your password: " + m.Link
	case auth.PurposeSignInLink:
		return "Sign in: " + m.Link
	case auth.PurposeWelcome:
		return "Your account is ready."
	case auth.PurposeSignUpAttempt:
		return "Someone tried to sign up with your number. If it was you, sign in instead."
	case auth.PurposeChanged:
		return "Your account details changed. Undo: " + m.Link
	default:
		// A purpose of another plugin: its own wording when it gave some
		// (auth.Message.DefaultText), else the bare link.
		if m.DefaultText != "" {
			return m.DefaultText
		}
		return m.Link
	}
}

// Deliver renders m in its locale's template and texts it. The core calls it
// after the transaction commits, so no text goes out for a rolled-back row.
//
// With a Verifier, a code message with no code is one the provider makes:
// the plugin asked for a verification (issueCode) and the provider texts its
// own code here, through the same background path every delivery takes.
func (p *Plugin) Deliver(ctx context.Context, to auth.Identity, m auth.Message) error {
	if p.verifier != nil && m.Code == "" && isCodePurpose(m.Purpose) {
		return p.verifier.Send(ctx, to.Value)
	}
	render := p.templates
	if t, ok := auth.PickLocale(p.localized, m.Locale); ok {
		render = t
	}
	if ms, ok := p.sms.(MetadataSender); ok && len(m.Metadata) > 0 {
		return ms.SendWithMetadata(ctx, to.Value, render(m), m.Metadata)
	}
	return p.sms.Send(ctx, to.Value, render(m))
}

// isCodePurpose reports whether a message of this purpose carries one of
// this plugin's own codes, which a Verifier makes instead.
func isCodePurpose(m auth.Purpose) bool {
	switch m {
	case auth.PurposeVerify, auth.PurposeSignInCode:
		return true
	}
	return false
}

// DataHooks send a code to every new unverified number, however it was
// created.
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{Identity: auth.TableHooks[auth.Identity]{
		AfterCreate: func(ctx context.Context, _ sqlb.DBTX, row *auth.Identity) error {
			if row.Kind != KindPhone || row.Verified() {
				return nil
			}
			return p.issueCode(ctx, *row, PurposeVerifyCode, auth.PurposeVerify, row.ID)
		},
	}}
}

// NumberRequest names a number as the user typed it; each operation
// normalizes it.
type NumberRequest struct {
	Phone string `json:"phone"`
}

// RateIdentifier counts per normalized number. A malformed number keys as ""
// and is refused by the operation anyway, so sharing that key costs nothing.
func (r NumberRequest) RateIdentifier() string { n, _ := Normalize(r.Phone); return n }

// CodeRequest carries a number and the six-digit code texted to it.
type CodeRequest struct {
	Phone string `json:"phone"`
	Code  string `json:"code"`
}

// RateIdentifier counts guesses per normalized number; see
// NumberRequest.RateIdentifier for the malformed case.
func (r CodeRequest) RateIdentifier() string { n, _ := Normalize(r.Phone); return n }

// SignInRequest is the input of sign-in: a number, its code, and the
// auth_user columns of the account the code creates, better-auth's additional
// fields in the phone verify body.
//
//ds:def id=phone-signinrequest-6vn3qk8w owner=@khanakia stability=stable
type SignInRequest struct {
	Phone string `json:"phone"`
	Code  string `json:"code"`
	// Fields sets the auth.WithSignUpFields columns of the account a code
	// creates, each of its declared type, else auth.ErrFieldInvalid before
	// the code is checked. The same columns may also be sent as top-level
	// keys, as better-auth does; one sent both ways is auth.ErrFieldInvalid.
	// Ignored when the number already has an owner.
	Fields auth.Fields `json:"fields,omitempty"`
	// top holds the top-level keys of a JSON body that are not fields of
	// this struct, for auth.Auth.MergeFields; never set from Go.
	top auth.Fields
}

// RateIdentifier counts guesses per normalized number, as CodeRequest does.
func (r SignInRequest) RateIdentifier() string { n, _ := Normalize(r.Phone); return n }

// UnmarshalJSON keeps the top-level keys that are not the request's own, so
// sign-up fields may sit beside phone and code; auth.Auth.MergeFields then
// refuses any that is not a declared column.
func (r *SignInRequest) UnmarshalJSON(data []byte) error {
	type plain SignInRequest
	var p plain
	top, err := auth.SplitBody(data, &p)
	if err != nil {
		return err
	}
	*r = SignInRequest(p)
	r.top = top
	return nil
}

// SignInResult is the output of sign-in. Token is for Go callers and bearer
// transports and is never encoded into JSON.
//
//ds:def id=signinresult-jkdd6tjg
type SignInResult struct {
	User auth.UserView `json:"user"`
	// Created is true when the code created the account.
	Created bool `json:"created"`
	// SecondFactorRequired is true when the session is pending a second
	// factor.
	SecondFactorRequired bool       `json:"secondFactorRequired"`
	Token                auth.Token `json:"-"`
}

// Add adds an unverified number to the signed-in user and texts it a code.
//
//ds:def id=plugin-add-5c9jbxm7
func (p *Plugin) Add(ctx context.Context, number string) error {
	_, err := p.add.Call(ctx, NumberRequest{Phone: number})
	return err
}

// Verify checks a code for the signed-in user's number, then marks it
// verified and primary. A wrong code, or no such number, is ErrCodeInvalid.
//
//ds:def id=plugin-verify-dc6sp7qk
func (p *Plugin) Verify(ctx context.Context, number, code string) error {
	_, err := p.verify.Call(ctx, CodeRequest{Phone: number, Code: code})
	return err
}

// Resend texts a new verify code to the signed-in user's unverified number.
// It answers the same when the number is already verified or not theirs.
//
//ds:def id=plugin-resend-eqvnp28n
func (p *Plugin) Resend(ctx context.Context, number string) error {
	_, err := p.resend.Call(ctx, NumberRequest{Phone: number})
	return err
}

// Remove deletes the signed-in user's number, unless it is their last way in.
//
//ds:def id=plugin-remove-cvp4jkp4
func (p *Plugin) Remove(ctx context.Context, number string) error {
	_, err := p.remove.Call(ctx, NumberRequest{Phone: number})
	return err
}

// SendCode texts a sign-in code to any valid number, so the answer never
// reveals whether it has an account.
//
//ds:def id=plugin-sendcode-n472t7sc
func (p *Plugin) SendCode(ctx context.Context, number string) error {
	_, err := p.sendCode.Call(ctx, NumberRequest{Phone: number})
	return err
}

// SignIn checks a sign-in code and starts a session, creating the account
// when the number has no verified owner.
//
//ds:def id=plugin-signin-fx9zwjak
func (p *Plugin) SignIn(ctx context.Context, number, code string) (SignInResult, error) {
	return p.signIn.Call(ctx, SignInRequest{Phone: number, Code: code})
}

// SignInWith is SignIn with the whole request, for a Go caller that sets
// Fields on the account the code creates.
//
//ds:def id=phone-signinwith-4tm9qx2v owner=@khanakia stability=stable
func (p *Plugin) SignInWith(ctx context.Context, in SignInRequest) (SignInResult, error) {
	return p.signIn.Call(ctx, in)
}

// ChangeResult is the output of confirm-change: the normalized number now
// verified and primary.
//
//ds:def id=changeresult-5t2nq8hw owner=@khanakia stability=stable
type ChangeResult struct {
	Phone string `json:"phone"`
}

// Change starts replacing the signed-in user's number by texting a code to
// the new one; nothing changes until ConfirmChange, so the account keeps its
// old number in between. It also sets a first number in one step for a user
// who has none.
//
//ds:def id=plugin-change-7k3vm9xc owner=@khanakia stability=stable
func (p *Plugin) Change(ctx context.Context, number string) error {
	_, err := p.change.Call(ctx, NumberRequest{Phone: number})
	return err
}

// ConfirmChange checks the code texted by Change: the new number becomes
// the verified primary and the old number is removed, in one transaction.
//
//ds:def id=plugin-confirmchange-9r6wt4bn owner=@khanakia stability=stable
func (p *Plugin) ConfirmChange(ctx context.Context, number, code string) (ChangeResult, error) {
	return p.confirmChange.Call(ctx, CodeRequest{Phone: number, Code: code})
}

func (p *Plugin) doAdd(ctx context.Context, c *auth.Call, in NumberRequest) (auth.Done, error) {
	// Without Multiple any number of the user's refuses the add; with it,
	// only the same number does, and that is a no-op.
	want := ""
	if p.multiple {
		want = in.Phone
	}
	switch _, err := p.userNumber(ctx, c.User.ID, want); {
	case err == nil && p.multiple:
		return auth.Done{OK: true}, nil
	case err == nil:
		return auth.Done{}, ErrHasNumber
	case !errors.Is(err, auth.ErrIdentityNotFound):
		// A failed lookup must not fall through to an insert, or a user could
		// end up with two numbers.
		return auth.Done{}, err
	}
	if _, err := c.Auth.CreateIdentity(ctx, auth.NewIdentity{UserID: c.User.ID, Kind: KindPhone, Raw: in.Phone}); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

func (p *Plugin) doVerify(ctx context.Context, c *auth.Call, in CodeRequest) (auth.Done, error) {
	idn, err := p.userNumber(ctx, c.User.ID, in.Phone)
	if isNoNumber(err) {
		return auth.Done{}, ErrCodeInvalid
	}
	if err != nil {
		return auth.Done{}, err
	}
	if err := p.checkCode(ctx, PurposeVerifyCode, idn.ID, idn.Value, in.Code); err != nil {
		return auth.Done{}, err
	}
	if _, err := c.Auth.VerifyIdentity(ctx, idn.ID); err != nil {
		return auth.Done{}, err
	}
	if p.multiple {
		return auth.Done{OK: true}, p.promoteIfNone(ctx, c.User.ID, idn.ID)
	}
	if _, err := c.Auth.SetPrimaryIdentity(ctx, c.User.ID, idn.ID); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

// promoteIfNone makes id primary when the user has no verified primary
// number, so the first verified number is the one texts go to and a second
// one never takes over without MakePrimary.
func (p *Plugin) promoteIfNone(ctx context.Context, userID, id string) error {
	ids, err := p.core.VerifiedIdentities(ctx, userID, KindPhone)
	if err != nil {
		return err
	}
	for _, idn := range ids {
		if idn.IsPrimary && idn.ID != id {
			return nil
		}
	}
	_, err = p.core.SetPrimaryIdentity(ctx, userID, id)
	return err
}

// doResend texts a new verify code to the user's unverified number. A number
// the user does not have, or one already verified, needs no code and is not an
// error; a failed lookup is, or the user would wait for a text never sent.
func (p *Plugin) doResend(ctx context.Context, c *auth.Call, in NumberRequest) (auth.Done, error) {
	idn, err := p.userNumber(ctx, c.User.ID, in.Phone)
	switch {
	case isNoNumber(err), err == nil && idn.Verified():
		return auth.Done{OK: true}, nil
	case err != nil:
		return auth.Done{}, err
	}
	if err := p.issueCode(ctx, idn, PurposeVerifyCode, auth.PurposeVerify, idn.ID); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

// isNoNumber reports an error of userNumber that means "the user has no such
// number" — absent or not a number at all — rather than a failed lookup.
func isNoNumber(err error) bool {
	return errors.Is(err, auth.ErrIdentityNotFound) || errors.Is(err, auth.ErrIdentifierInvalid)
}

func (p *Plugin) doRemove(ctx context.Context, c *auth.Call, in NumberRequest) (auth.Done, error) {
	idn, err := p.userNumber(ctx, c.User.ID, in.Phone)
	if err != nil {
		return auth.Done{}, err
	}
	if err := c.Auth.DeleteIdentity(ctx, c.User.ID, idn.ID); err != nil {
		return auth.Done{}, err
	}
	if idn.IsPrimary {
		// Texts need a destination: the oldest verified number left takes
		// over. None left (always so without Multiple), nothing to do.
		rest, err := c.Auth.VerifiedIdentities(ctx, c.User.ID, KindPhone)
		if err != nil {
			return auth.Done{}, err
		}
		if len(rest) > 0 {
			if _, err := c.Auth.SetPrimaryIdentity(ctx, c.User.ID, rest[0].ID); err != nil {
				return auth.Done{}, err
			}
		}
	}
	return auth.Done{OK: true}, nil
}

// Number is one row of the list. Verified and Primary are separate because
// an unverified number is listed but can never be primary.
type Number struct {
	Phone    string `json:"phone"`
	Verified bool   `json:"verified"`
	Primary  bool   `json:"primary"`
}

// ListResult is the output of list, in creation order; Numbers is never nil,
// so it encodes as [] rather than null.
type ListResult struct {
	Numbers []Number `json:"numbers"`
}

// List returns the signed-in user's numbers, verified or not. Registered
// only under Multiple; without it the call is auth.ErrOperationNotWired.
func (p *Plugin) List(ctx context.Context) ([]Number, error) {
	if !p.multiple {
		return nil, auth.ErrOperationNotWired
	}
	r, err := p.list.Call(ctx, struct{}{})
	return r.Numbers, err
}

// MakePrimary makes one of the signed-in user's verified numbers the primary
// one, the number texts go to. An unverified one is auth.ErrNotVerified, a
// number the user does not have auth.ErrIdentityNotFound. Registered only
// under Multiple, and it needs a fresh sign-in, as change does.
func (p *Plugin) MakePrimary(ctx context.Context, number string) error {
	if !p.multiple {
		return auth.ErrOperationNotWired
	}
	_, err := p.makePrimary.Call(ctx, NumberRequest{Phone: number})
	return err
}

func (p *Plugin) doList(ctx context.Context, c *auth.Call, _ struct{}) (ListResult, error) {
	ids, err := c.Auth.Identities(ctx, c.User.ID)
	if err != nil {
		return ListResult{}, err
	}
	out := ListResult{Numbers: []Number{}}
	for _, idn := range ids {
		if idn.Kind == KindPhone {
			out.Numbers = append(out.Numbers, Number{Phone: idn.Value, Verified: idn.Verified(), Primary: idn.IsPrimary})
		}
	}
	return out, nil
}

func (p *Plugin) doMakePrimary(ctx context.Context, c *auth.Call, in NumberRequest) (auth.Done, error) {
	idn, err := p.userNumber(ctx, c.User.ID, in.Phone)
	if err != nil {
		return auth.Done{}, err
	}
	if _, err := c.Auth.SetPrimaryIdentity(ctx, c.User.ID, idn.ID); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

// doSendCode sends to every valid number, whether or not it has an account, so
// the answer reveals nothing; only a malformed number is refused. Whoever
// holds the phone may
// sign in to its verified account, or create one. It never sends to an
// unverified row's account — the code proves control of the number, but an
// unverified row may be somebody else's claim.
func (p *Plugin) doSendCode(ctx context.Context, c *auth.Call, in NumberRequest) (auth.Done, error) {
	value, err := c.Auth.Normalize(KindPhone, in.Phone)
	if err != nil {
		return auth.Done{}, err
	}
	to := auth.Identity{Kind: KindPhone, Value: value}
	if err := p.issueCode(ctx, to, PurposeSignInCode, auth.PurposeSignInCode, value); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

// doSignIn spends a sign-in code. With a verified owner it signs that user in;
// without one it creates a user whose number is verified by this very code.
func (p *Plugin) doSignIn(ctx context.Context, c *auth.Call, in SignInRequest) (SignInResult, error) {
	value, err := c.Auth.Normalize(KindPhone, in.Phone)
	if err != nil {
		return SignInResult{}, ErrCodeInvalid
	}
	fields, err := c.Auth.MergeFields(in.Fields, in.top)
	if err != nil {
		return SignInResult{}, err
	}
	if err := c.Auth.CheckFields(fields); err != nil {
		return SignInResult{}, err
	}
	if err := p.checkCode(ctx, PurposeSignInCode, value, value, in.Code); err != nil {
		return SignInResult{}, err
	}
	r, err := c.SignInProven(ctx, KindPhone, value, true)
	if err != nil {
		return SignInResult{}, err
	}
	if r.Created {
		if err := c.Auth.SetFields(ctx, r.User.ID, fields); err != nil {
			return SignInResult{}, err
		}
	}
	return SignInResult{User: auth.ViewOf(r.User), Created: r.Created, Token: r.Token, SecondFactorRequired: r.Session.SecondFactorPending}, nil
}

// changeSubject binds a change code to the user and the new number, so a
// code texted for one number cannot confirm another. The user id is
// length-prefixed so no id and number can combine into another pair's
// subject.
func changeSubject(userID, value string) string {
	return strconv.Itoa(len(userID)) + ":" + userID + value
}

// doChange texts a code to the new number. No row exists until the code is
// checked, so a number typed by mistake changes nothing, and the current
// number keeps working meanwhile.
func (p *Plugin) doChange(ctx context.Context, c *auth.Call, in NumberRequest) (auth.Done, error) {
	value, err := c.Auth.Normalize(KindPhone, in.Phone)
	if err != nil {
		return auth.Done{}, err
	}
	to := auth.Identity{UserID: c.User.ID, Kind: KindPhone, Value: value}
	if err := p.issueCode(ctx, to, PurposeChangeCode, auth.PurposeVerify, changeSubject(c.User.ID, value)); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

// doConfirmChange spends the change code, then replaces the number: the new
// one is created verified and primary, and every old number of the user is
// removed (kept under Multiple). A new number another account has verified is ErrIdentityTaken,
// and nothing changes. Only a race reaches that answer: change texts no code
// to a number already taken (deliverUnlessTaken), so the caller holds one
// only when the number was free when it was sent.
func (p *Plugin) doConfirmChange(ctx context.Context, c *auth.Call, in CodeRequest) (ChangeResult, error) {
	value, err := c.Auth.Normalize(KindPhone, in.Phone)
	if err != nil {
		return ChangeResult{}, ErrCodeInvalid
	}
	if err := p.checkCode(ctx, PurposeChangeCode, changeSubject(c.User.ID, value), value, in.Code); err != nil {
		return ChangeResult{}, err
	}
	ids, err := c.Auth.Identities(ctx, c.User.ID)
	if err != nil {
		return ChangeResult{}, err
	}
	for _, idn := range ids {
		if idn.Kind == KindPhone && idn.Value == value {
			// The user already holds this number, verified or not: verify
			// it and make it primary rather than inserting a duplicate.
			if _, err := c.Auth.VerifyIdentity(ctx, idn.ID); err != nil {
				return ChangeResult{}, err
			}
			if _, err := c.Auth.SetPrimaryIdentity(ctx, c.User.ID, idn.ID); err != nil {
				return ChangeResult{}, err
			}
			return ChangeResult{Phone: value}, nil
		}
	}
	if _, err := c.Auth.CreateIdentity(ctx, auth.NewIdentity{UserID: c.User.ID, Kind: KindPhone, Raw: in.Phone, Verified: true, Primary: true}); err != nil {
		return ChangeResult{}, err
	}
	if p.multiple {
		return ChangeResult{Phone: value}, nil
	}
	for _, idn := range ids {
		if idn.Kind == KindPhone {
			if err := c.Auth.DeleteIdentity(ctx, c.User.ID, idn.ID); err != nil {
				return ChangeResult{}, err
			}
		}
	}
	return ChangeResult{Phone: value}, nil
}

// SendVerification texts a fresh verify code for one of this plugin's
// unverified numbers, when ResendOnSignIn is set. The core calls it through
// its dispatcher after a correct password was refused for lack of
// verification; a verified or foreign identity is ignored.
func (p *Plugin) SendVerification(ctx context.Context, to auth.Identity) error {
	if !p.resendOnSignIn || to.Kind != KindPhone || to.Verified() {
		return nil
	}
	return p.issueCode(ctx, to, PurposeVerifyCode, auth.PurposeVerify, to.ID)
}

// userNumber returns userID's number; raw "" means any.
func (p *Plugin) userNumber(ctx context.Context, userID, raw string) (auth.Identity, error) {
	want := ""
	if raw != "" {
		v, err := p.core.Normalize(KindPhone, raw)
		if err != nil {
			return auth.Identity{}, err
		}
		want = v
	}
	ids, err := p.core.Identities(ctx, userID)
	if err != nil {
		return auth.Identity{}, err
	}
	for _, idn := range ids {
		if idn.Kind == KindPhone && (want == "" || idn.Value == want) {
			return idn, nil
		}
	}
	return auth.Identity{}, auth.ErrIdentityNotFound
}

// issueCode replaces any open code for subject and texts a new one.
// purpose is the code's purpose; msg is the purpose of the text that carries
// it, which picks the template. With a Verifier the provider makes the code:
// the message goes out with none, and Deliver asks the provider to send. A
// verify or change code (msg auth.PurposeVerify) goes through
// deliverUnlessTaken; a sign-in code goes to a number that already has its
// owner.
func (p *Plugin) issueCode(ctx context.Context, to auth.Identity, purpose, msg auth.Purpose, subject string) error {
	m := auth.Message{Purpose: msg}
	if p.verifier == nil {
		code, err := p.newCode(ctx, purpose, subject, to.Value)
		if err != nil {
			return err
		}
		m.Code = code
	}
	if msg == auth.PurposeVerify {
		return p.deliverUnlessTaken(ctx, to, m)
	}
	return p.core.Deliver(ctx, to, m)
}

// deliverUnlessTaken texts m, a verify or change code for the number to,
// unless another account has already verified that number. Then its owner
// gets the duplicate sign-up notice instead, as the email plugin does: a code
// that could only ever answer auth.identity_taken is never sent, and the
// requester's answer, the writes and the one delivery are the same either
// way, so neither the answer nor its timing says the number has an account.
// The code was issued before this check on purpose, for that timing; nobody
// receives it. With a Verifier the provider is never asked to text the
// number, so no provider code reaches it either.
func (p *Plugin) deliverUnlessTaken(ctx context.Context, to auth.Identity, m auth.Message) error {
	owner, err := p.core.FindIdentity(ctx, KindPhone, to.Value, true)
	switch {
	case err == nil && owner.UserID != to.UserID:
		return p.core.Deliver(ctx, owner, auth.Message{Purpose: auth.PurposeSignUpAttempt})
	case err != nil && !errors.Is(err, auth.ErrIdentityNotFound):
		return err
	}
	return p.core.Deliver(ctx, to, m)
}

// checkCode spends the open code for subject when code matches; see
// auth.CheckCode for the attempt counter and single use. number is the
// normalized number the code was texted to, which a Verifier checks by.
func (p *Plugin) checkCode(ctx context.Context, purpose auth.Purpose, subject, number, code string) error {
	if p.verifier != nil {
		return p.verifier.Check(ctx, number, code)
	}
	return p.core.CheckCode(ctx, purpose, subject, code, p.maxTries)
}

// UserJoin brings the primary phone identity into a composite user query.
// LEFT because a user may have no phone; kind and primary in the ON clause, or
// the result would multiply.
func UserJoin() sqlb.Join {
	return sqlb.Join{
		Type:  sqlb.JoinLeft,
		Table: TableIdentity,
		On: []sqlb.Predicate{
			sqlb.EqExpr(IdentityUserID, auth.UserID),
			sqlb.Eq(IdentityKind, KindPhone),
			sqlb.Eq(IdentityIsPrimary, true),
		},
	}
}

// UserBindings binds this plugin's columns to dst. Every column of a LEFT join
// must survive NULL, so strings and the flag are coalesced and VerifiedAt is a
// pointer, where nil is the meaningful answer.
func UserBindings(dst *Data) []sqlb.Binding {
	empty := sqlb.Literal[string]("''")
	notPrimary := sqlb.Literal[bool]("FALSE")
	return []sqlb.Binding{
		sqlb.Bind(sqlb.Coalesce(IdentityValue, empty), &dst.Number),
		sqlb.Bind(sqlb.Coalesce(IdentityValueRaw, empty), &dst.NumberRaw),
		sqlb.Bind(IdentityVerifiedAt, &dst.VerifiedAt),
		sqlb.Bind(sqlb.Coalesce(IdentityIsPrimary, notPrimary), &dst.IsPrimary),
	}
}

// Of builds the standalone lookup for one user's primary phone data, for an
// app that reads it outside a composite user query.
func Of(a *auth.Auth, userID string, dst *Data) (sqlb.Query, error) {
	return a.Select().
		Columns(UserBindings(dst)...).
		From(TableIdentity).
		Where(sqlb.Eq(IdentityUserID, userID), sqlb.Eq(IdentityKind, KindPhone), sqlb.Eq(IdentityIsPrimary, true)).
		Build()
}
