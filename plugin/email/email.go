// Package email registers the email identifier kind: normalization, the
// uniqueness policy, verification links, primary-address bookkeeping, change
// with undo, and delivery through an app-supplied Mailer.
//
// It has no table of its own. Addresses are rows of the core auth_identity
// table, so the core's one uniqueness rule and one verified check cover them;
// the plugin adds two columns to auth_user so the primary verified address is
// readable without a join.
package email

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity: route prefix and migration
// owner.
const PluginName = "email"

// KindEmail is the identifier kind this plugin registers. It is stored in
// every auth_identity row this plugin owns, so it never changes.
const KindEmail auth.IdentifierKindName = "email"

// Verification purposes this plugin owns. What each row's Identifier holds:
//
//   - PurposeVerifyToken: the identity id being verified.
//   - PurposeChangeToken: the user id; Meta is the new normalized address.
//   - PurposeUndoToken: the user id; Meta is "<old>\n<new>".
//   - PurposeApproveToken: the user id; Meta is the new normalized address,
//     sent to the current address under ApproveChangeFirst.
const (
	//ds:def id=purposeverifytoken-m9zusn9c owner=@khanakia stability=stable
	PurposeVerifyToken auth.Purpose = "email.verify"
	//ds:def id=purposechangetoken-uuqg97cm owner=@khanakia stability=stable
	PurposeChangeToken auth.Purpose = "email.change"
	//ds:def id=purposeundotoken-w3f3bsxc owner=@khanakia stability=stable
	PurposeUndoToken    auth.Purpose = "email.undo"
	PurposeApproveToken auth.Purpose = "email.approve"
)

// One-time-code purposes, used under VerifyByCode instead of the link
// purposes above. What each code's subject holds:
//
//   - PurposeVerifyCode: the identity id being verified.
//   - PurposeChangeCode: the user id and the new normalized address
//     (changeSubject), because no row exists for the new address until the
//     code is checked.
//   - PurposeApproveCode: the same subject as PurposeChangeCode, for the code
//     ApproveChangeFirst mails the CURRENT address under VerifyByCode; a
//     distinct purpose, so an approval code can never confirm the change.
const (
	PurposeVerifyCode  auth.Purpose = "email.verify_code"
	PurposeChangeCode  auth.Purpose = "email.change_code"
	PurposeApproveCode auth.Purpose = "email.approve_code"
)

// PurposeChangeApproval is the message purpose of the approval mail
// ApproveChangeFirst sends to the current address. Apps word it with
// Templates; the default is a generic subject and the DefaultText the plugin
// supplies, which names the new address.
const PurposeChangeApproval auth.Purpose = "email.change_approval"

// Operation ids, exported so another plugin's hook or a rate rule can name
// them. They are wire names, stable across releases.
const (
	EndpointVerify        auth.EndpointID = "email.verify"
	EndpointResend        auth.EndpointID = "email.resend"
	EndpointList          auth.EndpointID = "email.list"
	EndpointAdd           auth.EndpointID = "email.add"
	EndpointMakePrimary   auth.EndpointID = "email.make-primary"
	EndpointRemove        auth.EndpointID = "email.remove"
	EndpointChange        auth.EndpointID = "email.change"
	EndpointConfirmChange auth.EndpointID = "email.confirm-change"
	EndpointUndoChange    auth.EndpointID = "email.undo-change"
	EndpointApproveChange auth.EndpointID = "email.approve-change"
	EndpointSendCode      auth.EndpointID = "email.send-code"
	EndpointSignInCode    auth.EndpointID = "email.sign-in-code"
	EndpointVerifyCode    auth.EndpointID = "email.verify-code"
	EndpointConfirmCode   auth.EndpointID = "email.confirm-change-code"
	EndpointCheckCode     auth.EndpointID = "email.check-code"
	EndpointApproveCode   auth.EndpointID = "email.approve-change-code"
	// EndpointVerifyLink is the GET verification VerifyByGET adds.
	EndpointVerifyLink auth.EndpointID = "email.verify-link"
)

// CodeKind names which code check-code looks at. The three kinds live under
// different subjects, so the client says which one it holds.
type CodeKind string

// Code kinds.
const (
	// CodeKindVerify is a verify code (VerifyByCode): the address as typed,
	// or the signed-in user's own address.
	CodeKindVerify CodeKind = "verify"
	// CodeKindSignIn is a sign-in code (SignInWithCode) for the address.
	CodeKindSignIn CodeKind = "sign_in"
	// CodeKindChange is a change code (VerifyByCode) for the signed-in
	// user's new address; signed out it is simply not found.
	CodeKindChange CodeKind = "change"
	// CodeKindApprove is an approval code (VerifyByCode with
	// ApproveChangeFirst), mailed to the signed-in user's current address
	// and named by the new address; signed out it is simply not found.
	CodeKindApprove CodeKind = "approve"
)

// CodeKindValues is the canonical iteration order over code kinds.
var CodeKindValues = []CodeKind{CodeKindVerify, CodeKindSignIn, CodeKindChange, CodeKindApprove}

// PurposeSignInCode is the one-time-code purpose of an email sign-in code. Its
// subject is the tenant and the normalized address; see codeSubject.
const PurposeSignInCode auth.Purpose = "email.sign_in"

// Sign-in code limits.
const (
	// DefaultCodeTTL is how long a mailed sign-in code works. Mail can take a
	// minute or two to arrive; longer only helps whoever reads the inbox later.
	//ds:def id=defaultcodettl-u6wv36f8 owner=@khanakia stability=stable
	DefaultCodeTTL = 10 * time.Minute
	// codeSendLimit codes per address per codeSendWindow: enough for a slow
	// inbox and a retry, too few to flood somebody's mailbox.
	//ds:def id=codesendlimit-qfj4z5qd owner=@khanakia stability=stable
	codeSendLimit = 3
	//ds:def id=codesendwindow-dcte2wg4 owner=@khanakia stability=stable
	codeSendWindow = 15 * time.Minute
	// codeTryLimit guesses per address per codeTryWindow. The core's per-code
	// attempt counter is the real bound; this stops a script cycling codes.
	//ds:def id=codetrylimit-g634sbgs owner=@khanakia stability=stable
	codeTryLimit = 10
	//ds:def id=codetrywindow-s4j4v4rp owner=@khanakia stability=stable
	codeTryWindow = 15 * time.Minute
)

// Column names this plugin adds to auth_user.
const (
	//ds:def id=colprimaryemail-wk287c2b owner=@khanakia stability=stable
	ColPrimaryEmail = "primary_email"
	//ds:def id=colemailverifiedat-vqzgpu2a owner=@khanakia stability=stable
	ColEmailVerifiedAt = "email_verified_at"
)

// Typed columns on auth_user. Both are null until the user has a verified
// primary address, which is the only kind that is copied here.
var (
	PrimaryEmail    = sqlb.Col[*string](auth.TableUser, ColPrimaryEmail)
	EmailVerifiedAt = sqlb.Col[*time.Time](auth.TableUser, ColEmailVerifiedAt)
)

// EmailColumns is this plugin's part of a composite user. Embed it: the
// columns are on auth_user, so the fields are flat.
//
// Why the name stutters: Go names an embedded field after its type, so if two
// plugins both exported a type called Columns, an app could not embed both.
// Every plugin names its column struct <Plugin>Columns for that reason.
//
//ds:def id=emailcolumns-nkpp3jz8
type EmailColumns struct {
	PrimaryEmail    *string
	EmailVerifiedAt *time.Time
}

// Bindings binds EmailColumns for a query on auth_user, so an app reads the
// primary address in the same SELECT as the user without a join.
func Bindings(c *EmailColumns) []sqlb.Binding {
	return []sqlb.Binding{sqlb.Bind(PrimaryEmail, &c.PrimaryEmail), sqlb.Bind(EmailVerifiedAt, &c.EmailVerifiedAt)}
}

// Default lifetimes.
const (
	// DefaultVerifyTTL is how long a verify or change link works: a day, so a
	// user who signs up at night can verify in the morning.
	//ds:def id=defaultverifyttl-npdv6uys owner=@khanakia stability=stable
	DefaultVerifyTTL = 24 * time.Hour
	// DefaultUndoTTL is how long the old address can undo a change. A week,
	// because the owner of a stolen account may not read mail every day.
	//ds:def id=defaultundottl-f64c6t59 owner=@khanakia stability=stable
	DefaultUndoTTL = 7 * 24 * time.Hour
	// maxEmailLength is the practical limit of an address (RFC 5321 path).
	//ds:def id=maxemaillength-4xhgzxu9 owner=@khanakia stability=stable
	maxEmailLength = 254
)

// Bounds on client-supplied message metadata (AddressRequest.Metadata). The
// map comes from a public request body and travels to the app's Mailer, so
// its size is capped: enough for an invite id and a few flags, too small to
// carry a payload.
const (
	//ds:def id=maxmetadataentries-6p3kr9wt owner=@khanakia stability=stable
	MaxMetadataEntries = 8
	//ds:def id=maxmetadatalength-2n8vx4qm owner=@khanakia stability=stable
	MaxMetadataLength = 256
)

// CheckMetadata refuses a metadata map over the bounds with
// auth.ErrBadRequest; nil and empty pass. Other identifier plugins that take
// metadata in a request body apply the same bounds through it.
func CheckMetadata(m map[string]string) error {
	if len(m) > MaxMetadataEntries {
		return auth.ErrBadRequest
	}
	for k, v := range m {
		if len(k) > MaxMetadataLength || len(v) > MaxMetadataLength {
			return auth.ErrBadRequest
		}
	}
	return nil
}

// Mail-sending limits per address. Each request mails somebody, so the limit
// is what stops the endpoint being used to flood a stranger's inbox.
const (
	// resendLimit verify links per address per resendWindow.
	//ds:def id=resendlimit-e86bngax owner=@khanakia stability=stable
	resendLimit = 3
	//ds:def id=resendwindow-h6y5x7v2 owner=@khanakia stability=stable
	resendWindow = time.Hour
	// changeLimit confirm links per new address per changeWindow; higher than
	// resend because a user may mistype the new address a few times.
	//ds:def id=changelimit-zhfvkgzx owner=@khanakia stability=stable
	changeLimit = 5
	//ds:def id=changewindow-p3k2ces8 owner=@khanakia stability=stable
	changeWindow = time.Hour
)

// Errors this plugin returns. ErrSingleAddress reaches the user; the others
// are configuration errors auth.New returns, so a broken setup fails at start
// rather than at the first sign-up.
var (
	ErrSingleAddress            = auth.NewError("email.single_address", http.StatusConflict, "This account can have one email address. Change it instead.")
	ErrNoMailer                 = errors.New("email: no mailer; pass email.WithMailer")
	ErrNoBaseURL                = errors.New("email: links need auth.WithBaseURL or email.Links")
	ErrCodesNeedLogin           = errors.New("email: SignInWithCode needs Login()")
	ErrSignInOnVerifyNeedsLogin = errors.New("email: SignInOnVerify needs Login()")
	// ErrCallbackInvalid refuses a verify-link whose callbackURL is not a
	// page of this site or of a trusted origin (auth.Auth.TrustsReturnURL),
	// so the GET route is never an open redirect. ErrBadCallback is the same
	// mistake in VerifyByGET's own argument, refused by auth.New.
	//ds:def id=email-errcallbackinvalid-4mw9qt2k owner=@khanakia stability=stable
	ErrCallbackInvalid = auth.NewError("email.callback_invalid", http.StatusBadRequest, "This page cannot be opened after verifying.")
	ErrBadCallback     = errors.New("email: VerifyByGET's callback must be a path of this site or a URL on a trusted origin")
)

// Mail is one message for the Mailer: plain text only, because every link a
// message carries must survive a client that renders no HTML.
//
//ds:def id=mail-gke5vh6e
type Mail struct {
	To      string
	Subject string
	Text    string
	// Metadata is what the sending operation attached (auth.Message.Metadata):
	// an invite id, a campaign, a page the client was on. Nil for most mail.
	// The Mailer may use it for its own routing or templates; the library
	// never reads it.
	Metadata map[string]string
}

// Mailer sends mail. The app implements it over SMTP, an API or a queue.
//
//ds:def id=mailer-2eb6h2qx
type Mailer interface {
	Send(ctx context.Context, m Mail) error
}

// MailerFunc adapts a function to Mailer, for an app whose sender is a
// closure over its SMTP or API client.
type MailerFunc func(ctx context.Context, m Mail) error

// Send calls f, so a closure satisfies Mailer without a named type.
func (f MailerFunc) Send(ctx context.Context, m Mail) error { return f(ctx, m) }

// Plugin is the email identifier plugin. Build it with New: the zero value
// has no kind, no templates and no operations.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs   auth.OptionErrors
	kind      auth.IdentifierKind
	multiple  bool
	codes     bool
	welcome   bool
	codeUp    bool
	byCode    bool
	mailer    Mailer
	verifyTTL time.Duration
	undoTTL   time.Duration
	// codeTTL, codeTries and the two code limits are the sign-in code
	// policy; the defaults are the constants above, each option replaces one.
	codeTTL        time.Duration
	codeTries      int
	codeSend       limit
	codeTry        limit
	signInOnVerify bool
	approveFirst   bool
	resendOnSignIn bool
	// changeUnverified is ChangeWithoutVerification.
	changeUnverified bool
	// replaceUnverified is set by ReplaceUnverified: a change while no
	// address is verified replaces the address at once.
	replaceUnverified bool
	// genCode (GenerateCode) makes every mailed code; reuseCode
	// (ReuseCodeOnResend) mails an open code again instead of replacing it.
	genCode   CodeGenerator
	reuseCode bool
	// checks (CheckAddresses) decide whether a new address may be stored.
	checks []AddressCheck
	// getVerify serves verify-link and points verify mail at it, with
	// getCallback as the page to land on ("" for a JSON answer).
	getVerify   bool
	getCallback string
	links       func(p auth.Purpose, t auth.Token) string
	templates   func(m auth.Message) (subject, text string)
	localized   map[string]TemplateFunc
	core        *auth.Auth

	verify        *auth.Op[TokenRequest, VerifyResult]
	verifyLink    *auth.Op[VerifyLinkRequest, VerifyResult]
	resend        *auth.Op[AddressRequest, auth.Done]
	list          *auth.Op[struct{}, ListResult]
	add           *auth.Op[AddressRequest, auth.Done]
	makePrimary   *auth.Op[AddressRequest, auth.Done]
	remove        *auth.Op[AddressRequest, auth.Done]
	change        *auth.Op[AddressRequest, auth.Done]
	confirmChange *auth.Op[TokenRequest, VerifyResult]
	undoChange    *auth.Op[TokenRequest, auth.Done]
	approveChange *auth.Op[TokenRequest, auth.Done]
	approveCode   *auth.Op[AddressCodeRequest, auth.Done]
	sendCode      *auth.Op[AddressRequest, auth.Done]
	signInCode    *auth.Op[CodeRequest, CodeSignInResult]
	verifyCode    *auth.Op[AddressCodeRequest, VerifyResult]
	confirmCode   *auth.Op[AddressCodeRequest, VerifyResult]
	checkCode     *auth.Op[CheckCodeRequest, auth.Done]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin; options are applied in order by New.
type Option func(*Plugin)

// Login allows email in sign-in. auth.New then requires the address to be
// unique, since a login box cannot pick between two users.
func Login() Option { return kindOpt(auth.Login()) }

// Recover allows email to receive recovery messages such as password reset
// links. Only a verified address receives one.
func Recover() Option { return kindOpt(auth.Recover()) }

// Contact makes email contact information only: several users may share an
// address, and it neither signs in nor recovers.
func Contact() Option { return kindOpt(auth.Contact()) }

// ScopedByTenant makes addresses unique per tenant; see auth.WithScope.
func ScopedByTenant() Option { return kindOpt(auth.ScopedByTenant()) }

// RequireVerified refuses sign-in until the address is verified, for an app
// where an unproven address must not open an account.
func RequireVerified() Option { return func(p *Plugin) { p.kind.RequireVerified = true } }

// SignInWithCode enables sign-in with a six-digit code sent to a verified
// address, as a passwordless method. It needs Login.
func SignInWithCode() Option { return func(p *Plugin) { p.codes = true } }

// SignUpWithCode also lets a code create an account for an address nobody has
// verified, whose control the code has just proven. Implies SignInWithCode.
//
//ds:def id=signupwithcode-9w3kx5mx
func SignUpWithCode() Option { return func(p *Plugin) { p.codes, p.codeUp = true, true } }

// VerifyByCode makes verification and address change work by a code the
// person types instead of a link they click: the verify mail, a resend, the
// confirm mail of a change and the approval mail of ApproveChangeFirst carry
// a code (WithCodeTTL, WithMaxAttempts apply), checked at verify-code,
// confirm-change-code and approve-change-code. A code suits a mobile app,
// where a link would open the browser, and survives mail scanners, which
// open every link. The undo mail of a change stays a link: its reader may
// be anywhere, and it must work after the sessions it ends are gone. The
// link routes stay registered, so links sent before the switch still work.
//
//ds:def id=verifybycode-8n4tr2mq owner=@khanakia stability=stable
func VerifyByCode() Option { return func(p *Plugin) { p.byCode = true } }

// Welcome sends a welcome mail (auth.PurposeWelcome) when a user's first
// address is verified: once per user, and only to an address the user has
// proven, so it cannot be used to mail strangers.
func Welcome() Option { return func(p *Plugin) { p.welcome = true } }

// Multiple allows many addresses per user, one of them primary. Without it a
// change replaces the address, and Add refuses a second one.
//
//ds:def id=multiple-epxe5zae
func Multiple() Option { return func(p *Plugin) { p.multiple = true } }

// WithMailer sets how mail is sent. Required: auth.New fails with
// ErrNoMailer without it, because verification is impossible without mail.
func WithMailer(m Mailer) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("email.WithMailer", m) {
			return
		}
		p.mailer = m
	}
}

// WithNormalizer replaces Normalize, for an app that folds dots or +tags.
func WithNormalizer(fn func(raw string) (string, error)) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("email.WithNormalizer", fn) {
			return
		}
		p.kind.Normalize = fn
	}
}

// WithVerifyTTL overrides DefaultVerifyTTL for verify and change links.
func WithVerifyTTL(d time.Duration) Option { return func(p *Plugin) { p.verifyTTL = d } }

// WithUndoTTL overrides DefaultUndoTTL, how long the old address can undo a
// change.
func WithUndoTTL(d time.Duration) Option { return func(p *Plugin) { p.undoTTL = d } }

// WithCodeTTL overrides DefaultCodeTTL, how long a mailed sign-in code works.
func WithCodeTTL(d time.Duration) Option { return func(p *Plugin) { p.codeTTL = d } }

// WithMaxAttempts overrides auth.DefaultCodeMaxAttempts for sign-in codes:
// the wrong guesses one code survives before it is spent.
func WithMaxAttempts(n int) Option { return func(p *Plugin) { p.codeTries = n } }

// WithCodeSendLimit replaces the default of 3 codes per address per 15
// minutes. Each code is a mail to somebody, so the limit is what stops the
// endpoint flooding an inbox; raise it for a product whose users retry often.
func WithCodeSendLimit(n int, window time.Duration) Option {
	return func(p *Plugin) { p.codeSend = limit{n, window} }
}

// WithCodeTryLimit replaces the default of 10 guesses per address per 15
// minutes. The per-code attempt cap (WithMaxAttempts) is the real bound; this
// one stops a script cycling fresh codes.
func WithCodeTryLimit(n int, window time.Duration) Option {
	return func(p *Plugin) { p.codeTry = limit{n, window} }
}

// SignInOnVerify makes a verify link also sign its user in: the click proves
// control of the mailbox, as a magic link does. It needs Login(). The session
// is a first factor only, so a user with two-factor gets a pending one.
func SignInOnVerify() Option { return func(p *Plugin) { p.signInOnVerify = true } }

// ApproveChangeFirst makes a change of address a two-step affair: the link
// goes to the CURRENT verified primary address first, and only when it is
// used does the confirm link go to the new address. Without it the old
// address is told after the switch, with an undo link; with it the old
// address decides before. A user whose current address is unverified gets
// the one-step flow, because there is nobody proven to ask. Under
// VerifyByCode the approval is a code, typed by the signed-in user at
// approve-change-code: the reader is the person who just asked, in the app.
func ApproveChangeFirst() Option { return func(p *Plugin) { p.approveFirst = true } }

// ReplaceUnverified lets a user who mistyped their address at sign-up fix it
// without ever receiving mail: while none of the user's addresses is verified,
// `change` replaces the address at once and the verification goes to the new
// one; no confirm step, no undo mail (an unverified address proves nothing
// about who owns the account, so there is nobody to warn). The moment an
// address is verified, a change is the normal two-step affair again: the new
// address must be proven first, and the old one gets the undo link, because
// that is what keeps a stolen session from redirecting every reset mail.
//
// The answer is the same whether or not the new address is already another
// account's: then nothing changes and that account's owner is told someone
// tried, as a duplicate sign-up does, so the route confirms no address. The
// rate rule of `change` (per new address) covers both paths.
//
//ds:def id=replaceunverified-3kq7mw8p owner=@khanakia stability=stable
func ReplaceUnverified() Option { return func(p *Plugin) { p.replaceUnverified = true } }

// WarnChangeWithoutVerification is logged by Init under
// ChangeWithoutVerification.
//
//ds:def id=warnchangewithoutverification-4kq8wn3x owner=@khanakia stability=stable
const WarnChangeWithoutVerification = "email: ChangeWithoutVerification is on: a signed-in session can replace a verified address without proving the new one (a stolen session redirects every reset mail)"

// ChangeWithoutVerification makes `change` replace the
// address at once even when the current one is verified, as ReplaceUnverified
// does while none is. The new address is unverified and gets the
// verification mail; the old one is gone, with no confirm step and no undo
// mail. Off by default; Init logs WarnChangeWithoutVerification at every
// start while it is on.
//
// The risk it opens: whoever holds a session (a laptop left open, a stolen
// cookie) can point the account at an address of their own, and every
// password-reset and magic-link mail goes there from then on, with no mail
// to the old address to warn its owner or undo it. The core still refuses
// a change that would remove the user's last way in.
//
//ds:def id=changewithoutverification-7nw2kq5x owner=@khanakia stability=stable
func ChangeWithoutVerification() Option { return func(p *Plugin) { p.changeUnverified = true } }

// VerifyByGET adds a GET verification route: GET
// <mount>/email/verify-link?token=…&callbackURL=… spends the token, verifies
// the address (and signs in under SignInOnVerify), then redirects to
// callbackURL, or to callbackURL?error=<code> when the link is bad; without a
// trusted callbackURL a failure lands on auth.WithErrorURL's page, and the
// route answers JSON like POST verify when neither is set. The verify mail's
// default link points at it, BaseURL + DefaultMountPrefix +
// "/email/verify-link", with callback ("" for none) as its callbackURL; Links
// still overrides.
//
// Off by default, and the risk is why: a GET spends the token, so a mail
// scanner or a link preview that fetches the URL verifies the address (and,
// under SignInOnVerify, opens a session nobody uses) before the person
// clicks, and the person then lands on "this link has expired". With
// SignInOnVerify a GET sign-in also cannot be origin-checked, so a link to
// an attacker's own verification signs a victim into the attacker's account
// (login CSRF), which auth.WithFetchMetadata, judging mutations only,
// does not cover. The default POST page has neither problem. callbackURL must
// pass auth.Auth.TrustsReturnURL; the POST route stays for links already
// sent.
//
//ds:def id=email-verifybyget-6qz3wn8t owner=@khanakia stability=stable
func VerifyByGET(callback string) Option {
	return func(p *Plugin) { p.getVerify, p.getCallback = true, callback }
}

// DefaultMountPrefix is where VerifyByGET's default link assumes the auth
// handler is mounted, as the oauth plugin's default callback does.
//
//ds:def id=email-defaultmountprefix-8vk2rx5m owner=@khanakia stability=stable
const DefaultMountPrefix = "/auth"

// verifyLinkPath is the route of verify-link under the plugin.
const verifyLinkPath = "/verify-link"

// callbackParam and tokenParam are the query parameters of verify-link: the
// landing page and the token.
const (
	callbackParam = "callbackURL"
	tokenParam    = "token"
)

// ResendOnSignIn makes SendVerification mail a fresh verify link, so a
// sign-in refused because the address is unverified (RequireVerified) gets the
// link again without a separate resend. Off, SendVerification sends nothing:
// a sign-in attempt then mails nobody.
func ResendOnSignIn() Option { return func(p *Plugin) { p.resendOnSignIn = true } }

// SendVerification mails a fresh verify link for one of this plugin's
// unverified addresses, when ResendOnSignIn is set. The core calls it through
// its dispatcher after a correct password was refused for lack of
// verification; a verified or foreign identity is ignored.
func (p *Plugin) SendVerification(ctx context.Context, to auth.Identity) error {
	if !p.resendOnSignIn || to.Kind != KindEmail || to.Verified() {
		return nil
	}
	return p.sendVerify(ctx, to)
}

// limit is one rate rule's numbers.
type limit struct {
	n      int
	window time.Duration
}

// Links builds the URL a message carries. The link must open a page of the
// app that POSTs the token; a GET that spent the token would be spent by every
// mail scanner that previews links.
func Links(fn func(p auth.Purpose, t auth.Token) string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("email.Links", fn) {
			return
		}
		p.links = fn
	}
}

// TemplateFunc renders one message as a subject and a text body. It must
// include m.Link or m.Code when set, or the message is useless.
type TemplateFunc = func(m auth.Message) (subject, text string)

// TemplatesByLocale adds translations: the message's Locale picks one by
// auth.PickLocale (exact tag, then base language), and a message whose
// language has none uses the templates set by Templates, or the English
// defaults. The library ships no translations; the words are the app's.
//
// The choice is made at delivery, so the order of this option and Templates
// does not matter.
//
//ds:def id=templatesbylocale-mexdnb77
func TemplatesByLocale(byLocale map[string]TemplateFunc) Option {
	return func(p *Plugin) { p.localized = byLocale }
}

// Templates replaces the default English subjects and bodies, for every
// locale TemplatesByLocale does not cover.
//
//ds:def id=templates-63cjtwhk
func Templates(fn func(m auth.Message) (subject, text string)) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("email.Templates", fn) {
			return
		}
		p.templates = fn
	}
}

func kindOpt(o auth.KindOption) Option { return func(p *Plugin) { p.kind = auth.ApplyKind(p.kind, o) } }

// Compile-time proof of each capability; a wrong signature would otherwise
// silently drop it.
var (
	_ auth.IdentifierProvider = (*Plugin)(nil)
	_ auth.Deliverer          = (*Plugin)(nil)
	_ auth.ColumnExtender     = (*Plugin)(nil)
	_ auth.DataHooker         = (*Plugin)(nil)
	_ auth.OperationProvider  = (*Plugin)(nil)
	_ auth.RateLimiter        = (*Plugin)(nil)
	_ auth.Initializer        = (*Plugin)(nil)
	_ auth.Validator          = (*Plugin)(nil)
	_ auth.SignInMethod       = (*Plugin)(nil)
	_ auth.VerificationSender = (*Plugin)(nil)
)

// New builds the plugin. With no options an address is unique among verified
// rows and verifiable, but neither signs in nor recovers: those are choices.
func New(opts ...Option) *Plugin {
	p := &Plugin{
		kind: auth.IdentifierKind{
			Name: KindEmail, Unique: true, UniqueOnlyVerified: true, Verifiable: true,
			Normalize: Normalize, Validate: Validate,
		},
		verifyTTL: DefaultVerifyTTL,
		undoTTL:   DefaultUndoTTL,
		codeTTL:   DefaultCodeTTL,
		codeTries: auth.DefaultCodeMaxAttempts,
		codeSend:  limit{codeSendLimit, codeSendWindow},
		codeTry:   limit{codeTryLimit, codeTryWindow},
		templates: DefaultTemplates,
	}
	for _, o := range opts {
		o(p)
	}
	p.verify = auth.Define(auth.OpInfo{ID: EndpointVerify, Kind: auth.Mutation, Require: auth.Public, Path: "/verify", SignIn: p.signInOnVerify}, p.doVerify)
	p.verifyLink = auth.Define(auth.OpInfo{ID: EndpointVerifyLink, Kind: auth.Query, Require: auth.Public, Path: verifyLinkPath, SignIn: p.signInOnVerify}, p.doVerifyLink)
	p.resend = auth.Define(auth.OpInfo{ID: EndpointResend, Kind: auth.Mutation, Require: auth.Public, Path: "/resend"}, p.doResend)
	p.list = auth.Define(auth.OpInfo{ID: EndpointList, Kind: auth.Query, Require: auth.SignedIn, Path: "/list"}, p.doList)
	p.add = auth.Define(auth.OpInfo{ID: EndpointAdd, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/add"}, p.doAdd)
	p.makePrimary = auth.Define(auth.OpInfo{ID: EndpointMakePrimary, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/make-primary"}, p.doMakePrimary)
	p.remove = auth.Define(auth.OpInfo{ID: EndpointRemove, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/remove"}, p.doRemove)
	p.change = auth.Define(auth.OpInfo{ID: EndpointChange, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/change"}, p.doChange)
	p.confirmChange = auth.Define(auth.OpInfo{ID: EndpointConfirmChange, Kind: auth.Mutation, Require: auth.Public, Path: "/confirm-change"}, p.doConfirmChange)
	p.sendCode = auth.Define(auth.OpInfo{ID: EndpointSendCode, Kind: auth.Mutation, Require: auth.Public, Path: "/send-code"}, p.doSendCode)
	p.signInCode = auth.Define(auth.OpInfo{ID: EndpointSignInCode, Kind: auth.Mutation, Require: auth.Public, Path: "/sign-in-code", SignIn: true}, p.doSignInCode)
	p.undoChange = auth.Define(auth.OpInfo{ID: EndpointUndoChange, Kind: auth.Mutation, Require: auth.Public, Path: "/undo-change"}, p.doUndoChange)
	p.verifyCode = auth.Define(auth.OpInfo{ID: EndpointVerifyCode, Kind: auth.Mutation, Require: auth.Public, Path: "/verify-code", SignIn: p.signInOnVerify}, p.doVerifyCode)
	p.confirmCode = auth.Define(auth.OpInfo{ID: EndpointConfirmCode, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/confirm-change-code"}, p.doConfirmChangeCode)
	p.checkCode = auth.Define(auth.OpInfo{ID: EndpointCheckCode, Kind: auth.Mutation, Require: auth.Public, Path: "/check-code"}, p.doCheckCode)
	p.approveChange = auth.Define(auth.OpInfo{ID: EndpointApproveChange, Kind: auth.Mutation, Require: auth.Public, Path: "/approve-change"}, p.doApproveChange)
	p.approveCode = auth.Define(auth.OpInfo{ID: EndpointApproveCode, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/approve-change-code"}, p.doApproveChangeCode)
	return p
}

// Name returns PluginName, the key the core stores this plugin's migrations
// and route prefix under; it never changes.
func (p *Plugin) Name() string { return PluginName }

// Identifiers registers the email kind with the core, which from then on
// owns its uniqueness and verified checks.
func (p *Plugin) Identifiers() []auth.IdentifierKind { return []auth.IdentifierKind{p.kind} }

// Validate checks that messages can be sent and linked, so a setup that
// could never verify an address fails in auth.New, not at the first sign-up.
func (p *Plugin) Validate(c *auth.Config) error {
	if p.mailer == nil {
		return ErrNoMailer
	}
	if p.links == nil && c.BaseURL == "" {
		return ErrNoBaseURL
	}
	if p.codes && !p.kind.CanLogin {
		return ErrCodesNeedLogin
	}
	if p.signInOnVerify && !p.kind.CanLogin {
		return ErrSignInOnVerifyNeedsLogin
	}
	if p.reuseCode {
		// A reused code is derived or sealed under a key from the secret.
		if _, err := c.DeriveKeys(reuseKeyProbe); err != nil {
			return fmt.Errorf("email: ReuseCodeOnResend: %w", err)
		}
	}
	return nil
}

// reuseKeyProbe is the label Validate derives a key under only to learn that
// auth.WithSecret was given; the key itself is discarded.
const reuseKeyProbe = "email.reuse-probe"

// SignsIn reports whether code sign-in is on, which is what counts as a way
// in for the core's "someone can sign in" check.
func (p *Plugin) SignsIn() bool { return p.codes && p.kind.CanLogin }

// Init captures the core and fills the default link builder from
// auth.WithBaseURL; it runs after Validate has checked one of them is set.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	if p.changeUnverified {
		a.Logger().Warn(WarnChangeWithoutVerification)
	}
	if p.getVerify && p.getCallback != "" && !a.TrustsReturnURL(p.getCallback) {
		return ErrBadCallback
	}
	if p.links == nil {
		base := strings.TrimSuffix(a.Config().BaseURL, "/")
		p.links = func(purpose auth.Purpose, t auth.Token) string { return DefaultLink(base, purpose, t) }
		if p.getVerify {
			p.links = func(purpose auth.Purpose, t auth.Token) string {
				switch purpose {
				case PurposeVerifyToken:
					q := url.Values{tokenParam: {t.Reveal()}}
					if p.getCallback != "" {
						q.Set(callbackParam, p.getCallback)
					}
					return base + DefaultMountPrefix + "/" + PluginName + verifyLinkPath + "?" + q.Encode()
				default:
					return DefaultLink(base, purpose, t)
				}
			}
		}
	}
	return nil
}

// Default app pages the links open. Each page reads the token from the query
// and POSTs it to the matching operation. They are pages of the app, not of
// this library, because a link must never spend its token on a GET.
const (
	//ds:def id=defaultverifypage-27eburvg owner=@khanakia stability=stable
	DefaultVerifyPage = "/verify-email"
	//ds:def id=defaultchangepage-fbv79xmc owner=@khanakia stability=stable
	DefaultChangePage = "/confirm-email-change"
	//ds:def id=defaultundopage-svuesac4 owner=@khanakia stability=stable
	DefaultUndoPage = "/undo-email-change"
	// DefaultApprovePage is where the approval link of ApproveChangeFirst
	// lands; the page POSTs the token to approve-change.
	DefaultApprovePage = "/approve-email-change"
)

// defaultPages maps each link purpose to the page DefaultLink points at.
var defaultPages = map[auth.Purpose]string{
	PurposeVerifyToken:  DefaultVerifyPage,
	PurposeChangeToken:  DefaultChangePage,
	PurposeUndoToken:    DefaultUndoPage,
	PurposeApproveToken: DefaultApprovePage,
}

// DefaultLink is the link the plugin sends when no Links option is given: a
// page of the app, named for the purpose, with the token in the query.
func DefaultLink(base string, purpose auth.Purpose, t auth.Token) string {
	return base + defaultPages[purpose] + "?token=" + url.QueryEscape(t.Reveal())
}

// Columns adds the primary address to auth_user. The data hooks keep it in
// step with auth_identity; nothing else may write it.
func (p *Plugin) Columns() []auth.ColumnExtension {
	return []auth.ColumnExtension{
		{Table: auth.TableNameUser, Name: ColPrimaryEmail, Type: auth.ColumnText, Nullable: true},
		{Table: auth.TableNameUser, Name: ColEmailVerifiedAt, Type: auth.ColumnTimestamp, Nullable: true},
	}
}

// RateLimits bounds the operations that send mail, per address, so none can
// be used to flood an inbox.
func (p *Plugin) RateLimits() []auth.RateRule {
	rules := []auth.RateRule{
		{Match: EndpointResend, Key: auth.ByIdentifier, Limit: resendLimit, Window: resendWindow},
		{Match: EndpointChange, Key: auth.ByIdentifier, Limit: changeLimit, Window: changeWindow},
	}
	if p.byCode {
		rules = append(rules,
			auth.RateRule{Match: EndpointVerifyCode, Key: auth.ByIdentifier, Limit: p.codeTry.n, Window: p.codeTry.window},
			auth.RateRule{Match: EndpointConfirmCode, Key: auth.ByIdentifier, Limit: p.codeTry.n, Window: p.codeTry.window},
		)
	}
	if p.byCode && p.approveFirst {
		rules = append(rules, auth.RateRule{Match: EndpointApproveCode, Key: auth.ByIdentifier, Limit: p.codeTry.n, Window: p.codeTry.window})
	}
	if p.byCode || p.SignsIn() {
		// A peek counts an attempt like a check, so it shares the guess budget.
		rules = append(rules, auth.RateRule{Match: EndpointCheckCode, Key: auth.ByIdentifier, Limit: p.codeTry.n, Window: p.codeTry.window})
	}
	if p.SignsIn() {
		rules = append(rules,
			auth.RateRule{Match: EndpointSendCode, Key: auth.ByIdentifier, Limit: p.codeSend.n, Window: p.codeSend.window},
			auth.RateRule{Match: EndpointSignInCode, Key: auth.ByIdentifier, Limit: p.codeTry.n, Window: p.codeTry.window},
		)
	}
	return rules
}

// Operations lists every operation; the code ones only when SignsIn, so an
// app without codes exposes no route that mails them.
func (p *Plugin) Operations() []auth.Operation {
	ops := []auth.Operation{p.verify, p.resend, p.list, p.add, p.makePrimary, p.remove, p.change, p.confirmChange, p.undoChange}
	if p.getVerify {
		ops = append(ops, p.verifyLink)
	}
	if p.approveFirst {
		ops = append(ops, p.approveChange)
	}
	if p.byCode {
		ops = append(ops, p.verifyCode, p.confirmCode)
	}
	if p.byCode && p.approveFirst {
		ops = append(ops, p.approveCode)
	}
	if p.SignsIn() {
		ops = append(ops, p.sendCode, p.signInCode)
	}
	if p.byCode || p.SignsIn() {
		ops = append(ops, p.checkCode)
	}
	return ops
}

// Normalize trims and lowercases an address. It does not remove dots or
// +tags: that blocks a common habit, and the choice belongs to the app
// (WithNormalizer).
func Normalize(raw string) (string, error) { return fold(raw), nil }

// fold is the default normal form, shared by Normalize and the rate-limit
// keys so a limit counts "A@x.io" and " a@x.io" as one address.
func fold(raw string) string { return strings.ToLower(strings.TrimSpace(raw)) }

// Validate is a structural check only. No pattern matches the real grammar;
// delivery of the verify link is the real validation.
func Validate(v string) error {
	at := strings.IndexByte(v, '@')
	switch {
	case len(v) > maxEmailLength:
		return errors.New("email: address too long")
	case at <= 0 || at == len(v)-1:
		return errors.New("email: no local part or domain")
	case strings.Contains(v[at+1:], "@"):
		return errors.New("email: more than one @")
	case strings.ContainsAny(v, " \t\r\n<>,;\""):
		return errors.New("email: contains a character an address cannot have")
	case !strings.Contains(v[at+1:], "."):
		return errors.New("email: domain has no dot")
	}
	return nil
}

// Deliver renders m in its locale's template and sends it. The core calls it
// after the transaction commits, so mail never goes out for a rolled-back row.
func (p *Plugin) Deliver(ctx context.Context, to auth.Identity, m auth.Message) error {
	render := p.templates
	if t, ok := auth.PickLocale(p.localized, m.Locale); ok {
		render = t
	}
	subject, text := render(m)
	return p.mailer.Send(ctx, Mail{To: to.Value, Subject: subject, Text: text, Metadata: m.Metadata})
}

// genericSubject is the subject of a message whose purpose this plugin does
// not know and whose sender gave no subject of its own.
const genericSubject = "A message about your account"

// DefaultTemplates are short English messages. A link is on its own line so
// every client makes it clickable.
//
//ds:def id=defaulttemplates-57x3ftqb
func DefaultTemplates(m auth.Message) (subject, text string) {
	switch m.Purpose {
	case auth.PurposeVerify:
		// Under VerifyByCode the message carries a code instead of a link.
		if m.Code != "" && m.Link == "" {
			return "Your verification code", "Your verification code is " + m.Code + ".\n\nIf you did not ask for this, ignore this email."
		}
		return "Verify your email address", "Open this link to verify your email address:\n\n" + m.Link + "\n\nIf you did not ask for this, ignore this email."
	case auth.PurposeReset:
		// A reset by code (the password plugin's ResetByCode) carries a code
		// instead of a link.
		if m.Code != "" && m.Link == "" {
			return "Your password reset code", "Your password reset code is " + m.Code + ".\n\nIf you did not ask for this, ignore this email. Your password has not changed."
		}
		return "Reset your password", "Open this link to choose a new password:\n\n" + m.Link + "\n\nIf you did not ask for this, ignore this email. Your password has not changed."
	case auth.PurposeSignUpAttempt:
		return "Someone tried to sign up with your address", "Someone tried to create an account with this email address. You already have one.\n\nIf this was you, sign in instead. If it was not, you do not need to do anything."
	case auth.PurposeChanged:
		return "Your email address was changed", "The email address of your account was changed. If you did not do this, open this link to undo it and sign out every session:\n\n" + m.Link
	case auth.PurposeSignInCode:
		return "Your sign-in code", "Your sign-in code is " + m.Code
	case auth.PurposeWelcome:
		return "Welcome", "Your account is ready. You can sign in with this address from now on."
	case auth.PurposeSignInLink:
		return "Your sign-in link", "Open this link to sign in. It works once, for a few minutes:\n\n" + m.Link + "\n\nIf you did not ask for this, ignore this email."
	default:
		// A purpose of another plugin: use its own wording when it gave some
		// (auth.Message.DefaultText), under the generic subject if it gave
		// none, so a mail never goes out without one.
		subject := genericSubject
		if m.DefaultSubject != "" {
			subject = m.DefaultSubject
		}
		if m.DefaultText != "" {
			return subject, m.DefaultText
		}
		return subject, m.Link
	}
}

// DataHooks keep auth_user's copy of the primary address, and send a verify
// link for every unverified address however it was created.
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{Identity: auth.TableHooks[auth.Identity]{
		// A new address, however it is created (sign-up, add, change, an
		// OAuth link), passes the CheckAddresses checks first. An address
		// value is never updated in place, so creation is the one door.
		BeforeCreate: func(ctx context.Context, _ sqlb.DBTX, row *auth.Identity) error {
			if row.Kind != KindEmail {
				return nil
			}
			return p.checkAddress(ctx, row.Value)
		},
		AfterCreate: func(ctx context.Context, _ sqlb.DBTX, row *auth.Identity) error {
			if row.Kind != KindEmail {
				return nil
			}
			if !row.Verified() {
				return p.sendVerify(ctx, *row)
			}
			if err := p.sendWelcome(ctx, *row); err != nil {
				return err
			}
			if row.IsPrimary {
				return p.copyPrimary(ctx, row.UserID, &row.Value, row.VerifiedAt)
			}
			return p.promoteIfNone(ctx, row.UserID, row.ID)
		},
		AfterUpdate: func(ctx context.Context, _ sqlb.DBTX, old, row *auth.Identity) error {
			// Two updates matter: an address becoming primary, copied to
			// auth_user, and an address becoming verified, which may be the
			// user's first. Anything else changes nothing this plugin keeps.
			if row.Kind != KindEmail || !row.Verified() || (!row.IsPrimary && old.Verified()) {
				return nil
			}
			if row.IsPrimary {
				return p.copyPrimary(ctx, row.UserID, &row.Value, row.VerifiedAt)
			}
			if err := p.sendWelcome(ctx, *row); err != nil {
				return err
			}
			return p.promoteIfNone(ctx, row.UserID, row.ID)
		},
		BeforeDelete: func(ctx context.Context, _ sqlb.DBTX, row *auth.Identity) error {
			if row.Kind != KindEmail || !row.IsPrimary {
				return nil
			}
			return p.copyPrimary(ctx, row.UserID, nil, nil)
		},
	}}
}

func (p *Plugin) copyPrimary(ctx context.Context, userID string, value *string, at *time.Time) error {
	if err := auth.SetUserColumn(ctx, p.core, PluginName, userID, PrimaryEmail, value); err != nil {
		return err
	}
	return auth.SetUserColumn(ctx, p.core, PluginName, userID, EmailVerifiedAt, at)
}

// promoteIfNone makes id primary when the user has no primary address yet, so
// the first verified address is the one messages go to.
func (p *Plugin) promoteIfNone(ctx context.Context, userID, id string) error {
	ids, err := p.core.VerifiedIdentities(ctx, userID, KindEmail)
	if err != nil {
		return err
	}
	for _, idn := range ids {
		if idn.IsPrimary {
			return nil
		}
	}
	_, err = p.core.SetPrimaryIdentity(ctx, userID, id)
	return err
}

// sendVerify mails a verify link, or under VerifyByCode a verify code, for
// an unverified address. A new link spends every earlier verify link of the
// address first, so only the newest mail verifies: a link left in an old
// mail, a forwarded one or one read by whoever had the mailbox before stops
// working the moment the user asks for another. A code rotates on its own
// (see ReuseCodeOnResend). An address another account has verified gets the
// duplicate sign-up notice instead (deliverUnlessTaken).
func (p *Plugin) sendVerify(ctx context.Context, idn auth.Identity) error {
	var msg auth.Message
	if p.byCode {
		code, err := p.issueCode(ctx, CodeKindVerify, PurposeVerifyCode, idn.ID, idn.Value, p.codeTTL)
		if err != nil {
			return err
		}
		msg = auth.Message{Purpose: auth.PurposeVerify, Code: code}
	} else {
		if err := p.core.ConsumeAllVerifications(ctx, PurposeVerifyToken, idn.ID); err != nil {
			return err
		}
		tok, err := p.core.IssueVerification(ctx, PurposeVerifyToken, idn.ID, p.verifyTTL, "")
		if err != nil {
			return err
		}
		msg = auth.Message{Purpose: auth.PurposeVerify, Link: p.links(PurposeVerifyToken, tok)}
	}
	return p.deliverUnlessTaken(ctx, idn, msg)
}

// deliverUnlessTaken mails msg, a verify or confirm link or code for an
// address to, unless another account has already verified that address. Then
// the mailbox owner gets the duplicate sign-up notice instead, as on a
// sign-up with a taken address: a link that could only ever answer
// auth.identity_taken is never sent, and the requester's answer, the writes
// and the one delivery are the same either way, so neither the answer nor its
// timing says the address has an account. The token or code was issued before
// this check on purpose, for that timing; nobody receives it.
func (p *Plugin) deliverUnlessTaken(ctx context.Context, to auth.Identity, msg auth.Message) error {
	owner, err := p.core.FindIdentity(ctx, KindEmail, to.Value, true)
	switch {
	case err == nil && owner.UserID != to.UserID:
		return p.core.Deliver(ctx, owner, auth.Message{Purpose: auth.PurposeSignUpAttempt})
	case err != nil && !errors.Is(err, auth.ErrIdentityNotFound):
		return err
	}
	return p.core.Deliver(ctx, to, msg)
}

// TokenRequest carries a token from a link. The token is never logged: its
// String method redacts it.
type TokenRequest struct {
	Token auth.WireToken `json:"token"`
}

// AddressRequest names one address, as the user typed it; each operation
// normalizes it.
type AddressRequest struct {
	Email string `json:"email"`
	// Metadata travels to the Mailer with the message send-code mails (an
	// invite id, say); other operations ignore it. At most
	// MaxMetadataEntries entries of MaxMetadataLength bytes each.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// RateIdentifier counts per normalized address for ByIdentifier limits, so
// changing the case of an address does not reset its limit.
func (r AddressRequest) RateIdentifier() string { return fold(r.Email) }

// AddressCodeRequest names an address and the code mailed to it, for
// verify-code and confirm-change-code under VerifyByCode.
type AddressCodeRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// RateIdentifier counts guesses per normalized address.
func (r AddressCodeRequest) RateIdentifier() string { return fold(r.Email) }

// CheckCodeRequest names a code to look at without spending it: the kind of
// code, the address it was mailed to, and the code.
type CheckCodeRequest struct {
	Kind  CodeKind `json:"kind"`
	Email string   `json:"email"`
	Code  string   `json:"code"`
}

// RateIdentifier counts peeks per normalized address, in the same budget as
// guesses.
func (r CheckCodeRequest) RateIdentifier() string { return fold(r.Email) }

// VerifyResult is the output of verify and confirm-change: the normalized
// address now verified, which the page can show.
type VerifyResult struct {
	Email string `json:"email"`
	// SignedIn is true when SignInOnVerify started a session for the
	// address's user; SecondFactorRequired then says whether it is pending.
	// Token is for Go callers and bearer transports, never encoded into JSON.
	SignedIn             bool       `json:"signedIn,omitempty"`
	SecondFactorRequired bool       `json:"secondFactorRequired,omitempty"`
	Token                auth.Token `json:"-"`
}

// Address is one row of the list. Verified and Primary are separate because
// an unverified address is listed but can never be primary.
//
//ds:def id=address-rpwjw8k5
type Address struct {
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
	Primary  bool   `json:"primary"`
}

// ListResult is the output of list, in creation order; Addresses is never
// nil, so it encodes as [] rather than null.
type ListResult struct {
	Addresses []Address `json:"addresses"`
}

// Verify spends a verify token and marks its address verified. A token for
// an address removed since is ErrTokenInvalid.
//
//ds:def id=plugin-verify-eyd3s3ph
func (p *Plugin) Verify(ctx context.Context, t auth.Token) (VerifyResult, error) {
	return p.verify.Call(ctx, TokenRequest{Token: t.Wire()})
}

// VerifyCode checks a verify code (VerifyByCode) and marks its address
// verified: the signed-in user's own address, or signed out the address as
// typed. A wrong code, an unknown address and a verified one are all
// auth.ErrCodeInvalid.
//
//ds:def id=plugin-verifycode-3w9kp6rt owner=@khanakia stability=stable
func (p *Plugin) VerifyCode(ctx context.Context, address, code string) (VerifyResult, error) {
	return p.verifyCode.Call(ctx, AddressCodeRequest{Email: address, Code: code})
}

// ConfirmChangeCode checks the code Change mailed to the new address
// (VerifyByCode): the new address becomes the verified primary, and the old
// primary is mailed an undo link.
//
//ds:def id=plugin-confirmchangecode-6z2mv8kq owner=@khanakia stability=stable
func (p *Plugin) ConfirmChangeCode(ctx context.Context, address, code string) (VerifyResult, error) {
	return p.confirmCode.Call(ctx, AddressCodeRequest{Email: address, Code: code})
}

// SetFor gives userID the address, from server-side code with no session: an
// admin plugin's "set email" or "create user". It applies this plugin's own
// rules: the address is normalized; one another user has verified is
// auth.ErrIdentityTaken; one the user already holds is verified and made
// primary when verified is set, and left alone otherwise; without Multiple
// the user's other addresses are replaced, with it the address is added.
// verified creates the address verified and primary at once (the data hooks
// copy it to auth_user); otherwise it is created unverified and the data
// hooks mail the verify link as for any new address. An unknown user is
// auth.ErrUserNotFound. Everything runs in one transaction, or joins the one
// in ctx.
//
// Not an operation: there is no caller to authorize here, the admin plugin
// has done that. From a request, use the operations.
//
//ds:def id=plugin-setfor-9k2mw4rt owner=@khanakia stability=stable
func (p *Plugin) SetFor(ctx context.Context, userID, address string, verified bool) error {
	if p.core == nil {
		return auth.ErrOperationNotWired
	}
	return p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		if _, err := p.core.User(ctx, userID); err != nil {
			return err
		}
		value, err := p.core.Normalize(KindEmail, address)
		if err != nil {
			return err
		}
		owner, err := p.core.FindIdentity(ctx, KindEmail, value, true)
		switch {
		case err == nil && owner.UserID != userID:
			return auth.ErrIdentityTaken
		case err != nil && !errors.Is(err, auth.ErrIdentityNotFound):
			return err
		}
		ids, err := p.emailsOf(ctx, userID)
		if err != nil {
			return err
		}
		for _, idn := range ids {
			if idn.Value != value {
				continue
			}
			if !verified {
				return nil
			}
			if _, err := p.core.VerifyIdentity(ctx, idn.ID); err != nil {
				return err
			}
			_, err := p.core.SetPrimaryIdentity(ctx, userID, idn.ID)
			return err
		}
		if _, err := p.core.CreateIdentity(ctx, auth.NewIdentity{UserID: userID, Kind: KindEmail, Raw: address, Verified: verified, Primary: verified}); err != nil {
			return err
		}
		if p.multiple {
			return nil
		}
		for _, idn := range ids {
			if err := p.core.DeleteIdentity(ctx, userID, idn.ID); err != nil {
				return err
			}
		}
		return nil
	})
}

// CheckCode reports whether a code is right without spending it, so a form
// can validate the code the person typed before asking for what comes next
// (the new password, the new address). A wrong guess still counts an
// attempt, so peeking cannot be used to brute-force; every refusal is
// auth.ErrCodeInvalid.
//
//ds:def id=plugin-checkcode-4v7xm9nq owner=@khanakia stability=stable
func (p *Plugin) CheckCode(ctx context.Context, kind CodeKind, address, code string) error {
	_, err := p.checkCode.Call(ctx, CheckCodeRequest{Kind: kind, Email: address, Code: code})
	return err
}

// Resend sends a new verify link for an unverified address. It answers the
// same for every input, so it reveals no account.
//
//ds:def id=plugin-resend-p773mqmd
func (p *Plugin) Resend(ctx context.Context, address string) error {
	_, err := p.resend.Call(ctx, AddressRequest{Email: address})
	return err
}

// List returns the signed-in user's addresses, verified or not.
//
//ds:def id=plugin-list-xqu67ksd
func (p *Plugin) List(ctx context.Context) ([]Address, error) {
	r, err := p.list.Call(ctx, struct{}{})
	return r.Addresses, err
}

// Add adds an unverified address and sends it a verify link. Adding one the
// user already has is a no-op; without Multiple a second is ErrSingleAddress.
//
//ds:def id=plugin-add-tg8gzc4e
func (p *Plugin) Add(ctx context.Context, address string) error {
	_, err := p.add.Call(ctx, AddressRequest{Email: address})
	return err
}

// MakePrimary makes a verified address the primary one, the address
// messages go to. An unverified one is auth.ErrNotVerified.
//
//ds:def id=plugin-makeprimary-7bpn7cqu
func (p *Plugin) MakePrimary(ctx context.Context, address string) error {
	_, err := p.makePrimary.Call(ctx, AddressRequest{Email: address})
	return err
}

// Remove removes an address, unless it is the last way into the account.
//
//ds:def id=plugin-remove-2wyf2vx8
func (p *Plugin) Remove(ctx context.Context, address string) error {
	_, err := p.remove.Call(ctx, AddressRequest{Email: address})
	return err
}

// Change starts replacing the primary address by mailing a confirm link to
// the new one; nothing changes until ConfirmChange.
//
//ds:def id=plugin-change-scvhtqjv
func (p *Plugin) Change(ctx context.Context, address string) error {
	_, err := p.change.Call(ctx, AddressRequest{Email: address})
	return err
}

// ApproveChange spends an approval token (ApproveChangeFirst) and sends the
// confirm link to the new address.
func (p *Plugin) ApproveChange(ctx context.Context, t auth.Token) error {
	_, err := p.approveChange.Call(ctx, TokenRequest{Token: t.Wire()})
	return err
}

// ApproveChangeCode checks the approval code Change mailed to the signed-in
// user's current address (ApproveChangeFirst with VerifyByCode) for a change
// to address, and sends the confirm code to that new address. A wrong code,
// a code for another address and no pending change are all
// auth.ErrCodeInvalid.
//
//ds:def id=plugin-approvechangecode-4m8xt2qv owner=@khanakia stability=stable
func (p *Plugin) ApproveChangeCode(ctx context.Context, address, code string) error {
	_, err := p.approveCode.Call(ctx, AddressCodeRequest{Email: address, Code: code})
	return err
}

// ConfirmChange spends a change token: the new address becomes the verified
// primary, and the old primary is mailed an undo link.
//
//ds:def id=plugin-confirmchange-nnwjd6cx
func (p *Plugin) ConfirmChange(ctx context.Context, t auth.Token) (VerifyResult, error) {
	return p.confirmChange.Call(ctx, TokenRequest{Token: t.Wire()})
}

// UndoChange spends an undo token: the old address is primary again, the new
// one is removed, and every session of the user ends.
//
//ds:def id=plugin-undochange-dfs5h6pe
func (p *Plugin) UndoChange(ctx context.Context, t auth.Token) error {
	_, err := p.undoChange.Call(ctx, TokenRequest{Token: t.Wire()})
	return err
}

// VerifyLinkRequest is the query of verify-link (VerifyByGET): the token
// and, optionally, the page to land on afterwards.
type VerifyLinkRequest struct {
	Token       auth.WireToken `json:"token"`
	CallbackURL string         `json:"callbackURL,omitempty"`
}

// doVerifyLink is verify over GET: the same verification, then a redirect
// to callbackURL; a failure redirects there too, with the error code. The
// callback is checked before the token is touched, so a bad one spends
// nothing. A failure with no trusted callbackURL lands on
// auth.WithErrorURL's page, and answers JSON only when the app set none.
func (p *Plugin) doVerifyLink(ctx context.Context, c *auth.Call, in VerifyLinkRequest) (VerifyResult, error) {
	// First, so a callbackURL the app does not trust also lands on the
	// app's error page rather than answering JSON to a browser.
	c.RedirectOnError("")
	if in.CallbackURL != "" {
		if !c.Auth.TrustsReturnURL(in.CallbackURL) {
			return VerifyResult{}, ErrCallbackInvalid
		}
		c.RedirectOnError(in.CallbackURL)
	}
	out, err := p.doVerify(ctx, c, TokenRequest{Token: in.Token})
	if err != nil {
		return VerifyResult{}, err
	}
	if in.CallbackURL != "" {
		c.Effects.Redirect(in.CallbackURL)
	}
	return out, nil
}

func (p *Plugin) doVerify(ctx context.Context, c *auth.Call, in TokenRequest) (VerifyResult, error) {
	v, err := c.Auth.ConsumeVerification(ctx, PurposeVerifyToken, in.Token.Token())
	if err != nil {
		return VerifyResult{}, err
	}
	idn, err := c.Auth.VerifyIdentity(ctx, v.Identifier)
	if errors.Is(err, auth.ErrIdentityNotFound) {
		// The address was removed after the link was sent.
		return VerifyResult{}, auth.ErrTokenInvalid
	}
	if err != nil {
		return VerifyResult{}, err
	}
	return p.verified(ctx, c, idn)
}

// verified builds the answer of a verification, starting a session when
// SignInOnVerify asks for one; verify and verify-code share it.
func (p *Plugin) verified(ctx context.Context, c *auth.Call, idn auth.Identity) (VerifyResult, error) {
	out := VerifyResult{Email: idn.Value}
	if p.signInOnVerify {
		sess, tok, err := c.Auth.CreateSession(ctx, idn.UserID, c.Client)
		if err != nil {
			return VerifyResult{}, err
		}
		c.Effects.IssueSessionOf(sess, tok)
		out.SignedIn, out.SecondFactorRequired, out.Token = true, sess.SecondFactorPending, tok
	}
	return out, nil
}

// doCheckCode peeks at a code under the subject its kind uses; see the kinds.
// A kind whose feature is off, an unknown address and a wrong code answer
// alike.
func (p *Plugin) doCheckCode(ctx context.Context, c *auth.Call, in CheckCodeRequest) (auth.Done, error) {
	value, err := c.Auth.Normalize(KindEmail, in.Email)
	if err != nil {
		return auth.Done{}, auth.ErrCodeInvalid
	}
	var purpose auth.Purpose
	var subject string
	switch in.Kind {
	case CodeKindVerify:
		if !p.byCode {
			return auth.Done{}, auth.ErrCodeInvalid
		}
		idn, err := p.codeAddress(ctx, c, value)
		if err != nil {
			return auth.Done{}, err
		}
		purpose, subject = PurposeVerifyCode, idn.ID
	case CodeKindSignIn:
		if !p.SignsIn() {
			return auth.Done{}, auth.ErrCodeInvalid
		}
		purpose, subject = PurposeSignInCode, codeSubject(ctx, value)
	case CodeKindChange:
		if !p.byCode || c.User == nil {
			return auth.Done{}, auth.ErrCodeInvalid
		}
		purpose, subject = PurposeChangeCode, changeSubject(c.User.ID, value)
	case CodeKindApprove:
		if !p.byCode || !p.approveFirst || c.User == nil {
			return auth.Done{}, auth.ErrCodeInvalid
		}
		purpose, subject = PurposeApproveCode, changeSubject(c.User.ID, value)
	default:
		return auth.Done{}, auth.ErrCodeInvalid
	}
	if err := c.Auth.PeekCode(ctx, purpose, subject, in.Code, p.codeTries); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

// codeAddress finds the unverified row a verify code is bound to: the
// signed-in user's own address, or the oldest row for the address typed.
// Every miss is ErrCodeInvalid, so the answer names no account.
func (p *Plugin) codeAddress(ctx context.Context, c *auth.Call, value string) (auth.Identity, error) {
	var idn auth.Identity
	var err error
	if c.User != nil {
		idn, err = p.userAddress(ctx, c.User.ID, value)
	} else {
		idn, err = c.Auth.FindIdentity(ctx, KindEmail, value, false)
	}
	switch {
	case errors.Is(err, auth.ErrIdentityNotFound), errors.Is(err, auth.ErrIdentifierInvalid):
		return auth.Identity{}, auth.ErrCodeInvalid
	case err != nil:
		return auth.Identity{}, err
	case idn.Verified():
		// No open code can exist for a verified row; same answer, no lookup.
		return auth.Identity{}, auth.ErrCodeInvalid
	}
	return idn, nil
}

// doVerifyCode is the code form of verify. The address is looked up first,
// because a code is bound to its row: the signed-in user's own address, or
// the oldest row for the address typed. Every refusal is ErrCodeInvalid, so
// the answer does not say which addresses have accounts.
func (p *Plugin) doVerifyCode(ctx context.Context, c *auth.Call, in AddressCodeRequest) (VerifyResult, error) {
	idn, err := p.codeAddress(ctx, c, in.Email)
	if err != nil {
		return VerifyResult{}, err
	}
	if err := c.Auth.CheckCode(ctx, PurposeVerifyCode, idn.ID, in.Code, p.codeTries); err != nil {
		return VerifyResult{}, err
	}
	idn, err = c.Auth.VerifyIdentity(ctx, idn.ID)
	if err != nil {
		return VerifyResult{}, err
	}
	return p.verified(ctx, c, idn)
}

// doResend always succeeds. It sends only when the address has no verified
// owner — a verified address needs no link, and saying so would tell a
// stranger which addresses have accounts.
func (p *Plugin) doResend(ctx context.Context, c *auth.Call, in AddressRequest) (auth.Done, error) {
	var idn auth.Identity
	var err error
	if c.User != nil {
		idn, err = p.userAddress(ctx, c.User.ID, in.Email)
	} else {
		idn, err = c.Auth.FindIdentity(ctx, KindEmail, in.Email, false)
	}
	switch {
	case errors.Is(err, auth.ErrIdentityNotFound), errors.Is(err, auth.ErrIdentifierInvalid):
		return auth.Done{OK: true}, nil
	case err != nil:
		return auth.Done{}, err
	case idn.Verified():
		return auth.Done{OK: true}, nil
	}
	if err := p.sendVerify(ctx, idn); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

func (p *Plugin) doList(ctx context.Context, c *auth.Call, _ struct{}) (ListResult, error) {
	ids, err := c.Auth.Identities(ctx, c.User.ID)
	if err != nil {
		return ListResult{}, err
	}
	out := ListResult{Addresses: []Address{}}
	for _, idn := range ids {
		if idn.Kind == KindEmail {
			out.Addresses = append(out.Addresses, Address{Email: idn.Value, Verified: idn.Verified(), Primary: idn.IsPrimary})
		}
	}
	return out, nil
}

func (p *Plugin) doAdd(ctx context.Context, c *auth.Call, in AddressRequest) (auth.Done, error) {
	if !p.multiple {
		ids, err := p.emailsOf(ctx, c.User.ID)
		if err != nil {
			return auth.Done{}, err
		}
		if len(ids) > 0 {
			return auth.Done{}, ErrSingleAddress
		}
	}
	switch _, err := p.userAddress(ctx, c.User.ID, in.Email); {
	case err == nil:
		return auth.Done{OK: true}, nil // already there: adding twice is a no-op
	case !errors.Is(err, auth.ErrIdentityNotFound):
		// A failed lookup must not fall through to an insert: it would add a
		// second row for an address the user may already have.
		return auth.Done{}, err
	}
	_, err := c.Auth.CreateIdentity(ctx, auth.NewIdentity{UserID: c.User.ID, Kind: KindEmail, Raw: in.Email})
	if err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

func (p *Plugin) doMakePrimary(ctx context.Context, c *auth.Call, in AddressRequest) (auth.Done, error) {
	idn, err := p.userAddress(ctx, c.User.ID, in.Email)
	if err != nil {
		return auth.Done{}, err
	}
	if _, err := c.Auth.SetPrimaryIdentity(ctx, c.User.ID, idn.ID); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

func (p *Plugin) doRemove(ctx context.Context, c *auth.Call, in AddressRequest) (auth.Done, error) {
	idn, err := p.userAddress(ctx, c.User.ID, in.Email)
	if err != nil {
		return auth.Done{}, err
	}
	if err := c.Auth.DeleteIdentity(ctx, c.User.ID, idn.ID); err != nil {
		return auth.Done{}, err
	}
	if idn.IsPrimary {
		rest, err := c.Auth.VerifiedIdentities(ctx, c.User.ID, KindEmail)
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

// doChange sends a confirm link to the new address. No row exists until the
// link is used, so an address typed by mistake changes nothing. Under
// ReplaceUnverified, a user with no verified address skips that and gets the
// replacement at once (replaceAtOnce).
func (p *Plugin) doChange(ctx context.Context, c *auth.Call, in AddressRequest) (auth.Done, error) {
	value, err := c.Auth.Normalize(KindEmail, in.Email)
	if err != nil {
		return auth.Done{}, err
	}
	// Checked before any mail: the confirm link would otherwise go to an
	// address the write at confirmation is going to refuse.
	if err := p.checkAddress(ctx, value); err != nil {
		return auth.Done{}, err
	}
	if p.replaceUnverified || p.changeUnverified {
		ids, err := p.emailsOf(ctx, c.User.ID)
		if err != nil {
			return auth.Done{}, err
		}
		if p.changeUnverified || !anyVerified(ids) {
			return auth.Done{OK: true}, p.replaceAtOnce(ctx, c, ids, in.Email, value)
		}
	}
	if p.approveFirst {
		current, err := p.verifiedPrimary(ctx, c.User.ID)
		if err != nil {
			return auth.Done{}, err
		}
		if current != nil {
			return auth.Done{OK: true}, p.sendApproval(ctx, *current, value)
		}
	}
	return auth.Done{OK: true}, p.sendConfirm(ctx, c.User.ID, value)
}

// anyVerified reports whether one of the rows is verified.
func anyVerified(ids []auth.Identity) bool {
	for _, idn := range ids {
		if idn.Verified() {
			return true
		}
	}
	return false
}

// replaceAtOnce is the ReplaceUnverified path of a change: ids are the user's
// addresses, none verified. The new address is created unverified, which
// makes the AfterCreate hook mail it the verification, and it takes the place
// of the address being changed: the primary one (the oldest when none is
// marked primary). Only that row goes. Under Multiple the user's other
// unverified addresses stay, since they were added on purpose and a change
// names one address, not all of them. Three cases answer OK and
// differ only in what is mailed: an address the user already has gets the
// verification again; an address another account has verified changes
// nothing and that owner is told, as on a duplicate sign-up; a free address
// is the replacement. The call runs inside the mutation's transaction, so a
// failed insert leaves the old address in place.
func (p *Plugin) replaceAtOnce(ctx context.Context, c *auth.Call, ids []auth.Identity, raw, value string) error {
	for _, idn := range ids {
		if idn.Value == value {
			return p.sendVerify(ctx, idn)
		}
	}
	owner, err := c.Auth.FindIdentity(ctx, KindEmail, value, true)
	switch {
	case err == nil:
		return c.Auth.Deliver(ctx, owner, auth.Message{Purpose: auth.PurposeSignUpAttempt})
	case !errors.Is(err, auth.ErrIdentityNotFound):
		return err
	}
	// Create before delete: the core refuses to remove a user's last way in,
	// and creating the new address as primary moves the flag off the old one.
	replaced := replacedAddress(ids)
	if _, err := c.Auth.CreateIdentity(ctx, auth.NewIdentity{UserID: c.User.ID, Kind: KindEmail, Raw: raw, Primary: replaced == nil || replaced.IsPrimary}); err != nil {
		return err
	}
	if replaced == nil {
		return nil
	}
	return c.Auth.DeleteIdentity(ctx, c.User.ID, replaced.ID)
}

// replacedAddress picks the address a ReplaceUnverified change replaces: the
// primary one, or the oldest (ids come oldest first) when none is primary;
// nil when the user has none.
func replacedAddress(ids []auth.Identity) *auth.Identity {
	for i := range ids {
		if ids[i].IsPrimary {
			return &ids[i]
		}
	}
	if len(ids) == 0 {
		return nil
	}
	return &ids[0]
}

// sendConfirm mails the confirm link to the new address; the change token's
// Meta is the address, so no row exists until the link is used. An address
// another account has verified gets the duplicate sign-up notice instead
// (deliverUnlessTaken). Under
// VerifyByCode it mails a code bound to the user and the address instead.
func (p *Plugin) sendConfirm(ctx context.Context, userID, value string) error {
	to := auth.Identity{UserID: userID, Kind: KindEmail, Value: value}
	if p.byCode {
		code, err := p.issueCode(ctx, CodeKindChange, PurposeChangeCode, changeSubject(userID, value), value, p.codeTTL)
		if err != nil {
			return err
		}
		return p.deliverUnlessTaken(ctx, to, auth.Message{Purpose: auth.PurposeVerify, Code: code})
	}
	tok, err := p.core.IssueVerification(ctx, PurposeChangeToken, userID, p.verifyTTL, value)
	if err != nil {
		return err
	}
	return p.deliverUnlessTaken(ctx, to, auth.Message{Purpose: auth.PurposeVerify, Link: p.links(PurposeChangeToken, tok)})
}

// changeSubject binds a change code to the user and the new address, so a
// code mailed for one address cannot confirm another. The user id is
// length-prefixed so no id and address can combine into another pair's
// subject.
func changeSubject(userID, value string) string {
	return strconv.Itoa(len(userID)) + ":" + userID + value
}

// sendApproval mails the current address an approval link whose token names
// the new address, so approve-change can continue with it. Under
// VerifyByCode it mails a code bound to the user and the new address
// instead, checked at approve-change-code.
func (p *Plugin) sendApproval(ctx context.Context, current auth.Identity, value string) error {
	if p.byCode {
		code, err := p.issueCode(ctx, CodeKindApprove, PurposeApproveCode, changeSubject(current.UserID, value), current.Value, p.codeTTL)
		if err != nil {
			return err
		}
		return p.core.Deliver(ctx, current, auth.Message{
			Purpose:        PurposeChangeApproval,
			Code:           code,
			DefaultSubject: "Approve your email address change",
			DefaultText:    "Someone asked to change the email address of your account to " + value + ". If this was you, enter this code in the app to continue: " + code + "\n\nIf it was not, ignore this email; your address stays as it is.",
		})
	}
	tok, err := p.core.IssueVerification(ctx, PurposeApproveToken, current.UserID, p.verifyTTL, value)
	if err != nil {
		return err
	}
	link := p.links(PurposeApproveToken, tok)
	return p.core.Deliver(ctx, current, auth.Message{
		Purpose:        PurposeChangeApproval,
		Link:           link,
		DefaultSubject: "Approve your email address change",
		DefaultText:    "Someone asked to change the email address of your account to " + value + ". If this was you, open this link to continue:\n\n" + link + "\n\nIf it was not, ignore this email; your address stays as it is.",
	})
}

// verifiedPrimary returns the user's verified primary address, or nil.
func (p *Plugin) verifiedPrimary(ctx context.Context, userID string) (*auth.Identity, error) {
	ids, err := p.emailsOf(ctx, userID)
	if err != nil {
		return nil, err
	}
	for i := range ids {
		if ids[i].IsPrimary && ids[i].Verified() {
			return &ids[i], nil
		}
	}
	return nil, nil
}

// doApproveChange spends an approval token and sends the confirm link to the
// new address it names: the second step of ApproveChangeFirst.
func (p *Plugin) doApproveChange(ctx context.Context, c *auth.Call, in TokenRequest) (auth.Done, error) {
	v, err := c.Auth.ConsumeVerification(ctx, PurposeApproveToken, in.Token.Token())
	if err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, p.sendConfirm(ctx, v.Identifier, v.Meta)
}

// doApproveChangeCode checks the approval code against the signed-in user and
// the new address it was mailed for, then sends the confirm code to the new
// address: the second step of ApproveChangeFirst under VerifyByCode.
func (p *Plugin) doApproveChangeCode(ctx context.Context, c *auth.Call, in AddressCodeRequest) (auth.Done, error) {
	value, err := c.Auth.Normalize(KindEmail, in.Email)
	if err != nil {
		return auth.Done{}, auth.ErrCodeInvalid
	}
	if err := c.Auth.CheckCode(ctx, PurposeApproveCode, changeSubject(c.User.ID, value), in.Code, p.codeTries); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, p.sendConfirm(ctx, c.User.ID, value)
}

// undoSeparator joins the old and new address in an undo token's Meta. A
// newline cannot occur in a valid address.
const undoSeparator = "\n"

// errUndoMalformed is an undo token whose Meta lacks undoSeparator. Only this
// plugin issues undo tokens, so it means a row was written by something else;
// it is an internal error, not a bad link, and is not exported.
var errUndoMalformed = errors.New("email: undo token meta is malformed")

func (p *Plugin) doConfirmChange(ctx context.Context, c *auth.Call, in TokenRequest) (VerifyResult, error) {
	v, err := c.Auth.ConsumeVerification(ctx, PurposeChangeToken, in.Token.Token())
	if err != nil {
		return VerifyResult{}, err
	}
	return p.applyChange(ctx, c, v.Identifier, v.Meta)
}

// doConfirmChangeCode is the code form of confirm-change, for the signed-in
// user: the code was mailed to the new address and bound to this user.
func (p *Plugin) doConfirmChangeCode(ctx context.Context, c *auth.Call, in AddressCodeRequest) (VerifyResult, error) {
	value, err := c.Auth.Normalize(KindEmail, in.Email)
	if err != nil {
		return VerifyResult{}, auth.ErrCodeInvalid
	}
	if err := c.Auth.CheckCode(ctx, PurposeChangeCode, changeSubject(c.User.ID, value), in.Code, p.codeTries); err != nil {
		return VerifyResult{}, err
	}
	return p.applyChange(ctx, c, c.User.ID, value)
}

// applyChange makes newValue the user's verified primary address once a
// confirm link or code proved it, and mails the old primary an undo link.
func (p *Plugin) applyChange(ctx context.Context, c *auth.Call, userID, newValue string) (VerifyResult, error) {
	old, err := p.emailsOf(ctx, userID)
	if err != nil {
		return VerifyResult{}, err
	}
	// Find the old primary in a pass of its own: the rows come in created_at
	// order, and the new address may be listed before the primary one, which
	// in a single pass would send no undo link to the address that needs it.
	var oldPrimary *auth.Identity
	for i := range old {
		if old[i].IsPrimary {
			oldPrimary = &old[i]
		}
	}
	for i := range old {
		if old[i].Value == newValue {
			// The new address is already a row of this user: verify it and
			// make it primary rather than inserting a duplicate.
			if _, err := c.Auth.VerifyIdentity(ctx, old[i].ID); err != nil {
				return VerifyResult{}, err
			}
			if _, err := c.Auth.SetPrimaryIdentity(ctx, userID, old[i].ID); err != nil {
				return VerifyResult{}, err
			}
			return VerifyResult{Email: newValue}, p.sendUndo(ctx, userID, oldPrimary, newValue)
		}
	}
	if _, err := c.Auth.CreateIdentity(ctx, auth.NewIdentity{UserID: userID, Kind: KindEmail, Raw: newValue, Verified: true, Primary: true}); err != nil {
		return VerifyResult{}, err
	}
	if !p.multiple {
		for _, o := range old {
			if err := c.Auth.DeleteIdentity(ctx, userID, o.ID); err != nil {
				return VerifyResult{}, err
			}
		}
	}
	return VerifyResult{Email: newValue}, p.sendUndo(ctx, userID, oldPrimary, newValue)
}

func (p *Plugin) sendUndo(ctx context.Context, userID string, oldPrimary *auth.Identity, newValue string) error {
	if oldPrimary == nil || !oldPrimary.Verified() || oldPrimary.Value == newValue {
		return nil
	}
	tok, err := p.core.IssueVerification(ctx, PurposeUndoToken, userID, p.undoTTL, oldPrimary.Value+undoSeparator+newValue)
	if err != nil {
		return err
	}
	return p.core.Deliver(ctx, *oldPrimary, auth.Message{Purpose: auth.PurposeChanged, Link: p.links(PurposeUndoToken, tok)})
}

// doUndoChange restores the old address as primary, removes the address that
// replaced it, and signs out every session: an undo is the answer to a stolen
// account, and the thief's session must end with it.
func (p *Plugin) doUndoChange(ctx context.Context, c *auth.Call, in TokenRequest) (auth.Done, error) {
	v, err := c.Auth.ConsumeVerification(ctx, PurposeUndoToken, in.Token.Token())
	if err != nil {
		return auth.Done{}, err
	}
	oldValue, newValue, ok := strings.Cut(v.Meta, undoSeparator)
	if !ok {
		return auth.Done{}, errUndoMalformed
	}
	userID := v.Identifier
	restored, err := p.userAddress(ctx, userID, oldValue)
	switch {
	case errors.Is(err, auth.ErrIdentityNotFound):
		restored, err = c.Auth.CreateIdentity(ctx, auth.NewIdentity{UserID: userID, Kind: KindEmail, Raw: oldValue, Verified: true, Primary: true})
		if err != nil {
			return auth.Done{}, err
		}
	case err != nil:
		return auth.Done{}, err
	default:
		if _, err := c.Auth.SetPrimaryIdentity(ctx, userID, restored.ID); err != nil {
			return auth.Done{}, err
		}
	}
	// A failed lookup must fail the undo: reporting success while the
	// replacing address stays would leave the thief a way back in.
	replaced, err := p.userAddress(ctx, userID, newValue)
	switch {
	case errors.Is(err, auth.ErrIdentityNotFound):
	case err != nil:
		return auth.Done{}, err
	case replaced.ID != restored.ID:
		if err := c.Auth.DeleteIdentity(ctx, userID, replaced.ID); err != nil {
			return auth.Done{}, err
		}
	}
	if err := c.Auth.EndUserSessions(ctx, userID, "", auth.SessionEndCredentialChanged); err != nil {
		return auth.Done{}, err
	}
	c.Effects.ClearSession()
	return auth.Done{OK: true}, nil
}

func (p *Plugin) emailsOf(ctx context.Context, userID string) ([]auth.Identity, error) {
	all, err := p.core.Identities(ctx, userID)
	if err != nil {
		return nil, err
	}
	var out []auth.Identity
	for _, idn := range all {
		if idn.Kind == KindEmail {
			out = append(out, idn)
		}
	}
	return out, nil
}

// userAddress finds one of userID's own addresses by what the user typed.
func (p *Plugin) userAddress(ctx context.Context, userID, raw string) (auth.Identity, error) {
	value, err := p.core.Normalize(KindEmail, raw)
	if err != nil {
		return auth.Identity{}, err
	}
	ids, err := p.emailsOf(ctx, userID)
	if err != nil {
		return auth.Identity{}, err
	}
	for _, idn := range ids {
		if idn.Value == value {
			return idn, nil
		}
	}
	return auth.Identity{}, auth.ErrIdentityNotFound
}

// CodeRequest carries an address and the six-digit code mailed to it.
type CodeRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
	// Name and Image are the display name and picture URL for the account a
	// code creates (SignUpWithCode); ignored when the address already has an
	// owner. They are the two profile columns every user has.
	Name  string `json:"name,omitempty"`
	Image string `json:"image,omitempty"`
	// Fields sets other auth_user columns of the account a code creates, only
	// the columns auth.WithSignUpFields names, each of its declared type,
	// else auth.ErrFieldInvalid before the code is checked. The same columns
	// may also be sent as top-level keys; one sent both ways is
	// auth.ErrFieldInvalid. Ignored when the address already has an owner.
	Fields auth.Fields `json:"fields,omitempty"`
	// top holds the top-level keys of a JSON body that are not fields of
	// this struct, for auth.Auth.MergeFields; never set from Go.
	top auth.Fields
}

// RateIdentifier counts guesses per address.
func (r CodeRequest) RateIdentifier() string { return fold(r.Email) }

// UnmarshalJSON keeps the top-level keys that are not the request's own, so
// sign-up fields may sit beside email and code; auth.Auth.MergeFields then
// refuses any that is not a declared column.
func (r *CodeRequest) UnmarshalJSON(data []byte) error {
	type plain CodeRequest
	var p plain
	top, err := auth.SplitBody(data, &p)
	if err != nil {
		return err
	}
	*r = CodeRequest(p)
	r.top = top
	return nil
}

// CodeSignInResult is the output of sign-in-code. Token is for Go callers and
// bearer transports, never encoded into JSON.
//
//ds:def id=codesigninresult-w7mbekyk
type CodeSignInResult struct {
	User                 auth.UserView `json:"user"`
	Created              bool          `json:"created"`
	SecondFactorRequired bool          `json:"secondFactorRequired"`
	Token                auth.Token    `json:"-"`
}

// SendCode mails a sign-in code when the address may receive one, and
// answers the same when it may not.
//
//ds:def id=plugin-sendcode-fym6bpqv
func (p *Plugin) SendCode(ctx context.Context, address string) error {
	_, err := p.sendCode.Call(ctx, AddressRequest{Email: address})
	return err
}

// SendCodeWithMetadata is SendCode with metadata the Mailer receives beside
// the message; see AddressRequest.Metadata.
func (p *Plugin) SendCodeWithMetadata(ctx context.Context, address string, metadata map[string]string) error {
	_, err := p.sendCode.Call(ctx, AddressRequest{Email: address, Metadata: metadata})
	return err
}

// SignInCode checks a sign-in code and starts a session.
//
//ds:def id=plugin-signincode-huj2ynaq
func (p *Plugin) SignInCode(ctx context.Context, address, code string) (CodeSignInResult, error) {
	return p.signInCode.Call(ctx, CodeRequest{Email: address, Code: code})
}

// SignInCodeAs is SignInCode with the display name a new account gets
// (SignUpWithCode); the name is ignored when the address has an owner.
func (p *Plugin) SignInCodeAs(ctx context.Context, address, code, name string) (CodeSignInResult, error) {
	return p.signInCode.Call(ctx, CodeRequest{Email: address, Code: code, Name: name})
}

// SignInCodeWith is SignInCode with the full request: the profile (Name,
// Image) a new account gets under SignUpWithCode.
func (p *Plugin) SignInCodeWith(ctx context.Context, in CodeRequest) (CodeSignInResult, error) {
	return p.signInCode.Call(ctx, in)
}

// codeSubject binds a code to the tenant in ctx and the address, so a code
// sent in one tenant never signs in to another. The tenant is length-prefixed,
// so no tenant id and address can ever combine into another pair's subject;
// a NUL separator would be shorter, and Postgres refuses NUL in text.
func codeSubject(ctx context.Context, value string) string {
	scope, _ := auth.ScopeFrom(ctx)
	return strconv.Itoa(len(scope)) + ":" + scope + value
}

// doSendCode answers the same for every input. It sends to a verified owner's
// address, or with SignUpWithCode to an address nobody has verified; never to
// an unverified row's account.
func (p *Plugin) doSendCode(ctx context.Context, c *auth.Call, in AddressRequest) (auth.Done, error) {
	if err := CheckMetadata(in.Metadata); err != nil {
		return auth.Done{}, err
	}
	value, err := c.Auth.Normalize(KindEmail, in.Email)
	if err != nil {
		return auth.Done{OK: true}, nil
	}
	_, err = c.Auth.FindIdentity(ctx, KindEmail, value, true)
	switch {
	case errors.Is(err, auth.ErrIdentityNotFound):
		if !p.codeUp {
			return auth.Done{OK: true}, nil
		}
	case err != nil:
		return auth.Done{}, err
	}
	code, err := p.issueCode(ctx, CodeKindSignIn, PurposeSignInCode, codeSubject(ctx, value), value, p.codeTTL)
	if err != nil {
		return auth.Done{}, err
	}
	to := auth.Identity{Kind: KindEmail, Value: value}
	return auth.Done{OK: true}, c.Auth.Deliver(ctx, to, auth.Message{Purpose: auth.PurposeSignInCode, Code: code, Metadata: in.Metadata})
}

// doSignInCode spends a code: it signs in the verified owner, or with
// SignUpWithCode creates a user whose address the code verified. A code is one
// factor, so a user with two-factor gets a pending session.
func (p *Plugin) doSignInCode(ctx context.Context, c *auth.Call, in CodeRequest) (CodeSignInResult, error) {
	value, err := c.Auth.Normalize(KindEmail, in.Email)
	if err != nil {
		return CodeSignInResult{}, auth.ErrCodeInvalid
	}
	fields, err := c.Auth.MergeFields(in.Fields, in.top)
	if err != nil {
		return CodeSignInResult{}, err
	}
	if err := c.Auth.CheckFields(fields); err != nil {
		return CodeSignInResult{}, err
	}
	if err := c.Auth.CheckCode(ctx, PurposeSignInCode, codeSubject(ctx, value), in.Code, p.codeTries); err != nil {
		return CodeSignInResult{}, err
	}
	var create *auth.NewUser
	if p.codeUp {
		create = &auth.NewUser{Name: in.Name, Image: in.Image}
	}
	r, err := c.SignInProvenAs(ctx, KindEmail, value, create)
	if errors.Is(err, auth.ErrIdentityNotFound) {
		// The owner went away after the code was sent: the same answer as a
		// wrong code, so it reveals nothing.
		return CodeSignInResult{}, auth.ErrCodeInvalid
	}
	if err != nil {
		return CodeSignInResult{}, err
	}
	if r.Created {
		if err := c.Auth.SetFields(ctx, r.User.ID, fields); err != nil {
			return CodeSignInResult{}, err
		}
	}
	return CodeSignInResult{User: auth.ViewOf(r.User), Created: r.Created, SecondFactorRequired: r.Session.SecondFactorPending, Token: r.Token}, nil
}

// sendWelcome mails the welcome when row is the user's only verified address,
// which is true exactly once: at the first verification.
func (p *Plugin) sendWelcome(ctx context.Context, row auth.Identity) error {
	if !p.welcome {
		return nil
	}
	ids, err := p.core.VerifiedIdentities(ctx, row.UserID, KindEmail)
	if err != nil || len(ids) != 1 {
		return err
	}
	return p.core.Deliver(ctx, row, auth.Message{Purpose: auth.PurposeWelcome})
}
