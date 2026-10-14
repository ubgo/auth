// Package chat is an identifier plugin written outside the library: a chat
// handle (think a messaging app's @name) that a user adds to their account,
// proves with a code the plugin sends through the app's chat bot, and can
// then receive messages through, including password reset links when the
// handle is a recovery channel.
//
// It shows the two things an identifier plugin is: an IdentifierProvider
// that registers a kind, and a Deliverer that sends a Message to one of
// that kind's identities. It uses only exported API, so a plugin in your own
// repository can do everything it does.
package chat

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ubgo/auth"
)

// Names the plugin registers. PluginName is the route prefix; KindChat is
// written to auth_identity.kind, so both are fixed once deployed.
const (
	PluginName                         = "chat"
	KindChat   auth.IdentifierKindName = "chat"
	// PurposeVerifyCode is the code table's purpose for a handle's verify
	// code; it is this plugin's own, so no other plugin's codes can match.
	PurposeVerifyCode auth.Purpose    = "chat.verify"
	EndpointAdd       auth.EndpointID = "chat.add"
	EndpointVerify    auth.EndpointID = "chat.verify"
	// DefaultCodeTTL is how long a verify code works.
	DefaultCodeTTL = 10 * time.Minute
)

// Handle shape: letters, digits and underscores, 3 to 32 characters, after
// the leading "@" is dropped and case is folded.
const (
	minHandleLength = 3
	maxHandleLength = 32
)

// handlePattern is the stored form of a handle.
var handlePattern = regexp.MustCompile(`^[a-z0-9_]+$`)

// Errors this plugin answers; each is safe to show.
var (
	// ErrHasHandle: the account already has a handle. Verify or remove it.
	ErrHasHandle = auth.NewError("chat.has_handle", http.StatusConflict, "This account already has a chat handle.")
	// ErrNoSender is returned by Validate when New was given no Sender.
	ErrNoSender = errors.New("chat: a Sender is required; pass chat.New(sender)")
)

// Sender delivers a text to a handle. The app implements it over its chat
// platform's bot API; the example prints to the log.
//
//ds:def id=sender-x3m9kf4p
type Sender interface {
	Send(ctx context.Context, handle, text string) error
}

// SenderFunc adapts a function to Sender.
type SenderFunc func(ctx context.Context, handle, text string) error

// Send calls f.
func (f SenderFunc) Send(ctx context.Context, handle, text string) error { return f(ctx, handle, text) }

// Template renders a message to the text the bot sends. It must include
// m.Code or m.Link when the message carries one.
type Template func(m auth.Message) string

// Plugin is the chat identifier plugin. Build it with New.
type Plugin struct {
	kind      auth.IdentifierKind
	sender    Sender
	template  Template
	localized map[string]Template
	codeTTL   time.Duration
	core      *auth.Auth

	add    *auth.Op[HandleRequest, auth.Done]
	verify *auth.Op[CodeRequest, auth.Done]
}

// The optional interfaces this plugin implements, checked by the compiler.
//
//ds:def id=chat-t75jv2w3
var (
	_ auth.IdentifierProvider = (*Plugin)(nil)
	_ auth.Deliverer          = (*Plugin)(nil)
	_ auth.Initializer        = (*Plugin)(nil)
	_ auth.Validator          = (*Plugin)(nil)
	_ auth.OperationProvider  = (*Plugin)(nil)
)

// Option configures the plugin.
type Option func(*Plugin)

// Login lets a handle sign in (another plugin does the signing in; this one
// only makes the kind eligible). It implies Unique.
func Login() Option { return kindOpt(auth.Login()) }

// Recover lets a verified handle receive account-recovery messages, such as
// a password reset link. It implies Unique.
func Recover() Option { return kindOpt(auth.Recover()) }

// Contact makes the handle contact information only: several accounts may
// share one, it cannot sign in and receives no recovery messages.
func Contact() Option { return kindOpt(auth.Contact()) }

// Templates replaces the English wording for every purpose.
func Templates(t Template) Option { return func(p *Plugin) { p.template = t } }

// TemplatesByLocale adds translations, picked by auth.PickLocale from the
// message's Locale; a language without one falls back to Templates.
//
//ds:def id=templatesbylocale-t8qpcv56
func TemplatesByLocale(byLocale map[string]Template) Option {
	return func(p *Plugin) { p.localized = byLocale }
}

// WithCodeTTL changes how long a verify code works.
func WithCodeTTL(d time.Duration) Option { return func(p *Plugin) { p.codeTTL = d } }

func kindOpt(o auth.KindOption) Option { return func(p *Plugin) { p.kind = auth.ApplyKind(p.kind, o) } }

// New builds the plugin. The kind starts Verifiable, because a handle is
// proven by a code, and unique among verified rows only, so a stranger's
// unverified claim on a handle blocks nobody; the options add Login, Recover
// or Contact.
//
//ds:def id=new-g7rzgcyw
func New(sender Sender, opts ...Option) *Plugin {
	p := &Plugin{
		kind: auth.IdentifierKind{
			Name: KindChat, Verifiable: true, UniqueOnlyVerified: true,
			Normalize: Normalize, Validate: Validate,
		},
		sender:   sender,
		template: DefaultTemplate,
		codeTTL:  DefaultCodeTTL,
	}
	for _, o := range opts {
		o(p)
	}
	p.add = auth.Define(auth.OpInfo{ID: EndpointAdd, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/add"}, p.doAdd)
	p.verify = auth.Define(auth.OpInfo{ID: EndpointVerify, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/verify"}, p.doVerify)
	return p
}

// Name is the only method every plugin must have.
func (p *Plugin) Name() string { return PluginName }

// Identifiers registers the chat kind. From here on the core owns its
// uniqueness, its normalization and its verified checks.
//
//ds:def id=plugin-identifiers-kut9xkpf
func (p *Plugin) Identifiers() []auth.IdentifierKind { return []auth.IdentifierKind{p.kind} }

// Validate refuses a plugin that could never deliver.
//
//ds:def id=plugin-validate-p9znvk22
func (p *Plugin) Validate(*auth.Config) error {
	if p.sender == nil {
		return ErrNoSender
	}
	return nil
}

// Init keeps the core handle for codes, identities and delivery.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	return nil
}

// Operations lists the routes: POST /auth/chat/add and /auth/chat/verify.
func (p *Plugin) Operations() []auth.Operation { return []auth.Operation{p.add, p.verify} }

// Normalize is the one folding rule: drop a leading "@", trim, lower-case.
// Every lookup, comparison and index uses its result.
//
//ds:def id=normalize-e6x287z7
func Normalize(raw string) (string, error) {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(raw), "@")), nil
}

// Validate refuses a normalized handle of the wrong shape.
//
//ds:def id=validate-gd6ab33z
func Validate(v string) error {
	if len(v) < minHandleLength || len(v) > maxHandleLength || !handlePattern.MatchString(v) {
		return fmt.Errorf("%w: a chat handle is %d to %d letters, digits or underscores", auth.ErrIdentifierInvalid, minHandleLength, maxHandleLength)
	}
	return nil
}

// DefaultTemplate is the English wording. The last case is where another
// plugin's own purpose lands: the sender's DefaultText, if it gave one, else
// the bare link.
//
//ds:def id=defaulttemplate-u22n35bb
func DefaultTemplate(m auth.Message) string {
	switch m.Purpose {
	case auth.PurposeVerify:
		return "Your verification code is " + m.Code + "."
	case auth.PurposeReset:
		return "Reset your password here: " + m.Link
	case auth.PurposeSignUpAttempt:
		return "Someone tried to sign up with your chat handle. If it was not you, nothing happens."
	default:
		if m.DefaultText != "" {
			return m.DefaultText
		}
		return m.Link
	}
}

// Deliver sends m to a handle through the Sender. The core calls it after the
// transaction that asked for the message commits, in the background.
//
//ds:def id=plugin-deliver-z6sjdm2a
func (p *Plugin) Deliver(ctx context.Context, to auth.Identity, m auth.Message) error {
	render := p.template
	if t, ok := auth.PickLocale(p.localized, m.Locale); ok {
		render = t
	}
	return p.sender.Send(ctx, to.Value, render(m))
}

// HandleRequest names a handle.
type HandleRequest struct {
	Handle string `json:"handle"`
}

// RateIdentifier counts per normalized handle for ByIdentifier rate rules.
func (r HandleRequest) RateIdentifier() string { h, _ := Normalize(r.Handle); return h }

// CodeRequest carries the code sent to a handle.
type CodeRequest struct {
	Handle string `json:"handle"`
	Code   string `json:"code"`
}

// Add stores an unverified handle on the signed-in account and sends it a
// code, through the same operation the HTTP route runs.
func (p *Plugin) Add(ctx context.Context, handle string) error {
	_, err := p.add.Call(ctx, HandleRequest{Handle: handle})
	return err
}

// Verify spends the code and marks the handle verified and primary.
func (p *Plugin) Verify(ctx context.Context, handle, code string) error {
	_, err := p.verify.Call(ctx, CodeRequest{Handle: handle, Code: code})
	return err
}

//ds:def id=plugin-doadd-vt2w5p5s
func (p *Plugin) doAdd(ctx context.Context, c *auth.Call, in HandleRequest) (auth.Done, error) {
	switch _, err := p.userHandle(ctx, c.User.ID, ""); {
	case err == nil:
		return auth.Done{}, ErrHasHandle
	case !errors.Is(err, auth.ErrIdentityNotFound):
		// A failed lookup must not fall through to an insert, or a user
		// could end up with two handles.
		return auth.Done{}, err
	}
	idn, err := c.Auth.CreateIdentity(ctx, auth.NewIdentity{UserID: c.User.ID, Kind: KindChat, Raw: in.Handle})
	if err != nil {
		return auth.Done{}, err
	}
	code, err := c.Auth.IssueCode(ctx, PurposeVerifyCode, idn.ID, p.codeTTL)
	if err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, c.Auth.Deliver(ctx, idn, auth.Message{Purpose: auth.PurposeVerify, Code: code})
}

//ds:def id=plugin-doverify-29u2jhtd
func (p *Plugin) doVerify(ctx context.Context, c *auth.Call, in CodeRequest) (auth.Done, error) {
	idn, err := p.userHandle(ctx, c.User.ID, in.Handle)
	if errors.Is(err, auth.ErrIdentityNotFound) || errors.Is(err, auth.ErrIdentifierInvalid) {
		return auth.Done{}, auth.ErrCodeInvalid // a handle the user never added gets the same answer as a wrong code
	}
	if err != nil {
		return auth.Done{}, err
	}
	if err := c.Auth.CheckCode(ctx, PurposeVerifyCode, idn.ID, in.Code, auth.DefaultCodeMaxAttempts); err != nil {
		return auth.Done{}, err
	}
	if _, err := c.Auth.VerifyIdentity(ctx, idn.ID); err != nil {
		return auth.Done{}, err
	}
	if _, err := c.Auth.SetPrimaryIdentity(ctx, c.User.ID, idn.ID); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

// userHandle returns the user's chat identity, or the one with raw's value
// when raw is set, or auth.ErrIdentityNotFound.
func (p *Plugin) userHandle(ctx context.Context, userID, raw string) (auth.Identity, error) {
	want := ""
	if raw != "" {
		v, err := p.core.Normalize(KindChat, raw)
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
		if idn.Kind == KindChat && (want == "" || idn.Value == want) {
			return idn, nil
		}
	}
	return auth.Identity{}, auth.ErrIdentityNotFound
}
