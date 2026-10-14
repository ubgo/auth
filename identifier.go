package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// IdentifierKind is the policy for one way of naming a user. Identifier plugins
// build one and return it from Identifiers; the core stores every kind in the
// one auth_identity table and applies these rules to all of them the same way.
//
// Why uniqueness is policy and not schema: whether an email must be unique is a
// product decision. A phone-first app may let a family share an address; a
// developer tool may allow many addresses per account. Neither fits a fixed
// UNIQUE column.
//
// Invariant: a kind that signs in or recovers must be unique, and a unique kind
// must have a normalizer. New refuses anything else, because each violation is
// a deployment that is broken in a way nobody notices until a user is stuck.
type IdentifierKind struct {
	// Name is written to auth_identity.kind and to generated index names, so
	// it must match KindNamePattern.
	Name IdentifierKindName

	// Unique requests a unique index over the normalized value, among rows of
	// this kind.
	Unique bool

	// UniqueOnlyVerified narrows that index to verified rows. It is the right
	// setting for anything a stranger can type: an unverified claim then
	// grants nothing and blocks nobody.
	UniqueOnlyVerified bool

	// ScopedByTenant makes uniqueness hold per scope_id instead of globally.
	ScopedByTenant bool

	// CanLogin allows this kind in a sign-in lookup.
	CanLogin bool

	// CanRecover allows this kind to receive account-recovery messages. The
	// plugin that registers it must implement Deliverer.
	CanRecover bool

	// Verifiable means the kind has a proof-of-control flow. A handle has none.
	Verifiable bool

	// RequireVerified refuses a sign-in through an unverified identity of
	// this kind. Sign-in methods check it after the credential, so the
	// refusal reveals nothing to a caller who does not know the password.
	RequireVerified bool

	// Normalize converts input to the one form that is stored and compared.
	Normalize func(raw string) (string, error)

	// Validate rejects a normalized value that is malformed. Optional.
	Validate func(normalized string) error
}

// KindNamePattern is what a kind name may look like. It is strict because the
// name is embedded in generated DDL: a unique index WHERE clause and, on
// MySQL, a generated column name.
var KindNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// KindOption adjusts an IdentifierKind. Identifier plugins wrap these in their
// own option types, so every plugin offers the same words: Login, Recover,
// Contact.
type KindOption func(*IdentifierKind)

// Login allows the kind in sign-in, which implies Unique.
func Login() KindOption { return func(k *IdentifierKind) { k.CanLogin, k.Unique = true, true } }

// Recover allows the kind to receive recovery messages, which implies Unique.
func Recover() KindOption { return func(k *IdentifierKind) { k.CanRecover, k.Unique = true, true } }

// Unique requests a unique index without making the kind a sign-in method.
func Unique() KindOption { return func(k *IdentifierKind) { k.Unique = true } }

// Contact makes the kind contact information only: not unique, no sign-in, no
// recovery. It is a named option because "several users may share this" is a
// real product shape and should read as a choice, not an omission.
func Contact() KindOption {
	return func(k *IdentifierKind) { k.Unique, k.CanLogin, k.CanRecover = false, false, false }
}

// ScopedByTenant makes uniqueness per tenant: the same value may belong to
// one account in each tenant, and every create and lookup of the kind then
// needs a tenant in ctx (WithScope), or fails with ErrNoScope.
func ScopedByTenant() KindOption { return func(k *IdentifierKind) { k.ScopedByTenant = true } }

// ApplyKind runs options over a base kind. Plugins call it from their
// constructors.
func ApplyKind(k IdentifierKind, opts ...KindOption) IdentifierKind {
	for _, o := range opts {
		o(&k)
	}
	return k
}

// validateKind checks one kind on its own.
func validateKind(k IdentifierKind) error {
	switch {
	case !KindNamePattern.MatchString(string(k.Name)):
		return fmt.Errorf("%w: kind name %q must match %s", ErrBadIdentifier, k.Name, KindNamePattern)
	case len(k.Name) > maxKindNameLength:
		return fmt.Errorf("%w: kind name %q is longer than %d characters, so its index name would not fit an SQL identifier", ErrBadIdentifier, k.Name, maxKindNameLength)
	case k.CanLogin && !k.Unique:
		return fmt.Errorf("%w: kind %q", ErrNonUniqueLogin, k.Name)
	case k.CanRecover && !k.Unique:
		return fmt.Errorf("%w: kind %q may recover but is not unique", ErrNonUniqueLogin, k.Name)
	case k.Normalize == nil:
		return fmt.Errorf("%w: kind %q", ErrNoNormalizer, k.Name)
	case k.RequireVerified && !k.Verifiable:
		return fmt.Errorf("%w: kind %q requires verification but has no verification flow", ErrBadIdentifier, k.Name)
	case k.CanRecover && !k.Verifiable:
		return fmt.Errorf("%w: kind %q may recover but has no verification flow", ErrBadIdentifier, k.Name)
	}
	return nil
}

// IdentifierProvider is implemented by a plugin that registers identifier
// kinds: email, phone, username.
type IdentifierProvider interface {
	Identifiers() []IdentifierKind
}

// Message is something the core or a plugin asks an identifier plugin to send
// to one of its identities.
type Message struct {
	// Purpose says what the message is for; the delivering plugin picks its
	// template by it.
	Purpose Purpose
	// Link is a URL the recipient opens, such as a verify or reset link.
	// Empty for messages that carry only a code or only information.
	Link string
	// Code is a short code to type in, for channels such as SMS. Optional.
	Code string
	// Locale is the recipient's language as a BCP 47 tag, or "" for the
	// default. Deliver fills it from the request when the sender left it
	// empty; templates pick their language by it.
	Locale string
	// DefaultSubject and DefaultText are the sending plugin's own English
	// wording for a Purpose of its own, which the delivering plugin's default
	// templates cannot know: the delivering plugin cannot import the sender
	// (organization imports email, not the reverse). A delivering plugin uses
	// them only in its fallback case, so an app's own templates still win.
	// With only DefaultText set, the subject stays the delivering plugin's
	// generic one ("A message about your account" for email); an SMS uses
	// DefaultText alone. Empty for the core's purposes, which every
	// delivering plugin words itself.
	DefaultSubject string
	DefaultText    string
	// Metadata is free per-message data the sending operation attaches (an
	// invitation id, a campaign) for the app's own sender to read; the core
	// never reads it, and the delivering plugin passes it through. The
	// sending plugin bounds its size.
	Metadata map[string]string
	// Data is a typed payload whose type the Purpose's sending plugin
	// documents (organization.InvitationData for an invitation), for an
	// app template to read with a type assertion: better-auth's type-safe
	// template variables. The core never reads it and never logs it; the
	// delivering plugin passes it through. It is `any` because each
	// Purpose has its own type and the core cannot name the sender's; the
	// sender's MessageDataDecoder restores that type when the message goes
	// through WithDeliveryOutbox, and a message whose Data no registered
	// plugin decodes is refused there rather than delivered without it.
	Data any `json:"-"`
}

// MessageDataDecoder is a plugin that sends messages with Message.Data and
// can restore that Data's type from JSON, which WithDeliveryOutbox needs: a
// queued message is stored as JSON, and without its decoder the Data would
// come back as a map the template's type assertion rejects. It answers
// (nil, nil) for a Purpose that is not its own.
//
//ds:def id=core-messagedatadecoder-5wq8nk3x owner=@khanakia stability=stable
type MessageDataDecoder interface {
	DecodeMessageData(p Purpose, raw json.RawMessage) (any, error)
}

// ErrMessageDataUndecodable is a Message.Data the delivery outbox cannot
// store: no registered MessageDataDecoder restores it for its Purpose, or
// it does not encode as JSON. Refusing at enqueue keeps the sending
// operation from succeeding while the template silently loses its data.
var ErrMessageDataUndecodable = errors.New("auth: message data cannot be queued: no plugin decodes it for its purpose")

// Message purposes. A delivering plugin picks its template by these; a plugin
// with a message of its own declares its own Purpose beside them.
const (
	// PurposeVerify carries a link or code that proves control of an
	// identity.
	//ds:def id=core-purposes-wkjp4y8h owner=@khanakia stability=stable
	PurposeVerify Purpose = "verify"
	// PurposeReset carries a password reset link.
	PurposeReset Purpose = "reset"
	// PurposeSignUpAttempt tells the owner of a verified identity that
	// someone tried to sign up with it. It carries no link.
	PurposeSignUpAttempt Purpose = "sign_up_attempt"
	// PurposeChanged tells the old owner of an identifier that it was
	// replaced, with an undo link.
	PurposeChanged Purpose = "changed"
	// PurposeSignInCode carries a one-time sign-in code.
	PurposeSignInCode Purpose = "sign_in_code"
	// PurposeSignInLink carries a one-time sign-in link.
	PurposeSignInLink Purpose = "sign_in_link"
	// PurposeWelcome greets a new user once their first address is proven.
	//ds:def id=purposewelcome-addygcmp owner=@khanakia stability=stable
	PurposeWelcome Purpose = "welcome"
)

// Deliverer is implemented by an identifier plugin that can send a message to
// one of its identities. A kind with CanRecover must come from a Deliverer.
type Deliverer interface {
	Deliver(ctx context.Context, to Identity, m Message) error
}
