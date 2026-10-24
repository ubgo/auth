package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// Self-service account deletion: the signed-in user removes their own
// account, with or without a confirmation link, through the pipeline like
// every other feature.

// Account deletion operation ids.
const (
	// EndpointDeleteAccount deletes the signed-in user's account, or sends
	// the confirmation link when WithAccountDeletion asks for one.
	EndpointDeleteAccount EndpointID = "core.account-delete"
	// EndpointConfirmDeleteAccount spends the confirmation link and deletes
	// the account it was issued for.
	EndpointConfirmDeleteAccount EndpointID = "core.account-delete-confirm"
)

// PurposeDeleteAccount is the purpose of the confirmation message a
// delivering plugin sends, and of the verification token in the link. One
// value for both because the token proves exactly what the message asked:
// "delete the account this link was sent for".
//
//ds:def id=purposedeleteaccount-4m2kq9ef owner=@khanakia stability=stable
const PurposeDeleteAccount Purpose = "delete_account"

// DefaultDeleteAccountTTL is how long a confirmation link works. An hour
// covers a mailbox that is slow to receive and short enough that a link
// forgotten in an inbox cannot delete the account days later.
//
//ds:def id=defaultdeleteaccountttl-9h3nxrwe owner=@khanakia stability=stable
const DefaultDeleteAccountTTL = time.Hour

// DefaultDeleteAccountPage is the path of the app's page a confirmation link
// opens when AccountDeletion.Link is nil: BaseURL + this + "?token=…". The
// page posts the token to /account/delete/confirm.
//
//ds:def id=defaultdeleteaccountpage-6tz8vpqk owner=@khanakia stability=stable
const DefaultDeleteAccountPage = "/account/delete"

// Wording of the confirmation message, carried in Message.DefaultSubject and
// DefaultText so a delivering plugin that knows no template for the purpose
// still sends something that makes sense; an app's own templates win.
const (
	deleteAccountSubject = "Confirm deleting your account"
	deleteAccountText    = "Open this link to delete your account. It works once, for a limited time:\n\n%s\n\nIf you did not ask for this, ignore this message. Your account stays as it is."
)

// AccountDeletion configures the self-service deletion operations, which
// exist only when WithAccountDeletion is given: deleting an account is a
// decision an app makes on purpose, and a route that appeared in every
// existing deployment would not be one.
//
// With the zero value, POST /account/delete deletes the account at once: the
// call already needs a FreshSignIn session, which is the same proof a
// password change needs. ConfirmByLink adds a second step for apps whose
// users mostly sign in through a provider and hold no password: the call
// sends a link to the user's recovery channel instead, and the account is
// deleted when the link is spent.
//
//ds:def id=core-accountdeletion-7wq2xn5p owner=@khanakia stability=stable
type AccountDeletion struct {
	// ConfirmByLink makes /account/delete send a confirmation link rather
	// than delete; /account/delete/confirm then deletes. The user needs a
	// verified recovery identity, or the call answers ErrNoRecoveryChannel.
	ConfirmByLink bool
	// LinkTTL is how long the link works; zero means DefaultDeleteAccountTTL.
	LinkTTL time.Duration
	// Link builds the URL the message carries from the token. Nil means
	// BaseURL + DefaultDeleteAccountPage + "?token=…"; New refuses
	// ConfirmByLink with neither a Link nor a BaseURL, since no link could
	// be built.
	Link func(t Token) string
}

// WithAccountDeletion turns self-service deletion on and configures it; see
// AccountDeletion. Without it the two routes do not exist and DeleteAccount
// answers ErrAccountDeletionOff; auth.WithAccountDeletion(auth.AccountDeletion{})
// is the plain form, deleting at once.
//
//ds:def id=opt-withaccountdeletion-3kd8rz2m owner=@khanakia stability=stable
func WithAccountDeletion(d AccountDeletion) Option {
	return func(s *settings) { s.accountDeletion, s.accountDeletionOn = d, true }
}

// ErrAccountDeletionOff is answered by DeleteAccount and ConfirmDeleteAccount
// when WithAccountDeletion was not given: the feature is off, which is the
// default, not a wiring mistake.
var ErrAccountDeletionOff = errors.New("auth: account deletion is off; pass auth.WithAccountDeletion")

// WithDataHooks registers data hooks from the app itself, without writing a
// plugin: a BeforeDelete on User removes the app's own rows that reference
// the user inside the deleting transaction, or refuses the deletion with an
// error (an open subscription, an owner of a shared workspace). They run
// after every plugin's hooks, in the order given.
//
//ds:def id=opt-withdatahooks-8pf4ym6n owner=@khanakia stability=stable
func WithDataHooks(h ...DataHooks) Option {
	return func(s *settings) { s.dataHooks = append(s.dataHooks, h...) }
}

// WithOperationHooks registers operation hooks from the app itself: a Before
// hook on EndpointDeleteAccount refuses self-service deletion for some users
// while an admin can still delete them, an After hook on a sign-in records
// it. The same rules as a plugin's hooks apply: a Match that names an
// operation nothing registered fails New, and an error from a hook fails the
// call and drops its effects.
//
//ds:def id=opt-withoperationhooks-5vn9qw3c owner=@khanakia stability=stable
func WithOperationHooks(h ...OperationHook) Option {
	return func(s *settings) { s.opHooks = append(s.opHooks, h...) }
}

// ErrDeleteAccountNeedsLink is returned by New when AccountDeletion asks for
// a confirmation link and neither a Link function nor a BaseURL exists to
// build one from.
var ErrDeleteAccountNeedsLink = errors.New("auth: account deletion by link needs auth.WithBaseURL or AccountDeletion.Link")

// DeleteAccountResult is the output of core.account-delete. Exactly one of
// the two fields is true.
type DeleteAccountResult struct {
	// Deleted is true when the account is gone; the session is cleared.
	Deleted bool `json:"deleted"`
	// ConfirmationSent is true when a link went out instead
	// (AccountDeletion.ConfirmByLink); the account exists until it is spent.
	ConfirmationSent bool `json:"confirmationSent"`
}

// ConfirmDeleteAccountRequest is the input of core.account-delete-confirm.
type ConfirmDeleteAccountRequest struct {
	Token WireToken `json:"token"`
}

// resolveAccountDeletion settles the deletion settings at New: the TTL
// default, and that a link can be built when one is asked for; the link
// itself is built per call (deleteAccountLink).
func (a *Auth) resolveAccountDeletion(d AccountDeletion, on bool) error {
	a.accountDeletionOn = on
	if !on {
		return nil
	}
	if d.LinkTTL <= 0 {
		d.LinkTTL = DefaultDeleteAccountTTL
	}
	if d.ConfirmByLink && d.Link == nil && a.cfg.BaseURL == "" {
		return ErrDeleteAccountNeedsLink
	}
	a.accountDeletion = d
	return nil
}

// deleteAccountLink builds the confirmation link: the app's builder, or the
// default page under BaseURL(ctx), so a user on an allowed host gets a link
// to that host.
func (a *Auth) deleteAccountLink(ctx context.Context, t Token) string {
	if a.accountDeletion.Link != nil {
		return a.accountDeletion.Link(t)
	}
	return a.BaseURL(ctx) + DefaultDeleteAccountPage + "?token=" + url.QueryEscape(t.Reveal())
}

// deleteAccount is the body of core.account-delete: delete now, or send the
// link when configured. The call's session is forgotten either way the
// account goes, so a cache cannot keep answering for a deleted user.
func (a *Auth) deleteAccount(ctx context.Context, c *Call) (DeleteAccountResult, error) {
	if a.accountDeletion.ConfirmByLink {
		tok, err := a.IssueVerification(ctx, PurposeDeleteAccount, c.User.ID, a.accountDeletion.LinkTTL, "")
		if err != nil {
			return DeleteAccountResult{}, err
		}
		link := a.deleteAccountLink(ctx, tok)
		m := Message{Purpose: PurposeDeleteAccount, Link: link, DefaultSubject: deleteAccountSubject, DefaultText: fmt.Sprintf(deleteAccountText, link)}
		if err := a.DeliverRecovery(ctx, c.User.ID, m); err != nil {
			return DeleteAccountResult{}, err
		}
		return DeleteAccountResult{ConfirmationSent: true}, nil
	}
	if err := a.deleteUserOfCall(ctx, c, c.User.ID); err != nil {
		return DeleteAccountResult{}, err
	}
	return DeleteAccountResult{Deleted: true}, nil
}

// confirmDeleteAccount spends the link's token and deletes the account it
// names. A wrong, spent or expired token is ErrTokenInvalid, all alike. The
// caller may be signed out (the link was opened in another browser) or
// signed in as that user; in the second case their session is cleared too.
func (a *Auth) confirmDeleteAccount(ctx context.Context, c *Call, in ConfirmDeleteAccountRequest) (Done, error) {
	v, err := a.ConsumeVerification(ctx, PurposeDeleteAccount, in.Token.Token())
	if err != nil {
		return Done{}, err
	}
	if err := a.deleteUserOfCall(ctx, c, v.Identifier); err != nil {
		return Done{}, err
	}
	return Done{OK: true}, nil
}

// deleteUserOfCall deletes userID and, when the call's own session belongs
// to that user, drops it from the cache and asks the transport to clear it.
func (a *Auth) deleteUserOfCall(ctx context.Context, c *Call, userID string) error {
	if err := a.DeleteUser(ctx, userID); err != nil {
		return err
	}
	if c.Session != nil && c.Session.UserID == userID {
		if err := a.forgetSession(ctx, c); err != nil {
			return err
		}
		c.Effects.ClearSession()
	}
	return nil
}

// DeleteAccount deletes the signed-in user's account, or sends the
// confirmation link when configured, through the same operation POST
// /account/delete runs. The request in ctx must hold a fresh session.
func (a *Auth) DeleteAccount(ctx context.Context) (DeleteAccountResult, error) {
	if !a.accountDeletionOn {
		return DeleteAccountResult{}, ErrAccountDeletionOff
	}
	return a.core.deleteAccount.Call(ctx, struct{}{})
}

// ConfirmDeleteAccount spends a confirmation link's token and deletes the
// account, through the same operation POST /account/delete/confirm runs.
func (a *Auth) ConfirmDeleteAccount(ctx context.Context, t Token) error {
	if !a.accountDeletionOn {
		return ErrAccountDeletionOff
	}
	_, err := a.core.confirmDelete.Call(ctx, ConfirmDeleteAccountRequest{Token: t.Wire()})
	return err
}
