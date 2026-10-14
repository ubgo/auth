package twofactor

import (
	"context"
	"errors"
	"net/http"

	"github.com/ubgo/auth"
)

// Step-up checks and the password guard: the better-auth shapes that ask the
// signed-in user to prove themselves again. check verifies a code without
// touching the session (better-auth's verify on a signed-in session),
// totp-uri reads the authenticator URI back behind the password and a fresh
// sign-in (better-auth's get-totp-uri), and RequirePassword puts the password
// in front of the settings operations as better-auth's enable, disable and
// generate-backup-codes do.

// Errors of the step-up operations.
var (
	// ErrNotTOTP: totp-uri was asked for a factor that is not an
	// authenticator app; a delivered-code factor has no URI.
	ErrNotTOTP = auth.NewError("twofactor.not_totp", http.StatusConflict, "Your second factor is not an authenticator app.")
	// ErrTrustNeedsSession: verify was asked to trust the device and to leave
	// the session pending in one call. A device is trusted for a sign-in, so
	// the pair is refused rather than half done.
	ErrTrustNeedsSession = auth.NewError("twofactor.trust_needs_session", http.StatusBadRequest, "A device can only be remembered when signing in.")
)

// PasswordChecker is what the plugin needs from a password plugin to ask for
// the user's password, as better-auth does: the two methods
// `*password.Plugin` already has. Found through auth.PluginOf at Init, so
// this package imports no other module and an app registers nothing extra.
// Verify runs the password plugin's own operation, with its rate limit and
// its enumeration-safe timing.
type PasswordChecker interface {
	auth.Plugin
	HasPassword(ctx context.Context, userID string) (bool, error)
	Verify(ctx context.Context, password auth.Token) error
}

// RequirePassword makes enroll, disable, recovery-codes and
// view-recovery-codes ask for the password of a user who has one, on top of
// the fresh sign-in they already need: better-auth's password field on
// enable, disable and generate-backup-codes. A user without a password (a
// passkey or social sign-in) passes on the fresh session alone, which is
// better-auth's allowPasswordless; better-auth's default, refusing such a
// user outright, is not offered, because it would keep exactly the users
// with no password from turning a second factor on. Off by default: the
// fresh session is the proof this library asks for everywhere else.
func RequirePassword() Option { return func(p *Plugin) { p.requirePassword = true } }

// ReadableTOTPURI registers totp-uri: the signed-in user reads the otpauth://
// URI of their authenticator-app factor again, to add a second device or
// redraw a lost QR code (better-auth's get-totp-uri). It needs a fresh
// sign-in and, for a user with a password, the password, which is
// better-auth's guard plus the fresh window.
//
// Off by default, because the URI is the secret itself: whoever reads it
// clones the authenticator, and for a user without a password a stolen fresh
// session is then enough to defeat the second factor for good, with no
// trace the user would notice. Without this option a lost QR code during
// setup is covered by enrolling again.
func ReadableTOTPURI() Option { return func(p *Plugin) { p.readableURI = true } }

// PasswordRequest carries the user's password, for totp-uri and
// view-recovery-codes; ignored for a user without one.
type PasswordRequest struct {
	Password auth.Token `json:"password,omitempty"`
}

// TOTPURIResult is the otpauth:// URI an authenticator app reads, with the
// issuer the user enrolled with. The field is named as better-auth names it.
type TOTPURIResult struct {
	URL string `json:"totpURI"`
}

// CheckCode verifies a current code or an unused recovery code for the
// signed-in user in ctx and changes no session: a step-up before a sensitive
// action. It is the check operation, so it has verify's rate rule and
// lockout; a delivered-code user calls Send first.
func (p *Plugin) CheckCode(ctx context.Context, code string) error {
	_, err := p.check.Call(ctx, CodeRequest{Code: code})
	return err
}

// TOTPURI reads the signed-in user's authenticator URI back; see
// ReadableTOTPURI. Without that option the operation is not registered and
// the call fails.
func (p *Plugin) TOTPURI(ctx context.Context, in PasswordRequest) (TOTPURIResult, error) {
	return p.uri.Call(ctx, in)
}

func (p *Plugin) doCheck(ctx context.Context, c *auth.Call, in CodeRequest) (auth.Done, error) {
	if err := p.pass(ctx, c.User.ID, in.proof()); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

// doTOTPURI checks the password before it reads anything, so a caller
// without it learns nothing about the factor. An unconfirmed enrolment
// answers too, as better-auth's does: it is the QR code setup is showing.
func (p *Plugin) doTOTPURI(ctx context.Context, c *auth.Call, in PasswordRequest) (TOTPURIResult, error) {
	if err := p.checkPassword(ctx, c.User.ID, in.Password, true); err != nil {
		return TOTPURIResult{}, err
	}
	row, err := p.totpFactor(ctx, c.User.ID)
	if err != nil {
		return TOTPURIResult{}, err
	}
	secret, err := p.openSealed(ctx, p.ring, sealedTOTPSecret, row.secret, c.User.ID)
	if err != nil {
		return TOTPURIResult{}, err
	}
	return TOTPURIResult{URL: otpauthURL(p.issuerFor(row.issuer), p.accountLabel(ctx, *c.User), secret, p.digits, p.period)}, nil
}

// totpFactor is userID's authenticator-app factor, the primary or a further
// one, confirmed or still being set up; ErrNotTOTP when there is none.
func (p *Plugin) totpFactor(ctx context.Context, userID string) (factorRow, error) {
	row, err := p.load(ctx, userID)
	if err != nil {
		return factorRow{}, err
	}
	if Method(row.method) == MethodTOTP {
		return row, nil
	}
	ext, err := p.extras(ctx, userID, row)
	if err != nil {
		return factorRow{}, err
	}
	for _, x := range ext {
		if Method(x.method) == MethodTOTP {
			return x, nil
		}
	}
	return factorRow{}, ErrNotTOTP
}

// checkPassword asks the password plugin when required: nothing without a
// password plugin or for a user with no password, otherwise the password's
// own check, whose error (wrong or empty) is the answer.
func (p *Plugin) checkPassword(ctx context.Context, userID string, pw auth.Token, required bool) error {
	if !required || p.passwords == nil {
		return nil
	}
	has, err := p.passwords.HasPassword(ctx, userID)
	if err != nil {
		return err
	}
	if !has {
		return nil
	}
	return p.passwords.Verify(ctx, pw)
}

// ReauthenticateRequest is the input of reauthenticate: a current code or a
// recovery code, and the ticket the first re-authentication step answered
// with (auth.Reauthentication.Ticket).
type ReauthenticateRequest struct {
	Code   string         `json:"code"`
	Ticket auth.WireToken `json:"ticket"`
	// Method and SecurityKey pick the factor, as on CodeRequest.
	Method      Method               `json:"method,omitempty"`
	SecurityKey *SecurityKeyResponse `json:"securityKey,omitempty"`
}

// Reauthenticate finishes a re-authentication whose first step asked for the
// second factor: it checks code like verify (same lockout, recovery codes
// spent) and then spends ticket, after which the signed-in session is fresh
// again. A wrong code is ErrCodeInvalid; a wrong, spent or expired ticket, or
// one from another session, is auth.ErrReauthTicketInvalid.
func (p *Plugin) Reauthenticate(ctx context.Context, in ReauthenticateRequest) (auth.Reauthentication, error) {
	return p.reauth.Call(ctx, in)
}

// doReauthenticate checks the code first: a client without it learns
// nothing about the ticket. When the ticket is then refused, the operation
// fails and its transaction undoes the code's use, as a failed verify does.
func (p *Plugin) doReauthenticate(ctx context.Context, c *auth.Call, in ReauthenticateRequest) (auth.Reauthentication, error) {
	if err := c.Auth.CanReauthenticate(c); err != nil {
		return auth.Reauthentication{}, err
	}
	if err := p.pass(ctx, c.User.ID, FactorProof{Method: in.Method, Code: in.Code, SecurityKey: in.SecurityKey}); err != nil {
		if errors.Is(err, ErrCodeInvalid) || errors.Is(err, ErrLocked) || errors.Is(err, ErrSecurityKeyInvalid) {
			c.Auth.ReportReauthFailure(c)
		}
		return auth.Reauthentication{}, err
	}
	return c.Auth.CompleteReauthentication(ctx, c, in.Ticket.Token())
}
