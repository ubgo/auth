package passkey

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/ubgo/auth"
)

// Re-authentication with a passkey: the signed-in user answers an assertion
// for one of their own passkeys, and their current session becomes fresh again
// (auth.Reauthenticate) with no new session and no new token. A user-verified
// assertion proves two factors, as at sign-in (CreateMultiFactorSession), so
// no second factor is asked; one without user verification proves possession
// only and goes through the second factor like a password.

// Operation ids and paths of re-authentication.
const (
	// EndpointReauthBegin starts an assertion ceremony for the signed-in
	// user's own passkeys, bound to their current session.
	EndpointReauthBegin auth.EndpointID = "passkey.reauthenticate-begin"
	// EndpointReauthFinish verifies it and refreshes the session.
	EndpointReauthFinish auth.EndpointID = "passkey.reauthenticate-finish"

	pathReauthBegin  = "/reauthenticate-begin"
	pathReauthFinish = "/reauthenticate-finish"
)

// PurposeReauth is a re-authentication ceremony. Its Identifier is the id of
// the session it was begun on, so a ceremony from another session (a second
// tab after a sign-out, a captured value) is refused; Meta is the JSON of
// webauthn.SessionData.
const PurposeReauth auth.Purpose = "passkey.reauth"

// Rate limits of re-authentication. begin writes a ceremony row, like
// login-begin, so it shares its per-IP bound; finish is bounded per IP and
// per signed-in user, as sign-in is per address and per account.
const (
	//ds:def id=passkey-reauthaccountlimit-8mx2qv4k owner=@khanakia stability=stable
	reauthAccountLimit  = 10
	reauthAccountWindow = 15 * time.Minute
)

// ErrNoPasskeys is returned by reauthenticate-begin for a user with no
// passkey: there is nothing to assert, and the client offers the password.
var ErrNoPasskeys = auth.NewError("passkey.none", http.StatusBadRequest, "Add a passkey first, or confirm with your password.")

// ReauthFinishRequest completes a re-authentication ceremony. Credential is
// the JSON the browser's PublicKeyCredential serializes to.
type ReauthFinishRequest struct {
	Ceremony   string          `json:"ceremony"`
	Credential json.RawMessage `json:"credential"`
}

// ReauthenticateBegin starts an assertion for the signed-in user's own
// passkeys, bound to the current session.
func (p *Plugin) ReauthenticateBegin(ctx context.Context) (BeginResult, error) {
	return p.reauthBegin.Call(ctx, struct{}{})
}

// ReauthenticateFinish verifies the assertion and makes the current session
// fresh again; see auth.Reauthentication for an answer that asks for the
// second factor. Every refused assertion is ErrPasskeyInvalid.
func (p *Plugin) ReauthenticateFinish(ctx context.Context, in ReauthFinishRequest) (auth.Reauthentication, error) {
	return p.reauthFinish.Call(ctx, in)
}

// defineReauth builds the two operations; New calls it.
func (p *Plugin) defineReauth() {
	p.reauthBegin = auth.Define(auth.OpInfo{ID: EndpointReauthBegin, Kind: auth.Mutation, Require: auth.SignedIn, Path: pathReauthBegin}, p.doReauthBegin)
	p.reauthFinish = auth.Define(auth.OpInfo{ID: EndpointReauthFinish, Kind: auth.Mutation, Require: auth.SignedIn, Path: pathReauthFinish}, p.doReauthFinish)
}

// reauthRules are the re-authentication rate rules RateLimits adds.
func reauthRules() []auth.RateRule {
	return []auth.RateRule{
		{Match: EndpointReauthBegin, Key: auth.ByIP, Limit: loginBeginIPLimit, Window: loginBeginIPWindow},
		{Match: EndpointReauthFinish, Key: auth.ByIP, Limit: loginBeginIPLimit, Window: loginBeginIPWindow},
		{Match: EndpointReauthFinish, Key: auth.ByFunc, Limit: reauthAccountLimit, Window: reauthAccountWindow, KeyFunc: auth.UserRateKey},
	}
}

func (p *Plugin) doReauthBegin(ctx context.Context, c *auth.Call, _ struct{}) (BeginResult, error) {
	if err := c.Auth.CanReauthenticate(c); err != nil {
		return BeginResult{}, err
	}
	w, err := p.waUserOf(ctx, c.User.ID)
	if err != nil {
		return BeginResult{}, err
	}
	if len(w.creds) == 0 {
		return BeginResult{}, ErrNoPasskeys
	}
	opts := []webauthn.LoginOption{webauthn.WithUserVerification(protocol.UserVerificationRequirement(p.userVerification()))}
	if len(p.authExt) > 0 {
		opts = append(opts, webauthn.WithAssertionExtensions(p.authExt))
	}
	// BeginLogin names every credential of w, so the browser offers only
	// this user's passkeys.
	assertion, session, err := p.wa.BeginLogin(w, opts...)
	if err != nil {
		return BeginResult{}, fmt.Errorf("passkey: begin re-authentication: %w", err)
	}
	return begin(ctx, p, PurposeReauth, c.Session.ID, assertion, session)
}

// doReauthFinish checks the ceremony belongs to this session, verifies the
// assertion against the signed-in user's own passkeys, and hands the core
// what it proved. Every refusal is ErrPasskeyInvalid (or ErrCeremonyInvalid
// for a ceremony that is not this session's) and is reported to the
// security stream; none of them ends the session.
func (p *Plugin) doReauthFinish(ctx context.Context, c *auth.Call, in ReauthFinishRequest) (auth.Reauthentication, error) {
	if err := c.Auth.CanReauthenticate(c); err != nil {
		return auth.Reauthentication{}, err
	}
	v, session, err := p.finish(ctx, PurposeReauth, in.Ceremony)
	if err != nil {
		return auth.Reauthentication{}, err
	}
	if subtle.ConstantTimeCompare([]byte(v.Identifier), []byte(c.Session.ID)) != 1 {
		return auth.Reauthentication{}, ErrCeremonyInvalid
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(in.Credential))
	if err != nil {
		c.Auth.ReportReauthFailure(c)
		return auth.Reauthentication{}, ErrPasskeyInvalid
	}
	w, err := p.waUserOf(ctx, c.User.ID)
	if err != nil {
		return auth.Reauthentication{}, err
	}
	cred, err := p.wa.ValidateLogin(w, session, parsed)
	switch {
	case err != nil:
		c.Auth.Logger().Info("passkey: re-authentication refused", "error", err)
		c.Auth.ReportReauthFailure(c)
		return auth.Reauthentication{}, ErrPasskeyInvalid
	case cred.Authenticator.CloneWarning:
		// A counter that went backwards means the credential was cloned.
		c.Auth.Logger().Warn("passkey: clone warning, re-authentication refused", "user", c.User.ID)
		c.Auth.ReportReauthFailure(c)
		return auth.Reauthentication{}, ErrPasskeyInvalid
	}
	if err := p.touch(ctx, c.User.ID, cred); err != nil {
		return auth.Reauthentication{}, err
	}
	uv := parsed.Response.AuthenticatorData.Flags.HasUserVerified()
	return c.Auth.Reauthenticate(ctx, c, auth.ReauthAttempt{MultiFactor: uv, SingleFactor: !uv})
}
