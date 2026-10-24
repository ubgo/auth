package passkey

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// PurposePresence is a proof-of-presence ceremony: an assertion that a
// signed-in user is physically at an authenticator, for an approval such as
// plugin/agentauth's. Its Identifier is the user id and the scope joined by
// presenceSeparator, so a ceremony begun for one approval never completes
// another; Meta is the JSON of webauthn.SessionData.
const PurposePresence auth.Purpose = "passkey.presence"

// presenceSeparator joins a ceremony's user id and scope: the ASCII unit
// separator, which a user id never holds; not NUL, which Postgres text
// refuses.
const presenceSeparator = "\x1f"

// PresenceEnrolled reports whether userID has a passkey. With
// BeginPresence and VerifyPresence it satisfies agentauth.PresenceVerifier.
func (p *Plugin) PresenceEnrolled(ctx context.Context, userID string) (bool, error) {
	var n int64
	err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TablePasskey).Where(sqlb.Eq(UserID, userID)))
	return n > 0, err
}

// BeginPresence starts an assertion over userID's passkeys with user
// verification required, whatever AuthenticatorSelection says, because
// presence means a person proved it, not a device that was merely touched.
// It returns the ceremony handle and the options for
// navigator.credentials.get; a user with no passkey is ErrNotFound.
func (p *Plugin) BeginPresence(ctx context.Context, userID, scope string) (string, json.RawMessage, error) {
	w, err := p.waUserOf(ctx, userID)
	if err != nil {
		return "", nil, err
	}
	if len(w.creds) == 0 {
		return "", nil, ErrNotFound
	}
	opts := []webauthn.LoginOption{webauthn.WithUserVerification(protocol.VerificationRequired)}
	assertion, session, err := p.wa.BeginLogin(w, opts...)
	if err != nil {
		return "", nil, fmt.Errorf("passkey: begin presence: %w", err)
	}
	res, err := begin(ctx, p, PurposePresence, userID+presenceSeparator+scope, assertion, session)
	return res.Ceremony, res.Options, err
}

// VerifyPresence spends the ceremony and checks the assertion: begun for
// userID and scope, signed by one of userID's passkeys, with the user
// verified, and no clone warning. It updates the passkey's counter. Every
// refusal is ErrPasskeyInvalid, or ErrCeremonyInvalid for a spent or
// unknown ceremony.
func (p *Plugin) VerifyPresence(ctx context.Context, userID, scope, ceremony string, credential json.RawMessage) error {
	v, session, err := p.finish(ctx, PurposePresence, ceremony)
	if err != nil {
		return err
	}
	if v.Identifier != userID+presenceSeparator+scope {
		return ErrCeremonyInvalid
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(credential))
	if err != nil {
		return ErrPasskeyInvalid
	}
	w, err := p.waUserOf(ctx, userID)
	if err != nil {
		return err
	}
	cred, err := p.wa.ValidateLogin(w, session, parsed)
	if err != nil || !parsed.Response.AuthenticatorData.Flags.HasUserVerified() || cred.Authenticator.CloneWarning {
		p.core.Logger().Info("passkey: presence refused", "error", err)
		return ErrPasskeyInvalid
	}
	return p.touch(ctx, userID, cred)
}
