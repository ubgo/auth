package agentauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ubgo/auth"
)

// PresenceVerifier runs the WebAuthn ceremony that proves a person, not an
// agent driving the browser, approved a request (protocol section 8.11).
// plugin/passkey's Plugin implements it; the interface keeps the WebAuthn
// library out of this module. scope binds a ceremony to one approval, so
// an assertion made for one agent never approves another.
type PresenceVerifier interface {
	// PresenceEnrolled reports whether userID has a passkey to prove
	// presence with.
	PresenceEnrolled(ctx context.Context, userID string) (bool, error)
	// BeginPresence starts an assertion over userID's passkeys with user
	// verification required, and returns its single-use ceremony handle
	// and the options for navigator.credentials.get.
	BeginPresence(ctx context.Context, userID, scope string) (ceremony string, options json.RawMessage, err error)
	// VerifyPresence spends the ceremony and checks the assertion: one of
	// userID's passkeys, begun for scope, with the user verified.
	VerifyPresence(ctx context.Context, userID, scope, ceremony string, credential json.RawMessage) error
}

// ProofOfPresence enables WebAuthn-gated approvals with v, better-auth's
// proofOfPresence: a capability with StrengthWebAuthn, a first agent on a
// pending host, and new capabilities for an active agent then need a
// passkey assertion on top of the signed-in session. Registering a new
// agent under an already approved host needs the session only.
func ProofOfPresence(v PresenceVerifier) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("agentauth.ProofOfPresence", v) {
			return
		}
		p.presence = v
	}
}

// Errors of the presence check.
var (
	ErrWebAuthnNotEnrolled = auth.NewError("agentauth.webauthn_not_enrolled", http.StatusForbidden, "No passkeys registered. Register a passkey before approving capabilities that require proof of physical presence.")
	ErrWebAuthnFailed      = auth.NewError("agentauth.webauthn_verification_failed", http.StatusForbidden, "WebAuthn verification failed.")
)

// ApprovalWebAuthnRequired is ApproveResult.Status when the approval waits
// for a WebAuthn assertion: nothing was approved, and WebAuthn carries the
// challenge to answer.
const ApprovalWebAuthnRequired ApprovalStatus = "webauthn_required"

// PresenceChallenge is the WebAuthn challenge of an approval.
type PresenceChallenge struct {
	Ceremony string          `json:"ceremony"`
	Options  json.RawMessage `json:"webauthn_options"`
}

// PresenceResponse answers a PresenceChallenge: its ceremony, and the JSON
// the browser's PublicKeyCredential serializes to.
type PresenceResponse struct {
	Ceremony   string          `json:"ceremony"`
	Credential json.RawMessage `json:"credential"`
}

// needsPresence reports whether approving names for agent needs a WebAuthn
// assertion, better-auth's context-aware approval strength.
func (p *Plugin) needsPresence(ctx context.Context, agent agentRow, pendingGrants int, approved []string) (bool, error) {
	if p.presence == nil {
		return false, nil
	}
	if agent.Status == string(AgentPending) {
		host, err := p.loadHost(ctx, agent.HostID)
		if errors.Is(err, ErrHostNotFound) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		if host.Status == string(HostPending) {
			return true, nil
		}
	} else if pendingGrants > 0 {
		return true, nil
	}
	for _, name := range approved {
		if c, ok := p.capability(name); ok && c.ApprovalStrength == StrengthWebAuthn {
			return true, nil
		}
	}
	return false, nil
}

// checkPresence runs the presence step of an approval: a challenge when
// resp is nil, the verification otherwise. It returns the challenge to
// answer, or nil once presence is proven.
func (p *Plugin) checkPresence(ctx context.Context, userID, agentID string, resp *PresenceResponse) (*PresenceChallenge, error) {
	enrolled, err := p.presence.PresenceEnrolled(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !enrolled {
		return nil, ErrWebAuthnNotEnrolled
	}
	scope := PluginName + ":" + agentID
	if resp == nil {
		ceremony, options, err := p.presence.BeginPresence(ctx, userID, scope)
		if err != nil {
			return nil, err
		}
		return &PresenceChallenge{Ceremony: ceremony, Options: options}, nil
	}
	if err := p.presence.VerifyPresence(ctx, userID, scope, resp.Ceremony, resp.Credential); err != nil {
		var ae *auth.Error
		if errors.As(err, &ae) {
			p.core.Logger().Info("agentauth: presence refused", "error", err)
			return nil, ErrWebAuthnFailed
		}
		return nil, err
	}
	return nil, nil
}
