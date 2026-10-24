package oauthprovider

import (
	"encoding/json"
	"errors"
	"slices"

	"github.com/ubgo/auth/plugin/jwt"
)

// targetError is an authorization error that cannot be redirected because
// the client is unknown or disabled: errors.Is sees ErrBadRedirectTarget
// (so callers that check it keep working, and the status is its 400) and
// the reason, whose RFC code (invalid_client, client_disabled) the answer
// carries.
type targetError struct{ reason error }

func (e targetError) Error() string   { return e.reason.Error() }
func (e targetError) Unwrap() []error { return []error{ErrBadRedirectTarget, e.reason} }

// badTarget wraps a reason as a targetError.
func badTarget(reason error) error { return targetError{reason: reason} }

// targetCode is the RFC code of a targetError's reason, or "".
func targetCode(err error) string {
	var te targetError
	if !errors.As(err, &te) {
		return ""
	}
	return rfcCode(te.reason)
}

// idTokenHintSubject reads an id_token_hint: an ID token signed by this
// provider's keys, for this client, whatever its expiry (OpenID Connect
// Core section 3.1.2.1 accepts an expired one). It answers the sub, or
// false for a token this provider did not issue to the client.
func (p *Plugin) idTokenHintSubject(token, clientID string) (string, bool) {
	keys := jwt.KeysFromJWKS(p.signer.PublicKeys())
	h, ok := assertionHeader(token)
	pub, known := keys[h.Kid]
	if !ok || !known {
		return "", false
	}
	_, body, err := jwt.VerifySignature(token, pub, "JWT")
	if err != nil {
		return "", false
	}
	var c struct {
		Iss string          `json:"iss"`
		Sub string          `json:"sub"`
		Aud json.RawMessage `json:"aud"`
	}
	if json.Unmarshal(body, &c) != nil || c.Iss != p.issuer || c.Sub == "" || !audienceHas(c.Aud, clientID) {
		return "", false
	}
	return c.Sub, true
}

// audienceHas reports whether an aud claim, one string or an array, names
// want.
func audienceHas(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	return json.Unmarshal(raw, &many) == nil && slices.Contains(many, want)
}
