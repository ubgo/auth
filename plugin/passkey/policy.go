package passkey

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/ubgo/auth"
)

// Authenticator policy and relying-party moves: which authenticator models
// may hold a passkey here, how much the server asks the authenticator to
// prove about itself, and how a deployment that changes domain keeps the
// passkeys bound to the old one.

// Conveyance is the WebAuthn attestation conveyance preference: how much the
// relying party asks an authenticator to prove about its make and model at
// registration (WebAuthn §5.4.7).
type Conveyance string

// The four conveyance preferences.
const (
	// ConveyanceNone asks for no attestation: the browser may strip it and
	// zero the AAGUID. The default, and better-auth's.
	ConveyanceNone Conveyance = "none"
	// ConveyanceIndirect lets the browser anonymize the attestation.
	ConveyanceIndirect Conveyance = "indirect"
	// ConveyanceDirect asks for the authenticator's own attestation
	// statement, which WithMetadata can verify against the FIDO Metadata
	// Service. The browser may ask the user's consent.
	ConveyanceDirect Conveyance = "direct"
	// ConveyanceEnterprise asks for an attestation that can identify the
	// individual device, for managed fleets whose browsers are configured to
	// allow it for this relying party.
	ConveyanceEnterprise Conveyance = "enterprise"
)

// ConveyanceValues is the canonical iteration order over conveyances.
var ConveyanceValues = []Conveyance{ConveyanceNone, ConveyanceIndirect, ConveyanceDirect, ConveyanceEnterprise}

// MetadataProvider is a FIDO Metadata Service source from the WebAuthn
// library (its metadata/providers/memory or metadata/providers/cached
// packages build one). The plugin hands it to the library unread, which then
// checks each registration's attestation against the authenticator's trust
// anchors, attestation types and status reports, as the provider asks.
type MetadataProvider = metadata.Provider

// WellKnownPath is where a browser fetches the related origins of a relying
// party: https://<rp id>/.well-known/webauthn (WebAuthn Level 3, Related
// Origin Requests).
//
//ds:def id=wellknownpath-r25pk01 owner=@khanakia stability=stable
const WellKnownPath = "/.well-known/webauthn"

var (
	// ErrAuthenticatorNotAllowed refuses a registration from an authenticator
	// model the policy does not take: one outside AllowAuthenticators (or one
	// that hides its model), or one in DenyAuthenticators. It is reached only
	// by a signed-in user or a finished sign-up ceremony and names the policy,
	// never the user.
	//
	//ds:def id=errauthenticatornotallowed-r25pk02 owner=@khanakia stability=stable
	ErrAuthenticatorNotAllowed = auth.NewError("passkey.authenticator_not_allowed", http.StatusForbidden, "This kind of passkey is not accepted here. Use another one.")

	// ErrAuthenticatorPolicy is a configuration mistake auth.New refuses:
	// an AAGUID that is not a UUID, both an allow-list and a deny-list, an
	// allow-list without WithMetadata, or a conveyance WebAuthn does not
	// define.
	ErrAuthenticatorPolicy = errors.New("passkey: authenticator policy: AAGUIDs are UUIDs, AllowAuthenticators and DenyAuthenticators exclude each other, AllowAuthenticators needs WithMetadata, and Attestation takes none, indirect, direct or enterprise")
)

// Attestation sets the attestation conveyance preference sent at every
// registration. Without it the plugin asks for none, or for direct under
// WithMetadata, since a metadata check needs the authenticator's statement.
//
//ds:def id=attestation-option-r25pk03 owner=@khanakia stability=stable
func Attestation(c Conveyance) Option { return func(p *Plugin) { p.conveyance = c } }

// WithMetadata verifies every registration's attestation against a FIDO
// Metadata Service provider: the attestation must chain to the model's
// trust anchor, and a model with a compromised status is refused, as the
// provider configures. It is what makes an AAGUID evidence rather than a
// claim, so AllowAuthenticators requires it. A registration that fails the
// check is passkey.invalid, with the reason in the log.
//
//ds:def id=withmetadata-option-r25pk04 owner=@khanakia stability=stable
func WithMetadata(m MetadataProvider) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("passkey.WithMetadata", m) {
			return
		}
		p.mds = m
	}
}

// AllowAuthenticators accepts new passkeys only from these authenticator
// models, by AAGUID (the UUID strings of the passkey-authenticator-aaguids
// list, any case), such as a company's issued security keys. An
// authenticator that hides its model (a zero AAGUID) is refused. Without an
// attestation check an AAGUID is whatever the client claims, so a crafted
// client could pass any allow-list: auth.New refuses AllowAuthenticators
// without WithMetadata. Passkeys registered before the list existed keep
// signing in; remove them to enforce the list on them too.
//
//ds:def id=allowauthenticators-option-r25pk05 owner=@khanakia stability=stable
func AllowAuthenticators(aaguids ...string) Option {
	return func(p *Plugin) { p.allowAAGUIDs = append(p.allowAAGUIDs, aaguids...) }
}

// DenyAuthenticators refuses new passkeys from these authenticator models,
// by AAGUID: a model with a known flaw, or a provider the product does not
// support. Without WithMetadata the AAGUID is self-reported, so this steers
// honest clients rather than stopping a determined one; it needs no metadata
// for that reason. An authenticator that hides its model is not refused.
//
//ds:def id=denyauthenticators-option-r25pk06 owner=@khanakia stability=stable
func DenyAuthenticators(aaguids ...string) Option {
	return func(p *Plugin) { p.denyAAGUIDs = append(p.denyAAGUIDs, aaguids...) }
}

// validatePolicy refuses an authenticator policy no ceremony could honour,
// and normalizes the AAGUID lists to the form aaguidString writes.
func (p *Plugin) validatePolicy() error {
	if p.conveyance != "" && !slices.Contains(ConveyanceValues, p.conveyance) {
		return ErrAuthenticatorPolicy
	}
	if len(p.allowAAGUIDs) > 0 && (len(p.denyAAGUIDs) > 0 || p.mds == nil) {
		return ErrAuthenticatorPolicy
	}
	for _, list := range []*[]string{&p.allowAAGUIDs, &p.denyAAGUIDs} {
		out := make([]string, 0, len(*list))
		for _, s := range *list {
			n, ok := normalizeAAGUID(s)
			if !ok {
				return ErrAuthenticatorPolicy
			}
			out = append(out, n)
		}
		*list = out
	}
	return nil
}

// normalizeAAGUID parses a UUID string, with or without dashes and in any
// case, into aaguidString's lowercase dashed form; false for anything else,
// including the all-zero AAGUID, which names no model.
func normalizeAAGUID(s string) (string, bool) {
	raw, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(s), "-", ""))
	if err != nil || len(raw) != aaguidLen {
		return "", false
	}
	n := aaguidString(raw)
	return n, n != ""
}

// conveyancePreference is the preference Init hands the library: the
// configured one, else direct under WithMetadata, else none.
func (p *Plugin) conveyancePreference() Conveyance {
	switch {
	case p.conveyance != "":
		return p.conveyance
	case p.mds != nil:
		return ConveyanceDirect
	}
	return ConveyanceNone
}

// checkAuthenticator applies the AAGUID policy to a verified credential. It
// runs before the row is written, at both registration and sign-up. Under an
// allow-list the model must also be proven (provenModel): the WebAuthn
// library accepts a "none" or self attestation whatever the metadata says,
// and skips the chain check for a certificate whose subject and issuer names
// match, both of which a crafted client controls.
func (p *Plugin) checkAuthenticator(ctx context.Context, cred *webauthn.Credential) error {
	model := aaguidString(cred.Authenticator.AAGUID)
	if model != "" && slices.Contains(p.denyAAGUIDs, model) {
		return ErrAuthenticatorNotAllowed
	}
	if len(p.allowAAGUIDs) == 0 {
		return nil
	}
	if !slices.Contains(p.allowAAGUIDs, model) {
		return ErrAuthenticatorNotAllowed
	}
	if err := p.provenModel(ctx, cred); err != nil {
		p.core.Logger().Info("passkey: authenticator model not proven", "aaguid", model, "error", err)
		return ErrAuthenticatorNotAllowed
	}
	return nil
}

// provenAttestationTypes are the attestation types whose statement carries a
// certificate chain a metadata trust anchor can vouch for. "none" and
// "basic_surrogate" (self attestation) prove nothing about the model.
var provenAttestationTypes = []string{string(metadata.BasicFull), string(metadata.AttCA), string(metadata.AnonCA)}

// provenModel checks that the credential's attestation certificate chains to
// a root the metadata provider lists for the credential's AAGUID. The
// library has already verified the attestation signature with that
// certificate and, for packed attestation, that the certificate names the
// same AAGUID; this adds the chain check it may skip.
func (p *Plugin) provenModel(ctx context.Context, cred *webauthn.Credential) error {
	if !slices.Contains(provenAttestationTypes, cred.AttestationType) {
		return fmt.Errorf("attestation type %q proves no model", cred.AttestationType)
	}
	var obj protocol.AttestationObject
	if err := webauthncbor.Unmarshal(cred.Attestation.Object, &obj); err != nil {
		return fmt.Errorf("attestation object: %w", err)
	}
	chain, err := x5cChain(obj.AttStatement)
	if err != nil {
		return err
	}
	id, err := uuid.FromBytes(cred.Authenticator.AAGUID)
	if err != nil {
		return err
	}
	entry, err := p.mds.GetEntry(ctx, id)
	if err != nil {
		return err
	}
	if entry == nil {
		return errors.New("no metadata entry")
	}
	opts := entry.MetadataStatement.Verifier(chain[1:])
	opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	_, err = chain[0].Verify(opts)
	return err
}

// attStmtX5C is the attestation statement key holding the certificate
// chain (WebAuthn section 8.2, packed attestation), a wire name kept verbatim.
const attStmtX5C = "x5c"

// x5cChain parses an attestation statement's x5c array: the attestation
// certificate first, then any intermediates. stmt is map[string]any because
// that is the WebAuthn library's decoded CBOR type; every value is narrowed
// with a checked assertion before use.
func x5cChain(stmt map[string]any) ([]*x509.Certificate, error) {
	raw, ok := stmt[attStmtX5C].([]any)
	if !ok || len(raw) == 0 {
		return nil, errors.New("attestation statement has no certificate")
	}
	out := make([]*x509.Certificate, 0, len(raw))
	for _, r := range raw {
		der, ok := r.([]byte)
		if !ok {
			return nil, errors.New("attestation certificate is not bytes")
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// wellKnown is the Related Origin Requests document.
type wellKnown struct {
	Origins []string `json:"origins"`
}

// WellKnown serves the Related Origin Requests document for the relying
// party, {"origins": [...]}, listing the plugin's origins. It is how a
// deployment that moves to a new domain keeps its passkeys: they are bound
// to the old relying party id for good, so keep
// RelyingParty("old.example", "https://new.example", …), and serve this
// handler at https://old.example/.well-known/webauthn (WellKnownPath), so
// the browser lets the new origin use the old id. Browsers without Related
// Origin Requests still need the old domain. It answers GET and HEAD only,
// and works after auth.New.
//
//ds:def id=wellknown-r25pk07 owner=@khanakia stability=stable
func (p *Plugin) WellKnown() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		body, _ := json.Marshal(wellKnown{Origins: p.origins}) // a list of strings always marshals
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(body)
	})
}
