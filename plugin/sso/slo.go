package sso

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/ubgo/auth"
)

// Single logout (SAMLOptions.EnableSingleLogout): the SP-initiated logout
// route, the SP's SLO endpoint for the IdP's requests and responses, and
// the session records that tie an app session to the IdP's NameID and
// SessionIndex.

// Verification purposes of single logout.
const (
	// PurposeSAMLSession finds an app session from (provider, NameID,
	// SessionIndex); Meta is the JSON samlSession.
	PurposeSAMLSession auth.Purpose = "sso.saml_session"
	// PurposeSAMLSessionByID finds the SAML session of an app session id.
	PurposeSAMLSessionByID auth.Purpose = "sso.saml_session_id"
	// PurposeSAMLLogout is an SP-initiated LogoutRequest's ID, consumed by
	// the IdP's LogoutResponse.
	PurposeSAMLLogout auth.Purpose = "sso.saml_logout"
)

// Operation ids and routes of single logout.
const (
	EndpointLogout  auth.EndpointID = "sso.saml-logout"
	EndpointSLO     auth.EndpointID = "sso.saml-slo"
	EndpointSLOPost auth.EndpointID = "sso.saml-slo-post"
	PathLogout                      = "/saml2/logout"
	PathSLO                         = "/saml2/sp/slo"
)

// DefaultLogoutRequestTTL bounds an SP-initiated LogoutRequest.
const DefaultLogoutRequestTTL = 5 * time.Minute

// Errors of single logout.
var (
	ErrSLOUnsupported        = auth.NewError("sso.idp_slo_unsupported", http.StatusBadRequest, "This identity provider does not support single logout.")
	ErrSAMLSessionNotFound   = auth.NewError("sso.saml_session_not_found", http.StatusNotFound, "This session did not start with SAML single sign-on.")
	ErrInvalidLogoutRequest  = auth.NewError("sso.invalid_logout_request", http.StatusBadRequest, "The logout request was not accepted.")
	ErrInvalidLogoutResponse = auth.NewError("sso.invalid_logout_response", http.StatusBadRequest, "The logout response was not accepted.")
	ErrLogoutFailedAtIdP     = auth.NewError("sso.logout_failed_at_idp", http.StatusBadGateway, "The identity provider could not sign you out.")
)

// samlSession ties an app session to the IdP's view of it.
type samlSession struct {
	Provider     string   `json:"p"`
	NameID       string   `json:"n"`
	NameIDFormat string   `json:"f,omitempty"`
	Index        string   `json:"i,omitempty"`
	SessionID    string   `json:"s"`
	UserID       string   `json:"u"`
	Indexes      []string `json:"-"`
}

// sessionKey is the PurposeSAMLSession token of one IdP session.
func sessionKey(provider, nameID, index string) auth.Token {
	return auth.Token(provider + "\x00" + nameID + "\x00" + index)
}

// recordSAMLSession stores both directions of the tie, replacing a record
// of the same IdP session.
func (p *Plugin) recordSAMLSession(ctx context.Context, pr Provider, info UserInfo, sess auth.Session) error {
	s := samlSession{Provider: pr.ProviderID, NameID: info.NameID, NameIDFormat: info.NameIDFormat, Index: info.SessionIndex, SessionID: sess.ID, UserID: sess.UserID}
	raw, _ := json.Marshal(s) // a struct of strings always marshals
	ttl := sess.ExpiresAt.Sub(p.core.Now())
	if ttl <= 0 {
		ttl = DefaultStateTTL
	}
	key := sessionKey(pr.ProviderID, info.NameID, info.SessionIndex)
	if _, err := p.core.ConsumeVerification(ctx, PurposeSAMLSession, key); err != nil && !errors.Is(err, auth.ErrTokenInvalid) {
		return err
	}
	if err := p.core.IssueVerificationToken(ctx, PurposeSAMLSession, pr.ProviderID, key, ttl, string(raw)); err != nil {
		return err
	}
	return p.core.IssueVerificationToken(ctx, PurposeSAMLSessionByID, pr.ProviderID, auth.Token(sess.ID), ttl, string(raw))
}

// takeByID consumes the record of an app session; ok is false when the
// session did not start with SAML.
func (p *Plugin) takeByID(ctx context.Context, sessionID string) (samlSession, bool, error) {
	v, err := p.core.ConsumeVerification(ctx, PurposeSAMLSessionByID, auth.Token(sessionID))
	if errors.Is(err, auth.ErrTokenInvalid) {
		return samlSession{}, false, nil
	}
	if err != nil {
		return samlSession{}, false, err
	}
	var s samlSession
	if err := json.Unmarshal([]byte(v.Meta), &s); err != nil {
		return samlSession{}, false, err
	}
	_, err = p.core.ConsumeVerification(ctx, PurposeSAMLSession, sessionKey(s.Provider, s.NameID, s.Index))
	if err != nil && !errors.Is(err, auth.ErrTokenInvalid) {
		return samlSession{}, false, err
	}
	return s, true, nil
}

// takeByIndex consumes the record of an IdP session.
func (p *Plugin) takeByIndex(ctx context.Context, provider, nameID, index string) (samlSession, bool, error) {
	v, err := p.core.ConsumeVerification(ctx, PurposeSAMLSession, sessionKey(provider, nameID, index))
	if errors.Is(err, auth.ErrTokenInvalid) {
		return samlSession{}, false, nil
	}
	if err != nil {
		return samlSession{}, false, err
	}
	var s samlSession
	if err := json.Unmarshal([]byte(v.Meta), &s); err != nil {
		return samlSession{}, false, err
	}
	_, err = p.core.ConsumeVerification(ctx, PurposeSAMLSessionByID, auth.Token(s.SessionID))
	if err != nil && !errors.Is(err, auth.ErrTokenInvalid) {
		return samlSession{}, false, err
	}
	return s, true, nil
}

// OperationHooks forgets the SAML session record when the app session is
// signed out, under EnableSingleLogout.
func (p *Plugin) OperationHooks() []auth.OperationHook {
	if !p.saml.EnableSingleLogout {
		return nil
	}
	// Sign-out is a SignedIn operation, and the pipeline checks that before
	// any Before hook runs, so c.Session is set here.
	return []auth.OperationHook{{Match: []auth.EndpointID{auth.EndpointSignOut}, Before: func(ctx context.Context, c *auth.Call) error {
		_, _, err := p.takeByID(ctx, c.Session.ID)
		return err
	}}}
}

// LogoutRequest starts an SP-initiated single logout.
type LogoutRequest struct {
	// CallbackURL is where the browser lands after the IdP answers.
	CallbackURL string `json:"callbackURL,omitempty"`
}

// LogoutResult is where to send the browser: the IdP's SLO URL.
type LogoutResult struct {
	URL      string `json:"url"`
	Redirect bool   `json:"redirect"`
}

// logoutMeta is a pending LogoutRequest.
type logoutMeta struct {
	Provider string `json:"p"`
	ReturnTo string `json:"r"`
}

func (p *Plugin) doLogout(ctx context.Context, c *auth.Call, in LogoutRequest) (LogoutResult, error) {
	returnTo, err := p.returnTo(in.CallbackURL)
	if err != nil {
		return LogoutResult{}, err
	}
	s, ok, err := p.takeByID(ctx, c.Session.ID)
	if err != nil {
		return LogoutResult{}, err
	}
	if !ok {
		return LogoutResult{}, ErrSAMLSessionNotFound
	}
	pr, err := p.ProviderByID(ctx, s.Provider)
	if err != nil || pr.SAML == nil {
		return LogoutResult{}, ErrProviderNotFound
	}
	idp, err := pr.SAML.IdP(p.saml.MaxMetadataSize)
	if err != nil {
		return LogoutResult{}, err
	}
	if idp.SLOURL == "" {
		return LogoutResult{}, ErrSLOUnsupported
	}
	sp, err := p.spSettings(pr)
	if err != nil {
		return LogoutResult{}, err
	}
	id := samlRequestIDPrefix + auth.NewToken().Reveal()
	var idx []string
	if s.Index != "" {
		idx = []string{s.Index}
	}
	doc := LogoutDocument(KindLogoutRequest, id, sp.EntityID, idp.SLOURL, s.NameID, s.NameIDFormat, idx, "", "", c.Auth.Now())
	meta, _ := json.Marshal(logoutMeta{Provider: pr.ProviderID, ReturnTo: returnTo}) // strings always marshal
	if err := c.Auth.IssueVerificationToken(ctx, PurposeSAMLLogout, pr.ProviderID, auth.Token(id), p.saml.LogoutRequestTTL, string(meta)); err != nil {
		return LogoutResult{}, err
	}
	u, err := RedirectURL(idp.SLOURL, paramSAMLRequest, doc, "", sp.SigningKey, sp.SignatureAlgorithm)
	if err != nil {
		return LogoutResult{}, err
	}
	if err := c.Auth.EndSession(ctx, c.User.ID, c.Session.ID, auth.SessionEndSignOut); err != nil {
		return LogoutResult{}, err
	}
	c.Effects.ClearSession()
	return LogoutResult{URL: u, Redirect: true}, nil
}

// SLORequest is what the IdP sends to the SLO endpoint: a LogoutRequest
// (IdP-initiated) or a LogoutResponse (to an SP-initiated logout), by the
// redirect binding (query) or the POST binding (form).
type SLORequest struct {
	SAMLRequest  string `json:"SAMLRequest,omitempty"`
	SAMLResponse string `json:"SAMLResponse,omitempty"`
	RelayState   string `json:"RelayState,omitempty"`
	SigAlg       string `json:"SigAlg,omitempty"`
	Signature    string `json:"Signature,omitempty"`
	// ProviderID names the provider when the IdP's SLO URL carries it
	// (?providerId=); otherwise the message's issuer or InResponseTo does.
	ProviderID string `json:"providerId,omitempty"`
}

func (p *Plugin) doSLOGet(ctx context.Context, c *auth.Call, in SLORequest) (LogoutResult, error) {
	return p.doSLO(ctx, c, in, true)
}

func (p *Plugin) doSLOPost(ctx context.Context, c *auth.Call, in SLORequest) (LogoutResult, error) {
	return p.doSLO(ctx, c, in, false)
}

func (p *Plugin) doSLO(ctx context.Context, c *auth.Call, in SLORequest, redirect bool) (LogoutResult, error) {
	m := BindingMessage{Redirect: redirect, RelayState: in.RelayState, SigAlg: in.SigAlg, Signature: in.Signature}
	switch {
	case in.SAMLRequest != "" && in.SAMLResponse == "":
		m.Param, m.Value = paramSAMLRequest, in.SAMLRequest
	case in.SAMLResponse != "" && in.SAMLRequest == "":
		m.Param, m.Value = paramSAMLResponse, in.SAMLResponse
	default:
		return LogoutResult{}, ErrInvalidLogoutRequest
	}
	pr, pending, err := p.sloProvider(ctx, c, in, m)
	if err != nil {
		return LogoutResult{}, p.samlFailure(c, in.ProviderID, err)
	}
	idp, err := pr.SAML.IdP(p.saml.MaxMetadataSize)
	if err != nil {
		return LogoutResult{}, err
	}
	if m.SigAlg != "" {
		if err := p.saml.CheckAlgorithms(RawFacts{SignatureAlgorithms: []string{m.SigAlg}}, func(alg string) {
			c.Auth.Logger().Warn("sso: logout message uses a deprecated algorithm", "provider", pr.ProviderID, "algorithm", alg)
		}); err != nil {
			return LogoutResult{}, p.samlFailure(c, pr.ProviderID, err)
		}
	}
	msg, err := DecodeLogout(m, idp.Certs, c.Auth.Now(), p.saml.MaxResponseSize)
	if err != nil {
		return LogoutResult{}, p.samlFailure(c, pr.ProviderID, err)
	}
	if m.Param == paramSAMLRequest {
		return p.idpLogout(ctx, c, pr, idp, msg, in.RelayState)
	}
	return p.logoutAnswered(c, pr, idp, msg, pending)
}

// sloProvider finds the provider of an SLO message: a LogoutResponse by the
// pending request it answers (consumed here, once), a LogoutRequest by
// providerId or by its issuer, read before the signature check only to
// choose whose certificates check it.
func (p *Plugin) sloProvider(ctx context.Context, c *auth.Call, in SLORequest, m BindingMessage) (Provider, logoutMeta, error) {
	peek, err := PeekLogout(m, p.saml.MaxResponseSize)
	if err != nil {
		return Provider{}, logoutMeta{}, err
	}
	var pending logoutMeta
	id := in.ProviderID
	if m.Param == paramSAMLResponse {
		v, err := c.Auth.ConsumeVerification(ctx, PurposeSAMLLogout, auth.Token(peek.InResponseTo))
		if err != nil {
			return Provider{}, logoutMeta{}, ErrInvalidLogoutResponse
		}
		if json.Unmarshal([]byte(v.Meta), &pending) != nil || (id != "" && id != pending.Provider) {
			return Provider{}, logoutMeta{}, ErrInvalidLogoutResponse
		}
		id = pending.Provider
	}
	if id == "" {
		pr, err := p.providerByIdPEntity(ctx, peek.Issuer)
		return pr, pending, err
	}
	pr, err := p.ProviderByID(ctx, id)
	if err != nil || pr.SAML == nil {
		return Provider{}, logoutMeta{}, ErrProviderNotFound
	}
	return pr, pending, nil
}

// providerByIdPEntity returns the one SAML provider whose IdP entity id is
// entityID; none or several is ErrProviderNotFound.
func (p *Plugin) providerByIdPEntity(ctx context.Context, entityID string) (Provider, error) {
	all, err := p.providersWhere(ctx)
	if err != nil {
		return Provider{}, err
	}
	var found []Provider
	for _, pr := range append(slices.Clone(p.defaults), all...) {
		if pr.SAML == nil {
			continue
		}
		if idp, err := pr.SAML.IdP(p.saml.MaxMetadataSize); err == nil && idp.EntityID == entityID && entityID != "" {
			found = append(found, pr)
		}
	}
	if len(found) != 1 {
		return Provider{}, ErrProviderNotFound
	}
	return found[0], nil
}

// requireSigned applies the signing policy of an incoming logout message.
func (p *Plugin) requireSigned(msg *LogoutMessage) bool {
	if msg.Kind == KindLogoutRequest {
		return !p.saml.AllowUnsignedLogoutRequests
	}
	return !p.saml.AllowUnsignedLogoutResponses
}

// idpLogout ends the app sessions the IdP's LogoutRequest names and
// answers it with a LogoutResponse at the IdP's SLO URL.
func (p *Plugin) idpLogout(ctx context.Context, c *auth.Call, pr Provider, idp IdPSettings, msg *LogoutMessage, relay string) (LogoutResult, error) {
	now, skew := c.Auth.Now(), p.saml.ClockSkew
	switch {
	case msg.Kind != KindLogoutRequest:
		return LogoutResult{}, ErrInvalidLogoutRequest
	case !msg.Signed && p.requireSigned(msg):
		return LogoutResult{}, p.samlFailure(c, pr.ProviderID, samlErr(SAMLSignatureInvalid, "unsigned LogoutRequest"))
	case msg.Issuer != idp.EntityID:
		return LogoutResult{}, p.samlFailure(c, pr.ProviderID, samlErr(SAMLIssuerMismatch, "issuer %q", msg.Issuer))
	case msg.Destination != "" && msg.Destination != p.sloURLFor(pr.ProviderID):
		return LogoutResult{}, p.samlFailure(c, pr.ProviderID, samlErr(SAMLDestinationMismatch, "destination %q", msg.Destination))
	case !msg.NotOnOrAfter.IsZero() && !now.Add(-skew).Before(msg.NotOnOrAfter):
		return LogoutResult{}, p.samlFailure(c, pr.ProviderID, samlErr(SAMLExpired, "NotOnOrAfter %s", msg.NotOnOrAfter))
	case msg.NameID == "" || msg.ID == "":
		return LogoutResult{}, ErrInvalidLogoutRequest
	}
	indexes := msg.SessionIndexes
	if len(indexes) == 0 {
		indexes = []string{""}
	}
	status := StatusSuccess
	for _, idx := range indexes {
		s, ok, err := p.takeByIndex(ctx, pr.ProviderID, msg.NameID, idx)
		if err != nil {
			return LogoutResult{}, err
		}
		if !ok {
			continue
		}
		if err := c.Auth.EndSession(ctx, s.UserID, s.SessionID, auth.SessionEndProviderLogout); err != nil && !errors.Is(err, auth.ErrSessionNotFound) {
			c.Auth.Logger().Warn("sso: single logout could not end a session", "provider", pr.ProviderID, "error", err)
			status = statusResponder
		}
	}
	if idp.SLOURL == "" {
		return LogoutResult{}, ErrSLOUnsupported
	}
	sp, err := p.spSettings(pr)
	if err != nil {
		return LogoutResult{}, err
	}
	doc := LogoutDocument(KindLogoutResponse, samlRequestIDPrefix+auth.NewToken().Reveal(), sp.EntityID, idp.SLOURL, "", "", nil, msg.ID, status, now)
	u, err := RedirectURL(idp.SLOURL, paramSAMLResponse, doc, relay, sp.SigningKey, sp.SignatureAlgorithm)
	if err != nil {
		return LogoutResult{}, err
	}
	c.Effects.Redirect(u)
	return LogoutResult{URL: u, Redirect: true}, nil
}

// logoutAnswered finishes an SP-initiated logout.
func (p *Plugin) logoutAnswered(c *auth.Call, pr Provider, idp IdPSettings, msg *LogoutMessage, pending logoutMeta) (LogoutResult, error) {
	switch {
	case msg.Kind != KindLogoutResponse:
		return LogoutResult{}, ErrInvalidLogoutResponse
	case !msg.Signed && p.requireSigned(msg):
		return LogoutResult{}, p.samlFailure(c, pr.ProviderID, samlErr(SAMLSignatureInvalid, "unsigned LogoutResponse"))
	case msg.Issuer != idp.EntityID:
		return LogoutResult{}, p.samlFailure(c, pr.ProviderID, samlErr(SAMLIssuerMismatch, "issuer %q", msg.Issuer))
	case msg.Destination != "" && msg.Destination != p.sloURLFor(pr.ProviderID):
		return LogoutResult{}, p.samlFailure(c, pr.ProviderID, samlErr(SAMLDestinationMismatch, "destination %q", msg.Destination))
	case msg.Status != StatusSuccess:
		return LogoutResult{}, ErrLogoutFailedAtIdP
	}
	c.Effects.Redirect(pending.ReturnTo)
	return LogoutResult{URL: pending.ReturnTo, Redirect: true}, nil
}

// sloURLFor is the SP's single logout URL for a provider.
func (p *Plugin) sloURLFor(providerID string) string { return p.perProvider(p.slo, providerID) }
