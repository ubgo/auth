package agentauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// SessionUser is the user an agent acts for.
type SessionUser struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// SessionGrant is one effective grant of an agent session.
type SessionGrant struct {
	Capability  string      `json:"capability"`
	Constraints Constraints `json:"constraints"`
	GrantedBy   *string     `json:"grantedBy"`
	Status      GrantStatus `json:"status"`
}

// SessionAgent is the agent of a session.
type SessionAgent struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	Mode             Mode            `json:"mode"`
	CapabilityGrants []SessionGrant  `json:"capabilityGrants"`
	HostID           string          `json:"hostId"`
	CreatedAt        time.Time       `json:"createdAt"`
	ActivatedAt      *time.Time      `json:"activatedAt"`
	Metadata         json.RawMessage `json:"metadata"`
}

// SessionHost is the host of a session.
type SessionHost struct {
	ID     string  `json:"id"`
	UserID *string `json:"userId"`
	Status string  `json:"status"`
}

// AgentSession is an authenticated agent request, better-auth's
// AgentSession: the agent, its effective grants (the active, unexpired
// ones, narrowed to the JWT's capabilities claim when it has one), its
// host and the user it acts for.
type AgentSession struct {
	Type    Mode         `json:"type"`
	AgentID string       `json:"agentId"`
	UserID  *string      `json:"userId"`
	Agent   SessionAgent `json:"agent"`
	Host    *SessionHost `json:"host"`
	User    SessionUser  `json:"user"`
}

// HasGrant reports whether the session holds an effective grant of
// capability, for an app route that serves a capability with a Location.
// Constraints are the route's to enforce, with Constraints.Validate.
func (s AgentSession) HasGrant(capability string) (SessionGrant, bool) {
	for _, g := range s.Agent.CapabilityGrants {
		if g.Capability == capability {
			return g, true
		}
	}
	return SessionGrant{}, false
}

// agentAuth is a verified agent request with the rows behind it.
type agentAuth struct {
	session AgentSession
	agent   agentRow
	host    *hostRow
	grants  []grantRow
}

// verifyAgent authenticates an agent JWT, better-auth's agent JWT path
// (protocol section 4.5): typ agent+jwt, sub naming the agent, iss (when
// present) naming its host, an active agent within its lifetimes, a
// signature by its stored key, an audience naming this server, a fresh
// iat, the request binding and a jti not seen before. It then extends the
// agent's sliding lifetime.
func (p *Plugin) verifyAgent(ctx context.Context, b Bearer) (agentAuth, error) {
	t, err := parseJWT(b.Token, TypeAgentJWT)
	if err != nil {
		return agentAuth{}, err
	}
	agent, err := p.loadAgent(ctx, t.claims.Subject)
	if err != nil {
		return agentAuth{}, err
	}
	if t.claims.Issuer != "" && t.claims.Issuer != agent.HostID {
		return agentAuth{}, ErrInvalidJWT
	}
	switch AgentStatus(agent.Status) {
	case AgentRevoked:
		return agentAuth{}, ErrAgentRevoked
	case AgentClaimed:
		return agentAuth{}, ErrAgentClaimed
	case AgentPending:
		return agentAuth{}, ErrAgentPending
	case AgentRejected:
		return agentAuth{}, ErrAgentRejected
	}
	now := p.core.Now()
	if p.absolute > 0 && !now.Before(agent.CreatedAt.Add(p.absolute)) {
		return agentAuth{}, ErrAbsoluteLifetimeExceeded
	}
	pub, err := p.signerKey(ctx, agent.PublicKey, agent.JWKSURL, t.header.Kid, ErrInvalidPublicKey)
	if err != nil {
		return agentAuth{}, err
	}
	location := ""
	if len(t.claims.Capabilities) == 1 {
		if def, ok := p.capability(t.claims.Capabilities[0]); ok {
			location = def.Location
		}
	}
	if err := p.verifyCommon(ctx, t, pub, jtiScopeAgent, agent.ID, location, b); err != nil {
		return agentAuth{}, err
	}
	if p.expired(agent, now) {
		return agentAuth{}, ErrAgentExpired
	}
	var host *hostRow
	if h, err := p.loadHost(ctx, agent.HostID); err == nil {
		host = &h
	} else if !errors.Is(err, ErrHostNotFound) {
		return agentAuth{}, err
	}
	user, err := p.sessionUser(ctx, agent, host)
	if err != nil {
		return agentAuth{}, err
	}
	all, err := p.loadGrants(ctx, agent.ID)
	if err != nil {
		return agentAuth{}, err
	}
	var effective []grantRow
	for _, g := range all {
		if !g.liveAt(now) {
			continue
		}
		if t.claims.Capabilities != nil && !containsString(t.claims.Capabilities, g.Capability) {
			continue
		}
		effective = append(effective, g)
	}
	if err := p.heartbeat(ctx, agent, now); err != nil {
		return agentAuth{}, err
	}
	s := AgentSession{
		Type: Mode(agent.Mode), AgentID: agent.ID, UserID: agent.UserID, User: user,
		Agent: SessionAgent{ID: agent.ID, Name: agent.Name, Mode: Mode(agent.Mode), HostID: agent.HostID, CreatedAt: agent.CreatedAt, ActivatedAt: agent.ActivatedAt, CapabilityGrants: []SessionGrant{}},
	}
	if agent.Metadata != nil {
		s.Agent.Metadata = json.RawMessage(*agent.Metadata)
	}
	if host != nil {
		s.Host = &SessionHost{ID: host.ID, UserID: host.UserID, Status: host.Status}
		if s.UserID == nil {
			s.UserID = host.UserID
		}
	}
	for _, g := range effective {
		c, _ := g.constraints()
		s.Agent.CapabilityGrants = append(s.Agent.CapabilityGrants, SessionGrant{Capability: g.Capability, Constraints: c, GrantedBy: g.GrantedBy, Status: GrantStatus(g.Status)})
	}
	return agentAuth{session: s, agent: agent, host: host, grants: effective}, nil
}

// expired reports an agent past its sliding lifetime or its maximum
// lifetime from activation. better-auth reactivates such an agent
// transparently; this port refuses it with ErrAgentExpired instead.
func (p *Plugin) expired(a agentRow, now time.Time) bool {
	if a.Status == string(AgentExpired) {
		return true
	}
	if a.ExpiresAt != nil && !a.ExpiresAt.After(now) {
		return true
	}
	anchor := a.CreatedAt
	if a.ActivatedAt != nil {
		anchor = *a.ActivatedAt
	}
	return p.maxLifetime > 0 && !now.Before(anchor.Add(p.maxLifetime))
}

// heartbeat records the use and slides the agent's expiry, capped by its
// maximum and absolute lifetimes.
func (p *Plugin) heartbeat(ctx context.Context, a agentRow, now time.Time) error {
	sets := []sqlb.Assignment{sqlb.Set(AgentLastUsed, &now)}
	if p.sessionTTL > 0 {
		anchor := a.CreatedAt
		if a.ActivatedAt != nil {
			anchor = *a.ActivatedAt
		}
		exp := p.slidingExpiry(a.CreatedAt, anchor, now)
		sets = append(sets, sqlb.Set(AgentExpires, &exp))
	}
	_, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableAgent).Set(sets...).Where(sqlb.Eq(AgentID, a.ID)))
	return err
}

// slidingExpiry is when an agent used at now expires: the session TTL
// from now, capped by its maximum lifetime from activated and its absolute
// lifetime from created. Registration, activation and every use store it,
// so the expiry an agent is shown is the one it is held to.
func (p *Plugin) slidingExpiry(created, activated, now time.Time) time.Time {
	exp := now.Add(p.sessionTTL)
	if p.maxLifetime > 0 && activated.Add(p.maxLifetime).Before(exp) {
		exp = activated.Add(p.maxLifetime)
	}
	if p.absolute > 0 && created.Add(p.absolute).Before(exp) {
		exp = created.Add(p.absolute)
	}
	return exp
}

// sessionUser is the user an agent acts for: its own user, else its
// host's, else AutonomousUser's answer.
func (p *Plugin) sessionUser(ctx context.Context, a agentRow, host *hostRow) (SessionUser, error) {
	id := a.UserID
	if id == nil && host != nil {
		id = host.UserID
	}
	if id != nil {
		u, err := p.core.User(ctx, *id)
		if errors.Is(err, auth.ErrUserNotFound) {
			return SessionUser{}, ErrAutonomousOwnerRequired
		}
		if err != nil {
			return SessionUser{}, err
		}
		return SessionUser{ID: u.ID, Name: u.Name}, nil
	}
	if p.autonomousUser != nil {
		u, err := p.autonomousUser(ctx, a.HostID, a.ID)
		if err != nil {
			return SessionUser{}, err
		}
		if u != nil {
			return *u, nil
		}
	}
	return SessionUser{}, ErrAutonomousOwnerRequired
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Session authenticates an agent JWT and returns the agent's session,
// better-auth's getAgentSession. Every call spends the token's jti.
func (p *Plugin) Session(ctx context.Context, b Bearer) (AgentSession, error) {
	return p.session.Call(ctx, b)
}

func (p *Plugin) doSession(ctx context.Context, _ *auth.Call, b Bearer) (AgentSession, error) {
	if b.Token == "" {
		return AgentSession{}, ErrAuthenticationRequired
	}
	v, err := p.verifyAgent(ctx, b)
	return v.session, err
}

// tokenType reads a JWT's typ header without trusting anything else.
func tokenType(raw string) string {
	head, _, ok := strings.Cut(raw, ".")
	if !ok {
		return ""
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(head)
	if err != nil {
		return ""
	}
	var h jwsHeader
	if json.Unmarshal(b, &h) != nil {
		return ""
	}
	return h.Typ
}

// RevokeRequest revokes an agent, protocol section 6.6: by the agent
// itself (an agent JWT, AgentID optional), by its host (a host JWT), or by
// the signed-in user who owns the agent or its host.
type RevokeRequest struct {
	Bearer
	AgentID string `json:"agent_id,omitempty"`
}

// RevokeResult is the revoked agent.
type RevokeResult struct {
	AgentID string      `json:"agent_id"`
	Status  AgentStatus `json:"status"`
}

// Revoke revokes an agent and every grant it holds.
func (p *Plugin) Revoke(ctx context.Context, in RevokeRequest) (RevokeResult, error) {
	return p.revoke.Call(ctx, in)
}

func (p *Plugin) doRevoke(ctx context.Context, c *auth.Call, in RevokeRequest) (RevokeResult, error) {
	agent, err := p.callerAgent(ctx, c, in.Bearer, in.AgentID)
	if err != nil {
		return RevokeResult{}, err
	}
	if err := p.revokeAgentRows(ctx, agent.ID); err != nil {
		return RevokeResult{}, err
	}
	return RevokeResult{AgentID: agent.ID, Status: AgentRevoked}, nil
}

// ownedBy reports whether userID owns the agent, directly or through its
// host, better-auth's revoke ownership rule.
func (p *Plugin) ownedBy(ctx context.Context, a agentRow, userID string) bool {
	if a.UserID != nil {
		return *a.UserID == userID
	}
	h, err := p.loadHost(ctx, a.HostID)
	return err == nil && h.UserID != nil && *h.UserID == userID
}

// StatusRequest asks for an agent's status, protocol section 6.5: with an
// agent JWT for itself, or a host JWT and the AgentID of one of its agents.
type StatusRequest struct {
	Bearer
	AgentID string `json:"agent_id,omitempty"`
}

// AgentStatusView is an agent's status and grants.
type AgentStatusView struct {
	AgentID     string      `json:"agent_id"`
	Name        string      `json:"name"`
	HostID      string      `json:"host_id"`
	Status      AgentStatus `json:"status"`
	Grants      []GrantView `json:"agent_capability_grants"`
	Mode        Mode        `json:"mode"`
	UserID      *string     `json:"user_id"`
	ActivatedAt *string     `json:"activated_at"`
	CreatedAt   *string     `json:"created_at"`
	LastUsedAt  *string     `json:"last_used_at"`
	ExpiresAt   *string     `json:"expires_at"`
}

// Status returns an agent's status. A host polls it while its agent waits
// for approval.
func (p *Plugin) Status(ctx context.Context, in StatusRequest) (AgentStatusView, error) {
	return p.status.Call(ctx, in)
}

func (p *Plugin) doStatus(ctx context.Context, _ *auth.Call, in StatusRequest) (AgentStatusView, error) {
	var agent agentRow
	switch {
	case in.Token == "":
		return AgentStatusView{}, ErrAuthenticationRequired
	case tokenType(in.Token) == TypeHostJWT:
		vh, err := p.verifyHostJWT(ctx, in.Bearer, true)
		if err != nil {
			return AgentStatusView{}, err
		}
		if in.AgentID == "" {
			return AgentStatusView{}, ErrInvalidRequest
		}
		if agent, err = p.loadAgent(ctx, in.AgentID); err != nil {
			return AgentStatusView{}, err
		}
		if agent.HostID != vh.host.ID {
			return AgentStatusView{}, ErrUnauthorized
		}
	default:
		v, err := p.verifyAgent(ctx, in.Bearer)
		if err != nil {
			return AgentStatusView{}, err
		}
		agent = v.agent
	}
	return p.statusView(ctx, agent)
}

// IntrospectRequest asks whether an agent JWT is valid, protocol section
// 6.10, for a resource server that received one.
type IntrospectRequest struct {
	Token string `json:"token"`
}

// IntrospectGrant is a grant in an introspection answer.
type IntrospectGrant struct {
	Capability string      `json:"capability"`
	Status     GrantStatus `json:"status"`
}

// Introspection is the answer: Active false and nothing else for any
// token that would not authenticate.
type Introspection struct {
	Active    bool              `json:"active"`
	AgentID   string            `json:"agent_id,omitempty"`
	HostID    string            `json:"host_id,omitempty"`
	UserID    *string           `json:"user_id,omitempty"`
	Grants    []IntrospectGrant `json:"agent_capability_grants,omitempty"`
	Mode      Mode              `json:"mode,omitempty"`
	ExpiresAt *string           `json:"expires_at,omitempty"`
}

// Introspect checks an agent JWT and spends its jti, as better-auth does.
func (p *Plugin) Introspect(ctx context.Context, in IntrospectRequest) (Introspection, error) {
	return p.introspect.Call(ctx, in)
}

func (p *Plugin) doIntrospect(ctx context.Context, _ *auth.Call, in IntrospectRequest) (Introspection, error) {
	inactive := Introspection{}
	t, err := parseJWT(in.Token, TypeAgentJWT)
	if err != nil {
		return inactive, nil
	}
	agent, err := p.loadAgent(ctx, t.claims.Subject)
	if errors.Is(err, ErrAgentNotFound) || (err == nil && agent.Status != string(AgentActive)) {
		return inactive, nil
	}
	if err != nil {
		return inactive, err
	}
	pub, err := p.signerKey(ctx, agent.PublicKey, agent.JWKSURL, t.header.Kid, ErrInvalidPublicKey)
	if err != nil {
		return inactive, nil
	}
	location := ""
	if len(t.claims.Capabilities) == 1 {
		if def, ok := p.capability(t.claims.Capabilities[0]); ok {
			location = def.Location
		}
	}
	now := p.core.Now()
	if err := p.verifyCommon(ctx, t, pub, jtiScopeAgent, agent.ID, location, Bearer{}); err != nil {
		if !errors.Is(err, errJTIRace) && (errors.Is(err, ErrInvalidJWT) || errors.Is(err, ErrJTIReplay) || errors.Is(err, ErrRequestBindingMismatch)) {
			return inactive, nil
		}
		return inactive, err
	}
	if p.expired(agent, now) {
		return inactive, nil
	}
	grants, err := p.loadGrants(ctx, agent.ID)
	if err != nil {
		return inactive, err
	}
	out := Introspection{Active: true, AgentID: agent.ID, HostID: agent.HostID, UserID: agent.UserID, Mode: Mode(agent.Mode), ExpiresAt: timeString(agent.ExpiresAt), Grants: []IntrospectGrant{}}
	for _, g := range grants {
		if g.liveAt(now) && (t.claims.Capabilities == nil || containsString(t.claims.Capabilities, g.Capability)) {
			out.Grants = append(out.Grants, IntrospectGrant{Capability: g.Capability, Status: GrantStatus(g.Status)})
		}
	}
	return out, nil
}

// RotateHostKeyRequest replaces a host's key, protocol section 6.8. Bearer
// is a host JWT signed by the current key.
type RotateHostKeyRequest struct {
	Bearer
	PublicKey PublicKey `json:"public_key"`
}

// RotateHostKeyResult is the host after rotation.
type RotateHostKeyResult struct {
	HostID string     `json:"host_id"`
	Status HostStatus `json:"status"`
}

// RotateHostKey replaces the key of the host that signed in.Token; the old
// key stops working at once. better-auth renames the host to the new key's
// thumbprint; this port keeps the host id, because agents and grants name
// it, and records the new key's kid instead.
func (p *Plugin) RotateHostKey(ctx context.Context, in RotateHostKeyRequest) (RotateHostKeyResult, error) {
	return p.rotateHostKey.Call(ctx, in)
}

func (p *Plugin) doRotateHostKey(ctx context.Context, _ *auth.Call, in RotateHostKeyRequest) (RotateHostKeyResult, error) {
	if in.Token == "" {
		return RotateHostKeyResult{}, ErrAuthenticationRequired
	}
	vh, err := p.verifyHostJWT(ctx, in.Bearer, false)
	if err != nil {
		return RotateHostKeyResult{}, err
	}
	if _, err := parsePublicKey(in.PublicKey, p.algorithms); err != nil {
		return RotateHostKeyResult{}, err
	}
	kid := in.PublicKey.identifier()
	if other, err := p.loadHost(ctx, kid); err == nil && other.ID != vh.host.ID {
		return RotateHostKeyResult{}, ErrHostAlreadyLinked
	} else if err != nil && !errors.Is(err, ErrHostNotFound) {
		return RotateHostKeyResult{}, err
	}
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableHost).Set(
		sqlb.Set(HostPublicKey, in.PublicKey.canonical()), sqlb.Set(HostKid, kid), sqlb.Set(HostUpdated, p.core.Now())).
		Where(sqlb.Eq(HostID, vh.host.ID))); err != nil {
		return RotateHostKeyResult{}, err
	}
	return RotateHostKeyResult{HostID: vh.host.ID, Status: HostStatus(vh.host.Status)}, nil
}
