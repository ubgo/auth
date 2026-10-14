package agentauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// DefaultEnrollmentTokenTTL is how long a host's enrollment token works,
// better-auth's enrollmentTokenTTL.
const DefaultEnrollmentTokenTTL = time.Hour

// enrollmentTokenBytes is the entropy of an enrollment token, better-auth's
// 32 random bytes.
const enrollmentTokenBytes = 32

// annotationReactivated marks a reactivate call that reactivated, as
// opposed to one that answered a live agent as it is: only the first is an
// agent.reactivated event.
const (
	annotationReactivated = "agentauth.reactivated"
	annotationTrue        = "true"
)

// reasonReactivated is the reason recorded on the grants a reactivation
// gives back.
const reasonReactivated = "reactivated"

// EnrollmentTokenTTL overrides DefaultEnrollmentTokenTTL.
func EnrollmentTokenTTL(d time.Duration) Option { return func(p *Plugin) { p.enrollTTL = d } }

// ReactivateRequest reactivates an expired agent, protocol section 6.6: a
// host JWT, and the agent of that host.
type ReactivateRequest struct {
	Bearer
	AgentID string `json:"agent_id"`
}

// Reactivate brings an expired agent back, better-auth's reactivateAgent,
// and answers its status in Status's shape. Its capabilities decay to the
// host's budget: every grant it held is revoked and the budget granted
// again, so a capability a user approved on top of the budget must be asked
// for again. An agent that has not expired is answered as it is; a
// revoked, rejected, claimed or pending one, or one past its
// AbsoluteLifetime, is refused.
func (p *Plugin) Reactivate(ctx context.Context, in ReactivateRequest) (AgentStatusView, error) {
	return p.reactivate.Call(ctx, in)
}

// doReactivate checks the host before the agent's status, unlike
// better-auth, so another host's token learns nothing about an agent. An
// agent past its absolute lifetime is refused without being revoked here,
// as every other path refuses it: the operation's transaction would roll a
// revocation back with the refusal. better-auth sends the budget to a user
// for approval when nobody owns the host; here no agent can be active in
// that state (a delegated agent's approval links its host to the user, and
// an autonomous agent takes its budget without one), so the budget is
// always granted at once, as at registration.
func (p *Plugin) doReactivate(ctx context.Context, c *auth.Call, in ReactivateRequest) (AgentStatusView, error) {
	if in.Token == "" {
		return AgentStatusView{}, ErrAuthenticationRequired
	}
	vh, err := p.verifyHostJWT(ctx, in.Bearer, false)
	if err != nil {
		return AgentStatusView{}, err
	}
	agent, err := p.loadAgent(ctx, in.AgentID)
	if err != nil {
		return AgentStatusView{}, err
	}
	if agent.HostID != vh.host.ID {
		return AgentStatusView{}, ErrUnauthorized
	}
	if err := refuseRetired(agent); err != nil {
		return AgentStatusView{}, err
	}
	now := p.core.Now()
	if agent.Status == string(AgentActive) && !p.expired(agent, now) {
		return p.statusView(ctx, agent)
	}
	if p.absolute > 0 && !now.Before(agent.CreatedAt.Add(p.absolute)) {
		return AgentStatusView{}, ErrAbsoluteLifetimeExceeded
	}
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableGrant).Set(
		sqlb.Set(GrantStatusCol, string(GrantRevoked)), sqlb.Set(GrantUpdated, now)).
		Where(sqlb.Eq(GrantAgent, agent.ID), sqlb.In(GrantStatusCol, string(GrantActive), string(GrantPending)))); err != nil {
		return AgentStatusView{}, err
	}
	for _, name := range vh.host.budget() {
		if err := p.insertGrant(ctx, agent.ID, name, nil, agent.UserID, GrantActive, reasonReactivated, p.grantExpiry(name)); err != nil {
			return AgentStatusView{}, err
		}
	}
	var expires *time.Time
	if p.sessionTTL > 0 {
		e := p.slidingExpiry(agent.CreatedAt, now, now)
		expires = &e
	}
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableAgent).Set(
		sqlb.Set(AgentStatusCol, string(AgentActive)), sqlb.Set(AgentActivated, &now), sqlb.Set(AgentExpires, expires),
		sqlb.Set(AgentLastUsed, &now), sqlb.Set(AgentUpdated, now)).Where(sqlb.Eq(AgentID, agent.ID))); err != nil {
		return AgentStatusView{}, err
	}
	agent.Status, agent.ActivatedAt, agent.ExpiresAt, agent.LastUsedAt = string(AgentActive), &now, expires, &now
	c.Annotate(annotationReactivated, annotationTrue)
	return p.statusView(ctx, agent)
}

// refuseRetired refuses an agent that can never act again, or not yet.
func refuseRetired(agent agentRow) error {
	switch AgentStatus(agent.Status) {
	case AgentRevoked:
		return ErrAgentRevoked
	case AgentRejected:
		return ErrAgentRejected
	case AgentClaimed:
		return ErrAgentClaimed
	case AgentPending:
		return ErrAgentPending
	}
	return nil
}

// statusView is agent's status, as Status answers it.
func (p *Plugin) statusView(ctx context.Context, agent agentRow) (AgentStatusView, error) {
	grants, err := p.loadGrants(ctx, agent.ID)
	if err != nil {
		return AgentStatusView{}, err
	}
	created := agent.CreatedAt
	return AgentStatusView{
		AgentID: agent.ID, Name: agent.Name, HostID: agent.HostID, Status: AgentStatus(agent.Status), Grants: p.grantViews(grants),
		Mode: Mode(agent.Mode), UserID: agent.UserID, ActivatedAt: timeString(agent.ActivatedAt), CreatedAt: timeString(&created),
		LastUsedAt: timeString(agent.LastUsedAt), ExpiresAt: timeString(agent.ExpiresAt),
	}, nil
}

// RotateAgentKeyRequest replaces an agent's key, protocol section 6.8: a
// host JWT, the agent of that host and its new key.
type RotateAgentKeyRequest struct {
	Bearer
	AgentID   string    `json:"agent_id"`
	PublicKey PublicKey `json:"public_key"`
}

// RotateAgentKeyResult is the agent after rotation.
type RotateAgentKeyResult struct {
	AgentID string      `json:"agent_id"`
	Status  AgentStatus `json:"status"`
	// HostID is the host that rotated the key, for the agent.key_rotated
	// event; not part of the protocol's answer.
	HostID string `json:"-"`
}

// RotateAgentKey replaces an active agent's key, better-auth's rotateKey:
// the old key stops working at once. An agent that fetched its keys from a
// JWKS URL has a stored key from then on.
func (p *Plugin) RotateAgentKey(ctx context.Context, in RotateAgentKeyRequest) (RotateAgentKeyResult, error) {
	return p.rotateAgent.Call(ctx, in)
}

func (p *Plugin) doRotateAgentKey(ctx context.Context, _ *auth.Call, in RotateAgentKeyRequest) (RotateAgentKeyResult, error) {
	if in.Token == "" {
		return RotateAgentKeyResult{}, ErrAuthenticationRequired
	}
	vh, err := p.verifyHostJWT(ctx, in.Bearer, false)
	if err != nil {
		return RotateAgentKeyResult{}, err
	}
	if _, err := parsePublicKey(in.PublicKey, p.algorithms); err != nil {
		return RotateAgentKeyResult{}, err
	}
	agent, err := p.loadAgent(ctx, in.AgentID)
	if err != nil {
		return RotateAgentKeyResult{}, err
	}
	if agent.HostID != vh.host.ID {
		return RotateAgentKeyResult{}, ErrUnauthorized
	}
	if err := refuseRetired(agent); err != nil {
		return RotateAgentKeyResult{}, err
	}
	canonical := in.PublicKey.canonical()
	var n int64
	if err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableAgent).Where(
		sqlb.Eq(AgentHost, vh.host.ID), sqlb.Eq(AgentPublicKey, canonical), sqlb.NotEq(AgentID, agent.ID))); err != nil {
		return RotateAgentKeyResult{}, err
	}
	if n > 0 {
		return RotateAgentKeyResult{}, ErrAgentExists
	}
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableAgent).Set(
		sqlb.Set(AgentPublicKey, canonical), sqlb.Set(AgentKid, optional(in.PublicKey.KeyID)), sqlb.Set(AgentJWKSURL, (*string)(nil)),
		sqlb.Set(AgentUpdated, p.core.Now())).Where(sqlb.Eq(AgentID, agent.ID))); err != nil {
		return RotateAgentKeyResult{}, err
	}
	return RotateAgentKeyResult{AgentID: agent.ID, Status: AgentStatus(agent.Status), HostID: vh.host.ID}, nil
}

// UpdateHostRequest changes a host the signed-in user owns, better-auth's
// updateHost. A nil field is left as it is. PublicKey and JWKSURL replace
// how the host signs; at most one of them is given.
type UpdateHostRequest struct {
	HostID              string     `json:"host_id"`
	Name                *string    `json:"name,omitempty"`
	PublicKey           *PublicKey `json:"public_key,omitempty"`
	JWKSURL             *string    `json:"jwks_url,omitempty"`
	DefaultCapabilities []string   `json:"default_capabilities,omitempty"`
}

// UpdateHostResult is the host after the update.
type UpdateHostResult struct {
	HostID              string     `json:"id"`
	Name                *string    `json:"name"`
	DefaultCapabilities []string   `json:"default_capabilities"`
	JWKSURL             *string    `json:"jwks_url"`
	Status              HostStatus `json:"status"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// UpdateHost renames a host, replaces its key or JWKS URL, or replaces its
// budget. A new key stops the old one at once, as RotateHostKey does.
func (p *Plugin) UpdateHost(ctx context.Context, in UpdateHostRequest) (UpdateHostResult, error) {
	return p.updateHost.Call(ctx, in)
}

// doUpdateHost lets only the host's owner change it, where better-auth also
// lets any signed-in user change a host nobody owns and a member of the
// owner's organization change any: a host nobody owns is claimed with
// CreateHost, not edited. A host the user does not own answers
// ErrHostNotFound. A host waiting for enrollment gets its key only from
// EnrollHost.
func (p *Plugin) doUpdateHost(ctx context.Context, c *auth.Call, in UpdateHostRequest) (UpdateHostResult, error) {
	if in.PublicKey != nil && in.JWKSURL != nil {
		return UpdateHostResult{}, ErrInvalidRequest
	}
	host, err := p.loadHost(ctx, in.HostID)
	if err != nil {
		return UpdateHostResult{}, err
	}
	if host.ID != in.HostID || host.UserID == nil || *host.UserID != c.User.ID {
		return UpdateHostResult{}, ErrHostNotFound
	}
	if host.Status == string(HostRevoked) {
		return UpdateHostResult{}, ErrHostRevoked
	}
	if host.Status == string(HostPendingEnrollment) && (in.PublicKey != nil || in.JWKSURL != nil) {
		return UpdateHostResult{}, ErrInvalidRequest
	}
	now := p.core.Now()
	sets := []sqlb.Assignment{sqlb.Set(HostUpdated, now)}
	if in.Name != nil {
		host.Name = optional(truncate(*in.Name, maxNameRunes))
		sets = append(sets, sqlb.Set(HostName, host.Name))
	}
	if in.PublicKey != nil {
		if _, err := parsePublicKey(*in.PublicKey, p.algorithms); err != nil {
			return UpdateHostResult{}, err
		}
		kid := in.PublicKey.identifier()
		if other, err := p.loadHost(ctx, kid); err == nil && other.ID != host.ID {
			return UpdateHostResult{}, ErrHostAlreadyLinked
		} else if err != nil && !errors.Is(err, ErrHostNotFound) {
			return UpdateHostResult{}, err
		}
		host.JWKSURL = nil
		sets = append(sets, sqlb.Set(HostPublicKey, in.PublicKey.canonical()), sqlb.Set(HostKid, kid), sqlb.Set(HostJWKSURL, host.JWKSURL))
	}
	if in.JWKSURL != nil {
		if err := p.checkJWKSURL(*in.JWKSURL); err != nil {
			return UpdateHostResult{}, err
		}
		host.JWKSURL = in.JWKSURL
		sets = append(sets, sqlb.Set(HostJWKSURL, host.JWKSURL), sqlb.Set(HostPublicKey, ""), sqlb.Set(HostKid, ""))
	}
	if in.DefaultCapabilities != nil {
		reqs := make([]CapabilityRequest, 0, len(in.DefaultCapabilities))
		for _, n := range in.DefaultCapabilities {
			reqs = append(reqs, CapabilityRequest{Name: n})
		}
		if err := p.checkCapabilityNames(reqs); err != nil {
			return UpdateHostResult{}, err
		}
		host.DefaultCaps = encodeNames(in.DefaultCapabilities)
		sets = append(sets, sqlb.Set(HostDefaultCaps, host.DefaultCaps))
	}
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableHost).Set(sets...).Where(sqlb.Eq(HostID, host.ID))); err != nil {
		return UpdateHostResult{}, err
	}
	return UpdateHostResult{
		HostID: host.ID, Name: host.Name, DefaultCapabilities: nonNil(host.budget()), JWKSURL: host.JWKSURL,
		Status: HostStatus(host.Status), UpdatedAt: now,
	}, nil
}

// EnrollHostRequest binds a device's key to a host created for enrollment
// (CreateHost with neither a key nor a JWKS URL), protocol section 3.2.
// Token is the one-time enrollment token CreateHost returned.
type EnrollHostRequest struct {
	Token     string    `json:"token"`
	PublicKey PublicKey `json:"public_key"`
	Name      string    `json:"name,omitempty"`
}

// EnrollHostResult is the enrolled host.
type EnrollHostResult struct {
	HostID              string     `json:"host_id"`
	Name                *string    `json:"name"`
	DefaultCapabilities []string   `json:"default_capabilities"`
	Status              HostStatus `json:"status"`
}

// EnrollHost enrolls a device as a host, better-auth's enrollHost: a user
// creates the host in the app (and its budget), hands the token to the
// device, and the device enrolls with its own key, so the private key never
// leaves the device. The token works once, for EnrollmentTokenTTL.
func (p *Plugin) EnrollHost(ctx context.Context, in EnrollHostRequest) (EnrollHostResult, error) {
	return p.enrollHost.Call(ctx, in)
}

// doEnrollHost finds the host by the token's SHA-256 in SQL, so the token
// is never compared in Go. A key another host already holds is refused
// (ErrHostAlreadyLinked), where better-auth merges the two hosts: a merge
// would hand the enrolling user that other host's agents. The status flip
// is guarded, so of two enrollments racing with one token only one wins.
func (p *Plugin) doEnrollHost(ctx context.Context, _ *auth.Call, in EnrollHostRequest) (EnrollHostResult, error) {
	if in.Token == "" {
		return EnrollHostResult{}, ErrEnrollmentTokenInvalid
	}
	if _, err := parsePublicKey(in.PublicKey, p.algorithms); err != nil {
		return EnrollHostResult{}, err
	}
	sum := sha256.Sum256([]byte(in.Token))
	var host hostRow
	err := p.core.One(ctx, p.core.Select().Columns(host.bindings()...).From(TableHost).Where(sqlb.Eq(HostEnrollHash, sum[:])).Limit(1))
	switch {
	case errors.Is(err, sqlb.ErrNoRows):
		return EnrollHostResult{}, ErrEnrollmentTokenInvalid
	case err != nil:
		return EnrollHostResult{}, err
	case host.Status != string(HostPendingEnrollment):
		return EnrollHostResult{}, ErrEnrollmentTokenInvalid
	}
	now := p.core.Now()
	if host.EnrollUntil == nil || !host.EnrollUntil.After(now) {
		return EnrollHostResult{}, ErrEnrollmentTokenExpired
	}
	kid := in.PublicKey.identifier()
	if other, err := p.loadHost(ctx, kid); err == nil && other.ID != host.ID {
		return EnrollHostResult{}, ErrHostAlreadyLinked
	} else if err != nil && !errors.Is(err, ErrHostNotFound) {
		return EnrollHostResult{}, err
	}
	if in.Name != "" {
		host.Name = optional(truncate(in.Name, maxNameRunes))
	}
	n, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableHost).Set(
		sqlb.Set(HostPublicKey, in.PublicKey.canonical()), sqlb.Set(HostKid, kid), sqlb.Set(HostStatusCol, string(HostActive)),
		sqlb.Set(HostActivated, &now), sqlb.Set(HostName, host.Name), sqlb.Set(HostEnrollHash, []byte(nil)),
		sqlb.Set(HostEnrollUntil, (*time.Time)(nil)), sqlb.Set(HostUpdated, now)).
		Where(sqlb.Eq(HostID, host.ID), sqlb.Eq(HostStatusCol, string(HostPendingEnrollment))))
	if err != nil {
		return EnrollHostResult{}, err
	}
	if n == 0 {
		return EnrollHostResult{}, ErrEnrollmentTokenInvalid
	}
	return EnrollHostResult{HostID: host.ID, Name: host.Name, DefaultCapabilities: nonNil(host.budget()), Status: HostActive}, nil
}

// newEnrollmentToken is a fresh token and the SHA-256 stored for it.
func newEnrollmentToken() (string, []byte) {
	b := make([]byte, enrollmentTokenBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24)
	tok := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(tok))
	return tok, sum[:]
}

// Enrollment rate rule: tries per client IP per window. A token has 256
// bits, so guessing is hopeless anyway; the rule keeps the route from
// serving as a free database load generator.
const (
	enrollLimit  = 10
	enrollWindow = time.Minute
)

var _ auth.RateLimiter = (*Plugin)(nil)

// RateLimits limits EnrollHost per IP.
func (p *Plugin) RateLimits() []auth.RateRule {
	return []auth.RateRule{{Match: EndpointEnrollHost, Key: auth.ByIP, Limit: enrollLimit, Window: enrollWindow}}
}
