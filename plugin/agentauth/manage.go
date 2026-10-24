package agentauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// maxMetadataBytes bounds an agent's stored metadata. It is display data
// (a team, a project, a label), so 4 KiB is far more than any real use and
// keeps one owner from filling the table through UpdateAgent.
const maxMetadataBytes = 4 << 10

// callerAgent resolves the agent a revoke-style request acts on, protocol
// section 6.6: an agent JWT acts on itself (agentID, when given, must name
// it), a host JWT on one of its own agents, and a signed-in user on an
// agent they own directly or through its host. A revoked agent stays
// reachable by its host and its owner, so callers decide what that means.
func (p *Plugin) callerAgent(ctx context.Context, c *auth.Call, b Bearer, agentID string) (agentRow, error) {
	switch {
	case b.Token != "" && tokenType(b.Token) == TypeHostJWT:
		vh, err := p.verifyHostJWT(ctx, b, false)
		if err != nil {
			return agentRow{}, err
		}
		agent, err := p.loadAgent(ctx, agentID)
		if err != nil {
			return agentRow{}, err
		}
		if agent.HostID != vh.host.ID {
			return agentRow{}, ErrUnauthorized
		}
		return agent, nil
	case b.Token != "":
		v, err := p.verifyAgent(ctx, b)
		if err != nil {
			return agentRow{}, err
		}
		if agentID != "" && agentID != v.agent.ID {
			return agentRow{}, ErrUnauthorized
		}
		return v.agent, nil
	case c.User != nil:
		agent, err := p.loadAgent(ctx, agentID)
		if err != nil {
			return agentRow{}, err
		}
		if !p.ownedBy(ctx, agent, c.User.ID) {
			return agentRow{}, ErrUnauthorized
		}
		return agent, nil
	}
	return agentRow{}, ErrAuthenticationRequired
}

// RevokeHostRequest revokes a host, protocol section 6.10: the host itself
// with its JWT (HostID optional, and when given it must name that host),
// or the signed-in user who owns it (HostID required).
type RevokeHostRequest struct {
	Bearer
	HostID string `json:"host_id,omitempty"`
}

// RevokeHostResult is the revoked host and how many agents it took with
// it.
type RevokeHostResult struct {
	HostID        string     `json:"host_id"`
	Status        HostStatus `json:"status"`
	AgentsRevoked int        `json:"agents_revoked"`
}

// RevokeHost revokes a host and every agent under it, with their grants.
func (p *Plugin) RevokeHost(ctx context.Context, in RevokeHostRequest) (RevokeHostResult, error) {
	return p.revokeHost.Call(ctx, in)
}

// doRevokeHost closes two doors: a user revokes only a host they own (not
// a host nobody owns yet, nor one owned by another member of their
// organization), and the revoked host keeps its key, so the same key can
// neither register again dynamically nor be claimed with CreateHost; a
// revoked key is assumed compromised. A host the user does not own answers
// ErrHostNotFound, so its existence is not revealed.
func (p *Plugin) doRevokeHost(ctx context.Context, c *auth.Call, in RevokeHostRequest) (RevokeHostResult, error) {
	var host hostRow
	switch {
	case in.Token != "":
		vh, err := p.verifyHostJWT(ctx, in.Bearer, true)
		if err != nil {
			return RevokeHostResult{}, err
		}
		if in.HostID != "" && in.HostID != vh.host.ID {
			return RevokeHostResult{}, ErrUnauthorized
		}
		host = vh.host
	case c.User != nil:
		if in.HostID == "" {
			return RevokeHostResult{}, ErrInvalidRequest
		}
		var err error
		if host, err = p.loadHost(ctx, in.HostID); err != nil {
			return RevokeHostResult{}, err
		}
		if host.UserID == nil || *host.UserID != c.User.ID {
			return RevokeHostResult{}, ErrHostNotFound
		}
		if host.Status == string(HostRevoked) {
			return RevokeHostResult{HostID: host.ID, Status: HostRevoked}, nil
		}
	default:
		return RevokeHostResult{}, ErrAuthenticationRequired
	}
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableHost).Set(
		sqlb.Set(HostStatusCol, string(HostRevoked)), sqlb.Set(HostUpdated, p.core.Now())).Where(sqlb.Eq(HostID, host.ID))); err != nil {
		return RevokeHostResult{}, err
	}
	var ids []string
	var id string
	if err := p.core.Each(ctx, p.core.Select().Columns(sqlb.Bind(AgentID, &id)).From(TableAgent).Where(
		sqlb.Eq(AgentHost, host.ID), sqlb.NotIn(AgentStatusCol, string(AgentRevoked), string(AgentRejected))), func() error {
		ids = append(ids, id)
		return nil
	}); err != nil {
		return RevokeHostResult{}, err
	}
	for _, agentID := range ids {
		if err := p.revokeAgentRows(ctx, agentID); err != nil {
			return RevokeHostResult{}, err
		}
	}
	return RevokeHostResult{HostID: host.ID, Status: HostRevoked, AgentsRevoked: len(ids)}, nil
}

// RevokeCapabilityRequest revokes capabilities of one agent without
// revoking the agent: by the agent itself (an agent JWT), its host (a host
// JWT) or the signed-in user who owns it.
type RevokeCapabilityRequest struct {
	Bearer
	AgentID      string   `json:"agent_id,omitempty"`
	Capabilities []string `json:"capabilities"`
}

// RevokeCapabilityResult names the capabilities that had a grant to
// revoke, and the grants revoked. A capability with nothing to revoke is
// left out, so a repeated call answers empty lists.
type RevokeCapabilityResult struct {
	AgentID  string   `json:"agent_id"`
	Revoked  []string `json:"revoked"`
	GrantIDs []string `json:"grant_ids"`
}

// RevokeCapability revokes every active or pending grant of the named
// capabilities, under every constraint scope. Executing a revoked capability
// then answers ErrGrantRevoked, and the host's budget does not grant it
// again.
func (p *Plugin) RevokeCapability(ctx context.Context, in RevokeCapabilityRequest) (RevokeCapabilityResult, error) {
	return p.revokeCap.Call(ctx, in)
}

// doRevokeCapability leaves denied and consumed grants as they are: they
// authorize nothing already,
// and a consumed grant is the record that a single-use capability ran.
func (p *Plugin) doRevokeCapability(ctx context.Context, c *auth.Call, in RevokeCapabilityRequest) (RevokeCapabilityResult, error) {
	if len(in.Capabilities) == 0 {
		return RevokeCapabilityResult{}, ErrInvalidRequest
	}
	agent, err := p.callerAgent(ctx, c, in.Bearer, in.AgentID)
	if err != nil {
		return RevokeCapabilityResult{}, err
	}
	if agent.Status == string(AgentRevoked) {
		return RevokeCapabilityResult{}, ErrAgentRevoked
	}
	grants, err := p.loadGrants(ctx, agent.ID)
	if err != nil {
		return RevokeCapabilityResult{}, err
	}
	out := RevokeCapabilityResult{AgentID: agent.ID, Revoked: []string{}, GrantIDs: []string{}}
	for _, name := range in.Capabilities {
		if slices.Contains(out.Revoked, name) {
			continue
		}
		flipped := false
		for _, g := range grants {
			if g.Capability != name || (g.Status != string(GrantActive) && g.Status != string(GrantPending)) {
				continue
			}
			if err := p.setGrantStatus(ctx, g.ID, GrantRevoked); err != nil {
				return RevokeCapabilityResult{}, err
			}
			out.GrantIDs = append(out.GrantIDs, g.ID)
			flipped = true
		}
		if flipped {
			out.Revoked = append(out.Revoked, name)
		}
	}
	return out, nil
}

// ClaimRequest starts the claim of an autonomous agent, protocol section
// 3.4: a host (Bearer, a host JWT; under AllowDynamicHostRegistration a
// new host registers itself here, as at /agent/register) asks a user to
// take over the agent AgentID, typically one the user found on a resource
// the agent made.
type ClaimRequest struct {
	Bearer
	AgentID string `json:"agent_id"`
	ApprovalHints
}

// ClaimResult is the agent to be claimed and the approval the user must
// give: the user code to enter on the device authorization page.
type ClaimResult struct {
	AgentID  string      `json:"agent_id"`
	HostID   string      `json:"host_id"`
	Name     string      `json:"name"`
	Mode     Mode        `json:"mode"`
	Status   AgentStatus `json:"status"`
	Grants   []GrantView `json:"agent_capability_grants"`
	Approval *Approval   `json:"approval"`
}

// Claim records a claim request. A signed-in
// user approving it with ApproveCapability (its user code) becomes the
// agent's owner: the agent becomes AgentClaimed, which authenticates
// nothing more, and its host, when nobody owns it, becomes the user's.
func (p *Plugin) Claim(ctx context.Context, in ClaimRequest) (ClaimResult, error) {
	return p.claim.Call(ctx, in)
}

// doClaim always uses device authorization: the claimant is unknown until
// someone enters the code, and resolving a login hint here would tell the
// host whether the hint names an account. The request is marked
// ApprovalKindClaim, so only its own code claims the agent; approving any
// other request never claims it.
func (p *Plugin) doClaim(ctx context.Context, _ *auth.Call, in ClaimRequest) (ClaimResult, error) {
	if in.Token == "" {
		return ClaimResult{}, ErrAuthenticationRequired
	}
	if _, err := p.registerHost(ctx, RegisterRequest{Bearer: in.Bearer}, ModeDelegated); err != nil {
		return ClaimResult{}, err
	}
	agent, err := p.loadAgent(ctx, in.AgentID)
	if err != nil {
		return ClaimResult{}, err
	}
	if agent.Mode != string(ModeAutonomous) {
		return ClaimResult{}, ErrUnsupportedMode
	}
	switch AgentStatus(agent.Status) {
	case AgentClaimed:
		return ClaimResult{}, ErrAgentClaimed
	case AgentActive:
	default:
		return ClaimResult{}, ErrAgentNotFound
	}
	host, err := p.loadHost(ctx, agent.HostID)
	if err != nil {
		return ClaimResult{}, err
	}
	if host.UserID != nil {
		return ClaimResult{}, ErrAgentClaimed
	}
	grants, err := p.loadGrants(ctx, agent.ID)
	if err != nil {
		return ClaimResult{}, err
	}
	active := []string{}
	for _, g := range grants {
		if g.Status == string(GrantActive) {
			active = append(active, g.Capability)
		}
	}
	hints := ApprovalHints{PreferredMethod: MethodDeviceAuthorization, BindingMessage: in.BindingMessage}
	if hints.BindingMessage == "" {
		hints.BindingMessage = `Claim autonomous agent "` + agent.Name + `"`
	}
	kind := ApprovalKindClaim
	approval, err := p.newApproval(ctx, approvalInput{
		agentID: agent.ID, agentName: agent.Name, hostID: agent.HostID, capabilities: active, hints: hints, kind: &kind,
	})
	if err != nil {
		return ClaimResult{}, err
	}
	return ClaimResult{
		AgentID: agent.ID, HostID: agent.HostID, Name: agent.Name, Mode: ModeAutonomous, Status: AgentStatus(agent.Status),
		Grants: p.grantViews(grants), Approval: approval,
	}, nil
}

// matchClaim returns the pending claim request that code answers for
// agent, or nil when the call answers no claim and is an ordinary
// approval. named is the request the caller named by id, if any; a named
// claim must match its own code.
func (p *Plugin) matchClaim(ctx context.Context, agent agentRow, code string, named *approvalRow) (*approvalRow, error) {
	if agent.Mode != string(ModeAutonomous) {
		return nil, nil
	}
	var rows []approvalRow
	if named != nil {
		if deref(named.Kind) != ApprovalKindClaim {
			return nil, nil
		}
		if named.Status != string(ApprovalPending) {
			return nil, ErrApprovalResolved
		}
		rows = []approvalRow{*named}
	} else {
		pending, err := p.pendingApprovals(ctx, agent.ID)
		if err != nil {
			return nil, err
		}
		for _, r := range pending {
			if deref(r.Kind) == ApprovalKindClaim {
				rows = append(rows, r)
			}
		}
	}
	for _, r := range rows {
		if userCodeMatches(code, r.CodeHash) {
			if !r.ExpiresAt.After(p.core.Now()) {
				return nil, ErrApprovalExpired
			}
			return &r, nil
		}
	}
	if named != nil {
		return nil, ErrInvalidUserCode
	}
	return nil, nil
}

// answerClaim approves or denies a claim the user's code matched. Approval
// makes userID the agent's owner and marks it claimed, links its host to
// userID when nobody owns it yet, and resolves the agent's pending
// requests; a denial resolves only the claim.
func (p *Plugin) answerClaim(ctx context.Context, userID string, agent agentRow, claim approvalRow, action string) (ApproveResult, error) {
	// Revoked (or otherwise retired) since the claim was requested. A
	// claimed agent cannot be here: approving a claim resolves every
	// pending request of the agent, and Claim refuses a claimed one.
	if agent.Status != string(AgentActive) {
		return ApproveResult{}, ErrApprovalResolved
	}
	now := p.core.Now()
	if action == ActionDeny {
		if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableApproval).Set(
			sqlb.Set(ApprovalStatusCol, string(ApprovalDenied)), sqlb.Set(ApprovalUpdated, now)).Where(sqlb.Eq(ApprovalID, claim.ID))); err != nil {
			return ApproveResult{}, err
		}
		return ApproveResult{Status: ApprovalDenied, AgentID: agent.ID, Added: []string{}}, nil
	}
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableAgent).Set(
		sqlb.Set(AgentStatusCol, string(AgentClaimed)), sqlb.Set(AgentUser, &userID), sqlb.Set(AgentUpdated, now)).
		Where(sqlb.Eq(AgentID, agent.ID))); err != nil {
		return ApproveResult{}, err
	}
	host, err := p.loadHost(ctx, agent.HostID)
	switch {
	case errors.Is(err, ErrHostNotFound):
	case err != nil:
		return ApproveResult{}, err
	case host.UserID == nil:
		if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableHost).Set(
			sqlb.Set(HostUser, &userID), sqlb.Set(HostStatusCol, string(HostActive)), sqlb.Set(HostActivated, &now),
			sqlb.Set(HostUpdated, now)).Where(sqlb.Eq(HostID, host.ID))); err != nil {
			return ApproveResult{}, err
		}
	}
	if err := p.resolveApprovals(ctx, agent.ID, ApprovalApproved); err != nil {
		return ApproveResult{}, err
	}
	return ApproveResult{Status: ApprovalApproved, AgentID: agent.ID, Added: []string{}, Claimed: true}, nil
}

// UpdateAgentRequest renames an agent or replaces its metadata, for the
// signed-in user who owns it. A nil Name or empty Metadata leaves that
// field as it is; Metadata is a JSON object whose values are strings,
// numbers, booleans or null, and {} clears it.
type UpdateAgentRequest struct {
	AgentID  string          `json:"agent_id"`
	Name     *string         `json:"name,omitempty"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// UpdateAgentResult is the agent as stored after the update.
type UpdateAgentResult struct {
	AgentID   string          `json:"agent_id"`
	Name      string          `json:"name"`
	Metadata  json.RawMessage `json:"metadata"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// UpdateAgent updates an agent's name or metadata. The metadata is what
// AgentSession.Agent.Metadata carries to the app's routes.
func (p *Plugin) UpdateAgent(ctx context.Context, in UpdateAgentRequest) (UpdateAgentResult, error) {
	return p.updateAgent.Call(ctx, in)
}

// doUpdateAgent answers ErrAgentNotFound for an agent the user does not
// own, so an agent id reveals nothing to another user.
func (p *Plugin) doUpdateAgent(ctx context.Context, c *auth.Call, in UpdateAgentRequest) (UpdateAgentResult, error) {
	agent, err := p.loadAgent(ctx, in.AgentID)
	if err != nil {
		return UpdateAgentResult{}, err
	}
	if !p.ownedBy(ctx, agent, c.User.ID) {
		return UpdateAgentResult{}, ErrAgentNotFound
	}
	now := p.core.Now()
	sets := []sqlb.Assignment{sqlb.Set(AgentUpdated, now)}
	name := agent.Name
	if in.Name != nil {
		if name = truncate(*in.Name, maxNameRunes); name == "" {
			return UpdateAgentResult{}, ErrInvalidRequest
		}
		sets = append(sets, sqlb.Set(AgentName, name))
	}
	metadata := agent.Metadata
	if len(in.Metadata) > 0 {
		m, err := canonicalMetadata(in.Metadata)
		if err != nil {
			return UpdateAgentResult{}, err
		}
		metadata = &m
		sets = append(sets, sqlb.Set(AgentMetadata, metadata))
	}
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableAgent).Set(sets...).Where(sqlb.Eq(AgentID, agent.ID))); err != nil {
		return UpdateAgentResult{}, err
	}
	out := UpdateAgentResult{AgentID: agent.ID, Name: name, UpdatedAt: now}
	if metadata != nil {
		out.Metadata = json.RawMessage(*metadata)
	}
	return out, nil
}

// canonicalMetadata checks raw is a JSON object of primitive values within
// maxMetadataBytes, and returns it re-encoded compactly with sorted keys,
// so equal metadata is stored as equal text.
func canonicalMetadata(raw json.RawMessage) (string, error) {
	if len(raw) > maxMetadataBytes {
		return "", ErrInvalidRequest
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil || dec.More() {
		return "", ErrInvalidRequest
	}
	for _, v := range m {
		switch v.(type) {
		case string, json.Number, bool, nil:
		default:
			return "", ErrInvalidRequest
		}
	}
	b, _ := json.Marshal(m) // strings, numbers, booleans and null always encode
	return string(b), nil
}
