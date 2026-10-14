package agentauth

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Catalogue paging, better-auth's list-capabilities defaults.
const (
	defaultListLimit = 100
	maxListLimit     = 100
)

// ListCapabilitiesRequest lists the catalogue, protocol section 6.2. Bearer
// is optional: with an agent JWT each entry says whether the agent holds
// it, with a host JWT whether the host's budget covers it.
type ListCapabilitiesRequest struct {
	Bearer
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

// InputField is one argument of a capability, from its input schema.
type InputField struct {
	Name        string          `json:"name"`
	Type        json.RawMessage `json:"type,omitempty"`
	Description json.RawMessage `json:"description,omitempty"`
}

// CapabilityView is a catalogue entry as an agent sees it.
type CapabilityView struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Location    string          `json:"location,omitempty"`
	Input       json.RawMessage `json:"input,omitempty"`
	Output      json.RawMessage `json:"output,omitempty"`
	InputFields []InputField    `json:"input_fields,omitempty"`
	// ApprovalStrength is the capability's, when it sets one.
	ApprovalStrength ApprovalStrength `json:"approval_strength,omitempty"`
	// GrantStatus is "granted" or "not_granted" for an authenticated
	// caller, and empty otherwise.
	GrantStatus string `json:"grant_status,omitempty"`
}

// Grant status words of the catalogue.
const (
	grantStatusGranted    = "granted"
	grantStatusNotGranted = "not_granted"
)

// CapabilityList is one page of the catalogue.
type CapabilityList struct {
	Capabilities []CapabilityView `json:"capabilities"`
	HasMore      bool             `json:"has_more"`
	NextCursor   string           `json:"next_cursor,omitempty"`
}

// ListCapabilities returns a page of the catalogue.
func (p *Plugin) ListCapabilities(ctx context.Context, in ListCapabilitiesRequest) (CapabilityList, error) {
	return p.listCaps.Call(ctx, in)
}

// callerGrants resolves an optional bearer to the names it holds: an
// agent's effective grants, or a host's budget. nil, nil for no bearer.
// RequireAuthForCapabilities makes a missing bearer an error; an invalid
// one is ignored otherwise, as better-auth's optional authentication does.
func (p *Plugin) callerGrants(ctx context.Context, b Bearer) ([]string, error) {
	if b.Token == "" {
		if p.requireAuthList {
			return nil, ErrAuthenticationRequired
		}
		return nil, nil
	}
	var held []string
	var err error
	if tokenType(b.Token) == TypeHostJWT {
		var vh verifiedHost
		if vh, err = p.verifyHostJWT(ctx, b, false); err == nil {
			held = append([]string{}, vh.host.budget()...)
		}
	} else {
		var v agentAuth
		if v, err = p.verifyAgent(ctx, b); err == nil {
			held = []string{}
			for _, g := range v.grants {
				held = append(held, g.Capability)
			}
		}
	}
	if err != nil {
		if p.requireAuthList {
			return nil, err
		}
		return nil, nil
	}
	return held, nil
}

// view is a catalogue entry for a caller holding held (nil: anonymous).
func view(c Capability, held []string) CapabilityView {
	v := CapabilityView{Name: c.Name, Description: c.Description, Location: c.Location, InputFields: inputFields(c.Input), ApprovalStrength: c.ApprovalStrength}
	if held != nil {
		v.GrantStatus = grantStatusNotGranted
		if hasCapability(held, c.Name) {
			v.GrantStatus = grantStatusGranted
		}
	}
	return v
}

// inputFields lists the properties of a JSON Schema object.
func inputFields(schema json.RawMessage) []InputField {
	var s struct {
		Properties map[string]struct {
			Type        json.RawMessage `json:"type"`
			Description json.RawMessage `json:"description"`
		} `json:"properties"`
	}
	if len(schema) == 0 || json.Unmarshal(schema, &s) != nil {
		return nil
	}
	out := make([]InputField, 0, len(s.Properties))
	for name, prop := range s.Properties {
		out = append(out, InputField{Name: name, Type: prop.Type, Description: prop.Description})
	}
	slices.SortFunc(out, func(a, b InputField) int { return strings.Compare(a.Name, b.Name) })
	return out
}

func (p *Plugin) doListCapabilities(ctx context.Context, _ *auth.Call, in ListCapabilitiesRequest) (CapabilityList, error) {
	held, err := p.callerGrants(ctx, in.Bearer)
	if err != nil {
		return CapabilityList{}, err
	}
	limit := in.Limit
	if limit <= 0 || limit > maxListLimit {
		limit = defaultListLimit
	}
	start := 0
	if in.Cursor != "" {
		if start, err = strconv.Atoi(in.Cursor); err != nil || start < 0 {
			return CapabilityList{}, ErrInvalidRequest
		}
	}
	out := CapabilityList{Capabilities: []CapabilityView{}}
	for i := start; i < len(p.capabilities) && i < start+limit; i++ {
		out.Capabilities = append(out.Capabilities, view(p.capabilities[i], held))
	}
	if start+limit < len(p.capabilities) {
		out.HasMore, out.NextCursor = true, strconv.Itoa(start+limit)
	}
	return out, nil
}

// DescribeCapabilityRequest names one capability, protocol section 6.2.1.
type DescribeCapabilityRequest struct {
	Bearer
	Name string `json:"name"`
}

// DescribeCapability returns one catalogue entry with its schemas.
func (p *Plugin) DescribeCapability(ctx context.Context, in DescribeCapabilityRequest) (CapabilityView, error) {
	return p.describeCap.Call(ctx, in)
}

func (p *Plugin) doDescribeCapability(ctx context.Context, _ *auth.Call, in DescribeCapabilityRequest) (CapabilityView, error) {
	held, err := p.callerGrants(ctx, in.Bearer)
	if err != nil {
		return CapabilityView{}, err
	}
	def, ok := p.capability(in.Name)
	if !ok {
		return CapabilityView{}, ErrCapabilityNotFound
	}
	v := view(def, held)
	v.Input, v.Output = def.Input, def.Output
	return v, nil
}

// RequestCapabilityRequest asks for more capabilities, protocol section
// 6.4. Bearer is the agent's JWT.
type RequestCapabilityRequest struct {
	Bearer
	Capabilities []CapabilityRequest `json:"capabilities"`
	Reason       string              `json:"reason,omitempty"`
	// ApprovalHints steer the approval when one is needed.
	ApprovalHints
}

// RequestCapabilityResult is the requested grants, and the approval when
// some wait for a user.
type RequestCapabilityResult struct {
	AgentID  string      `json:"agent_id"`
	Status   AgentStatus `json:"status"`
	Grants   []GrantView `json:"agent_capability_grants"`
	Approval *Approval   `json:"approval,omitempty"`
}

// RequestCapability requests capabilities for the agent that signed
// in.Token.
func (p *Plugin) RequestCapability(ctx context.Context, in RequestCapabilityRequest) (RequestCapabilityResult, error) {
	return p.requestCap.Call(ctx, in)
}

func (p *Plugin) doRequestCapability(ctx context.Context, _ *auth.Call, in RequestCapabilityRequest) (RequestCapabilityResult, error) {
	if in.Token == "" {
		return RequestCapabilityResult{}, ErrAuthenticationRequired
	}
	if len(in.Capabilities) == 0 {
		return RequestCapabilityResult{}, ErrInvalidRequest
	}
	if err := p.checkCapabilityNames(in.Capabilities); err != nil {
		return RequestCapabilityResult{}, err
	}
	v, err := p.verifyAgent(ctx, in.Bearer)
	if err != nil {
		return RequestCapabilityResult{}, err
	}
	all, err := p.loadGrants(ctx, v.agent.ID)
	if err != nil {
		return RequestCapabilityResult{}, err
	}
	now := p.core.Now()
	var owner *string
	if v.host != nil {
		owner = v.host.UserID
	}
	covered := func(r CapabilityRequest, status GrantStatus) bool {
		for _, g := range all {
			if g.Capability != r.Name || g.Status != string(status) || (status == GrantActive && !g.liveAt(now)) {
				continue
			}
			if status == GrantPending && g.GrantedBy != nil && (owner == nil || *g.GrantedBy != *owner) {
				continue
			}
			if c, ok := g.constraints(); ok && c.Covers(r.Constraints) {
				return true
			}
		}
		return false
	}
	var fresh []CapabilityRequest
	allActive := true
	for _, r := range in.Capabilities {
		active := covered(r, GrantActive)
		allActive = allActive && active
		if !active && !covered(r, GrantPending) {
			fresh = append(fresh, r)
		}
	}
	if len(fresh) == 0 {
		if allActive {
			return RequestCapabilityResult{}, ErrAlreadyGranted
		}
		approval, err := p.newApproval(ctx, approvalInput{agentID: v.agent.ID, agentName: v.agent.Name, hostID: v.agent.HostID, userID: owner, capabilities: names(in.Capabilities), hints: in.ApprovalHints})
		if err != nil {
			return RequestCapabilityResult{}, err
		}
		return RequestCapabilityResult{AgentID: v.agent.ID, Status: AgentPending, Grants: p.grantViews(filterRequested(all, in.Capabilities)), Approval: approval}, nil
	}
	// A capability the user revoked or denied before is an explicit "no":
	// it goes back to the user even when the budget covers it.
	refused := func(name string) bool {
		return slices.ContainsFunc(all, func(g grantRow) bool {
			return g.Capability == name && (g.Status == string(GrantRevoked) || g.Status == string(GrantDenied))
		})
	}
	var budget []string
	if v.host != nil && v.host.Status == string(HostActive) {
		budget = v.host.budget()
	}
	reason := truncate(in.Reason, maxReasonRunes)
	var pending []CapabilityRequest
	for _, r := range fresh {
		if hasCapability(budget, r.Name) && !refused(r.Name) {
			if err := p.insertGrant(ctx, v.agent.ID, r.Name, r.Constraints, owner, GrantActive, reason, p.grantExpiry(r.Name)); err != nil {
				return RequestCapabilityResult{}, err
			}
			continue
		}
		pending = append(pending, r)
	}
	if Mode(v.agent.Mode) == ModeAutonomous && owner == nil {
		pending = nil
	}
	for _, r := range pending {
		if err := p.insertGrant(ctx, v.agent.ID, r.Name, r.Constraints, owner, GrantPending, reason, nil); err != nil {
			return RequestCapabilityResult{}, err
		}
	}
	if all, err = p.loadGrants(ctx, v.agent.ID); err != nil {
		return RequestCapabilityResult{}, err
	}
	out := RequestCapabilityResult{AgentID: v.agent.ID, Status: AgentActive, Grants: p.grantViews(filterRequested(all, in.Capabilities))}
	if len(pending) > 0 {
		out.Status = AgentPending
		if out.Approval, err = p.newApproval(ctx, approvalInput{agentID: v.agent.ID, agentName: v.agent.Name, hostID: v.agent.HostID, userID: owner, capabilities: names(pending), hints: in.ApprovalHints}); err != nil {
			return RequestCapabilityResult{}, err
		}
	}
	return out, nil
}

// ApproveRequest is a signed-in user's answer to a pending agent or
// capability request. A device authorization request needs its user code;
// a CIBA request is answered by the user it was addressed to; with neither
// pending, only the agent's or host's owner may answer.
type ApproveRequest struct {
	// AgentID names the agent; ApprovalID names one approval request
	// instead (the CIBA inbox's approval_id). One of them is required.
	AgentID    string `json:"agent_id,omitempty"`
	ApprovalID string `json:"approval_id,omitempty"`
	// UserCode is the code the agent showed the user.
	UserCode string `json:"user_code,omitempty"`
	// Action is ActionApprove or ActionDeny.
	Action string `json:"action"`
	// Capabilities narrows an approval to these names; the rest are
	// denied. Empty approves every pending capability.
	Capabilities []string `json:"capabilities,omitempty"`
	// TTLSeconds overrides the approved grants' lifetime.
	TTLSeconds int64  `json:"ttl,omitempty"`
	Reason     string `json:"reason,omitempty"`
	// WebAuthn answers the challenge of an earlier ApprovalWebAuthnRequired
	// result.
	WebAuthn *PresenceResponse `json:"webauthn_response,omitempty"`
}

// ApproveResult is the outcome. Status ApprovalWebAuthnRequired approved
// nothing yet: answer WebAuthn and call again.
type ApproveResult struct {
	Status   ApprovalStatus     `json:"status"`
	AgentID  string             `json:"agent_id"`
	Added    []string           `json:"added"`
	WebAuthn *PresenceChallenge `json:"webauthn,omitempty"`
	// Claimed reports an approved claim (Claim): the user now owns the
	// agent, which is AgentClaimed.
	Claimed bool `json:"claimed,omitempty"`
}

// ApproveCapability answers a pending request for the signed-in user. It
// needs a fresh sign-in, as better-auth's freshSessionWindow does.
func (p *Plugin) ApproveCapability(ctx context.Context, in ApproveRequest) (ApproveResult, error) {
	return p.approve.Call(ctx, in)
}

func (p *Plugin) doApprove(ctx context.Context, c *auth.Call, in ApproveRequest) (ApproveResult, error) {
	if in.Action != ActionApprove && in.Action != ActionDeny {
		return ApproveResult{}, ErrInvalidRequest
	}
	if in.AgentID == "" && in.ApprovalID == "" {
		return ApproveResult{}, ErrInvalidRequest
	}
	userID := c.User.ID
	agentID := in.AgentID
	var named *approvalRow
	if in.ApprovalID != "" {
		r, err := p.loadApproval(ctx, in.ApprovalID)
		if err != nil {
			return ApproveResult{}, err
		}
		if in.AgentID != "" && in.AgentID != r.AgentID {
			return ApproveResult{}, ErrApprovalNotFound
		}
		named, agentID = &r, r.AgentID
	}
	agent, err := p.loadAgent(ctx, agentID)
	if err != nil {
		return ApproveResult{}, err
	}
	claim, err := p.matchClaim(ctx, agent, in.UserCode, named)
	if err != nil {
		return ApproveResult{}, err
	}
	if claim != nil {
		return p.answerClaim(ctx, userID, agent, *claim, in.Action)
	}
	if agent.UserID != nil && *agent.UserID != userID {
		return ApproveResult{}, ErrApprovalOwnerMismatch
	}
	if err := p.authorizeApproval(ctx, agent, userID, in.UserCode, named); err != nil {
		return ApproveResult{}, err
	}
	now := p.core.Now()
	all, err := p.loadGrants(ctx, agent.ID)
	if err != nil {
		return ApproveResult{}, err
	}
	var pendingGrants []grantRow
	for _, g := range all {
		if g.Status == string(GrantPending) {
			pendingGrants = append(pendingGrants, g)
		}
	}
	agentPending := agent.Status == string(AgentPending)
	if len(pendingGrants) == 0 && !agentPending {
		return ApproveResult{}, ErrApprovalResolved
	}
	if in.Action == ActionDeny {
		for _, g := range pendingGrants {
			if err := p.setGrantStatus(ctx, g.ID, GrantDenied); err != nil {
				return ApproveResult{}, err
			}
		}
		if agentPending {
			if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableAgent).Set(
				sqlb.Set(AgentStatusCol, string(AgentRejected)), sqlb.Set(AgentUser, &userID), sqlb.Set(AgentUpdated, now)).
				Where(sqlb.Eq(AgentID, agent.ID))); err != nil {
				return ApproveResult{}, err
			}
		}
		if err := p.resolveApprovals(ctx, agent.ID, ApprovalDenied); err != nil {
			return ApproveResult{}, err
		}
		return ApproveResult{Status: ApprovalDenied, AgentID: agent.ID, Added: []string{}}, nil
	}
	approved := in.Capabilities
	if len(approved) == 0 {
		for _, g := range pendingGrants {
			approved = append(approved, g.Capability)
		}
	}
	presence, err := p.needsPresence(ctx, agent, len(pendingGrants), approved)
	if err != nil {
		return ApproveResult{}, err
	}
	if presence {
		challenge, err := p.checkPresence(ctx, userID, agent.ID, in.WebAuthn)
		if err != nil {
			return ApproveResult{}, err
		}
		if challenge != nil {
			return ApproveResult{Status: ApprovalWebAuthnRequired, AgentID: agent.ID, Added: []string{}, WebAuthn: challenge}, nil
		}
	}
	for _, name := range approved {
		for _, b := range p.blocked {
			if capabilityCovers(b, name) {
				return ApproveResult{}, ErrCapabilityBlocked
			}
		}
	}
	added := []string{}
	for _, g := range pendingGrants {
		if !slices.Contains(approved, g.Capability) {
			if err := p.setGrantStatus(ctx, g.ID, GrantDenied); err != nil {
				return ApproveResult{}, err
			}
			continue
		}
		// A live active grant that covers this one makes it redundant; a
		// lapsed one (past its GrantTTL) does not, or approving a request
		// made after the lapse would grant nothing.
		cons, _ := g.constraints()
		if slices.ContainsFunc(all, func(a grantRow) bool {
			ac, ok := a.constraints()
			return a.Capability == g.Capability && a.Status == string(GrantActive) && a.liveAt(now) && ok && ac.Covers(cons)
		}) {
			if _, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableGrant).Where(sqlb.Eq(GrantID, g.ID))); err != nil {
				return ApproveResult{}, err
			}
			continue
		}
		exp := p.grantExpiry(g.Capability)
		if in.TTLSeconds > 0 {
			t := now.Add(time.Duration(in.TTLSeconds) * time.Second)
			exp = &t
		}
		if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableGrant).Set(
			sqlb.Set(GrantStatusCol, string(GrantActive)), sqlb.Set(GrantExpires, exp), sqlb.Set(GrantGrantedBy, &userID),
			sqlb.Set(GrantUpdated, now)).Where(sqlb.Eq(GrantID, g.ID))); err != nil {
			return ApproveResult{}, err
		}
		added = append(added, g.Capability)
	}
	if err := p.resolveApprovals(ctx, agent.ID, ApprovalApproved); err != nil {
		return ApproveResult{}, err
	}
	if agentPending {
		if err := p.activatePendingAgent(ctx, agent, userID); err != nil {
			return ApproveResult{}, err
		}
	}
	return ApproveResult{Status: ApprovalApproved, AgentID: agent.ID, Added: added}, nil
}

// activatePendingAgent makes an approved agent active for userID, and
// links its host to userID when the host had no owner, better-auth's
// activatePendingAgent. A host owned by someone else is left as it is;
// better-auth transfers it and revokes the previous owner's agents, which
// this port does not.
func (p *Plugin) activatePendingAgent(ctx context.Context, agent agentRow, userID string) error {
	now := p.core.Now()
	sets := []sqlb.Assignment{sqlb.Set(AgentStatusCol, string(AgentActive)), sqlb.Set(AgentUser, &userID), sqlb.Set(AgentActivated, &now), sqlb.Set(AgentUpdated, now)}
	if p.sessionTTL > 0 {
		exp := p.slidingExpiry(agent.CreatedAt, now, now)
		sets = append(sets, sqlb.Set(AgentExpires, &exp))
	}
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableAgent).Set(sets...).Where(sqlb.Eq(AgentID, agent.ID))); err != nil {
		return err
	}
	host, err := p.loadHost(ctx, agent.HostID)
	if errors.Is(err, ErrHostNotFound) {
		return nil
	}
	if err != nil || host.UserID != nil {
		return err
	}
	budget, err := p.hostBudget(ctx, HostCapabilitiesContext{UserID: &userID, HostID: host.ID, HostName: deref(host.Name)})
	if err != nil {
		return err
	}
	_, err = p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableHost).Set(
		sqlb.Set(HostUser, &userID), sqlb.Set(HostStatusCol, string(HostActive)), sqlb.Set(HostActivated, &now),
		sqlb.Set(HostDefaultCaps, encodeNames(budget)), sqlb.Set(HostUpdated, now)).Where(sqlb.Eq(HostID, host.ID)))
	return err
}

// ExecuteRequest runs a capability, protocol section 6.11. Bearer is the
// agent's JWT.
type ExecuteRequest struct {
	Bearer
	Capability string `json:"capability"`
	// Arguments are the capability's arguments, as JSON decoded them.
	Arguments map[string]any `json:"arguments,omitempty"`
}

// ExecuteResult is the capability's result, better-auth's sync answer.
type ExecuteResult struct {
	// Data is whatever ExecuteFunc returned, for the JSON encoder.
	Data any `json:"data"`
}

// Execution is what ExecuteFunc receives.
type Execution struct {
	Capability Capability
	Arguments  map[string]any
	Session    AgentSession
	// GrantID is the grant that authorized the call.
	GrantID string
	// ConsumeGrant spends the grant, for a single-use capability such as a
	// payment: it becomes GrantConsumed and authorizes nothing more.
	ConsumeGrant func(ctx context.Context) error
}

// Execute runs a capability for the agent that signed in.Token.
func (p *Plugin) Execute(ctx context.Context, in ExecuteRequest) (ExecuteResult, error) {
	return p.execute.Call(ctx, in)
}

func (p *Plugin) doExecute(ctx context.Context, _ *auth.Call, in ExecuteRequest) (ExecuteResult, error) {
	if in.Token == "" {
		return ExecuteResult{}, ErrAuthenticationRequired
	}
	v, err := p.verifyAgent(ctx, in.Bearer)
	if err != nil {
		return ExecuteResult{}, err
	}
	def, ok := p.capability(in.Capability)
	if !ok {
		return ExecuteResult{}, ErrCapabilityNotFound
	}
	grant, err := p.grantFor(ctx, v, in.Capability, in.Arguments)
	if err != nil {
		return ExecuteResult{}, err
	}
	if p.onExecute == nil {
		return ExecuteResult{}, ErrExecuteNotConfigured
	}
	data, err := p.onExecute(ctx, Execution{
		Capability: def, Arguments: in.Arguments, Session: v.session, GrantID: grant.ID,
		ConsumeGrant: func(ctx context.Context) error { return p.setGrantStatus(ctx, grant.ID, GrantConsumed) },
	})
	if err != nil {
		var ae *auth.Error
		if errors.As(err, &ae) {
			return ExecuteResult{}, err
		}
		return ExecuteResult{}, errors.Join(auth.ErrInternal, err)
	}
	return ExecuteResult{Data: data}, nil
}

// grantFor finds the grant that allows capability with args, better-auth's
// execute rules: an effective grant whose constraints the arguments
// satisfy; else, when the agent holds the capability only under
// constraints these arguments break, the constraint error; else a grant
// made now from the host's budget, unless the user revoked or denied the
// capability before; else grant_revoked or capability_not_granted.
func (p *Plugin) grantFor(ctx context.Context, v agentAuth, capability string, args map[string]any) (grantRow, error) {
	var constrained []Constraints
	for _, g := range v.grants {
		if g.Capability != capability {
			continue
		}
		c, ok := g.constraints()
		if !ok {
			continue
		}
		if c == nil || c.Validate(args) == nil {
			return g, nil
		}
		constrained = append(constrained, c)
	}
	if len(constrained) > 0 {
		return grantRow{}, constrained[0].Validate(args)
	}
	all, err := p.loadGrants(ctx, v.agent.ID)
	if err != nil {
		return grantRow{}, err
	}
	revoked, refused := false, false
	for _, g := range all {
		if g.Capability == capability {
			revoked = revoked || g.Status == string(GrantRevoked)
			refused = refused || g.Status == string(GrantRevoked) || g.Status == string(GrantDenied)
		}
	}
	if v.host != nil && v.host.Status == string(HostActive) && !refused && hasCapability(v.host.budget(), capability) {
		if err := p.insertGrant(ctx, v.agent.ID, capability, nil, v.host.UserID, GrantActive, reasonAutoGranted, p.grantExpiry(capability)); err != nil {
			return grantRow{}, err
		}
		all, err := p.loadGrants(ctx, v.agent.ID)
		if err != nil {
			return grantRow{}, err
		}
		now := p.core.Now()
		for i := len(all) - 1; i >= 0; i-- {
			if all[i].Capability == capability && all[i].liveAt(now) {
				return all[i], nil
			}
		}
	}
	if revoked {
		return grantRow{}, ErrGrantRevoked
	}
	return grantRow{}, ErrCapabilityNotGranted
}

// reasonAutoGranted marks a grant made from the host's budget at execution.
const reasonAutoGranted = "auto_granted_from_host_budget"
