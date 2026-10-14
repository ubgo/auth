package agentauth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// ApprovalMethodContext is what an ApprovalMethodFunc chooses from,
// better-auth's resolveApprovalMethod context.
type ApprovalMethodContext struct {
	// UserID is the user the approval is for, nil when nobody owns the
	// agent or its host yet (only device authorization can serve that).
	UserID       *string
	AgentName    string
	HostID       string
	Capabilities []string
	// PreferredMethod is the agent's preferred_method, possibly empty.
	PreferredMethod string
	// SupportedMethods is ApprovalMethods.
	SupportedMethods []string
}

// ApprovalMethodFunc chooses the approval method of one request,
// better-auth's resolveApprovalMethod. A method outside SupportedMethods,
// or CIBA for a request with no user, falls back to device authorization.
type ApprovalMethodFunc func(ctx context.Context, mc ApprovalMethodContext) (string, error)

// ApprovalMethods narrows ApprovalMethodValues: the methods discovery lists
// and requests may use. Without MethodCIBA the CIBA endpoint answers
// invalid_request.
func ApprovalMethods(methods ...string) Option {
	return func(p *Plugin) { p.approvalMethods = methods }
}

// ResolveApprovalMethod installs an ApprovalMethodFunc. The default takes
// the agent's preferred_method when it is supported, and device
// authorization otherwise, as better-auth's default does.
func ResolveApprovalMethod(fn ApprovalMethodFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("agentauth.ResolveApprovalMethod", fn) {
			return
		}
		p.resolveMethod = fn
	}
}

// defaultApprovalMethod is better-auth's default resolveApprovalMethod.
func defaultApprovalMethod(_ context.Context, mc ApprovalMethodContext) (string, error) {
	if mc.PreferredMethod != "" && slices.Contains(mc.SupportedMethods, mc.PreferredMethod) {
		return mc.PreferredMethod, nil
	}
	return MethodDeviceAuthorization, nil
}

// ApprovalHints are the request fields that steer an approval, protocol
// section 9: the agent's preferred method, the CIBA login hint and the
// message shown to the user.
type ApprovalHints struct {
	PreferredMethod string `json:"preferred_method,omitempty"`
	LoginHint       string `json:"login_hint,omitempty"`
	BindingMessage  string `json:"binding_message,omitempty"`
}

// approvalInput is one approval to create, better-auth's buildApprovalInfo
// context.
type approvalInput struct {
	agentID, agentName, hostID string
	userID                     *string
	capabilities               []string
	hints                      ApprovalHints
	// kind is approvalRow.Kind: nil, or ApprovalKindClaim.
	kind *string
}

// newApproval records an approval request and returns what the agent shows
// or waits for, better-auth's buildApprovalInfo: CIBA when the method
// resolves to it and the request has a user, device authorization
// otherwise.
func (p *Plugin) newApproval(ctx context.Context, in approvalInput) (*Approval, error) {
	resolve := p.resolveMethod
	if resolve == nil {
		resolve = defaultApprovalMethod
	}
	method, err := resolve(ctx, ApprovalMethodContext{
		UserID: in.userID, AgentName: in.agentName, HostID: in.hostID, Capabilities: in.capabilities,
		PreferredMethod: in.hints.PreferredMethod, SupportedMethods: p.approvalMethods,
	})
	if err != nil {
		return nil, err
	}
	if !slices.Contains(p.approvalMethods, method) {
		method = MethodDeviceAuthorization
	}
	if method == MethodCIBA && in.userID != nil {
		binding := truncate(in.hints.BindingMessage, maxBindingRunes)
		if binding == "" {
			binding = `Agent "` + in.agentName + `" requesting approval`
		}
		if _, err := p.insertApproval(ctx, approvalRow{
			Method: MethodCIBA, AgentID: in.agentID, HostID: optional(in.hostID), UserID: in.userID,
			Capabilities: strings.Join(in.capabilities, " "), LoginHint: optional(truncate(in.hints.LoginHint, maxNameRunes)),
			BindingMessage: &binding, Kind: in.kind,
		}); err != nil {
			return nil, err
		}
		return &Approval{Method: MethodCIBA, ExpiresIn: int64(DefaultApprovalTTL / time.Second), Interval: int64(DefaultApprovalInterval / time.Second)}, nil
	}
	code := newUserCode()
	id, err := p.insertApproval(ctx, approvalRow{
		Method: MethodDeviceAuthorization, AgentID: in.agentID, HostID: optional(in.hostID), UserID: in.userID,
		Capabilities: strings.Join(in.capabilities, " "), CodeHash: hashUserCode(code),
		LoginHint: optional(truncate(in.hints.LoginHint, maxNameRunes)), BindingMessage: optional(truncate(in.hints.BindingMessage, maxBindingRunes)),
		Kind: in.kind,
	})
	if err != nil {
		return nil, err
	}
	page := p.devicePageURL()
	return &Approval{
		Method: MethodDeviceAuthorization, DeviceCode: id, VerificationURI: page,
		VerificationURIComplete: page + "?agent_id=" + in.agentID + "&code=" + code, UserCode: code,
		ExpiresIn: int64(DefaultApprovalTTL / time.Second), Interval: int64(DefaultApprovalInterval / time.Second),
	}, nil
}

// insertApproval writes a pending approval request expiring after
// DefaultApprovalTTL and returns its id; r's id, status and times are
// filled here. It reports approval.created.
func (p *Plugin) insertApproval(ctx context.Context, r approvalRow) (string, error) {
	id, err := p.core.NewID(prefixApproval)
	if err != nil {
		return "", err
	}
	now := p.core.Now()
	_, err = p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableApproval).Row(
		sqlb.Set(ApprovalID, id), sqlb.Set(ApprovalMethod, r.Method), sqlb.Set(ApprovalAgent, r.AgentID),
		sqlb.Set(ApprovalHost, r.HostID), sqlb.Set(ApprovalUser, r.UserID),
		sqlb.Set(ApprovalCapabilities, r.Capabilities), sqlb.Set(ApprovalStatusCol, string(ApprovalPending)),
		sqlb.Set(ApprovalCodeHash, r.CodeHash), sqlb.Set(ApprovalLoginHint, r.LoginHint), sqlb.Set(ApprovalBinding, r.BindingMessage),
		sqlb.Set(ApprovalKind, r.Kind),
		sqlb.Set(ApprovalInterval, int64(DefaultApprovalInterval/time.Second)),
		sqlb.Set(ApprovalExpires, now.Add(DefaultApprovalTTL)), sqlb.Set(ApprovalCreated, now), sqlb.Set(ApprovalUpdated, now)))
	if err != nil {
		return "", err
	}
	p.emitApproval(ctx, id, r)
	return id, nil
}

// CIBAAuthorizeRequest is a host's backchannel authentication request
// (protocol section 9.2): ask the user named by LoginHint to approve the
// host's agent AgentID. Bearer is the host's JWT.
type CIBAAuthorizeRequest struct {
	Bearer
	// LoginHint names the user by any sign-in identifier (an email, a
	// phone number, a username); only a verified one matches.
	LoginHint    string   `json:"login_hint"`
	Capabilities []string `json:"capabilities,omitempty"`
	// BindingMessage is shown to the user beside the request.
	BindingMessage string `json:"binding_message,omitempty"`
	AgentID        string `json:"agent_id"`
}

// CIBAAuthorizeResult is the request's handle. Its shape is the same
// whether or not LoginHint named a user, so it never reveals who has an
// account.
type CIBAAuthorizeResult struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int64  `json:"expires_in"`
	Interval  int64  `json:"interval"`
}

// CIBAAuthorize creates a CIBA approval request for the host that signed
// in.Token.
func (p *Plugin) CIBAAuthorize(ctx context.Context, in CIBAAuthorizeRequest) (CIBAAuthorizeResult, error) {
	return p.cibaAuthorize.Call(ctx, in)
}

// doCIBAAuthorize is better-auth's cibaAuthorize, with two differences:
// the agent must be one of the calling host's own (better-auth takes any
// agent id), and a login hint naming nobody records a request no user can
// answer instead of skipping the write, so both answers cost the same
// database round trip.
func (p *Plugin) doCIBAAuthorize(ctx context.Context, _ *auth.Call, in CIBAAuthorizeRequest) (CIBAAuthorizeResult, error) {
	if !slices.Contains(p.approvalMethods, MethodCIBA) || strings.TrimSpace(in.LoginHint) == "" || in.AgentID == "" {
		return CIBAAuthorizeResult{}, ErrInvalidRequest
	}
	if in.Token == "" {
		return CIBAAuthorizeResult{}, ErrAuthenticationRequired
	}
	vh, err := p.verifyHostJWT(ctx, in.Bearer, false)
	if err != nil {
		return CIBAAuthorizeResult{}, err
	}
	agent, err := p.loadAgent(ctx, in.AgentID)
	if err != nil {
		return CIBAAuthorizeResult{}, err
	}
	if agent.HostID != vh.host.ID {
		return CIBAAuthorizeResult{}, ErrAgentNotFound
	}
	reqs := make([]CapabilityRequest, 0, len(in.Capabilities))
	for _, c := range in.Capabilities {
		reqs = append(reqs, CapabilityRequest{Name: c})
	}
	if err := p.checkCapabilityNames(reqs); err != nil {
		return CIBAAuthorizeResult{}, err
	}
	userID, err := p.userByHint(ctx, in.LoginHint)
	if err != nil {
		return CIBAAuthorizeResult{}, err
	}
	binding := truncate(in.BindingMessage, maxBindingRunes)
	id, err := p.insertApproval(ctx, approvalRow{
		Method: MethodCIBA, AgentID: agent.ID, HostID: &vh.host.ID, UserID: userID,
		Capabilities: strings.Join(in.Capabilities, " "), LoginHint: optional(truncate(in.LoginHint, maxNameRunes)),
		BindingMessage: optional(binding),
	})
	if err != nil {
		return CIBAAuthorizeResult{}, err
	}
	return CIBAAuthorizeResult{AuthReqID: id, ExpiresIn: int64(DefaultApprovalTTL / time.Second), Interval: int64(DefaultApprovalInterval / time.Second)}, nil
}

// userByHint resolves a login hint to the user owning it as a verified
// sign-in identifier; nil when it names nobody.
func (p *Plugin) userByHint(ctx context.Context, hint string) (*string, error) {
	// A hint that is no sign-in identifier names nobody, like an unknown one.
	kind, _, detectErr := p.core.DetectKind(hint)
	if detectErr != nil {
		return nil, nil
	}
	idn, err := p.core.FindIdentity(ctx, kind, hint, true)
	switch {
	case errors.Is(err, auth.ErrIdentityNotFound):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return &idn.UserID, nil
}

// PendingApproval is one request waiting for the signed-in user, the
// CIBA pending list's entry.
type PendingApproval struct {
	ApprovalID     string   `json:"approval_id"`
	Method         string   `json:"method"`
	AgentID        string   `json:"agent_id"`
	AgentName      *string  `json:"agent_name"`
	BindingMessage *string  `json:"binding_message"`
	Capabilities   []string `json:"capabilities"`
	// CapabilityConstraints and CapabilityReasons are the agent's pending
	// grants' constraints and reasons, by capability.
	CapabilityConstraints map[string]Constraints `json:"capability_constraints"`
	CapabilityReasons     map[string]string      `json:"capability_reasons"`
	ExpiresIn             int64                  `json:"expires_in"`
	CreatedAt             time.Time              `json:"created_at"`
}

// PendingApprovals is the signed-in user's pending requests, newest first.
type PendingApprovals struct {
	Requests []PendingApproval `json:"requests"`
}

// PendingApprovalsFor lists the signed-in user's pending approval requests,
// better-auth's /agent/ciba/pending: what the app's approval inbox shows.
func (p *Plugin) PendingApprovalsFor(ctx context.Context) (PendingApprovals, error) {
	return p.pending.Call(ctx, struct{}{})
}

func (p *Plugin) doPendingApprovals(ctx context.Context, c *auth.Call, _ struct{}) (PendingApprovals, error) {
	now := p.core.Now()
	var r approvalRow
	var rows []approvalRow
	if err := p.core.Each(ctx, p.core.Select().Columns(r.bindings()...).From(TableApproval).Where(
		sqlb.Eq(ApprovalUser, &c.User.ID), sqlb.Eq(ApprovalStatusCol, string(ApprovalPending)), sqlb.Greater(ApprovalExpires, now)).
		Order(sqlb.OrderBy(ApprovalCreated, sqlb.SortDesc), sqlb.OrderBy(ApprovalID, sqlb.SortDesc)), func() error {
		rows = append(rows, r)
		return nil
	}); err != nil {
		return PendingApprovals{}, err
	}
	out := PendingApprovals{Requests: make([]PendingApproval, 0, len(rows))}
	for _, row := range rows {
		e := PendingApproval{
			ApprovalID: row.ID, Method: row.Method, AgentID: row.AgentID, BindingMessage: row.BindingMessage,
			Capabilities: strings.Fields(row.Capabilities), ExpiresIn: int64(row.ExpiresAt.Sub(now) / time.Second), CreatedAt: row.CreatedAt,
		}
		if agent, err := p.loadAgent(ctx, row.AgentID); err == nil {
			e.AgentName = &agent.Name
			grants, err := p.loadGrants(ctx, agent.ID)
			if err != nil {
				return PendingApprovals{}, err
			}
			for _, g := range grants {
				if g.Status != string(GrantPending) {
					continue
				}
				if cons, ok := g.constraints(); ok && len(cons) > 0 {
					if e.CapabilityConstraints == nil {
						e.CapabilityConstraints = map[string]Constraints{}
					}
					e.CapabilityConstraints[g.Capability] = cons
				}
				if g.Reason != nil && *g.Reason != "" {
					if e.CapabilityReasons == nil {
						e.CapabilityReasons = map[string]string{}
					}
					e.CapabilityReasons[g.Capability] = *g.Reason
				}
			}
		} else if !errors.Is(err, ErrAgentNotFound) {
			return PendingApprovals{}, err
		}
		out.Requests = append(out.Requests, e)
	}
	return out, nil
}

// loadApproval finds an approval request by id.
func (p *Plugin) loadApproval(ctx context.Context, id string) (approvalRow, error) {
	var r approvalRow
	err := p.core.One(ctx, p.core.Select().Columns(r.bindings()...).From(TableApproval).Where(sqlb.Eq(ApprovalID, id)))
	if errors.Is(err, sqlb.ErrNoRows) {
		return r, ErrApprovalNotFound
	}
	return r, err
}

// authorizeApproval decides whether userID may answer agent's pending
// requests. named is the request the caller named by id, if any. A device
// authorization request needs its user code, because any signed-in user
// could otherwise approve an agent nobody owns yet; a CIBA request is
// answered by the user it was addressed to, which the request itself
// proves; with neither pending, only the agent's or host's owner may
// answer.
func (p *Plugin) authorizeApproval(ctx context.Context, agent agentRow, userID, code string, named *approvalRow) error {
	now := p.core.Now()
	requests := []approvalRow{}
	if named != nil {
		if named.Status != string(ApprovalPending) {
			return ErrApprovalResolved
		}
		requests = append(requests, *named)
	} else {
		var err error
		if requests, err = p.pendingApprovals(ctx, agent.ID); err != nil {
			return err
		}
	}
	var device, ciba []approvalRow
	for _, r := range requests {
		if r.Method == MethodCIBA {
			ciba = append(ciba, r)
		} else {
			device = append(device, r)
		}
	}
	if len(device) > 0 {
		for _, r := range device {
			if userCodeMatches(code, r.CodeHash) {
				if !r.ExpiresAt.After(now) {
					return ErrApprovalExpired
				}
				return nil
			}
		}
		return ErrInvalidUserCode
	}
	if len(ciba) > 0 {
		expired := false
		for _, r := range ciba {
			if r.UserID == nil || *r.UserID != userID {
				continue
			}
			if r.ExpiresAt.After(now) {
				return nil
			}
			expired = true
		}
		if expired {
			return ErrApprovalExpired
		}
		return ErrApprovalOwnerMismatch
	}
	if !p.ownedBy(ctx, agent, userID) {
		return ErrInvalidUserCode
	}
	return nil
}
