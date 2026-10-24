package agentauth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/ubgo/sqlb"
)

// ID prefixes, so an id names its kind.
const (
	prefixHost     = "agh"
	prefixAgent    = "agt"
	prefixGrant    = "agg"
	prefixApproval = "aga"
)

// hostRow is one auth_agent_host row.
type hostRow struct {
	ID          string
	Name        *string
	UserID      *string
	DefaultCaps string
	PublicKey   string
	Kid         string
	Status      string
	ActivatedAt *time.Time
	ExpiresAt   *time.Time
	LastUsedAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
	// JWKSURL is set for a host whose keys are fetched (AllowJWKSURLs);
	// PublicKey is then "".
	JWKSURL *string
	// EnrollUntil is the enrollment token's expiry while the host is
	// HostPendingEnrollment. The token's hash is only ever matched in SQL.
	EnrollUntil *time.Time
}

func (r *hostRow) bindings() []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(HostID, &r.ID), sqlb.Bind(HostName, &r.Name), sqlb.Bind(HostUser, &r.UserID),
		sqlb.Bind(HostDefaultCaps, &r.DefaultCaps), sqlb.Bind(HostPublicKey, &r.PublicKey), sqlb.Bind(HostKid, &r.Kid),
		sqlb.Bind(HostStatusCol, &r.Status), sqlb.Bind(HostActivated, &r.ActivatedAt), sqlb.Bind(HostExpires, &r.ExpiresAt),
		sqlb.Bind(HostLastUsed, &r.LastUsedAt), sqlb.Bind(HostCreated, &r.CreatedAt), sqlb.Bind(HostUpdated, &r.UpdatedAt),
		sqlb.Bind(HostJWKSURL, &r.JWKSURL), sqlb.Bind(HostEnrollUntil, &r.EnrollUntil),
	}
}

// budget is the host's default capabilities.
func (r *hostRow) budget() []string { return decodeNames(r.DefaultCaps) }

// agentRow is one auth_agent row.
type agentRow struct {
	ID          string
	Name        string
	UserID      *string
	HostID      string
	Status      string
	Mode        string
	PublicKey   string
	Kid         *string
	LastUsedAt  *time.Time
	ActivatedAt *time.Time
	ExpiresAt   *time.Time
	Metadata    *string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	// JWKSURL is set for an agent whose keys are fetched (AllowJWKSURLs);
	// PublicKey is then "".
	JWKSURL *string
}

func (r *agentRow) bindings() []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(AgentID, &r.ID), sqlb.Bind(AgentName, &r.Name), sqlb.Bind(AgentUser, &r.UserID),
		sqlb.Bind(AgentHost, &r.HostID), sqlb.Bind(AgentStatusCol, &r.Status), sqlb.Bind(AgentMode, &r.Mode),
		sqlb.Bind(AgentPublicKey, &r.PublicKey), sqlb.Bind(AgentKid, &r.Kid), sqlb.Bind(AgentLastUsed, &r.LastUsedAt),
		sqlb.Bind(AgentActivated, &r.ActivatedAt), sqlb.Bind(AgentExpires, &r.ExpiresAt), sqlb.Bind(AgentMetadata, &r.Metadata),
		sqlb.Bind(AgentCreated, &r.CreatedAt), sqlb.Bind(AgentUpdated, &r.UpdatedAt), sqlb.Bind(AgentJWKSURL, &r.JWKSURL),
	}
}

// grantRow is one auth_agent_grant row.
type grantRow struct {
	ID          string
	AgentID     string
	Capability  string
	Constraints *string
	GrantedBy   *string
	DeniedBy    *string
	Reason      *string
	Status      string
	ExpiresAt   *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (r *grantRow) bindings() []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(GrantID, &r.ID), sqlb.Bind(GrantAgent, &r.AgentID), sqlb.Bind(GrantCapability, &r.Capability),
		sqlb.Bind(GrantConstraints, &r.Constraints), sqlb.Bind(GrantGrantedBy, &r.GrantedBy), sqlb.Bind(GrantDeniedBy, &r.DeniedBy),
		sqlb.Bind(GrantReason, &r.Reason), sqlb.Bind(GrantStatusCol, &r.Status), sqlb.Bind(GrantExpires, &r.ExpiresAt),
		sqlb.Bind(GrantCreated, &r.CreatedAt), sqlb.Bind(GrantUpdated, &r.UpdatedAt),
	}
}

// constraints decodes the grant's constraints; nil is unrestricted. A
// stored value that does not decode restricts everything: it matches no
// arguments, because a grant must never widen by being unreadable.
func (r *grantRow) constraints() (Constraints, bool) {
	if r.Constraints == nil {
		return nil, true
	}
	var c Constraints
	if err := json.Unmarshal([]byte(*r.Constraints), &c); err != nil {
		return nil, false
	}
	return c, true
}

// liveAt reports an active grant that has not expired at now.
func (r *grantRow) liveAt(now time.Time) bool {
	return r.Status == string(GrantActive) && (r.ExpiresAt == nil || r.ExpiresAt.After(now))
}

// approvalRow is one auth_agent_approval row.
type approvalRow struct {
	ID           string
	Method       string
	AgentID      string
	HostID       *string
	UserID       *string
	Capabilities string
	Status       string
	// CodeHash is nil for a CIBA request, which has no user code.
	CodeHash       []byte
	LoginHint      *string
	BindingMessage *string
	// Kind is nil for a capability request, ApprovalKindClaim for a claim.
	Kind      *string
	Interval  int64
	ExpiresAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (r *approvalRow) bindings() []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(ApprovalID, &r.ID), sqlb.Bind(ApprovalMethod, &r.Method), sqlb.Bind(ApprovalAgent, &r.AgentID),
		sqlb.Bind(ApprovalHost, &r.HostID), sqlb.Bind(ApprovalUser, &r.UserID), sqlb.Bind(ApprovalCapabilities, &r.Capabilities),
		sqlb.Bind(ApprovalStatusCol, &r.Status), sqlb.Bind(ApprovalCodeHash, &r.CodeHash), sqlb.Bind(ApprovalInterval, &r.Interval),
		sqlb.Bind(ApprovalLoginHint, &r.LoginHint), sqlb.Bind(ApprovalBinding, &r.BindingMessage), sqlb.Bind(ApprovalKind, &r.Kind),
		sqlb.Bind(ApprovalExpires, &r.ExpiresAt), sqlb.Bind(ApprovalCreated, &r.CreatedAt), sqlb.Bind(ApprovalUpdated, &r.UpdatedAt),
	}
}

// loadHost finds a host by id, or by kid (the key's kid or thumbprint).
func (p *Plugin) loadHost(ctx context.Context, idOrKid string) (hostRow, error) {
	var r hostRow
	if idOrKid == "" {
		return r, ErrHostNotFound
	}
	err := p.core.One(ctx, p.core.Select().Columns(r.bindings()...).From(TableHost).Where(sqlb.Eq(HostID, idOrKid)))
	if errors.Is(err, sqlb.ErrNoRows) {
		err = p.core.One(ctx, p.core.Select().Columns(r.bindings()...).From(TableHost).Where(sqlb.Eq(HostKid, idOrKid)).
			Order(sqlb.OrderBy(HostCreated, sqlb.SortAsc), sqlb.OrderBy(HostID, sqlb.SortAsc)).Limit(1))
	}
	if errors.Is(err, sqlb.ErrNoRows) {
		return r, ErrHostNotFound
	}
	return r, err
}

// loadAgent finds an agent by id.
func (p *Plugin) loadAgent(ctx context.Context, id string) (agentRow, error) {
	var r agentRow
	if id == "" {
		return r, ErrAgentNotFound
	}
	err := p.core.One(ctx, p.core.Select().Columns(r.bindings()...).From(TableAgent).Where(sqlb.Eq(AgentID, id)))
	if errors.Is(err, sqlb.ErrNoRows) {
		return r, ErrAgentNotFound
	}
	return r, err
}

// loadGrants returns every grant of an agent, oldest first.
func (p *Plugin) loadGrants(ctx context.Context, agentID string) ([]grantRow, error) {
	var r grantRow
	var out []grantRow
	err := p.core.Each(ctx, p.core.Select().Columns(r.bindings()...).From(TableGrant).Where(sqlb.Eq(GrantAgent, agentID)).
		Order(sqlb.OrderBy(GrantCreated, sqlb.SortAsc), sqlb.OrderBy(GrantID, sqlb.SortAsc)), func() error {
		out = append(out, r)
		return nil
	})
	return out, err
}

// pendingApprovals returns an agent's pending approval requests.
func (p *Plugin) pendingApprovals(ctx context.Context, agentID string) ([]approvalRow, error) {
	var r approvalRow
	var out []approvalRow
	err := p.core.Each(ctx, p.core.Select().Columns(r.bindings()...).From(TableApproval).Where(
		sqlb.Eq(ApprovalAgent, agentID), sqlb.Eq(ApprovalStatusCol, string(ApprovalPending))).
		Order(sqlb.OrderBy(ApprovalCreated, sqlb.SortAsc), sqlb.OrderBy(ApprovalID, sqlb.SortAsc)), func() error {
		out = append(out, r)
		return nil
	})
	return out, err
}

// insertGrant writes one grant.
func (p *Plugin) insertGrant(ctx context.Context, agentID, capability string, constraints Constraints, grantedBy *string, status GrantStatus, reason string, expires *time.Time) error {
	id, err := p.core.NewID(prefixGrant)
	if err != nil {
		return err
	}
	var cons *string
	if constraints != nil {
		b, err := json.Marshal(constraints)
		if err != nil {
			return err
		}
		s := string(b)
		cons = &s
	}
	now := p.core.Now()
	_, err = p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableGrant).Row(
		sqlb.Set(GrantID, id), sqlb.Set(GrantAgent, agentID), sqlb.Set(GrantCapability, capability),
		sqlb.Set(GrantConstraints, cons), sqlb.Set(GrantGrantedBy, grantedBy), sqlb.Set(GrantDeniedBy, (*string)(nil)),
		sqlb.Set(GrantReason, optional(reason)), sqlb.Set(GrantStatusCol, string(status)), sqlb.Set(GrantExpires, expires),
		sqlb.Set(GrantCreated, now), sqlb.Set(GrantUpdated, now)))
	return err
}

// setGrantStatus moves one grant to status.
func (p *Plugin) setGrantStatus(ctx context.Context, id string, status GrantStatus) error {
	_, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableGrant).
		Set(sqlb.Set(GrantStatusCol, string(status)), sqlb.Set(GrantUpdated, p.core.Now())).Where(sqlb.Eq(GrantID, id)))
	return err
}

// revokeAgentRows revokes an agent and every grant it holds, and clears its
// key so nothing it signed verifies again.
func (p *Plugin) revokeAgentRows(ctx context.Context, agentID string) error {
	now := p.core.Now()
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableAgent).Set(
		sqlb.Set(AgentStatusCol, string(AgentRevoked)), sqlb.Set(AgentPublicKey, ""), sqlb.Set(AgentKid, (*string)(nil)),
		sqlb.Set(AgentJWKSURL, (*string)(nil)), sqlb.Set(AgentUpdated, now)).Where(sqlb.Eq(AgentID, agentID))); err != nil {
		return err
	}
	_, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableGrant).Set(
		sqlb.Set(GrantStatusCol, string(GrantRevoked)), sqlb.Set(GrantUpdated, now)).Where(sqlb.Eq(GrantAgent, agentID)))
	return err
}

// deleteUserAgents deletes, inside DeleteUser's transaction, every agent of
// userID's hosts and every agent acting for userID, with their grants and
// approval requests. UserTables deletes only rows whose user column names
// the user; an agent still pending, or registered under ForceApproval,
// names only its host, and its grants and requests may name nobody, so
// without this they would outlive the account.
func (p *Plugin) deleteUserAgents(ctx context.Context, userID string) error {
	var hostIDs, agentIDs []string
	var id string
	if err := p.core.Each(ctx, p.core.Select().Columns(sqlb.Bind(HostID, &id)).From(TableHost).Where(sqlb.Eq(HostUser, &userID)), func() error {
		hostIDs = append(hostIDs, id)
		return nil
	}); err != nil {
		return err
	}
	collect := func(where sqlb.Predicate) error {
		return p.core.Each(ctx, p.core.Select().Columns(sqlb.Bind(AgentID, &id)).From(TableAgent).Where(where), func() error {
			agentIDs = append(agentIDs, id)
			return nil
		})
	}
	if err := collect(sqlb.Eq(AgentUser, &userID)); err != nil {
		return err
	}
	if len(hostIDs) > 0 {
		if err := collect(sqlb.In(AgentHost, hostIDs...)); err != nil {
			return err
		}
	}
	if len(agentIDs) == 0 {
		return nil
	}
	d := p.core.Dialect()
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableGrant).Where(sqlb.In(GrantAgent, agentIDs...))); err != nil {
		return err
	}
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableApproval).Where(sqlb.In(ApprovalAgent, agentIDs...))); err != nil {
		return err
	}
	_, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableAgent).Where(sqlb.In(AgentID, agentIDs...)))
	return err
}

// optional is s as a nullable column value: nil for "".
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// encodeNames stores a capability list as a JSON array.
func encodeNames(names []string) string {
	if names == nil {
		names = []string{}
	}
	b, _ := json.Marshal(names) // a []string always encodes
	return string(b)
}

// decodeNames reads a stored capability list; a malformed one is empty.
func decodeNames(s string) []string {
	var out []string
	if s == "" || json.Unmarshal([]byte(s), &out) != nil {
		return nil
	}
	return out
}

// timeString formats an optional time as RFC 3339, the protocol's form.
func timeString(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

// deref is *s, or "" for nil.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
