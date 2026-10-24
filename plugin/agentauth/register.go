package agentauth

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// RegisterRequest registers an agent, protocol section 6.3. Bearer is a
// host JWT whose agent_public_key claim is the new agent's key.
type RegisterRequest struct {
	Bearer
	Name         string              `json:"name"`
	Capabilities []CapabilityRequest `json:"capabilities,omitempty"`
	Reason       string              `json:"reason,omitempty"`
	// Mode defaults to ModeDelegated.
	Mode     Mode   `json:"mode,omitempty"`
	HostName string `json:"host_name,omitempty"`
	// ForceApproval sends every capability to the user, even those in the
	// host's budget.
	ForceApproval bool `json:"force_approval,omitempty"`
	// ApprovalHints steer the approval when one is needed.
	ApprovalHints
}

// RegisterResult is the registered agent.
type RegisterResult struct {
	AgentID string      `json:"agent_id"`
	HostID  string      `json:"host_id"`
	Name    string      `json:"name"`
	Mode    Mode        `json:"mode"`
	Status  AgentStatus `json:"status"`
	Grants  []GrantView `json:"agent_capability_grants"`
	// Approval is set when the agent or a capability waits for a user.
	Approval *Approval `json:"approval,omitempty"`
}

// Register registers an agent under the host that signed in.Token.
func (p *Plugin) Register(ctx context.Context, in RegisterRequest) (RegisterResult, error) {
	return p.register.Call(ctx, in)
}

// verifiedHost is a host whose JWT verified, and the token's claims.
type verifiedHost struct {
	host   hostRow
	claims Claims
}

// verifyHostJWT authenticates a known host:
// typ host+jwt, iss naming the host by id or kid, a signature by its
// stored key, an audience naming this server, a fresh iat, and a jti not
// seen before. pendingOK admits a pending host (registration and status).
func (p *Plugin) verifyHostJWT(ctx context.Context, b Bearer, pendingOK bool) (verifiedHost, error) {
	t, err := parseJWT(b.Token, TypeHostJWT)
	if err != nil {
		return verifiedHost{}, err
	}
	if t.claims.Issuer == "" {
		return verifiedHost{}, ErrInvalidJWT
	}
	host, err := p.loadHost(ctx, t.claims.Issuer)
	if err != nil {
		return verifiedHost{}, err
	}
	return p.verifyKnownHost(ctx, t, host, b, pendingOK)
}

// verifyKnownHost checks t against a host already loaded. Both callers
// load the host by t's iss (as its id or its kid), so iss names it.
func (p *Plugin) verifyKnownHost(ctx context.Context, t parsedJWT, host hostRow, b Bearer, pendingOK bool) (verifiedHost, error) {
	switch {
	case host.Status == string(HostRevoked) || (host.PublicKey == "" && host.JWKSURL == nil):
		return verifiedHost{}, ErrHostRevoked
	case host.Status == string(HostPending) && !pendingOK:
		return verifiedHost{}, ErrUnauthorized
	case host.Status != string(HostActive) && host.Status != string(HostPending):
		return verifiedHost{}, ErrHostRevoked
	}
	pub, err := p.signerKey(ctx, host.PublicKey, host.JWKSURL, t.header.Kid, ErrInvalidJWT)
	if err != nil {
		return verifiedHost{}, err
	}
	if err := p.verifyCommon(ctx, t, pub, jtiScopeHost, host.ID, "", b); err != nil {
		return verifiedHost{}, err
	}
	return verifiedHost{host: host, claims: t.claims}, nil
}

// verifyCommon is every check a JWT passes once its key is known:
// signature, audience, times, request binding and the single-use jti.
func (p *Plugin) verifyCommon(ctx context.Context, t parsedJWT, pub any, scope, identity, location string, b Bearer) error {
	if err := t.verify(pub); err != nil {
		return err
	}
	if !p.audienceOK(t.claims.Audience, location) {
		return ErrInvalidJWT
	}
	if err := p.checkTimes(t.claims, p.core.Now()); err != nil {
		return err
	}
	if err := checkBinding(t.claims, b); err != nil {
		return err
	}
	return p.spendJTI(ctx, scope, identity, t.claims.ID)
}

// registerHost resolves the host a registration comes from: a known one by
// the token's iss, or, under AllowDynamicHostRegistration, an unknown one
// that proves its inline host_public_key, created pending (or active for an
// autonomous agent) on first sight.
func (p *Plugin) registerHost(ctx context.Context, in RegisterRequest, mode Mode) (verifiedHost, error) {
	t, err := parseJWT(in.Token, TypeHostJWT)
	if err != nil {
		return verifiedHost{}, err
	}
	if t.claims.Issuer != "" {
		host, err := p.loadHost(ctx, t.claims.Issuer)
		if err == nil {
			return p.verifyKnownHost(ctx, t, host, in.Bearer, true)
		}
		if !errors.Is(err, ErrHostNotFound) {
			return verifiedHost{}, err
		}
	}
	if !p.dynamicHosts {
		return verifiedHost{}, ErrDynamicHostRegistration
	}
	if t.claims.HostPublicKey == nil {
		return verifiedHost{}, ErrInvalidJWT
	}
	key := *t.claims.HostPublicKey
	pub, err := parsePublicKey(key, p.algorithms)
	if err != nil {
		return verifiedHost{}, err
	}
	identity := key.identifier()
	if err := p.verifyCommon(ctx, t, pub, jtiScopeHost, identity, "", in.Bearer); err != nil {
		return verifiedHost{}, err
	}
	if existing, err := p.loadHost(ctx, identity); err == nil {
		// The same key registering again: it is that host, under its own
		// stored state, and its key must still be the one that signed.
		if existing.PublicKey != key.canonical() {
			return verifiedHost{}, ErrInvalidJWT
		}
		if existing.Status == string(HostRevoked) {
			return verifiedHost{}, ErrHostRevoked
		}
		return verifiedHost{host: existing, claims: t.claims}, nil
	} else if !errors.Is(err, ErrHostNotFound) {
		return verifiedHost{}, err
	}
	name := truncate(firstNonEmpty(t.claims.HostName, in.HostName), maxNameRunes)
	budget, err := p.hostBudget(ctx, HostCapabilitiesContext{Mode: mode, HostName: name})
	if err != nil {
		return verifiedHost{}, err
	}
	host, err := p.insertHost(ctx, key, nil, budget, name, firstStatus(mode))
	return verifiedHost{host: host, claims: t.claims}, err
}

// insertHost writes a host and returns its row.
func (p *Plugin) insertHost(ctx context.Context, key PublicKey, userID *string, budget []string, name string, status HostStatus) (hostRow, error) {
	id, err := p.core.NewID(prefixHost)
	if err != nil {
		return hostRow{}, err
	}
	now := p.core.Now()
	var activated *time.Time
	if status == HostActive {
		activated = &now
	}
	r := hostRow{
		ID: id, Name: optional(name), UserID: userID, DefaultCaps: encodeNames(budget), PublicKey: key.canonical(),
		Kid: key.identifier(), Status: string(status), ActivatedAt: activated, CreatedAt: now, UpdatedAt: now,
	}
	_, err = p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableHost).Row(
		sqlb.Set(HostID, r.ID), sqlb.Set(HostName, r.Name), sqlb.Set(HostUser, r.UserID), sqlb.Set(HostDefaultCaps, r.DefaultCaps),
		sqlb.Set(HostPublicKey, r.PublicKey), sqlb.Set(HostKid, r.Kid), sqlb.Set(HostStatusCol, r.Status),
		sqlb.Set(HostActivated, r.ActivatedAt), sqlb.Set(HostExpires, (*time.Time)(nil)), sqlb.Set(HostLastUsed, (*time.Time)(nil)),
		sqlb.Set(HostCreated, now), sqlb.Set(HostUpdated, now)))
	return r, err
}

// firstStatus is a dynamically registered host's status: active for an
// autonomous agent, which no user will approve, pending otherwise.
func firstStatus(mode Mode) HostStatus {
	if mode == ModeAutonomous {
		return HostActive
	}
	return HostPending
}

// firstNonEmpty is a, or b when a is empty.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (p *Plugin) doRegister(ctx context.Context, _ *auth.Call, in RegisterRequest) (RegisterResult, error) {
	name := truncate(in.Name, maxNameRunes)
	if name == "" || in.Token == "" {
		if in.Token == "" {
			return RegisterResult{}, ErrInvalidJWT
		}
		return RegisterResult{}, ErrInvalidRequest
	}
	mode := in.Mode
	if mode == "" {
		mode = ModeDelegated
	}
	if !slices.Contains(p.modes, mode) {
		return RegisterResult{}, ErrUnsupportedMode
	}
	if err := p.checkCapabilityNames(in.Capabilities); err != nil {
		return RegisterResult{}, err
	}
	vh, err := p.registerHost(ctx, in, mode)
	if err != nil {
		return RegisterResult{}, err
	}
	host := vh.host
	if mode == ModeAutonomous && host.UserID != nil {
		return RegisterResult{}, ErrUnsupportedMode
	}
	if mode == ModeAutonomous && host.Status == string(HostPending) {
		if err := p.activateHost(ctx, &host); err != nil {
			return RegisterResult{}, err
		}
	}
	var agentKey PublicKey
	var agentJWKS *string
	switch {
	case vh.claims.AgentPublicKey != nil:
		agentKey = *vh.claims.AgentPublicKey
		if _, err := parsePublicKey(agentKey, p.algorithms); err != nil {
			return RegisterResult{}, err
		}
	case vh.claims.AgentJWKSURL != "":
		if err := p.checkJWKSURL(vh.claims.AgentJWKSURL); err != nil {
			return RegisterResult{}, err
		}
		u := vh.claims.AgentJWKSURL
		agentJWKS = &u
	default:
		return RegisterResult{}, ErrInvalidPublicKey
	}
	// sameAgent finds this agent again: by its key, or by its JWKS URL.
	storedKey, sameAgent := agentKey.canonical(), sqlb.Eq(AgentPublicKey, agentKey.canonical())
	if agentJWKS != nil {
		storedKey, sameAgent = "", sqlb.Eq(AgentJWKSURL, agentJWKS)
	}
	userID := host.UserID
	if p.maxAgents > 0 && userID != nil {
		var n int64
		if err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableAgent).Where(
			sqlb.Eq(AgentUser, userID), sqlb.Eq(AgentStatusCol, string(AgentActive)))); err != nil {
			return RegisterResult{}, err
		}
		if n >= int64(p.maxAgents) {
			return RegisterResult{}, ErrAgentLimitReached
		}
	}

	// The host's budget decides what is granted at once and what waits for
	// a user: within the budget is granted, the
	// rest pending; an autonomous agent on an unclaimed host gets nothing
	// pending, because no user exists to approve it.
	budget := host.budget()
	var granted, pending []CapabilityRequest
	if len(budget) > 0 && len(in.Capabilities) == 0 {
		for _, b := range budget {
			granted = append(granted, CapabilityRequest{Name: b})
		}
	}
	for _, r := range in.Capabilities {
		if hasCapability(budget, r.Name) {
			granted = append(granted, r)
		} else {
			pending = append(pending, r)
		}
	}
	if mode == ModeAutonomous && userID == nil {
		pending = nil
	}
	delegatedWithoutUser := mode == ModeDelegated && userID == nil
	if in.ForceApproval || delegatedWithoutUser {
		pending, granted = append(granted, pending...), nil
	}
	agentUser := userID
	if in.ForceApproval || delegatedWithoutUser {
		agentUser = nil
	}
	hostPending := host.Status == string(HostPending)
	needsApproval := in.ForceApproval || hostPending || len(pending) > 0 || delegatedWithoutUser

	// Idempotency (protocol section 6.3): the same key on the same host
	// is the same agent. A pending one gets a fresh approval; any other is
	// a conflict.
	var existing agentRow
	err = p.core.One(ctx, p.core.Select().Columns(existing.bindings()...).From(TableAgent).Where(
		sqlb.Eq(AgentHost, host.ID), sameAgent).Limit(1))
	switch {
	case err == nil && existing.Status == string(AgentPending):
		grants, err := p.loadGrants(ctx, existing.ID)
		if err != nil {
			return RegisterResult{}, err
		}
		approval, err := p.newApproval(ctx, approvalInput{agentID: existing.ID, agentName: existing.Name, hostID: host.ID, userID: userID, capabilities: names(append(granted, pending...)), hints: in.ApprovalHints})
		if err != nil {
			return RegisterResult{}, err
		}
		return RegisterResult{AgentID: existing.ID, HostID: host.ID, Name: existing.Name, Mode: Mode(existing.Mode), Status: AgentPending, Grants: p.grantViews(grants), Approval: approval}, nil
	case err == nil:
		return RegisterResult{}, ErrAgentExists
	case !errors.Is(err, sqlb.ErrNoRows):
		return RegisterResult{}, err
	}

	agentID, err := p.core.NewID(prefixAgent)
	if err != nil {
		return RegisterResult{}, err
	}
	now := p.core.Now()
	status := AgentActive
	var activated, expires *time.Time
	if needsApproval {
		status = AgentPending
	} else {
		activated = &now
		if p.sessionTTL > 0 {
			e := p.slidingExpiry(now, now, now)
			expires = &e
		}
	}
	if _, err := p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableAgent).Row(
		sqlb.Set(AgentID, agentID), sqlb.Set(AgentName, name), sqlb.Set(AgentUser, agentUser), sqlb.Set(AgentHost, host.ID),
		sqlb.Set(AgentStatusCol, string(status)), sqlb.Set(AgentMode, string(mode)), sqlb.Set(AgentPublicKey, storedKey),
		sqlb.Set(AgentKid, optional(agentKey.KeyID)), sqlb.Set(AgentJWKSURL, agentJWKS), sqlb.Set(AgentLastUsed, (*time.Time)(nil)), sqlb.Set(AgentActivated, activated),
		sqlb.Set(AgentExpires, expires), sqlb.Set(AgentMetadata, (*string)(nil)), sqlb.Set(AgentCreated, now), sqlb.Set(AgentUpdated, now))); err != nil {
		return RegisterResult{}, err
	}
	reason := truncate(in.Reason, maxReasonRunes)
	grantStatus := GrantActive
	if hostPending {
		grantStatus = GrantPending
	}
	for _, g := range granted {
		var exp *time.Time
		if grantStatus == GrantActive {
			exp = p.grantExpiry(g.Name)
		}
		if err := p.insertGrant(ctx, agentID, g.Name, g.Constraints, agentUser, grantStatus, reason, exp); err != nil {
			return RegisterResult{}, err
		}
	}
	for _, g := range pending {
		if err := p.insertGrant(ctx, agentID, g.Name, g.Constraints, agentUser, GrantPending, reason, nil); err != nil {
			return RegisterResult{}, err
		}
	}
	grants, err := p.loadGrants(ctx, agentID)
	if err != nil {
		return RegisterResult{}, err
	}
	out := RegisterResult{AgentID: agentID, HostID: host.ID, Name: name, Mode: mode, Status: status, Grants: p.grantViews(grants)}
	if needsApproval {
		if out.Approval, err = p.newApproval(ctx, approvalInput{agentID: agentID, agentName: name, hostID: host.ID, userID: agentUser, capabilities: names(append(granted, pending...)), hints: in.ApprovalHints}); err != nil {
			return RegisterResult{}, err
		}
	}
	return out, nil
}

// names lists the requested names.
func names(reqs []CapabilityRequest) []string {
	out := make([]string, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, r.Name)
	}
	return out
}

// activateHost makes a pending host active, as an autonomous agent's first
// registration does.
func (p *Plugin) activateHost(ctx context.Context, host *hostRow) error {
	now := p.core.Now()
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableHost).Set(
		sqlb.Set(HostStatusCol, string(HostActive)), sqlb.Set(HostActivated, &now), sqlb.Set(HostUpdated, now)).Where(sqlb.Eq(HostID, host.ID))); err != nil {
		return err
	}
	host.Status, host.ActivatedAt = string(HostActive), &now
	return nil
}

// CreateHostRequest creates a host for the signed-in user, protocol
// section 3.2: the host's key, and the budget its agents receive without
// asking. Instead of a key the host may name a JWKS URL (AllowJWKSURLs);
// with neither, the host is created for enrollment and a device binds its
// key later with the returned token (EnrollHost).
type CreateHostRequest struct {
	Name                string    `json:"name,omitempty"`
	PublicKey           PublicKey `json:"public_key"`
	JWKSURL             string    `json:"jwks_url,omitempty"`
	DefaultCapabilities []string  `json:"default_capabilities,omitempty"`
}

// CreateHostResult is the created host. EnrollmentToken is set only for a
// host created for enrollment, and only in this answer: the server keeps
// its SHA-256.
type CreateHostResult struct {
	HostID                   string     `json:"host_id"`
	DefaultCapabilities      []string   `json:"default_capabilities"`
	Status                   HostStatus `json:"status"`
	EnrollmentToken          string     `json:"enrollment_token,omitempty"`
	EnrollmentTokenExpiresAt *time.Time `json:"enrollment_token_expires_at,omitempty"`
	// Reactivated is true when the call took over or reactivated an
	// existing host with the same key (the host.reactivated event).
	Reactivated bool `json:"-"`
}

// CreateHost creates a host owned by the signed-in user, or reactivates
// the user's host with the same key.
func (p *Plugin) CreateHost(ctx context.Context, in CreateHostRequest) (CreateHostResult, error) {
	return p.createHost.Call(ctx, in)
}

// hasKey reports whether a request carried a key at all.
func (k PublicKey) hasKey() bool { return k.KeyType != "" || k.X != "" || k.Y != "" || k.Curve != "" }

func (p *Plugin) doCreateHost(ctx context.Context, c *auth.Call, in CreateHostRequest) (CreateHostResult, error) {
	keyed := in.PublicKey.hasKey()
	switch {
	case keyed && in.JWKSURL != "":
		return CreateHostResult{}, ErrInvalidRequest
	case keyed:
		if _, err := parsePublicKey(in.PublicKey, p.algorithms); err != nil {
			return CreateHostResult{}, err
		}
	case in.JWKSURL != "":
		if err := p.checkJWKSURL(in.JWKSURL); err != nil {
			return CreateHostResult{}, err
		}
	}
	userID := c.User.ID
	budget := in.DefaultCapabilities
	if budget == nil {
		var err error
		if budget, err = p.hostBudget(ctx, HostCapabilitiesContext{UserID: &userID, HostName: truncate(in.Name, maxNameRunes)}); err != nil {
			return CreateHostResult{}, err
		}
	}
	reqs := make([]CapabilityRequest, 0, len(budget))
	for _, b := range budget {
		reqs = append(reqs, CapabilityRequest{Name: b})
	}
	if err := p.checkCapabilityNames(reqs); err != nil {
		return CreateHostResult{}, err
	}
	if !keyed {
		return p.createKeylessHost(ctx, userID, in, budget)
	}
	existing, err := p.loadHost(ctx, in.PublicKey.identifier())
	switch {
	case err == nil && existing.PublicKey == in.PublicKey.canonical():
		if existing.Status == string(HostRevoked) {
			return CreateHostResult{}, ErrHostRevoked
		}
		if existing.UserID != nil && *existing.UserID != userID {
			return CreateHostResult{}, ErrHostAlreadyLinked
		}
		now := p.core.Now()
		if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableHost).Set(
			sqlb.Set(HostUser, &userID), sqlb.Set(HostDefaultCaps, encodeNames(budget)), sqlb.Set(HostStatusCol, string(HostActive)),
			sqlb.Set(HostActivated, &now), sqlb.Set(HostUpdated, now)).Where(sqlb.Eq(HostID, existing.ID))); err != nil {
			return CreateHostResult{}, err
		}
		return CreateHostResult{HostID: existing.ID, DefaultCapabilities: nonNil(budget), Status: HostActive, Reactivated: true}, nil
	case err == nil:
		// Another key already uses this kid: refuse rather than shadow it.
		return CreateHostResult{}, ErrHostAlreadyLinked
	case !errors.Is(err, ErrHostNotFound):
		return CreateHostResult{}, err
	}
	host, err := p.insertHost(ctx, in.PublicKey, &userID, budget, truncate(in.Name, maxNameRunes), HostActive)
	if err != nil {
		return CreateHostResult{}, err
	}
	return CreateHostResult{HostID: host.ID, DefaultCapabilities: nonNil(budget), Status: HostActive}, nil
}

// createKeylessHost creates a host that signs with a JWKS URL, or, with
// neither a URL nor a key, one waiting for enrollment with a fresh token.
func (p *Plugin) createKeylessHost(ctx context.Context, userID string, in CreateHostRequest, budget []string) (CreateHostResult, error) {
	id, err := p.core.NewID(prefixHost)
	if err != nil {
		return CreateHostResult{}, err
	}
	now := p.core.Now()
	out := CreateHostResult{HostID: id, DefaultCapabilities: nonNil(budget), Status: HostActive}
	var jwksURL *string
	var hash []byte
	var until, activated *time.Time
	if in.JWKSURL != "" {
		jwksURL, activated = &in.JWKSURL, &now
	} else {
		out.Status = HostPendingEnrollment
		out.EnrollmentToken, hash = newEnrollmentToken()
		u := now.Add(p.enrollTTL)
		until, out.EnrollmentTokenExpiresAt = &u, &u
	}
	_, err = p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableHost).Row(
		sqlb.Set(HostID, id), sqlb.Set(HostName, optional(truncate(in.Name, maxNameRunes))), sqlb.Set(HostUser, &userID),
		sqlb.Set(HostDefaultCaps, encodeNames(budget)), sqlb.Set(HostPublicKey, ""), sqlb.Set(HostKid, ""),
		sqlb.Set(HostStatusCol, string(out.Status)), sqlb.Set(HostActivated, activated), sqlb.Set(HostExpires, (*time.Time)(nil)),
		sqlb.Set(HostLastUsed, (*time.Time)(nil)), sqlb.Set(HostCreated, now), sqlb.Set(HostUpdated, now),
		sqlb.Set(HostJWKSURL, jwksURL), sqlb.Set(HostEnrollHash, hash), sqlb.Set(HostEnrollUntil, until)))
	if err != nil {
		return CreateHostResult{}, err
	}
	return out, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
