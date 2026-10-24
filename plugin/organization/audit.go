package organization

// AuditOrgID names the organization a request acts in, for plugin/audit's
// OrgScoped (an event's orgId), without this package importing it. Empty
// when the request leaves the organization to the session's active one; the
// operations then annotate the call with the organization they resolved.
func (r OrgRequest) AuditOrgID() string { return r.OrgID }

// AuditOrgID is OrgRequest's, for invite.
func (r InviteRequest) AuditOrgID() string { return r.OrgID }

// AuditOrgID is OrgRequest's, for remove-member.
func (r MemberRequest) AuditOrgID() string { return r.OrgID }

// AuditOrgID is OrgRequest's, for set-role.
func (r SetRoleRequest) AuditOrgID() string { return r.OrgID }

// AuditOrgID is OrgRequest's, for update.
func (r UpdateRequest) AuditOrgID() string { return r.OrgID }

// AuditOrgID is OrgRequest's, for get and get-full.
func (r GetRequest) AuditOrgID() string { return r.OrgID }

// AuditOrgID is OrgRequest's, for set-active.
func (r SetActiveRequest) AuditOrgID() string { return r.OrgID }

// AuditOrgID is OrgRequest's, for has-permission.
func (r PermissionRequest) AuditOrgID() string { return r.OrgID }

// AuditOrgID is OrgRequest's, for create-team.
func (r CreateTeamRequest) AuditOrgID() string { return r.OrgID }

// AuditOrgID is OrgRequest's, for create-role.
func (r CreateRoleRequest) AuditOrgID() string { return r.OrgID }

// AuditOrgID is OrgRequest's, for update-role.
func (r UpdateRoleRequest) AuditOrgID() string { return r.OrgID }

// AuditOrgID is OrgRequest's, for delete-role and get-role.
func (r RoleRequest) AuditOrgID() string { return r.OrgID }

// TargetUserID names the member a request is about, for plugin/audit's
// Targeted (an event's subjectId), so the member sees it in their own
// history.
func (r MemberRequest) TargetUserID() string { return r.UserID }

// TargetUserID is MemberRequest's, for set-role.
func (r SetRoleRequest) TargetUserID() string { return r.UserID }

// TargetUserID is MemberRequest's, for add-team-member and
// remove-team-member.
func (r TeamMemberRequest) TargetUserID() string { return r.UserID }
