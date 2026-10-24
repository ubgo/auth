package audit

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// EventType is the name for what an event records
// (user_signed_in, organization_created, …). The log stores the operation id,
// the one vocabulary every transport already uses; the type is derived from
// it by TypeOf, so a query can ask for "every sign-in" across the dozen
// operations that sign someone in.
type EventType string

// Event types, as the audit log names them.
const (
	TypeUserSignedUp            EventType = "user_signed_up"
	TypeUserSignedIn            EventType = "user_signed_in"
	TypeUserSignedOut           EventType = "user_signed_out"
	TypeUserProfileUpdated      EventType = "user_profile_updated"
	TypeUserEmailVerified       EventType = "user_email_verified"
	TypeUserBanned              EventType = "user_banned"
	TypeUserUnbanned            EventType = "user_unbanned"
	TypeUserDeleted             EventType = "user_deleted"
	TypeSessionRevoked          EventType = "session_revoked"
	TypeSessionsRevokedAll      EventType = "sessions_revoked_all"
	TypeUserImpersonated        EventType = "user_impersonated"
	TypeImpersonationStopped    EventType = "user_impersonation_stopped"
	TypeAccountLinked           EventType = "account_linked"
	TypeAccountUnlinked         EventType = "account_unlinked"
	TypePasswordChanged         EventType = "password_changed"
	TypePasswordResetRequested  EventType = "password_reset_requested"
	TypePasswordResetCompleted  EventType = "password_reset_completed"
	TypeEmailVerificationSent   EventType = "email_verification_sent"
	TypeOrganizationCreated     EventType = "organization_created"
	TypeOrganizationUpdated     EventType = "organization_updated"
	TypeOrganizationDeleted     EventType = "organization_deleted"
	TypeMemberRemoved           EventType = "organization_member_removed"
	TypeMemberRoleUpdated       EventType = "organization_member_role_updated"
	TypeInvitationCreated       EventType = "organization_invitation_created"
	TypeInvitationAccepted      EventType = "organization_invitation_accepted"
	TypeInvitationRejected      EventType = "organization_invitation_rejected"
	TypeInvitationCanceled      EventType = "organization_invitation_cancelled"
	TypeTeamCreated             EventType = "organization_team_created"
	TypeTeamUpdated             EventType = "organization_team_updated"
	TypeTeamDeleted             EventType = "organization_team_deleted"
	TypeTeamMemberAdded         EventType = "organization_team_member_added"
	TypeTeamMemberRemoved       EventType = "organization_team_member_removed"
	TypeOrganizationRoleCreated EventType = "organization_role_created"
	TypeOrganizationRoleUpdated EventType = "organization_role_updated"
	TypeOrganizationRoleDeleted EventType = "organization_role_deleted"
	// TypeRateLimitExceeded is a call over an auth rate rule's limit
	// (auth.RateEvent), whatever the rule's action did with it; the event's
	// Code says which (RateCodeBlocked and its siblings). Unlike every other
	// type it is derived from Code, not Op: Op is the operation that was
	// limited, so a query by Op finds its limit events too.
	TypeRateLimitExceeded EventType = "rate_limit_exceeded"
)

// RateCodePrefix starts the Code of every rate-limit event, followed by the
// auth.RateOutcome: "rate.blocked", "rate.logged", "rate.challenged",
// "rate.challenge_passed". It is what makes such an event
// TypeRateLimitExceeded.
//
//ds:def id=ratecodeprefix-audit-8kw3nv6q owner=@khanakia stability=stable
const RateCodePrefix = "rate."

// typeOfEvent is e's type: TypeRateLimitExceeded for a rate-limit event,
// otherwise the type of its operation.
func (p *Plugin) typeOfEvent(e Event) EventType {
	if strings.HasPrefix(e.Code, RateCodePrefix) {
		return TypeRateLimitExceeded
	}
	return p.TypeOf(e.Op)
}

// eventTypes maps the operation ids of the built-in plugins to their type.
// Ids are strings rather than the plugins' constants because this package is
// in the core module and the organization and password plugins are not: a
// test in the integration module (TestTypes_NameRealOperations) wires every
// plugin and fails on an id that no operation has, so the strings cannot
// drift silently.
var eventTypes = map[auth.EndpointID]EventType{
	"password.sign-up": TypeUserSignedUp, "passkey.sign-up-finish": TypeUserSignedUp,

	"password.sign-in": TypeUserSignedIn, "email.sign-in-code": TypeUserSignedIn, "phone.sign-in": TypeUserSignedIn,
	"magiclink.verify": TypeUserSignedIn, "magiclink.sign-in": TypeUserSignedIn, "passkey.login-finish": TypeUserSignedIn,
	"twofactor.verify": TypeUserSignedIn, "anonymous.sign-in": TypeUserSignedIn, "handoff.verify": TypeUserSignedIn,
	"sso.callback": TypeUserSignedIn, "sso.saml-acs": TypeUserSignedIn,

	"core.sign-out": TypeUserSignedOut,
	"core.profile":  TypeUserProfileUpdated, "admin.update-user": TypeUserProfileUpdated, "username.set": TypeUserProfileUpdated,
	"email.verify": TypeUserEmailVerified, "email.verify-code": TypeUserEmailVerified, "email.verify-link": TypeUserEmailVerified,
	"admin.ban": TypeUserBanned, "admin.unban": TypeUserUnbanned,
	"core.account-delete-confirm": TypeUserDeleted, "admin.remove-user": TypeUserDeleted, "anonymous.delete": TypeUserDeleted,

	"core.device-sessions-revoke": TypeSessionRevoked, "admin.revoke-session": TypeSessionRevoked,
	"core.sign-out-all": TypeSessionsRevokedAll, "core.sessions-revoke": TypeSessionsRevokedAll, "admin.revoke-sessions": TypeSessionsRevokedAll,
	"admin.impersonate": TypeUserImpersonated, "admin.stop-impersonating": TypeImpersonationStopped,

	"oauth.unlink": TypeAccountUnlinked,
	// The ID-token re-authentication ends in "-id-token" like a native
	// sign-in, but signs nobody in: it keeps its own id as its type, as
	// password.reauthenticate does, rather than the suffix rule's
	// user_signed_in.
	"oauth.reauthenticate-id-token": "oauth.reauthenticate-id-token",
	"password.change":               TypePasswordChanged, "password.change-expired": TypePasswordChanged, "admin.set-password": TypePasswordChanged,
	"password.forgot": TypePasswordResetRequested,
	"password.reset":  TypePasswordResetCompleted, "password.reset-code": TypePasswordResetCompleted,
	"email.resend": TypeEmailVerificationSent,

	"organization.create": TypeOrganizationCreated, "organization.update": TypeOrganizationUpdated, "organization.delete": TypeOrganizationDeleted,
	"organization.remove-member": TypeMemberRemoved, "organization.set-role": TypeMemberRoleUpdated,
	"organization.invite": TypeInvitationCreated, "organization.accept": TypeInvitationAccepted,
	"organization.reject": TypeInvitationRejected, "organization.cancel": TypeInvitationCanceled,
	"organization.create-team": TypeTeamCreated, "organization.update-team": TypeTeamUpdated, "organization.remove-team": TypeTeamDeleted,
	"organization.add-team-member": TypeTeamMemberAdded, "organization.remove-team-member": TypeTeamMemberRemoved,
	"organization.create-role": TypeOrganizationRoleCreated, "organization.update-role": TypeOrganizationRoleUpdated,
	"organization.delete-role": TypeOrganizationRoleDeleted,
}

// EventTyper is a plugin that names the event types of its own operations,
// for a type the operation's metadata cannot say: a sign-in operation needs
// none, since auth.OpInfo.SignIn already makes it user_signed_in, but a
// third-party sign-up or ban does. Found among the registered plugins
// at Init; the values are strings so the plugin needs no import of this
// package (TypeUserSignedIn is "user_signed_in"). Types overrides it.
//
//ds:def id=eventtyper-r5n8w3vd owner=@khanakia stability=stable
type EventTyper interface {
	AuditEventTypes() map[auth.EndpointID]string
}

// Types maps operations to event types, over the built-in mapping and every
// EventTyper plugin: an app's own sign-in operation to TypeUserSignedIn, or a
// built-in operation to a name of the app's choosing. Repeated calls add up;
// a later one wins for the same operation. An empty type fails Init.
//
//ds:def id=types-x2j6q9tb owner=@khanakia stability=stable
func Types(m map[auth.EndpointID]EventType) Option {
	return func(p *Plugin) {
		if p.types == nil {
			p.types = map[auth.EndpointID]EventType{}
		}
		maps.Copy(p.types, m)
	}
}

// buildTypeMap is the mapping in force: every operation marked SignIn (among
// ops and each plugin's own, which includes the self-served ones ops leaves
// out) as TypeUserSignedIn, then the built-in mapping, then each EventTyper
// in plugins (in wiring order), then the app's own, each overriding the one
// before. The flag comes first so an explicit entry, such as
// password.change-expired as password_changed, still wins.
func buildTypeMap(plugins []auth.Plugin, ops []auth.Operation, app map[auth.EndpointID]EventType) (map[auth.EndpointID]EventType, error) {
	m := map[auth.EndpointID]EventType{}
	for _, pl := range plugins {
		if prov, ok := pl.(auth.OperationProvider); ok {
			ops = append(ops, prov.Operations()...)
		}
	}
	for _, op := range ops {
		if info := op.Info(); info.SignIn {
			m[info.ID] = TypeUserSignedIn
		}
	}
	maps.Copy(m, eventTypes)
	for _, pl := range plugins {
		et, ok := pl.(EventTyper)
		if !ok {
			continue
		}
		for op, t := range et.AuditEventTypes() {
			if t == "" {
				return nil, fmt.Errorf("audit: plugin %q declares an empty event type for %q", pl.Name(), op)
			}
			m[op] = EventType(t)
		}
	}
	for op, t := range app {
		if t == "" {
			return nil, fmt.Errorf("audit: Types names an empty event type for %q", op)
		}
		m[op] = t
	}
	return m, nil
}

// TypeOf is the event type of op under this plugin's mapping (the built-in
// one, EventTyper plugins and Types); see the package TypeOf for the rest.
// Before Init it is the package TypeOf.
func (p *Plugin) TypeOf(op auth.EndpointID) EventType {
	if t, ok := p.typeMap[op]; ok {
		return t
	}
	return TypeOf(op)
}

// OpsOf is the package OpsOf under this plugin's mapping: the operations
// mapped to t, plus t itself read as an operation id unless that id is
// mapped to another type. Before Init it is the package OpsOf.
func (p *Plugin) OpsOf(t EventType) []string {
	if p.typeMap == nil {
		return OpsOf(t)
	}
	var out []string
	if mapped, ok := p.typeMap[auth.EndpointID(t)]; !ok || mapped == t {
		out = append(out, string(t))
	}
	for op, et := range p.typeMap {
		if et == t && string(op) != string(t) {
			out = append(out, string(op))
		}
	}
	slices.Sort(out)
	return out
}

// TypeOf is the event type of an operation under the built-in mapping:
// its named type when there is one, otherwise the operation id itself, so
// every event has a type and an app's own operations are queryable by type
// too. Plugin.TypeOf adds EventTyper plugins and Types.
func TypeOf(op auth.EndpointID) EventType {
	if t, ok := eventTypes[op]; ok {
		return t
	}
	// The OAuth plugin names one callback per provider
	// ("oauth.google-callback"); a callback signs in, or links an account
	// when the caller was signed in, which the operation id cannot tell.
	if s := string(op); strings.HasPrefix(s, oauthPrefix) && (strings.HasSuffix(s, oauthCallback) || strings.HasSuffix(s, oauthIDToken)) {
		return TypeUserSignedIn
	}
	// The link event recorded beside an OAuth sign-in that linked (linkEvent).
	if s := string(op); strings.HasPrefix(s, oauthPrefix) && strings.HasSuffix(s, oauthLinked) {
		return TypeAccountLinked
	}
	return EventType(op)
}

// The OAuth plugin's per-provider operation ids, as oauth.CallbackEndpoint
// and oauth.IDTokenEndpoint build them.
const (
	oauthPrefix   = "oauth."
	oauthCallback = "-callback"
	oauthIDToken  = "-id-token"
)

// OpsOf lists the operation ids whose events have type t, sorted: the
// operations mapped to it, plus t itself read as an operation id, which is
// what TypeOf answers for an unmapped one. The per-provider OAuth callbacks
// and link events are not listed, since their ids depend on the providers
// wired; typeFilter matches them by pattern.
func OpsOf(t EventType) []string {
	out := []string{string(t)}
	for op, et := range eventTypes {
		if et == t {
			out = append(out, string(op))
		}
	}
	slices.Sort(out)
	return out
}

// typeFilter is the WHERE term of a query by type: the operations mapped to
// it (Plugin.OpsOf), for a sign-in every provider's OAuth callback by
// pattern, and for a link every provider's link event (linkEvent).
func (p *Plugin) typeFilter(t EventType) sqlb.Predicate {
	// A rate-limit event's type comes from its Code (typeOfEvent), and
	// every other type must leave such events out, although their Op is
	// the limited operation's.
	if t == TypeRateLimitExceeded {
		return sqlb.Like(EventCode, RateCodePrefix+"%")
	}
	return sqlb.And(sqlb.NotLike(EventCode, RateCodePrefix+"%"), p.opTypeFilter(t))
}

// opTypeFilter matches the events whose operation has type t.
func (p *Plugin) opTypeFilter(t EventType) sqlb.Predicate {
	// An empty list (every id that would match is mapped elsewhere)
	// renders FALSE in sqlb, which is the right answer.
	in := sqlb.In(EventOp, p.OpsOf(t)...)
	if t == TypeAccountLinked {
		return sqlb.Or(in, sqlb.Like(EventOp, oauthPrefix+"%"+oauthLinked))
	}
	if t != TypeUserSignedIn {
		return in
	}
	return sqlb.Or(in,
		sqlb.Like(EventOp, oauthPrefix+"%"+oauthCallback),
		sqlb.Like(EventOp, oauthPrefix+"%"+oauthIDToken))
}

// EndpointMyEvents is the self-service history operation's id.
const EndpointMyEvents auth.EndpointID = "audit.my-events"

// MyQuery is the input of my-events: the caller's own history, narrowed by
// type and organization, paged as Query.
type MyQuery struct {
	Type  EventType `json:"type,omitempty"`
	OrgID string    `json:"orgId,omitempty"`
	Page  int       `json:"page,omitempty,string"`
	Limit int       `json:"limit,omitempty,string"`
}

// MyEvents is the signed-in user's own history (the client's audit-log
// query): events they made or that were made to them. On an event
// someone else made (an admin's ban), the other party's id, session,
// address and user agent are left out, and no event shows an impersonator,
// so a user's history never reveals who an administrator is or where they
// work from.
func (p *Plugin) MyEvents(ctx context.Context, q MyQuery) (Page, error) {
	return p.myEvents.Call(ctx, q)
}

func (p *Plugin) doMyEvents(ctx context.Context, c *auth.Call, q MyQuery) (Page, error) {
	page, err := p.Events(ctx, Query{UserID: c.User.ID, OrgID: q.OrgID, Type: q.Type, Page: q.Page, Limit: q.Limit})
	if err != nil {
		return Page{}, err
	}
	for i := range page.Events {
		e := &page.Events[i]
		if e.ActorID != c.User.ID {
			e.ActorID, e.SessionID, e.IP, e.UserAgent = "", "", "", ""
		}
		e.ImpersonatorID = ""
	}
	return page, nil
}

// Operations serves my-events.
func (p *Plugin) Operations() []auth.Operation { return []auth.Operation{p.myEvents} }
