package twofactor

import (
	"context"

	"github.com/ubgo/auth"
)

// EnrolmentRule decides whether userID must have a second factor before
// their session is usable: always (func returning true), per role, or per
// organization, which the rule looks up itself through a so this plugin
// imports no organization model. An error requires enrolment: a rule that
// cannot decide fails closed.
//
//ds:def id=twofactor-enrolmentrule-3vk8qw2m owner=@khanakia stability=stable
type EnrolmentRule func(ctx context.Context, a *auth.Auth, userID string) (bool, error)

// RequireEnrolment makes a user the rule names, who has no second factor
// on, sign in to a session with the core's auth.TaskSetupMFA task pending:
// it reaches only status and the enrolment operations (enroll, confirm, and
// the security-key registration with WithSecurityKeys), and every other
// operation answers auth.ErrSessionTaskPending, until a factor is turned on.
// Then the session is replaced by an ordinary one under a new token, and the
// old token stops working. Without this option the plugin declares no task
// and nothing changes. A nil rule is refused (auth.ErrNilOption).
//
//ds:def id=twofactor-requireenrolment-8mq4wk6t owner=@khanakia stability=stable
func RequireEnrolment(rule EnrolmentRule) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("twofactor.RequireEnrolment", rule) {
			return
		}
		p.enrolRule = rule
	}
}

var _ auth.SessionTasker = (*Plugin)(nil)

// SessionTasks declares auth.TaskSetupMFA with exactly the operations a user
// needs to enrol from nothing, only under RequireEnrolment.
func (p *Plugin) SessionTasks() []auth.SessionTask {
	if p.enrolRule == nil {
		return nil
	}
	allow := []auth.EndpointID{EndpointStatus, EndpointEnroll, EndpointConfirm}
	if p.keys != nil {
		allow = append(allow, EndpointSecurityKeyRegisterBegin, EndpointSecurityKeyRegisterFinish)
	}
	return []auth.SessionTask{{ID: auth.TaskSetupMFA, Allow: allow}}
}

// SessionTasksFor requires auth.TaskSetupMFA of a user the rule names who
// has no second factor on (none enrolled, or one DisableFor paused).
func (p *Plugin) SessionTasksFor(ctx context.Context, in auth.SignInAttempt) ([]auth.SessionTaskID, error) {
	if p.enrolRule == nil {
		return nil, nil
	}
	on, err := p.enabledFor(ctx, in.UserID)
	if err != nil {
		return nil, err
	}
	if on {
		return nil, nil
	}
	must, err := p.enrolRule(ctx, p.core, in.UserID)
	if err != nil {
		p.core.Logger().Warn("twofactor: enrolment rule failed; requiring enrolment", "error", err)
		must = true
	}
	if !must {
		return nil, nil
	}
	return []auth.SessionTaskID{auth.TaskSetupMFA}, nil
}

// completeEnrolment finishes the setup-mfa task of the call's session after
// a factor was turned on; for a session without the task it changes nothing.
func (p *Plugin) completeEnrolment(ctx context.Context, c *auth.Call) error {
	_, err := c.Auth.CompleteSessionTask(ctx, c, auth.TaskSetupMFA)
	return err
}
