package metadata

import (
	"context"

	"github.com/ubgo/auth"
)

// The admin operations ask one Authorizer, so the plugin decides no
// permission itself and does not import plugin/admin: an app on admin's roles,
// plugin/access, Casbin, OPA, a relationship store or its own rules wires the
// question to its model with an AuthorizerFunc.

// Action is what an admin operation does with the documents.
type Action string

// Actions.
const (
	// ActionRead reads all three documents (metadata.admin-get).
	ActionRead Action = "read"
	// ActionWrite patches any of them (metadata.admin-update).
	ActionWrite Action = "write"
)

// ActionValues is the canonical iteration order over actions.
var ActionValues = []Action{ActionRead, ActionWrite}

// AccessRequest is one decision: may the caller take Action on the
// documents of TargetUserID?
type AccessRequest struct {
	// CallerID is the signed-in user asking.
	CallerID string
	// TargetUserID is the user whose documents the request names, as the
	// input gave it: the decision comes before the user is looked up, so a
	// refusal never reveals whether the user exists.
	TargetUserID string
	Action       Action
	// Call is the operation's call (session, client IP, decoded input), for
	// an attribute-based rule. Read it; never change it.
	Call *auth.Call
}

// Authorizer decides an AccessRequest. An error refuses: the plugin never
// reads the boolean of a call that failed, so a policy engine that is down
// fails closed. It must be safe for concurrent use.
//
//ds:def id=metadata-authorizer-4wk8qn3v owner=@khanakia stability=api
type Authorizer interface {
	Authorize(ctx context.Context, req AccessRequest) (bool, error)
}

// AuthorizerFunc adapts a function to Authorizer.
type AuthorizerFunc func(ctx context.Context, req AccessRequest) (bool, error)

// Authorize calls f.
func (f AuthorizerFunc) Authorize(ctx context.Context, req AccessRequest) (bool, error) {
	return f(ctx, req)
}

// authorize asks the Authorizer and answers ErrForbidden for a refusal and
// the Authorizer's own error for a failure.
func (p *Plugin) authorize(ctx context.Context, c *auth.Call, target string, action Action) error {
	ok, err := p.authorizer.Authorize(ctx, AccessRequest{CallerID: c.User.ID, TargetUserID: target, Action: action, Call: c})
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}
