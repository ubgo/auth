package oidcclient

import (
	"context"
	"net/http"
)

// Decision is an Authorizer's answer. Its zero value is Deny, so an
// authorizer that forgets to decide refuses: the careless path is the safe
// one.
type Decision int

const (
	// Deny refuses the request with the no-access response.
	Deny Decision = iota
	// Allow lets the request through, unless an error came with it.
	Allow
)

// DecisionValues is every Decision.
var DecisionValues = []Decision{Deny, Allow}

// AuthorizeRequest is what an Authorizer decides from: the signed-in User
// (fresh: the login server said yes within the recheck interval) and the
// request, for rules by route, method or tenant host.
type AuthorizeRequest struct {
	User    User
	Request *http.Request
}

// Authorizer is the app's own rule on top of the login server's: roles,
// tenant membership, route rules. It runs on every request Client.Require
// lets through, after the session is known to be fresh. The default is none:
// the login server alone decides who may use the app.
//
// It fails closed: only (Allow, nil) allows. Any error refuses, an error
// together with Allow included; ErrAccessDenied is answered as no access,
// any other error as a failure.
type Authorizer func(ctx context.Context, in AuthorizeRequest) (Decision, error)
