// Package access is a permission vocabulary and the roles built from it: an
// app (or a plugin such as organization) declares which actions exist on which
// resources, defines roles as subsets of those statements, and asks a role
// whether it may do something.
//
// It is the Go shape of better-auth's access plugin (createAccessControl,
// ac.newRole, role.authorize) and has no storage, no transport and no import
// of the auth core, so a role check costs a map lookup and the package can
// decide permissions for anything, not only organizations.
//
// # Why a role may only name declared statements
//
// A typo in a role definition ("membr": ["delete"]) must fail when the role is
// built, at start-up, rather than silently granting nothing until someone
// notices a button that never works, or, worse, granting something under a
// resource name an attacker can also spell. NewRole refuses any resource or
// action the AccessControl did not declare.
package access

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Statements are the resources of an application and the actions each one
// allows: {"project": ["create", "share", "delete"]}. The declared set is the
// whole vocabulary: a role can name nothing outside it.
type Statements map[string][]string

// Permissions are a set of actions per resource, the same shape as
// Statements: what a role grants, or what a request asks for. JSON-encoded it
// is better-auth's permission object, so it is what an HTTP client sends.
type Permissions map[string][]string

// Connector says how several checks combine: every one must pass (And) or one
// is enough (Or).
type Connector string

// Connectors.
const (
	// And requires every action (or every resource); the default.
	And Connector = "AND"
	// Or requires one action (or one resource).
	Or Connector = "OR"
)

// Actions is one resource's part of a Request: the actions asked for, and
// whether all of them (And, the default) or any one (Or) must be granted.
type Actions struct {
	Actions   []string
	Connector Connector
}

// All asks for every one of actions.
func All(actions ...string) Actions { return Actions{Actions: actions, Connector: And} }

// Any asks for at least one of actions.
func Any(actions ...string) Actions { return Actions{Actions: actions, Connector: Or} }

// Request is a permission check: per resource, the actions asked for. Build
// one from Permissions with Permissions.Request when every action of every
// resource is required.
type Request map[string]Actions

// Request turns p into a Request requiring every listed action.
func (p Permissions) Request() Request {
	r := make(Request, len(p))
	for res, acts := range p {
		r[res] = All(acts...)
	}
	return r
}

// Clone returns a deep copy, so a caller can change it without touching a
// role's own map.
func (p Permissions) Clone() Permissions {
	out := make(Permissions, len(p))
	for res, acts := range p {
		out[res] = slices.Clone(acts)
	}
	return out
}

// Errors.
var (
	// ErrUnknownResource is a role, or a check, naming a resource the
	// statements do not declare.
	ErrUnknownResource = errors.New("access: unknown resource")
	// ErrUnknownAction is a role naming an action its resource does not
	// declare.
	ErrUnknownAction = errors.New("access: unknown action")
	// ErrEmptyStatements is an AccessControl with no resource, which no role
	// could grant anything from.
	ErrEmptyStatements = errors.New("access: no statements")
	// ErrDenied is a check the role does not pass; the returned error wraps
	// it with better-auth's message, which names the resource.
	ErrDenied = errors.New("access: denied")
)

// AccessControl holds the declared statements and builds roles from them.
// Build it with New; it is immutable afterwards and safe for concurrent use.
type AccessControl struct {
	statements Statements
}

// New declares the statements. Each resource needs at least one action and
// no action may repeat within a resource, so the vocabulary has one spelling
// for everything.
func New(s Statements) (*AccessControl, error) {
	if len(s) == 0 {
		return nil, ErrEmptyStatements
	}
	out := make(Statements, len(s))
	for res, acts := range s {
		if strings.TrimSpace(res) == "" {
			return nil, fmt.Errorf("%w: empty resource name", ErrUnknownResource)
		}
		if len(acts) == 0 {
			return nil, fmt.Errorf("access: resource %q declares no action", res)
		}
		seen := map[string]bool{}
		for _, a := range acts {
			if strings.TrimSpace(a) == "" || seen[a] {
				return nil, fmt.Errorf("access: resource %q declares an empty or repeated action %q", res, a)
			}
			seen[a] = true
		}
		out[res] = slices.Clone(acts)
	}
	return &AccessControl{statements: out}, nil
}

// MustNew is New for statements known at compile time; it panics on an
// error, which then shows at start-up.
func MustNew(s Statements) *AccessControl {
	ac, err := New(s)
	if err != nil {
		panic(err)
	}
	return ac
}

// Statements returns a copy of the declared statements.
func (ac *AccessControl) Statements() Statements {
	return Statements(Permissions(ac.statements).Clone())
}

// Check reports whether p names only declared resources and actions: the
// validation NewRole applies, exported for a role stored at run time (the
// organization plugin's dynamic roles) before it is saved.
func (ac *AccessControl) Check(p Permissions) error {
	for res, acts := range p {
		declared, ok := ac.statements[res]
		if !ok {
			return fmt.Errorf("%w: %q", ErrUnknownResource, res)
		}
		for _, a := range acts {
			if !slices.Contains(declared, a) {
				return fmt.Errorf("%w: %q on %q", ErrUnknownAction, a, res)
			}
		}
	}
	return nil
}

// NewRole builds a role granting p, which must be a subset of the
// statements (Check).
func (ac *AccessControl) NewRole(p Permissions) (Role, error) {
	if err := ac.Check(p); err != nil {
		return Role{}, err
	}
	return Role{perms: p.Clone()}, nil
}

// MustRole is NewRole for a role known at compile time; it panics on an
// error.
func (ac *AccessControl) MustRole(p Permissions) Role {
	r, err := ac.NewRole(p)
	if err != nil {
		panic(err)
	}
	return r
}

// Role is a set of granted actions per resource. The zero value grants
// nothing.
type Role struct {
	perms Permissions
}

// Permissions returns a copy of what the role grants.
func (r Role) Permissions() Permissions { return r.perms.Clone() }

// Authorize checks req against the role; nil means allowed. connector joins
// the resources (And when empty): with And every resource must pass, with Or
// one is enough. A resource the role grants nothing on fails at once,
// whatever the connector, as in better-auth. An empty request is denied:
// asking for nothing proves nothing.
//
// A denial wraps ErrDenied with better-auth's wording, so errors.Is works and
// the message matches what a better-auth client shows.
func (r Role) Authorize(req Request, connector Connector) error {
	if connector == "" {
		connector = And
	}
	// Resources in a fixed order, so the resource a denial names does not
	// depend on map iteration.
	resources := make([]string, 0, len(req))
	for res := range req {
		resources = append(resources, res)
	}
	sort.Strings(resources)
	ok := false
	for _, res := range resources {
		allowed, granted := r.perms[res]
		if !granted {
			return fmt.Errorf("%w: You are not allowed to access resource: %s", ErrDenied, res)
		}
		want := req[res]
		if want.Connector == Or {
			ok = slices.ContainsFunc(want.Actions, func(a string) bool { return slices.Contains(allowed, a) })
		} else {
			ok = len(want.Actions) > 0 && !slices.ContainsFunc(want.Actions, func(a string) bool { return !slices.Contains(allowed, a) })
		}
		if ok && connector == Or {
			return nil
		}
		if !ok && connector == And {
			return fmt.Errorf("%w: unauthorized to access resource %q", ErrDenied, res)
		}
	}
	if ok {
		return nil
	}
	return fmt.Errorf("%w: Not authorized", ErrDenied)
}

// Allows is Authorize with And, as a boolean, for a caller that needs no
// reason.
func (r Role) Allows(req Request) bool { return r.Authorize(req, And) == nil }
