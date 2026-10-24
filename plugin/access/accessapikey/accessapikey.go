// Package accessapikey checks plugin/apikey's key permissions with a
// plugin/access access control, so the statements an app already declared
// for its roles are the vocabulary of its API keys too:
//
//	apikey.New(apikey.WithPermissions(accessapikey.New(ac)))
//
// Without it the apikey plugin uses its built-in apikey.Vocabulary, which
// answers identically for the same statements.
package accessapikey

import (
	"slices"

	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/apikey"
)

// Checker is an apikey.PermissionChecker over an access control. It holds
// the control by pointer, which is immutable once built, so it is safe for
// concurrent use.
type Checker struct{ ac *access.AccessControl }

// New adapts ac. A nil ac checks nothing and grants nothing: Check refuses
// every permission with access.ErrEmptyStatements, so a key cannot be given
// any.
func New(ac *access.AccessControl) Checker { return Checker{ac: ac} }

// Check is ac.Check: a permission naming an undeclared resource or action
// is access.ErrUnknownResource or access.ErrUnknownAction.
func (c Checker) Check(p apikey.Permissions) error {
	if c.ac == nil {
		return access.ErrEmptyStatements
	}
	return c.ac.Check(access.Permissions(p))
}

// Grants reports whether held authorizes want: every action of every
// resource of want must be in held. A held resource or action the statements
// no longer declare (one removed after the key was made) is skipped rather
// than refusing the whole role, as apikey.Vocabulary.Grants does, so the
// key's other permissions keep their answer; the stale one grants nothing,
// because a role without it cannot allow it.
func (c Checker) Grants(held, want apikey.Permissions) bool {
	if c.ac == nil {
		return false
	}
	// declared keeps only what the statements declare, so NewRole should not
	// fail; if it ever does, the check is refused (fail closed).
	role, err := c.ac.NewRole(declared(c.ac.Statements(), held))
	if err != nil {
		return false
	}
	return role.Allows(access.Permissions(want).Request())
}

// declared returns the part of held that stmts declares: undeclared
// resources and actions dropped, and a resource left with no action dropped
// too, so NewRole accepts it.
func declared(stmts access.Statements, held apikey.Permissions) access.Permissions {
	out := make(access.Permissions, len(held))
	for res, acts := range held {
		allowed, ok := stmts[res]
		if !ok {
			continue
		}
		kept := slices.DeleteFunc(slices.Clone(acts), func(a string) bool { return !slices.Contains(allowed, a) })
		if len(kept) > 0 {
			out[res] = kept
		}
	}
	return out
}

// The adapter must stay an apikey.PermissionChecker.
var _ apikey.PermissionChecker = Checker{}
