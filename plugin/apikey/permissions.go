package apikey

import (
	"fmt"
	"slices"
	"strings"
)

// Permissions are actions per resource on a key: what a key holds, or what
// a check asks for. JSON-encoded it is the permission object. It has the
// shape of plugin/access.Permissions, so an app holding those converts with
// apikey.Permissions(p); the plugin keeps its own type because the core
// module carries no permission engine.
type Permissions map[string][]string

// Clone returns a deep copy.
func (p Permissions) Clone() Permissions {
	out := make(Permissions, len(p))
	for res, acts := range p {
		out[res] = slices.Clone(acts)
	}
	return out
}

// PermissionChecker is the permission model behind WithPermissions: which
// permissions a key may carry, and whether a key's permissions cover a
// check. Vocabulary is the built-in one; plugin/access's accessapikey
// adapts an access control, and an app may write its own. The plugin keeps
// the rules every model shares: a key without permissions, an empty check,
// and stored permissions Check no longer accepts all grant nothing. It must
// be safe for concurrent use.
type PermissionChecker interface {
	// Check returns an error when p names anything the model does not
	// declare; the plugin wraps it in ErrBadPermissions.
	Check(p Permissions) error
	// Grants reports whether held covers want; want is never empty.
	Grants(held, want Permissions) bool
}

// Vocabulary is the built-in PermissionChecker: the resources a key's
// permissions may name and the actions each allows. auth.New refuses an
// empty one, a resource with no action and an empty or repeated action.
type Vocabulary map[string][]string

// validate refuses a vocabulary with no resource, a resource with no
// action, or an empty or repeated action, so it has one spelling for
// everything, as plugin/access does.
func (s Vocabulary) validate() error {
	if len(s) == 0 {
		return fmt.Errorf("%w: WithPermissions declares no resource", ErrBadPermissions)
	}
	for res, acts := range s {
		if strings.TrimSpace(res) == "" || len(acts) == 0 {
			return fmt.Errorf("%w: resource %q is empty or declares no action", ErrBadPermissions, res)
		}
		for i, a := range acts {
			if strings.TrimSpace(a) == "" || slices.Contains(acts[:i], a) {
				return fmt.Errorf("%w: resource %q declares an empty or repeated action %q", ErrBadPermissions, res, a)
			}
		}
	}
	return nil
}

// Check reports whether p names only declared resources and actions.
func (s Vocabulary) Check(p Permissions) error {
	for res, acts := range p {
		declared, ok := s[res]
		if !ok {
			return fmt.Errorf("unknown resource %q", res)
		}
		for _, a := range acts {
			if !slices.Contains(declared, a) {
				return fmt.Errorf("unknown action %q on %q", a, res)
			}
		}
	}
	return nil
}

// Grants reports whether granted covers every action of every resource of
// want, every action required. An empty
// want, or a resource of want with no action, is denied, since asking for
// nothing proves nothing. A resource or action of want the vocabulary no
// longer declares is denied even when granted holds it (fails closed), and
// such stale entries of granted are otherwise ignored, so the key's other
// permissions keep their answer; accessapikey answers the same.
func (s Vocabulary) Grants(granted, want Permissions) bool {
	if len(want) == 0 {
		return false
	}
	for res, acts := range want {
		declared, known := s[res]
		allowed, ok := granted[res]
		if !known || !ok || len(acts) == 0 || slices.ContainsFunc(acts, func(a string) bool { return !slices.Contains(declared, a) || !slices.Contains(allowed, a) }) {
			return false
		}
	}
	return true
}
