package ldap

import (
	"context"
	"errors"
)

// ErrInvalidCredentials is what a Directory returns when the user is
// unknown OR the password is wrong. One error for both, by contract: the
// plugin answers it as ErrCredentialsInvalid, and a Directory that told the
// two apart (in its error or in how long it took) would tell a stranger
// which usernames exist. A locked or disabled account is this error too.
var ErrInvalidCredentials = errors.New("ldap: unknown user or wrong password")

// ErrAmbiguousUser is what a Directory returns when the username matched
// more than one entry: a filter that is not specific enough, which is a
// configuration mistake. The plugin logs it and answers
// ErrCredentialsInvalid, so the person sees the same answer as for a wrong
// password and the operator sees the cause.
var ErrAmbiguousUser = errors.New("ldap: the username matched more than one entry; make the user filter specific")

// Directory checks a username and password against a directory and returns
// the user's entry. It is the plugin's only view of LDAP, so an app can put
// anything behind it: the go-ldap Client this module ships, a pooled client
// of its own, Active Directory through another library, or a fake in tests.
//
// The contract an implementation must keep, because sign-in security
// depends on it:
//
//   - an unknown user and a wrong password both return ErrInvalidCredentials
//     (or an error wrapping it), and take the same work: the Client binds a
//     decoy DN for an unknown user so both cost one search and one bind;
//   - an empty password is ErrInvalidCredentials, never an attempt: LDAP
//     treats a simple bind with an empty password as an anonymous bind,
//     which succeeds (RFC 4513 section 5.1.2);
//   - any other error is a failure to decide (the server is down, the
//     service account's password expired) and is returned as it is;
//   - the returned Entry is the authenticated user's, read after the
//     password was proven.
type Directory interface {
	Authenticate(ctx context.Context, username, password string) (Entry, error)
}

// DirectoryFunc adapts a function to Directory.
type DirectoryFunc func(ctx context.Context, username, password string) (Entry, error)

// Authenticate calls f.
func (f DirectoryFunc) Authenticate(ctx context.Context, username, password string) (Entry, error) {
	return f(ctx, username, password)
}

// Entry is a directory entry: its distinguished name and its attributes,
// each with every value the directory holds. Attribute names are as the
// directory spells them; Get matches them without regard to case, as LDAP
// does.
type Entry struct {
	DN         string
	Attributes map[string][]string
}

// Get returns the first value of the attribute named, matched without regard
// to case, or "" when the entry has none. Most profile attributes (mail, cn)
// are single-valued in practice; read Attributes for the others.
func (e Entry) Get(name string) string {
	if v := e.Attributes[name]; len(v) > 0 {
		return v[0]
	}
	for k, v := range e.Attributes {
		if len(v) > 0 && equalFold(k, name) {
			return v[0]
		}
	}
	return ""
}

// equalFold is ASCII case folding: LDAP attribute descriptions are ASCII
// (RFC 4512 section 1.4), so Unicode folding would only add surprises.
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
