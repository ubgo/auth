package oidcclient

import (
	"context"
	"encoding/json"
)

// Claims are the members of a verified ID token (or a userinfo answer),
// each kept as the raw JSON the server sent, so no number, nested object or
// array is reshaped before the app reads it. The typed accessors cover the
// common cases; anything else is json.Unmarshal of the raw value.
type Claims map[string]json.RawMessage

// String returns the claim name as a string, and whether it is one.
func (c Claims) String(name string) (string, bool) {
	var s string
	if raw, ok := c[name]; !ok || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// Bool returns the claim name as a boolean, and whether it is one. A claim
// holding the string "true" is not a boolean here: a caller that must accept
// that spelling (email_verified at some servers) reads both, as DefaultUser
// does.
func (c Claims) Bool(name string) (bool, bool) {
	var b bool
	if raw, ok := c[name]; !ok || json.Unmarshal(raw, &b) != nil {
		return false, false
	}
	return b, true
}

// Strings returns the claim name as a list of strings, and whether it is
// one. A single string is a list of one, as groups and roles claims are
// sent both ways.
func (c Claims) Strings(name string) ([]string, bool) {
	raw, ok := c[name]
	if !ok {
		return nil, false
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return list, true
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}, true
	}
	return nil, false
}

// Standard claim names the package reads (OpenID Connect Core section 5.1,
// Front- and Back-Channel Logout).
const (
	ClaimSubject       = "sub"
	ClaimIssuer        = "iss"
	ClaimEmail         = "email"
	ClaimEmailVerified = "email_verified"
	ClaimName          = "name"
	ClaimSessionID     = "sid"
)

// Identity is who the login server says signed in: the verified ID token's
// claims, read once. Only the package builds one, after every floor check
// passed (signature, alg, iss, aud, exp, azp, nonce at sign-in, the same sub
// and iss at refresh), so a UserMapper can trust every field.
type Identity struct {
	// Issuer and Subject together name the person at the login server. They
	// key back-channel logout, so no mapper may change them on a User.
	Issuer  string
	Subject string
	Email   string
	// EmailVerified is true only for the boolean true or the string "true".
	EmailVerified bool
	Name          string
	// ProviderSessionID is the ID token's sid: the login server's session,
	// which a back-channel logout token names. Empty when the server sends
	// none (Google does not).
	ProviderSessionID string
	// Claims are every member of the ID token, the ones above included.
	Claims Claims
}

// User is the signed-in person as the app sees it: UserFrom returns it on
// every request the middleware let through. DefaultUser fills it from the
// Identity; a UserMapper replaces or enriches it (the app's own user id,
// roles from a groups claim).
//
// It is stored in the session, so its size is the cookie's size under the
// default store: a mapper that does not need Claims may set it to nil.
type User struct {
	// ID is the app's id for the person. DefaultUser sets it to Subject; a
	// mapper that links to the app's own user table sets that row's id.
	ID string `json:"id"`
	// Issuer and Subject are the Identity's and cannot be changed by a
	// mapper: a User whose Issuer or Subject differ is refused (fail closed),
	// because back-channel logout finds sessions by them.
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Name          string   `json:"name,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	Claims        Claims   `json:"claims,omitempty"`
}

// DefaultUser is the User the package stores when no UserMapper is set:
// every field copied from id, ID set to the Subject, no Roles. A mapper
// usually starts from it and changes what it needs.
func DefaultUser(id Identity) User {
	return User{
		ID: id.Subject, Issuer: id.Issuer, Subject: id.Subject, Email: id.Email,
		EmailVerified: id.EmailVerified, Name: id.Name, Claims: id.Claims,
	}
}

// MapReason says why a UserMapper is called.
type MapReason string

const (
	// MapSignIn is the callback of a sign-in: the first time this session
	// sees the Identity. A mapper that creates the app's user does it here.
	MapSignIn MapReason = "sign_in"
	// MapRefresh is a re-check that brought a new ID token (a refresh at a
	// server that issues one), so roles derived from claims stay current.
	// Previous is set.
	MapRefresh MapReason = "refresh"
)

// MapReasonValues is every MapReason.
var MapReasonValues = []MapReason{MapSignIn, MapRefresh}

// MapUserRequest is what a UserMapper decides from. A struct, so fields can
// be added without breaking mappers.
type MapUserRequest struct {
	Reason   MapReason
	Identity Identity
	// Previous is the User stored in the session before a MapRefresh; nil
	// at MapSignIn.
	Previous *User
	// AccessToken is the session's current access token, for a mapper that
	// calls the userinfo endpoint (Provider.UserInfo) or an API of the login
	// server.
	AccessToken Secret
	// Provider calls the login server with the client's credentials.
	Provider *Provider
}

// UserMapper turns a verified Identity into the app's User: link or create
// the app's own user, derive roles from claims, refuse an unverified email.
// It is the "OnLogin" hook. Returning ErrAccessDenied (or an error wrapping
// it) refuses with the no-access response; any other error refuses as a
// failure. Either way no session is written (MapSignIn) or the session ends
// (MapRefresh): a mapper error never lets anyone in.
type UserMapper func(ctx context.Context, in MapUserRequest) (User, error)
