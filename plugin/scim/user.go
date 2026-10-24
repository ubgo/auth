package scim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// User is a SCIM user resource (RFC 7643 §4.1) as this plugin stores and
// answers it: the core schema, the enterprise extension, and their common
// attributes. Passwords, ims, photos and x509Certificates are not
// accepted; an unknown attribute is ignored.
//
//ds:def id=scim-user-3q9wk5mt owner=@khanakia stability=stable
type User struct {
	Schemas           []string        `json:"schemas"`
	ID                string          `json:"id,omitempty"`
	ExternalID        string          `json:"externalId,omitempty"`
	UserName          string          `json:"userName"`
	Name              *Name           `json:"name,omitempty"`
	DisplayName       string          `json:"displayName,omitempty"`
	Title             string          `json:"title,omitempty"`
	UserType          string          `json:"userType,omitempty"`
	PreferredLanguage string          `json:"preferredLanguage,omitempty"`
	Locale            string          `json:"locale,omitempty"`
	Timezone          string          `json:"timezone,omitempty"`
	Active            *bool           `json:"active,omitempty"`
	Emails            []MultiValue    `json:"emails,omitempty"`
	PhoneNumbers      []MultiValue    `json:"phoneNumbers,omitempty"`
	Addresses         []Address       `json:"addresses,omitempty"`
	Roles             []MultiValue    `json:"roles,omitempty"`
	Entitlements      []MultiValue    `json:"entitlements,omitempty"`
	Enterprise        *EnterpriseUser `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
	Meta              *Meta           `json:"meta,omitempty"`
}

// Name is a user's structured name.
type Name struct {
	Formatted       string `json:"formatted,omitempty"`
	FamilyName      string `json:"familyName,omitempty"`
	GivenName       string `json:"givenName,omitempty"`
	MiddleName      string `json:"middleName,omitempty"`
	HonorificPrefix string `json:"honorificPrefix,omitempty"`
	HonorificSuffix string `json:"honorificSuffix,omitempty"`
}

// MultiValue is one entry of emails, phoneNumbers, roles or entitlements.
type MultiValue struct {
	Value   string `json:"value,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// Address is one postal address.
type Address struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"streetAddress,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postalCode,omitempty"`
	Country       string `json:"country,omitempty"`
	Type          string `json:"type,omitempty"`
	Primary       bool   `json:"primary,omitempty"`
}

// EnterpriseUser is the enterprise extension (RFC 7643 §4.3).
type EnterpriseUser struct {
	EmployeeNumber string   `json:"employeeNumber,omitempty"`
	CostCenter     string   `json:"costCenter,omitempty"`
	Organization   string   `json:"organization,omitempty"`
	Division       string   `json:"division,omitempty"`
	Department     string   `json:"department,omitempty"`
	Manager        *Manager `json:"manager,omitempty"`
}

// Manager references another user. displayName is read-only and not kept.
type Manager struct {
	Value string `json:"value,omitempty"`
	Ref   string `json:"$ref,omitempty"`
}

// Meta is a resource's metadata (RFC 7643 §3.1).
type Meta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location,omitempty"`
	// Version is the weak ETag of a user's revision, W/"n"; an If-Match
	// with it makes a PUT, PATCH or DELETE conditional.
	Version string `json:"version,omitempty"`
}

// Field bounds.
const (
	maxUserName    = 512
	maxLongString  = 1024
	maxShortString = 256
	maxEmails      = 20
	maxEmailLength = 254
	maxMultiValues = 10
)

// IsActive reports the user's active flag, true when absent.
func (u User) IsActive() bool { return u.Active == nil || *u.Active }

// PrimaryEmail derives the address the library user gets: the one marked
// primary, else the first of type work, else the first; with no emails,
// userName when it is an address. Empty when none qualifies.
func (u User) PrimaryEmail() string {
	for _, e := range u.Emails {
		if e.Primary {
			return e.Value
		}
	}
	for _, e := range u.Emails {
		if strings.EqualFold(e.Type, "work") {
			return e.Value
		}
	}
	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}
	if isEmail(u.UserName) {
		return u.UserName
	}
	return ""
}

// displayName is displayName, else the formatted name, else given and family.
func (u User) displayName() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	if u.Name == nil {
		return ""
	}
	if u.Name.Formatted != "" {
		return u.Name.Formatted
	}
	return strings.TrimSpace(u.Name.GivenName + " " + u.Name.FamilyName)
}

// isEmail is a plain address of at most maxEmailLength bytes.
func isEmail(s string) bool {
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && len(s) <= maxEmailLength
}

// decodeUser turns a request document into a validated User. Entra's
// "True"/"False" strings for active and primary are coerced first, for
// IdPs that send booleans as strings.
func decodeUser(doc map[string]any) (User, error) {
	normalizeBooleans(doc)
	normalizeManager(doc)
	// doc came out of json.Unmarshal (and PATCH, which copies values of
	// the same kinds), so it always marshals.
	b, _ := json.Marshal(doc)
	var u User
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&u); err != nil {
		return User{}, errorf(http.StatusBadRequest, InvalidValue, "An attribute has the wrong type: "+err.Error())
	}
	u.ID, u.Meta = "", nil
	if u.Enterprise != nil && *u.Enterprise == (EnterpriseUser{}) {
		u.Enterprise = nil
	}
	return u, validateUser(u)
}

// validateUser checks every field bound.
func validateUser(u User) error {
	if err := checkSchemas(u.Schemas, SchemaUser, SchemaEnterpriseUser); err != nil {
		return err
	}
	switch {
	case strings.TrimSpace(u.UserName) == "" || utf8.RuneCountInString(u.UserName) > maxUserName:
		return invalid(fmt.Sprintf("userName is required and at most %d characters", maxUserName))
	case len(u.ExternalID) > maxLongString || len(u.DisplayName) > maxLongString || len(u.Title) > maxLongString:
		return invalid(fmt.Sprintf("externalId, displayName and title are at most %d characters", maxLongString))
	case len(u.UserType) > maxShortString || len(u.PreferredLanguage) > maxShortString || len(u.Locale) > maxShortString || len(u.Timezone) > maxShortString:
		return invalid(fmt.Sprintf("userType, preferredLanguage, locale and timezone are at most %d characters", maxShortString))
	case len(u.Emails) > maxEmails:
		return invalid(fmt.Sprintf("at most %d emails", maxEmails))
	case len(u.PhoneNumbers) > maxMultiValues || len(u.Addresses) > maxMultiValues || len(u.Roles) > maxMultiValues || len(u.Entitlements) > maxMultiValues:
		return invalid(fmt.Sprintf("at most %d phoneNumbers, addresses, roles and entitlements", maxMultiValues))
	}
	for _, e := range u.Emails {
		if !isEmail(e.Value) {
			return invalid("an email value is not an address")
		}
	}
	if err := checkMulti("emails", u.Emails); err != nil {
		return err
	}
	for name, list := range map[string][]MultiValue{"phoneNumbers": u.PhoneNumbers, "roles": u.Roles, "entitlements": u.Entitlements} {
		if err := checkMulti(name, list); err != nil {
			return err
		}
	}
	addr := make([]MultiValue, len(u.Addresses))
	for i, a := range u.Addresses {
		addr[i] = MultiValue{Type: a.Type, Primary: a.Primary, Value: a.Formatted + a.StreetAddress + a.Locality + a.PostalCode}
	}
	if err := checkMulti("addresses", addr); err != nil {
		return err
	}
	if u.PrimaryEmail() == "" {
		return invalid("a user needs an email, or a userName that is an email")
	}
	return nil
}

// checkMulti enforces one primary at most, distinct defined types, and
// distinct type and value pairs.
func checkMulti(name string, list []MultiValue) error {
	primaries := 0
	types, seen := map[string]bool{}, map[string]bool{}
	for _, v := range list {
		if v.Primary {
			primaries++
		}
		if v.Type != "" {
			if types[strings.ToLower(v.Type)] {
				return invalid(name + " repeats a type")
			}
			types[strings.ToLower(v.Type)] = true
		}
		k := strings.ToLower(v.Type) + "\x00" + strings.ToLower(v.Value)
		if seen[k] {
			return invalid(name + " repeats an entry")
		}
		seen[k] = true
	}
	if primaries > 1 {
		return invalid(name + " has more than one primary")
	}
	return nil
}

// checkSchemas requires base and allows only known, distinct URNs.
func checkSchemas(got []string, base string, allowed ...string) error {
	if !slices.Contains(got, base) {
		return invalid("schemas must contain " + base)
	}
	seen := map[string]bool{}
	for _, s := range got {
		if seen[s] || (s != base && !slices.Contains(allowed, s)) {
			return invalid("schemas has an unknown or repeated URN: " + s)
		}
		seen[s] = true
	}
	return nil
}

// invalid is a 400 invalidValue.
func invalid(detail string) *Error { return errorf(http.StatusBadRequest, InvalidValue, detail) }

// normalizeManager turns a manager given as a bare id, as Entra's PATCH
// sends it ("value":"<id>" on the manager path), into {"value": id}.
func normalizeManager(doc map[string]any) {
	ext, ok := doc[keyOf(doc, SchemaEnterpriseUser)].(map[string]any)
	if !ok {
		return
	}
	k := keyOf(ext, "manager")
	if id, ok := ext[k].(string); ok {
		ext[k] = map[string]any{"value": id}
	}
}

// booleanAttrs are the attributes Entra may send as "True"/"False".
var booleanAttrs = []string{"active", "primary"}

// normalizeBooleans coerces "true"/"false" strings (any case) to booleans
// wherever an active or primary attribute appears; any other string is
// left for decoding to refuse.
func normalizeBooleans(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if s, ok := val.(string); ok && slices.ContainsFunc(booleanAttrs, func(a string) bool { return strings.EqualFold(a, k) }) {
				switch strings.ToLower(s) {
				case "true":
					t[k] = true
				case "false":
					t[k] = false
				}
				continue
			}
			normalizeBooleans(val)
		}
	case []any:
		for _, e := range t {
			normalizeBooleans(e)
		}
	}
}
