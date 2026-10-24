package oauthprovider

import (
	"encoding/json"
	"slices"
	"strings"
)

// levelZeroACR is the only authentication context class this provider
// asserts: no claim about how the user signed in.
const levelZeroACR = "0"

// claimsRequest is the OpenID Connect claims request parameter (Core section
// 5.5): a JSON object with optional "userinfo" and "id_token" members, each an
// object of claim name to null or a request object. Unknown top-level members
// are ignored, as they change nothing.
type claimsRequest struct {
	UserInfo map[string]json.RawMessage `json:"userinfo"`
	IDToken  map[string]json.RawMessage `json:"id_token"`
}

// acrRequest is the id_token acr member's request object.
type acrRequest struct {
	Essential *bool    `json:"essential"`
	Value     *string  `json:"value"`
	Values    []string `json:"values"`
}

// parseClaimsRequest decodes a claims parameter; false when it is not a
// valid claims request object (members are objects or null, acr's essential a
// boolean, value a string, values strings).
func parseClaimsRequest(raw string) (claimsRequest, bool) {
	var top map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &top) != nil || top == nil {
		return claimsRequest{}, false
	}
	var cr claimsRequest
	for _, member := range []string{"userinfo", "id_token"} {
		v, ok := top[member]
		if !ok {
			continue
		}
		var m map[string]json.RawMessage
		if json.Unmarshal(v, &m) != nil || m == nil {
			return claimsRequest{}, false
		}
		for _, c := range m {
			if string(c) == "null" {
				continue
			}
			var obj map[string]json.RawMessage
			if json.Unmarshal(c, &obj) != nil {
				return claimsRequest{}, false
			}
		}
		if member == "userinfo" {
			cr.UserInfo = m
		} else {
			cr.IDToken = m
		}
	}
	if raw, ok := cr.IDToken["acr"]; ok && string(raw) != "null" {
		var a acrRequest
		if json.Unmarshal(raw, &a) != nil {
			return claimsRequest{}, false
		}
	}
	return cr, true
}

// acrSatisfiable reports whether an essential acr request can be met: it
// must allow level "0", the only one asserted.
func (cr claimsRequest) acrSatisfiable() bool {
	raw, ok := cr.IDToken["acr"]
	if !ok || string(raw) == "null" {
		return true
	}
	var a acrRequest
	_ = json.Unmarshal(raw, &a) // parseClaimsRequest checked it
	if a.Essential == nil || !*a.Essential {
		return true
	}
	return (a.Value == nil || *a.Value == levelZeroACR) && (a.Values == nil || slices.Contains(a.Values, levelZeroACR))
}

// requestedUserInfo is the userinfo claim names the request asks for, kept
// to the supported claims, in a fixed order so stored lists compare equal.
func (cr claimsRequest) requestedUserInfo(supported []string) []string {
	var out []string
	for name := range cr.UserInfo {
		if slices.Contains(supported, name) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// supportedClaims is AdvertisedClaims, or the provider's own claims.
func (p *Plugin) supportedClaims() []string {
	if p.advertisedClaims != nil {
		return p.advertisedClaims
	}
	return builtinClaims
}

// standardClaims maps each claim the scopes release to its scope.
var standardClaims = map[string]string{
	claimName: ScopeProfile, claimPicture: ScopeProfile, claimGivenName: ScopeProfile, claimFamilyName: ScopeProfile,
	claimEmail: ScopeEmail, claimEmailVerified: ScopeEmail,
}

// splitDisplayName splits a name: the last space-separated word is the
// family name and the rest the given name; a single word is neither.
func splitDisplayName(name string) (given, family string) {
	parts := strings.Fields(name)
	if len(parts) <= 1 {
		return "", ""
	}
	return strings.Join(parts[:len(parts)-1], " "), parts[len(parts)-1]
}

// joinClaims and splitClaims store a claim-name list in a column.
func joinClaims(names []string) *string { return optional(strings.Join(names, listSeparator)) }
func splitClaims(s *string) []string    { return strings.Fields(deref(s)) }
