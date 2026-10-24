package oauthprovider

import (
	"maps"
	"slices"
	"strings"
)

// paramResource is the RFC 8707 parameter, the one an authorize or token
// request may repeat.
const paramResource = "resource"

// joinResources validates the values of a repeated resource parameter and
// joins them space-separated, the form every Resource field carries. A
// value holding whitespace could not be split back, so it is refused.
func joinResources(values []string) (string, error) {
	for _, v := range values {
		if v == "" || strings.ContainsAny(v, " \t\n") {
			return "", ErrInvalidTarget
		}
	}
	return strings.Join(dedupe(values), listSeparator), nil
}

// splitResources is the resources of a joined Resource field.
func splitResources(joined string) []string { return strings.Fields(joined) }

// narrowResources is the resources a token or refresh request may ask
// for: a subset of the ones authorized (RFC 8707 section 2.2), or all of
// them when it names none.
func narrowResources(requested, authorized string) (string, error) {
	if requested == "" {
		return authorized, nil
	}
	have := splitResources(authorized)
	for _, r := range splitResources(requested) {
		if !slices.Contains(have, r) {
			return "", ErrInvalidTarget
		}
	}
	return requested, nil
}

// combinePolicy folds one resource's policy into the policy of a request
// for several: the shortest lifetimes, DPoP when any requires it, every custom
// claim, and one signing algorithm and key at most, conflicting pins being
// invalid_request.
func combinePolicy(into *Resource, pol Resource) error {
	shorter := func(a, b *int64) *int64 {
		if a == nil || (b != nil && *b < *a) {
			return b
		}
		return a
	}
	into.AccessTTL, into.RefreshTTL = shorter(into.AccessTTL, pol.AccessTTL), shorter(into.RefreshTTL, pol.RefreshTTL)
	into.DPoPRequired = into.DPoPRequired || pol.DPoPRequired
	if len(pol.CustomClaims) > 0 {
		if into.CustomClaims == nil {
			into.CustomClaims = map[string]any{}
		}
		maps.Copy(into.CustomClaims, pol.CustomClaims)
	}
	for _, pin := range []struct {
		to   *string
		from string
	}{{&into.SigningAlgorithm, pol.SigningAlgorithm}, {&into.SigningKeyID, pol.SigningKeyID}} {
		switch {
		case pin.from == "":
		case *pin.to == "":
			*pin.to = pin.from
		case *pin.to != pin.from:
			return ErrInvalidRequest
		}
	}
	return nil
}

// HasResource reports whether the token was issued for resource, one of
// the resources it names.
func (t AccessToken) HasResource(resource string) bool {
	return slices.Contains(splitResources(t.Resource), resource)
}
