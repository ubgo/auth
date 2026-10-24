package scim

import (
	"net/url"
	"strings"
)

// alwaysReturned survive every projection (RFC 7643 §7 "returned: always").
var alwaysReturned = []string{"schemas", "id"}

// projection is a parsed attributes or excludedAttributes list.
type projection struct {
	include bool
	paths   [][2]string // attribute, sub-attribute ("" for the whole attribute)
}

// parseProjection reads attributes and excludedAttributes from q; giving
// both is invalidValue.
func parseProjection(q url.Values) (*projection, error) {
	inc, exc := q.Get("attributes"), q.Get("excludedAttributes")
	switch {
	case inc != "" && exc != "":
		return nil, invalid("attributes and excludedAttributes are mutually exclusive")
	case inc == "" && exc == "":
		return nil, nil
	}
	pr := &projection{include: inc != ""}
	for _, raw := range strings.Split(inc+exc, ",") {
		raw = stripCoreSchema(strings.TrimSpace(raw))
		if raw == "" {
			continue
		}
		var a, s string
		if len(raw) > len(SchemaEnterpriseUser) && strings.EqualFold(raw[:len(SchemaEnterpriseUser)+1], SchemaEnterpriseUser+":") {
			a, s = SchemaEnterpriseUser, raw[len(SchemaEnterpriseUser)+1:]
		} else {
			a, s, _ = strings.Cut(raw, ".")
		}
		pr.paths = append(pr.paths, [2]string{a, s})
	}
	return pr, nil
}

// apply projects doc in place.
func (pr *projection) apply(doc map[string]any) {
	if pr == nil {
		return
	}
	if !pr.include {
		for _, p := range pr.paths {
			if isAlways(p[0]) && p[1] == "" {
				continue
			}
			k := keyOf(doc, p[0])
			if p[1] == "" {
				delete(doc, k)
				continue
			}
			if m, ok := doc[k].(map[string]any); ok {
				delete(m, keyOf(m, p[1]))
			}
		}
		return
	}
	keep := map[string]map[string]bool{} // attribute (lower) → sub-attributes (lower), nil for all
	for _, p := range pr.paths {
		a := strings.ToLower(p[0])
		if p[1] == "" {
			keep[a] = nil
			continue
		}
		if subs, seen := keep[a]; !seen || subs != nil {
			if subs == nil {
				subs = map[string]bool{}
			}
			subs[strings.ToLower(p[1])] = true
			keep[a] = subs
		}
	}
	for k, v := range doc {
		if isAlways(k) {
			continue
		}
		subs, ok := keep[strings.ToLower(k)]
		if !ok {
			delete(doc, k)
			continue
		}
		if subs == nil {
			continue
		}
		if m, ok := v.(map[string]any); ok {
			for sk := range m {
				if !subs[strings.ToLower(sk)] {
					delete(m, sk)
				}
			}
		}
	}
}

// isAlways reports an attribute every answer keeps.
func isAlways(attr string) bool {
	for _, a := range alwaysReturned {
		if strings.EqualFold(a, attr) {
			return true
		}
	}
	return false
}
