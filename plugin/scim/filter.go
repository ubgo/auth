package scim

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// maxFilterTerms bounds a list filter.
const maxFilterTerms = 10

// term is one `attribute eq "value"` of a list filter. Attr is lower-cased
// with any core schema prefix removed; Type is the selector of
// `emails[type eq "work"].value`.
type term struct {
	Attr, Type, Value string
}

// errFilter is a filter this server does not support or cannot parse.
func errFilter(detail string) *Error {
	return errorf(http.StatusBadRequest, InvalidFilter, detail)
}

// parseFilter parses a subset of RFC 7644 §3.4.2.2: one to ten
// `attribute eq "value"` terms joined by `and`, attribute names and the
// operator in any case. allowed lists the attributes, lower-cased.
func parseFilter(f string, allowed ...string) ([]term, error) {
	var out []term
	rest := strings.TrimSpace(f)
	for {
		t, after, err := parseTerm(rest)
		if err != nil {
			return nil, err
		}
		key := t.Attr
		if t.Type != "" {
			key = "emails[type].value"
		}
		ok := false
		for _, a := range allowed {
			ok = ok || a == key
		}
		if !ok {
			return nil, errFilter("filtering on " + t.Attr + " is not supported")
		}
		out = append(out, t)
		if len(out) > maxFilterTerms {
			return nil, errFilter(fmt.Sprintf("at most %d terms", maxFilterTerms))
		}
		after = strings.TrimSpace(after)
		if after == "" {
			return out, nil
		}
		word, next, _ := strings.Cut(after, " ")
		if !strings.EqualFold(word, "and") {
			return nil, errFilter("only 'and' joins terms")
		}
		rest = strings.TrimSpace(next)
	}
}

// parseTerm reads `attr eq value` from the start of s and returns the rest.
func parseTerm(s string) (term, string, error) {
	attr, rest, ok := strings.Cut(s, " ")
	if !ok {
		return term{}, "", errFilter("expected: attribute eq \"value\"")
	}
	attr = stripCoreSchema(attr)
	var t term
	if open := strings.IndexByte(attr, '['); open >= 0 {
		// emails[type eq "work"].value: the selector holds spaces, so the
		// first Cut split it; join it back up to the closing bracket.
		full := attr + " " + rest
		closeAt := strings.IndexByte(full, ']')
		if closeAt < 0 {
			return term{}, "", errFilter("unclosed [")
		}
		sel, err := parseSelector(full[open+1 : closeAt])
		if err != nil {
			return term{}, "", err
		}
		suffix, after, _ := strings.Cut(full[closeAt+1:], " ")
		if !strings.EqualFold(full[:open], "emails") || !strings.EqualFold(sel.Attr, "type") || !strings.EqualFold(suffix, ".value") {
			return term{}, "", errFilter("only emails[type eq \"…\"].value is supported")
		}
		t.Attr, t.Type = "emails", sel.Value
		attr, rest = "emails.value", after
	}
	t.Attr = strings.ToLower(attr)
	op, rest, ok := strings.Cut(strings.TrimSpace(rest), " ")
	if !ok || !strings.EqualFold(op, "eq") {
		return term{}, "", errFilter("only the eq operator is supported")
	}
	v, rest, err := parseValue(strings.TrimSpace(rest))
	if err != nil {
		return term{}, "", err
	}
	t.Value = v
	return t, rest, nil
}

// parseSelector parses the inside of a value filter, `type eq "work"` or
// `primary eq true`.
func parseSelector(s string) (term, error) {
	attr, rest, ok := strings.Cut(strings.TrimSpace(s), " ")
	if !ok {
		return term{}, errFilter("expected: attribute eq value")
	}
	op, rest, ok := strings.Cut(strings.TrimSpace(rest), " ")
	if !ok || !strings.EqualFold(op, "eq") {
		return term{}, errFilter("only the eq operator is supported")
	}
	v, after, err := parseValue(strings.TrimSpace(rest))
	if err != nil || strings.TrimSpace(after) != "" {
		return term{}, errFilter("a value filter is one term")
	}
	return term{Attr: strings.ToLower(attr), Value: v}, nil
}

// parseValue reads a quoted string or a bare true, false or number.
func parseValue(s string) (string, string, error) {
	if strings.HasPrefix(s, `"`) {
		for i := 1; i < len(s); i++ {
			switch s[i] {
			case '\\':
				i++
			case '"':
				v, err := strconv.Unquote(s[:i+1])
				if err != nil {
					return "", "", errFilter("bad string")
				}
				return v, s[i+1:], nil
			}
		}
		return "", "", errFilter("unclosed string")
	}
	// s is never empty: both callers cut it after the operator from a
	// trimmed string, so something other than a space follows.
	v, rest, _ := strings.Cut(s, " ")
	return strings.ToLower(v), rest, nil
}

// stripCoreSchema removes a core schema URN prefix from an attribute path.
func stripCoreSchema(attr string) string {
	for _, urn := range []string{SchemaUser, SchemaGroup} {
		if len(attr) > len(urn) && strings.EqualFold(attr[:len(urn)+1], urn+":") {
			return attr[len(urn)+1:]
		}
	}
	return attr
}
