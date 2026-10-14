package scim

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
)

// PatchRequest is a PATCH body (RFC 7644 §3.5.2).
type PatchRequest struct {
	Schemas    []string  `json:"schemas"`
	Operations []PatchOp `json:"Operations"`
}

// PatchOp is one operation. Op is add, replace or remove in any case, and
// replace when empty.
type PatchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// Patch operation names, lower-cased.
const (
	opAdd     = "add"
	opReplace = "replace"
	opRemove  = "remove"
)

// readOnly attributes no operation may touch.
var readOnly = []string{"id", "schemas", "meta"}

// path is a parsed PATCH path: an attribute of the resource or of the
// enterprise extension, an optional value filter, an optional sub-attribute.
type path struct {
	ext    bool
	attr   string
	filter *term
	sub    string
}

// parsePath parses `[urn:]attr[.sub]` and `attr[filter][.sub]`.
func parsePath(p string) (path, error) {
	var out path
	p = stripCoreSchema(strings.TrimSpace(p))
	if len(p) >= len(SchemaEnterpriseUser) && strings.EqualFold(p[:len(SchemaEnterpriseUser)], SchemaEnterpriseUser) {
		out.ext = true
		p = strings.TrimPrefix(p[len(SchemaEnterpriseUser):], ":")
		if p == "" {
			return out, nil
		}
	}
	if open := strings.IndexByte(p, '['); open >= 0 {
		closeAt := strings.LastIndexByte(p, ']')
		if closeAt < open {
			return path{}, errorf(http.StatusBadRequest, InvalidPath, "unclosed [ in path")
		}
		sel, err := parseSelector(p[open+1 : closeAt])
		if err != nil {
			return path{}, errorf(http.StatusBadRequest, InvalidPath, "bad value filter in path")
		}
		out.filter = &sel
		rest := p[closeAt+1:]
		if rest != "" && !strings.HasPrefix(rest, ".") {
			return path{}, errorf(http.StatusBadRequest, InvalidPath, "bad path after ]")
		}
		out.sub = strings.TrimPrefix(rest, ".")
		p = p[:open]
	} else if a, s, ok := strings.Cut(p, "."); ok {
		p, out.sub = a, s
	}
	if p == "" || strings.ContainsAny(p, " []\"") || strings.ContainsAny(out.sub, " []\".") {
		return path{}, errorf(http.StatusBadRequest, InvalidPath, "bad path")
	}
	out.attr = p
	return out, nil
}

// applyPatch applies ops in order to doc, a resource as a document.
// required names attributes a remove may not delete. The caller decodes and
// validates the result, so a patch that breaks the resource changes nothing.
func applyPatch(doc map[string]any, ops []PatchOp, required ...string) error {
	for _, o := range ops {
		op := strings.ToLower(o.Op)
		if op == "" {
			op = opReplace
		}
		if op != opAdd && op != opReplace && op != opRemove {
			return invalid("op must be add, replace or remove")
		}
		var v any
		if len(o.Value) > 0 {
			if err := json.Unmarshal(o.Value, &v); err != nil {
				return errSyntax
			}
		}
		if o.Path == "" {
			if op == opRemove {
				return errorf(http.StatusBadRequest, NoTarget, "remove needs a path")
			}
			obj, ok := v.(map[string]any)
			if !ok {
				return invalid("an operation without a path needs an object value")
			}
			for k, val := range obj {
				p, err := parsePath(k)
				if err != nil {
					return err
				}
				if p.ext && p.attr == "" {
					sub, ok := val.(map[string]any)
					if !ok {
						return invalid("the enterprise extension is an object")
					}
					for sk, sv := range sub {
						// "manager.value" names a sub-attribute exactly as the
						// path form does, so manager.displayName stays
						// read-only and manager.value lands inside manager.
						attr, subAttr, _ := strings.Cut(sk, ".")
						if err := apply(doc, op, path{ext: true, attr: attr, sub: subAttr}, sv, required); err != nil {
							return err
						}
					}
					continue
				}
				if err := apply(doc, op, p, val, required); err != nil {
					return err
				}
			}
			continue
		}
		p, err := parsePath(o.Path)
		if err != nil {
			return err
		}
		if err := apply(doc, op, p, v, required); err != nil {
			return err
		}
	}
	return nil
}

// apply runs one operation at one path.
func apply(doc map[string]any, op string, p path, v any, required []string) error {
	if !p.ext && slices.ContainsFunc(readOnly, func(r string) bool { return strings.EqualFold(r, p.attr) }) {
		return errorf(http.StatusBadRequest, Mutability, p.attr+" is read-only")
	}
	cont := doc
	if p.ext {
		cont = childMap(doc, SchemaEnterpriseUser, op != opRemove)
		if cont == nil {
			return errorf(http.StatusBadRequest, NoTarget, "no enterprise attributes")
		}
		if p.attr == "" {
			if op == opRemove {
				delete(doc, keyOf(doc, SchemaEnterpriseUser))
				return nil
			}
			obj, ok := v.(map[string]any)
			if !ok {
				return invalid("the enterprise extension is an object")
			}
			for k, val := range obj {
				cont[k] = val
			}
			return nil
		}
		if strings.EqualFold(p.attr, "manager") && p.sub != "" && strings.EqualFold(p.sub, "displayName") {
			return errorf(http.StatusBadRequest, Mutability, "manager.displayName is read-only")
		}
	}
	key := keyOf(cont, p.attr)
	if p.filter != nil {
		return applyFiltered(cont, key, op, p, v)
	}
	if op == opRemove {
		if p.sub == "" && slices.ContainsFunc(required, func(r string) bool { return strings.EqualFold(r, p.attr) }) {
			return errorf(http.StatusBadRequest, Mutability, p.attr+" cannot be removed")
		}
		return remove(cont, key, p.sub, v)
	}
	if p.sub != "" {
		switch cur := cont[key].(type) {
		case []any:
			// emails.value: the primary entry, else the first, else a new one.
			el := pickPrimary(cur)
			if el == nil {
				el = map[string]any{"primary": true}
				cont[key] = append(cur, el)
			}
			el[keyOf(el, p.sub)] = v
		default:
			m := childMap(cont, key, true)
			m[keyOf(m, p.sub)] = v
		}
		return nil
	}
	cur, exists := cont[key]
	if list, ok := cur.([]any); ok && exists && op == opAdd {
		cont[key] = appendValues(list, v)
		return nil
	}
	if m, ok := cur.(map[string]any); ok && op == opAdd {
		if add, ok := v.(map[string]any); ok {
			for k, val := range add {
				m[keyOf(m, k)] = val
			}
			return nil
		}
	}
	cont[key] = v
	return nil
}

// applyFiltered runs an operation on `attr[filter]` and `attr[filter].sub`.
// A replace or add whose `type eq` filter matches nothing creates the entry
// (never primary), as Entra expects; any other miss is noTarget.
func applyFiltered(cont map[string]any, key, op string, p path, v any) error {
	list, _ := cont[key].([]any)
	var hits []int
	for i, e := range list {
		if m, ok := e.(map[string]any); ok && matches(m, *p.filter) {
			hits = append(hits, i)
		}
	}
	if op == opRemove {
		if len(hits) == 0 {
			return errorf(http.StatusBadRequest, NoTarget, "no value matches the filter")
		}
		if p.sub != "" {
			for _, i := range hits {
				m := list[i].(map[string]any)
				delete(m, keyOf(m, p.sub))
			}
			return nil
		}
		kept := list[:0:0]
		for i, e := range list {
			if !slices.Contains(hits, i) {
				kept = append(kept, e)
			}
		}
		cont[key] = kept
		return nil
	}
	if len(hits) == 0 {
		if p.filter.Attr != "type" {
			return errorf(http.StatusBadRequest, NoTarget, "no value matches the filter")
		}
		el := map[string]any{"type": p.filter.Value}
		if p.sub != "" {
			el[p.sub] = v
		} else if obj, ok := v.(map[string]any); ok {
			for k, val := range obj {
				el[k] = val
			}
			el["type"] = p.filter.Value
		}
		delete(el, "primary")
		cont[key] = append(list, el)
		return nil
	}
	for _, i := range hits {
		m := list[i].(map[string]any)
		if p.sub != "" {
			m[keyOf(m, p.sub)] = v
			continue
		}
		obj, ok := v.(map[string]any)
		if !ok {
			return invalid("a filtered value without a sub-attribute is an object")
		}
		for k, val := range obj {
			m[keyOf(m, k)] = val
		}
	}
	return nil
}

// remove deletes an attribute, a sub-attribute, or, when v lists values,
// the entries of a multi-valued attribute with those values (how an IdP
// removes group members).
func remove(cont map[string]any, key, sub string, v any) error {
	cur, exists := cont[key]
	if !exists {
		return nil
	}
	if sub != "" {
		if m, ok := cur.(map[string]any); ok {
			delete(m, keyOf(m, sub))
		}
		return nil
	}
	list, isList := cur.([]any)
	if !isList || v == nil {
		delete(cont, key)
		return nil
	}
	drop := map[string]bool{}
	for _, d := range asList(v) {
		if m, ok := d.(map[string]any); ok {
			if s, ok := m["value"].(string); ok {
				drop[s] = true
			}
		}
	}
	kept := list[:0:0]
	for _, e := range list {
		if m, ok := e.(map[string]any); ok {
			if s, ok := m["value"].(string); ok && drop[s] {
				continue
			}
		}
		kept = append(kept, e)
	}
	cont[key] = kept
	return nil
}

// matches reports whether a multi-value entry satisfies a value filter:
// strings compare case-insensitively, booleans by their text.
func matches(m map[string]any, f term) bool {
	switch v := m[keyOf(m, f.Attr)].(type) {
	case string:
		return strings.EqualFold(v, f.Value)
	case bool:
		return (v && f.Value == "true") || (!v && f.Value == "false")
	}
	return false
}

// appendValues adds v's entries to list, skipping an entry whose value is
// already present, so adding a member twice is one member.
func appendValues(list []any, v any) []any {
	have := map[string]bool{}
	for _, e := range list {
		if m, ok := e.(map[string]any); ok {
			if s, ok := m["value"].(string); ok {
				have[s] = true
			}
		}
	}
	for _, e := range asList(v) {
		if m, ok := e.(map[string]any); ok {
			if s, ok := m["value"].(string); ok {
				if have[s] {
					continue
				}
				have[s] = true
			}
		}
		list = append(list, e)
	}
	return list
}

// asList is v as a list: itself when it is one, else a list of one.
func asList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return []any{v}
}

// pickPrimary returns the entry marked primary, else the first, else nil.
func pickPrimary(list []any) map[string]any {
	var first map[string]any
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if first == nil {
			first = m
		}
		if p, _ := m[keyOf(m, "primary")].(bool); p {
			return m
		}
	}
	return first
}

// keyOf returns the key of m equal to name ignoring case, or name.
func keyOf(m map[string]any, name string) string {
	if _, ok := m[name]; ok {
		return name
	}
	for k := range m {
		if strings.EqualFold(k, name) {
			return k
		}
	}
	return name
}

// childMap returns m[name] as a map, creating it when create is set; nil
// when it is absent or not an object and create is not set.
func childMap(m map[string]any, name string, create bool) map[string]any {
	key := keyOf(m, name)
	if c, ok := m[key].(map[string]any); ok {
		return c
	}
	if !create {
		return nil
	}
	c := map[string]any{}
	m[key] = c
	return c
}
