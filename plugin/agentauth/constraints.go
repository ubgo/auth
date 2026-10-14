package agentauth

import (
	"bytes"
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"strings"
)

// Constraint operators, protocol section 2.13.
const (
	OpEq    = "eq"
	OpMin   = "min"
	OpMax   = "max"
	OpIn    = "in"
	OpNotIn = "not_in"
)

// Constraints scope a grant: each key is an argument name, each value the
// rule the argument must satisfy, such as {"amount": {"max": 1000},
// "currency": {"in": ["USD", "EUR"]}}. Nil is an unrestricted grant.
type Constraints map[string]Constraint

// primitiveKind is the JSON type of a Primitive.
type primitiveKind uint8

const (
	kindString primitiveKind = iota + 1
	kindNumber
	kindBool
)

// Primitive is a JSON string, number or boolean: the values a constraint
// compares against.
type Primitive struct {
	kind primitiveKind
	s    string
	n    float64
	b    bool
}

// String, Number and Bool build Primitives.
func String(s string) Primitive { return Primitive{kind: kindString, s: s} }

// Number is a numeric Primitive.
func Number(n float64) Primitive { return Primitive{kind: kindNumber, n: n} }

// Bool is a boolean Primitive.
func Bool(b bool) Primitive { return Primitive{kind: kindBool, b: b} }

// UnmarshalJSON accepts a string, a number or a boolean; anything else is
// not a primitive.
func (v *Primitive) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*v = String(s)
		return nil
	}
	var n float64
	if err := json.Unmarshal(b, &n); err == nil {
		*v = Number(n)
		return nil
	}
	var f bool
	if err := json.Unmarshal(b, &f); err != nil {
		return ErrInvalidRequest
	}
	*v = Bool(f)
	return nil
}

// MarshalJSON writes the primitive as its JSON type.
func (v Primitive) MarshalJSON() ([]byte, error) {
	switch v.kind {
	case kindNumber:
		return json.Marshal(v.n)
	case kindBool:
		return json.Marshal(v.b)
	default:
		return json.Marshal(v.s)
	}
}

// Constraint is one argument's rule: a bare primitive is shorthand for eq;
// an object names operators. Unknown operators are kept, so they are
// stored as the agent sent them and refused at execution with
// ErrUnknownConstraintOperator, as in better-auth.
type Constraint struct {
	Eq    *Primitive
	Min   *float64
	Max   *float64
	In    []Primitive
	NotIn []Primitive
	// Unknown holds operators the protocol does not define.
	Unknown map[string]json.RawMessage
	// shorthand marks a bare primitive, written back as one.
	shorthand bool
}

// Eq returns the shorthand constraint "equals v".
func Eq(v Primitive) Constraint { return Constraint{Eq: &v, shorthand: true} }

// UnmarshalJSON reads a bare primitive or an operator object. The
// parameter is the JSON boundary the standard library mandates.
func (c *Constraint) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || b[0] != '{' {
		var v Primitive
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*c = Eq(v)
		return nil
	}
	var ops map[string]json.RawMessage
	if err := json.Unmarshal(b, &ops); err != nil {
		return err
	}
	var out Constraint
	for k, raw := range ops {
		var err error
		switch k {
		case OpEq:
			var v Primitive
			err = json.Unmarshal(raw, &v)
			out.Eq = &v
		case OpMin:
			err = json.Unmarshal(raw, &out.Min)
		case OpMax:
			err = json.Unmarshal(raw, &out.Max)
		case OpIn:
			err = json.Unmarshal(raw, &out.In)
		case OpNotIn:
			err = json.Unmarshal(raw, &out.NotIn)
		default:
			if out.Unknown == nil {
				out.Unknown = map[string]json.RawMessage{}
			}
			out.Unknown[k] = raw
		}
		if err != nil {
			return ErrInvalidRequest
		}
	}
	*c = out
	return nil
}

// MarshalJSON writes the constraint in the form it was read.
func (c Constraint) MarshalJSON() ([]byte, error) {
	if c.shorthand && c.Eq != nil {
		return json.Marshal(*c.Eq)
	}
	m := map[string]json.RawMessage{}
	for k, v := range c.Unknown {
		m[k] = v
	}
	put := func(k string, v any) error {
		b, err := json.Marshal(v)
		m[k] = b
		return err
	}
	var err error
	if c.Eq != nil {
		err = put(OpEq, *c.Eq)
	}
	if c.Min != nil && err == nil {
		err = put(OpMin, *c.Min)
	}
	if c.Max != nil && err == nil {
		err = put(OpMax, *c.Max)
	}
	if c.In != nil && err == nil {
		err = put(OpIn, c.In)
	}
	if c.NotIn != nil && err == nil {
		err = put(OpNotIn, c.NotIn)
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// toNumber is v as a finite number: a number, or a string that parses as
// one. Agents send arguments through LLM tool calls, which often quote
// numbers; "", whitespace, words and infinities stay non-numeric.
func toNumber(v any) (float64, bool) {
	var f float64
	switch x := v.(type) {
	case float64:
		f = x
	case float32:
		f = float64(x)
	case int:
		f = float64(x)
	case int64:
		f = float64(x)
	case json.Number:
		n, err := x.Float64()
		if err != nil {
			return 0, false
		}
		f = n
	case string:
		if strings.TrimSpace(x) == "" {
			return 0, false
		}
		n, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		if err != nil {
			return 0, false
		}
		f = n
	default:
		return 0, false
	}
	return f, !math.IsInf(f, 0) && !math.IsNaN(f)
}

// equals compares an argument with an operand, directed by the operand's
// type, better-auth's primitivesEqual: a numeric operand matches a quoted
// number, a string operand matches a number written the same way, and
// "007" never equals 7. It also closes a not_in bypass: not_in [666]
// still refuses "666".
func equals(actual any, operand Primitive) bool {
	switch operand.kind {
	case kindNumber:
		n, ok := toNumber(actual)
		return ok && n == operand.n
	case kindBool:
		b, ok := actual.(bool)
		return ok && b == operand.b
	default:
		if s, ok := actual.(string); ok {
			return s == operand.s
		}
		if _, isString := actual.(string); !isString {
			if n, ok := toNumber(actual); ok {
				return strconv.FormatFloat(n, 'f', -1, 64) == operand.s
			}
		}
		return false
	}
}

// check reports whether actual satisfies c, and the unknown operators c
// carries.
func (c Constraint) check(actual any) (ok bool, unknown []string) {
	for k := range c.Unknown {
		unknown = append(unknown, k)
	}
	slices.Sort(unknown)
	ok = true
	if c.Eq != nil && !equals(actual, *c.Eq) {
		ok = false
	}
	if c.Min != nil {
		if n, isNum := toNumber(actual); !isNum || n < *c.Min {
			ok = false
		}
	}
	if c.Max != nil {
		if n, isNum := toNumber(actual); !isNum || n > *c.Max {
			ok = false
		}
	}
	if c.In != nil && !slices.ContainsFunc(c.In, func(v Primitive) bool { return equals(actual, v) }) {
		ok = false
	}
	if c.NotIn != nil && slices.ContainsFunc(c.NotIn, func(v Primitive) bool { return equals(actual, v) }) {
		ok = false
	}
	return ok, unknown
}

// Validate checks args against the constraints: ErrUnknownConstraintOperator
// when a rule names an operator the protocol does not define (checked
// first, as better-auth does), ErrConstraintViolated when an argument
// breaks a rule. A missing argument breaks every rule on it.
func (cs Constraints) Validate(args map[string]any) error {
	violated := false
	for field, c := range cs {
		ok, unknown := c.check(args[field])
		if len(unknown) > 0 {
			return ErrUnknownConstraintOperator
		}
		if !ok {
			violated = true
		}
	}
	if violated {
		return ErrConstraintViolated
	}
	return nil
}

// Covers reports whether a grant scoped by cs already allows everything a
// request scoped by req would, better-auth's constraintsCover: an
// unrestricted grant covers everything, a restricted one never covers an
// unrestricted request, and otherwise each requested field must be within
// the existing rule on it.
func (cs Constraints) Covers(req Constraints) bool {
	if cs == nil {
		return true
	}
	if req == nil {
		return false
	}
	for field, r := range req {
		e, ok := cs[field]
		if !ok {
			continue
		}
		if !fieldCovers(e, r) {
			return false
		}
	}
	return true
}

// fieldCovers is better-auth's fieldConstraintCovers.
func fieldCovers(e, r Constraint) bool {
	switch {
	case e.Eq != nil:
		if r.Eq != nil {
			return *r.Eq == *e.Eq
		}
		return len(r.In) == 1 && r.In[0] == *e.Eq
	case e.In != nil:
		if r.Eq != nil {
			return slices.Contains(e.In, *r.Eq)
		}
		if r.In == nil {
			return false
		}
		for _, v := range r.In {
			if !slices.Contains(e.In, v) {
				return false
			}
		}
		return true
	}
	if r.Min != nil && e.Min != nil && *r.Min < *e.Min {
		return false
	}
	if r.Max != nil && e.Max != nil && *r.Max > *e.Max {
		return false
	}
	eb, err1 := json.Marshal(e)
	rb, err2 := json.Marshal(r)
	return err1 == nil && err2 == nil && string(eb) == string(rb)
}
