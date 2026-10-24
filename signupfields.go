package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/sqlb"
)

// Sign-up fields: the extra columns a sign-up body may set on the new
// account. A field is an auth_user column the app declared with
// WithUserColumns and listed with WithSignUpFields; nothing else can be
// named, so a request can never set a core column (the name, a verification
// flag) or a plugin's (a ban, two-factor), whatever it sends.

// Fields is the "fields" object of a sign-up body: column name to JSON value.
// A value is decoded by the column's declared type: a JSON string for text,
// an integer for int, true or false for bool, an RFC 3339 string for
// timestamp, and null for a nullable column.
//
//ds:def id=core-fields-4kd9wq2n owner=@khanakia stability=stable
type Fields map[string]json.RawMessage

// ErrFieldInvalid refuses a sign-up field that is not one WithSignUpFields
// listed, or whose value does not have the column's type. It names neither,
// so a probe learns nothing about the schema.
var ErrFieldInvalid = NewError("auth.field_invalid", http.StatusBadRequest, "A field in this request cannot be set, or has the wrong type.")

// WithSignUpFields lets a sign-up body set the listed app columns of the new
// account (Fields). Each must be a column WithUserColumns declared: New
// refuses a core column, a plugin's column, or a name nobody declared,
// because a column the app did not mark writable by strangers (a role, a
// ban) must not become one by a typo.
//
//ds:def id=opt-withsignupfields-8mn3wq7k owner=@khanakia stability=stable
func WithSignUpFields(cols ...string) Option {
	return func(s *settings) { s.signUpFields = append(s.signUpFields, cols...) }
}

// resolveSignUpFields checks WithSignUpFields against the app's columns. It
// runs after collectColumns.
func (a *Auth) resolveSignUpFields(names []string) error {
	fields, err := a.resolveFields("WithSignUpFields", names)
	a.signUpFields = fields
	return err
}

// resolveFields maps names to the app columns WithUserColumns declared, or
// fails naming option for one that is not such a column. nil for no names.
func (a *Auth) resolveFields(option string, names []string) (map[string]ColumnExtension, error) {
	var out map[string]ColumnExtension
	for _, n := range names {
		i := slices.IndexFunc(a.columns, func(c ColumnExtension) bool { return c.owner == AppName && c.Name == n })
		if i < 0 {
			return nil, fmt.Errorf("%w: %s names %q, which is not a WithUserColumns column", ErrBadOperation, option, n)
		}
		if out == nil {
			out = map[string]ColumnExtension{}
		}
		out[n] = a.columns[i]
	}
	return out, nil
}

// WithProfileFields lets POST /auth/profile (Auth.UpdateProfile) set the
// listed app columns of the signed-in user's own row, ProfileRequest.Fields.
// The rules are the sign-up fields': each must be a WithUserColumns column
// (New refuses a core column, a plugin's or an undeclared name), a value must
// have the column's type, and anything else is ErrFieldInvalid with nothing
// written. A column the user must not change for themselves (a plan, a role)
// is simply not listed; the app writes it with SetUserColumn from its own
// route.
//
//ds:def id=opt-withprofilefields-4nw8qk2x owner=@khanakia stability=stable
func WithProfileFields(cols ...string) Option {
	return func(s *settings) { s.profileFields = append(s.profileFields, cols...) }
}

// fieldValue is one decoded field: the SQL assignment for its column.
type fieldValue = sqlb.Assignment

// decodeFields checks f and returns its assignments in column-name order, so
// the statement text is the same for the same fields.
func (a *Auth) decodeFields(f Fields) ([]fieldValue, error) {
	return decodeFieldsFrom(a.signUpFields, f)
}

// decodeFieldsFrom is decodeFields against the allowed columns.
func decodeFieldsFrom(allowed map[string]ColumnExtension, f Fields) ([]fieldValue, error) {
	names := make([]string, 0, len(f))
	for n := range f {
		names = append(names, n)
	}
	slices.Sort(names)
	out := make([]fieldValue, 0, len(names))
	for _, n := range names {
		col, ok := allowed[n]
		if !ok {
			return nil, ErrFieldInvalid
		}
		as, err := fieldAssignment(col, f[n])
		if err != nil {
			return nil, ErrFieldInvalid
		}
		out = append(out, as)
	}
	return out, nil
}

// fieldAssignment decodes raw by col's type into the assignment that writes
// it. Strict: a number for a text column or a string for an int is refused,
// never converted.
func fieldAssignment(col ColumnExtension, raw json.RawMessage) (fieldValue, error) {
	null := string(bytes.TrimSpace(raw)) == jsonNull
	if null && !col.Nullable {
		return fieldValue{}, ErrFieldInvalid
	}
	switch col.Type {
	case ColumnText:
		return decodeField[string](col, raw, null)
	case ColumnInt:
		return decodeField[int64](col, raw, null)
	case ColumnBool:
		return decodeField[bool](col, raw, null)
	case ColumnTimestamp:
		return decodeField[time.Time](col, raw, null)
	default:
		// collectColumns refuses any other type; reaching this means a
		// value changed after wiring. Fail closed.
		return fieldValue{}, ErrFieldInvalid
	}
}

// decodeField decodes raw as T into a pointer assignment, nil for null.
func decodeField[T any](col ColumnExtension, raw json.RawMessage, null bool) (fieldValue, error) {
	c := sqlb.Col[*T](TableUser, col.Name)
	if null {
		return sqlb.Set(c, nil), nil
	}
	var v T
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&v); err != nil || dec.More() {
		return fieldValue{}, ErrFieldInvalid
	}
	return sqlb.Set(c, &v), nil
}

// CheckFields reports whether f may be written by SetFields: every name a
// WithSignUpFields column, every value of its type. Empty is valid. An
// operation calls it before it changes anything, so a bad field refuses the
// whole sign-up rather than half of it.
//
//ds:def id=core-checkfields-2wq7nk5d owner=@khanakia stability=stable
func (a *Auth) CheckFields(f Fields) error {
	_, err := a.decodeFields(f)
	return err
}

// SetFields writes f to userID's auth_user row in one UPDATE, inside the
// transaction in ctx, after the same checks as CheckFields. Empty writes
// nothing. It is the sign-up path's one exception to "only the owner writes
// a column", and only for columns the app listed in WithSignUpFields.
//
//ds:def id=core-setfields-6hn2wq8d owner=@khanakia stability=stable
func (a *Auth) SetFields(ctx context.Context, userID string, f Fields) error {
	sets, err := a.decodeFields(f)
	if err != nil || len(sets) == 0 {
		return err
	}
	return a.writeFields(ctx, userID, sets)
}

// writeFields writes decoded fields to userID's auth_user row.
func (a *Auth) writeFields(ctx context.Context, userID string, sets []fieldValue) error {
	q := sqlb.NewUpdate(a.cfg.Dialect).Table(TableUser).
		Set(append(sets, sqlb.Set(UserUpdatedAt, a.now()))...).Where(sqlb.Eq(UserID, userID))
	if _, err := a.Exec(ctx, q); err != nil {
		return fmt.Errorf("auth: set sign-up fields: %w", err)
	}
	return nil
}

// errSplitTarget refuses a SplitBody destination that is not a pointer to a
// struct, a programming error in the caller.
var errSplitTarget = errors.New("auth: SplitBody needs a pointer to a struct")

// SplitBody decodes a request body whose sign-up fields sit at the top level,
// beside email and password. The keys dst declares (its json names, matched
// case-insensitively as encoding/json does) are decoded into dst strictly,
// unknown nested keys and wrong types included; every other top-level key is
// returned as Fields for MergeFields to check. A transport's UnmarshalJSON
// calls it with an alias of its own type, so the alias has no UnmarshalJSON
// to recurse into. dst is any for the reason json.Unmarshal's is: the target
// is the caller's struct, and anything but a pointer to a struct is refused
// with errSplitTarget.
//
//ds:def id=core-splitbody-8qn2wk5d owner=@khanakia stability=stable
func SplitBody(data []byte, dst any) (Fields, error) {
	rv := reflect.ValueOf(dst)
	if rv.Kind() != reflect.Pointer || rv.IsNil() || rv.Elem().Kind() != reflect.Struct {
		return nil, errSplitTarget
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, err
	}
	known := jsonNames(rv.Elem().Type())
	own := map[string]json.RawMessage{}
	var rest Fields
	for k, v := range all {
		if known[strings.ToLower(k)] {
			own[k] = v
			continue
		}
		if rest == nil {
			rest = Fields{}
		}
		rest[k] = v
	}
	body, err := json.Marshal(own)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return nil, err
	}
	return rest, nil
}

// jsonNames is every top-level JSON key t decodes, lower-cased, embedded
// structs' promoted fields included.
func jsonNames(t reflect.Type) map[string]bool {
	out := map[string]bool{}
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" && tag == "-" {
			continue
		}
		if f.Anonymous && name == "" {
			ft := f.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				maps.Copy(out, jsonNames(ft))
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[strings.ToLower(name)] = true
	}
	return out
}

// MergeFields joins the nested "fields" object and the top-level keys
// SplitBody returned. A top-level key that is not a WithSignUpFields column
// is ErrBadRequest, the answer an unknown key always got; a column sent in
// both places is ErrFieldInvalid, because neither value is obviously the
// one meant. The values themselves are checked later, by CheckFields.
//
//ds:def id=core-mergefields-3pk7wn2q owner=@khanakia stability=stable
func (a *Auth) MergeFields(nested, top Fields) (Fields, error) {
	if len(top) == 0 {
		return nested, nil
	}
	out := make(Fields, len(nested)+len(top))
	maps.Copy(out, nested)
	for k, v := range top {
		if _, ok := a.signUpFields[k]; !ok {
			return nil, ErrBadRequest
		}
		if _, dup := nested[k]; dup {
			return nil, ErrFieldInvalid
		}
		out[k] = v
	}
	return out, nil
}
