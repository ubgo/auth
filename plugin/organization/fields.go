package organization

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Additional fields: better-auth's additionalFields on the organization,
// member, invitation, team and organization-role schemas. Each is a real
// column the app declares, migrated with the plugin's tables, typed like a
// core column extension (auth.ColumnType), and carried in a "fields" object
// on the requests that create or change the row and on every read of it.

// Field is one extra column on one of the plugin's tables.
type Field struct {
	// Name is the column name; it must match FieldNamePattern and must not
	// be one of the table's own columns.
	Name string
	// Type is one of auth.ColumnTypeValues; a value is decoded as the core
	// decodes sign-up fields (auth.Fields): a JSON string for text, an
	// integer for int, true or false for bool, an RFC 3339 string for
	// timestamp, null for a nullable column.
	Type     auth.ColumnType
	Nullable bool
	// Default is a constant SQL literal ('x', 42, true, false) or empty. A
	// NOT NULL field needs one, so existing rows can be filled.
	Default string
	// Required refuses a create that does not give the field
	// (better-auth's required: true).
	Required bool
	// ServerOnly refuses the field in a request from a client: only Go
	// calls and hooks set it (better-auth's input: false). For a value the
	// app decides, such as a plan or an external id.
	ServerOnly bool
}

// FieldsConfig lists the extra columns per table (WithFields). Team fields
// need Teams and role fields DynamicRoles; Validate refuses them otherwise.
type FieldsConfig struct {
	Org, Member, Invitation, Team, Role []Field
}

// FieldNamePattern is what an extra column may be named: the core's rule for
// column extensions, so a name is a plain identifier on every engine.
var FieldNamePattern = auth.KindNamePattern

// fieldDefaultPattern is a constant SQL literal: a quoted string without a
// quote inside, an integer, or a boolean. Anything else would be SQL from
// configuration in a migration.
var fieldDefaultPattern = regexp.MustCompile(`^('[^']*'|-?[0-9]+|true|false)$`)

// WithFields declares extra columns on the plugin's tables.
func WithFields(cfg FieldsConfig) Option { return func(p *Plugin) { p.fields = cfg } }

// fieldSet is the extra columns of one table.
type fieldSet struct {
	label  string // migration label: org, member, invitation, team, role
	table  sqlb.Table
	fields []Field
	own    []string // the table's own columns, which a field may not shadow
}

// fieldSets lists every table's extra columns, in a fixed order.
func (p *Plugin) fieldSets() []fieldSet {
	return []fieldSet{
		{"org", TableOrg, p.fields.Org, []string{ColOrgID, ColOrgSlug, ColOrgName, ColOrgCreatedAt, ColOrgLogo, ColOrgMetadata}},
		{"member", TableMember, p.fields.Member, []string{ColMemberOrgID, ColMemberUserID, ColMemberRole, ColMemberJoinedAt}},
		{"invitation", TableInvite, p.fields.Invitation, []string{ColInviteID, ColInviteOrgID, ColInviteEmail, ColInviteKind, ColInviteIdentifier, ColInviteRole, ColInviteInvitedBy, ColInviteExpiresAt, ColInviteAccepted, ColInviteCreatedAt, ColInviteStatus, ColInviteTeamID}},
		{"team", TableTeam, p.fields.Team, []string{ColTeamID, ColTeamOrgID, ColTeamName, ColTeamCreatedAt, ColTeamUpdatedAt}},
		{"role", TableRole, p.fields.Role, []string{ColRoleID, ColRoleOrgID, ColRoleName, ColRolePermission, ColRoleCreatedAt, ColRoleUpdatedAt}},
	}
}

// validateFields refuses a field that could not be migrated or read back.
func (p *Plugin) validateFields() error {
	if len(p.fields.Team) > 0 && p.teams == nil {
		return fmt.Errorf("organization.WithFields: team fields need Teams")
	}
	if len(p.fields.Role) > 0 && p.dynamic == nil {
		return fmt.Errorf("organization.WithFields: role fields need DynamicRoles")
	}
	for _, s := range p.fieldSets() {
		seen := map[string]bool{}
		for _, f := range s.fields {
			switch {
			case !FieldNamePattern.MatchString(f.Name):
				return fmt.Errorf("organization.WithFields: %s field %q must match %s", s.label, f.Name, FieldNamePattern)
			case slices.Contains(s.own, f.Name) || seen[f.Name]:
				return fmt.Errorf("organization.WithFields: %s field %q is already a column", s.label, f.Name)
			case !slices.Contains(auth.ColumnTypeValues, f.Type):
				return fmt.Errorf("organization.WithFields: %s field %q has unknown type %q", s.label, f.Name, f.Type)
			case f.Default != "" && !fieldDefaultPattern.MatchString(f.Default):
				return fmt.Errorf("organization.WithFields: %s field %q default must be a constant literal", s.label, f.Name)
			case !f.Nullable && f.Default == "":
				return fmt.Errorf("organization.WithFields: %s field %q is NOT NULL with no default, so existing rows cannot be filled", s.label, f.Name)
			case f.Required && s.label == "member":
				// A member joins by accepting an invitation, which carries
				// no member fields: a required one could never be met.
				return fmt.Errorf("organization.WithFields: member field %q cannot be Required; give it a Default", f.Name)
			}
			seen[f.Name] = true
		}
	}
	return nil
}

// fieldMigrations adds each declared column, one ledger entry per field, so
// declaring one later migrates then.
func (p *Plugin) fieldMigrations(t auth.SQLTypes) []auth.Migration {
	var out []auth.Migration
	for _, s := range p.fieldSets() {
		for _, f := range s.fields {
			typ := map[auth.ColumnType]string{auth.ColumnText: t.Value, auth.ColumnTimestamp: t.Timestamp, auth.ColumnBool: t.Bool, auth.ColumnInt: t.Int}[f.Type]
			null := " NOT NULL"
			if f.Nullable {
				null = " NULL"
			}
			def := ""
			if f.Default != "" {
				def = " DEFAULT " + f.Default
			}
			out = append(out, auth.Migration{Owner: PluginName, Name: "0006_field_" + s.label + "_" + f.Name, Statements: []string{
				"ALTER TABLE " + p.core.TableName(s.table) + " ADD COLUMN " + f.Name + " " + typ + null + def,
			}})
		}
	}
	return out
}

// set returns the assignments that write f to s's columns. fromClient
// refuses ServerOnly fields; create refuses a missing Required one. A name
// that is not a declared field, or a value of the wrong type, is
// auth.ErrFieldInvalid, which names neither.
func (s fieldSet) set(f auth.Fields, fromClient, create bool) ([]sqlb.Assignment, error) {
	names := make([]string, 0, len(f))
	for n := range f {
		names = append(names, n)
	}
	slices.Sort(names)
	var out []sqlb.Assignment
	for _, n := range names {
		i := slices.IndexFunc(s.fields, func(d Field) bool { return d.Name == n })
		if i < 0 || (fromClient && s.fields[i].ServerOnly) {
			return nil, auth.ErrFieldInvalid
		}
		as, err := s.assign(s.fields[i], f[n])
		if err != nil {
			return nil, err
		}
		out = append(out, as)
	}
	if create {
		for _, d := range s.fields {
			if _, ok := f[d.Name]; d.Required && !ok {
				return nil, auth.ErrFieldInvalid
			}
		}
	}
	return out, nil
}

// assign decodes raw by d's type into the assignment that writes it.
func (s fieldSet) assign(d Field, raw json.RawMessage) (sqlb.Assignment, error) {
	null := string(bytes.TrimSpace(raw)) == "null"
	if null && !d.Nullable {
		return sqlb.Assignment{}, auth.ErrFieldInvalid
	}
	switch d.Type {
	case auth.ColumnText:
		return assignField[string](s.table, d.Name, raw, null)
	case auth.ColumnInt:
		return assignField[int64](s.table, d.Name, raw, null)
	case auth.ColumnBool:
		return assignField[bool](s.table, d.Name, raw, null)
	default: // auth.ColumnTimestamp; validateFields admits no other type
		return assignField[time.Time](s.table, d.Name, raw, null)
	}
}

// assignField decodes raw strictly as T; a number for text or a string for
// an int is refused, never converted.
func assignField[T any](table sqlb.Table, name string, raw json.RawMessage, null bool) (sqlb.Assignment, error) {
	c := sqlb.Col[*T](table, name)
	if null {
		return sqlb.Set(c, nil), nil
	}
	var v T
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&v); err != nil || dec.More() {
		return sqlb.Assignment{}, auth.ErrFieldInvalid
	}
	return sqlb.Set(c, &v), nil
}

// read returns bindings for s's columns and a function that, after each row
// is scanned, returns the values as auth.Fields (nil when s has none).
func (s fieldSet) read() ([]sqlb.Binding, func() auth.Fields) {
	if len(s.fields) == 0 {
		return nil, func() auth.Fields { return nil }
	}
	binds := make([]sqlb.Binding, len(s.fields))
	vals := make([]func() any, len(s.fields))
	for i, d := range s.fields {
		binds[i], vals[i] = bindField(s.table, d)
	}
	return binds, func() auth.Fields {
		out := auth.Fields{}
		for i, d := range s.fields {
			// bindField scans only strings, int64s, bools and times
			// (or nil), and every one of them marshals.
			b, _ := json.Marshal(vals[i]())
			out[d.Name] = b
		}
		return out
	}
}

// bindField binds d to a pointer of its Go type and returns a reader of the
// scanned value.
func bindField(table sqlb.Table, d Field) (sqlb.Binding, func() any) {
	switch d.Type {
	case auth.ColumnText:
		return bindTyped[string](table, d.Name)
	case auth.ColumnInt:
		return bindTyped[int64](table, d.Name)
	case auth.ColumnBool:
		return bindTyped[bool](table, d.Name)
	default:
		// Postgres hands back a timestamptz in the connection's zone; the
		// library answers in UTC everywhere.
		var v *time.Time
		return sqlb.Bind(sqlb.Col[*time.Time](table, d.Name), &v), func() any {
			if v == nil {
				return nil
			}
			return v.UTC()
		}
	}
}

func bindTyped[T any](table sqlb.Table, name string) (sqlb.Binding, func() any) {
	var v *T
	return sqlb.Bind(sqlb.Col[*T](table, name), &v), func() any { return v }
}

// set by table, for the call sites.
func (p *Plugin) orgFields() fieldSet        { return p.fieldSets()[0] }
func (p *Plugin) memberFields() fieldSet     { return p.fieldSets()[1] }
func (p *Plugin) invitationFields() fieldSet { return p.fieldSets()[2] }
func (p *Plugin) teamFields() fieldSet       { return p.fieldSets()[3] }
func (p *Plugin) roleFields() fieldSet       { return p.fieldSets()[4] }

// fromClient reports whether a call came from a client rather than Go code,
// for ServerOnly fields.
func fromClient(c *auth.Call) bool { return c != nil && c.Transport != auth.TransportGo }

// mergeFields returns base with over's keys replaced, a new map.
func mergeFields(base, over auth.Fields) auth.Fields {
	out := auth.Fields{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

// orgCols binds every auth_org column and the org fields to o; call done
// after each row to fill o.Fields.
func (p *Plugin) orgCols(o *Org) (cols []sqlb.Binding, done func()) {
	extra, read := p.orgFields().read()
	return append(orgBindings(o), extra...), func() { o.Fields = read() }
}

// invitationCols is orgCols for an invitation.
func (p *Plugin) invitationCols(i *Invitation) (cols []sqlb.Binding, done func()) {
	extra, read := p.invitationFields().read()
	return append(invitationBindings(i), extra...), func() { i.Fields = read() }
}

// eachMember runs the members join with where, order and a page, calling fn
// with each member's view, fields included.
func (p *Plugin) eachMember(ctx context.Context, where []sqlb.Predicate, order []sqlb.OrderTerm, limit, offset int, fn func(MemberView)) error {
	var m Member
	extra, read := p.memberFields().read()
	q := membersSelect(p.core, &m, extra...).Where(where...).Order(order...).Limit(limit).Offset(offset)
	return p.core.Each(ctx, q, func() error {
		fn(MemberView{User: auth.ViewOf(m.User), Role: m.Role, JoinedAt: m.JoinedAt, Fields: read()})
		return nil
	})
}

// merge joins the nested "fields" object and the top-level body keys
// auth.SplitBody kept, as better-auth sends additionalFields beside the
// request's own keys. A top-level key that is not a field of s is
// auth.ErrBadRequest, the answer an unknown key always got; a field sent
// both ways is auth.ErrFieldInvalid, because neither value is obviously the
// one meant. The values are checked later, by set.
func (s fieldSet) merge(nested, top auth.Fields) (auth.Fields, error) {
	if len(top) == 0 {
		return nested, nil
	}
	out := mergeFields(nested, nil)
	for k, v := range top {
		if !slices.ContainsFunc(s.fields, func(d Field) bool { return d.Name == k }) {
			return nil, auth.ErrBadRequest
		}
		if _, dup := nested[k]; dup {
			return nil, auth.ErrFieldInvalid
		}
		out[k] = v
	}
	return out, nil
}
