// Package schema holds the app's own ent schemas. Nothing here describes an
// auth table: the library owns those and the app only reads them.
package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// Note is the app's own row, written next to a user the library creates.
// UserID holds an auth_user id with no foreign key, as every app table beside
// the library does.
type Note struct{ ent.Schema }

// Fields of Note.
func (Note) Fields() []ent.Field {
	return []ent.Field{
		field.String("user_id").NotEmpty(),
		field.String("body").NotEmpty(),
	}
}
