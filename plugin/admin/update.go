package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// EditableColumn is one of the app's own auth_user columns
// (auth.WithUserColumns) that update-user may set from its data object
// (better-auth's update-user data). Build it with Editable; the zero value
// edits nothing.
type EditableColumn struct {
	name string
	// prepare decodes and checks a value, and returns the write that stores
	// it, so every key is checked before the first write.
	prepare func(raw json.RawMessage) (columnWrite, error)
}

// columnWrite stores one prepared value for userID.
type columnWrite func(ctx context.Context, a *auth.Auth, userID string) error

// Name is the data key the column is set by: the column name.
func (e EditableColumn) Name() string { return e.name }

// Editable lets an admin set col, an app column, through update-user's data
// object under the column's name. The JSON value must decode into T exactly
// (an unknown shape is ErrBadUserData), then check, when not nil, may refuse
// it with its own error; the write goes through auth.SetUserColumn under
// auth.AppName, so a column the app did not register is refused there
// (auth.ErrNotColumnOwner) and a plugin's columns stay that plugin's.
func Editable[T any](col sqlb.Expr[T], check func(T) error) EditableColumn {
	return EditableColumn{name: col.Name(), prepare: func(raw json.RawMessage) (columnWrite, error) {
		var v T
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&v); err != nil || dec.More() {
			return nil, ErrBadUserData
		}
		if check != nil {
			if err := check(v); err != nil {
				return nil, err
			}
		}
		return func(ctx context.Context, a *auth.Auth, userID string) error {
			return auth.SetUserColumn(ctx, a, auth.AppName, userID, col, v)
		}, nil
	}}
}

// EditableColumns declares the app columns update-user's data may set. A
// later declaration of the same name replaces the earlier one.
func EditableColumns(cols ...EditableColumn) Option {
	return func(p *Plugin) {
		for _, c := range cols {
			if c.prepare != nil {
				p.editable[c.name] = c
			}
		}
	}
}

// Keys of update-user's data that are the profile fields, set as Name and
// Image are.
const (
	DataName  = "name"
	DataImage = "image"
)

// Errors of update-user's data.
var (
	// ErrNoUserData refuses a data object with no keys, better-auth's
	// NO_DATA_TO_UPDATE: an empty edit is a client mistake, not a success.
	ErrNoUserData = auth.NewError("admin.no_user_data", http.StatusBadRequest, "There is nothing to update.")
	// ErrFieldNotEditable refuses a data key that is neither a profile field
	// nor an EditableColumns column. Passwords, addresses and roles have
	// their own operations (set-password, set-email, set-role), where their
	// rules live, so they are refused here too.
	ErrFieldNotEditable = auth.NewError("admin.field_not_editable", http.StatusBadRequest, "This field cannot be changed here.")
	// ErrBadUserData refuses a data value of the wrong type, or a name or
	// image that is not a string.
	ErrBadUserData = auth.NewError("admin.bad_user_data", http.StatusBadRequest, "A value does not fit its field.")
)

// applyData splits data into the profile update and the column writes, and
// decodes and checks every key before anything is written, so a refused key
// leaves the user untouched.
func (p *Plugin) applyData(in UpdateUserRequest) (auth.UserUpdate, []columnWrite, error) {
	upd := auth.UserUpdate{Name: in.Name, Image: in.Image}
	if in.Data == nil {
		return upd, nil, nil
	}
	if len(in.Data) == 0 {
		return upd, nil, ErrNoUserData
	}
	var writes []columnWrite
	for key, raw := range in.Data {
		switch key {
		case DataName, DataImage:
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return upd, nil, ErrBadUserData
			}
			if key == DataName {
				upd.Name = &s
			} else {
				upd.Image = &s
			}
			continue
		}
		col, ok := p.editable[key]
		if !ok {
			return upd, nil, ErrFieldNotEditable
		}
		w, err := col.prepare(raw)
		if err != nil {
			return upd, nil, err
		}
		writes = append(writes, w)
	}
	return upd, writes, nil
}
