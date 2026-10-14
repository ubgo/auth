package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/ubgo/sqlb"
)

// ErrResourceNotFound is RequireOwner's answer for a row that does not exist
// and, by default, for one that belongs to someone else: one answer for both,
// so an id cannot be probed for whether it exists.
var ErrResourceNotFound = NewError("auth.resource_not_found", http.StatusNotFound, "Not found.")

// ErrResourceForbidden is RequireOwner's answer for another user's row when
// the Ownership asks to tell the two cases apart (Forbidden), as
// better-auth's requireResourceOwnership does by default.
var ErrResourceForbidden = NewError("auth.resource_forbidden", http.StatusForbidden, "This belongs to another account.")

// Ownership says where a plugin table records who owns a row: the table, its
// id column and the column holding the owner's user id. Both columns are
// typed expressions of the plugin's own table (sqlb.Col[string]), so a
// misspelt column is a failed query in the plugin's own test, not a silent
// pass.
//
//ds:def id=core-ownership-5qk8wn3d owner=@khanakia stability=stable
type Ownership struct {
	Table sqlb.Table
	ID    sqlb.Expr[string]
	Owner sqlb.Expr[string]
	// NotFound replaces ErrResourceNotFound, for a plugin with its own code
	// ("apikey.not_found").
	NotFound error
	// Forbidden, when set, is answered for a row that exists and belongs to
	// another user, as better-auth answers FORBIDDEN. Left nil, that row is
	// answered like a missing one (NotFound), which is the safe default:
	// telling the two apart tells a caller which ids exist.
	Forbidden error
}

// RequireOwner checks that row id of o.Table belongs to the call's user, as
// better-auth's requireResourceOwnership middleware does, in one indexed read
// on the call's connection (the operation's transaction, when it has one):
// a signed-out call is ErrSignedOut, an empty id ErrBadRequest, a missing row
// o.NotFound, and another user's row o.Forbidden or, by default, o.NotFound.
// The owner is compared as stored, exactly, as every id is.
//
// It is for an operation's own rows (a passkey, a key, a device); a plugin
// that also needs the row's other columns calls RequireOwnerRow.
func (c *Call) RequireOwner(ctx context.Context, o Ownership, id string) error {
	if c.User == nil {
		return ErrSignedOut
	}
	if id == "" {
		return ErrBadRequest
	}
	notFound := o.NotFound
	if notFound == nil {
		notFound = ErrResourceNotFound
	}
	var owner string
	err := c.Auth.One(ctx, c.Auth.Select().Columns(sqlb.Bind(o.Owner, &owner)).From(o.Table).Where(sqlb.Eq(o.ID, id)).Limit(1))
	if errors.Is(err, sqlb.ErrNoRows) {
		return notFound
	}
	if err != nil {
		return fmt.Errorf("auth: ownership of %s: %w", o.Table.Name, err)
	}
	if owner != c.User.ID {
		if o.Forbidden != nil {
			return o.Forbidden
		}
		return notFound
	}
	return nil
}

// RequireOwnerRow is RequireOwner that also reads the row: cols are bound to
// the columns of row id of o.Table and filled when, and only when, the row
// belongs to the call's user: better-auth's verifiedResource. The read keys
// on the id and the owner together, so another user's values never reach
// cols; a miss is then classified by RequireOwner's own read (missing,
// another user's), with the same answers. A signed-out call, an empty id or
// no columns is refused before any read.
//
//ds:def id=core-requireownerrow-8wq3nk5v owner=@khanakia stability=stable
func (c *Call) RequireOwnerRow(ctx context.Context, o Ownership, id string, cols ...sqlb.Binding) error {
	if c.User == nil {
		return ErrSignedOut
	}
	if id == "" || len(cols) == 0 {
		return ErrBadRequest
	}
	err := c.Auth.One(ctx, c.Auth.Select().Columns(cols...).From(o.Table).Where(sqlb.Eq(o.ID, id), sqlb.Eq(o.Owner, c.User.ID)).Limit(1))
	if errors.Is(err, sqlb.ErrNoRows) {
		if err := c.RequireOwner(ctx, o, id); err != nil {
			return err
		}
		// The row turned up between the two reads: answer it as missing
		// rather than return unfilled columns as a success.
		if o.NotFound != nil {
			return o.NotFound
		}
		return ErrResourceNotFound
	}
	if err != nil {
		return fmt.Errorf("auth: ownership of %s: %w", o.Table.Name, err)
	}
	return nil
}
