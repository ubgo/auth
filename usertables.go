package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/ubgo/sqlb"
)

// User-owned tables: how a user's rows are removed without a foreign key.
//
// ADR-0002 (2026-10-03): the library creates no foreign keys and no ON DELETE
// CASCADE, on any engine, in the core or any plugin. Tables are plain storage,
// so a table can move to another database or shard without a constraint tying
// it to auth_user, the deletion rules are in Go where tests can see them, and
// SQLite needs no pragma for a cascade to happen. In exchange every table that
// holds a user's rows must say so, and DeleteUser removes those rows itself,
// inside the transaction that deletes the user.

// UserTable is a table with a column that holds a user id: the rows whose
// Column equals a user's id belong to that user and are deleted with the user.
//
//ds:def id=core-usertable-8kq2mw4n owner=@khanakia stability=stable
type UserTable struct {
	// Table is one the plugin declares through TableOwner; New refuses one
	// it does not, because the registry would then name a table nobody
	// creates.
	Table sqlb.Table
	// Column holds the user id, as "user_id".
	Column string
}

// UserTableOwner is a plugin with tables whose rows belong to users. It lists
// them so DeleteUser removes a user's rows from each, in plugin order, before
// the core's own rows and the user. A plugin table with a user column that is
// not listed keeps its rows after the user is gone; the library's test suite
// refuses such a table (TestGuard_UserTablesAreDeleted), and a plugin in
// another repository should carry the same check.
//
//ds:def id=core-usertableowner-3nv9qx7m owner=@khanakia stability=stable
type UserTableOwner interface {
	UserTables() []UserTable
}

// ErrBadUserTable is returned by New for a UserTable that names a table its
// plugin does not declare, a column that is not an identifier, or a pair
// listed twice.
var ErrBadUserTable = errors.New("auth: user table is not valid")

// coreUserTables are the core's own tables with a user column, deleted after
// the plugins' and before the user row. The session table is listed even
// though sessions are also ended through the SessionStore, which may live
// outside the database: the store call reaches Redis and memory stores, and
// the table delete removes the SQL rows, archived ones (WithSessionArchive)
// included.
var coreUserTables = []UserTable{{Table: TableIdentity, Column: ColIdentityUserID}, {Table: TableSession, Column: ColSessionUserID}}

// collectUserTables checks every plugin's UserTables and records them in
// plugin order. It runs after checkAliases, so each plugin's Tables are known.
func (a *Auth) collectUserTables() error {
	seen := map[string]string{}
	for _, p := range a.plugins {
		owner, ok := p.(UserTableOwner)
		if !ok {
			continue
		}
		declared := map[string]bool{}
		if to, ok := p.(TableOwner); ok {
			for _, t := range to.Tables() {
				declared[t.Name] = true
			}
		}
		for _, ut := range owner.UserTables() {
			switch {
			case !declared[ut.Table.Name]:
				return fmt.Errorf("%w: plugin %q lists %q, which it does not declare in Tables", ErrBadUserTable, p.Name(), ut.Table.Name)
			case !tableIdentPattern.MatchString(ut.Column):
				return fmt.Errorf("%w: plugin %q: column %q of %q", ErrBadUserTable, p.Name(), ut.Column, ut.Table.Name)
			}
			key := ut.Table.Name + "." + ut.Column
			if prev, dup := seen[key]; dup {
				return fmt.Errorf("%w: %s listed by %q and %q", ErrBadUserTable, key, prev, p.Name())
			}
			seen[key] = p.Name()
			a.userTables = append(a.userTables, ut)
		}
	}
	return nil
}

// UserTables lists every table DeleteUser clears for a user, in deletion
// order: the plugins' in plugin order, then the core's. Tools and tests read
// it to check that no table with a user column is left out.
//
//ds:def id=core-usertables-5pw8kq2t owner=@khanakia stability=stable
func (a *Auth) UserTables() []UserTable {
	out := make([]UserTable, 0, len(a.userTables)+len(coreUserTables))
	out = append(out, a.userTables...)
	return append(out, coreUserTables...)
}

// deleteUserRows removes everything that belongs to user id except the user
// row itself: the sessions through the store first, so a store outside the
// database ends them too; then every registered user table in registry order
// (the plugins', then the identities and the session rows, which also clears
// rows an archive kept); then the verification tokens and codes filed under
// the user or any of its identities. It runs inside DeleteUser's transaction;
// every statement joins it through ctx.
func (a *Auth) deleteUserRows(ctx context.Context, id string) error {
	// Before the identities go: a verification token or a code is filed
	// under the user id, an identity id or an identity value, depending on
	// its purpose (see Verification.Identifier), so every one of those keys
	// is collected first.
	keys := []string{id}
	var idn Identity
	q := a.Select().Columns(IdentityBindings(&idn)...).From(TableIdentity).Where(sqlb.Eq(IdentityUserID, id))
	if err := a.Each(ctx, q, func() error { keys = append(keys, idn.ID, idn.Value); return nil }); err != nil {
		return fmt.Errorf("auth: list identities of deleted user: %w", err)
	}
	if a.sessions != nil {
		if err := a.sessions.DeleteUser(ctx, id, ""); err != nil {
			return fmt.Errorf("auth: end sessions of deleted user: %w", err)
		}
	}
	d := a.cfg.Dialect
	for _, ut := range a.UserTables() {
		col := sqlb.Col[string](ut.Table, ut.Column)
		if _, err := a.Exec(ctx, sqlb.NewDelete(d).From(ut.Table).Where(sqlb.Eq(col, id))); err != nil {
			return fmt.Errorf("auth: delete %s of deleted user: %w", ut.Table.Name, err)
		}
	}
	if err := a.verifications.DeleteIdentifiers(ctx, keys, a.now()); err != nil {
		return fmt.Errorf("auth: delete tokens of deleted user: %w", err)
	}
	if _, err := a.Exec(ctx, sqlb.NewDelete(d).From(TableCode).Where(sqlb.In(codeSubject, keys...))); err != nil {
		return fmt.Errorf("auth: delete codes of deleted user: %w", err)
	}
	return nil
}
