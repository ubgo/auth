package scim

import (
	"context"
	"errors"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Identity tombstones, better-auth's scimIdentityTombstone: deleting a SCIM
// user with an externalId leaves a row naming the library user it was
// linked to, so an IdP that deletes and later re-creates the same person
// (same connection, same externalId) gets the same account back, not a
// second one beside a deactivated first.
const (
	TableNameTombstone  = "auth_scim_tombstone"
	TableAliasTombstone = "sct"
	ColDeletedAt        = "deleted_at"
)

// TableTombstone and its typed columns.
var (
	TableTombstone  = sqlb.Table{Name: TableNameTombstone, Alias: TableAliasTombstone}
	TombConnection  = sqlb.Col[string](TableTombstone, ColConnectionID)
	TombExternalKey = sqlb.Col[string](TableTombstone, ColExternalIDKey)
	TombUserID      = sqlb.Col[string](TableTombstone, ColUserID)
	TombIdentityID  = sqlb.Col[*string](TableTombstone, ColIdentityID)
	TombDeletedAt   = sqlb.Col[time.Time](TableTombstone, ColDeletedAt)
)

// tombstoneMigration creates the tombstone table.
func (p *Plugin) tombstoneMigration(t auth.SQLTypes) string {
	return "CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableTombstone) + " (" +
		ColConnectionID + " " + t.Key + " NOT NULL, " +
		ColExternalIDKey + " " + t.Key + " NOT NULL, " +
		ColUserID + " " + t.ID + " NOT NULL, " +
		ColIdentityID + " " + t.ID + " NULL, " +
		ColDeletedAt + " " + t.Timestamp + " NOT NULL, " +
		"PRIMARY KEY (" + ColConnectionID + ", " + ColExternalIDKey + "))" + t.TableSuffix
}

// bury records a deleted SCIM user's link, replacing an older one.
func (p *Plugin) bury(ctx context.Context, row userRow) error {
	if row.externalID == nil {
		return nil
	}
	key := keyOfValue(*row.externalID)
	d := p.core.Dialect()
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableTombstone).Where(sqlb.Eq(TombConnection, row.connectionID), sqlb.Eq(TombExternalKey, key))); err != nil {
		return err
	}
	_, err := p.core.Exec(ctx, sqlb.NewInsert(d).Into(TableTombstone).Row(
		sqlb.Set(TombConnection, row.connectionID), sqlb.Set(TombExternalKey, key), sqlb.Set(TombUserID, row.userID),
		sqlb.Set(TombIdentityID, row.identityID), sqlb.Set(TombDeletedAt, p.now()),
	))
	return err
}

// exhume returns and removes the tombstone of conn's externalID whose
// library user still exists; ok is false when there is none.
func (p *Plugin) exhume(ctx context.Context, conn, externalID string) (userID string, identityID *string, ok bool, err error) {
	if externalID == "" {
		return "", nil, false, nil
	}
	key := keyOfValue(externalID)
	err = p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(TombUserID, &userID), sqlb.Bind(TombIdentityID, &identityID)).From(TableTombstone).
		Where(sqlb.Eq(TombConnection, conn), sqlb.Eq(TombExternalKey, key)))
	if errors.Is(err, sqlb.ErrNoRows) {
		return "", nil, false, nil
	}
	if err != nil {
		return "", nil, false, err
	}
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableTombstone).Where(sqlb.Eq(TombConnection, conn), sqlb.Eq(TombExternalKey, key))); err != nil {
		return "", nil, false, err
	}
	// Only "not found" means gone; any other failure is the caller's, so a
	// failed lookup never provisions a second account for a living person.
	if _, err := p.core.User(ctx, userID); errors.Is(err, auth.ErrUserNotFound) {
		return "", nil, false, nil // the user is gone: provision a new one
	} else if err != nil {
		return "", nil, false, err
	}
	if identityID != nil {
		id, err := p.core.IdentityByID(ctx, *identityID)
		switch {
		case errors.Is(err, auth.ErrIdentityNotFound) || (err == nil && id.UserID != userID):
			identityID = nil
		case err != nil:
			return "", nil, false, err
		}
	}
	return userID, identityID, true, nil
}
