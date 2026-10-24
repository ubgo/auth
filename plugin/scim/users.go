package scim

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/sqlb"
)

// userRow is one auth_scim_user row.
type userRow struct {
	id, connectionID, userID string
	identityID               *string
	userName                 string
	externalID               *string
	active                   bool
	email, resource          string
	created, updated         time.Time
	revision                 int64
}

// userBindings scans every column of a userRow.
func userBindings(u *userRow) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(UserID, &u.id), sqlb.Bind(UserConnectionID, &u.connectionID), sqlb.Bind(UserUserID, &u.userID),
		sqlb.Bind(UserIdentityID, &u.identityID), sqlb.Bind(UserUserName, &u.userName), sqlb.Bind(UserExternalID, &u.externalID),
		sqlb.Bind(UserActive, &u.active), sqlb.Bind(UserPrimaryEmail, &u.email), sqlb.Bind(UserResource, &u.resource),
		sqlb.Bind(UserCreatedAt, &u.created), sqlb.Bind(UserUpdatedAt, &u.updated), sqlb.Bind(UserRevision, &u.revision),
	}
}

// users routes /Users and /Users/{id}.
func (p *Plugin) users(r *http.Request, conn, id string, pr *projection) (int, any, error) {
	ctx := r.Context()
	switch {
	case id == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		return p.listUsers(r, conn, pr)
	case id == "" && r.Method == http.MethodPost:
		doc, err := readDoc(r)
		if err != nil {
			return 0, nil, err
		}
		u, err := decodeUser(doc)
		if err != nil {
			return 0, nil, err
		}
		var row userRow
		err = p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			row, err = p.createUser(ctx, conn, u)
			return err
		})
		return p.userAnswer(r, http.StatusCreated, row, pr, err)
	case id == "":
		return 0, nil, errMethod
	}
	row, err := p.loadUser(ctx, conn, id)
	if err != nil {
		return 0, nil, err
	}
	fence, err := fenceOf(r, row)
	if err != nil {
		return 0, nil, err
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return p.userAnswer(r, http.StatusOK, row, pr, nil)
	case http.MethodPut:
		doc, err := readDoc(r)
		if err != nil {
			return 0, nil, err
		}
		u, err := decodeUser(doc)
		if err != nil {
			return 0, nil, err
		}
		err = p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			row, err = p.replaceUser(ctx, row, u, fence)
			return err
		})
		return p.userAnswer(r, http.StatusOK, row, pr, err)
	case http.MethodPatch:
		ops, err := readPatch(r)
		if err != nil {
			return 0, nil, err
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(row.resource), &doc); err != nil {
			return 0, nil, err
		}
		if err := applyPatch(doc, ops, "userName"); err != nil {
			return 0, nil, err
		}
		u, err := decodeUser(doc)
		if err != nil {
			return 0, nil, err
		}
		err = p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			row, err = p.replaceUser(ctx, row, u, fence)
			return err
		})
		return p.userAnswer(r, http.StatusOK, row, pr, err)
	case http.MethodDelete:
		err := p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error { return p.deleteUser(ctx, row, fence) })
		return http.StatusNoContent, nil, err
	}
	return 0, nil, errMethod
}

// userAnswer renders row with meta and the request's projection pr.
func (p *Plugin) userAnswer(r *http.Request, status int, row userRow, pr *projection, err error) (int, any, error) {
	if err != nil {
		return 0, nil, err
	}
	doc, err := p.userDoc(r, row)
	if err != nil {
		return 0, nil, err
	}
	pr.apply(doc)
	return status, doc, nil
}

// userDoc is a stored user as a SCIM document with id and meta.
func (p *Plugin) userDoc(r *http.Request, row userRow) (map[string]any, error) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(row.resource), &doc); err != nil {
		return nil, err
	}
	doc["id"] = row.id
	doc["meta"] = Meta{ResourceType: "User", Created: row.created, LastModified: row.updated, Version: version(row.revision),
		Location: location(r, p.core.BaseURL(r.Context()), pathUsers, row.id)}
	return doc, nil
}

// loadUser loads a user of conn; another connection's id is not found.
func (p *Plugin) loadUser(ctx context.Context, conn, id string) (userRow, error) {
	var row userRow
	err := p.core.One(ctx, p.core.Select().Columns(userBindings(&row)...).From(TableUser).
		Where(sqlb.Eq(UserID, id), sqlb.Eq(UserConnectionID, conn)))
	if errors.Is(err, sqlb.ErrNoRows) {
		return userRow{}, errNotFound
	}
	return row, err
}

// checkUserUnique refuses a userName or externalId another user of the
// connection holds; self is the user being replaced, or "".
func (p *Plugin) checkUserUnique(ctx context.Context, conn, self string, u User) error {
	var id string
	same := []sqlb.Predicate{sqlb.Eq(UserConnectionID, conn), sqlb.Eq(UserUserNameKey, keyOfValue(strings.ToLower(u.UserName)))}
	if self != "" {
		same = append(same, sqlb.NotEq(UserID, self))
	}
	if taken, err := p.exists(ctx, p.core.Select().Columns(sqlb.Bind(UserID, &id)).From(TableUser).Where(same...).Limit(1)); err != nil || taken {
		if taken {
			return errConflict("SCIM User userName")
		}
		return err
	}
	if u.ExternalID == "" {
		return nil
	}
	same = []sqlb.Predicate{sqlb.Eq(UserConnectionID, conn), sqlb.Eq(UserExternalKey, optKey(u.ExternalID))}
	if self != "" {
		same = append(same, sqlb.NotEq(UserID, self))
	}
	taken, err := p.exists(ctx, p.core.Select().Columns(sqlb.Bind(UserID, &id)).From(TableUser).Where(same...).Limit(1))
	if taken {
		return errConflict("SCIM User externalId")
	}
	return err
}

// serialize is the stored resource: the user without id and meta, bounded.
func serialize(u User) (string, error) {
	u.ID, u.Meta = "", nil
	// A User holds only strings, bools, slices of them and values decoded
	// from JSON, so it always marshals.
	b, _ := json.Marshal(u)
	if len(b) > MaxResourceSize {
		return "", invalid(fmt.Sprintf("the user is larger than %d bytes", MaxResourceSize))
	}
	return string(b), nil
}

// createUser provisions u for conn: a new library user (or the one
// ResolveUser names), its primary email, and the SCIM row.
func (p *Plugin) createUser(ctx context.Context, conn string, u User) (userRow, error) {
	if err := p.checkUserUnique(ctx, conn, "", u); err != nil {
		return userRow{}, err
	}
	res, err := serialize(u)
	if err != nil {
		return userRow{}, err
	}
	var link Resolution
	if p.resolve != nil {
		if link, err = p.resolve(ctx, ResolveInput{ConnectionID: conn, User: u}); err != nil {
			return userRow{}, err
		}
	}
	row := userRow{connectionID: conn, userName: u.UserName, externalID: optString(u.ExternalID), active: u.IsActive(),
		email: u.PrimaryEmail(), resource: res, created: p.now(), updated: p.now(), revision: 1}
	if link.UserID == "" {
		// A person deleted and re-created by the same connection gets the
		// account the tombstone names back.
		uid, ident, ok, err := p.exhume(ctx, conn, u.ExternalID)
		if err != nil {
			return userRow{}, err
		}
		if ok {
			row.userID, row.identityID = uid, ident
		}
	}
	switch {
	case row.userID != "":
		// Revived from a tombstone: the account and its identity are back,
		// unless another source took the profile over meanwhile.
		if row.identityID != nil {
			if err := p.checkNoProfileSource(ctx, row.userID); err != nil {
				return userRow{}, err
			}
		}
	case link.UserID != "":
		// A linked user keeps its own profile; the connection may hold one
		// SCIM user per library user.
		if _, err := p.core.User(ctx, link.UserID); err != nil {
			return userRow{}, err
		}
		var id string
		taken, err := p.exists(ctx, p.core.Select().Columns(sqlb.Bind(UserID, &id)).From(TableUser).
			Where(sqlb.Eq(UserConnectionID, conn), sqlb.Eq(UserUserID, link.UserID)).Limit(1))
		if err != nil {
			return userRow{}, err
		}
		if taken {
			return userRow{}, errConflict("A SCIM User for this user")
		}
		row.userID = link.UserID
		switch link.Profile {
		case "", ProfilePreserve:
		case ProfileManage:
			if row.identityID, err = p.claimProfile(ctx, row.userID, row.email, u); err != nil {
				return userRow{}, err
			}
		default:
			return userRow{}, ErrBadProfile
		}
	default:
		if err := p.checkEmailFree(ctx, row.email); err != nil {
			return userRow{}, err
		}
		created, err := p.core.CreateUser(ctx, auth.NewUser{Name: truncateName(u.displayName())})
		if err != nil {
			return userRow{}, err
		}
		row.userID = created.ID
		ident, err := p.core.CreateIdentity(ctx, auth.NewIdentity{UserID: created.ID, Kind: email.KindEmail, Raw: row.email, Verified: p.trustEmails, Primary: true})
		if err != nil {
			return userRow{}, err
		}
		row.identityID = &ident.ID
	}
	if row.id, err = p.core.NewID("scu"); err != nil {
		return userRow{}, err
	}
	ins := sqlb.NewInsert(p.core.Dialect()).Into(TableUser).Row(
		sqlb.Set(UserID, row.id), sqlb.Set(UserConnectionID, conn), sqlb.Set(UserUserID, row.userID),
		sqlb.Set(UserIdentityID, row.identityID), sqlb.Set(UserUserName, row.userName),
		sqlb.Set(UserUserNameKey, keyOfValue(strings.ToLower(row.userName))), sqlb.Set(UserExternalID, row.externalID),
		sqlb.Set(UserExternalKey, optKey(u.ExternalID)), sqlb.Set(UserActive, row.active), sqlb.Set(UserPrimaryEmail, row.email),
		sqlb.Set(UserResource, row.resource), sqlb.Set(UserCreatedAt, row.created), sqlb.Set(UserUpdatedAt, row.updated),
		sqlb.Set(UserRevision, row.revision),
	)
	if _, err := p.core.Exec(ctx, ins); err != nil {
		return userRow{}, err
	}
	return row, p.reconcile(ctx, row.userID, false)
}

// checkNoProfileSource refuses (409) when a SCIM user of any connection
// already writes userID's profile: the one that holds its email identity.
func (p *Plugin) checkNoProfileSource(ctx context.Context, userID string) error {
	var id string
	taken, err := p.exists(ctx, p.core.Select().Columns(sqlb.Bind(UserID, &id)).From(TableUser).
		Where(sqlb.Eq(UserUserID, userID), sqlb.IsNotNull(UserIdentityID)).Limit(1))
	if taken {
		return errConflict("A SCIM source managing this User profile")
	}
	return err
}

// claimProfile makes a ProfileManage link the profile source of userID: no
// other
// source may hold it, the name is written, and the SCIM primary email becomes
// the user's primary email identity, which the source then owns (the one it
// replaces on a later email change). An identity of the user already holding
// the address is adopted; otherwise a new one is created (verified only under
// TrustEmails) and the user's old primary email identity removed, since a
// managed profile has one email, the IdP's.
func (p *Plugin) claimProfile(ctx context.Context, userID, addr string, u User) (*string, error) {
	if err := p.checkNoProfileSource(ctx, userID); err != nil {
		return nil, err
	}
	name := truncateName(u.displayName())
	if _, err := p.core.UpdateUser(ctx, userID, auth.UserUpdate{Name: &name}); err != nil {
		return nil, err
	}
	norm, err := p.core.Normalize(email.KindEmail, addr)
	if err != nil {
		return nil, invalid("the primary email is not a valid address")
	}
	ids, err := p.core.Identities(ctx, userID)
	if err != nil {
		return nil, err
	}
	var old *auth.Identity
	for i, idn := range ids {
		if idn.Kind != email.KindEmail {
			continue
		}
		if idn.Value == norm {
			return &ids[i].ID, nil
		}
		if idn.IsPrimary {
			old = &ids[i]
		}
	}
	if err := p.checkEmailFree(ctx, addr); err != nil {
		return nil, err
	}
	ident, err := p.core.CreateIdentity(ctx, auth.NewIdentity{UserID: userID, Kind: email.KindEmail, Raw: addr, Verified: p.trustEmails, Primary: true})
	if err != nil {
		return nil, err
	}
	if old != nil {
		if err := p.core.DeleteIdentity(ctx, userID, old.ID); err != nil {
			return nil, err
		}
	}
	return &ident.ID, nil
}

// replaceUser stores u over row (PUT, and PATCH after the patch), and
// follows a managed user's profile: the name, and a new primary email,
// unverified, in place of the old one.
func (p *Plugin) replaceUser(ctx context.Context, row userRow, u User, f fence) (userRow, error) {
	if err := p.checkUserUnique(ctx, row.connectionID, row.id, u); err != nil {
		return userRow{}, err
	}
	res, err := serialize(u)
	if err != nil {
		return userRow{}, err
	}
	addr := u.PrimaryEmail()
	if row.identityID != nil {
		name := truncateName(u.displayName())
		if _, err := p.core.UpdateUser(ctx, row.userID, auth.UserUpdate{Name: &name}); err != nil {
			return userRow{}, err
		}
		if norm, err := p.core.Normalize(email.KindEmail, addr); err == nil && !strings.EqualFold(norm, row.email) {
			if err := p.checkEmailFree(ctx, addr); err != nil {
				return userRow{}, err
			}
			ident, err := p.core.CreateIdentity(ctx, auth.NewIdentity{UserID: row.userID, Kind: email.KindEmail, Raw: addr, Verified: p.trustEmails, Primary: true})
			if err != nil {
				return userRow{}, err
			}
			if err := p.core.DeleteIdentity(ctx, row.userID, *row.identityID); err != nil && !errors.Is(err, auth.ErrIdentityNotFound) {
				return userRow{}, err
			}
			row.identityID = &ident.ID
		}
	}
	row.userName, row.externalID, row.active, row.email, row.resource, row.updated = u.UserName, optString(u.ExternalID), u.IsActive(), addr, res, p.now()
	upd := sqlb.NewUpdate(p.core.Dialect()).Table(TableUser).Set(
		sqlb.Set(UserIdentityID, row.identityID), sqlb.Set(UserUserName, row.userName),
		sqlb.Set(UserUserNameKey, keyOfValue(strings.ToLower(row.userName))), sqlb.Set(UserExternalID, row.externalID),
		sqlb.Set(UserExternalKey, optKey(u.ExternalID)), sqlb.Set(UserActive, row.active), sqlb.Set(UserPrimaryEmail, row.email),
		sqlb.Set(UserResource, row.resource), sqlb.Set(UserUpdatedAt, row.updated), sqlb.Set(UserRevision, f.revision+1),
	).Where(sqlb.Eq(UserID, row.id), sqlb.Eq(UserRevision, f.revision))
	n, err := p.core.Exec(ctx, upd)
	if err != nil {
		return userRow{}, err
	}
	if n != 1 {
		// Another write landed since this one read the user (or since the
		// IdP's If-Match): the transaction rolls back every change above.
		return userRow{}, f.stale()
	}
	row.revision = f.revision + 1
	if err := p.reconcile(ctx, row.userID, false); err != nil {
		return userRow{}, err
	}
	return row, p.syncGroupsOf(ctx, row.connectionID, row.id)
}

// ActiveUser returns the SCIM user id and library user id of the active SCIM
// user a connection provisioned under externalID: an SSO sign-in that names
// the IdP's user can resolve it to the provisioned account, never by email.
// ErrNoActiveUser answers when there is none, or it is inactive.
//
//ds:def id=scim-plugin-activeuser-9m4xk2qw owner=@khanakia stability=stable
func (p *Plugin) ActiveUser(ctx context.Context, connectionID, externalID string) (scimUserID, userID string, err error) {
	err = p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(UserID, &scimUserID), sqlb.Bind(UserUserID, &userID)).From(TableUser).
		Where(sqlb.Eq(UserConnectionID, connectionID), sqlb.Eq(UserExternalKey, optKey(externalID)), sqlb.Eq(UserActive, true)))
	if errors.Is(err, sqlb.ErrNoRows) || (err == nil && externalID == "") {
		return "", "", ErrNoActiveUser
	}
	return scimUserID, userID, err
}

// ErrNoActiveUser is ActiveUser's answer for no active provisioned user.
var ErrNoActiveUser = errors.New("scim: no active provisioned user")

// checkEmailFree refuses an address any identity holds, verified or not
// (global email uniqueness): the plugin never links by
// email, and two accounts with one address would make the next sign-in by
// email ambiguous.
func (p *Plugin) checkEmailFree(ctx context.Context, addr string) error {
	_, err := p.core.FindIdentity(ctx, email.KindEmail, addr, false)
	switch {
	case err == nil:
		return errConflict("A user with this email")
	case errors.Is(err, auth.ErrIdentityNotFound):
		return nil
	}
	return err
}

// deleteUser removes the SCIM user and its memberships; the library user is
// kept deactivated, or deleted under DeleteUsers, once no SCIM user is left.
func (p *Plugin) deleteUser(ctx context.Context, row userRow, f fence) error {
	groups, err := p.groupsOf(ctx, row.id)
	if err != nil {
		return err
	}
	d := p.core.Dialect()
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableMember).Where(sqlb.Eq(MemberSCIMUserID, row.id))); err != nil {
		return err
	}
	n, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableUser).Where(sqlb.Eq(UserID, row.id), sqlb.Eq(UserRevision, f.revision)))
	if err != nil {
		return err
	}
	if n != 1 {
		return f.stale()
	}
	if err := p.bury(ctx, row); err != nil {
		return err
	}
	for _, g := range groups {
		if err := p.syncGroup(ctx, row.connectionID, g); err != nil {
			return err
		}
	}
	return p.reconcile(ctx, row.userID, true)
}

// reconcile sets the library user's deactivation from its SCIM users: active
// while any is active; deactivated, with every session ended, while all are
// inactive. With none left (gone is set), the user stays deactivated, or is
// deleted under DeleteUsers.
func (p *Plugin) reconcile(ctx context.Context, userID string, gone bool) error {
	var total, active int64
	if err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &total)).From(TableUser).Where(sqlb.Eq(UserUserID, userID))); err != nil {
		return err
	}
	if err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &active)).From(TableUser).
		Where(sqlb.Eq(UserUserID, userID), sqlb.Eq(UserActive, true))); err != nil {
		return err
	}
	if total == 0 && !gone {
		return nil
	}
	if p.onReconcile != nil {
		if err := p.onReconcile(ctx, ReconcileInput{UserID: userID, Active: active > 0, Sources: int(total)}); err != nil {
			return err
		}
	}
	if active > 0 {
		return auth.SetUserColumn[*time.Time](ctx, p.core, PluginName, userID, DeactivatedAt, nil)
	}
	if total == 0 && p.deleteUsers {
		return p.core.DeleteUser(ctx, userID)
	}
	var at *time.Time
	if err := p.core.LoadUserColumns(ctx, userID, sqlb.Bind(DeactivatedAt, &at)); err != nil {
		return err
	}
	if at == nil {
		now := p.now()
		if err := auth.SetUserColumn(ctx, p.core, PluginName, userID, DeactivatedAt, &now); err != nil {
			return err
		}
	}
	return p.core.EndUserSessions(ctx, userID, "", auth.SessionEndBanned)
}

// listUsers answers GET /Users with filter, pagination and projection.
func (p *Plugin) listUsers(r *http.Request, conn string, pr *projection) (int, any, error) {
	q := r.URL.Query()
	start, count, err := page(q)
	if err != nil {
		return 0, nil, err
	}
	var terms []term
	if f := q.Get("filter"); f != "" {
		if terms, err = parseFilter(f, "id", "username", "externalid", "emails.value", "emails[type].value"); err != nil {
			return 0, nil, err
		}
	}
	where := []sqlb.Predicate{sqlb.Eq(UserConnectionID, conn)}
	var inGo []term
	for _, t := range terms {
		switch t.Attr {
		case "id":
			where = append(where, sqlb.Eq(UserID, t.Value))
		case "username":
			where = append(where, sqlb.Eq(UserUserNameKey, keyOfValue(strings.ToLower(t.Value))))
		case "externalid":
			where = append(where, sqlb.Eq(UserExternalKey, optKey(t.Value)))
		default:
			inGo = append(inGo, t)
		}
	}
	var row userRow
	var docs []map[string]any
	stmt := p.core.Select().Columns(userBindings(&row)...).From(TableUser).Where(where...).
		Order(sqlb.OrderBy(UserCreatedAt, sqlb.SortAsc), sqlb.OrderBy(UserID, sqlb.SortAsc))
	err = p.core.Each(r.Context(), stmt, func() error {
		doc, err := p.userDoc(r, row)
		if err != nil {
			return err
		}
		if matchesEmails(row.resource, inGo) {
			pr.apply(doc)
			docs = append(docs, doc)
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, pageOf(docs, start, count), nil
}

// matchesEmails applies the email terms, which compare case-insensitively
// against every address (or the addresses of one type).
func matchesEmails(resource string, terms []term) bool {
	if len(terms) == 0 {
		return true
	}
	var u User
	if json.Unmarshal([]byte(resource), &u) != nil {
		return false
	}
	for _, t := range terms {
		hit := false
		for _, e := range u.Emails {
			if strings.EqualFold(e.Value, t.Value) && (t.Type == "" || strings.EqualFold(e.Type, t.Type)) {
				hit = true
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// fence is the revision a write is conditional on: the one the request read,
// or the one its If-Match names (strict).
type fence struct {
	revision int64
	strict   bool
}

// errPrecondition is an If-Match that names an older revision (RFC 7644
// section 3.14).
var errPrecondition = errorf(http.StatusPreconditionFailed, "", "The resource changed since the version in If-Match")

// errConcurrent is a write that lost a race with another write.
var errConcurrent = errorf(http.StatusConflict, "", "The resource changed while this request ran; retry")

// stale is the error of a write whose fence no longer holds.
func (f fence) stale() error {
	if f.strict {
		return errPrecondition
	}
	return errConcurrent
}

// version is the weak ETag of a revision.
func version(rev int64) string { return `W/"` + strconv.FormatInt(rev, 10) + `"` }

// fenceOf reads If-Match: absent or "*", the loaded revision; a weak or
// strong ETag of a revision, that revision, strictly; anything else fails
// the precondition.
func fenceOf(r *http.Request, row userRow) (fence, error) {
	h := strings.TrimSpace(r.Header.Get("If-Match"))
	if h == "" || h == "*" {
		return fence{revision: row.revision}, nil
	}
	n, err := strconv.ParseInt(strings.Trim(strings.TrimPrefix(h, "W/"), `"`), 10, 64)
	if err != nil {
		return fence{}, errPrecondition
	}
	return fence{revision: n, strict: true}, nil
}
