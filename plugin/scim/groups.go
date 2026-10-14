package scim

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ubgo/sqlb"
)

// groupRow is one auth_scim_group row.
type groupRow struct {
	id, connectionID, displayName string
	externalID                    *string
	created, updated              time.Time
}

// groupBindings scans every column of a groupRow.
func groupBindings(g *groupRow) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(GroupID, &g.id), sqlb.Bind(GroupConnectionID, &g.connectionID), sqlb.Bind(GroupDisplayName, &g.displayName),
		sqlb.Bind(GroupExternalID, &g.externalID), sqlb.Bind(GroupCreatedAt, &g.created), sqlb.Bind(GroupUpdatedAt, &g.updated),
	}
}

// memberRef is a member as the group answer lists it, and the library user
// it maps to.
type memberRef struct {
	scimID, userID, display string
}

// groupsRoute routes /Groups and /Groups/{id}.
func (p *Plugin) groupsRoute(r *http.Request, conn, id string, pr *projection) (int, any, error) {
	ctx := r.Context()
	switch {
	case id == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		return p.listGroups(r, conn, pr)
	case id == "" && r.Method == http.MethodPost:
		doc, err := readDoc(r)
		if err != nil {
			return 0, nil, err
		}
		if p.entraGroups {
			if err := dropEntraMarker(doc); err != nil {
				return 0, nil, err
			}
		}
		g, err := decodeGroup(doc)
		if err != nil {
			return 0, nil, err
		}
		var row groupRow
		err = p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			row, err = p.writeGroup(ctx, conn, groupRow{}, g)
			return err
		})
		return p.groupAnswer(r, http.StatusCreated, row, pr, err)
	case id == "":
		return 0, nil, errMethod
	}
	row, err := p.loadGroup(ctx, conn, id)
	if err != nil {
		return 0, nil, err
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return p.groupAnswer(r, http.StatusOK, row, pr, nil)
	case http.MethodPut, http.MethodPatch:
		var g Group
		if r.Method == http.MethodPut {
			doc, err := readDoc(r)
			if err != nil {
				return 0, nil, err
			}
			if g, err = decodeGroup(doc); err != nil {
				return 0, nil, err
			}
		} else {
			ops, err := readPatch(r)
			if err != nil {
				return 0, nil, err
			}
			doc, err := p.groupDoc(r, row)
			if err != nil {
				return 0, nil, err
			}
			delete(doc, "id")
			delete(doc, "meta")
			if err := applyPatch(doc, ops, "displayName"); err != nil {
				return 0, nil, err
			}
			if g, err = decodeGroup(doc); err != nil {
				return 0, nil, err
			}
		}
		err = p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			row, err = p.writeGroup(ctx, conn, row, g)
			return err
		})
		return p.groupAnswer(r, http.StatusOK, row, pr, err)
	case http.MethodDelete:
		err := p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			d := p.core.Dialect()
			if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableMember).Where(sqlb.Eq(MemberGroupID, row.id))); err != nil {
				return err
			}
			if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableGroup).Where(sqlb.Eq(GroupID, row.id))); err != nil {
				return err
			}
			return p.dropGroup(ctx, conn, row.id)
		})
		return http.StatusNoContent, nil, err
	}
	return 0, nil, errMethod
}

// dropEntraMarker removes exactly one EntraLegacyGroupSchema from schemas;
// two, or an attribute object under the marker, are invalidValue.
func dropEntraMarker(doc map[string]any) error {
	if _, has := doc[keyOf(doc, EntraLegacyGroupSchema)]; has {
		return invalid("attributes under the legacy Entra group schema are not accepted")
	}
	list, _ := doc[keyOf(doc, "schemas")].([]any)
	kept, seen := list[:0:0], 0
	for _, s := range list {
		if v, ok := s.(string); ok && v == EntraLegacyGroupSchema {
			seen++
			continue
		}
		kept = append(kept, s)
	}
	if seen > 1 {
		return invalid("the legacy Entra group schema is repeated")
	}
	doc[keyOf(doc, "schemas")] = kept
	return nil
}

// loadGroup loads a group of conn; another connection's id is not found.
func (p *Plugin) loadGroup(ctx context.Context, conn, id string) (groupRow, error) {
	var row groupRow
	err := p.core.One(ctx, p.core.Select().Columns(groupBindings(&row)...).From(TableGroup).
		Where(sqlb.Eq(GroupID, id), sqlb.Eq(GroupConnectionID, conn)))
	if errors.Is(err, sqlb.ErrNoRows) {
		return groupRow{}, errNotFound
	}
	return row, err
}

// members lists a group's members with the user each maps to.
func (p *Plugin) members(ctx context.Context, groupID string) ([]memberRef, error) {
	var m memberRef
	var userName string
	var out []memberRef
	q := p.core.Select().Columns(sqlb.Bind(MemberSCIMUserID, &m.scimID), sqlb.Bind(MemberUserID, &m.userID), sqlb.Bind(UserUserName, &userName)).
		From(TableMember).
		Join(sqlb.Join{Type: sqlb.JoinInner, Table: TableUser, On: []sqlb.Predicate{sqlb.EqExpr(UserID, MemberSCIMUserID)}}).
		Where(sqlb.Eq(MemberGroupID, groupID)).Order(sqlb.OrderBy(MemberCreatedAt, sqlb.SortAsc), sqlb.OrderBy(MemberSCIMUserID, sqlb.SortAsc))
	err := p.core.Each(ctx, q, func() error {
		m.display = userName
		out = append(out, m)
		return nil
	})
	return out, err
}

// groupAnswer renders row with members, meta and the request's projection pr.
func (p *Plugin) groupAnswer(r *http.Request, status int, row groupRow, pr *projection, err error) (int, any, error) {
	if err != nil {
		return 0, nil, err
	}
	doc, err := p.groupDoc(r, row)
	if err != nil {
		return 0, nil, err
	}
	pr.apply(doc)
	return status, doc, nil
}

// groupDoc is a stored group as a SCIM document.
func (p *Plugin) groupDoc(r *http.Request, row groupRow) (map[string]any, error) {
	ms, err := p.members(r.Context(), row.id)
	if err != nil {
		return nil, err
	}
	base := p.core.BaseURL(r.Context())
	list := make([]any, 0, len(ms))
	for _, m := range ms {
		list = append(list, map[string]any{"value": m.scimID, "display": m.display, "type": memberTypeUser, "$ref": location(r, base, pathUsers, m.scimID)})
	}
	doc := map[string]any{"schemas": []any{SchemaGroup}, "id": row.id, "displayName": row.displayName, "members": list,
		"meta": Meta{ResourceType: "Group", Created: row.created, LastModified: row.updated, Location: location(r, base, pathGroups, row.id)}}
	if row.externalID != nil {
		doc["externalId"] = *row.externalID
	}
	return doc, nil
}

// writeGroup creates (row.id empty) or replaces a group with g's attributes
// and exactly g's members, then tells the GroupMapper.
func (p *Plugin) writeGroup(ctx context.Context, conn string, row groupRow, g Group) (groupRow, error) {
	if err := p.checkGroupUnique(ctx, conn, row.id, g); err != nil {
		return groupRow{}, err
	}
	users := map[string]string{} // SCIM user id → library user id
	for _, m := range g.Members {
		u, err := p.loadUser(ctx, conn, m.Value)
		if errors.Is(err, errNotFound) {
			return groupRow{}, invalid("member " + m.Value + " is not a user of this connection")
		}
		if err != nil {
			return groupRow{}, err
		}
		users[m.Value] = u.userID
	}
	now := p.now()
	d := p.core.Dialect()
	row.displayName, row.externalID, row.updated = g.DisplayName, optString(g.ExternalID), now
	if row.id == "" {
		id, err := p.core.NewID("scg")
		if err != nil {
			return groupRow{}, err
		}
		row.id, row.connectionID, row.created = id, conn, now
		if _, err := p.core.Exec(ctx, sqlb.NewInsert(d).Into(TableGroup).Row(
			sqlb.Set(GroupID, row.id), sqlb.Set(GroupConnectionID, conn), sqlb.Set(GroupDisplayName, row.displayName),
			sqlb.Set(GroupDisplayKey, keyOfValue(strings.ToLower(row.displayName))), sqlb.Set(GroupExternalID, row.externalID),
			sqlb.Set(GroupExternalKey, optKey(g.ExternalID)), sqlb.Set(GroupCreatedAt, now), sqlb.Set(GroupUpdatedAt, now),
		)); err != nil {
			return groupRow{}, err
		}
	} else {
		if _, err := p.core.Exec(ctx, sqlb.NewUpdate(d).Table(TableGroup).Set(
			sqlb.Set(GroupDisplayName, row.displayName), sqlb.Set(GroupDisplayKey, keyOfValue(strings.ToLower(row.displayName))),
			sqlb.Set(GroupExternalID, row.externalID), sqlb.Set(GroupExternalKey, optKey(g.ExternalID)), sqlb.Set(GroupUpdatedAt, now),
		).Where(sqlb.Eq(GroupID, row.id))); err != nil {
			return groupRow{}, err
		}
		if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableMember).Where(sqlb.Eq(MemberGroupID, row.id))); err != nil {
			return groupRow{}, err
		}
	}
	for _, m := range g.Members {
		if _, err := p.core.Exec(ctx, sqlb.NewInsert(d).Into(TableMember).Row(
			sqlb.Set(MemberGroupID, row.id), sqlb.Set(MemberSCIMUserID, m.Value), sqlb.Set(MemberConnectionID, conn),
			sqlb.Set(MemberUserID, users[m.Value]), sqlb.Set(MemberCreatedAt, now),
		)); err != nil {
			return groupRow{}, err
		}
	}
	return row, p.syncGroup(ctx, conn, row.id)
}

// checkGroupUnique refuses a displayName or externalId another group of the
// connection holds.
func (p *Plugin) checkGroupUnique(ctx context.Context, conn, self string, g Group) error {
	var id string
	where := []sqlb.Predicate{sqlb.Eq(GroupConnectionID, conn), sqlb.Eq(GroupDisplayKey, keyOfValue(strings.ToLower(g.DisplayName)))}
	if self != "" {
		where = append(where, sqlb.NotEq(GroupID, self))
	}
	if taken, err := p.exists(ctx, p.core.Select().Columns(sqlb.Bind(GroupID, &id)).From(TableGroup).Where(where...).Limit(1)); err != nil || taken {
		if taken {
			return errConflict("SCIM Group displayName")
		}
		return err
	}
	if g.ExternalID == "" {
		return nil
	}
	where = []sqlb.Predicate{sqlb.Eq(GroupConnectionID, conn), sqlb.Eq(GroupExternalKey, optKey(g.ExternalID))}
	if self != "" {
		where = append(where, sqlb.NotEq(GroupID, self))
	}
	taken, err := p.exists(ctx, p.core.Select().Columns(sqlb.Bind(GroupID, &id)).From(TableGroup).Where(where...).Limit(1))
	if taken {
		return errConflict("SCIM Group externalId")
	}
	return err
}

// groupsOf lists the groups a SCIM user is a member of.
func (p *Plugin) groupsOf(ctx context.Context, scimUserID string) ([]string, error) {
	var id string
	var out []string
	err := p.core.Each(ctx, p.core.Select().Columns(sqlb.Bind(MemberGroupID, &id)).From(TableMember).
		Where(sqlb.Eq(MemberSCIMUserID, scimUserID)), func() error { out = append(out, id); return nil })
	return out, err
}

// syncGroupsOf tells the GroupMapper about every group of a SCIM user whose
// state may have changed.
func (p *Plugin) syncGroupsOf(ctx context.Context, conn, scimUserID string) error {
	if p.groups == nil && p.roles == nil {
		return nil
	}
	groups, err := p.groupsOf(ctx, scimUserID)
	if err != nil {
		return err
	}
	for _, g := range groups {
		if err := p.syncGroup(ctx, conn, g); err != nil {
			return err
		}
	}
	return nil
}

// syncGroup hands the GroupMapper a group's current state.
func (p *Plugin) syncGroup(ctx context.Context, conn, groupID string) error {
	if p.groups == nil && p.roles == nil {
		return nil
	}
	row, err := p.loadGroup(ctx, conn, groupID)
	if err != nil {
		return err
	}
	ms, err := p.members(ctx, groupID)
	if err != nil {
		return err
	}
	st := GroupState{ConnectionID: conn, ID: row.id, DisplayName: row.displayName, UserIDs: []string{}}
	if row.externalID != nil {
		st.ExternalID = *row.externalID
	}
	for _, m := range ms {
		st.UserIDs = append(st.UserIDs, m.userID)
	}
	if p.groups != nil {
		if err := p.groups.SyncGroup(ctx, st); err != nil {
			return err
		}
	}
	return p.projectGroup(ctx, RoleSource{ConnectionID: conn, GroupID: row.id, ExternalID: st.ExternalID, DisplayName: row.displayName}, ms)
}

// dropGroup tells the GroupMapper and the role projection a group is gone.
func (p *Plugin) dropGroup(ctx context.Context, conn, groupID string) error {
	if p.groups != nil {
		if err := p.groups.DeleteGroup(ctx, conn, groupID); err != nil {
			return err
		}
	}
	return p.projectGroup(ctx, RoleSource{ConnectionID: conn, GroupID: groupID}, nil)
}

// listGroups answers GET /Groups with filter, pagination and projection;
// excludedAttributes=members keeps a page of large groups light.
func (p *Plugin) listGroups(r *http.Request, conn string, pr *projection) (int, any, error) {
	q := r.URL.Query()
	start, count, err := page(q)
	if err != nil {
		return 0, nil, err
	}
	where := []sqlb.Predicate{sqlb.Eq(GroupConnectionID, conn)}
	if f := q.Get("filter"); f != "" {
		terms, err := parseFilter(f, "id", "displayname", "externalid")
		if err != nil {
			return 0, nil, err
		}
		for _, t := range terms {
			switch t.Attr {
			case "id":
				where = append(where, sqlb.Eq(GroupID, t.Value))
			case "displayname":
				where = append(where, sqlb.Eq(GroupDisplayKey, keyOfValue(strings.ToLower(t.Value))))
			default:
				where = append(where, sqlb.Eq(GroupExternalKey, optKey(t.Value)))
			}
		}
	}
	var row groupRow
	var rows []groupRow
	if err := p.core.Each(r.Context(), p.core.Select().Columns(groupBindings(&row)...).From(TableGroup).Where(where...).
		Order(sqlb.OrderBy(GroupCreatedAt, sqlb.SortAsc), sqlb.OrderBy(GroupID, sqlb.SortAsc)),
		func() error { rows = append(rows, row); return nil }); err != nil {
		return 0, nil, err
	}
	docs := make([]map[string]any, 0, len(rows))
	for _, g := range rows {
		doc, err := p.groupDoc(r, g)
		if err != nil {
			return 0, nil, err
		}
		pr.apply(doc)
		docs = append(docs, doc)
	}
	return http.StatusOK, pageOf(docs, start, count), nil
}

// ProjectionResult reports a ReconcileProjection.
type ProjectionResult struct {
	ProvisioningDomainID string
	Groups               int
	Batches              int
}

// ErrNoGroupMapper answers ReconcileProjection with neither WithGroupMapper
// nor ProjectRoles.
var ErrNoGroupMapper = errors.New("scim: ReconcileProjection needs WithGroupMapper or ProjectRoles")

// ReconcileProjection replays every group of a provisioning domain's
// connections into the GroupMapper, in batches of 50 groups per
// transaction, better-auth's reconcileSCIMProjection: after a mapper bug
// is fixed, or the app's grouping was rebuilt, the app's state catches up
// with the IdP's without waiting for the next change.
//
//ds:def id=scim-plugin-reconcileprojection-4w8nq3vk owner=@khanakia stability=stable
func (p *Plugin) ReconcileProjection(ctx context.Context, domain string) (ProjectionResult, error) {
	out := ProjectionResult{ProvisioningDomainID: domain}
	if p.groups == nil && p.roles == nil {
		return out, ErrNoGroupMapper
	}
	type ref struct{ conn, id string }
	var r ref
	var all []ref
	q := p.core.Select().Columns(sqlb.Bind(GroupConnectionID, &r.conn), sqlb.Bind(GroupID, &r.id)).From(TableGroup).
		Join(sqlb.Join{Type: sqlb.JoinInner, Table: TableConnection, On: []sqlb.Predicate{sqlb.EqExpr(ConnID, GroupConnectionID)}}).
		Where(sqlb.Eq(ConnDomain, domain), sqlb.Eq(ConnStatus, ConnectionActive)).Order(sqlb.OrderBy(GroupID, sqlb.SortAsc))
	if err := p.core.Each(ctx, q, func() error { all = append(all, r); return nil }); err != nil {
		return out, err
	}
	for start := 0; start < len(all); start += decommissionBatch {
		batch := all[start:min(start+decommissionBatch, len(all))]
		if err := p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			for _, g := range batch {
				if err := p.syncGroup(ctx, g.conn, g.id); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return out, err
		}
		out.Groups += len(batch)
		out.Batches++
	}
	return out, nil
}
