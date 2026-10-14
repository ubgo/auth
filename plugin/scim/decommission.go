package scim

import (
	"context"
	"database/sql"
	"time"

	"github.com/ubgo/sqlb"
)

// DecommissionRequest names the connection to retire.
type DecommissionRequest struct {
	ConnectionID string
	// ProvisioningDomainID, when set, must be the connection's; a managed
	// connection is found only within its domain.
	ProvisioningDomainID string
	ActorID              string
	// MaxBatches bounds the work of one call (batches of 50 SCIM users);
	// zero runs to completion. A call that stops early answers
	// DecommissionReconciling, and the next call resumes at the cursor.
	MaxBatches int
}

// DecommissionStatus is where a decommission stands.
type DecommissionStatus string

// Decommission statuses, better-auth's.
const (
	DecommissionReconciling DecommissionStatus = "reconciling"
	DecommissionComplete    DecommissionStatus = "complete"
)

// DecommissionResult reports a decommission's progress.
type DecommissionResult struct {
	ConnectionID         string
	ProvisioningDomainID string
	Status               DecommissionStatus
	DecommissionedAt     *time.Time
	ReconciledUsers      int64
	Batches              int64
}

// DecommissionConnection retires a connection for good, better-auth's
// decommissionSCIMConnection (and decommissionSCIMManagedConnection): its
// tokens stop working at once (every request with one answers 401 "SCIM
// connection is decommissioned": a static token, and a managed credential
// that was active, which is marked decommissioned; one revoked before keeps
// answering "Invalid SCIM bearer token"), then
// its SCIM users are made inactive in batches, each in its own transaction,
// and each linked library user is reconciled, so a user with no other active
// source is deactivated and signed out. Groups are told to the GroupMapper
// as deleted at the end. The SCIM rows are kept for the record. It is
// irreversible, resumable (the cursor survives a crash) and meant to be run
// by one worker at a time.
//
//ds:def id=scim-plugin-decommissionconnection-2q8xv5mk owner=@khanakia stability=stable
func (p *Plugin) DecommissionConnection(ctx context.Context, in DecommissionRequest) (DecommissionResult, error) {
	c, ok, err := p.loadConn(ctx, in.ConnectionID)
	if err != nil {
		return DecommissionResult{}, err
	}
	if !ok || (in.ProvisioningDomainID != "" && c.domain != in.ProvisioningDomainID) {
		return DecommissionResult{}, ErrConnectionNotFound
	}
	d := p.core.Dialect()
	if c.status == ConnectionActive {
		err := p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			now := p.now()
			if _, err := p.core.Exec(ctx, sqlb.NewUpdate(d).Table(TableConnection).
				Set(sqlb.Set(ConnStatus, ConnectionDecommissioning), sqlb.Set(ConnDecomStarted, &now)).
				Where(sqlb.Eq(ConnID, c.id), sqlb.Eq(ConnStatus, ConnectionActive))); err != nil {
				return err
			}
			if _, err := p.core.Exec(ctx, sqlb.NewUpdate(d).Table(TableCredential).Set(sqlb.Set(CredStatus, CredentialDecommissioned)).
				Where(sqlb.Eq(CredConnection, c.id), sqlb.Eq(CredStatus, CredentialActive))); err != nil {
				return err
			}
			return p.event(ctx, c.id, EventConnectionDecommissioning, in.ActorID, "")
		})
		if err != nil {
			return DecommissionResult{}, err
		}
		c.status = ConnectionDecommissioning
	}
	for done := 0; c.status == ConnectionDecommissioning && (in.MaxBatches == 0 || done < in.MaxBatches); done++ {
		if c, err = p.decommissionBatch(ctx, c, in.ActorID); err != nil {
			return DecommissionResult{}, err
		}
	}
	res := DecommissionResult{ConnectionID: c.id, ProvisioningDomainID: c.domain, Status: DecommissionReconciling,
		DecommissionedAt: c.decommissioned, ReconciledUsers: c.reconciled, Batches: c.batches}
	if c.status == ConnectionDecommissioned {
		res.Status = DecommissionComplete
	}
	return res, nil
}

// decommissionBatch makes the next batch of a connection's SCIM users
// inactive and reconciles their library users, or, with none left, tells
// the GroupMapper its groups are gone and marks the connection done.
func (p *Plugin) decommissionBatch(ctx context.Context, c connRow, actor string) (connRow, error) {
	err := p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		d := p.core.Dialect()
		var sid, uid string
		var batch [][2]string
		if err := p.core.Each(ctx, p.core.Select().Columns(sqlb.Bind(UserID, &sid), sqlb.Bind(UserUserID, &uid)).From(TableUser).
			Where(sqlb.Eq(UserConnectionID, c.id), sqlb.Greater(UserID, c.cursor)).Order(sqlb.OrderBy(UserID, sqlb.SortAsc)).Limit(decommissionBatch),
			func() error { batch = append(batch, [2]string{sid, uid}); return nil }); err != nil {
			return err
		}
		if len(batch) == 0 {
			return p.finishDecommission(ctx, &c, actor)
		}
		for _, b := range batch {
			if _, err := p.core.Exec(ctx, sqlb.NewUpdate(d).Table(TableUser).Set(sqlb.Set(UserActive, false), sqlb.Set(UserUpdatedAt, p.now()),
				sqlb.SetExpr(UserRevision, sqlb.Add(UserRevision, sqlb.Literal[int64]("1")))).
				Where(sqlb.Eq(UserID, b[0]))); err != nil {
				return err
			}
			if err := p.reconcile(ctx, b[1], false); err != nil {
				return err
			}
		}
		c.cursor, c.reconciled, c.batches = batch[len(batch)-1][0], c.reconciled+int64(len(batch)), c.batches+1
		_, err := p.core.Exec(ctx, sqlb.NewUpdate(d).Table(TableConnection).
			Set(sqlb.Set(ConnDecomCursor, c.cursor), sqlb.Set(ConnReconciled, c.reconciled), sqlb.Set(ConnBatches, c.batches)).
			Where(sqlb.Eq(ConnID, c.id)))
		return err
	})
	return c, err
}

// finishDecommission ends a decommission: groups to the mapper, the
// connection marked decommissioned, the event logged.
func (p *Plugin) finishDecommission(ctx context.Context, c *connRow, actor string) error {
	if p.groups != nil || p.roles != nil {
		var gid string
		var groups []string
		if err := p.core.Each(ctx, p.core.Select().Columns(sqlb.Bind(GroupID, &gid)).From(TableGroup).Where(sqlb.Eq(GroupConnectionID, c.id)),
			func() error { groups = append(groups, gid); return nil }); err != nil {
			return err
		}
		for _, g := range groups {
			if err := p.dropGroup(ctx, c.id, g); err != nil {
				return err
			}
		}
	}
	now := p.now()
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableConnection).
		Set(sqlb.Set(ConnStatus, ConnectionDecommissioned), sqlb.Set(ConnDecommission, &now)).Where(sqlb.Eq(ConnID, c.id))); err != nil {
		return err
	}
	c.status, c.decommissioned = ConnectionDecommissioned, &now
	return p.event(ctx, c.id, EventConnectionDecommissioned, actor, "")
}
