package auth

import (
	"context"

	"github.com/ubgo/sqlb"
)

// TableHooks run around writes to one core table, inside the writing
// transaction. A Before hook may change the row or refuse the write; an error
// from any hook rolls the whole transaction back.
//
// Every hook receives tx and must use it: a hook that wrote through the
// database handle instead would escape the rollback.
//
//ds:def id=core-tablehooks-4tp6dfkv owner=@khanakia stability=stable
type TableHooks[T any] struct {
	BeforeCreate func(ctx context.Context, tx sqlb.DBTX, row *T) error
	AfterCreate  func(ctx context.Context, tx sqlb.DBTX, row *T) error
	BeforeUpdate func(ctx context.Context, tx sqlb.DBTX, old, new *T) error
	AfterUpdate  func(ctx context.Context, tx sqlb.DBTX, old, new *T) error
	BeforeDelete func(ctx context.Context, tx sqlb.DBTX, row *T) error
}

// DataHooks are a plugin's hooks on the core tables.
//
//ds:def id=core-datahooks-3gpn2nnz owner=@khanakia stability=stable
type DataHooks struct {
	User         TableHooks[User]
	Identity     TableHooks[Identity]
	Session      TableHooks[Session]
	Verification TableHooks[Verification]
	// SessionEnded runs for every session that ends: sign-out, revoke, an
	// admin, a ban, a password change, token-reuse theft, user deletion and
	// the expiry sweep (see SessionEndReason), once per session, inside the
	// transaction that ends it and before the store is told, so a rollback
	// leaves nothing durable. tx is the transaction and must be used for
	// writes. A hook cannot refuse an ending; failures are reported, not
	// enforced: a session that must end (a stolen token, a banned user, a
	// changed password) never stays alive because a hook failed. When a hook
	// returns an error the core rolls that attempt back, ends the session
	// again without the hooks in a transaction of its own, and emits
	// SecuritySessionEndHookFailed (and logs it) with the reason and error.
	// Inside a transaction the caller already opened the attempt cannot be
	// rolled back alone, so the error is reported and the ending continues,
	// and the hook's own writes in that transaction stay with it. Gaps: a store that expires
	// sessions itself (Redis TTL, storage) or wraps another (mirror) reports
	// no expiry, and stateless mode reports only ends the core performs
	// (see SessionEnd). It is not told of a pending second-factor session
	// being replaced (SessionLifecycle.SessionReplaced is).
	SessionEnded func(ctx context.Context, tx sqlb.DBTX, e SessionEnd) error
}

// DataHooker supplies data hooks.
//
//ds:def id=core-datahooker-mvyjtp5j owner=@khanakia stability=stable
type DataHooker interface {
	DataHooks() DataHooks
}

// hookStage names which hook of a TableHooks a write runs.
type hookStage int

const (
	stageBeforeCreate hookStage = iota
	stageAfterCreate
	stageBeforeUpdate
	stageAfterUpdate
	stageBeforeDelete
)

// runHooks runs one stage of one table's hooks from every plugin, in plugin
// order, stopping at the first error. tx is the writing transaction: every
// core write runs its hooks inside a.Tx, so the caller passes the transaction
// its callback received rather than runHooks looking one up and having to
// handle "there is none", which no caller can produce.
func runHooks[T any](ctx context.Context, a *Auth, tx sqlb.DBTX, pick func(DataHooks) TableHooks[T], stage hookStage, old, row *T) error {
	for _, dh := range a.dataHooks {
		h := pick(dh)
		var fn func() error
		switch stage {
		case stageBeforeCreate:
			if h.BeforeCreate != nil {
				fn = func() error { return h.BeforeCreate(ctx, tx, row) }
			}
		case stageAfterCreate:
			if h.AfterCreate != nil {
				fn = func() error { return h.AfterCreate(ctx, tx, row) }
			}
		case stageBeforeUpdate:
			if h.BeforeUpdate != nil {
				fn = func() error { return h.BeforeUpdate(ctx, tx, old, row) }
			}
		case stageAfterUpdate:
			if h.AfterUpdate != nil {
				fn = func() error { return h.AfterUpdate(ctx, tx, old, row) }
			}
		case stageBeforeDelete:
			if h.BeforeDelete != nil {
				fn = func() error { return h.BeforeDelete(ctx, tx, row) }
			}
		}
		if fn != nil {
			_, end := a.dataHookSpan(ctx, hookStageNames[stage], hookModel(row))
			err := fn()
			end(err)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// hookStageNames are the stages as a data-hook span reports them.
var hookStageNames = map[hookStage]string{
	stageBeforeCreate: "before_create", stageAfterCreate: "after_create",
	stageBeforeUpdate: "before_update", stageAfterUpdate: "after_update", stageBeforeDelete: "before_delete",
}

// hookModel names the core model a data hook's row is, for its span.
func hookModel(row any) string {
	switch row.(type) {
	case *User:
		return "user"
	case *Identity:
		return "identity"
	case *Session:
		return "session"
	case *Verification:
		return "verification"
	}
	return ""
}

func pickUser(d DataHooks) TableHooks[User]                 { return d.User }
func pickIdentity(d DataHooks) TableHooks[Identity]         { return d.Identity }
func pickSession(d DataHooks) TableHooks[Session]           { return d.Session }
func pickVerification(d DataHooks) TableHooks[Verification] { return d.Verification }
