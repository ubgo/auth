package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/ubgo/sqlb"
)

// txState is the transaction attached to a context, plus the work to run only
// once it commits.
type txState struct {
	tx *sql.Tx

	mu          sync.Mutex
	afterCommit []func(context.Context)
	afterEnd    []func(context.Context)
}

type txKey struct{}

// Tx runs fn in one transaction and commits it when fn returns nil.
//
// Why the library owns begin and commit rather than accepting an app's *sql.Tx:
// messages such as a verify email must go out only after the data they refer to
// is committed. If the app committed, the library could not know when to send,
// and an app that forgot one extra call would silently never send a verify
// link. Here the careless path is the correct path: the app writes its own rows
// with tx, every library call made with the ctx that fn receives joins the same
// transaction, and the messages go out after the commit.
//
// A Tx inside a Tx joins the outer one; only the outermost commits.
//
//ds:def id=core-tx-7y49gnwg owner=@khanakia stability=stable
func (a *Auth) Tx(ctx context.Context, fn func(ctx context.Context, tx *sql.Tx) error) error {
	if st := txFrom(ctx); st != nil {
		return fn(ctx, st.tx)
	}
	if a.db == nil {
		return ErrNoDatabase
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("auth: begin transaction: %w", err)
	}
	st := &txState{tx: tx}
	txCtx := context.WithValue(ctx, txKey{}, st)
	defer st.runAfterEnd(ctx)
	if err := fn(txCtx, tx); err != nil {
		_ = tx.Rollback() // the fn error is the one worth reporting
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("auth: commit: %w", err)
	}
	st.mu.Lock()
	work := st.afterCommit
	st.mu.Unlock()
	for _, w := range work {
		w(ctx)
	}
	return nil
}

func (st *txState) runAfterEnd(ctx context.Context) {
	st.mu.Lock()
	work := st.afterEnd
	st.mu.Unlock()
	for _, w := range work {
		w(ctx)
	}
}

func txFrom(ctx context.Context) *txState {
	st, _ := ctx.Value(txKey{}).(*txState)
	return st
}

// conn returns the transaction in ctx, or the database outside one.
func (a *Auth) conn(ctx context.Context) (sqlb.DBTX, error) {
	if st := txFrom(ctx); st != nil {
		return st.tx, nil
	}
	if a.db == nil {
		return nil, ErrNoDatabase
	}
	return a.db, nil
}

// Conn returns what a plugin must run its own statements on for ctx: the open
// transaction when there is one, the database otherwise. A plugin that used
// DB() directly inside a transaction would write outside it and escape the
// rollback.
func (a *Auth) Conn(ctx context.Context) (sqlb.DBTX, error) { return a.conn(ctx) }

// AfterCommit runs fn once the transaction in ctx commits, or at once when ctx
// has no transaction. A rolled-back transaction runs nothing.
//
//ds:def id=core-aftercommit-s8ap3vuj owner=@khanakia stability=stable
func (a *Auth) AfterCommit(ctx context.Context, fn func(context.Context)) {
	st := txFrom(ctx)
	if st == nil {
		fn(ctx)
		return
	}
	st.mu.Lock()
	st.afterCommit = append(st.afterCommit, fn)
	st.mu.Unlock()
}

// AfterTx runs fn once the transaction in ctx ends, whether it commits or
// rolls back, or at once when ctx has no transaction. It is for a write that a
// failure must not undo, such as counting a wrong guess: the operation fails,
// its transaction rolls back, and the count still lands. fn must use the
// database handle, since the transaction is gone when it runs.
//
//ds:def id=core-aftertx-4qx8tmhm owner=@khanakia stability=stable
func (a *Auth) AfterTx(ctx context.Context, fn func(context.Context)) {
	st := txFrom(ctx)
	if st == nil {
		fn(ctx)
		return
	}
	st.mu.Lock()
	st.afterEnd = append(st.afterEnd, fn)
	st.mu.Unlock()
}

// Statement is a sqlb builder ready to render: every Insert, Update, Delete
// and Select a sqlb constructor returns satisfies it.
//
// Exec, One and Each take the builder rather than a rendered sqlb.Query so the
// render step and its error live in one place (prepare), not after every
// statement: a fixed statement shape never fails to render, and a branch per
// call site for that would be code no input can reach.
//
//ds:def id=core-statement-bkwcgy25 owner=@khanakia stability=stable
type Statement interface {
	Build() (sqlb.Query, error)
}

// prepare picks the connection for ctx and renders s for it.
func (a *Auth) prepare(ctx context.Context, s Statement) (sqlb.DBTX, sqlb.Query, error) {
	c, err := a.conn(ctx)
	if err != nil {
		return nil, sqlb.Query{}, err
	}
	q, err := s.Build()
	if err != nil {
		return nil, sqlb.Query{}, fmt.Errorf("auth: build statement: %w", err)
	}
	return c, q, nil
}

// Exec renders a write statement and runs it on the connection for ctx — the
// open transaction when there is one, the database otherwise (see Conn) — and
// returns the number of rows it matched.
//
// It is how a plugin writes its OWN tables. Core tables stay closed to plugins
// whatever runs the statement: a plugin changes a core row only through the
// core API (CreateIdentity, SetUserColumn, …), and
// TestGuard_PluginsNeverWriteCoreTables enforces that on the syntax tree.
//
//ds:def id=core-exec-yaek8r9j owner=@khanakia stability=stable
func (a *Auth) Exec(ctx context.Context, s Statement) (int64, error) {
	c, q, err := a.prepare(ctx, s)
	if err != nil {
		return 0, err
	}
	ctx, end := a.dbSpan(ctx, q.SQL)
	res, err := c.ExecContext(ctx, q.SQL, q.Args...)
	if err != nil {
		end(err)
		return 0, err
	}
	n, err := res.RowsAffected()
	end(err)
	return n, err
}

// One renders a read and runs it on the connection for ctx, expecting exactly
// one row, which it scans into the statement's bindings. sqlb.ErrNoRows when
// there is none; the caller maps that to its own not-found error.
//
//ds:def id=core-one-gc295a2p owner=@khanakia stability=stable
func (a *Auth) One(ctx context.Context, s Statement) error {
	c, q, err := a.prepare(ctx, s)
	if err != nil {
		return err
	}
	ctx, end := a.dbSpan(ctx, q.SQL)
	err = sqlb.One(ctx, c, q)
	// No row is an answer, not a failed statement.
	end(ignoreNoRows(err))
	return err
}

// ignoreNoRows is err, or nil for sqlb.ErrNoRows.
func ignoreNoRows(err error) error {
	if errors.Is(err, sqlb.ErrNoRows) {
		return nil
	}
	return err
}

// Each renders a read and runs it on the connection for ctx, calling fn after
// each row is scanned into the statement's bindings; an error from fn stops
// the iteration and is returned.
//
//ds:def id=core-each-h7cmxjbg owner=@khanakia stability=stable
func (a *Auth) Each(ctx context.Context, s Statement, fn func() error) error {
	c, q, err := a.prepare(ctx, s)
	if err != nil {
		return err
	}
	ctx, end := a.dbSpan(ctx, q.SQL)
	err = sqlb.Each(ctx, c, q, fn)
	end(err)
	return err
}

// sqlbTx names the transaction type the core's own Tx callbacks receive. Core
// statements reach the transaction through conn(ctx), so every write in a
// callback goes to the same place; the callback hands tx itself only to the
// data hooks, whose signature takes it explicitly.
type sqlbTx = *sql.Tx
