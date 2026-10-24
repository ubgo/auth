package main

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"github.com/ubgo/auth"
)

// loggingStore is a session store of the app's own: it delegates every call
// to another store, counts them, and logs them. It is the smallest possible
// custom store, and it shows the whole contract a store must keep. A real one
// would talk to a key-value service instead of delegating.
//
// A store never sees a raw token, only its hash, so even this store's log
// line cannot leak a credential. The test runs it through sessiontest.Run,
// which is how any custom store proves it keeps the contract.
type loggingStore struct {
	next   auth.SessionStore
	logger *log.Logger
	// finds counts Find calls: the number of times a request paid for a
	// session lookup, which is what a cache is meant to bring down.
	finds atomic.Int64
}

// newLoggingStore wraps next. logger may be log.Default(); nil logs nothing.
func newLoggingStore(next auth.SessionStore, logger *log.Logger) *loggingStore {
	return &loggingStore{next: next, logger: logger}
}

// Finds returns how many times the core looked a session up.
func (s *loggingStore) Finds() int64 { return s.finds.Load() }

func (s *loggingStore) logf(format string, args ...any) {
	if s.logger != nil {
		s.logger.Printf("session store: "+format, args...)
	}
}

// Insert saves a new session.
func (s *loggingStore) Insert(ctx context.Context, sess auth.Session, tokenHash []byte) error {
	s.logf("insert %s for %s", sess.ID, sess.UserID)
	return s.next.Insert(ctx, sess, tokenHash)
}

// Find looks a session up by token hash; the count is what the test reads.
func (s *loggingStore) Find(ctx context.Context, tokenHash []byte, now time.Time) (auth.Session, error) {
	s.finds.Add(1)
	s.logf("find")
	return s.next.Find(ctx, tokenHash, now)
}

// Touch slides a session's expiry.
func (s *loggingStore) Touch(ctx context.Context, id string, expiresAt, lastSeenAt time.Time) (bool, error) {
	s.logf("touch %s", id)
	return s.next.Touch(ctx, id, expiresAt, lastSeenAt)
}

// List returns a user's live sessions.
func (s *loggingStore) List(ctx context.Context, userID string, now time.Time) ([]auth.Session, error) {
	s.logf("list for %s", userID)
	return s.next.List(ctx, userID, now)
}

// Delete ends one session.
func (s *loggingStore) Delete(ctx context.Context, userID, id string) error {
	s.logf("delete %s", id)
	return s.next.Delete(ctx, userID, id)
}

// DeleteUser ends every session of a user but exceptID.
func (s *loggingStore) DeleteUser(ctx context.Context, userID, exceptID string) error {
	s.logf("delete all for %s except %q", userID, exceptID)
	return s.next.DeleteUser(ctx, userID, exceptID)
}

// Sweep deletes expired sessions.
func (s *loggingStore) Sweep(ctx context.Context, now time.Time) (int64, error) {
	n, err := s.next.Sweep(ctx, now)
	s.logf("sweep removed %d", n)
	return n, err
}

// SetData replaces a session's app data. The log line says how long it is
// and never what it holds: the data is the app's, not the store's.
func (s *loggingStore) SetData(ctx context.Context, id string, data auth.AppData) error {
	s.logf("set data of %s (%d bytes)", id, len(data))
	return s.next.SetData(ctx, id, data)
}
