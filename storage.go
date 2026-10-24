package auth

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SecondaryStorage is one key-value store for the short-lived records:
// implement these four methods over Redis, Memcached, Cloudflare KV or
// anything with expiring keys, and WithSecondaryStorage keeps sessions and
// rate-limit counters in it instead of the database. Values are strings; a
// ttl of 0 means no expiry.
//
// Verification tokens are not in it: they stay in SQL,
// where a conditional UPDATE spends each one exactly once inside the
// operation's transaction, so a KV store needs no atomic get-and-delete.
//
//ds:def id=core-secondarystorage-8nq3kw5d owner=@khanakia stability=stable
type SecondaryStorage interface {
	// Get returns the value under key and true, or false when there is none
	// or it expired. An error is a failure of the store, not a miss.
	Get(ctx context.Context, key string) (string, bool, error)
	// Set stores value under key for ttl (0: no expiry), replacing any.
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	// Delete removes key; an absent key is no error.
	Delete(ctx context.Context, key string) error
	// Increment adds one to the counter under key and returns the new value,
	// atomically. An absent key starts at 1 and expires ttl later; later
	// increments never extend that, so the counter is a fixed window.
	Increment(ctx context.Context, key string, ttl time.Duration) (int64, error)
}

// Key layout of the storage-backed stores. Each is a fixed prefix and an id,
// so two stores can share one SecondaryStorage, and the prefix namespaces
// them within a shared Redis.
const (
	storageSessionKey   = "auth:session:"
	storageSessionIDKey = "auth:session-id:"
	storageUserKey      = "auth:user-sessions:"
	storageUserGenKey   = "auth:user-generation:"
	storageRateKey      = "auth:rate:"
)

// WithSecondaryStorage keeps sessions (NewStorageSessionStore) and rate-limit
// counters (NewStorageRateStore) in kv instead of the database. It is
// WithSessionStore and WithRateStore in one; a later WithSessionStore or
// WithRateStore replaces its half. Users, identities and verification tokens
// stay in SQL.
//
//ds:def id=opt-withsecondarystorage-4wd9nq2k owner=@khanakia stability=stable
func WithSecondaryStorage(kv SecondaryStorage) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithSecondaryStorage", kv) {
			return
		}
		s.sessions = NewStorageSessionStore(kv)
		s.rateStore = NewStorageRateStore(kv)
	}
}

// storageRateStore counts rate-limit hits with SecondaryStorage.Increment.
type storageRateStore struct{ kv SecondaryStorage }

// NewStorageRateStore returns a RateStore over kv: one fixed-window counter
// per key, created by the first hit with the window as its expiry, which is
// exactly the RateStore contract when Increment is atomic.
//
//ds:def id=core-newstorageratestore-6qk2wn8d owner=@khanakia stability=stable
func NewStorageRateStore(kv SecondaryStorage) RateStore { return storageRateStore{kv: kv} }

// OptionErr passes on the storage's own option errors (OptionChecker), so a
// store built with a nil option still fails New after this wrapper hides it.
func (r storageRateStore) OptionErr() error { return optionErrOf(r.kv) }

// Hit implements RateStore.
func (r storageRateStore) Hit(ctx context.Context, key string, window time.Duration) (int, error) {
	n, err := r.kv.Increment(ctx, storageRateKey+key, window)
	return int(n), err
}

// storageSessionStore keeps sessions in a SecondaryStorage: each session as
// JSON under its token hash, its id pointing at the hash, and per user the
// list of its session ids, because a KV store cannot be asked "every
// session of this user".
//
// The per-user list is read, changed and written back, which two instances
// can interleave and so drop an id. That is why a session does not depend
// on the list to be ended: every session is stamped with its user's
// generation, a counter "sign out everywhere" (DeleteUser) advances with an
// atomic Increment, and Find refuses a session from an older generation
// whether or not the list still names it. A dropped id can therefore only
// make List show one session fewer, never keep a session alive; a sign-in
// racing a DeleteUser may end up refused, never the reverse.
type storageSessionStore struct {
	kv SecondaryStorage
	// mu serialises this instance's read-modify-write of a user's list.
	mu sync.Mutex
}

// NewStorageSessionStore returns a SessionStore over kv; see
// storageSessionStore for the layout. Each record expires with its session,
// computed from the session's own times, never the wall clock, so a test
// clock and the store agree.
//
//ds:def id=core-newstoragesessionstore-2pq7xk4w owner=@khanakia stability=stable
func NewStorageSessionStore(kv SecondaryStorage) SessionStore {
	return &storageSessionStore{kv: kv}
}

// OptionErr passes on the storage's own option errors (OptionChecker), so a
// store built with a nil option still fails New after this wrapper hides it.
func (s *storageSessionStore) OptionErr() error { return optionErrOf(s.kv) }

// storedSession is the record under a session's token hash: the session
// and the user generation it belongs to.
type storedSession struct {
	Session    Session `json:"s"`
	Generation int64   `json:"g"`
}

// ttlFrom is how long a record about s must live: until the session's own
// expiry, counted from from; never 0, which would mean "no expiry".
func ttlFrom(s Session, from time.Time) time.Duration {
	return max(s.ExpiresAt.Sub(from), time.Second)
}

// put writes s of generation gen under its hash and its id, living until
// its expiry.
func (m *storageSessionStore) put(ctx context.Context, s Session, gen int64, hash string, from time.Time) error {
	body, err := json.Marshal(storedSession{Session: s, Generation: gen})
	if err != nil {
		return err
	}
	ttl := ttlFrom(s, from)
	if err := m.kv.Set(ctx, storageSessionKey+hash, string(body), ttl); err != nil {
		return err
	}
	return m.kv.Set(ctx, storageSessionIDKey+s.ID, hash, ttl)
}

// Insert implements SessionStore.
func (m *storageSessionStore) Insert(ctx context.Context, s Session, tokenHash []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	gen, err := m.generation(ctx, s.UserID)
	if err != nil {
		return err
	}
	if err := m.put(ctx, s, gen, hex.EncodeToString(tokenHash), s.CreatedAt); err != nil {
		return err
	}
	ids, err := m.userIDs(ctx, s.UserID)
	if err != nil {
		return err
	}
	if !slices.Contains(ids, s.ID) {
		ids = append(ids, s.ID)
	}
	return m.setUserIDs(ctx, s.UserID, ids)
}

// byHash reads the record under hash, or false.
func (m *storageSessionStore) byHash(ctx context.Context, hash string) (storedSession, bool, error) {
	body, ok, err := m.kv.Get(ctx, storageSessionKey+hash)
	if err != nil || !ok {
		return storedSession{}, false, err
	}
	var rec storedSession
	if err := json.Unmarshal([]byte(body), &rec); err != nil {
		return storedSession{}, false, fmt.Errorf("auth: stored session: %w", err)
	}
	return rec, true, nil
}

// byID reads session id's record and its hash, or false.
func (m *storageSessionStore) byID(ctx context.Context, id string) (storedSession, string, bool, error) {
	hash, ok, err := m.kv.Get(ctx, storageSessionIDKey+id)
	if err != nil || !ok {
		return storedSession{}, "", false, err
	}
	rec, ok, err := m.byHash(ctx, hash)
	return rec, hash, ok, err
}

// generation reads userID's generation; a user never signed out everywhere
// is at 0.
func (m *storageSessionStore) generation(ctx context.Context, userID string) (int64, error) {
	raw, ok, err := m.kv.Get(ctx, storageUserGenKey+userID)
	if err != nil || !ok {
		return 0, err
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("auth: stored generation: %w", err)
	}
	return n, nil
}

// live reports whether rec is still a session at now: not expired, and of
// its user's current generation.
func (m *storageSessionStore) live(ctx context.Context, rec storedSession, now time.Time) (bool, error) {
	if !rec.Session.ExpiresAt.After(now) {
		return false, nil
	}
	gen, err := m.generation(ctx, rec.Session.UserID)
	return gen == rec.Generation, err
}

// Find implements SessionStore.
func (m *storageSessionStore) Find(ctx context.Context, tokenHash []byte, now time.Time) (Session, error) {
	rec, ok, err := m.byHash(ctx, hex.EncodeToString(tokenHash))
	if err != nil {
		return Session{}, err
	}
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	alive, err := m.live(ctx, rec, now)
	if err != nil {
		return Session{}, err
	}
	if !alive {
		return Session{}, ErrSessionNotFound
	}
	return rec.Session, nil
}

// Touch implements SessionStore. "First wins" holds within this instance
// (the mutex); across instances two refreshes may both report true, which
// only issues the same new expiry twice.
func (m *storageSessionStore) Touch(ctx context.Context, id string, expiresAt, lastSeenAt time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, hash, ok, err := m.byID(ctx, id)
	if err != nil || !ok || !rec.Session.ExpiresAt.Before(expiresAt) {
		return false, err
	}
	rec.Session.ExpiresAt, rec.Session.LastSeenAt = expiresAt, lastSeenAt
	if err := m.put(ctx, rec.Session, rec.Generation, hash, lastSeenAt); err != nil {
		return false, err
	}
	return true, nil
}

// List implements SessionStore.
func (m *storageSessionStore) List(ctx context.Context, userID string, now time.Time) ([]Session, error) {
	ids, err := m.userIDs(ctx, userID)
	if err != nil {
		return nil, err
	}
	var out []Session
	for _, id := range ids {
		rec, _, ok, err := m.byID(ctx, id)
		if err != nil {
			return nil, err
		}
		if !ok || rec.Session.SecondFactorPending {
			continue
		}
		alive, err := m.live(ctx, rec, now)
		if err != nil {
			return nil, err
		}
		if alive {
			out = append(out, rec.Session)
		}
	}
	slices.SortFunc(out, func(a, b Session) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(b.ID, a.ID)
	})
	return out, nil
}

// Delete implements SessionStore.
func (m *storageSessionStore) Delete(ctx context.Context, userID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, hash, ok, err := m.byID(ctx, id)
	if err != nil || !ok || rec.Session.UserID != userID {
		return err
	}
	return m.remove(ctx, id, hash)
}

// remove deletes one session's records; the user's list is rewritten by the
// caller or pruned by the next read.
func (m *storageSessionStore) remove(ctx context.Context, id, hash string) error {
	if err := m.kv.Delete(ctx, storageSessionKey+hash); err != nil {
		return err
	}
	return m.kv.Delete(ctx, storageSessionIDKey+id)
}

// DeleteUser implements SessionStore: the generation first, so every
// session of the user stops opening at once, listed or not; then the
// excepted session is restamped into the new generation, and the others'
// records are removed (they would expire by themselves; removing them keeps
// the store small).
func (m *storageSessionStore) DeleteUser(ctx context.Context, userID, exceptID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	gen, err := m.kv.Increment(ctx, storageUserGenKey+userID, 0)
	if err != nil {
		return err
	}
	ids, err := m.userIDs(ctx, userID)
	if err != nil {
		return err
	}
	var keep []string
	for _, id := range ids {
		rec, hash, ok, err := m.byID(ctx, id)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if id == exceptID {
			keep = append(keep, id)
			if err := m.put(ctx, rec.Session, gen, hash, rec.Session.LastSeenAt); err != nil {
				return err
			}
			continue
		}
		if err := m.remove(ctx, id, hash); err != nil {
			return err
		}
	}
	return m.setUserIDs(ctx, userID, keep)
}

// Sweep implements SessionStore: records expire in the store by themselves.
func (m *storageSessionStore) Sweep(context.Context, time.Time) (int64, error) { return 0, nil }

// SetData implements SessionStore.
func (m *storageSessionStore) SetData(ctx context.Context, id string, data AppData) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, hash, ok, err := m.byID(ctx, id)
	if err != nil || !ok {
		return err
	}
	rec.Session.Data = data
	return m.put(ctx, rec.Session, rec.Generation, hash, rec.Session.LastSeenAt)
}

// SetReauthenticatedAt implements SessionReauthStore. A concurrent SetData on
// another instance can undo it (both rewrite the record), which only makes
// the session less fresh: the user re-authenticates again, nothing is let in.
func (m *storageSessionStore) SetReauthenticatedAt(ctx context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, hash, ok, err := m.byID(ctx, id)
	if err != nil || !ok {
		return err
	}
	rec.Session.ReauthenticatedAt = &at
	return m.put(ctx, rec.Session, rec.Generation, hash, rec.Session.LastSeenAt)
}

// userIDs reads userID's list of session ids.
func (m *storageSessionStore) userIDs(ctx context.Context, userID string) ([]string, error) {
	raw, ok, err := m.kv.Get(ctx, storageUserKey+userID)
	if err != nil || !ok || raw == "" {
		return nil, err
	}
	return strings.Split(raw, storageIDSeparator), nil
}

// storageIDSeparator joins a user's session ids; ids are opaque text without
// spaces (NewID), so a space never appears inside one.
const storageIDSeparator = " "

// setUserIDs writes userID's list, or deletes it when empty.
func (m *storageSessionStore) setUserIDs(ctx context.Context, userID string, ids []string) error {
	if len(ids) == 0 {
		return m.kv.Delete(ctx, storageUserKey+userID)
	}
	return m.kv.Set(ctx, storageUserKey+userID, strings.Join(ids, storageIDSeparator), 0)
}

// memoryStorage is NewMemoryStorage: a map with expiries on a clock.
type memoryStorage struct {
	mu   sync.Mutex
	now  func() time.Time
	vals map[string]memoryValue
}

type memoryValue struct {
	v   string
	exp time.Time
}

// errNegativeTTL refuses a negative ttl, which would mean "already expired".
var errNegativeTTL = errors.New("auth: negative ttl")

// NewMemoryStorage returns a SecondaryStorage in this process's memory, on
// the given clock (nil: time.Now), for tests and single-process apps. Expired
// keys read as absent and are dropped as they are read.
//
//ds:def id=core-newmemorystorage-9wk3nd2q owner=@khanakia stability=stable
func NewMemoryStorage(now func() time.Time) SecondaryStorage {
	if now == nil {
		now = time.Now
	}
	return &memoryStorage{now: now, vals: map[string]memoryValue{}}
}

// get reads key under the lock, dropping it when expired.
func (m *memoryStorage) get(key string) (memoryValue, bool) {
	v, ok := m.vals[key]
	if ok && !v.exp.IsZero() && !m.now().Before(v.exp) {
		delete(m.vals, key)
		return memoryValue{}, false
	}
	return v, ok
}

// Get implements SecondaryStorage.
func (m *memoryStorage) Get(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.get(key)
	return v.v, ok, nil
}

// Set implements SecondaryStorage.
func (m *memoryStorage) Set(_ context.Context, key, value string, ttl time.Duration) error {
	if ttl < 0 {
		return errNegativeTTL
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	v := memoryValue{v: value}
	if ttl > 0 {
		v.exp = m.now().Add(ttl)
	}
	m.vals[key] = v
	return nil
}

// Delete implements SecondaryStorage.
func (m *memoryStorage) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.vals, key)
	return nil
}

// Increment implements SecondaryStorage.
func (m *memoryStorage) Increment(_ context.Context, key string, ttl time.Duration) (int64, error) {
	if ttl < 0 {
		return 0, errNegativeTTL
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.get(key)
	if !ok {
		v = memoryValue{v: "0"}
		if ttl > 0 {
			v.exp = m.now().Add(ttl)
		}
	}
	n, err := strconv.ParseInt(v.v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("auth: %q holds no counter: %w", key, err)
	}
	n++
	v.v = strconv.FormatInt(n, 10)
	m.vals[key] = v
	return n, nil
}
