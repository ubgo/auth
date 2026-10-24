package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/ubgo/sqlb"
)

// VerificationStore is where single-use verification tokens live: email
// links, reset links, magic links, OAuth state, passkey ceremonies. The SQL
// store on auth_verification is the default; WithVerificationStore replaces
// it, with a key-value store, say.
//
// A store keeps a token's hash, never the token. The contract every store
// keeps, checked by github.com/ubgo/auth/verificationtest:
//
//   - Consume spends a token exactly once: of any number of concurrent
//     Consume calls with one hash, exactly one returns the row and every
//     other returns ErrTokenInvalid.
//   - A wrong, spent, expired (ExpiresAt not after now) or wrong-purpose
//     token is ErrTokenInvalid, all alike, and a wrong-purpose attempt does
//     not spend the token.
//   - ConsumeAll ends every open token of one purpose for one identifier
//     and no other; DeleteIdentifiers ends every token, of any purpose,
//     filed under any of the identifiers.
//
// What a store outside the database gives up: it joins no transaction. With
// the SQL store, a token spent by an operation that then fails is unspent
// again by the rollback, and a token issued by one that fails never
// existed. A key-value store keeps both: the spent token stays spent (the
// user asks for a new link) and the issued one stays until it expires,
// although nobody received it, because delivery runs only after a commit.
// Sweep has nothing to delete there either: the store's own expiry removes
// each record.
//
//ds:def id=core-verificationstore-7mq2wk9d owner=@khanakia stability=stable
type VerificationStore interface {
	// Insert saves v under tokenHash.
	Insert(ctx context.Context, v Verification, tokenHash []byte) error
	// Consume spends the token of purpose whose hash is tokenHash, live at
	// now, and returns its row with ConsumedAt set, or ErrTokenInvalid.
	Consume(ctx context.Context, purpose Purpose, tokenHash []byte, now time.Time) (Verification, error)
	// ConsumeAll spends every open token of purpose filed under identifier.
	ConsumeAll(ctx context.Context, purpose Purpose, identifier string, now time.Time) error
	// DeleteIdentifiers ends every token filed under any of identifiers,
	// whatever its purpose, issued up to now: what DeleteUser calls for the
	// user's id and its identities' ids and values.
	DeleteIdentifiers(ctx context.Context, identifiers []string, now time.Time) error
	// Sweep deletes tokens that expired, or were spent, before cutoff, and
	// returns how many. A store that expires records itself returns 0.
	Sweep(ctx context.Context, cutoff time.Time) (int64, error)
}

// WithVerificationStore keeps verification tokens in s instead of the
// auth_verification table. NewStorageVerificationStore puts them in a
// key-value store (contrib/redis NewVerificationStore is that over Redis);
// NewMemoryVerificationStore keeps them in this process. See
// VerificationStore for what a store outside the database gives up. The
// table is still created, so switching back needs no migration.
//
//ds:def id=opt-withverificationstore-4hz8nq3v owner=@khanakia stability=stable
func WithVerificationStore(s VerificationStore) Option {
	return func(st *settings) {
		if st.optErrs.RefuseNil("auth.WithVerificationStore", s) {
			return
		}
		st.verifications = s
	}
}

// ErrTokenExists is an Insert of a token hash the store already holds,
// from a store that refuses duplicates (ExclusiveVerificationStore). Random
// tokens never collide, so only a caller that inserts a chosen value meets
// it: a single-use claim such as plugin/oauth's ID-token replay guard, for
// which it is the answer "already claimed".
//
//ds:def id=core-errtokenexists-6wq3nk8v owner=@khanakia stability=stable
var ErrTokenExists = errors.New("auth: verification token already stored")

// ExclusiveVerificationStore is a VerificationStore that can promise
// exclusive inserts: when RefusesDuplicateTokens reports true, Insert of a
// hash already stored (live or not yet swept) fails with ErrTokenExists, and
// of any number of concurrent Inserts of one hash exactly one succeeds. The
// SQL store always does (the token_hash column is unique); the key-value
// store does when its storage is a SetIfAbsenter. A caller that needs a
// single-use claim asks this before relying on it, because a store without
// the promise would accept the second claim silently.
//
//ds:def id=core-exclusiveverificationstore-2kd9wm4q owner=@khanakia stability=stable
type ExclusiveVerificationStore interface {
	VerificationStore
	RefusesDuplicateTokens() bool
}

// SetIfAbsenter is a SecondaryStorage that can store a key only when it is
// absent, in one atomic step: Redis SET NX. It is what lets the key-value
// verification store refuse a duplicate token (ExclusiveVerificationStore).
//
//ds:def id=core-setifabsenter-8vn2kq5w owner=@khanakia stability=stable
type SetIfAbsenter interface {
	SecondaryStorage
	// SetIfAbsent stores value under key for ttl (0: no expiry) and returns
	// true, or returns false and changes nothing when a live value is
	// already there.
	SetIfAbsent(ctx context.Context, key, value string, ttl time.Duration) (bool, error)
}

// VerificationStore returns the store verification tokens live in, so a
// conformance test can run against the SQL store this Auth uses.
func (a *Auth) VerificationStore() VerificationStore { return a.verifications }

// sqlVerificationStore is the default: auth_verification, inside the
// operation's transaction through ctx.
type sqlVerificationStore struct{ a *Auth }

// Insert implements VerificationStore.
func (s sqlVerificationStore) Insert(ctx context.Context, v Verification, tokenHash []byte) error {
	q := sqlb.NewInsert(s.a.cfg.Dialect).Into(TableVerification).Row(
		sqlb.Set(VerificationID, v.ID), sqlb.Set(VerificationIdentifier, v.Identifier),
		sqlb.Set(VerificationPurpose, v.Purpose), sqlb.Set(VerificationTokenHash, tokenHash),
		sqlb.Set(VerificationExpiresAt, v.ExpiresAt), sqlb.Set(VerificationMeta, v.Meta),
		sqlb.Set(VerificationCreatedAt, v.CreatedAt),
	)
	if _, err := s.a.Exec(ctx, q); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("auth: insert verification: %w: %w", ErrTokenExists, err)
		}
		return fmt.Errorf("auth: insert verification: %w", err)
	}
	return nil
}

// RefusesDuplicateTokens implements ExclusiveVerificationStore: token_hash is
// unique, so the database refuses a second row and serializes two concurrent
// inserts.
func (sqlVerificationStore) RefusesDuplicateTokens() bool { return true }

// Consume implements VerificationStore. Single use is enforced by the
// database, not by Go: the UPDATE matches only a row whose consumed_at is
// null, so of two requests with one token exactly one changes a row. There
// is no RETURNING, which MySQL lacks; the row is read back afterwards.
func (s sqlVerificationStore) Consume(ctx context.Context, purpose Purpose, tokenHash []byte, now time.Time) (Verification, error) {
	q := sqlb.NewUpdate(s.a.cfg.Dialect).Table(TableVerification).Set(sqlb.Set(VerificationConsumedAt, &now)).
		Where(
			sqlb.Eq(VerificationTokenHash, tokenHash), sqlb.Eq(VerificationPurpose, purpose),
			sqlb.IsNull(VerificationConsumedAt), sqlb.Greater(VerificationExpiresAt, now),
		)
	n, err := s.a.Exec(ctx, q)
	if err != nil {
		return Verification{}, fmt.Errorf("auth: consume verification: %w", err)
	}
	if n != 1 {
		return Verification{}, ErrTokenInvalid
	}
	var out Verification
	sel := s.a.Select().Columns(VerificationBindings(&out)...).From(TableVerification).
		Where(sqlb.Eq(VerificationTokenHash, tokenHash)).Limit(1)
	return out, s.a.One(ctx, sel)
}

// ConsumeAll implements VerificationStore.
func (s sqlVerificationStore) ConsumeAll(ctx context.Context, purpose Purpose, identifier string, now time.Time) error {
	q := sqlb.NewUpdate(s.a.cfg.Dialect).Table(TableVerification).Set(sqlb.Set(VerificationConsumedAt, &now)).
		Where(sqlb.Eq(VerificationPurpose, purpose), sqlb.Eq(VerificationIdentifier, identifier), sqlb.IsNull(VerificationConsumedAt))
	_, err := s.a.Exec(ctx, q)
	return err
}

// DeleteIdentifiers implements VerificationStore.
func (s sqlVerificationStore) DeleteIdentifiers(ctx context.Context, identifiers []string, _ time.Time) error {
	if len(identifiers) == 0 {
		return nil
	}
	_, err := s.a.Exec(ctx, sqlb.NewDelete(s.a.cfg.Dialect).From(TableVerification).Where(sqlb.In(VerificationIdentifier, identifiers...)))
	return err
}

// Sweep implements VerificationStore.
func (s sqlVerificationStore) Sweep(ctx context.Context, cutoff time.Time) (int64, error) {
	return s.a.Exec(ctx, sqlb.NewDelete(s.a.cfg.Dialect).From(TableVerification).Where(sqlb.Or(
		sqlb.Less(VerificationExpiresAt, cutoff),
		sqlb.Less(VerificationConsumedAt, &cutoff),
	)))
}

// GetAndDeleter is a SecondaryStorage that can read and delete one key in a
// single atomic step, as Redis GETDEL does. It is what makes a verification
// token in a key-value store single-use: a Get then a Delete would let two
// requests both read the token before either deleted it.
//
//ds:def id=core-getanddeleter-5wq8nk2m owner=@khanakia stability=stable
type GetAndDeleter interface {
	SecondaryStorage
	// GetAndDelete returns the value under key and removes it, atomically;
	// false when there is none or it expired.
	GetAndDelete(ctx context.Context, key string) (string, bool, error)
}

// Key layout of the storage-backed verification store. The token part is
// the hex SHA-256 of the token and the identifier part the hex SHA-256 of
// the identifier, so no token and no email address or user id appears in a
// key.
const (
	storageVerificationKey   = "auth:verification:"
	storagePurposeCutoffKey  = "auth:verification-cutoff:"
	storageIdentCutoffKey    = "auth:verification-id-cutoff:"
	storageVerificationSep   = ":"
	errVerificationStoredFmt = "auth: stored verification: %w"
)

// MinVerificationCutoffTTL is the shortest life of a revocation cutoff
// (ConsumeAll, DeleteIdentifiers) in a key-value verification store: seven
// days, beyond the longest token lifetime the library issues by default
// (a 24-hour email verification). A cutoff must outlive every token issued
// before it, because once it expires those tokens would be accepted again;
// the store also stretches it to the longest lifetime it has itself issued.
//
//ds:def id=core-minverificationcutoffttl-5kq8wn3d owner=@khanakia stability=stable
const MinVerificationCutoffTTL = 7 * 24 * time.Hour

// storageVerificationStore keeps verification tokens in a key-value store:
// each record as JSON under its purpose and token hash, expiring with the
// token. A KV store cannot be asked "every token of this identifier", so
// ConsumeAll and DeleteIdentifiers write a cutoff instant instead, one per
// purpose and identifier and one per identifier, and Consume refuses a
// record created at or before a cutoff that applies to it.
//
// A cutoff expires (it would otherwise grow the store forever), and its TTL
// is no shorter than the longest-lived token it can guard: the larger of
// MinVerificationCutoffTTL and the longest lifetime this store has issued.
// Every token created before the cutoff has expired by the time the cutoff
// does, so nothing comes back. The one case that TTL cannot cover is a token
// issued by another process with a lifetime longer than both, which no
// plugin's default reaches. Cutoffs compare the core's clock across
// instances, so clock skew between instances shifts the line by the skew.
type storageVerificationStore struct {
	kv GetAndDeleter
	// longest is the longest token lifetime Insert has seen, in
	// nanoseconds; it stretches the cutoff TTL past
	// MinVerificationCutoffTTL.
	longest *atomic.Int64
}

// NewStorageVerificationStore returns a VerificationStore over kv; see
// storageVerificationStore for the layout. Pass it to WithVerificationStore.
//
//ds:def id=core-newstorageverificationstore-9dk4wq7n owner=@khanakia stability=stable
func NewStorageVerificationStore(kv GetAndDeleter) VerificationStore {
	return storageVerificationStore{kv: kv, longest: new(atomic.Int64)}
}

// OptionErr passes on the storage's own option errors (OptionChecker), so a
// store built with a nil option still fails New after this wrapper hides it.
func (v storageVerificationStore) OptionErr() error { return optionErrOf(v.kv) }

// NewMemoryVerificationStore returns a VerificationStore in this process's
// memory, on the given clock (nil: time.Now), for tests and single-process
// apps.
//
//ds:def id=core-newmemoryverificationstore-3nw7kq2d owner=@khanakia stability=stable
func NewMemoryVerificationStore(now func() time.Time) VerificationStore {
	if now == nil {
		now = time.Now
	}
	return NewStorageVerificationStore(&memoryStorage{now: now, vals: map[string]memoryValue{}})
}

// hashedKey is the hex SHA-256 of a value that must not appear in a key.
func hashedKey(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

func verificationKey(purpose Purpose, tokenHash []byte) string {
	return storageVerificationKey + string(purpose) + storageVerificationSep + hex.EncodeToString(tokenHash)
}

func purposeCutoffKey(purpose Purpose, identifier string) string {
	return storagePurposeCutoffKey + string(purpose) + storageVerificationSep + hashedKey(identifier)
}

func identCutoffKey(identifier string) string {
	return storageIdentCutoffKey + hashedKey(identifier)
}

// cutoffTTL is how long a cutoff written now must live; see
// storageVerificationStore.
func (s storageVerificationStore) cutoffTTL() time.Duration {
	return max(MinVerificationCutoffTTL, time.Duration(s.longest.Load()))
}

// setCutoff writes now as the cutoff under key.
func (s storageVerificationStore) setCutoff(ctx context.Context, key string, now time.Time) error {
	return s.kv.Set(ctx, key, strconv.FormatInt(now.UnixMicro(), 10), s.cutoffTTL())
}

// revoked reports whether a cutoff under key is at or after created.
func (s storageVerificationStore) revoked(ctx context.Context, key string, created time.Time) (bool, error) {
	raw, ok, err := s.kv.Get(ctx, key)
	if err != nil || !ok {
		return false, err
	}
	micros, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return false, fmt.Errorf(errVerificationStoredFmt, err)
	}
	return !created.After(time.UnixMicro(micros)), nil
}

// Insert implements VerificationStore. The record lives until the token
// expires, measured on the token's own times, never this process's clock.
func (s storageVerificationStore) Insert(ctx context.Context, v Verification, tokenHash []byte) error {
	life := max(v.ExpiresAt.Sub(v.CreatedAt), time.Second)
	for {
		cur := s.longest.Load()
		if int64(life) <= cur || s.longest.CompareAndSwap(cur, int64(life)) {
			break
		}
	}
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	key := verificationKey(v.Purpose, tokenHash)
	if nx, ok := s.kv.(SetIfAbsenter); ok {
		stored, err := nx.SetIfAbsent(ctx, key, string(body), life)
		if err == nil && !stored {
			return ErrTokenExists
		}
		return err
	}
	return s.kv.Set(ctx, key, string(body), life)
}

// RefusesDuplicateTokens implements ExclusiveVerificationStore: true when the
// storage can set a key only if it is absent. The key holds the purpose, so
// the promise is per purpose here, which is all a claim needs. A spent record
// is deleted by Consume, so its hash can be stored again; a claim is never
// consumed.
func (s storageVerificationStore) RefusesDuplicateTokens() bool {
	_, ok := s.kv.(SetIfAbsenter)
	return ok
}

// Consume implements VerificationStore: GetAndDelete makes it single-use,
// and the purpose in the key makes a wrong-purpose attempt a miss that
// spends nothing.
func (s storageVerificationStore) Consume(ctx context.Context, purpose Purpose, tokenHash []byte, now time.Time) (Verification, error) {
	raw, ok, err := s.kv.GetAndDelete(ctx, verificationKey(purpose, tokenHash))
	if err != nil {
		return Verification{}, fmt.Errorf("auth: consume verification: %w", err)
	}
	if !ok {
		return Verification{}, ErrTokenInvalid
	}
	var v Verification
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return Verification{}, fmt.Errorf(errVerificationStoredFmt, err)
	}
	if !v.ExpiresAt.After(now) {
		return Verification{}, ErrTokenInvalid
	}
	for _, key := range []string{purposeCutoffKey(purpose, v.Identifier), identCutoffKey(v.Identifier)} {
		gone, err := s.revoked(ctx, key, v.CreatedAt)
		if err != nil {
			return Verification{}, err
		}
		if gone {
			return Verification{}, ErrTokenInvalid
		}
	}
	v.ConsumedAt = &now
	return v, nil
}

// ConsumeAll implements VerificationStore.
func (s storageVerificationStore) ConsumeAll(ctx context.Context, purpose Purpose, identifier string, now time.Time) error {
	return s.setCutoff(ctx, purposeCutoffKey(purpose, identifier), now)
}

// DeleteIdentifiers implements VerificationStore.
func (s storageVerificationStore) DeleteIdentifiers(ctx context.Context, identifiers []string, now time.Time) error {
	var errs []error
	for _, id := range identifiers {
		if err := s.setCutoff(ctx, identCutoffKey(id), now); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Sweep implements VerificationStore: every record and cutoff expires by
// itself.
func (storageVerificationStore) Sweep(context.Context, time.Time) (int64, error) { return 0, nil }

// SetIfAbsent implements SetIfAbsenter.
func (m *memoryStorage) SetIfAbsent(_ context.Context, key, value string, ttl time.Duration) (bool, error) {
	if ttl < 0 {
		return false, errNegativeTTL
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.get(key); ok {
		return false, nil
	}
	v := memoryValue{v: value}
	if ttl > 0 {
		v.exp = m.now().Add(ttl)
	}
	m.vals[key] = v
	return true, nil
}

// GetAndDelete implements GetAndDeleter.
func (m *memoryStorage) GetAndDelete(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.get(key)
	delete(m.vals, key)
	return v.v, ok, nil
}
