package redisrate

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/ubgo/auth"
)

// DefaultSessionKeyPrefix namespaces the session keys in a shared Redis.
const DefaultSessionKeyPrefix = "ubgo:auth:session:"

// Key segments under the prefix. A session lives in a Redis hash under its
// token hash, an id key maps a session id to that token hash (Touch and
// Delete know only the id), and a per-user set holds the user's session ids
// (List and DeleteUser).
const (
	segmentSession = "s:"
	segmentID      = "id:"
	segmentUser    = "u:"
	// segmentRotated holds a token hash a rotation replaced
	// (auth.SessionTokenRotator): its value is "<session id>|<grace end in
	// unix microseconds>", and it lives as long as the session did when it
	// was rotated.
	segmentRotated = "p:"
)

// Fields of the session hash. exp and seen are unix microseconds so Touch can
// compare and move them inside Redis without parsing JSON there; the rest of
// the session is JSON, written at Insert and rewritten only by SetData. reauth
// is Session.ReauthenticatedAt in unix microseconds, its own field so a
// re-authentication and a concurrent SetData never undo each other; absent
// until the first re-authentication, and then it wins over the JSON copy.
const (
	fieldExpires  = "exp"
	fieldLastSeen = "seen"
	fieldSession  = "s"
	fieldReauth   = "reauth"
	// fieldPrevious is the hex of the token hash the last rotation
	// replaced, so the next rotation can drop its key: only the latest
	// replaced token is found, as in SQL.
	fieldPrevious = "prev"
)

// rotatedSep separates the session id from the grace end in a rotated key.
const rotatedSep = "|"

// casScript moves a session's id key from the old token hash to the new
// one, only while it still names the old: the one atomic step that decides
// which of concurrent rotations wins. KEYS[1] is the id key; ARGV[1] the old
// hash, ARGV[2] the new, ARGV[3] the TTL in milliseconds. Returns 1 when it
// moved.
var casScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3])
return 1
`)

// reauthScript is SetReauthenticatedAt: set the field only on a hash that
// still exists, so an ended session is not brought back as a partial hash
// without a TTL. KEYS[1] is the session hash; ARGV[1] the time in unix
// microseconds.
var reauthScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
redis.call('HSET', KEYS[1], '` + fieldReauth + `', ARGV[1])
return 1
`)

// touchScript is Touch: move the expiry forward only when it is earlier, and
// re-arm the hash's TTL. It runs as one atomic step on the session hash, so
// of concurrent refreshes exactly one moves it. It names one key only, so it
// runs on a Redis Cluster, where the id key may live on another node; Touch
// re-arms that key's TTL in a second command. KEYS[1] is the session hash;
// ARGV[1] the new expiry and ARGV[2] the new last-seen, both unix
// microseconds; ARGV[3] the new TTL in milliseconds. Returns 1 when it moved.
var touchScript = redis.NewScript(`
local exp = redis.call('HGET', KEYS[1], '` + fieldExpires + `')
if not exp or tonumber(exp) >= tonumber(ARGV[1]) then return 0 end
redis.call('HSET', KEYS[1], '` + fieldExpires + `', ARGV[1], '` + fieldLastSeen + `', ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1
`)

// minTTL is the shortest life a session key gets. A store compares the
// instants the core gives it and never judges expiry by its own clock; the
// Redis TTL is only the cleanup, measured from this process's clock. When
// that clock is already past the expiry (a test with a fixed clock, a
// machine whose clock jumped), the key still leaves within a minute rather
// than at once, which would make a live session unfindable.
const minTTL = time.Minute

// SessionStore keeps sessions in Redis, expiring each with its session, for
// apps that want sessions off the database or shared by instances that share
// no database. It joins no transaction: a rolled-back sign-up can leave a
// session nobody holds the token of, and it expires by itself (see
// auth.SessionStore). Times are kept to the microsecond, as the SQL store
// keeps them. Every command names one key or a MULTI of keys, never a script
// over several, so it runs on a Redis Cluster, where the hash, id key and
// user set of one session may live on different nodes.
type SessionStore struct {
	optionErr
	client redis.Cmdable
	prefix string
	now    func() time.Time
}

var (
	_ auth.SessionStore        = (*SessionStore)(nil)
	_ auth.SessionReauthStore  = (*SessionStore)(nil)
	_ auth.SessionTokenRotator = (*SessionStore)(nil)
)

// NewSessionStore wraps a go-redis client. Pass it to auth.WithSessionStore.
//
//ds:def id=newsessionstore-kxwh5sna
func NewSessionStore(client redis.Cmdable, opts ...Option) *SessionStore {
	c := newConfig(DefaultSessionKeyPrefix, opts)
	return &SessionStore{optionErr: optionErr{c.optErrs.OptionErr()}, client: client, prefix: c.prefix, now: c.now}
}

// ttl is how long a key expiring at expiresAt lives from now, at least
// minTTL.
func (s *SessionStore) ttl(expiresAt time.Time) time.Duration {
	return max(expiresAt.Sub(s.now()), minTTL)
}

func (s *SessionStore) sessionKey(hash []byte) string {
	return s.prefix + segmentSession + hex.EncodeToString(hash)
}
func (s *SessionStore) idKey(id string) string       { return s.prefix + segmentID + id }
func (s *SessionStore) userKey(userID string) string { return s.prefix + segmentUser + userID }

// micros is the unix-microsecond text of t, the form the hash fields hold.
func micros(t time.Time) string { return strconv.FormatInt(t.UnixMicro(), 10) }

// Insert writes the hash, the id key and the user set member in one MULTI,
// so a session is never findable without being touchable or listable.
func (s *SessionStore) Insert(ctx context.Context, sess auth.Session, tokenHash []byte) error {
	// A Session is strings, times, bools and integers; encoding it cannot
	// fail.
	body, _ := json.Marshal(sess)
	skey, ikey, ttl := s.sessionKey(tokenHash), s.idKey(sess.ID), s.ttl(sess.ExpiresAt)
	_, err := s.client.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HSet(ctx, skey, fieldExpires, micros(sess.ExpiresAt), fieldLastSeen, micros(sess.LastSeenAt), fieldSession, body)
		p.PExpire(ctx, skey, ttl)
		p.Set(ctx, ikey, hex.EncodeToString(tokenHash), ttl)
		p.SAdd(ctx, s.userKey(sess.UserID), sess.ID)
		return nil
	})
	if err != nil {
		return fmt.Errorf("redisrate: insert session: %w", err)
	}
	return nil
}

// load reads one session hash. A missing key is auth.ErrSessionNotFound.
func (s *SessionStore) load(ctx context.Context, skey string) (auth.Session, error) {
	fields, err := s.client.HGetAll(ctx, skey).Result()
	if err != nil {
		return auth.Session{}, fmt.Errorf("redisrate: read session: %w", err)
	}
	return decodeSession(fields)
}

// decodeSession rebuilds a session from its hash: the JSON body, with the
// expiry and last-seen from their own fields, which Touch may have moved.
func decodeSession(fields map[string]string) (auth.Session, error) {
	body, ok := fields[fieldSession]
	if !ok {
		return auth.Session{}, auth.ErrSessionNotFound
	}
	var sess auth.Session
	if err := json.Unmarshal([]byte(body), &sess); err != nil {
		return auth.Session{}, fmt.Errorf("redisrate: decode session: %w", err)
	}
	exp, err := strconv.ParseInt(fields[fieldExpires], 10, 64)
	if err != nil {
		return auth.Session{}, fmt.Errorf("redisrate: decode session expiry: %w", err)
	}
	seen, err := strconv.ParseInt(fields[fieldLastSeen], 10, 64)
	if err != nil {
		return auth.Session{}, fmt.Errorf("redisrate: decode session last-seen: %w", err)
	}
	sess.ExpiresAt, sess.LastSeenAt = time.UnixMicro(exp).UTC(), time.UnixMicro(seen).UTC()
	if raw, ok := fields[fieldReauth]; ok {
		ra, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return auth.Session{}, fmt.Errorf("redisrate: decode session reauthentication: %w", err)
		}
		at := time.UnixMicro(ra).UTC()
		sess.ReauthenticatedAt = &at
	}
	return sess, nil
}

// Find returns the live session under tokenHash. Redis drops the key at its
// expiry, and the check against now covers the core's clock running ahead
// of Redis's.
func (s *SessionStore) Find(ctx context.Context, tokenHash []byte, now time.Time) (auth.Session, error) {
	sess, err := s.load(ctx, s.sessionKey(tokenHash))
	if err != nil {
		return auth.Session{}, err
	}
	if !sess.ExpiresAt.After(now) {
		return auth.Session{}, auth.ErrSessionNotFound
	}
	return sess, nil
}

// hashOf resolves a session id to its token hash, or "" when unknown.
func (s *SessionStore) hashOf(ctx context.Context, id string) (string, error) {
	h, err := s.client.Get(ctx, s.idKey(id)).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("redisrate: read session id: %w", err)
	}
	return h, nil
}

// Touch moves the expiry forward when it is earlier, atomically in Redis.
func (s *SessionStore) Touch(ctx context.Context, id string, expiresAt, lastSeenAt time.Time) (bool, error) {
	h, err := s.hashOf(ctx, id)
	if err != nil || h == "" {
		return false, err
	}
	ttl := s.ttl(expiresAt)
	n, err := touchScript.Run(ctx, s.client, []string{s.prefix + segmentSession + h}, micros(expiresAt), micros(lastSeenAt), ttl.Milliseconds()).Int()
	if err != nil {
		return false, fmt.Errorf("redisrate: touch session: %w", err)
	}
	if n != 1 {
		return false, nil
	}
	if err := s.client.PExpire(ctx, s.idKey(id), ttl).Err(); err != nil {
		return false, fmt.Errorf("redisrate: touch session id: %w", err)
	}
	return true, nil
}

// List returns the user's live, non-pending sessions, newest first. Ids
// whose session expired are pruned from the user's set on the way, which is
// the only upkeep the set gets.
func (s *SessionStore) List(ctx context.Context, userID string, now time.Time) ([]auth.Session, error) {
	ids, err := s.client.SMembers(ctx, s.userKey(userID)).Result()
	if err != nil {
		return nil, fmt.Errorf("redisrate: list sessions: %w", err)
	}
	var out []auth.Session
	var stale []any
	for _, id := range ids {
		sess, _, err := s.byID(ctx, id)
		if errors.Is(err, auth.ErrSessionNotFound) {
			stale = append(stale, id)
			continue
		}
		if err != nil {
			return nil, err
		}
		if sess.UserID == userID && sess.ExpiresAt.After(now) && !sess.SecondFactorPending {
			out = append(out, sess)
		}
	}
	if len(stale) > 0 {
		if err := s.client.SRem(ctx, s.userKey(userID), stale...).Err(); err != nil {
			return nil, fmt.Errorf("redisrate: prune sessions: %w", err)
		}
	}
	slices.SortFunc(out, func(x, y auth.Session) int {
		if c := y.CreatedAt.Compare(x.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(y.ID, x.ID)
	})
	return out, nil
}

// byID loads a session through its id key and returns its token hash too.
func (s *SessionStore) byID(ctx context.Context, id string) (auth.Session, string, error) {
	h, err := s.hashOf(ctx, id)
	if err != nil {
		return auth.Session{}, "", err
	}
	if h == "" {
		return auth.Session{}, "", auth.ErrSessionNotFound
	}
	sess, err := s.load(ctx, s.prefix+segmentSession+h)
	return sess, h, err
}

// Delete ends one session of userID; an id of another user, or an unknown
// one, changes nothing.
func (s *SessionStore) Delete(ctx context.Context, userID, id string) error {
	sess, h, err := s.byID(ctx, id)
	if errors.Is(err, auth.ErrSessionNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if sess.UserID != userID {
		return nil
	}
	_, err = s.client.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.Del(ctx, s.prefix+segmentSession+h)
		p.Del(ctx, s.idKey(sess.ID))
		p.SRem(ctx, s.userKey(sess.UserID), sess.ID)
		return nil
	})
	if err != nil {
		return fmt.Errorf("redisrate: delete session: %w", err)
	}
	return nil
}

// DeleteUser ends every session of userID but exceptID.
func (s *SessionStore) DeleteUser(ctx context.Context, userID, exceptID string) error {
	ids, err := s.client.SMembers(ctx, s.userKey(userID)).Result()
	if err != nil {
		return fmt.Errorf("redisrate: list sessions: %w", err)
	}
	for _, id := range ids {
		if id == exceptID {
			continue
		}
		if err := s.Delete(ctx, userID, id); err != nil {
			return err
		}
	}
	return nil
}

// Sweep has nothing to do: Redis expires every session key with its
// session, and List prunes the user sets.
func (*SessionStore) Sweep(context.Context, time.Time) (int64, error) { return 0, nil }

// SetData rewrites the session's JSON body with the new data. The expiry and
// last-seen fields are not touched, so a concurrent Touch and a SetData
// never undo each other; of two concurrent SetData calls the last wins, as
// in SQL. An unknown id changes nothing.
func (s *SessionStore) SetData(ctx context.Context, id string, data auth.AppData) error {
	sess, h, err := s.byID(ctx, id)
	if errors.Is(err, auth.ErrSessionNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	sess.Data = data
	// Strings, times, bools, integers and JSON that validate already
	// passed: encoding cannot fail.
	body, _ := json.Marshal(sess)
	if err := s.client.HSet(ctx, s.prefix+segmentSession+h, fieldSession, body).Err(); err != nil {
		return fmt.Errorf("redisrate: set session data: %w", err)
	}
	return nil
}

// SetReauthenticatedAt records a re-authentication in the session's reauth
// field, atomically and only while the session exists (auth.SessionReauthStore).
// An unknown id changes nothing.
func (s *SessionStore) SetReauthenticatedAt(ctx context.Context, id string, at time.Time) error {
	h, err := s.hashOf(ctx, id)
	if err != nil || h == "" {
		return err
	}
	if err := reauthScript.Run(ctx, s.client, []string{s.prefix + segmentSession + h}, micros(at)).Err(); err != nil {
		return fmt.Errorf("redisrate: set session reauthentication: %w", err)
	}
	return nil
}

// RotateToken moves the session to newHash (auth.SessionTokenRotator). The
// id key decides the race: a compare-and-set moves it from the old hash to
// the new, so of concurrent rotations one wins. The winner then writes the
// session under the new hash, records the old one under its rotated key and
// drops the old hash; when a Delete ended the session in between (its id key
// is gone), the new hash is dropped again rather than left as a session no
// id names.
func (s *SessionStore) RotateToken(ctx context.Context, id string, oldHash, newHash []byte, graceUntil, expiresAt, lastSeenAt time.Time) (bool, error) {
	oldHex, newHex := hex.EncodeToString(oldHash), hex.EncodeToString(newHash)
	fields, err := s.client.HGetAll(ctx, s.prefix+segmentSession+oldHex).Result()
	if err != nil {
		return false, fmt.Errorf("redisrate: read session: %w", err)
	}
	if _, ok := fields[fieldSession]; !ok {
		return false, nil
	}
	ttl := s.ttl(expiresAt)
	moved, err := casScript.Run(ctx, s.client, []string{s.idKey(id)}, oldHex, newHex, ttl.Milliseconds()).Int()
	if err != nil {
		return false, fmt.Errorf("redisrate: rotate session id: %w", err)
	}
	if moved != 1 {
		return false, nil
	}
	skey, rkey := s.prefix+segmentSession+newHex, s.prefix+segmentRotated+oldHex
	values := []any{fieldExpires, micros(expiresAt), fieldLastSeen, micros(lastSeenAt), fieldSession, fields[fieldSession], fieldPrevious, oldHex}
	if ra, ok := fields[fieldReauth]; ok {
		values = append(values, fieldReauth, ra)
	}
	_, err = s.client.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HSet(ctx, skey, values...)
		p.PExpire(ctx, skey, ttl)
		p.Set(ctx, rkey, id+rotatedSep+micros(graceUntil), ttl)
		p.Del(ctx, s.prefix+segmentSession+oldHex)
		if prev := fields[fieldPrevious]; prev != "" {
			p.Del(ctx, s.prefix+segmentRotated+prev)
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("redisrate: rotate session: %w", err)
	}
	if h, err := s.hashOf(ctx, id); err != nil || h != newHex {
		// Ended while it rotated: nothing may stay findable.
		if derr := s.client.Del(ctx, skey, rkey).Err(); derr != nil {
			return false, fmt.Errorf("redisrate: undo rotation of an ended session: %w", derr)
		}
		return false, err
	}
	return true, nil
}

// FindRotated returns the live session whose replaced token hash is
// tokenHash, with the end of that token's grace (auth.SessionTokenRotator).
func (s *SessionStore) FindRotated(ctx context.Context, tokenHash []byte, now time.Time) (auth.Session, time.Time, error) {
	raw, err := s.client.Get(ctx, s.prefix+segmentRotated+hex.EncodeToString(tokenHash)).Result()
	if errors.Is(err, redis.Nil) {
		return auth.Session{}, time.Time{}, auth.ErrSessionNotFound
	}
	if err != nil {
		return auth.Session{}, time.Time{}, fmt.Errorf("redisrate: read rotated token: %w", err)
	}
	id, until, ok := strings.Cut(raw, rotatedSep)
	grace, perr := strconv.ParseInt(until, 10, 64)
	if !ok || perr != nil {
		return auth.Session{}, time.Time{}, fmt.Errorf("redisrate: decode rotated token %q", raw)
	}
	sess, _, err := s.byID(ctx, id)
	if err != nil {
		return auth.Session{}, time.Time{}, err
	}
	if !sess.ExpiresAt.After(now) {
		return auth.Session{}, time.Time{}, auth.ErrSessionNotFound
	}
	return sess, time.UnixMicro(grace).UTC(), nil
}

// Clear deletes every session key under the store's prefix: every session,
// id index and user set. Every session ends at once, so it is for a test or
// a deliberate "sign everyone out"; see the package-level Clear.
func (s *SessionStore) Clear(ctx context.Context) error { return Clear(ctx, s.client, s.prefix) }
