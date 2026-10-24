package redisrate

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/ubgo/auth"
)

// DefaultRevocationKeyPrefix namespaces the revocation keys in a shared
// Redis.
const DefaultRevocationKeyPrefix = "ubgo:auth:revoked:"

// SessionRevocations is the revocation list of stateless sessions in Redis,
// shared by every instance, so a stateless session signed out on one is
// refused by all at once. One key per revoked session id (never the token or
// its hash) holds the instant the entry stops mattering, in unix
// microseconds; Revoked compares it with the core's clock, and the key's
// TTL, measured from this process's clock and at least a minute, is only the
// cleanup. A later revoke of the same id extends the entry and an earlier
// one never shortens it, in one atomic script on one key, so it runs on a
// Redis Cluster.
type SessionRevocations struct {
	optionErr
	client redis.Cmdable
	prefix string
	now    func() time.Time
}

var _ auth.SessionRevocations = (*SessionRevocations)(nil)

// NewSessionRevocations wraps a go-redis client. Pass it to
// auth.WithSessionRevocations.
//
//ds:def id=newsessionrevocations-8kq3vx5n
func NewSessionRevocations(client redis.Cmdable, opts ...Option) *SessionRevocations {
	c := newConfig(DefaultRevocationKeyPrefix, opts)
	return &SessionRevocations{optionErr: optionErr{c.optErrs.OptionErr()}, client: client, prefix: c.prefix, now: c.now}
}

// revokeScript is Revoke: keep the later of the stored and the given
// instant, and re-arm the TTL. KEYS[1] is the id key; ARGV[1] the instant in
// unix microseconds; ARGV[2] the TTL in milliseconds.
var revokeScript = redis.NewScript(`
local cur = redis.call('GET', KEYS[1])
if cur and tonumber(cur) >= tonumber(ARGV[1]) then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
return 1
`)

func (r *SessionRevocations) key(id string) string { return r.prefix + id }

// Revoke lists id until until.
func (r *SessionRevocations) Revoke(ctx context.Context, id string, until time.Time) error {
	ttl := max(until.Sub(r.now()), minTTL)
	if err := revokeScript.Run(ctx, r.client, []string{r.key(id)}, micros(until), ttl.Milliseconds()).Err(); err != nil {
		return fmt.Errorf("redisrate: revoke session: %w", err)
	}
	return nil
}

// Revoked reports whether id is listed and its entry still matters at now.
// A failure to read, or a value that is not an instant, is an error: the
// core then fails the request rather than let a revoked session in.
func (r *SessionRevocations) Revoked(ctx context.Context, id string, now time.Time) (bool, error) {
	v, err := r.client.Get(ctx, r.key(id)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("redisrate: read revocation: %w", err)
	}
	until, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return false, fmt.Errorf("redisrate: decode revocation: %w", err)
	}
	return now.Before(time.UnixMicro(until)), nil
}
