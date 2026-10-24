package redisrate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/ubgo/auth"
)

// DefaultStorageKeyPrefix namespaces NewStorage's keys in a shared Redis.
//
//ds:def id=redis-defaultstoragekeyprefix-5kq2nw8d owner=@khanakia stability=stable
const DefaultStorageKeyPrefix = "ubgo:auth:kv:"

// Storage is an auth.SecondaryStorage on Redis: pass it to
// auth.WithSecondaryStorage and sessions and rate counters live in Redis.
// Increment is INCR and EXPIRE NX in one MULTI (Redis 7 or later), so a
// counter is never left without its expiry.
type Storage struct {
	optionErr
	client redis.Cmdable
	prefix string
}

var (
	_ auth.GetAndDeleter = (*Storage)(nil)
	_ auth.SetIfAbsenter = (*Storage)(nil)
)

// NewStorage wraps a go-redis client; KeyPrefix overrides
// DefaultStorageKeyPrefix. The store owns no connection.
func NewStorage(client redis.Cmdable, opts ...Option) *Storage {
	c := newConfig(DefaultStorageKeyPrefix, opts)
	return &Storage{optionErr: optionErr{c.optErrs.OptionErr()}, client: client, prefix: c.prefix}
}

// Get implements auth.SecondaryStorage: redis.Nil is a miss, any other
// failure an error.
func (s *Storage) Get(ctx context.Context, key string) (string, bool, error) {
	v, err := s.client.Get(ctx, s.prefix+key).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("redisrate: storage get: %w", err)
	}
	return v, true, nil
}

// Set implements auth.SecondaryStorage; a ttl of 0 keeps the key.
func (s *Storage) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if err := s.client.Set(ctx, s.prefix+key, value, ttl).Err(); err != nil {
		return fmt.Errorf("redisrate: storage set: %w", err)
	}
	return nil
}

// Delete implements auth.SecondaryStorage.
func (s *Storage) Delete(ctx context.Context, key string) error {
	if err := s.client.Del(ctx, s.prefix+key).Err(); err != nil {
		return fmt.Errorf("redisrate: storage delete: %w", err)
	}
	return nil
}

// SetIfAbsent implements auth.SetIfAbsenter with SET NX and the expiry in
// one command, so of two clients claiming one key exactly one stores it and
// the key is never left without its expiry. It is what makes the Redis
// verification store refuse a duplicate token, which plugin/oauth's
// ID-token replay guard relies on.
func (s *Storage) SetIfAbsent(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	ok, err := s.client.SetNX(ctx, s.prefix+key, value, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("redisrate: storage setnx: %w", err)
	}
	return ok, nil
}

// GetAndDelete implements auth.GetAndDeleter with GETDEL (Redis 6.2 or
// later): one command reads and removes the key, so of two clients spending
// one verification token exactly one gets the value. redis.Nil is a miss.
func (s *Storage) GetAndDelete(ctx context.Context, key string) (string, bool, error) {
	v, err := s.client.GetDel(ctx, s.prefix+key).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("redisrate: storage getdel: %w", err)
	}
	return v, true, nil
}

// Increment implements auth.SecondaryStorage: the expiry is set only by the
// increment that created the key, so the window is fixed.
func (s *Storage) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	k := s.prefix + key
	var incr *redis.IntCmd
	_, err := s.client.TxPipelined(ctx, func(p redis.Pipeliner) error {
		incr = p.Incr(ctx, k)
		if ttl > 0 {
			p.ExpireNX(ctx, k, ttl)
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("redisrate: storage increment: %w", err)
	}
	return incr.Val(), nil
}

// Clear deletes every key under the storage's prefix; see the package-level
// Clear.
func (s *Storage) Clear(ctx context.Context) error { return Clear(ctx, s.client, s.prefix) }

// DefaultVerificationKeyPrefix namespaces NewVerificationStore's keys in a
// shared Redis.
//
//ds:def id=redis-defaultverificationkeyprefix-8nw2kq4d owner=@khanakia stability=stable
const DefaultVerificationKeyPrefix = "ubgo:auth:verification:"

// NewVerificationStore keeps verification tokens (email and reset links,
// magic links, OAuth state, passkey ceremonies) in Redis: pass it to
// auth.WithVerificationStore. It is auth.NewStorageVerificationStore over a
// Storage with DefaultVerificationKeyPrefix (KeyPrefix overrides it), so a
// token is spent with GETDEL, exactly once, and every key carries the
// SHA-256 of the token and of the identifier, never either value. See
// auth.VerificationStore for what a store outside the database gives up.
func NewVerificationStore(client redis.Cmdable, opts ...Option) auth.VerificationStore {
	return auth.NewStorageVerificationStore(NewStorage(client, append([]Option{KeyPrefix(DefaultVerificationKeyPrefix)}, opts...)...))
}
