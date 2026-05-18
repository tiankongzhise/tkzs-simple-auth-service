package redisx

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

const deleteByPrefixBatchSize = 500

type redisCommander interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value any, expiration time.Duration) *redis.StatusCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
	Exists(ctx context.Context, keys ...string) *redis.IntCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
	Incr(ctx context.Context, key string) *redis.IntCmd
	IncrBy(ctx context.Context, key string, value int64) *redis.IntCmd
	HGet(ctx context.Context, key string, field string) *redis.StringCmd
	HSet(ctx context.Context, key string, values ...any) *redis.IntCmd
	SAdd(ctx context.Context, key string, members ...any) *redis.IntCmd
	SMembers(ctx context.Context, key string) *redis.StringSliceCmd
	Eval(ctx context.Context, script string, keys []string, args ...any) *redis.Cmd
	EvalSha(ctx context.Context, sha1 string, keys []string, args ...any) *redis.Cmd
	Scan(ctx context.Context, cursor uint64, match string, count int64) *redis.ScanCmd
}

type RedisExecutor struct {
	client redisCommander
}

func NewRedisExecutor(client *redis.Client) *RedisExecutor {
	return &RedisExecutor{client: client}
}

func NewRedisClient(opts RedisClientOptions) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:         opts.Addr,
		Username:     opts.Username,
		Password:     opts.Password,
		DB:           opts.DB,
		DialTimeout:  opts.DialTimeout,
		ReadTimeout:  opts.ReadTimeout,
		WriteTimeout: opts.WriteTimeout,
		PoolSize:     opts.PoolSize,
	})
}

type RedisClientOptions struct {
	Addr         string
	Username     string
	Password     string
	DB           int
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	PoolSize     int
}

func (e *RedisExecutor) Get(ctx context.Context, key string) (string, error) {
	value, err := e.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	return value, err
}

func (e *RedisExecutor) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	return e.client.Set(ctx, key, value, ttl).Err()
}

func (e *RedisExecutor) Del(ctx context.Context, keys ...string) error {
	return e.client.Del(ctx, keys...).Err()
}

func (e *RedisExecutor) Exists(ctx context.Context, key string) (bool, error) {
	count, err := e.client.Exists(ctx, key).Result()
	return count > 0, err
}

func (e *RedisExecutor) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return e.client.Expire(ctx, key, ttl).Err()
}

func (e *RedisExecutor) Incr(ctx context.Context, key string) (int64, error) {
	return e.client.Incr(ctx, key).Result()
}

func (e *RedisExecutor) IncrBy(ctx context.Context, key string, value int64) (int64, error) {
	return e.client.IncrBy(ctx, key, value).Result()
}

func (e *RedisExecutor) HGet(ctx context.Context, key string, field string) (string, error) {
	value, err := e.client.HGet(ctx, key, field).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	return value, err
}

func (e *RedisExecutor) HSet(ctx context.Context, key string, field string, value string) error {
	return e.client.HSet(ctx, key, field, value).Err()
}

func (e *RedisExecutor) SAdd(ctx context.Context, key string, members ...string) error {
	args := make([]any, 0, len(members))
	for _, member := range members {
		args = append(args, member)
	}
	return e.client.SAdd(ctx, key, args...).Err()
}

func (e *RedisExecutor) SMembers(ctx context.Context, key string) ([]string, error) {
	return e.client.SMembers(ctx, key).Result()
}

func (e *RedisExecutor) Eval(ctx context.Context, script string, keys []string, args ...string) (any, error) {
	return e.client.Eval(ctx, script, keys, stringsToAny(args)...).Result()
}

func (e *RedisExecutor) EvalSha(ctx context.Context, sha string, keys []string, args ...string) (any, error) {
	return e.client.EvalSha(ctx, sha, keys, stringsToAny(args)...).Result()
}

func (e *RedisExecutor) DeleteByPrefix(ctx context.Context, prefix string) error {
	var cursor uint64
	for {
		keys, nextCursor, err := e.client.Scan(ctx, cursor, prefix+"*", deleteByPrefixBatchSize).Result()
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			if err := e.client.Del(ctx, keys...).Err(); err != nil {
				return err
			}
		}
		if nextCursor == 0 {
			return nil
		}
		cursor = nextCursor
	}
}

func stringsToAny(values []string) []any {
	args := make([]any, 0, len(values))
	for _, value := range values {
		args = append(args, value)
	}
	return args
}
