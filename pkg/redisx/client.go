package redisx

import (
	"context"
	"time"
)

type Executor interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Del(ctx context.Context, keys ...string) error
	Exists(ctx context.Context, key string) (bool, error)
	Expire(ctx context.Context, key string, ttl time.Duration) error
	Incr(ctx context.Context, key string) (int64, error)
	IncrBy(ctx context.Context, key string, value int64) (int64, error)
	HGet(ctx context.Context, key string, field string) (string, error)
	HSet(ctx context.Context, key string, field string, value string) error
	SAdd(ctx context.Context, key string, members ...string) error
	SMembers(ctx context.Context, key string) ([]string, error)
	Eval(ctx context.Context, script string, keys []string, args ...string) (any, error)
	EvalSha(ctx context.Context, sha string, keys []string, args ...string) (any, error)
	DeleteByPrefix(ctx context.Context, prefix string) error
}

type SafeClient struct {
	keys *KeyBuilder
	exec Executor
}

func NewSafeClient(keys *KeyBuilder, exec Executor) *SafeClient {
	return &SafeClient{keys: keys, exec: exec}
}

func (c *SafeClient) KeyBuilder() *KeyBuilder {
	return c.keys
}

func (c *SafeClient) Get(ctx context.Context, key string) (string, error) {
	if err := c.keys.Validate(key); err != nil {
		return "", err
	}
	return c.exec.Get(ctx, key)
}

func (c *SafeClient) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	if err := c.keys.Validate(key); err != nil {
		return err
	}
	return c.exec.Set(ctx, key, value, ttl)
}

func (c *SafeClient) Del(ctx context.Context, keys ...string) error {
	if err := c.keys.ValidateKeys(keys...); err != nil {
		return err
	}
	return c.exec.Del(ctx, keys...)
}

func (c *SafeClient) Exists(ctx context.Context, key string) (bool, error) {
	if err := c.keys.Validate(key); err != nil {
		return false, err
	}
	return c.exec.Exists(ctx, key)
}

func (c *SafeClient) Expire(ctx context.Context, key string, ttl time.Duration) error {
	if err := c.keys.Validate(key); err != nil {
		return err
	}
	return c.exec.Expire(ctx, key, ttl)
}

func (c *SafeClient) Incr(ctx context.Context, key string) (int64, error) {
	if err := c.keys.Validate(key); err != nil {
		return 0, err
	}
	return c.exec.Incr(ctx, key)
}

func (c *SafeClient) IncrBy(ctx context.Context, key string, value int64) (int64, error) {
	if err := c.keys.Validate(key); err != nil {
		return 0, err
	}
	return c.exec.IncrBy(ctx, key, value)
}

func (c *SafeClient) HGet(ctx context.Context, key string, field string) (string, error) {
	if err := c.keys.Validate(key); err != nil {
		return "", err
	}
	return c.exec.HGet(ctx, key, field)
}

func (c *SafeClient) HSet(ctx context.Context, key string, field string, value string) error {
	if err := c.keys.Validate(key); err != nil {
		return err
	}
	return c.exec.HSet(ctx, key, field, value)
}

func (c *SafeClient) SAdd(ctx context.Context, key string, members ...string) error {
	if err := c.keys.Validate(key); err != nil {
		return err
	}
	return c.exec.SAdd(ctx, key, members...)
}

func (c *SafeClient) SMembers(ctx context.Context, key string) ([]string, error) {
	if err := c.keys.Validate(key); err != nil {
		return nil, err
	}
	return c.exec.SMembers(ctx, key)
}

func (c *SafeClient) Eval(ctx context.Context, script string, keys []string, args ...string) (any, error) {
	if err := c.keys.ValidateKeys(keys...); err != nil {
		return nil, err
	}
	return c.exec.Eval(ctx, script, keys, args...)
}

func (c *SafeClient) EvalSha(ctx context.Context, sha string, keys []string, args ...string) (any, error) {
	if err := c.keys.ValidateKeys(keys...); err != nil {
		return nil, err
	}
	return c.exec.EvalSha(ctx, sha, keys, args...)
}

func (c *SafeClient) DeleteCurrentServiceKeys(ctx context.Context) error {
	return c.exec.DeleteByPrefix(ctx, c.keys.Prefix())
}
