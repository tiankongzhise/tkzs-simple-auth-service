package redisx

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestRedisExecutorConvertsNilResponses(t *testing.T) {
	exec := &RedisExecutor{client: &fakeRedisCommander{
		get:  redis.NewStringResult("", redis.Nil),
		hget: redis.NewStringResult("", redis.Nil),
	}}

	if value, err := exec.Get(context.Background(), "authlimit:key"); err != nil || value != "" {
		t.Fatalf("Get() value = %q, err = %v", value, err)
	}
	if value, err := exec.HGet(context.Background(), "authlimit:key", "field"); err != nil || value != "" {
		t.Fatalf("HGet() value = %q, err = %v", value, err)
	}
}

func TestRedisExecutorMapsCommands(t *testing.T) {
	commander := &fakeRedisCommander{
		get:      redis.NewStringResult("value", nil),
		set:      redis.NewStatusResult("OK", nil),
		del:      redis.NewIntResult(1, nil),
		exists:   redis.NewIntResult(1, nil),
		expire:   redis.NewBoolResult(true, nil),
		incr:     redis.NewIntResult(2, nil),
		incrBy:   redis.NewIntResult(7, nil),
		hget:     redis.NewStringResult("hash-value", nil),
		hset:     redis.NewIntResult(1, nil),
		sadd:     redis.NewIntResult(1, nil),
		smembers: redis.NewStringSliceResult([]string{"a", "b"}, nil),
		eval:     redis.NewCmdResult("eval-value", nil),
		evalSha:  redis.NewCmdResult("sha-value", nil),
	}
	exec := &RedisExecutor{client: commander}
	ctx := context.Background()

	if value, err := exec.Get(ctx, "authlimit:key"); err != nil || value != "value" {
		t.Fatalf("Get() value = %q, err = %v", value, err)
	}
	if err := exec.Set(ctx, "authlimit:key", "value", time.Minute); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if err := exec.Del(ctx, "authlimit:key"); err != nil {
		t.Fatalf("Del() error = %v", err)
	}
	if ok, err := exec.Exists(ctx, "authlimit:key"); err != nil || !ok {
		t.Fatalf("Exists() ok = %v, err = %v", ok, err)
	}
	if err := exec.Expire(ctx, "authlimit:key", time.Minute); err != nil {
		t.Fatalf("Expire() error = %v", err)
	}
	if value, err := exec.Incr(ctx, "authlimit:key"); err != nil || value != 2 {
		t.Fatalf("Incr() value = %d, err = %v", value, err)
	}
	if value, err := exec.IncrBy(ctx, "authlimit:key", 5); err != nil || value != 7 {
		t.Fatalf("IncrBy() value = %d, err = %v", value, err)
	}
	if value, err := exec.HGet(ctx, "authlimit:key", "field"); err != nil || value != "hash-value" {
		t.Fatalf("HGet() value = %q, err = %v", value, err)
	}
	if err := exec.HSet(ctx, "authlimit:key", "field", "hash-value"); err != nil {
		t.Fatalf("HSet() error = %v", err)
	}
	if err := exec.SAdd(ctx, "authlimit:set", "a", "b"); err != nil {
		t.Fatalf("SAdd() error = %v", err)
	}
	if members, err := exec.SMembers(ctx, "authlimit:set"); err != nil || len(members) != 2 {
		t.Fatalf("SMembers() members = %#v, err = %v", members, err)
	}
	if value, err := exec.Eval(ctx, "return ARGV[1]", []string{"authlimit:key"}, "arg"); err != nil || value != "eval-value" {
		t.Fatalf("Eval() value = %#v, err = %v", value, err)
	}
	if value, err := exec.EvalSha(ctx, "sha", []string{"authlimit:key"}, "arg"); err != nil || value != "sha-value" {
		t.Fatalf("EvalSha() value = %#v, err = %v", value, err)
	}

	if commander.lastSet.value != "value" || commander.lastSet.ttl != time.Minute {
		t.Fatalf("Set args = %#v", commander.lastSet)
	}
	if commander.lastIncrBy != 5 {
		t.Fatalf("IncrBy arg = %d", commander.lastIncrBy)
	}
	if len(commander.lastEvalArgs) != 1 || commander.lastEvalArgs[0] != "arg" {
		t.Fatalf("Eval args = %#v", commander.lastEvalArgs)
	}
}

func TestRedisExecutorDeleteByPrefixScansAndDeletesBatches(t *testing.T) {
	commander := &fakeRedisCommander{
		scans: []*redis.ScanCmd{
			redis.NewScanCmdResult([]string{"authlimit:a", "authlimit:b"}, 42, nil),
			redis.NewScanCmdResult([]string{"authlimit:c"}, 0, nil),
		},
		del: redis.NewIntResult(1, nil),
	}
	exec := &RedisExecutor{client: commander}

	if err := exec.DeleteByPrefix(context.Background(), "authlimit:"); err != nil {
		t.Fatalf("DeleteByPrefix() error = %v", err)
	}

	if len(commander.scanCalls) != 2 {
		t.Fatalf("scan calls = %#v", commander.scanCalls)
	}
	if commander.scanCalls[0].cursor != 0 || commander.scanCalls[0].match != "authlimit:*" {
		t.Fatalf("first scan = %#v", commander.scanCalls[0])
	}
	if commander.scanCalls[1].cursor != 42 {
		t.Fatalf("second scan cursor = %d", commander.scanCalls[1].cursor)
	}
	if len(commander.deletedKeys) != 3 {
		t.Fatalf("deleted keys = %#v", commander.deletedKeys)
	}
}

type fakeRedisCommander struct {
	get      *redis.StringCmd
	set      *redis.StatusCmd
	del      *redis.IntCmd
	exists   *redis.IntCmd
	expire   *redis.BoolCmd
	incr     *redis.IntCmd
	incrBy   *redis.IntCmd
	hget     *redis.StringCmd
	hset     *redis.IntCmd
	sadd     *redis.IntCmd
	smembers *redis.StringSliceCmd
	eval     *redis.Cmd
	evalSha  *redis.Cmd
	scans    []*redis.ScanCmd

	lastSet struct {
		key   string
		value any
		ttl   time.Duration
	}
	lastIncrBy   int64
	lastEvalArgs []any
	scanCalls    []scanCall
	deletedKeys  []string
}

type scanCall struct {
	cursor uint64
	match  string
	count  int64
}

func (f *fakeRedisCommander) Get(_ context.Context, _ string) *redis.StringCmd {
	return f.get
}

func (f *fakeRedisCommander) Set(_ context.Context, key string, value any, expiration time.Duration) *redis.StatusCmd {
	f.lastSet.key = key
	f.lastSet.value = value
	f.lastSet.ttl = expiration
	return f.set
}

func (f *fakeRedisCommander) Del(_ context.Context, keys ...string) *redis.IntCmd {
	f.deletedKeys = append(f.deletedKeys, keys...)
	return f.del
}

func (f *fakeRedisCommander) Exists(_ context.Context, _ ...string) *redis.IntCmd {
	return f.exists
}

func (f *fakeRedisCommander) Expire(_ context.Context, _ string, _ time.Duration) *redis.BoolCmd {
	return f.expire
}

func (f *fakeRedisCommander) Incr(_ context.Context, _ string) *redis.IntCmd {
	return f.incr
}

func (f *fakeRedisCommander) IncrBy(_ context.Context, _ string, value int64) *redis.IntCmd {
	f.lastIncrBy = value
	return f.incrBy
}

func (f *fakeRedisCommander) HGet(_ context.Context, _ string, _ string) *redis.StringCmd {
	return f.hget
}

func (f *fakeRedisCommander) HSet(_ context.Context, _ string, _ ...any) *redis.IntCmd {
	return f.hset
}

func (f *fakeRedisCommander) SAdd(_ context.Context, _ string, _ ...any) *redis.IntCmd {
	return f.sadd
}

func (f *fakeRedisCommander) SMembers(_ context.Context, _ string) *redis.StringSliceCmd {
	return f.smembers
}

func (f *fakeRedisCommander) Eval(_ context.Context, _ string, _ []string, args ...any) *redis.Cmd {
	f.lastEvalArgs = args
	return f.eval
}

func (f *fakeRedisCommander) EvalSha(_ context.Context, _ string, _ []string, _ ...any) *redis.Cmd {
	return f.evalSha
}

func (f *fakeRedisCommander) Scan(_ context.Context, cursor uint64, match string, count int64) *redis.ScanCmd {
	f.scanCalls = append(f.scanCalls, scanCall{cursor: cursor, match: match, count: count})
	if len(f.scans) == 0 {
		return redis.NewScanCmdResult(nil, 0, nil)
	}
	next := f.scans[0]
	f.scans = f.scans[1:]
	return next
}
