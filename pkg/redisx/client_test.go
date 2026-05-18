package redisx

import (
	"context"
	"testing"
	"time"
)

func TestKeyBuilderBuildsServicePrefixedKeys(t *testing.T) {
	builder, err := NewKeyBuilder("authlimit")
	if err != nil {
		t.Fatalf("NewKeyBuilder() error = %v", err)
	}

	key, err := builder.Build("jwt", "access", "token001")
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if key != "authlimit:jwt:access:token001" {
		t.Fatalf("key = %q", key)
	}
}

func TestKeyBuilderRejectsInvalidServiceCodeAndParts(t *testing.T) {
	if _, err := NewKeyBuilder("AuthLimit"); err == nil {
		t.Fatal("NewKeyBuilder() expected invalid service code error")
	}

	builder, err := NewKeyBuilder("authlimit")
	if err != nil {
		t.Fatalf("NewKeyBuilder() error = %v", err)
	}
	if _, err := builder.Build("jwt:access"); err == nil {
		t.Fatal("Build() expected invalid part error")
	}
}

func TestSafeClientRejectsCrossServiceKeys(t *testing.T) {
	builder, err := NewKeyBuilder("authlimit")
	if err != nil {
		t.Fatalf("NewKeyBuilder() error = %v", err)
	}
	client := NewSafeClient(builder, &fakeExecutor{})

	if _, err := client.Get(context.Background(), "other:jwt:access:id"); err == nil {
		t.Fatal("Get() expected cross service key error")
	}
	if _, err := client.Eval(context.Background(), "return 1", []string{"authlimit:ok:1", "other:bad:1"}); err == nil {
		t.Fatal("Eval() expected cross service key error")
	}
}

func TestSafeClientAllowsCurrentServiceKeys(t *testing.T) {
	builder, err := NewKeyBuilder("authlimit")
	if err != nil {
		t.Fatalf("NewKeyBuilder() error = %v", err)
	}
	exec := &fakeExecutor{}
	client := NewSafeClient(builder, exec)

	key := builder.MustBuild("jwt", "access", "id")
	if err := client.Set(context.Background(), key, "ok", time.Minute); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if exec.lastKey != key {
		t.Fatalf("last key = %q", exec.lastKey)
	}
	if err := client.DeleteCurrentServiceKeys(context.Background()); err != nil {
		t.Fatalf("DeleteCurrentServiceKeys() error = %v", err)
	}
	if exec.deletedPrefix != "authlimit:" {
		t.Fatalf("deleted prefix = %q", exec.deletedPrefix)
	}
}

type fakeExecutor struct {
	lastKey       string
	deletedPrefix string
}

func (f *fakeExecutor) Get(_ context.Context, key string) (string, error) {
	f.lastKey = key
	return "", nil
}

func (f *fakeExecutor) Set(_ context.Context, key string, _ string, _ time.Duration) error {
	f.lastKey = key
	return nil
}

func (f *fakeExecutor) Del(_ context.Context, keys ...string) error {
	if len(keys) > 0 {
		f.lastKey = keys[0]
	}
	return nil
}

func (f *fakeExecutor) Exists(_ context.Context, key string) (bool, error) {
	f.lastKey = key
	return true, nil
}

func (f *fakeExecutor) Expire(_ context.Context, key string, _ time.Duration) error {
	f.lastKey = key
	return nil
}

func (f *fakeExecutor) Incr(_ context.Context, key string) (int64, error) {
	f.lastKey = key
	return 1, nil
}

func (f *fakeExecutor) IncrBy(_ context.Context, key string, value int64) (int64, error) {
	f.lastKey = key
	return value, nil
}

func (f *fakeExecutor) HGet(_ context.Context, key string, _ string) (string, error) {
	f.lastKey = key
	return "", nil
}

func (f *fakeExecutor) HSet(_ context.Context, key string, _ string, _ string) error {
	f.lastKey = key
	return nil
}

func (f *fakeExecutor) SAdd(_ context.Context, key string, _ ...string) error {
	f.lastKey = key
	return nil
}

func (f *fakeExecutor) SMembers(_ context.Context, key string) ([]string, error) {
	f.lastKey = key
	return nil, nil
}

func (f *fakeExecutor) Eval(_ context.Context, _ string, keys []string, _ ...string) (any, error) {
	if len(keys) > 0 {
		f.lastKey = keys[0]
	}
	return nil, nil
}

func (f *fakeExecutor) EvalSha(_ context.Context, _ string, keys []string, _ ...string) (any, error) {
	if len(keys) > 0 {
		f.lastKey = keys[0]
	}
	return nil, nil
}

func (f *fakeExecutor) DeleteByPrefix(_ context.Context, prefix string) error {
	f.deletedPrefix = prefix
	return nil
}
