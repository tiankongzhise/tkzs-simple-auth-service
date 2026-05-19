package limiter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/listing"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/redisx"
)

func TestVerifyUsesRedisTokenBucket(t *testing.T) {
	cache := newFakeCache(t)
	cache.result = []any{int64(1), int64(9), int64(1779091200000)}
	recorder := &fakeRecorder{}
	service := NewService(config.Default(), cache, WithRecorder(recorder))
	service.SetNow(func() time.Time { return time.Unix(1779091200, 0) })

	result, err := service.Verify(t.Context(), VerifyInput{
		ServiceID: "svc-001",
		IP:        "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !result.Allowed || result.Remaining != 9 {
		t.Fatalf("result = %#v", result)
	}
	if len(cache.keysPassed) != 1 || cache.keysPassed[0] != "authlimit:limit:bucket:svc-001:second:ip:127.0.0.1" {
		t.Fatalf("keys = %#v", cache.keysPassed)
	}
	if recorder.serviceID != "svc-001" || recorder.dimension != "ip" || recorder.key != "127.0.0.1" {
		t.Fatalf("recorder = %#v", recorder)
	}
}

func TestVerifyUsesDynamicRulesWhenConfigured(t *testing.T) {
	cfg := config.Default()
	cfg.Limit.DefaultCapacity = 100
	cache := newFakeCache(t)
	cache.result = []any{int64(1), int64(1), int64(1779091200000)}
	service := NewService(cfg, cache, WithRuleProvider(&fakeRuleProvider{rules: []model.RateLimitRule{
		{
			Dimension:     "ip",
			Granularity:   "minute",
			Capacity:      2,
			RatePerSecond: 1,
			Enabled:       true,
		},
	}}))
	service.SetNow(func() time.Time { return time.Unix(1779091200, 0) })

	result, err := service.Verify(t.Context(), VerifyInput{ServiceID: "svc-001", IP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Remaining != 1 {
		t.Fatalf("result = %#v", result)
	}
	if len(cache.keysPassed) != 1 || cache.keysPassed[0] != "authlimit:limit:bucket:svc-001:minute:ip:127.0.0.1" {
		t.Fatalf("keys = %#v", cache.keysPassed)
	}
	if cache.argsPassed[0] != "2" {
		t.Fatalf("args = %#v", cache.argsPassed)
	}
}

func TestVerifyFallsBackToDefaultRulesWhenNoDynamicRuleMatches(t *testing.T) {
	cfg := config.Default()
	cfg.Limit.Dimensions = []string{"ip"}
	cache := newFakeCache(t)
	cache.result = []any{int64(1), int64(99), int64(1779091200000)}
	service := NewService(cfg, cache, WithRuleProvider(&fakeRuleProvider{rules: []model.RateLimitRule{
		{
			Dimension:     "path",
			Granularity:   "minute",
			Capacity:      2,
			RatePerSecond: 1,
			Enabled:       true,
		},
	}}))
	service.SetNow(func() time.Time { return time.Unix(1779091200, 0) })

	result, err := service.Verify(t.Context(), VerifyInput{ServiceID: "svc-001", IP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Remaining != 99 {
		t.Fatalf("result = %#v", result)
	}
	if len(cache.keysPassed) != 1 || cache.keysPassed[0] != "authlimit:limit:bucket:svc-001:second:ip:127.0.0.1" {
		t.Fatalf("keys = %#v", cache.keysPassed)
	}
}

func TestVerifyRejectsWhenAnyDimensionLimited(t *testing.T) {
	cfg := config.Default()
	cfg.Limit.Dimensions = []string{"ip", "user_id"}
	cache := newFakeCache(t)
	cache.results = [][]any{
		{int64(1), int64(9), int64(1779091200000)},
		{int64(0), int64(0), int64(1779091210000)},
	}
	service := NewService(cfg, cache)
	service.SetNow(func() time.Time { return time.Unix(1779091200, 0) })

	result, err := service.Verify(t.Context(), VerifyInput{
		ServiceID: "svc-001",
		IP:        "127.0.0.1",
		UserID:    "user-001",
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Allowed || result.Remaining != 0 {
		t.Fatalf("result = %#v", result)
	}
}

func TestVerifyFallsBackToLocalLimiter(t *testing.T) {
	cfg := config.Default()
	cfg.Limit.LocalFallbackCapacity = 1
	cfg.Limit.LocalFallbackRatePerSecond = 1
	cache := newFakeCache(t)
	cache.err = errors.New("redis down")
	service := NewService(cfg, cache)
	now := time.Unix(1779091200, 0)
	service.SetNow(func() time.Time { return now })

	first, err := service.Verify(t.Context(), VerifyInput{ServiceID: "svc-001", IP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Verify() first error = %v", err)
	}
	second, err := service.Verify(t.Context(), VerifyInput{ServiceID: "svc-001", IP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Verify() second error = %v", err)
	}
	if !first.Allowed || second.Allowed {
		t.Fatalf("first = %#v, second = %#v", first, second)
	}
}

func TestVerifySkipsRateLimitWhenWhitelisted(t *testing.T) {
	cache := newFakeCache(t)
	service := NewService(config.Default(), cache, WithListChecker(&fakeListChecker{
		result: &listing.HitResult{Whitelisted: true},
	}))

	result, err := service.Verify(t.Context(), VerifyInput{ServiceID: "svc-001", IP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !result.Allowed || len(cache.keysPassed) != 0 {
		t.Fatalf("result = %#v, keys = %#v", result, cache.keysPassed)
	}
}

func TestVerifyRejectsBlacklistedSubject(t *testing.T) {
	service := NewService(config.Default(), newFakeCache(t), WithListChecker(&fakeListChecker{
		result: &listing.HitResult{Blacklisted: true},
	}))

	_, err := service.Verify(t.Context(), VerifyInput{ServiceID: "svc-001", IP: "127.0.0.1"})
	if !errors.Is(err, ErrBlacklisted) {
		t.Fatalf("Verify() error = %v", err)
	}
}

type fakeCache struct {
	keys       *redisx.KeyBuilder
	result     []any
	results    [][]any
	err        error
	keysPassed []string
	argsPassed []string
}

func newFakeCache(t *testing.T) *fakeCache {
	t.Helper()
	keys, err := redisx.NewKeyBuilder("authlimit")
	if err != nil {
		t.Fatalf("NewKeyBuilder() error = %v", err)
	}
	return &fakeCache{keys: keys}
}

func (c *fakeCache) KeyBuilder() *redisx.KeyBuilder {
	return c.keys
}

func (c *fakeCache) Eval(_ context.Context, _ string, keys []string, args ...string) (any, error) {
	if c.err != nil {
		return nil, c.err
	}
	c.keysPassed = append(c.keysPassed, keys...)
	c.argsPassed = append(c.argsPassed, args...)
	if len(c.results) > 0 {
		result := c.results[0]
		c.results = c.results[1:]
		return result, nil
	}
	return c.result, nil
}

type fakeRuleProvider struct {
	rules []model.RateLimitRule
	err   error
}

func (p *fakeRuleProvider) ListEnabledRules(_ context.Context, _ string) ([]model.RateLimitRule, error) {
	return p.rules, p.err
}

type fakeListChecker struct {
	result *listing.HitResult
	err    error
}

func (c *fakeListChecker) Check(_ context.Context, _ listing.HitInput) (*listing.HitResult, error) {
	return c.result, c.err
}

type fakeRecorder struct {
	serviceID string
	dimension string
	key       string
	allowed   bool
	remaining int
	resetAt   int64
}

func (r *fakeRecorder) RecordLimit(_ context.Context, serviceID string, dimension string, key string, allowed bool, remaining int, resetAt int64) error {
	r.serviceID = serviceID
	r.dimension = dimension
	r.key = key
	r.allowed = allowed
	r.remaining = remaining
	r.resetAt = resetAt
	return nil
}
