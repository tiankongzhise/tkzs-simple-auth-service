package limiter

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/redisx"
)

var ErrInvalidInput = errors.New("invalid limit input")

const tokenBucketScript = `
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local requested = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])
local bucket = redis.call("HMGET", key, "tokens", "updated")
local tokens = tonumber(bucket[1])
local updated = tonumber(bucket[2])
if tokens == nil then
  tokens = capacity
  updated = now
end
local delta = math.max(0, now - updated) / 1000
tokens = math.min(capacity, tokens + delta * rate)
local allowed = 0
if tokens >= requested then
  allowed = 1
  tokens = tokens - requested
end
redis.call("HSET", key, "tokens", tokens, "updated", now)
redis.call("EXPIRE", key, ttl)
local reset = now
if tokens < requested then
  reset = now + math.ceil(((requested - tokens) / rate) * 1000)
end
return {allowed, math.floor(tokens), reset}
`

type Cache interface {
	KeyBuilder() *redisx.KeyBuilder
	Eval(ctx context.Context, script string, keys []string, args ...string) (any, error)
}

type Service struct {
	cfg      *config.Config
	cache    Cache
	now      func() time.Time
	fallback *localLimiter
}

type VerifyInput struct {
	ServiceID string
	Path      string
	Method    string
	IP        string
	UserID    string
	AppID     string
}

type VerifyResult struct {
	Allowed   bool  `json:"allowed"`
	Remaining int   `json:"remaining"`
	ResetAt   int64 `json:"resetAt"`
}

func NewService(cfg *config.Config, cache Cache) *Service {
	return &Service{
		cfg:      cfg,
		cache:    cache,
		now:      time.Now,
		fallback: newLocalLimiter(cfg.Limit.LocalFallbackCapacity, cfg.Limit.LocalFallbackRatePerSecond),
	}
}

func (s *Service) SetNow(now func() time.Time) {
	s.now = now
}

func (s *Service) Verify(ctx context.Context, input VerifyInput) (*VerifyResult, error) {
	if input.ServiceID == "" {
		return nil, ErrInvalidInput
	}
	dimensions := s.dimensions(input)
	if len(dimensions) == 0 {
		return &VerifyResult{
			Allowed:   true,
			Remaining: s.cfg.Limit.DefaultCapacity,
			ResetAt:   s.now().Unix(),
		}, nil
	}
	results := make([]VerifyResult, 0, len(dimensions))
	for dimension, value := range dimensions {
		result, err := s.checkDimension(ctx, input.ServiceID, dimension, value)
		if err != nil {
			result = s.fallback.allow(input.ServiceID+":"+dimension+":"+value, s.now())
		}
		results = append(results, *result)
		if !result.Allowed {
			return result, nil
		}
	}
	return strictest(results), nil
}

func (s *Service) checkDimension(ctx context.Context, serviceID string, dimension string, value string) (*VerifyResult, error) {
	key, err := s.cache.KeyBuilder().Build("limit", "bucket", serviceID, dimension, value)
	if err != nil {
		return nil, err
	}
	nowMillis := s.now().UnixMilli()
	ttl := ttlSeconds(s.cfg.Limit.DefaultCapacity, s.cfg.Limit.DefaultRatePerSecond)
	raw, err := s.cache.Eval(
		ctx,
		tokenBucketScript,
		[]string{key},
		strconv.Itoa(s.cfg.Limit.DefaultCapacity),
		strconv.Itoa(s.cfg.Limit.DefaultRatePerSecond),
		strconv.FormatInt(nowMillis, 10),
		"1",
		strconv.Itoa(ttl),
	)
	if err != nil {
		return nil, err
	}
	return parseLuaResult(raw)
}

func (s *Service) dimensions(input VerifyInput) map[string]string {
	values := map[string]string{}
	for _, dimension := range s.cfg.Limit.Dimensions {
		switch dimension {
		case "ip":
			if input.IP != "" {
				values["ip"] = input.IP
			}
		case "user_id":
			if input.UserID != "" {
				values["user_id"] = input.UserID
			}
		case "app_id":
			if input.AppID != "" {
				values["app_id"] = input.AppID
			}
		case "path":
			if input.Path != "" {
				values["path"] = input.Path
			}
		}
	}
	return values
}

func parseLuaResult(raw any) (*VerifyResult, error) {
	values, ok := raw.([]any)
	if !ok || len(values) != 3 {
		return nil, fmt.Errorf("unexpected lua result %#v", raw)
	}
	allowed, err := toInt64(values[0])
	if err != nil {
		return nil, err
	}
	remaining, err := toInt64(values[1])
	if err != nil {
		return nil, err
	}
	resetMillis, err := toInt64(values[2])
	if err != nil {
		return nil, err
	}
	return &VerifyResult{
		Allowed:   allowed == 1,
		Remaining: int(remaining),
		ResetAt:   resetMillis / 1000,
	}, nil
}

func toInt64(value any) (int64, error) {
	switch typed := value.(type) {
	case int64:
		return typed, nil
	case int:
		return int64(typed), nil
	case string:
		return strconv.ParseInt(typed, 10, 64)
	default:
		return 0, fmt.Errorf("unexpected number type %T", value)
	}
}

func strictest(results []VerifyResult) *VerifyResult {
	if len(results) == 0 {
		return &VerifyResult{Allowed: true}
	}
	result := results[0]
	for _, item := range results[1:] {
		if item.Remaining < result.Remaining {
			result = item
		}
	}
	return &result
}

func ttlSeconds(capacity int, rate int) int {
	ttl := capacity / rate
	if ttl < 1 {
		return 1
	}
	return ttl * 2
}

type localLimiter struct {
	mu       sync.Mutex
	capacity int
	rate     int
	buckets  map[string]*localBucket
}

type localBucket struct {
	tokens  float64
	updated time.Time
}

func newLocalLimiter(capacity int, rate int) *localLimiter {
	return &localLimiter{capacity: capacity, rate: rate, buckets: map[string]*localBucket{}}
}

func (l *localLimiter) allow(key string, now time.Time) *VerifyResult {
	l.mu.Lock()
	defer l.mu.Unlock()
	bucket := l.buckets[key]
	if bucket == nil {
		bucket = &localBucket{tokens: float64(l.capacity), updated: now}
		l.buckets[key] = bucket
	}
	elapsed := now.Sub(bucket.updated).Seconds()
	if elapsed > 0 {
		bucket.tokens = minFloat(float64(l.capacity), bucket.tokens+elapsed*float64(l.rate))
		bucket.updated = now
	}
	allowed := false
	if bucket.tokens >= 1 {
		allowed = true
		bucket.tokens--
	}
	resetAt := now.Unix()
	if !allowed {
		resetAt = now.Add(time.Duration((1-bucket.tokens)/float64(l.rate)) * time.Second).Unix()
	}
	return &VerifyResult{Allowed: allowed, Remaining: int(bucket.tokens), ResetAt: resetAt}
}

func minFloat(a float64, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
