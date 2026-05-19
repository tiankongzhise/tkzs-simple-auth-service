package limiter

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/listing"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/metrics"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/redisx"
)

var (
	ErrInvalidInput = errors.New("invalid limit input")
	ErrBlacklisted  = errors.New("limit subject blacklisted")
)

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
	lists    ListChecker
	rules    RuleProvider
	recorder Recorder
	now      func() time.Time
	fallback *localLimiter
}

type ListChecker interface {
	Check(ctx context.Context, input listing.HitInput) (*listing.HitResult, error)
}

type Recorder interface {
	RecordLimit(ctx context.Context, serviceID string, dimension string, key string, allowed bool, remaining int, resetAt int64) error
}

type RuleProvider interface {
	ListEnabledRules(ctx context.Context, serviceID string) ([]model.RateLimitRule, error)
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

type Option func(*Service)

func WithListChecker(lists ListChecker) Option {
	return func(s *Service) {
		s.lists = lists
	}
}

func WithRuleProvider(rules RuleProvider) Option {
	return func(s *Service) {
		s.rules = rules
	}
}

func WithRecorder(recorder Recorder) Option {
	return func(s *Service) {
		s.recorder = recorder
	}
}

func NewService(cfg *config.Config, cache Cache, options ...Option) *Service {
	service := &Service{
		cfg:      cfg,
		cache:    cache,
		now:      time.Now,
		fallback: newLocalLimiter(),
	}
	for _, option := range options {
		option(service)
	}
	return service
}

func (s *Service) SetNow(now func() time.Time) {
	s.now = now
}

func (s *Service) Verify(ctx context.Context, input VerifyInput) (*VerifyResult, error) {
	if input.ServiceID == "" {
		return nil, ErrInvalidInput
	}
	if s.lists != nil {
		hit, err := s.lists.Check(ctx, listing.HitInput{
			ServiceID: input.ServiceID,
			IP:        input.IP,
			UserID:    input.UserID,
			AppID:     input.AppID,
		})
		if err != nil {
			return nil, err
		}
		if hit.Whitelisted {
			return &VerifyResult{Allowed: true, Remaining: s.cfg.Limit.DefaultCapacity, ResetAt: s.now().Unix()}, nil
		}
		if hit.Blacklisted {
			return nil, ErrBlacklisted
		}
	}
	checks, err := s.ruleChecks(ctx, input)
	if err != nil {
		return nil, err
	}
	if len(checks) == 0 {
		return &VerifyResult{
			Allowed:   true,
			Remaining: s.cfg.Limit.DefaultCapacity,
			ResetAt:   s.now().Unix(),
		}, nil
	}
	results := make([]VerifyResult, 0, len(checks))
	for _, check := range checks {
		result, err := s.checkDimension(ctx, input.ServiceID, check)
		if err != nil {
			result = s.fallback.allow(input.ServiceID+":"+check.Granularity+":"+check.Dimension+":"+check.Value, check.FallbackCapacity, check.FallbackRatePerSecond, s.now())
		}
		s.record(ctx, input.ServiceID, check.Dimension, check.Value, result)
		results = append(results, *result)
		if !result.Allowed {
			return result, nil
		}
	}
	return strictest(results), nil
}

func (s *Service) record(ctx context.Context, serviceID string, dimension string, value string, result *VerifyResult) {
	if result == nil {
		return
	}
	metrics.RecordLimit(serviceID, dimension, result.Allowed)
	if s.recorder == nil {
		return
	}
	_ = s.recorder.RecordLimit(ctx, serviceID, dimension, value, result.Allowed, result.Remaining, result.ResetAt)
}

func (s *Service) checkDimension(ctx context.Context, serviceID string, check ruleCheck) (*VerifyResult, error) {
	key, err := s.cache.KeyBuilder().Build("limit", "bucket", serviceID, check.Granularity, check.Dimension, check.Value)
	if err != nil {
		return nil, err
	}
	nowMillis := s.now().UnixMilli()
	ttl := ttlSeconds(check.Capacity, check.RatePerSecond)
	raw, err := s.cache.Eval(
		ctx,
		tokenBucketScript,
		[]string{key},
		strconv.Itoa(check.Capacity),
		strconv.Itoa(check.RatePerSecond),
		strconv.FormatInt(nowMillis, 10),
		"1",
		strconv.Itoa(ttl),
	)
	if err != nil {
		return nil, err
	}
	return parseLuaResult(raw)
}

type ruleCheck struct {
	Dimension             string
	Granularity           string
	Value                 string
	Capacity              int
	RatePerSecond         int
	FallbackCapacity      int
	FallbackRatePerSecond int
	BlacklistHits         int
	BlockSeconds          int
}

func (s *Service) ruleChecks(ctx context.Context, input VerifyInput) ([]ruleCheck, error) {
	values := s.dimensions(input)
	if len(values) == 0 {
		return nil, nil
	}
	if s.rules == nil {
		return s.defaultRuleChecks(values), nil
	}
	rules, err := s.rules.ListEnabledRules(ctx, input.ServiceID)
	if err != nil {
		return nil, err
	}
	checks := make([]ruleCheck, 0, len(rules))
	for _, rule := range rules {
		value := values[rule.Dimension]
		if value == "" {
			continue
		}
		checks = append(checks, ruleCheck{
			Dimension:             rule.Dimension,
			Granularity:           rule.Granularity,
			Value:                 value,
			Capacity:              rule.Capacity,
			RatePerSecond:         rule.RatePerSecond,
			FallbackCapacity:      rule.Capacity,
			FallbackRatePerSecond: rule.RatePerSecond,
			BlacklistHits:         rule.BlacklistHits,
			BlockSeconds:          rule.BlockSeconds,
		})
	}
	if len(checks) > 0 {
		return checks, nil
	}
	return s.defaultRuleChecks(values), nil
}

func (s *Service) defaultRuleChecks(values map[string]string) []ruleCheck {
	checks := make([]ruleCheck, 0, len(values))
	for _, dimension := range s.cfg.Limit.Dimensions {
		value := values[dimension]
		if value == "" {
			continue
		}
		checks = append(checks, ruleCheck{
			Dimension:             dimension,
			Granularity:           "second",
			Value:                 value,
			Capacity:              s.cfg.Limit.DefaultCapacity,
			RatePerSecond:         s.cfg.Limit.DefaultRatePerSecond,
			FallbackCapacity:      s.cfg.Limit.LocalFallbackCapacity,
			FallbackRatePerSecond: s.cfg.Limit.LocalFallbackRatePerSecond,
		})
	}
	return checks
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
	mu      sync.Mutex
	buckets map[string]*localBucket
}

type localBucket struct {
	tokens  float64
	updated time.Time
}

func newLocalLimiter() *localLimiter {
	return &localLimiter{buckets: map[string]*localBucket{}}
}

func (l *localLimiter) allow(key string, capacity int, rate int, now time.Time) *VerifyResult {
	l.mu.Lock()
	defer l.mu.Unlock()
	if capacity <= 0 {
		capacity = 1
	}
	if rate <= 0 {
		rate = 1
	}
	bucket := l.buckets[key]
	if bucket == nil {
		bucket = &localBucket{tokens: float64(capacity), updated: now}
		l.buckets[key] = bucket
	}
	elapsed := now.Sub(bucket.updated).Seconds()
	if elapsed > 0 {
		bucket.tokens = minFloat(float64(capacity), bucket.tokens+elapsed*float64(rate))
		bucket.updated = now
	}
	allowed := false
	if bucket.tokens >= 1 {
		allowed = true
		bucket.tokens--
	}
	resetAt := now.Unix()
	if !allowed {
		resetAt = now.Add(time.Duration((1-bucket.tokens)/float64(rate)) * time.Second).Unix()
	}
	return &VerifyResult{Allowed: allowed, Remaining: int(bucket.tokens), ResetAt: resetAt}
}

func minFloat(a float64, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
