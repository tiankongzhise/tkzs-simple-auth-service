package limitrule

import (
	"context"
	"errors"
	"strings"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
)

var (
	ErrInvalidInput = errors.New("invalid limit rule input")
	ErrNotFound     = errors.New("limit rule not found")
	ErrForbidden    = errors.New("limit rule access forbidden")
	ErrConflict     = errors.New("limit rule already exists")
)

const (
	DimensionIP     = "ip"
	DimensionUserID = "user_id"
	DimensionAppID  = "app_id"
	DimensionPath   = "path"

	GranularitySecond = "second"
	GranularityMinute = "minute"
	GranularityHour   = "hour"
	GranularityDay    = "day"
)

type Store interface {
	Create(ctx context.Context, rule *model.RateLimitRule) error
	List(ctx context.Context, filter ListFilter) ([]model.RateLimitRule, error)
	FindByID(ctx context.Context, id string) (*model.RateLimitRule, error)
	Update(ctx context.Context, rule *model.RateLimitRule) error
	Delete(ctx context.Context, id string) error
	FindServiceByID(ctx context.Context, id string) (*model.Service, error)
	EnabledIdentityExists(ctx context.Context, serviceID string, dimension string, granularity string, excludeID string) (bool, error)
}

type Service struct {
	store Store
}

type Actor struct {
	UserID  string
	IsAdmin bool
}

type ListFilter struct {
	ServiceID   string
	OwnerUserID string
	Dimension   string
	Enabled     *bool
}

type CreateInput struct {
	ServiceID     string
	Dimension     string
	Granularity   string
	Capacity      int
	RatePerSecond int
	BlacklistHits int
	BlockSeconds  int
	Enabled       bool
}

type UpdateInput struct {
	ID            string
	Dimension     string
	Granularity   string
	Capacity      int
	RatePerSecond int
	BlacklistHits int
	BlockSeconds  int
	Enabled       bool
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

func (s *Service) Create(ctx context.Context, actor Actor, input CreateInput) (*model.RateLimitRule, error) {
	if actor.UserID == "" || !validRuleFields(input.Dimension, input.Granularity, input.Capacity, input.RatePerSecond, input.BlacklistHits, input.BlockSeconds) {
		return nil, ErrInvalidInput
	}
	service, err := s.store.FindServiceByID(ctx, strings.TrimSpace(input.ServiceID))
	if err != nil {
		return nil, err
	}
	if !canAccessService(actor, service) {
		return nil, ErrForbidden
	}
	if input.Enabled {
		exists, err := s.store.EnabledIdentityExists(ctx, service.ID, input.Dimension, input.Granularity, "")
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, ErrConflict
		}
	}
	rule := &model.RateLimitRule{
		ServiceID:     service.ID,
		Dimension:     input.Dimension,
		Granularity:   input.Granularity,
		Capacity:      input.Capacity,
		RatePerSecond: input.RatePerSecond,
		BlacklistHits: input.BlacklistHits,
		BlockSeconds:  input.BlockSeconds,
		Enabled:       input.Enabled,
		OwnerUserID:   service.OwnerUserID,
	}
	if err := s.store.Create(ctx, rule); err != nil {
		return nil, err
	}
	return rule, nil
}

func (s *Service) List(ctx context.Context, actor Actor, filter ListFilter) ([]model.RateLimitRule, error) {
	if actor.UserID == "" {
		return nil, ErrInvalidInput
	}
	if !actor.IsAdmin {
		filter.OwnerUserID = actor.UserID
	}
	return s.store.List(ctx, filter)
}

func (s *Service) ListEnabledRules(ctx context.Context, serviceID string) ([]model.RateLimitRule, error) {
	enabled := true
	return s.store.List(ctx, ListFilter{ServiceID: serviceID, Enabled: &enabled})
}

func (s *Service) Get(ctx context.Context, actor Actor, id string) (*model.RateLimitRule, error) {
	if actor.UserID == "" || strings.TrimSpace(id) == "" {
		return nil, ErrInvalidInput
	}
	rule, err := s.store.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if !canAccessRule(actor, rule) {
		return nil, ErrForbidden
	}
	return rule, nil
}

func (s *Service) Update(ctx context.Context, actor Actor, input UpdateInput) (*model.RateLimitRule, error) {
	if actor.UserID == "" || strings.TrimSpace(input.ID) == "" ||
		!validRuleFields(input.Dimension, input.Granularity, input.Capacity, input.RatePerSecond, input.BlacklistHits, input.BlockSeconds) {
		return nil, ErrInvalidInput
	}
	rule, err := s.store.FindByID(ctx, input.ID)
	if err != nil {
		return nil, err
	}
	if !canAccessRule(actor, rule) {
		return nil, ErrForbidden
	}
	if input.Enabled {
		exists, err := s.store.EnabledIdentityExists(ctx, rule.ServiceID, input.Dimension, input.Granularity, rule.ID)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, ErrConflict
		}
	}
	rule.Dimension = input.Dimension
	rule.Granularity = input.Granularity
	rule.Capacity = input.Capacity
	rule.RatePerSecond = input.RatePerSecond
	rule.BlacklistHits = input.BlacklistHits
	rule.BlockSeconds = input.BlockSeconds
	rule.Enabled = input.Enabled
	if err := s.store.Update(ctx, rule); err != nil {
		return nil, err
	}
	return rule, nil
}

func (s *Service) Delete(ctx context.Context, actor Actor, id string) error {
	if actor.UserID == "" || strings.TrimSpace(id) == "" {
		return ErrInvalidInput
	}
	rule, err := s.store.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if !canAccessRule(actor, rule) {
		return ErrForbidden
	}
	return s.store.Delete(ctx, id)
}

func canAccessService(actor Actor, service *model.Service) bool {
	return service != nil && actor.UserID != "" && (actor.IsAdmin || service.OwnerUserID == actor.UserID)
}

func canAccessRule(actor Actor, rule *model.RateLimitRule) bool {
	return rule != nil && actor.UserID != "" && (actor.IsAdmin || rule.OwnerUserID == actor.UserID)
}

func validRuleFields(dimension string, granularity string, capacity int, ratePerSecond int, blacklistHits int, blockSeconds int) bool {
	if !validDimension(strings.TrimSpace(dimension)) || !validGranularity(strings.TrimSpace(granularity)) {
		return false
	}
	return capacity > 0 && ratePerSecond > 0 && blacklistHits >= 0 && blockSeconds >= 0
}

func validDimension(dimension string) bool {
	switch dimension {
	case DimensionIP, DimensionUserID, DimensionAppID, DimensionPath:
		return true
	default:
		return false
	}
}

func validGranularity(granularity string) bool {
	switch granularity {
	case GranularitySecond, GranularityMinute, GranularityHour, GranularityDay:
		return true
	default:
		return false
	}
}
