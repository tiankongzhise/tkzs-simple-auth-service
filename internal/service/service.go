package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/redisx"
)

var (
	ErrInvalidInput = errors.New("invalid service input")
	ErrNotFound     = errors.New("service not found")
	ErrForbidden    = errors.New("service access forbidden")
	ErrUnavailable  = errors.New("service dependency unavailable")
)

const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusOffline  = "offline"

	HealthHealthy   = "healthy"
	HealthUnhealthy = "unhealthy"
	HealthUnknown   = "unknown"
)

type Store interface {
	Create(ctx context.Context, service *model.Service) error
	List(ctx context.Context, filter ListFilter) ([]model.Service, error)
	FindByID(ctx context.Context, id string) (*model.Service, error)
	Update(ctx context.Context, service *model.Service) error
	Delete(ctx context.Context, id string) error
	ListDiscoverable(ctx context.Context) ([]model.Service, error)
}

type Cache interface {
	KeyBuilder() *redisx.KeyBuilder
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
}

type Service struct {
	cfg   *config.Config
	store Store
	cache Cache
	now   func() time.Time
}

type Actor struct {
	UserID  string
	IsAdmin bool
}

type ListFilter struct {
	OwnerUserID string
	Name        string
	Health      string
}

type CreateInput struct {
	Name                string
	Code                string
	BaseURL             string
	HealthPath          string
	HealthCheckInterval int
}

type UpdateInput struct {
	ID                  string
	Name                string
	BaseURL             string
	HealthPath          string
	HealthCheckInterval int
	Status              string
	HealthStatus        string
}

func NewService(cfg *config.Config, store Store, cache Cache) *Service {
	return &Service{cfg: cfg, store: store, cache: cache, now: time.Now}
}

func (s *Service) Create(ctx context.Context, actor Actor, input CreateInput) (*model.Service, error) {
	if actor.UserID == "" || !validCreate(input, s.cfg) {
		return nil, ErrInvalidInput
	}
	status := StatusPending
	approved := false
	var approvedBy *string
	var approvedAt *time.Time
	if actor.IsAdmin {
		status = StatusApproved
		approved = true
		approvedBy = &actor.UserID
		now := s.now().UTC()
		approvedAt = &now
	}
	record := &model.Service{
		Name:                strings.TrimSpace(input.Name),
		Code:                strings.TrimSpace(input.Code),
		OwnerUserID:         actor.UserID,
		BaseURL:             strings.TrimRight(strings.TrimSpace(input.BaseURL), "/"),
		HealthPath:          normalizeHealthPath(input.HealthPath, s.cfg.Health.DefaultPath),
		Status:              status,
		Approved:            approved,
		ApprovedBy:          approvedBy,
		ApprovedAt:          approvedAt,
		HealthStatus:        HealthUnknown,
		HealthCheckInterval: normalizedInterval(input.HealthCheckInterval, s.cfg),
	}
	if err := s.store.Create(ctx, record); err != nil {
		return nil, err
	}
	if approved {
		if err := s.SyncDiscovery(ctx); err != nil {
			return nil, err
		}
	}
	return record, nil
}

func (s *Service) List(ctx context.Context, actor Actor, filter ListFilter) ([]model.Service, error) {
	if actor.UserID == "" {
		return nil, ErrInvalidInput
	}
	if !actor.IsAdmin {
		filter.OwnerUserID = actor.UserID
	}
	return s.store.List(ctx, filter)
}

func (s *Service) Get(ctx context.Context, actor Actor, id string) (*model.Service, error) {
	record, err := s.store.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if !canAccess(actor, record) {
		return nil, ErrForbidden
	}
	return record, nil
}

func (s *Service) Update(ctx context.Context, actor Actor, input UpdateInput) (*model.Service, error) {
	if strings.TrimSpace(input.ID) == "" {
		return nil, ErrInvalidInput
	}
	record, err := s.store.FindByID(ctx, input.ID)
	if err != nil {
		return nil, err
	}
	if !canAccess(actor, record) {
		return nil, ErrForbidden
	}
	if strings.TrimSpace(input.Name) != "" {
		record.Name = strings.TrimSpace(input.Name)
	}
	if strings.TrimSpace(input.BaseURL) != "" {
		if !validURL(input.BaseURL) {
			return nil, ErrInvalidInput
		}
		record.BaseURL = strings.TrimRight(strings.TrimSpace(input.BaseURL), "/")
	}
	if strings.TrimSpace(input.HealthPath) != "" {
		record.HealthPath = normalizeHealthPath(input.HealthPath, s.cfg.Health.DefaultPath)
	}
	if input.HealthCheckInterval != 0 {
		if input.HealthCheckInterval < s.cfg.Health.MinIntervalSeconds || input.HealthCheckInterval > s.cfg.Health.MaxIntervalSeconds {
			return nil, ErrInvalidInput
		}
		record.HealthCheckInterval = input.HealthCheckInterval
	}
	if actor.IsAdmin && input.Status != "" {
		record.Status = input.Status
	}
	if actor.IsAdmin && input.HealthStatus != "" {
		record.HealthStatus = input.HealthStatus
	}
	if err := s.store.Update(ctx, record); err != nil {
		return nil, err
	}
	if err := s.SyncDiscovery(ctx); err != nil {
		return nil, err
	}
	return record, nil
}

func (s *Service) Delete(ctx context.Context, actor Actor, id string) error {
	record, err := s.store.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if !canAccess(actor, record) {
		return ErrForbidden
	}
	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}
	return s.SyncDiscovery(ctx)
}

func (s *Service) Approve(ctx context.Context, actor Actor, id string) (*model.Service, error) {
	if !actor.IsAdmin || actor.UserID == "" {
		return nil, ErrForbidden
	}
	record, err := s.store.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	record.Status = StatusApproved
	record.Approved = true
	record.ApprovedBy = &actor.UserID
	record.ApprovedAt = &now
	if err := s.store.Update(ctx, record); err != nil {
		return nil, err
	}
	if err := s.SyncDiscovery(ctx); err != nil {
		return nil, err
	}
	return record, nil
}

func (s *Service) Discover(ctx context.Context, name string, health string) ([]model.Service, error) {
	items, err := s.store.ListDiscoverable(ctx)
	if err != nil {
		return nil, err
	}
	filtered := make([]model.Service, 0, len(items))
	for _, item := range items {
		if name != "" && !strings.Contains(item.Name, name) {
			continue
		}
		if health != "" && item.HealthStatus != health {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered, nil
}

func (s *Service) SyncDiscovery(ctx context.Context) error {
	if s.cache == nil {
		return nil
	}
	items, err := s.store.ListDiscoverable(ctx)
	if err != nil {
		return err
	}
	data, err := json.Marshal(items)
	if err != nil {
		return err
	}
	key, err := s.cache.KeyBuilder().Build("service", "list")
	if err != nil {
		return err
	}
	if err := s.cache.Set(ctx, key, string(data), 0); err != nil {
		return ErrUnavailable
	}
	return nil
}

func canAccess(actor Actor, record *model.Service) bool {
	return record != nil && actor.UserID != "" && (actor.IsAdmin || record.OwnerUserID == actor.UserID)
}

func validCreate(input CreateInput, cfg *config.Config) bool {
	return strings.TrimSpace(input.Name) != "" &&
		strings.TrimSpace(input.Code) != "" &&
		validURL(input.BaseURL) &&
		normalizedInterval(input.HealthCheckInterval, cfg) > 0
}

func validURL(raw string) bool {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(raw))
	return err == nil && parsed.Scheme != "" && parsed.Host != ""
}

func normalizeHealthPath(path string, fallback string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		path = fallback
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func normalizedInterval(interval int, cfg *config.Config) int {
	if interval == 0 {
		return cfg.Health.DefaultIntervalSeconds
	}
	if interval < cfg.Health.MinIntervalSeconds || interval > cfg.Health.MaxIntervalSeconds {
		return 0
	}
	return interval
}
