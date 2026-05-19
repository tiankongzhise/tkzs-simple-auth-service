package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/redisx"
)

func TestAdminCreateAutoApprovesService(t *testing.T) {
	store := &fakeStore{}
	cache := newFakeServiceCache(t)
	service := NewService(config.Default(), store, cache)
	now := time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }

	result, err := service.Create(t.Context(), Actor{UserID: "admin", IsAdmin: true}, CreateInput{
		Name:    "orders",
		Code:    "orders",
		BaseURL: "http://orders.local:8080",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !result.Approved || result.Status != StatusApproved || result.ApprovedAt == nil {
		t.Fatalf("result = %#v", result)
	}
}

func TestNormalCreateNeedsApproval(t *testing.T) {
	store := &fakeStore{}
	service := NewService(config.Default(), store, nil)

	result, err := service.Create(t.Context(), Actor{UserID: "user-001"}, CreateInput{
		Name:    "orders",
		Code:    "orders",
		BaseURL: "http://orders.local:8080",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result.Approved || result.Status != StatusPending {
		t.Fatalf("result = %#v", result)
	}
}

func TestApproveSyncsDiscoveryList(t *testing.T) {
	store := &fakeStore{service: &model.Service{
		BaseModel:    model.BaseModel{ID: "svc-001"},
		Name:         "orders",
		Code:         "orders",
		OwnerUserID:  "user-001",
		BaseURL:      "http://orders.local:8080",
		HealthStatus: HealthHealthy,
	}}
	cache := newFakeServiceCache(t)
	service := NewService(config.Default(), store, cache)

	result, err := service.Approve(t.Context(), Actor{UserID: "admin", IsAdmin: true}, "svc-001")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if !result.Approved || result.Status != StatusApproved {
		t.Fatalf("result = %#v", result)
	}
	if !strings.Contains(cache.values["authlimit:service:list"], "orders") {
		t.Fatalf("service list cache = %#v", cache.values)
	}
}

func TestDiscoverFiltersHealthyApprovedServices(t *testing.T) {
	store := &fakeStore{discoverable: []model.Service{
		{Name: "orders", HealthStatus: HealthHealthy},
		{Name: "billing", HealthStatus: HealthHealthy},
	}}
	service := NewService(config.Default(), store, nil)

	items, err := service.Discover(t.Context(), "orders", HealthHealthy)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(items) != 1 || items[0].Name != "orders" {
		t.Fatalf("items = %#v", items)
	}
}

func TestUpdateHealthStatusSyncsDiscovery(t *testing.T) {
	store := &fakeStore{service: &model.Service{
		BaseModel:    model.BaseModel{ID: "svc-001"},
		Name:         "orders",
		Code:         "orders",
		OwnerUserID:  "user-001",
		BaseURL:      "http://orders.local:8080",
		Status:       StatusApproved,
		Approved:     true,
		HealthStatus: HealthUnknown,
	}}
	cache := newFakeServiceCache(t)
	service := NewService(config.Default(), store, cache)

	if err := service.UpdateHealthStatus(t.Context(), "svc-001", HealthHealthy); err != nil {
		t.Fatalf("UpdateHealthStatus() error = %v", err)
	}
	if store.service.HealthStatus != HealthHealthy {
		t.Fatalf("service = %#v", store.service)
	}
	if !strings.Contains(cache.values["authlimit:service:list"], "orders") {
		t.Fatalf("service list cache = %#v", cache.values)
	}
}

type fakeStore struct {
	service      *model.Service
	services     []model.Service
	discoverable []model.Service
	created      *model.Service
	updated      *model.Service
	deleted      string
}

func (s *fakeStore) Create(_ context.Context, service *model.Service) error {
	s.created = service
	s.service = service
	return nil
}

func (s *fakeStore) List(_ context.Context, filter ListFilter) ([]model.Service, error) {
	items := []model.Service{}
	for _, item := range s.services {
		if filter.OwnerUserID != "" && item.OwnerUserID != filter.OwnerUserID {
			continue
		}
		items = append(items, item)
	}
	return items, nil
}

func (s *fakeStore) FindByID(_ context.Context, id string) (*model.Service, error) {
	if s.service == nil || s.service.ID != id {
		return nil, ErrNotFound
	}
	return s.service, nil
}

func (s *fakeStore) Update(_ context.Context, service *model.Service) error {
	s.updated = service
	s.service = service
	return nil
}

func (s *fakeStore) Delete(_ context.Context, id string) error {
	s.deleted = id
	return nil
}

func (s *fakeStore) ListDiscoverable(_ context.Context) ([]model.Service, error) {
	if len(s.discoverable) > 0 {
		return s.discoverable, nil
	}
	if s.service != nil && s.service.Approved && s.service.Status == StatusApproved && s.service.HealthStatus == HealthHealthy {
		return []model.Service{*s.service}, nil
	}
	return nil, nil
}

func (s *fakeStore) ListHealthCheckTargets(_ context.Context) ([]model.Service, error) {
	return s.services, nil
}

func (s *fakeStore) CreateHealthCheckLog(_ context.Context, _ *model.HealthCheckLog) error {
	return nil
}

type fakeServiceCache struct {
	keys   *redisx.KeyBuilder
	values map[string]string
}

func newFakeServiceCache(t *testing.T) *fakeServiceCache {
	t.Helper()
	keys, err := redisx.NewKeyBuilder("authlimit")
	if err != nil {
		t.Fatalf("NewKeyBuilder() error = %v", err)
	}
	return &fakeServiceCache{keys: keys, values: map[string]string{}}
}

func (c *fakeServiceCache) KeyBuilder() *redisx.KeyBuilder {
	return c.keys
}

func (c *fakeServiceCache) Set(_ context.Context, key string, value string, _ time.Duration) error {
	c.values[key] = value
	return nil
}
