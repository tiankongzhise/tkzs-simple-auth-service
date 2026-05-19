package limitrule

import (
	"context"
	"errors"
	"testing"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	servicesvc "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/service"
)

func TestCreateStoresOwnerAndRejectsDuplicateEnabledIdentity(t *testing.T) {
	store := &fakeStore{
		service: &model.Service{BaseModel: model.BaseModel{ID: "svc-001"}, OwnerUserID: "user-001"},
		exists:  true,
	}
	service := NewService(store)

	_, err := service.Create(t.Context(), Actor{UserID: "user-001"}, CreateInput{
		ServiceID:     "svc-001",
		Dimension:     DimensionIP,
		Granularity:   GranularityMinute,
		Capacity:      60,
		RatePerSecond: 1,
		Enabled:       true,
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Create() error = %v", err)
	}

	store.exists = false
	result, err := service.Create(t.Context(), Actor{UserID: "user-001"}, CreateInput{
		ServiceID:     "svc-001",
		Dimension:     DimensionIP,
		Granularity:   GranularityMinute,
		Capacity:      60,
		RatePerSecond: 1,
		Enabled:       true,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result.OwnerUserID != "user-001" || store.created == nil {
		t.Fatalf("result = %#v, created = %#v", result, store.created)
	}
}

func TestCreateRejectsForeignServiceForNonAdmin(t *testing.T) {
	service := NewService(&fakeStore{
		service: &model.Service{BaseModel: model.BaseModel{ID: "svc-001"}, OwnerUserID: "other-user"},
	})

	_, err := service.Create(t.Context(), Actor{UserID: "user-001"}, CreateInput{
		ServiceID:     "svc-001",
		Dimension:     DimensionIP,
		Granularity:   GranularityMinute,
		Capacity:      60,
		RatePerSecond: 1,
		Enabled:       true,
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("Create() error = %v", err)
	}
}

func TestListScopesNonAdminToOwnedRules(t *testing.T) {
	store := &fakeStore{}
	service := NewService(store)

	_, err := service.List(t.Context(), Actor{UserID: "user-001"}, ListFilter{ServiceID: "svc-001"})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if store.listFilter.OwnerUserID != "user-001" {
		t.Fatalf("filter = %#v", store.listFilter)
	}
}

func TestUpdateCanDisableDuplicateIdentity(t *testing.T) {
	store := &fakeStore{
		rule: &model.RateLimitRule{
			BaseModel:     model.BaseModel{ID: "rule-001"},
			ServiceID:     "svc-001",
			Dimension:     DimensionIP,
			Granularity:   GranularityMinute,
			Capacity:      60,
			RatePerSecond: 1,
			Enabled:       true,
			OwnerUserID:   "user-001",
		},
		exists: true,
	}
	service := NewService(store)

	result, err := service.Update(t.Context(), Actor{UserID: "user-001"}, UpdateInput{
		ID:            "rule-001",
		Dimension:     DimensionIP,
		Granularity:   GranularityMinute,
		Capacity:      100,
		RatePerSecond: 2,
		Enabled:       false,
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if result.Enabled || result.Capacity != 100 {
		t.Fatalf("result = %#v", result)
	}
}

type fakeStore struct {
	service    *model.Service
	rule       *model.RateLimitRule
	created    *model.RateLimitRule
	listFilter ListFilter
	exists     bool
}

func (s *fakeStore) Create(_ context.Context, rule *model.RateLimitRule) error {
	s.created = rule
	return nil
}

func (s *fakeStore) List(_ context.Context, filter ListFilter) ([]model.RateLimitRule, error) {
	s.listFilter = filter
	return nil, nil
}

func (s *fakeStore) FindByID(_ context.Context, _ string) (*model.RateLimitRule, error) {
	if s.rule == nil {
		return nil, ErrNotFound
	}
	return s.rule, nil
}

func (s *fakeStore) Update(_ context.Context, rule *model.RateLimitRule) error {
	s.rule = rule
	return nil
}

func (s *fakeStore) Delete(_ context.Context, _ string) error {
	return nil
}

func (s *fakeStore) FindServiceByID(_ context.Context, _ string) (*model.Service, error) {
	if s.service == nil {
		return nil, servicesvc.ErrNotFound
	}
	return s.service, nil
}

func (s *fakeStore) EnabledIdentityExists(_ context.Context, _ string, _ string, _ string, _ string) (bool, error) {
	return s.exists, nil
}
