package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
)

func TestListLogsDefaultsToOperationAndPaginates(t *testing.T) {
	store := &fakeStore{operationLogs: []model.OperationLog{{ActorID: "user-001"}}}
	service := NewService(store)

	result, err := service.ListLogs(t.Context(), Actor{UserID: "user-001", IsAdmin: true}, LogFilter{})
	if err != nil {
		t.Fatalf("ListLogs() error = %v", err)
	}
	if result.Type != TypeOperation || result.Page != 1 || result.Size != 20 {
		t.Fatalf("result = %#v", result)
	}
	if store.lastFilter.Page != 1 || store.lastFilter.PageSize != 20 {
		t.Fatalf("filter = %#v", store.lastFilter)
	}
}

func TestListLogsRejectsInvalidType(t *testing.T) {
	service := NewService(&fakeStore{})

	_, err := service.ListLogs(t.Context(), Actor{UserID: "user-001"}, LogFilter{Type: "unknown"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("ListLogs() error = %v", err)
	}
}

func TestListLogsRestrictsNormalActor(t *testing.T) {
	store := &fakeStore{authLogs: []model.AuthLog{{SubjectID: "user-001"}}}
	service := NewService(store)

	_, err := service.ListLogs(t.Context(), Actor{UserID: "user-001"}, LogFilter{Type: TypeAuth})
	if err != nil {
		t.Fatalf("ListLogs() error = %v", err)
	}
	if store.lastFilter.SubjectID != "user-001" {
		t.Fatalf("filter = %#v", store.lastFilter)
	}
}

func TestListHealthChecksUsesHealthLogs(t *testing.T) {
	store := &fakeStore{healthLogs: []model.HealthCheckLog{{ServiceID: "svc-001"}}}
	service := NewService(store)

	items, err := service.ListHealthChecks(t.Context(), Actor{UserID: "admin", IsAdmin: true}, LogFilter{ServiceID: "svc-001"})
	if err != nil {
		t.Fatalf("ListHealthChecks() error = %v", err)
	}
	if len(items) != 1 || store.lastFilter.Type != "" || store.lastFilter.ServiceID != "svc-001" {
		t.Fatalf("items = %#v filter = %#v", items, store.lastFilter)
	}
}

type fakeStore struct {
	lastFilter    LogFilter
	operationLogs []model.OperationLog
	authLogs      []model.AuthLog
	limitLogs     []model.LimitLog
	healthLogs    []model.HealthCheckLog
}

func (s *fakeStore) ListOperationLogs(_ context.Context, filter LogFilter) ([]model.OperationLog, error) {
	s.lastFilter = filter
	return s.operationLogs, nil
}

func (s *fakeStore) ListAuthLogs(_ context.Context, filter LogFilter) ([]model.AuthLog, error) {
	s.lastFilter = filter
	return s.authLogs, nil
}

func (s *fakeStore) ListLimitLogs(_ context.Context, filter LogFilter) ([]model.LimitLog, error) {
	s.lastFilter = filter
	return s.limitLogs, nil
}

func (s *fakeStore) ListHealthLogs(_ context.Context, filter LogFilter) ([]model.HealthCheckLog, error) {
	s.lastFilter = filter
	return s.healthLogs, nil
}
