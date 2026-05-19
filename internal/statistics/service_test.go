package statistics

import (
	"context"
	"testing"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
)

func TestRecordLimitCreatesLogAndMinuteBucket(t *testing.T) {
	store := &fakeStore{}
	service := NewService(store)
	now := time.Date(2026, 5, 19, 9, 1, 30, 0, time.UTC)
	service.now = func() time.Time { return now }

	err := service.RecordLimit(t.Context(), "svc-001", "ip", "127.0.0.1", false, 0, now.Unix())
	if err != nil {
		t.Fatalf("RecordLimit() error = %v", err)
	}
	if store.log.ServiceID != "svc-001" || store.log.Allowed {
		t.Fatalf("log = %#v", store.log)
	}
	if store.bucket != now.Truncate(time.Minute) {
		t.Fatalf("bucket = %s", store.bucket)
	}
}

func TestListLimitStatisticsNormalizesPage(t *testing.T) {
	store := &fakeStore{}
	service := NewService(store)

	_, err := service.ListLimitStatistics(t.Context(), LimitStatisticFilter{PageSize: 500})
	if err != nil {
		t.Fatalf("ListLimitStatistics() error = %v", err)
	}
	if store.filter.Page != 1 || store.filter.PageSize != 100 {
		t.Fatalf("filter = %#v", store.filter)
	}
}

type fakeStore struct {
	log    model.LimitLog
	bucket time.Time
	filter LimitStatisticFilter
}

func (s *fakeStore) RecordLimit(_ context.Context, log model.LimitLog, bucket time.Time) error {
	s.log = log
	s.bucket = bucket
	return nil
}

func (s *fakeStore) ListLimitStatistics(_ context.Context, filter LimitStatisticFilter) ([]model.LimitStatistic, error) {
	s.filter = filter
	return nil, nil
}
