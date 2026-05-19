package statistics

import (
	"context"
	"testing"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/listing"
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

func TestRecordLimitWithRuleCreatesTemporaryBlacklist(t *testing.T) {
	store := &fakeStore{blockedCount: 3}
	lists := &fakeBlacklistCreator{}
	audit := &fakeAuditRecorder{}
	service := NewService(store).WithBlacklistCreator(lists).WithAudit(audit)
	now := time.Date(2026, 5, 19, 9, 1, 30, 0, time.UTC)
	service.now = func() time.Time { return now }

	err := service.RecordLimitWithRule(t.Context(), "svc-001", "ip", "127.0.0.1", false, 0, now.Unix(), 3, 60)
	if err != nil {
		t.Fatalf("RecordLimitWithRule() error = %v", err)
	}
	if lists.input.Type != "ip" || lists.input.Key != "127.0.0.1" || lists.input.ExpiresAt == nil {
		t.Fatalf("blacklist input = %#v", lists.input)
	}
	if audit.log.Event != "limit_auto_blacklist" {
		t.Fatalf("audit log = %#v", audit.log)
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
	log          model.LimitLog
	bucket       time.Time
	filter       LimitStatisticFilter
	blockedCount int64
}

func (s *fakeStore) RecordLimit(_ context.Context, log model.LimitLog, bucket time.Time) error {
	s.log = log
	s.bucket = bucket
	return nil
}

func (s *fakeStore) CountBlockedSince(_ context.Context, _ string, _ string, _ string, _ time.Time) (int64, error) {
	return s.blockedCount, nil
}

func (s *fakeStore) ListLimitStatistics(_ context.Context, filter LimitStatisticFilter) ([]model.LimitStatistic, error) {
	s.filter = filter
	return nil, nil
}

type fakeBlacklistCreator struct {
	input listing.CreateInput
}

func (c *fakeBlacklistCreator) CreateTemporaryBlacklist(_ context.Context, input listing.CreateInput) (*model.Blacklist, error) {
	c.input = input
	return &model.Blacklist{ServiceID: input.ServiceID, Type: input.Type, Key: input.Key}, nil
}

type fakeAuditRecorder struct {
	log model.AuthLog
}

func (r *fakeAuditRecorder) RecordAuth(_ context.Context, log model.AuthLog) error {
	r.log = log
	return nil
}
