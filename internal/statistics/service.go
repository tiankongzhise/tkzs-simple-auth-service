package statistics

import (
	"context"
	"errors"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/listing"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
)

var ErrInvalidInput = errors.New("invalid statistics input")

type Store interface {
	RecordLimit(ctx context.Context, log model.LimitLog, bucket time.Time) error
	CountBlockedSince(ctx context.Context, serviceID string, dimension string, key string, since time.Time) (int64, error)
	ListLimitStatistics(ctx context.Context, filter LimitStatisticFilter) ([]model.LimitStatistic, error)
}

type TemporaryBlacklistCreator interface {
	CreateTemporaryBlacklist(ctx context.Context, input listing.CreateInput) (*model.Blacklist, error)
}

type AuditRecorder interface {
	RecordAuth(ctx context.Context, log model.AuthLog) error
}

type Service struct {
	store Store
	now   func() time.Time
	lists TemporaryBlacklistCreator
	audit AuditRecorder
}

type LimitStatisticFilter struct {
	ServiceID string
	Dimension string
	StartAt   *time.Time
	EndAt     *time.Time
	Page      int
	PageSize  int
}

func NewService(store Store) *Service {
	return &Service{store: store, now: time.Now}
}

func (s *Service) WithBlacklistCreator(lists TemporaryBlacklistCreator) *Service {
	s.lists = lists
	return s
}

func (s *Service) WithAudit(audit AuditRecorder) *Service {
	s.audit = audit
	return s
}

func (s *Service) RecordLimit(ctx context.Context, serviceID string, dimension string, key string, allowed bool, remaining int, resetAt int64) error {
	if serviceID == "" || dimension == "" || key == "" {
		return ErrInvalidInput
	}
	return s.store.RecordLimit(ctx, model.LimitLog{
		ServiceID: serviceID,
		Dimension: dimension,
		Key:       key,
		Allowed:   allowed,
		Remaining: remaining,
		ResetAt:   resetAt,
	}, s.now().UTC().Truncate(time.Minute))
}

func (s *Service) RecordLimitWithRule(ctx context.Context, serviceID string, dimension string, key string, allowed bool, remaining int, resetAt int64, blacklistHits int, blockSeconds int) error {
	if err := s.RecordLimit(ctx, serviceID, dimension, key, allowed, remaining, resetAt); err != nil {
		return err
	}
	if allowed || blacklistHits <= 0 || blockSeconds <= 0 || s.lists == nil {
		return nil
	}
	listType := listingTypeForDimension(dimension)
	if listType == "" {
		return nil
	}
	since := s.now().UTC().Add(-time.Duration(blockSeconds) * time.Second)
	count, err := s.store.CountBlockedSince(ctx, serviceID, dimension, key, since)
	if err != nil {
		return err
	}
	if count < int64(blacklistHits) {
		return nil
	}
	expiresAt := s.now().UTC().Add(time.Duration(blockSeconds) * time.Second)
	if _, err := s.lists.CreateTemporaryBlacklist(ctx, listing.CreateInput{
		ServiceID: serviceID,
		Type:      listType,
		Key:       key,
		Reason:    "limit threshold exceeded",
		ExpiresAt: &expiresAt,
	}); err != nil && !errors.Is(err, listing.ErrUnavailable) {
		return err
	}
	if s.audit != nil {
		_ = s.audit.RecordAuth(ctx, model.AuthLog{
			SubjectID:   key,
			SubjectType: listType,
			Event:       "limit_auto_blacklist",
			Result:      "failure",
			Reason:      "limit threshold exceeded",
		})
	}
	return nil
}

func (s *Service) ListLimitStatistics(ctx context.Context, filter LimitStatisticFilter) ([]model.LimitStatistic, error) {
	filter.Page, filter.PageSize = normalizePage(filter.Page, filter.PageSize)
	return s.store.ListLimitStatistics(ctx, filter)
}

func normalizePage(page int, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}

func listingTypeForDimension(dimension string) string {
	switch dimension {
	case "ip":
		return listing.TypeIP
	case "user_id":
		return listing.TypeUser
	case "app_id":
		return listing.TypeApp
	default:
		return ""
	}
}
