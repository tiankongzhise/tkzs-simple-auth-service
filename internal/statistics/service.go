package statistics

import (
	"context"
	"errors"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
)

var ErrInvalidInput = errors.New("invalid statistics input")

type Store interface {
	RecordLimit(ctx context.Context, log model.LimitLog, bucket time.Time) error
	ListLimitStatistics(ctx context.Context, filter LimitStatisticFilter) ([]model.LimitStatistic, error)
}

type Service struct {
	store Store
	now   func() time.Time
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
