package statistics

import (
	"context"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type GormStore struct {
	db *gorm.DB
}

func NewGormStore(db *gorm.DB) *GormStore {
	return &GormStore{db: db}
}

func (s *GormStore) RecordLimit(ctx context.Context, log model.LimitLog, bucket time.Time) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&log).Error; err != nil {
			return err
		}
		blocked := int64(0)
		if !log.Allowed {
			blocked = 1
		}
		stat := model.LimitStatistic{
			ServiceID:    log.ServiceID,
			Dimension:    log.Dimension,
			BucketTime:   bucket,
			TotalCount:   1,
			BlockedCount: blocked,
		}
		return tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{
				{Name: "service_id"},
				{Name: "dimension"},
				{Name: "bucket_time"},
			},
			DoUpdates: clause.Assignments(map[string]any{
				"total_count":   gorm.Expr("limit_statistics.total_count + ?", 1),
				"blocked_count": gorm.Expr("limit_statistics.blocked_count + ?", blocked),
			}),
		}).Create(&stat).Error
	})
}

func (s *GormStore) ListLimitStatistics(ctx context.Context, filter LimitStatisticFilter) ([]model.LimitStatistic, error) {
	var items []model.LimitStatistic
	query := s.db.WithContext(ctx).Model(&model.LimitStatistic{})
	if filter.ServiceID != "" {
		query = query.Where("service_id = ?", filter.ServiceID)
	}
	if filter.Dimension != "" {
		query = query.Where("dimension = ?", filter.Dimension)
	}
	if filter.StartAt != nil {
		query = query.Where("bucket_time >= ?", *filter.StartAt)
	}
	if filter.EndAt != nil {
		query = query.Where("bucket_time <= ?", *filter.EndAt)
	}
	offset := (filter.Page - 1) * filter.PageSize
	if err := query.Order("bucket_time DESC").Limit(filter.PageSize).Offset(offset).Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}
