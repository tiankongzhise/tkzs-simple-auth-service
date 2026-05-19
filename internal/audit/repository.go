package audit

import (
	"context"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"gorm.io/gorm"
)

type GormStore struct {
	db *gorm.DB
}

func NewGormStore(db *gorm.DB) *GormStore {
	return &GormStore{db: db}
}

func (s *GormStore) ListOperationLogs(ctx context.Context, filter LogFilter) ([]model.OperationLog, error) {
	var items []model.OperationLog
	query := baseLogQuery(s.db.WithContext(ctx).Model(&model.OperationLog{}), filter)
	if filter.ActorID != "" {
		query = query.Where("actor_id = ?", filter.ActorID)
	}
	if err := query.Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

func (s *GormStore) ListAuthLogs(ctx context.Context, filter LogFilter) ([]model.AuthLog, error) {
	var items []model.AuthLog
	query := baseLogQuery(s.db.WithContext(ctx).Model(&model.AuthLog{}), filter)
	if filter.SubjectID != "" {
		query = query.Where("subject_id = ?", filter.SubjectID)
	}
	if err := query.Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

func (s *GormStore) ListLimitLogs(ctx context.Context, filter LogFilter) ([]model.LimitLog, error) {
	var items []model.LimitLog
	query := baseLogQuery(s.db.WithContext(ctx).Model(&model.LimitLog{}), filter)
	if filter.ServiceID != "" {
		query = query.Where("service_id = ?", filter.ServiceID)
	}
	if err := query.Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

func (s *GormStore) ListHealthLogs(ctx context.Context, filter LogFilter) ([]model.HealthCheckLog, error) {
	var items []model.HealthCheckLog
	query := baseLogQuery(s.db.WithContext(ctx).Model(&model.HealthCheckLog{}), filter)
	if filter.ServiceID != "" {
		query = query.Where("service_id = ?", filter.ServiceID)
	}
	if err := query.Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

func baseLogQuery(query *gorm.DB, filter LogFilter) *gorm.DB {
	if filter.Result != "" {
		query = query.Where("result = ?", filter.Result)
	}
	if filter.StartAt != nil {
		query = query.Where("created_at >= ?", *filter.StartAt)
	}
	if filter.EndAt != nil {
		query = query.Where("created_at <= ?", *filter.EndAt)
	}
	offset := (filter.Page - 1) * filter.PageSize
	return query.Order("created_at DESC").Limit(filter.PageSize).Offset(offset)
}
