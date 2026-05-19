package limitrule

import (
	"context"
	"errors"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	servicesvc "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/service"
	"gorm.io/gorm"
)

type GormStore struct {
	db *gorm.DB
}

func NewGormStore(db *gorm.DB) *GormStore {
	return &GormStore{db: db}
}

func (s *GormStore) Create(ctx context.Context, rule *model.RateLimitRule) error {
	return s.db.WithContext(ctx).Create(rule).Error
}

func (s *GormStore) List(ctx context.Context, filter ListFilter) ([]model.RateLimitRule, error) {
	var rules []model.RateLimitRule
	query := s.db.WithContext(ctx).Preload("Service").Order("created_at DESC")
	if filter.ServiceID != "" {
		query = query.Where("service_id = ?", filter.ServiceID)
	}
	if filter.OwnerUserID != "" {
		query = query.Where("owner_user_id = ?", filter.OwnerUserID)
	}
	if filter.Dimension != "" {
		query = query.Where("dimension = ?", filter.Dimension)
	}
	if filter.Enabled != nil {
		query = query.Where("enabled = ?", *filter.Enabled)
	}
	if err := query.Find(&rules).Error; err != nil {
		return nil, err
	}
	return rules, nil
}

func (s *GormStore) FindByID(ctx context.Context, id string) (*model.RateLimitRule, error) {
	var rule model.RateLimitRule
	err := s.db.WithContext(ctx).Preload("Service").Where("id = ?", id).First(&rule).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

func (s *GormStore) Update(ctx context.Context, rule *model.RateLimitRule) error {
	return s.db.WithContext(ctx).Save(rule).Error
}

func (s *GormStore) Delete(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&model.RateLimitRule{}, "id = ?", id).Error
}

func (s *GormStore) FindServiceByID(ctx context.Context, id string) (*model.Service, error) {
	var service model.Service
	err := s.db.WithContext(ctx).Where("id = ?", id).First(&service).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, servicesvc.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &service, nil
}

func (s *GormStore) EnabledIdentityExists(ctx context.Context, serviceID string, dimension string, granularity string, excludeID string) (bool, error) {
	var count int64
	query := s.db.WithContext(ctx).Model(&model.RateLimitRule{}).
		Where("service_id = ? AND dimension = ? AND granularity = ? AND enabled = ?", serviceID, dimension, granularity, true)
	if excludeID != "" {
		query = query.Where("id <> ?", excludeID)
	}
	if err := query.Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}
