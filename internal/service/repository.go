package service

import (
	"context"
	"errors"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"gorm.io/gorm"
)

type GormStore struct {
	db *gorm.DB
}

func NewGormStore(db *gorm.DB) *GormStore {
	return &GormStore{db: db}
}

func (s *GormStore) Create(ctx context.Context, service *model.Service) error {
	return s.db.WithContext(ctx).Create(service).Error
}

func (s *GormStore) List(ctx context.Context, filter ListFilter) ([]model.Service, error) {
	var services []model.Service
	query := s.db.WithContext(ctx).Order("created_at DESC")
	if filter.OwnerUserID != "" {
		query = query.Where("owner_user_id = ?", filter.OwnerUserID)
	}
	if filter.Name != "" {
		query = query.Where("name LIKE ?", "%"+filter.Name+"%")
	}
	if filter.Health != "" {
		query = query.Where("health_status = ?", filter.Health)
	}
	if err := query.Find(&services).Error; err != nil {
		return nil, err
	}
	return services, nil
}

func (s *GormStore) FindByID(ctx context.Context, id string) (*model.Service, error) {
	var service model.Service
	err := s.db.WithContext(ctx).Where("id = ?", id).First(&service).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &service, nil
}

func (s *GormStore) Update(ctx context.Context, service *model.Service) error {
	return s.db.WithContext(ctx).Save(service).Error
}

func (s *GormStore) Delete(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&model.Service{}, "id = ?", id).Error
}

func (s *GormStore) ListDiscoverable(ctx context.Context) ([]model.Service, error) {
	var services []model.Service
	err := s.db.WithContext(ctx).
		Where("approved = ? AND status = ? AND health_status = ?", true, StatusApproved, HealthHealthy).
		Order("created_at DESC").
		Find(&services).Error
	if err != nil {
		return nil, err
	}
	return services, nil
}
