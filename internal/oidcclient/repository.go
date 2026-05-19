package oidcclient

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

func (s *GormStore) ClientIDExists(ctx context.Context, clientID string) (bool, error) {
	var count int64
	if err := s.db.WithContext(ctx).Model(&model.OIDCClient{}).Where("client_id = ?", clientID).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *GormStore) Create(ctx context.Context, client *model.OIDCClient) error {
	return s.db.WithContext(ctx).Create(client).Error
}

func (s *GormStore) List(ctx context.Context, filter ListFilter) ([]model.OIDCClient, error) {
	var clients []model.OIDCClient
	query := s.db.WithContext(ctx).Order("created_at DESC")
	if filter.OwnerUserID != "" {
		query = query.Where("owner_user_id = ?", filter.OwnerUserID)
	}
	if err := query.Find(&clients).Error; err != nil {
		return nil, err
	}
	return clients, nil
}

func (s *GormStore) FindByID(ctx context.Context, id string) (*model.OIDCClient, error) {
	var client model.OIDCClient
	err := s.db.WithContext(ctx).Where("id = ?", id).First(&client).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &client, nil
}

func (s *GormStore) Update(ctx context.Context, client *model.OIDCClient) error {
	return s.db.WithContext(ctx).Save(client).Error
}

func (s *GormStore) Delete(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&model.OIDCClient{}, "id = ?", id).Error
}
