package user

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

func (s *GormStore) UsernameExists(ctx context.Context, username string) (bool, error) {
	var count int64
	if err := s.db.WithContext(ctx).Model(&model.User{}).Where("username = ?", username).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *GormStore) Create(ctx context.Context, user *model.User) error {
	return s.db.WithContext(ctx).Create(user).Error
}

func (s *GormStore) List(ctx context.Context, filter ListFilter) ([]model.User, error) {
	var users []model.User
	query := s.db.WithContext(ctx).Preload("Roles").Order("created_at DESC")
	if filter.UserID != "" {
		query = query.Where("id = ?", filter.UserID)
	}
	if err := query.Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}

func (s *GormStore) FindByID(ctx context.Context, id string) (*model.User, error) {
	var user model.User
	err := s.db.WithContext(ctx).Preload("Roles").Where("id = ?", id).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *GormStore) Update(ctx context.Context, user *model.User) error {
	return s.db.WithContext(ctx).Save(user).Error
}

func (s *GormStore) Delete(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&model.User{}, "id = ?", id).Error
}
