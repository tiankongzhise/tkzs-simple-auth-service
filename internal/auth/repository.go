package auth

import (
	"context"
	"errors"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"gorm.io/gorm"
)

var ErrUserNotFound = errors.New("user not found")
var ErrTokenRecordNotFound = errors.New("token record not found")

type GormStore struct {
	db *gorm.DB
}

func NewGormStore(db *gorm.DB) *GormStore {
	return &GormStore{db: db}
}

func (s *GormStore) FindUserByUsername(ctx context.Context, username string) (*model.User, error) {
	var user model.User
	err := s.db.WithContext(ctx).
		Preload("Roles.Permissions").
		Where("username = ?", username).
		First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *GormStore) FindUserByID(ctx context.Context, userID string) (*model.User, error) {
	var user model.User
	err := s.db.WithContext(ctx).
		Preload("Roles.Permissions").
		Where("id = ?", userID).
		First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *GormStore) SaveAuthTokens(ctx context.Context, tokens []model.AuthToken) error {
	return s.db.WithContext(ctx).Create(&tokens).Error
}

func (s *GormStore) FindActiveAuthToken(ctx context.Context, jti string, tokenType string, now time.Time) (*model.AuthToken, error) {
	var token model.AuthToken
	err := s.db.WithContext(ctx).
		Where("jti = ? AND token_type = ? AND status = ? AND expires_at > ?", jti, tokenType, model.TokenStatusActive, now).
		First(&token).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrTokenRecordNotFound
	}
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (s *GormStore) RevokeAuthTokens(ctx context.Context, jtis []string, at time.Time) error {
	if len(jtis) == 0 {
		return nil
	}
	return s.db.WithContext(ctx).
		Model(&model.AuthToken{}).
		Where("jti IN ?", jtis).
		Updates(map[string]any{
			"status":     model.TokenStatusRevoked,
			"revoked_at": at,
		}).
		Error
}

func (s *GormStore) UpdateLastLogin(ctx context.Context, userID string, at time.Time) error {
	return s.db.WithContext(ctx).
		Model(&model.User{}).
		Where("id = ?", userID).
		Update("last_login_at", at).
		Error
}
