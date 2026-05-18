package m2m

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

func (s *GormStore) FindAppCredentialByAppID(ctx context.Context, appID string) (*AppCredential, error) {
	var app model.App
	err := s.db.WithContext(ctx).Where("app_id = ?", appID).First(&app).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrAppNotFound
	}
	if err != nil {
		return nil, err
	}
	return &AppCredential{
		AppID:          app.AppID,
		Name:           app.Name,
		SecretMaterial: app.SecretHash,
		Status:         app.Status,
	}, nil
}
