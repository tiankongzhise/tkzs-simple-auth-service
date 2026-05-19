package m2m

import (
	"context"
	"errors"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/secret"
	"gorm.io/gorm"
)

type GormStore struct {
	db    *gorm.DB
	codec secret.Codec
}

func NewGormStore(db *gorm.DB, codecs ...secret.Codec) *GormStore {
	codec := secret.Codec(secret.LegacyPassthroughCodec{})
	if len(codecs) > 0 && codecs[0] != nil {
		codec = codecs[0]
	}
	return &GormStore{db: db, codec: codec}
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
	secretMaterial, err := s.codec.DecryptString(app.SecretHash)
	if err != nil {
		return nil, err
	}
	return &AppCredential{
		AppID:          app.AppID,
		Name:           app.Name,
		SecretMaterial: secretMaterial,
		Status:         app.Status,
	}, nil
}
