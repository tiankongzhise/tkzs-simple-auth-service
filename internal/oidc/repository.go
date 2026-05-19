package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrClientNotFound = errors.New("oidc client not found")
	ErrCodeNotFound   = errors.New("oidc auth code not found")
)

type GormStore struct {
	db *gorm.DB
}

func NewGormStore(db *gorm.DB) *GormStore {
	return &GormStore{db: db}
}

func (s *GormStore) FindClientByID(ctx context.Context, clientID string) (*Client, error) {
	var client model.OIDCClient
	err := s.db.WithContext(ctx).Where("client_id = ?", clientID).First(&client).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrClientNotFound
	}
	if err != nil {
		return nil, err
	}
	return &Client{
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		RedirectURI:  client.RedirectURI,
		Status:       client.Status,
	}, nil
}

func (s *GormStore) SaveAuthCode(ctx context.Context, code AuthCode) error {
	return s.db.WithContext(ctx).Create(&model.OIDCAuthCode{
		Code:        code.Code,
		ClientID:    code.ClientID,
		UserID:      code.UserID,
		RedirectURI: code.RedirectURI,
		Scope:       code.Scope,
		ExpiresAt:   code.ExpiresAt,
		Used:        code.Used,
	}).Error
}

func (s *GormStore) UseAuthCode(ctx context.Context, code string, now time.Time) (*AuthCode, error) {
	var result AuthCode
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var record model.OIDCAuthCode
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("code = ? AND used = ? AND expires_at > ?", code, false, now).
			First(&record).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrCodeNotFound
		}
		if err != nil {
			return err
		}
		if err := tx.Model(&record).Update("used", true).Error; err != nil {
			return err
		}
		result = AuthCode{
			Code:        record.Code,
			ClientID:    record.ClientID,
			UserID:      record.UserID,
			RedirectURI: record.RedirectURI,
			Scope:       record.Scope,
			ExpiresAt:   record.ExpiresAt,
			Used:        false,
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrCodeNotFound) {
			return nil, ErrInvalidAuthCode
		}
		return nil, err
	}
	return &result, nil
}
