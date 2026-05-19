package listing

import (
	"context"
	"errors"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"gorm.io/gorm"
)

type GormStore struct {
	db *gorm.DB
}

func NewGormStore(db *gorm.DB) *GormStore {
	return &GormStore{db: db}
}

func (s *GormStore) CreateBlacklist(ctx context.Context, entry *model.Blacklist) error {
	return s.db.WithContext(ctx).Create(entry).Error
}

func (s *GormStore) CreateWhitelist(ctx context.Context, entry *model.Whitelist) error {
	return s.db.WithContext(ctx).Create(entry).Error
}

func (s *GormStore) ListBlacklists(ctx context.Context, serviceID string) ([]model.Blacklist, error) {
	var items []model.Blacklist
	query := s.db.WithContext(ctx).Order("created_at DESC")
	if serviceID != "" {
		query = query.Where("service_id = ?", serviceID)
	}
	if err := query.Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

func (s *GormStore) ListWhitelists(ctx context.Context, serviceID string) ([]model.Whitelist, error) {
	var items []model.Whitelist
	query := s.db.WithContext(ctx).Order("created_at DESC")
	if serviceID != "" {
		query = query.Where("service_id = ?", serviceID)
	}
	if err := query.Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

func (s *GormStore) FindBlacklistByID(ctx context.Context, id string) (*model.Blacklist, error) {
	var item model.Blacklist
	err := s.db.WithContext(ctx).Where("id = ?", id).First(&item).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *GormStore) FindWhitelistByID(ctx context.Context, id string) (*model.Whitelist, error) {
	var item model.Whitelist
	err := s.db.WithContext(ctx).Where("id = ?", id).First(&item).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *GormStore) DeleteBlacklist(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&model.Blacklist{}, "id = ?", id).Error
}

func (s *GormStore) DeleteWhitelist(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&model.Whitelist{}, "id = ?", id).Error
}

func (s *GormStore) FindBlacklistHit(ctx context.Context, serviceID string, typ string, key string, now time.Time) (*model.Blacklist, error) {
	var item model.Blacklist
	err := hitQuery(s.db.WithContext(ctx), serviceID, typ, key, now).First(&item).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *GormStore) FindWhitelistHit(ctx context.Context, serviceID string, typ string, key string, now time.Time) (*model.Whitelist, error) {
	var item model.Whitelist
	err := hitQuery(s.db.WithContext(ctx), serviceID, typ, key, now).First(&item).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func hitQuery(db *gorm.DB, serviceID string, typ string, key string, now time.Time) *gorm.DB {
	return db.Where("service_id = ? AND type = ? AND key = ? AND (expires_at IS NULL OR expires_at > ?)", serviceID, typ, key, now)
}
