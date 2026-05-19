package listing

import (
	"context"
	"errors"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/redisx"
)

var (
	ErrInvalidInput = errors.New("invalid list input")
	ErrNotFound     = errors.New("list entry not found")
	ErrForbidden    = errors.New("list access forbidden")
	ErrUnavailable  = errors.New("list dependency unavailable")
)

const (
	ListBlacklist = "blacklist"
	ListWhitelist = "whitelist"

	TypeIP    = "ip"
	TypeUser  = "user"
	TypeApp   = "app"
	TypeToken = "token"
)

type Store interface {
	CreateBlacklist(ctx context.Context, entry *model.Blacklist) error
	CreateWhitelist(ctx context.Context, entry *model.Whitelist) error
	ListBlacklists(ctx context.Context, serviceID string) ([]model.Blacklist, error)
	ListWhitelists(ctx context.Context, serviceID string) ([]model.Whitelist, error)
	FindBlacklistByID(ctx context.Context, id string) (*model.Blacklist, error)
	FindWhitelistByID(ctx context.Context, id string) (*model.Whitelist, error)
	DeleteBlacklist(ctx context.Context, id string) error
	DeleteWhitelist(ctx context.Context, id string) error
	FindBlacklistHit(ctx context.Context, serviceID string, typ string, key string, now time.Time) (*model.Blacklist, error)
	FindWhitelistHit(ctx context.Context, serviceID string, typ string, key string, now time.Time) (*model.Whitelist, error)
}

type Cache interface {
	KeyBuilder() *redisx.KeyBuilder
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Exists(ctx context.Context, key string) (bool, error)
	Del(ctx context.Context, keys ...string) error
}

type Service struct {
	store Store
	cache Cache
	now   func() time.Time
}

type Actor struct {
	UserID  string
	IsAdmin bool
}

type CreateInput struct {
	ServiceID string
	Type      string
	Key       string
	Reason    string
	Permanent bool
	ExpiresAt *time.Time
}

type HitInput struct {
	ServiceID string
	IP        string
	UserID    string
	AppID     string
	TokenID   string
}

type HitResult struct {
	Blacklisted bool             `json:"blacklisted"`
	Whitelisted bool             `json:"whitelisted"`
	Blacklist   *model.Blacklist `json:"blacklist,omitempty"`
	Whitelist   *model.Whitelist `json:"whitelist,omitempty"`
}

func NewService(store Store, cache Cache) *Service {
	return &Service{store: store, cache: cache, now: time.Now}
}

func (s *Service) CreateBlacklist(ctx context.Context, actor Actor, input CreateInput) (*model.Blacklist, error) {
	if !actor.IsAdmin || !validInput(input, true) {
		return nil, ErrInvalidInput
	}
	return s.createBlacklist(ctx, actor.UserID, input)
}

func (s *Service) CreateTemporaryBlacklist(ctx context.Context, input CreateInput) (*model.Blacklist, error) {
	if input.ExpiresAt == nil || input.Permanent || !validInput(input, false) {
		return nil, ErrInvalidInput
	}
	return s.createBlacklist(ctx, "system", input)
}

func (s *Service) createBlacklist(ctx context.Context, createdBy string, input CreateInput) (*model.Blacklist, error) {
	entry := &model.Blacklist{
		ServiceID: input.ServiceID,
		Type:      input.Type,
		Key:       input.Key,
		Permanent: input.Permanent,
		Reason:    input.Reason,
		ExpiresAt: input.ExpiresAt,
		CreatedBy: createdBy,
	}
	if err := s.store.CreateBlacklist(ctx, entry); err != nil {
		return nil, err
	}
	if err := s.cacheEntry(ctx, ListBlacklist, input.ServiceID, input.Type, input.Key, input.ExpiresAt); err != nil {
		return nil, err
	}
	return entry, nil
}

func (s *Service) CreateWhitelist(ctx context.Context, actor Actor, input CreateInput) (*model.Whitelist, error) {
	if !actor.IsAdmin || !validInput(input, false) {
		return nil, ErrInvalidInput
	}
	entry := &model.Whitelist{
		ServiceID: input.ServiceID,
		Type:      input.Type,
		Key:       input.Key,
		Reason:    input.Reason,
		ExpiresAt: input.ExpiresAt,
		CreatedBy: actor.UserID,
	}
	if err := s.store.CreateWhitelist(ctx, entry); err != nil {
		return nil, err
	}
	if err := s.cacheEntry(ctx, ListWhitelist, input.ServiceID, input.Type, input.Key, input.ExpiresAt); err != nil {
		return nil, err
	}
	return entry, nil
}

func (s *Service) ListBlacklists(ctx context.Context, _ Actor, serviceID string) ([]model.Blacklist, error) {
	return s.store.ListBlacklists(ctx, serviceID)
}

func (s *Service) ListWhitelists(ctx context.Context, _ Actor, serviceID string) ([]model.Whitelist, error) {
	return s.store.ListWhitelists(ctx, serviceID)
}

func (s *Service) DeleteBlacklist(ctx context.Context, actor Actor, id string) error {
	if !actor.IsAdmin {
		return ErrForbidden
	}
	entry, err := s.store.FindBlacklistByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.store.DeleteBlacklist(ctx, id); err != nil {
		return err
	}
	return s.evictEntry(ctx, ListBlacklist, entry.ServiceID, entry.Type, entry.Key)
}

func (s *Service) DeleteWhitelist(ctx context.Context, actor Actor, id string) error {
	if !actor.IsAdmin {
		return ErrForbidden
	}
	entry, err := s.store.FindWhitelistByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.store.DeleteWhitelist(ctx, id); err != nil {
		return err
	}
	return s.evictEntry(ctx, ListWhitelist, entry.ServiceID, entry.Type, entry.Key)
}

func (s *Service) Check(ctx context.Context, input HitInput) (*HitResult, error) {
	if input.ServiceID == "" {
		return nil, ErrInvalidInput
	}
	subjects := subjects(input)
	for typ, key := range subjects {
		if s.cache != nil {
			cached, err := s.cacheHit(ctx, ListWhitelist, input.ServiceID, typ, key)
			if err != nil {
				return nil, err
			}
			if cached {
				return &HitResult{Whitelisted: true}, nil
			}
		}
		whitelist, err := s.store.FindWhitelistHit(ctx, input.ServiceID, typ, key, s.now())
		if err != nil {
			return nil, err
		}
		if whitelist != nil {
			return &HitResult{Whitelisted: true, Whitelist: whitelist}, nil
		}
	}
	for typ, key := range subjects {
		if s.cache != nil {
			cached, err := s.cacheHit(ctx, ListBlacklist, input.ServiceID, typ, key)
			if err != nil {
				return nil, err
			}
			if cached {
				return &HitResult{Blacklisted: true}, nil
			}
		}
		blacklist, err := s.store.FindBlacklistHit(ctx, input.ServiceID, typ, key, s.now())
		if err != nil {
			return nil, err
		}
		if blacklist != nil {
			return &HitResult{Blacklisted: true, Blacklist: blacklist}, nil
		}
	}
	return &HitResult{}, nil
}

func (s *Service) cacheEntry(ctx context.Context, listType string, serviceID string, typ string, key string, expiresAt *time.Time) error {
	if s.cache == nil {
		return nil
	}
	redisKey, err := s.cache.KeyBuilder().Build(listType, typ, serviceID, key)
	if err != nil {
		return err
	}
	ttl := time.Duration(0)
	if expiresAt != nil {
		ttl = expiresAt.Sub(s.now())
		if ttl <= 0 {
			ttl = time.Second
		}
	}
	if err := s.cache.Set(ctx, redisKey, "1", ttl); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Service) cacheHit(ctx context.Context, listType string, serviceID string, typ string, key string) (bool, error) {
	redisKey, err := s.cache.KeyBuilder().Build(listType, typ, serviceID, key)
	if err != nil {
		return false, err
	}
	exists, err := s.cache.Exists(ctx, redisKey)
	if err != nil {
		return false, ErrUnavailable
	}
	return exists, nil
}

func (s *Service) evictEntry(ctx context.Context, listType string, serviceID string, typ string, key string) error {
	if s.cache == nil {
		return nil
	}
	redisKey, err := s.cache.KeyBuilder().Build(listType, typ, serviceID, key)
	if err != nil {
		return err
	}
	if err := s.cache.Del(ctx, redisKey); err != nil {
		return ErrUnavailable
	}
	return nil
}

func validInput(input CreateInput, allowToken bool) bool {
	if input.ServiceID == "" || input.Type == "" || input.Key == "" {
		return false
	}
	switch input.Type {
	case TypeIP, TypeUser, TypeApp:
		return true
	case TypeToken:
		return allowToken
	default:
		return false
	}
}

func subjects(input HitInput) map[string]string {
	values := map[string]string{}
	if input.IP != "" {
		values[TypeIP] = input.IP
	}
	if input.UserID != "" {
		values[TypeUser] = input.UserID
	}
	if input.AppID != "" {
		values[TypeApp] = input.AppID
	}
	if input.TokenID != "" {
		values[TypeToken] = input.TokenID
	}
	return values
}
