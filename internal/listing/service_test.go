package listing

import (
	"context"
	"testing"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/redisx"
)

func TestCreateBlacklistCachesEntry(t *testing.T) {
	store := &fakeStore{}
	cache := newFakeCache(t)
	service := NewService(store, cache)

	entry, err := service.CreateBlacklist(t.Context(), Actor{UserID: "admin", IsAdmin: true}, CreateInput{
		ServiceID: "svc-001",
		Type:      TypeIP,
		Key:       "127.0.0.1",
		Permanent: true,
	})
	if err != nil {
		t.Fatalf("CreateBlacklist() error = %v", err)
	}
	if entry.Key != "127.0.0.1" {
		t.Fatalf("entry = %#v", entry)
	}
	if cache.values["authlimit:blacklist:ip:svc-001:127.0.0.1"] != "1" {
		t.Fatalf("cache = %#v", cache.values)
	}
}

func TestCheckWhitelistWinsBeforeBlacklist(t *testing.T) {
	store := &fakeStore{
		whitelist: &model.Whitelist{ServiceID: "svc-001", Type: TypeIP, Key: "127.0.0.1"},
		blacklist: &model.Blacklist{ServiceID: "svc-001", Type: TypeIP, Key: "127.0.0.1"},
	}
	service := NewService(store, nil)

	result, err := service.Check(t.Context(), HitInput{ServiceID: "svc-001", IP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Whitelisted || result.Blacklisted {
		t.Fatalf("result = %#v", result)
	}
}

func TestCheckBlacklistHit(t *testing.T) {
	store := &fakeStore{blacklist: &model.Blacklist{ServiceID: "svc-001", Type: TypeApp, Key: "app00001"}}
	service := NewService(store, nil)

	result, err := service.Check(t.Context(), HitInput{ServiceID: "svc-001", AppID: "app00001"})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Blacklisted {
		t.Fatalf("result = %#v", result)
	}
}

type fakeStore struct {
	blacklist  *model.Blacklist
	whitelist  *model.Whitelist
	blacklists []model.Blacklist
	whitelists []model.Whitelist
}

func (s *fakeStore) CreateBlacklist(_ context.Context, entry *model.Blacklist) error {
	s.blacklist = entry
	return nil
}

func (s *fakeStore) CreateWhitelist(_ context.Context, entry *model.Whitelist) error {
	s.whitelist = entry
	return nil
}

func (s *fakeStore) ListBlacklists(_ context.Context, _ string) ([]model.Blacklist, error) {
	return s.blacklists, nil
}

func (s *fakeStore) ListWhitelists(_ context.Context, _ string) ([]model.Whitelist, error) {
	return s.whitelists, nil
}

func (s *fakeStore) DeleteBlacklist(_ context.Context, _ string) error {
	return nil
}

func (s *fakeStore) DeleteWhitelist(_ context.Context, _ string) error {
	return nil
}

func (s *fakeStore) FindBlacklistHit(_ context.Context, _ string, typ string, key string, _ time.Time) (*model.Blacklist, error) {
	if s.blacklist != nil && s.blacklist.Type == typ && s.blacklist.Key == key {
		return s.blacklist, nil
	}
	return nil, nil
}

func (s *fakeStore) FindWhitelistHit(_ context.Context, _ string, typ string, key string, _ time.Time) (*model.Whitelist, error) {
	if s.whitelist != nil && s.whitelist.Type == typ && s.whitelist.Key == key {
		return s.whitelist, nil
	}
	return nil, nil
}

type fakeCache struct {
	keys   *redisx.KeyBuilder
	values map[string]string
}

func newFakeCache(t *testing.T) *fakeCache {
	t.Helper()
	keys, err := redisx.NewKeyBuilder("authlimit")
	if err != nil {
		t.Fatalf("NewKeyBuilder() error = %v", err)
	}
	return &fakeCache{keys: keys, values: map[string]string{}}
}

func (c *fakeCache) KeyBuilder() *redisx.KeyBuilder {
	return c.keys
}

func (c *fakeCache) Set(_ context.Context, key string, value string, _ time.Duration) error {
	c.values[key] = value
	return nil
}

func (c *fakeCache) Exists(_ context.Context, key string) (bool, error) {
	_, ok := c.values[key]
	return ok, nil
}

func (c *fakeCache) Del(_ context.Context, keys ...string) error {
	for _, key := range keys {
		delete(c.values, key)
	}
	return nil
}
