package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/jwtx"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/redisx"
	"golang.org/x/crypto/bcrypt"
)

func TestLoginSuccessIssuesTokensAndWritesRedisState(t *testing.T) {
	service, store, cache := testService(t)

	result, err := service.Login(context.Background(), LoginInput{
		Username: "admin",
		Password: "Zqlt_123456789",
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if result.AccessToken == "" || result.RefreshToken == "" || result.TokenType != "Bearer" {
		t.Fatalf("result = %#v", result)
	}
	if len(store.savedTokens) != 2 {
		t.Fatalf("saved tokens = %#v", store.savedTokens)
	}
	if cache.values["authlimit:jwt:access:"+store.savedTokens[0].JTI] == "" {
		t.Fatalf("missing access token redis state: %#v", cache.values)
	}
	if store.lastLoginUserID != "user-001" {
		t.Fatalf("last login user id = %q", store.lastLoginUserID)
	}
}

func TestLoginWrongPasswordLocksAccount(t *testing.T) {
	service, _, cache := testService(t)
	service.cfg.Security.AuthFailMaxCount = 1

	_, err := service.Login(context.Background(), LoginInput{
		Username: "admin",
		Password: "Wrong_123456",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v", err)
	}
	if cache.values["authlimit:auth:lock:user:user-001"] != "1" {
		t.Fatalf("lock key not set: %#v", cache.values)
	}

	_, err = service.Login(context.Background(), LoginInput{
		Username: "admin",
		Password: "Zqlt_123456789",
	})
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("Login() locked error = %v", err)
	}
}

func TestLoginRejectsInvalidInput(t *testing.T) {
	service, _, _ := testService(t)
	_, err := service.Login(context.Background(), LoginInput{
		Username: "bad-name",
		Password: "short",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Login() error = %v", err)
	}
}

func TestLoginReturnsUnavailableOnRedisError(t *testing.T) {
	service, _, cache := testService(t)
	cache.err = errors.New("redis down")

	_, err := service.Login(context.Background(), LoginInput{
		Username: "admin",
		Password: "Zqlt_123456789",
	})
	if !errors.Is(err, ErrAuthUnavailable) {
		t.Fatalf("Login() error = %v", err)
	}
}

func testService(t *testing.T) (*Service, *fakeUserStore, *fakeCache) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("Zqlt_123456789"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() error = %v", err)
	}
	store := &fakeUserStore{user: &model.User{
		BaseModel:    model.BaseModel{ID: "user-001"},
		Username:     "admin",
		PasswordHash: string(hash),
		Status:       model.StatusEnabled,
		Roles: []model.Role{
			{
				Code: "admin",
				Permissions: []model.Permission{
					{Code: "user:manage"},
				},
			},
		},
	}}
	cache := newFakeCache(t)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	manager := jwtx.NewManagerWithKeys(config.Default().JWT, privateKey, &privateKey.PublicKey)
	service := NewService(config.Default(), store, cache, manager)
	return service, store, cache
}

type fakeUserStore struct {
	user            *model.User
	savedTokens     []model.AuthToken
	lastLoginUserID string
}

func (s *fakeUserStore) FindUserByUsername(_ context.Context, username string) (*model.User, error) {
	if s.user == nil || s.user.Username != username {
		return nil, ErrUserNotFound
	}
	return s.user, nil
}

func (s *fakeUserStore) SaveAuthTokens(_ context.Context, tokens []model.AuthToken) error {
	s.savedTokens = append(s.savedTokens, tokens...)
	return nil
}

func (s *fakeUserStore) UpdateLastLogin(_ context.Context, userID string, _ time.Time) error {
	s.lastLoginUserID = userID
	return nil
}

type fakeCache struct {
	keys   *redisx.KeyBuilder
	values map[string]string
	ttls   map[string]time.Duration
	err    error
}

func newFakeCache(t *testing.T) *fakeCache {
	t.Helper()
	keys, err := redisx.NewKeyBuilder("authlimit")
	if err != nil {
		t.Fatalf("NewKeyBuilder() error = %v", err)
	}
	return &fakeCache{
		keys:   keys,
		values: map[string]string{},
		ttls:   map[string]time.Duration{},
	}
}

func (c *fakeCache) KeyBuilder() *redisx.KeyBuilder {
	return c.keys
}

func (c *fakeCache) Get(_ context.Context, key string) (string, error) {
	if c.err != nil {
		return "", c.err
	}
	return c.values[key], nil
}

func (c *fakeCache) Set(_ context.Context, key string, value string, ttl time.Duration) error {
	if c.err != nil {
		return c.err
	}
	c.values[key] = value
	c.ttls[key] = ttl
	return nil
}

func (c *fakeCache) Del(_ context.Context, keys ...string) error {
	if c.err != nil {
		return c.err
	}
	for _, key := range keys {
		delete(c.values, key)
	}
	return nil
}

func (c *fakeCache) Exists(_ context.Context, key string) (bool, error) {
	if c.err != nil {
		return false, c.err
	}
	_, ok := c.values[key]
	return ok, nil
}

func (c *fakeCache) Expire(_ context.Context, key string, ttl time.Duration) error {
	if c.err != nil {
		return c.err
	}
	c.ttls[key] = ttl
	return nil
}

func (c *fakeCache) Incr(_ context.Context, key string) (int64, error) {
	if c.err != nil {
		return 0, c.err
	}
	next := int64(1)
	if c.values[key] != "" {
		next = 2
	}
	c.values[key] = "1"
	return next, nil
}
