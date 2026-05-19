package user

import (
	"context"
	"errors"
	"testing"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/redisx"
	"golang.org/x/crypto/bcrypt"
)

func TestRegisterCreatesEnabledUserWithBcryptPassword(t *testing.T) {
	store := &fakeStore{}
	service := NewService(config.Default(), store)

	result, err := service.Register(t.Context(), RegisterInput{
		Username:    "user_001",
		Password:    "Pass_123",
		DisplayName: "User One",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if result.Status != model.StatusEnabled || result.DisplayName != "User One" {
		t.Fatalf("result = %#v", result)
	}
	if bcrypt.CompareHashAndPassword([]byte(result.PasswordHash), []byte("Pass_123")) != nil {
		t.Fatalf("password hash is not bcrypt: %q", result.PasswordHash)
	}
}

func TestRegisterRejectsDuplicateUsername(t *testing.T) {
	service := NewService(config.Default(), &fakeStore{usernameExists: true})

	_, err := service.Register(t.Context(), RegisterInput{Username: "user_001", Password: "Pass_123"})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Register() error = %v", err)
	}
}

func TestListRestrictsNormalUserToSelf(t *testing.T) {
	store := &fakeStore{users: []model.User{
		{BaseModel: model.BaseModel{ID: "user-001"}, Username: "one"},
		{BaseModel: model.BaseModel{ID: "user-002"}, Username: "two"},
	}}
	service := NewService(config.Default(), store)

	items, err := service.List(t.Context(), Actor{UserID: "user-001"})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(items) != 1 || items[0].ID != "user-001" {
		t.Fatalf("items = %#v", items)
	}
}

func TestGetRejectsOtherUserForNormalActor(t *testing.T) {
	service := NewService(config.Default(), &fakeStore{user: &model.User{BaseModel: model.BaseModel{ID: "user-002"}}})

	_, err := service.Get(t.Context(), Actor{UserID: "user-001"}, "user-002")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("Get() error = %v", err)
	}
}

func TestUpdateAllowsNormalUserToEditSelf(t *testing.T) {
	store := &fakeStore{user: &model.User{BaseModel: model.BaseModel{ID: "user-001"}, Username: "user_001"}}
	service := NewService(config.Default(), store)

	result, err := service.Update(t.Context(), Actor{UserID: "user-001"}, UpdateInput{
		ID:          "user-001",
		DisplayName: "New Name",
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if result.DisplayName != "New Name" || store.updated == nil {
		t.Fatalf("result = %#v updated=%#v", result, store.updated)
	}
}

func TestUpdateStatusRejectsSelfChange(t *testing.T) {
	service := NewService(config.Default(), &fakeStore{user: &model.User{BaseModel: model.BaseModel{ID: "admin"}}})

	_, err := service.UpdateStatus(t.Context(), Actor{UserID: "admin", CanManage: true}, UpdateStatusInput{
		ID:     "admin",
		Status: model.StatusDisabled,
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("UpdateStatus() error = %v", err)
	}
}

func TestUpdatePasswordRequiresOldPasswordForSelfAndClearsCache(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("Old_1234"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() error = %v", err)
	}
	cache := newFakeUserCache(t)
	store := &fakeStore{user: &model.User{
		BaseModel:    model.BaseModel{ID: "user-001"},
		PasswordHash: string(hash),
	}}
	service := NewService(config.Default(), store, WithCache(cache))

	err = service.UpdatePassword(t.Context(), Actor{UserID: "user-001"}, UpdatePasswordInput{
		ID:          "user-001",
		OldPassword: "Old_1234",
		NewPassword: "New_1234",
	})
	if err != nil {
		t.Fatalf("UpdatePassword() error = %v", err)
	}
	if cache.deleted != "authlimit:user:password:user-001" {
		t.Fatalf("deleted cache key = %q", cache.deleted)
	}
}

func TestUnlockClearsAuthFailureAndLockKeys(t *testing.T) {
	cache := newFakeUserCache(t)
	store := &fakeStore{user: &model.User{BaseModel: model.BaseModel{ID: "user-002"}}}
	service := NewService(config.Default(), store, WithCache(cache))

	if err := service.Unlock(t.Context(), Actor{UserID: "admin", CanManage: true}, UnlockInput{ID: "user-002"}); err != nil {
		t.Fatalf("Unlock() error = %v", err)
	}
	if len(cache.deletedKeys) != 2 ||
		cache.deletedKeys[0] != "authlimit:auth:fail:user:user-002" ||
		cache.deletedKeys[1] != "authlimit:auth:lock:user:user-002" {
		t.Fatalf("deleted keys = %#v", cache.deletedKeys)
	}
}

func TestUnlockRequiresManagePermission(t *testing.T) {
	service := NewService(config.Default(), &fakeStore{user: &model.User{BaseModel: model.BaseModel{ID: "user-002"}}})

	err := service.Unlock(t.Context(), Actor{UserID: "user-001"}, UnlockInput{ID: "user-002"})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("Unlock() error = %v", err)
	}
}

func TestDeleteRejectsSelfDeletion(t *testing.T) {
	service := NewService(config.Default(), &fakeStore{user: &model.User{BaseModel: model.BaseModel{ID: "admin"}}})

	err := service.Delete(t.Context(), Actor{UserID: "admin", CanManage: true}, "admin")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("Delete() error = %v", err)
	}
}

type fakeStore struct {
	usernameExists bool
	user           *model.User
	users          []model.User
	updated        *model.User
	deleted        string
}

func (s *fakeStore) UsernameExists(_ context.Context, _ string) (bool, error) {
	return s.usernameExists, nil
}

func (s *fakeStore) Create(_ context.Context, user *model.User) error {
	s.user = user
	return nil
}

func (s *fakeStore) List(_ context.Context, filter ListFilter) ([]model.User, error) {
	items := []model.User{}
	for _, item := range s.users {
		if filter.UserID != "" && item.ID != filter.UserID {
			continue
		}
		items = append(items, item)
	}
	return items, nil
}

func (s *fakeStore) FindByID(_ context.Context, id string) (*model.User, error) {
	if s.user == nil || s.user.ID != id {
		return nil, ErrNotFound
	}
	return s.user, nil
}

func (s *fakeStore) Update(_ context.Context, user *model.User) error {
	s.updated = user
	s.user = user
	return nil
}

func (s *fakeStore) Delete(_ context.Context, id string) error {
	s.deleted = id
	return nil
}

type fakeUserCache struct {
	keys        *redisx.KeyBuilder
	deleted     string
	deletedKeys []string
}

func newFakeUserCache(t *testing.T) *fakeUserCache {
	t.Helper()
	keys, err := redisx.NewKeyBuilder("authlimit")
	if err != nil {
		t.Fatalf("NewKeyBuilder() error = %v", err)
	}
	return &fakeUserCache{keys: keys}
}

func (c *fakeUserCache) KeyBuilder() *redisx.KeyBuilder {
	return c.keys
}

func (c *fakeUserCache) Del(_ context.Context, keys ...string) error {
	if len(keys) > 0 {
		c.deleted = keys[0]
	}
	c.deletedKeys = append(c.deletedKeys, keys...)
	return nil
}
