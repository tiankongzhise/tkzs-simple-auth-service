package user

import (
	"context"
	"errors"
	"testing"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
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

type fakeStore struct {
	usernameExists bool
	user           *model.User
	users          []model.User
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
