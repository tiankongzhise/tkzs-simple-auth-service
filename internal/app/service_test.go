package app

import (
	"context"
	"errors"
	"testing"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
)

func TestCreateReturnsSecretOnce(t *testing.T) {
	store := &fakeStore{}
	service := NewService(store)

	result, err := service.Create(t.Context(), Actor{UserID: "user-001"}, CreateInput{Name: "demo app"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result.App.AppID == "" || len(result.App.AppID) != 8 {
		t.Fatalf("app id = %q", result.App.AppID)
	}
	if result.AppSecret == "" || len(result.AppSecret) != 16 {
		t.Fatalf("app secret = %q", result.AppSecret)
	}
	if store.created == nil || store.created.SecretHash != result.AppSecret {
		t.Fatalf("created = %#v", store.created)
	}
}

func TestListFiltersOwnerForNormalUser(t *testing.T) {
	store := &fakeStore{apps: []model.App{
		{BaseModel: model.BaseModel{ID: "app-001"}, OwnerUserID: "user-001"},
		{BaseModel: model.BaseModel{ID: "app-002"}, OwnerUserID: "user-002"},
	}}
	service := NewService(store)

	items, err := service.List(t.Context(), Actor{UserID: "user-001"})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(items) != 1 || items[0].ID != "app-001" {
		t.Fatalf("items = %#v", items)
	}
}

func TestAdminCanAccessAnyApp(t *testing.T) {
	store := &fakeStore{app: &model.App{BaseModel: model.BaseModel{ID: "app-001"}, OwnerUserID: "user-002"}}
	service := NewService(store)

	if _, err := service.Get(t.Context(), Actor{UserID: "admin", IsAdmin: true}, "app-001"); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
}

func TestNormalUserCannotAccessOtherApp(t *testing.T) {
	store := &fakeStore{app: &model.App{BaseModel: model.BaseModel{ID: "app-001"}, OwnerUserID: "user-002"}}
	service := NewService(store)

	_, err := service.Get(t.Context(), Actor{UserID: "user-001"}, "app-001")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("Get() error = %v", err)
	}
}

func TestResetSecretReturnsNewSecret(t *testing.T) {
	store := &fakeStore{app: &model.App{BaseModel: model.BaseModel{ID: "app-001"}, OwnerUserID: "user-001", SecretHash: "old-secret"}}
	service := NewService(store)

	result, err := service.ResetSecret(t.Context(), Actor{UserID: "user-001"}, "app-001")
	if err != nil {
		t.Fatalf("ResetSecret() error = %v", err)
	}
	if result.AppSecret == "" || result.AppSecret == "old-secret" {
		t.Fatalf("app secret = %q", result.AppSecret)
	}
	if store.updated == nil || store.updated.SecretHash != result.AppSecret {
		t.Fatalf("updated = %#v", store.updated)
	}
}

type fakeStore struct {
	app     *model.App
	apps    []model.App
	created *model.App
	updated *model.App
	deleted string
}

func (s *fakeStore) AppIDExists(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (s *fakeStore) Create(_ context.Context, app *model.App) error {
	s.created = app
	return nil
}

func (s *fakeStore) List(_ context.Context, filter ListFilter) ([]model.App, error) {
	if filter.OwnerUserID == "" {
		return s.apps, nil
	}
	items := []model.App{}
	for _, item := range s.apps {
		if item.OwnerUserID == filter.OwnerUserID {
			items = append(items, item)
		}
	}
	return items, nil
}

func (s *fakeStore) FindByID(_ context.Context, id string) (*model.App, error) {
	if s.app == nil || s.app.ID != id {
		return nil, ErrNotFound
	}
	return s.app, nil
}

func (s *fakeStore) Update(_ context.Context, app *model.App) error {
	s.updated = app
	return nil
}

func (s *fakeStore) Delete(_ context.Context, id string) error {
	s.deleted = id
	return nil
}
