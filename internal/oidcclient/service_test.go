package oidcclient

import (
	"context"
	"errors"
	"testing"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"golang.org/x/crypto/bcrypt"
)

func TestCreateStoresBcryptSecretAndReturnsPlainSecretOnce(t *testing.T) {
	store := &fakeStore{}
	service := NewService(config.Default(), store)

	result, err := service.Create(t.Context(), Actor{UserID: "user-001"}, CreateInput{
		Name:        "web client",
		RedirectURI: "http://app.local/callback",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result.ClientSecret == "" {
		t.Fatal("client secret is empty")
	}
	if result.Client.ClientSecret == result.ClientSecret {
		t.Fatal("client secret stored in plain text")
	}
	if bcrypt.CompareHashAndPassword([]byte(result.Client.ClientSecret), []byte(result.ClientSecret)) != nil {
		t.Fatal("stored client secret is not a bcrypt hash of returned secret")
	}
}

func TestListRestrictsNormalUserToOwnClients(t *testing.T) {
	store := &fakeStore{clients: []model.OIDCClient{
		{BaseModel: model.BaseModel{ID: "client-001"}, OwnerUserID: "user-001"},
		{BaseModel: model.BaseModel{ID: "client-002"}, OwnerUserID: "user-002"},
	}}
	service := NewService(config.Default(), store)

	items, err := service.List(t.Context(), Actor{UserID: "user-001"})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(items) != 1 || items[0].ID != "client-001" {
		t.Fatalf("items = %#v", items)
	}
}

func TestGetRejectsOtherOwnerForNormalUser(t *testing.T) {
	service := NewService(config.Default(), &fakeStore{client: &model.OIDCClient{
		BaseModel:   model.BaseModel{ID: "client-002"},
		OwnerUserID: "user-002",
	}})

	_, err := service.Get(t.Context(), Actor{UserID: "user-001"}, "client-002")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("Get() error = %v", err)
	}
}

type fakeStore struct {
	clientIDExists bool
	client         *model.OIDCClient
	clients        []model.OIDCClient
}

func (s *fakeStore) ClientIDExists(_ context.Context, _ string) (bool, error) {
	return s.clientIDExists, nil
}

func (s *fakeStore) Create(_ context.Context, client *model.OIDCClient) error {
	s.client = client
	return nil
}

func (s *fakeStore) List(_ context.Context, filter ListFilter) ([]model.OIDCClient, error) {
	items := []model.OIDCClient{}
	for _, item := range s.clients {
		if filter.OwnerUserID != "" && item.OwnerUserID != filter.OwnerUserID {
			continue
		}
		items = append(items, item)
	}
	return items, nil
}

func (s *fakeStore) FindByID(_ context.Context, id string) (*model.OIDCClient, error) {
	if s.client == nil || s.client.ID != id {
		return nil, ErrNotFound
	}
	return s.client, nil
}
