package oidcclient

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net/url"
	"strings"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidInput = errors.New("invalid oidc client input")
	ErrNotFound     = errors.New("oidc client not found")
	ErrForbidden    = errors.New("oidc client access forbidden")
	ErrConflict     = errors.New("oidc client already exists")
	ErrUnavailable  = errors.New("oidc client dependency unavailable")
)

type Store interface {
	ClientIDExists(ctx context.Context, clientID string) (bool, error)
	Create(ctx context.Context, client *model.OIDCClient) error
	List(ctx context.Context, filter ListFilter) ([]model.OIDCClient, error)
	FindByID(ctx context.Context, id string) (*model.OIDCClient, error)
	Update(ctx context.Context, client *model.OIDCClient) error
	Delete(ctx context.Context, id string) error
}

type Service struct {
	cfg   *config.Config
	store Store
}

type Actor struct {
	UserID  string
	IsAdmin bool
}

type ListFilter struct {
	OwnerUserID string
}

type CreateInput struct {
	Name        string
	RedirectURI string
}

type UpdateInput struct {
	ID          string
	Name        string
	RedirectURI string
	Status      string
}

type Result struct {
	Client       model.OIDCClient `json:"client"`
	ClientSecret string           `json:"clientSecret,omitempty"`
}

func NewService(cfg *config.Config, store Store) *Service {
	return &Service{cfg: cfg, store: store}
}

func (s *Service) Create(ctx context.Context, actor Actor, input CreateInput) (*Result, error) {
	if actor.UserID == "" || !validName(input.Name) || !validRedirectURI(input.RedirectURI) {
		return nil, ErrInvalidInput
	}
	clientID, err := s.uniqueClientID(ctx)
	if err != nil {
		return nil, err
	}
	secret, err := randomSecret(32)
	if err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), s.cfg.Security.PasswordBcryptCost)
	if err != nil {
		return nil, err
	}
	record := &model.OIDCClient{
		ClientID:     clientID,
		ClientSecret: string(hash),
		Name:         strings.TrimSpace(input.Name),
		RedirectURI:  strings.TrimSpace(input.RedirectURI),
		OwnerUserID:  actor.UserID,
		Status:       model.StatusEnabled,
	}
	if err := s.store.Create(ctx, record); err != nil {
		return nil, err
	}
	return &Result{Client: *record, ClientSecret: secret}, nil
}

func (s *Service) List(ctx context.Context, actor Actor) ([]model.OIDCClient, error) {
	if actor.UserID == "" {
		return nil, ErrInvalidInput
	}
	filter := ListFilter{}
	if !actor.IsAdmin {
		filter.OwnerUserID = actor.UserID
	}
	return s.store.List(ctx, filter)
}

func (s *Service) Get(ctx context.Context, actor Actor, id string) (*model.OIDCClient, error) {
	if actor.UserID == "" || strings.TrimSpace(id) == "" {
		return nil, ErrInvalidInput
	}
	record, err := s.store.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if !canAccess(actor, record) {
		return nil, ErrForbidden
	}
	return record, nil
}

func (s *Service) Update(ctx context.Context, actor Actor, input UpdateInput) (*model.OIDCClient, error) {
	if actor.UserID == "" || strings.TrimSpace(input.ID) == "" || !validName(input.Name) ||
		!validRedirectURI(input.RedirectURI) {
		return nil, ErrInvalidInput
	}
	status := strings.TrimSpace(input.Status)
	if status != "" && status != model.StatusEnabled && status != model.StatusDisabled {
		return nil, ErrInvalidInput
	}
	record, err := s.store.FindByID(ctx, input.ID)
	if err != nil {
		return nil, err
	}
	if !canAccess(actor, record) {
		return nil, ErrForbidden
	}
	record.Name = strings.TrimSpace(input.Name)
	record.RedirectURI = strings.TrimSpace(input.RedirectURI)
	if status != "" {
		record.Status = status
	}
	if err := s.store.Update(ctx, record); err != nil {
		return nil, err
	}
	return record, nil
}

func (s *Service) Delete(ctx context.Context, actor Actor, id string) error {
	if actor.UserID == "" || strings.TrimSpace(id) == "" {
		return ErrInvalidInput
	}
	record, err := s.store.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if !canAccess(actor, record) {
		return ErrForbidden
	}
	return s.store.Delete(ctx, id)
}

func (s *Service) ResetSecret(ctx context.Context, actor Actor, id string) (*Result, error) {
	if actor.UserID == "" || strings.TrimSpace(id) == "" {
		return nil, ErrInvalidInput
	}
	record, err := s.store.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if !canAccess(actor, record) {
		return nil, ErrForbidden
	}
	secret, err := randomSecret(32)
	if err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), s.cfg.Security.PasswordBcryptCost)
	if err != nil {
		return nil, err
	}
	record.ClientSecret = string(hash)
	if err := s.store.Update(ctx, record); err != nil {
		return nil, err
	}
	return &Result{Client: *record, ClientSecret: secret}, nil
}

func (s *Service) uniqueClientID(ctx context.Context) (string, error) {
	for i := 0; i < 10; i++ {
		clientID, err := randomFromAlphabet("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 16)
		if err != nil {
			return "", err
		}
		exists, err := s.store.ClientIDExists(ctx, clientID)
		if err != nil {
			return "", err
		}
		if !exists {
			return clientID, nil
		}
	}
	return "", ErrUnavailable
}

func canAccess(actor Actor, record *model.OIDCClient) bool {
	return record != nil && actor.UserID != "" && (actor.IsAdmin || record.OwnerUserID == actor.UserID)
}

func validName(name string) bool {
	name = strings.TrimSpace(name)
	return len(name) > 0 && len(name) <= 64
}

func validRedirectURI(raw string) bool {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(raw))
	return err == nil && parsed.Scheme != "" && parsed.Host != ""
}

func randomSecret(length int) (string, error) {
	return randomFromAlphabet("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*", length)
}

func randomFromAlphabet(alphabet string, length int) (string, error) {
	var builder strings.Builder
	max := big.NewInt(int64(len(alphabet)))
	for i := 0; i < length; i++ {
		index, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		builder.WriteByte(alphabet[index.Int64()])
	}
	return builder.String(), nil
}
