package app

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"strings"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
)

var (
	ErrInvalidInput = errors.New("invalid app input")
	ErrNotFound     = errors.New("app not found")
	ErrForbidden    = errors.New("app access forbidden")
	ErrUnavailable  = errors.New("app dependency unavailable")
)

type Store interface {
	AppIDExists(ctx context.Context, appID string) (bool, error)
	Create(ctx context.Context, app *model.App) error
	List(ctx context.Context, filter ListFilter) ([]model.App, error)
	FindByID(ctx context.Context, id string) (*model.App, error)
	Update(ctx context.Context, app *model.App) error
	Delete(ctx context.Context, id string) error
}

type Service struct {
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
	Name string
}

type UpdateInput struct {
	ID     string
	Name   string
	Status string
}

type Result struct {
	App       model.App `json:"app"`
	AppSecret string    `json:"appSecret,omitempty"`
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

func (s *Service) Create(ctx context.Context, actor Actor, input CreateInput) (*Result, error) {
	if actor.UserID == "" || !validName(input.Name) {
		return nil, ErrInvalidInput
	}
	appID, err := s.uniqueAppID(ctx)
	if err != nil {
		return nil, err
	}
	secret, err := randomSecret(16)
	if err != nil {
		return nil, err
	}
	record := &model.App{
		AppID:       appID,
		Name:        strings.TrimSpace(input.Name),
		SecretHash:  secret,
		OwnerUserID: actor.UserID,
		Status:      model.StatusEnabled,
	}
	if err := s.store.Create(ctx, record); err != nil {
		return nil, err
	}
	return &Result{App: *record, AppSecret: secret}, nil
}

func (s *Service) List(ctx context.Context, actor Actor) ([]model.App, error) {
	if actor.UserID == "" {
		return nil, ErrInvalidInput
	}
	filter := ListFilter{}
	if !actor.IsAdmin {
		filter.OwnerUserID = actor.UserID
	}
	return s.store.List(ctx, filter)
}

func (s *Service) Get(ctx context.Context, actor Actor, id string) (*model.App, error) {
	record, err := s.store.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if !canAccess(actor, record) {
		return nil, ErrForbidden
	}
	return record, nil
}

func (s *Service) Update(ctx context.Context, actor Actor, input UpdateInput) (*model.App, error) {
	if strings.TrimSpace(input.ID) == "" || !validName(input.Name) {
		return nil, ErrInvalidInput
	}
	record, err := s.store.FindByID(ctx, input.ID)
	if err != nil {
		return nil, err
	}
	if !canAccess(actor, record) {
		return nil, ErrForbidden
	}
	status := strings.TrimSpace(input.Status)
	if status != "" && status != model.StatusEnabled && status != model.StatusDisabled {
		return nil, ErrInvalidInput
	}
	record.Name = strings.TrimSpace(input.Name)
	if status != "" {
		record.Status = status
	}
	if err := s.store.Update(ctx, record); err != nil {
		return nil, err
	}
	return record, nil
}

func (s *Service) Delete(ctx context.Context, actor Actor, id string) error {
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
	record, err := s.store.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if !canAccess(actor, record) {
		return nil, ErrForbidden
	}
	secret, err := randomSecret(16)
	if err != nil {
		return nil, err
	}
	record.SecretHash = secret
	if err := s.store.Update(ctx, record); err != nil {
		return nil, err
	}
	return &Result{App: *record, AppSecret: secret}, nil
}

func (s *Service) uniqueAppID(ctx context.Context) (string, error) {
	for i := 0; i < 10; i++ {
		appID, err := randomFromAlphabet("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 8)
		if err != nil {
			return "", err
		}
		exists, err := s.store.AppIDExists(ctx, appID)
		if err != nil {
			return "", err
		}
		if !exists {
			return appID, nil
		}
	}
	return "", ErrUnavailable
}

func canAccess(actor Actor, record *model.App) bool {
	return record != nil && actor.UserID != "" && (actor.IsAdmin || record.OwnerUserID == actor.UserID)
}

func validName(name string) bool {
	name = strings.TrimSpace(name)
	return len(name) > 0 && len(name) <= 64
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
