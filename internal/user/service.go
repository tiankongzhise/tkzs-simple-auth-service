package user

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"unicode"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/redisx"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidInput = errors.New("invalid user input")
	ErrNotFound     = errors.New("user not found")
	ErrForbidden    = errors.New("user access forbidden")
	ErrConflict     = errors.New("user already exists")
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{3,20}$`)

type Store interface {
	UsernameExists(ctx context.Context, username string) (bool, error)
	Create(ctx context.Context, user *model.User) error
	List(ctx context.Context, filter ListFilter) ([]model.User, error)
	FindByID(ctx context.Context, id string) (*model.User, error)
	Update(ctx context.Context, user *model.User) error
	Delete(ctx context.Context, id string) error
}

type Cache interface {
	KeyBuilder() *redisx.KeyBuilder
	Del(ctx context.Context, keys ...string) error
}

type Service struct {
	cfg   *config.Config
	store Store
	cache Cache
}

type Option func(*Service)

func WithCache(cache Cache) Option {
	return func(s *Service) {
		s.cache = cache
	}
}

type Actor struct {
	UserID    string
	CanManage bool
}

type ListFilter struct {
	UserID string
}

type RegisterInput struct {
	Username    string
	Password    string
	DisplayName string
}

type UpdateInput struct {
	ID          string
	DisplayName string
}

type UpdateStatusInput struct {
	ID     string
	Status string
}

type UpdatePasswordInput struct {
	ID          string
	OldPassword string
	NewPassword string
}

func NewService(cfg *config.Config, store Store, options ...Option) *Service {
	service := &Service{cfg: cfg, store: store}
	for _, option := range options {
		option(service)
	}
	return service
}

func (s *Service) Register(ctx context.Context, input RegisterInput) (*model.User, error) {
	username := strings.TrimSpace(input.Username)
	if !validUsername(username) || !validPassword(input.Password) {
		return nil, ErrInvalidInput
	}
	exists, err := s.store.UsernameExists(ctx, username)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrConflict
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), s.cfg.Security.PasswordBcryptCost)
	if err != nil {
		return nil, err
	}
	record := &model.User{
		Username:     username,
		PasswordHash: string(hash),
		DisplayName:  strings.TrimSpace(input.DisplayName),
		Status:       model.StatusEnabled,
	}
	if record.DisplayName == "" {
		record.DisplayName = username
	}
	if err := s.store.Create(ctx, record); err != nil {
		return nil, err
	}
	return record, nil
}

func (s *Service) List(ctx context.Context, actor Actor) ([]model.User, error) {
	if actor.UserID == "" {
		return nil, ErrInvalidInput
	}
	filter := ListFilter{}
	if !actor.CanManage {
		filter.UserID = actor.UserID
	}
	return s.store.List(ctx, filter)
}

func (s *Service) Get(ctx context.Context, actor Actor, id string) (*model.User, error) {
	if actor.UserID == "" || strings.TrimSpace(id) == "" {
		return nil, ErrInvalidInput
	}
	record, err := s.store.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if !actor.CanManage && record.ID != actor.UserID {
		return nil, ErrForbidden
	}
	return record, nil
}

func (s *Service) Update(ctx context.Context, actor Actor, input UpdateInput) (*model.User, error) {
	if actor.UserID == "" || strings.TrimSpace(input.ID) == "" {
		return nil, ErrInvalidInput
	}
	record, err := s.store.FindByID(ctx, input.ID)
	if err != nil {
		return nil, err
	}
	if !canAccess(actor, record) {
		return nil, ErrForbidden
	}
	displayName := strings.TrimSpace(input.DisplayName)
	if len(displayName) > 64 {
		return nil, ErrInvalidInput
	}
	record.DisplayName = displayName
	if record.DisplayName == "" {
		record.DisplayName = record.Username
	}
	if err := s.store.Update(ctx, record); err != nil {
		return nil, err
	}
	return record, nil
}

func (s *Service) UpdateStatus(ctx context.Context, actor Actor, input UpdateStatusInput) (*model.User, error) {
	if !actor.CanManage || actor.UserID == "" || strings.TrimSpace(input.ID) == "" {
		return nil, ErrForbidden
	}
	status := strings.TrimSpace(input.Status)
	if status != model.StatusEnabled && status != model.StatusDisabled {
		return nil, ErrInvalidInput
	}
	record, err := s.store.FindByID(ctx, input.ID)
	if err != nil {
		return nil, err
	}
	if record.ID == actor.UserID {
		return nil, ErrForbidden
	}
	record.Status = status
	if err := s.store.Update(ctx, record); err != nil {
		return nil, err
	}
	return record, nil
}

func (s *Service) UpdatePassword(ctx context.Context, actor Actor, input UpdatePasswordInput) error {
	if actor.UserID == "" || strings.TrimSpace(input.ID) == "" || !validPassword(input.NewPassword) {
		return ErrInvalidInput
	}
	record, err := s.store.FindByID(ctx, input.ID)
	if err != nil {
		return err
	}
	if !canAccess(actor, record) {
		return ErrForbidden
	}
	if !actor.CanManage {
		if strings.TrimSpace(input.OldPassword) == "" {
			return ErrInvalidInput
		}
		if bcrypt.CompareHashAndPassword([]byte(record.PasswordHash), []byte(input.OldPassword)) != nil {
			return ErrInvalidInput
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), s.cfg.Security.PasswordBcryptCost)
	if err != nil {
		return err
	}
	record.PasswordHash = string(hash)
	if err := s.store.Update(ctx, record); err != nil {
		return err
	}
	return s.invalidatePasswordCache(ctx, record.ID)
}

func (s *Service) Delete(ctx context.Context, actor Actor, id string) error {
	if !actor.CanManage || actor.UserID == "" || strings.TrimSpace(id) == "" {
		return ErrForbidden
	}
	record, err := s.store.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if record.ID == actor.UserID {
		return ErrForbidden
	}
	return s.store.Delete(ctx, id)
}

func (s *Service) invalidatePasswordCache(ctx context.Context, userID string) error {
	if s.cache == nil {
		return nil
	}
	key, err := s.cache.KeyBuilder().Build("user", "password", userID)
	if err != nil {
		return err
	}
	return s.cache.Del(ctx, key)
}

func canAccess(actor Actor, record *model.User) bool {
	return record != nil && actor.UserID != "" && (actor.CanManage || record.ID == actor.UserID)
}

func validUsername(username string) bool {
	return usernamePattern.MatchString(username)
}

func validPassword(password string) bool {
	if len(password) < 8 || len(password) > 20 {
		return false
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	return hasUpper && hasLower && hasDigit && hasSpecial
}
