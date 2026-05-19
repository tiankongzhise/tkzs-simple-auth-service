package user

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"unicode"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
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
}

type Service struct {
	cfg   *config.Config
	store Store
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

func NewService(cfg *config.Config, store Store) *Service {
	return &Service{cfg: cfg, store: store}
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
