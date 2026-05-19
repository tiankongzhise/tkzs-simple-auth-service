package role

import (
	"context"
	"errors"
	"strings"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
)

var (
	ErrInvalidInput = errors.New("invalid role input")
	ErrNotFound     = errors.New("role not found")
	ErrForbidden    = errors.New("role access forbidden")
	ErrConflict     = errors.New("role already exists")
)

type Store interface {
	RoleCodeExists(ctx context.Context, code string) (bool, error)
	Create(ctx context.Context, role *model.Role, permissionIDs []string) error
	List(ctx context.Context, filter ListFilter) ([]model.Role, error)
	FindByID(ctx context.Context, id string) (*model.Role, error)
	Update(ctx context.Context, role *model.Role, permissionIDs []string) error
	Delete(ctx context.Context, id string) error
	ListPermissions(ctx context.Context) ([]model.Permission, error)
	FindPermissionsByIDs(ctx context.Context, ids []string) ([]model.Permission, error)
}

type Service struct {
	store Store
}

type Actor struct {
	UserID      string
	IsAdmin     bool
	Permissions []string
}

type ListFilter struct {
	OwnerUserID string
}

type CreateInput struct {
	Code          string
	Name          string
	Description   string
	PermissionIDs []string
}

type UpdateInput struct {
	ID            string
	Name          string
	Description   string
	PermissionIDs []string
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

func (s *Service) ListPermissions(ctx context.Context) ([]model.Permission, error) {
	return s.store.ListPermissions(ctx)
}

func (s *Service) Create(ctx context.Context, actor Actor, input CreateInput) (*model.Role, error) {
	code := strings.TrimSpace(input.Code)
	name := strings.TrimSpace(input.Name)
	if actor.UserID == "" || !validCode(code) || name == "" || len(name) > 64 {
		return nil, ErrInvalidInput
	}
	if err := s.ensureAssignablePermissions(ctx, actor, input.PermissionIDs); err != nil {
		return nil, err
	}
	exists, err := s.store.RoleCodeExists(ctx, code)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrConflict
	}
	ownerID := actor.UserID
	role := &model.Role{
		Code:        code,
		Name:        name,
		Description: strings.TrimSpace(input.Description),
		OwnerUserID: &ownerID,
		System:      false,
	}
	if err := s.store.Create(ctx, role, input.PermissionIDs); err != nil {
		return nil, err
	}
	return role, nil
}

func (s *Service) List(ctx context.Context, actor Actor) ([]model.Role, error) {
	if actor.UserID == "" {
		return nil, ErrInvalidInput
	}
	filter := ListFilter{}
	if !actor.IsAdmin {
		filter.OwnerUserID = actor.UserID
	}
	return s.store.List(ctx, filter)
}

func (s *Service) Get(ctx context.Context, actor Actor, id string) (*model.Role, error) {
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

func (s *Service) Update(ctx context.Context, actor Actor, input UpdateInput) (*model.Role, error) {
	if actor.UserID == "" || strings.TrimSpace(input.ID) == "" || strings.TrimSpace(input.Name) == "" {
		return nil, ErrInvalidInput
	}
	if len(strings.TrimSpace(input.Name)) > 64 {
		return nil, ErrInvalidInput
	}
	if err := s.ensureAssignablePermissions(ctx, actor, input.PermissionIDs); err != nil {
		return nil, err
	}
	record, err := s.store.FindByID(ctx, input.ID)
	if err != nil {
		return nil, err
	}
	if !canAccess(actor, record) || record.System {
		return nil, ErrForbidden
	}
	record.Name = strings.TrimSpace(input.Name)
	record.Description = strings.TrimSpace(input.Description)
	if err := s.store.Update(ctx, record, input.PermissionIDs); err != nil {
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
	if !canAccess(actor, record) || record.System || record.Code == model.RoleAdminCode {
		return ErrForbidden
	}
	return s.store.Delete(ctx, id)
}

func (s *Service) ensureAssignablePermissions(ctx context.Context, actor Actor, ids []string) error {
	if len(ids) == 0 || actor.IsAdmin {
		return nil
	}
	permissions, err := s.store.FindPermissionsByIDs(ctx, ids)
	if err != nil {
		return err
	}
	if len(permissions) != len(ids) {
		return ErrInvalidInput
	}
	owned := map[string]bool{}
	for _, permission := range actor.Permissions {
		owned[permission] = true
	}
	for _, permission := range permissions {
		if !owned[permission.Code] {
			return ErrForbidden
		}
	}
	return nil
}

func canAccess(actor Actor, record *model.Role) bool {
	if record == nil || actor.UserID == "" {
		return false
	}
	if actor.IsAdmin || record.System {
		return true
	}
	return record.OwnerUserID != nil && *record.OwnerUserID == actor.UserID
}

func validCode(code string) bool {
	if len(code) < 3 || len(code) > 64 {
		return false
	}
	for _, r := range code {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == ':' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}
