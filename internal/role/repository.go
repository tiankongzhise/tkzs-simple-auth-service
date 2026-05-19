package role

import (
	"context"
	"errors"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"gorm.io/gorm"
)

type GormStore struct {
	db *gorm.DB
}

func NewGormStore(db *gorm.DB) *GormStore {
	return &GormStore{db: db}
}

func (s *GormStore) RoleCodeExists(ctx context.Context, code string) (bool, error) {
	var count int64
	if err := s.db.WithContext(ctx).Model(&model.Role{}).Where("code = ?", code).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *GormStore) Create(ctx context.Context, role *model.Role, permissionIDs []string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(role).Error; err != nil {
			return err
		}
		return replacePermissions(tx, role, permissionIDs)
	})
}

func (s *GormStore) List(ctx context.Context, filter ListFilter) ([]model.Role, error) {
	var roles []model.Role
	query := s.db.WithContext(ctx).Preload("Permissions").Order("created_at DESC")
	if filter.OwnerUserID != "" {
		query = query.Where("system = ? OR owner_user_id = ?", true, filter.OwnerUserID)
	}
	if err := query.Find(&roles).Error; err != nil {
		return nil, err
	}
	return roles, nil
}

func (s *GormStore) FindByID(ctx context.Context, id string) (*model.Role, error) {
	var role model.Role
	err := s.db.WithContext(ctx).Preload("Permissions").Where("id = ?", id).First(&role).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &role, nil
}

func (s *GormStore) Update(ctx context.Context, role *model.Role, permissionIDs []string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(role).Error; err != nil {
			return err
		}
		return replacePermissions(tx, role, permissionIDs)
	})
}

func (s *GormStore) Delete(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&model.Role{}, "id = ?", id).Error
}

func (s *GormStore) ListPermissions(ctx context.Context) ([]model.Permission, error) {
	var permissions []model.Permission
	err := s.db.WithContext(ctx).Order("module ASC, action ASC, code ASC").Find(&permissions).Error
	if err != nil {
		return nil, err
	}
	return permissions, nil
}

func (s *GormStore) FindPermissionsByIDs(ctx context.Context, ids []string) ([]model.Permission, error) {
	var permissions []model.Permission
	if len(ids) == 0 {
		return permissions, nil
	}
	err := s.db.WithContext(ctx).Where("id IN ?", ids).Find(&permissions).Error
	if err != nil {
		return nil, err
	}
	return permissions, nil
}

func (s *GormStore) FindUserByID(ctx context.Context, id string) (*model.User, error) {
	var user model.User
	err := s.db.WithContext(ctx).Preload("Roles").Where("id = ?", id).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *GormStore) FindAppByID(ctx context.Context, id string) (*model.App, error) {
	var app model.App
	err := s.db.WithContext(ctx).Preload("Roles").Where("id = ?", id).First(&app).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &app, nil
}

func (s *GormStore) FindRolesByIDs(ctx context.Context, ids []string) ([]model.Role, error) {
	var roles []model.Role
	if len(ids) == 0 {
		return roles, nil
	}
	err := s.db.WithContext(ctx).Preload("Permissions").Where("id IN ?", ids).Find(&roles).Error
	if err != nil {
		return nil, err
	}
	return roles, nil
}

func (s *GormStore) ReplaceUserRoles(ctx context.Context, user *model.User, roles []model.Role) error {
	return s.db.WithContext(ctx).Model(user).Association("Roles").Replace(roles)
}

func (s *GormStore) ReplaceAppRoles(ctx context.Context, app *model.App, roles []model.Role) error {
	return s.db.WithContext(ctx).Model(app).Association("Roles").Replace(roles)
}

func replacePermissions(tx *gorm.DB, role *model.Role, permissionIDs []string) error {
	if len(permissionIDs) == 0 {
		return tx.Model(role).Association("Permissions").Replace([]model.Permission{})
	}
	var permissions []model.Permission
	if err := tx.Where("id IN ?", permissionIDs).Find(&permissions).Error; err != nil {
		return err
	}
	if len(permissions) != len(permissionIDs) {
		return ErrInvalidInput
	}
	return tx.Model(role).Association("Permissions").Replace(permissions)
}
