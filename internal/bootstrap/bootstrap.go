package bootstrap

import (
	"errors"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	DefaultAdminUsername = "admin"
	DefaultAdminPassword = "Zqlt_123456789"
)

func Initialize(db *gorm.DB, cfg *config.Config) error {
	return db.Transaction(func(tx *gorm.DB) error {
		permissions, err := ensurePermissions(tx)
		if err != nil {
			return err
		}
		role, err := ensureAdminRole(tx, permissions)
		if err != nil {
			return err
		}
		return ensureSuperAdmin(tx, cfg.Security.PasswordBcryptCost, role)
	})
}

func ensurePermissions(tx *gorm.DB) ([]model.Permission, error) {
	seeds := SystemPermissions()
	permissions := make([]model.Permission, 0, len(seeds))
	for _, seed := range seeds {
		permission := model.Permission{
			Code:   seed.Code,
			Name:   seed.Name,
			Module: seed.Module,
			Action: seed.Action,
		}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "code"}},
			DoNothing: true,
		}).Create(&permission).Error; err != nil {
			return nil, err
		}
		if err := tx.Where("code = ?", seed.Code).First(&permission).Error; err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}
	return permissions, nil
}

func ensureAdminRole(tx *gorm.DB, permissions []model.Permission) (*model.Role, error) {
	seed := AdminRole()
	var role model.Role
	err := tx.Where("code = ?", seed.Code).First(&role).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		role = seed
		if err := tx.Create(&role).Error; err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	if !role.System {
		if err := tx.Model(&role).Update("system", true).Error; err != nil {
			return nil, err
		}
		role.System = true
	}
	if len(permissions) > 0 {
		if err := tx.Model(&role).Association("Permissions").Append(permissions); err != nil {
			return nil, err
		}
	}
	return &role, nil
}

func ensureSuperAdmin(tx *gorm.DB, cost int, role *model.Role) error {
	var admin model.User
	err := tx.Where("username = ?", DefaultAdminUsername).First(&admin).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		hash, err := bcrypt.GenerateFromPassword([]byte(DefaultAdminPassword), cost)
		if err != nil {
			return err
		}
		admin = model.User{
			Username:     DefaultAdminUsername,
			PasswordHash: string(hash),
			DisplayName:  "超级管理员",
			Status:       model.StatusEnabled,
			IsSuperAdmin: true,
		}
		if err := tx.Create(&admin).Error; err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if !admin.IsSuperAdmin {
		if err := tx.Model(&admin).Update("is_super_admin", true).Error; err != nil {
			return err
		}
		admin.IsSuperAdmin = true
	}

	if role != nil {
		if err := tx.Model(&admin).Association("Roles").Append(role); err != nil {
			return err
		}
	}
	return nil
}
