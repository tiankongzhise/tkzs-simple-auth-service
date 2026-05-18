package database

import (
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"gorm.io/gorm"
)

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(model.AllModels()...)
}
