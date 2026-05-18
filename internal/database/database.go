package database

import (
	"database/sql"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func Open(cfg config.PostgresConfig) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(cfg.DSN), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	if err := configurePool(db, cfg); err != nil {
		return nil, err
	}
	return db, nil
}

func configurePool(db *gorm.DB, cfg config.PostgresConfig) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	ApplyPoolConfig(sqlDB, cfg)
	return nil
}

func ApplyPoolConfig(db *sql.DB, cfg config.PostgresConfig) {
	if cfg.MaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns > 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetimeSeconds > 0 {
		db.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetimeSeconds) * time.Second)
	}
}
