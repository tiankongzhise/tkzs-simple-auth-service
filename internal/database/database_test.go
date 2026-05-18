package database

import (
	"database/sql"
	"testing"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
)

func TestApplyPoolConfigAllowsZeroValues(t *testing.T) {
	db := &sql.DB{}

	ApplyPoolConfig(db, config.PostgresConfig{})
}
