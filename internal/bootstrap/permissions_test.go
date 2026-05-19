package bootstrap

import (
	"strings"
	"testing"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestSystemPermissionsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, permission := range SystemPermissions() {
		if permission.Code == "" || permission.Name == "" || permission.Module == "" || permission.Action == "" {
			t.Fatalf("invalid permission seed: %#v", permission)
		}
		if seen[permission.Code] {
			t.Fatalf("duplicate permission code %q", permission.Code)
		}
		seen[permission.Code] = true
	}
}

func TestAdminRoleSeed(t *testing.T) {
	role := AdminRole()
	if role.Code != "admin" || !role.System {
		t.Fatalf("admin role = %#v", role)
	}
}

func TestQueryPermissionByCodeDoesNotCarryPrimaryKey(t *testing.T) {
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  "host=127.0.0.1 user=test dbname=test sslmode=disable",
		PreferSimpleProtocol: true,
	}), &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatalf("open dry-run db: %v", err)
	}

	permission := model.Permission{}
	permission.ID = "stale-id"
	stmt := queryPermissionByCode(db, "user:manage", &permission).Statement
	sql := stmt.SQL.String()

	if strings.Contains(sql, `AND "permissions"."id"`) {
		t.Fatalf("query includes stale primary key: %s", sql)
	}
	for _, variable := range stmt.Vars {
		if variable == "stale-id" {
			t.Fatalf("query vars include stale primary key: %#v", stmt.Vars)
		}
	}
	if !strings.Contains(sql, "code =") {
		t.Fatalf("query does not filter by code: %s", sql)
	}
}
