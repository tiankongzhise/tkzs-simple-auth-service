package model

import (
	"sync"
	"testing"

	"gorm.io/gorm/schema"
)

func TestAllModelsIncludesCoreTables(t *testing.T) {
	models := AllModels()
	if len(models) != 16 {
		t.Fatalf("model count = %d", len(models))
	}

	tables := map[string]bool{}
	for _, item := range models {
		table, ok := item.(interface{ TableName() string })
		if !ok {
			t.Fatalf("%T does not implement TableName", item)
		}
		tables[table.TableName()] = true
	}

	for _, name := range []string{
		"users", "apps", "roles", "permissions", "auth_tokens",
		"services", "rate_limit_rules", "blacklists", "whitelists",
		"oidc_clients", "oidc_auth_codes",
		"operation_logs", "auth_logs", "limit_logs", "health_check_logs",
		"limit_statistics",
	} {
		if !tables[name] {
			t.Fatalf("missing table %q", name)
		}
	}
}

func TestBaseModelBeforeCreateSetsID(t *testing.T) {
	model := &BaseModel{}
	if err := model.BeforeCreate(nil); err != nil {
		t.Fatalf("BeforeCreate() error = %v", err)
	}
	if model.ID == "" {
		t.Fatal("id is empty")
	}
}

func TestAuthTokenAppRelationUsesAppRecordID(t *testing.T) {
	parsed, err := schema.Parse(&AuthToken{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatalf("parse AuthToken schema: %v", err)
	}

	relation, ok := parsed.Relationships.Relations["App"]
	if !ok {
		t.Fatal("AuthToken.App relation not found")
	}
	if relation.Type != schema.BelongsTo {
		t.Fatalf("AuthToken.App relation type = %s, want %s", relation.Type, schema.BelongsTo)
	}
	if len(relation.References) != 1 {
		t.Fatalf("AuthToken.App references = %d, want 1", len(relation.References))
	}
	reference := relation.References[0]
	if reference.PrimaryKey == nil || reference.PrimaryKey.Schema.Name != "App" || reference.PrimaryKey.DBName != "id" {
		t.Fatalf("AuthToken.App primary key = %#v, want App.id", reference.PrimaryKey)
	}
	if reference.ForeignKey == nil || reference.ForeignKey.Schema.Name != "AuthToken" ||
		reference.ForeignKey.Name != "AppRecordID" || reference.ForeignKey.DBName != "app_id" {
		t.Fatalf("AuthToken.App foreign key = %#v, want AuthToken.AppRecordID/app_id", reference.ForeignKey)
	}
}
