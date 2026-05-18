package model

import "testing"

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
