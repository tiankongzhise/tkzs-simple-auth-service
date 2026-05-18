package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFileReadsExampleConfig(t *testing.T) {
	t.Setenv("AUTH_LIMIT_SERVER_HOST", "http://127.0.0.1:8080")
	t.Setenv("AUTH_LIMIT_SERVER_PORT", "8080")
	t.Setenv("AUTH_LIMIT_RUN_MODE", "dev")
	t.Setenv("AUTH_LIMIT_SERVICE_CODE", "authlimit")
	t.Setenv("AUTH_LIMIT_SERVICE_NAME", "鉴权限流核心服务")
	t.Setenv("AUTH_LIMIT_SERVICE_VERSION", "v0.1.0")
	t.Setenv("AUTH_LIMIT_POSTGRES_DSN", "host=127.0.0.1 port=5432 user=postgres password=secret dbname=auth_limit_db sslmode=disable")
	t.Setenv("AUTH_LIMIT_REDIS_ADDR", "127.0.0.1:6379")
	t.Setenv("AUTH_LIMIT_REDIS_USERNAME", "authlimit_user")
	t.Setenv("AUTH_LIMIT_REDIS_PASSWORD", "secret")
	t.Setenv("AUTH_LIMIT_REDIS_DB", "0")
	t.Setenv("AUTH_LIMIT_JWT_ISSUER", "authlimit")
	t.Setenv("AUTH_LIMIT_JWT_PRIVATE_KEY_PATH", "./certs/jwt_private.pem")
	t.Setenv("AUTH_LIMIT_JWT_PUBLIC_KEY_PATH", "./certs/jwt_public.pem")
	t.Setenv("AUTH_LIMIT_OIDC_ISSUER", "http://127.0.0.1:8080")

	cfg, err := LoadFile(filepath.Join("..", "config.example.yaml"))
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}

	if cfg.Service.Code != "authlimit" {
		t.Fatalf("service code = %q", cfg.Service.Code)
	}
	if cfg.Server.Port != 8080 {
		t.Fatalf("server port = %d", cfg.Server.Port)
	}
	if cfg.Redis.DialTimeout != 500*time.Millisecond {
		t.Fatalf("redis dial timeout = %s", cfg.Redis.DialTimeout)
	}
	if cfg.Redis.Password != "secret" {
		t.Fatalf("redis password = %q", cfg.Redis.Password)
	}
	if len(cfg.Limit.Dimensions) != 3 || cfg.Limit.Dimensions[0] != "ip" {
		t.Fatalf("dimensions = %#v", cfg.Limit.Dimensions)
	}
}

func TestValidateRejectsInvalidServiceCode(t *testing.T) {
	cfg := Default()
	cfg.Service.Code = "Auth-Limit"

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() expected error")
	}
}

func TestLoadUsesEnvConfigPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("service:\n  code: \"demo001\"\n"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv(EnvConfigPath, path)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Service.Code != "demo001" {
		t.Fatalf("service code = %q", cfg.Service.Code)
	}
}

func TestLoadEnvFileSetsMissingValuesAndExpandsReferences(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	_ = os.Unsetenv("TKZS_TEST_BASE_HOST")
	_ = os.Unsetenv("TKZS_TEST_POSTGRES_DSN")

	content := "TKZS_TEST_BASE_HOST=127.0.0.1\nTKZS_TEST_POSTGRES_DSN=\"host=${TKZS_TEST_BASE_HOST} password=secret\"\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	if err := LoadEnvFile(path); err != nil {
		t.Fatalf("LoadEnvFile() error = %v", err)
	}
	if got := os.Getenv("TKZS_TEST_POSTGRES_DSN"); got != "host=127.0.0.1 password=secret" {
		t.Fatalf("TKZS_TEST_POSTGRES_DSN = %q", got)
	}
}

func TestLoadEnvFileDoesNotOverrideExistingValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	t.Setenv("TKZS_TEST_EXISTING", "keep")

	if err := os.WriteFile(path, []byte("TKZS_TEST_EXISTING=replace\n"), 0600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	if err := LoadEnvFile(path); err != nil {
		t.Fatalf("LoadEnvFile() error = %v", err)
	}
	if got := os.Getenv("TKZS_TEST_EXISTING"); got != "keep" {
		t.Fatalf("TKZS_TEST_EXISTING = %q", got)
	}
}

func TestLoadFileMergesDefaultsAndExpandsEnvironment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	t.Setenv("TKZS_TEST_SERVICE_CODE", "demo001")
	t.Setenv("TKZS_TEST_REDIS_ADDR", "redis.local:6379")

	content := "service:\n  code: \"${TKZS_TEST_SERVICE_CODE}\"\nredis:\n  addr: \"${TKZS_TEST_REDIS_ADDR}\"\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if cfg.Service.Code != "demo001" {
		t.Fatalf("service code = %q", cfg.Service.Code)
	}
	if cfg.Redis.Addr != "redis.local:6379" {
		t.Fatalf("redis addr = %q", cfg.Redis.Addr)
	}
	if cfg.Server.Port != 8080 {
		t.Fatalf("default server port = %d", cfg.Server.Port)
	}
}

func TestLoadFileSupportsAuthLimitEnvironmentOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	t.Setenv("AUTH_LIMIT_SERVICE_CODE", "envdemo")

	if err := os.WriteFile(path, []byte("service:\n  code: \"filedemo\"\n"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if cfg.Service.Code != "envdemo" {
		t.Fatalf("service code = %q", cfg.Service.Code)
	}
}
