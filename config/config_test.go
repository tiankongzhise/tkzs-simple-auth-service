package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFileReadsExampleConfig(t *testing.T) {
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
