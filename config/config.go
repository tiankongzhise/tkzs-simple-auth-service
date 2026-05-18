package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const EnvConfigPath = "AUTH_LIMIT_CONFIG"

type Config struct {
	Server   ServerConfig
	Service  ServiceConfig
	Postgres PostgresConfig
	Redis    RedisConfig
	JWT      JWTConfig
	OIDC     OIDCConfig
	Limit    LimitConfig
	Security SecurityConfig
	Health   HealthConfig
	UI       UIConfig
}

type ServerConfig struct {
	Host    string
	Port    int
	RunMode string
}

type ServiceConfig struct {
	Code    string
	Name    string
	Version string
}

type PostgresConfig struct {
	DSN                    string
	MaxOpenConns           int
	MaxIdleConns           int
	ConnMaxLifetimeSeconds int
}

type RedisConfig struct {
	Addr         string
	Username     string
	Password     string
	DB           int
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	PoolSize     int
}

type JWTConfig struct {
	Issuer                   string
	AccessExpireMinutes      int
	RefreshExpireHours       int
	AutoRefreshBeforeMinutes int
	PrivateKeyPath           string
	PublicKeyPath            string
	RefreshRotate            bool
}

type OIDCConfig struct {
	Enable                         bool
	Issuer                         string
	AuthorizationCodeExpireMinutes int
	AccessTokenExpireMinutes       int
	RefreshTokenExpireHours        int
}

type LimitConfig struct {
	Enable                     bool
	DefaultCapacity            int
	DefaultRatePerSecond       int
	Dimensions                 []string
	LocalFallbackCapacity      int
	LocalFallbackRatePerSecond int
}

type SecurityConfig struct {
	AuthFailMaxCount        int
	AuthFailWindowMinutes   int
	LockMinutes             int
	M2MTimestampSkewSeconds int
	PasswordBcryptCost      int
}

type HealthConfig struct {
	DefaultPath            string
	DefaultIntervalSeconds int
	MinIntervalSeconds     int
	MaxIntervalSeconds     int
	UnhealthyThreshold     int
}

type UIConfig struct {
	Enable     bool
	PathPrefix string
}

func Load() (*Config, error) {
	if err := LoadEnvFile(".env"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	path := os.Getenv(EnvConfigPath)
	if path == "" {
		path = "./config.yaml"
	}
	return LoadFile(path)
}

func LoadFile(path string) (*Config, error) {
	if err := LoadEnvFile(".env"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	cfg := Default()
	values, err := readSimpleYAML(path)
	if err != nil {
		return nil, err
	}
	applyValues(cfg, values)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func Default() *Config {
	return &Config{
		Server:   ServerConfig{Host: "http://127.0.0.1:8080", Port: 8080, RunMode: "dev"},
		Service:  ServiceConfig{Code: "authlimit", Name: "鉴权限流核心服务", Version: "v0.1.0"},
		Postgres: PostgresConfig{MaxOpenConns: 20, MaxIdleConns: 10, ConnMaxLifetimeSeconds: 300},
		Redis: RedisConfig{
			Addr: "127.0.0.1:6379", DB: 0, DialTimeout: 500 * time.Millisecond,
			ReadTimeout: time.Second, WriteTimeout: time.Second, PoolSize: 20,
		},
		JWT: JWTConfig{
			Issuer: "authlimit", AccessExpireMinutes: 30, RefreshExpireHours: 24,
			AutoRefreshBeforeMinutes: 5, PrivateKeyPath: "./certs/jwt_private.pem",
			PublicKeyPath: "./certs/jwt_public.pem", RefreshRotate: true,
		},
		OIDC: OIDCConfig{
			Enable: true, Issuer: "http://127.0.0.1:8080",
			AuthorizationCodeExpireMinutes: 5, AccessTokenExpireMinutes: 30, RefreshTokenExpireHours: 24,
		},
		Limit: LimitConfig{
			Enable: true, DefaultCapacity: 100, DefaultRatePerSecond: 10,
			Dimensions:            []string{"ip", "user_id", "app_id"},
			LocalFallbackCapacity: 50, LocalFallbackRatePerSecond: 5,
		},
		Security: SecurityConfig{
			AuthFailMaxCount: 5, AuthFailWindowMinutes: 10, LockMinutes: 15,
			M2MTimestampSkewSeconds: 30, PasswordBcryptCost: 12,
		},
		Health: HealthConfig{
			DefaultPath: "/health", DefaultIntervalSeconds: 30, MinIntervalSeconds: 10,
			MaxIntervalSeconds: 300, UnhealthyThreshold: 3,
		},
		UI: UIConfig{Enable: true, PathPrefix: "/ui/"},
	}
}

func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	if ok, _ := regexp.MatchString(`^[a-z0-9]{3,16}$`, c.Service.Code); !ok {
		return fmt.Errorf("service.code must match ^[a-z0-9]{3,16}$")
	}
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535")
	}
	if c.Server.RunMode == "prod" {
		if !strings.HasPrefix(c.Server.Host, "https://") {
			return fmt.Errorf("server.host must use https in prod")
		}
		if c.OIDC.Enable && !strings.HasPrefix(c.OIDC.Issuer, "https://") {
			return fmt.Errorf("oidc.issuer must use https in prod")
		}
	}
	if c.JWT.AccessExpireMinutes <= 0 || c.JWT.RefreshExpireHours <= 0 || c.JWT.AutoRefreshBeforeMinutes <= 0 {
		return fmt.Errorf("jwt expiration values must be positive")
	}
	if c.Limit.DefaultCapacity <= 0 || c.Limit.DefaultRatePerSecond <= 0 {
		return fmt.Errorf("limit defaults must be positive")
	}
	if c.Limit.LocalFallbackCapacity <= 0 || c.Limit.LocalFallbackRatePerSecond <= 0 {
		return fmt.Errorf("limit local fallback values must be positive")
	}
	if c.Security.AuthFailMaxCount <= 0 || c.Security.AuthFailWindowMinutes <= 0 || c.Security.LockMinutes <= 0 {
		return fmt.Errorf("security lock and fail values must be positive")
	}
	if c.Security.M2MTimestampSkewSeconds <= 0 || c.Security.PasswordBcryptCost <= 0 {
		return fmt.Errorf("security m2m skew and bcrypt cost must be positive")
	}
	if c.Health.DefaultIntervalSeconds <= 0 || c.Health.MinIntervalSeconds <= 0 ||
		c.Health.MaxIntervalSeconds <= 0 || c.Health.UnhealthyThreshold <= 0 {
		return fmt.Errorf("health values must be positive")
	}
	if c.Health.MinIntervalSeconds > c.Health.MaxIntervalSeconds {
		return fmt.Errorf("health.min_interval_seconds must be <= max_interval_seconds")
	}
	if c.Health.DefaultIntervalSeconds < c.Health.MinIntervalSeconds ||
		c.Health.DefaultIntervalSeconds > c.Health.MaxIntervalSeconds {
		return fmt.Errorf("health.default_interval_seconds must be within min and max interval")
	}
	if c.UI.PathPrefix == "" || !strings.HasPrefix(c.UI.PathPrefix, "/") {
		return fmt.Errorf("ui.path_prefix must start with /")
	}
	return nil
}

func LoadEnvFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := stripComment(scanner.Text())
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "export ") && !strings.Contains(line, "=") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid env line: %s", line)
		}
		key := strings.TrimSpace(parts[0])
		value := cleanScalar(parts[1])
		value = os.ExpandEnv(value)
		if key == "" {
			return fmt.Errorf("env key cannot be empty")
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func readSimpleYAML(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	values := make(map[string]string)
	var section, listKey string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		raw := scanner.Text()
		line := stripComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}
		trimmed := strings.TrimSpace(line)
		isTopLevel := len(line) == len(strings.TrimLeft(line, " \t"))
		if isTopLevel && strings.HasSuffix(trimmed, ":") && !strings.HasPrefix(trimmed, "- ") {
			section = strings.TrimSuffix(trimmed, ":")
			listKey = ""
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			if listKey == "" {
				return nil, fmt.Errorf("list item without key: %s", raw)
			}
			item := cleanScalar(strings.TrimPrefix(trimmed, "- "))
			if values[listKey] == "" {
				values[listKey] = item
			} else {
				values[listKey] += "," + item
			}
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid config line: %s", raw)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		fullKey := key
		if section != "" {
			fullKey = section + "." + key
		}
		if value == "" {
			listKey = fullKey
			values[listKey] = ""
			continue
		}
		listKey = ""
		values[fullKey] = cleanScalar(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func stripComment(line string) string {
	inQuote := false
	for i, r := range line {
		if r == '"' {
			inQuote = !inQuote
			continue
		}
		if r == '#' && !inQuote {
			return line[:i]
		}
	}
	return line
}

func cleanScalar(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	return os.ExpandEnv(value)
}

func applyValues(c *Config, values map[string]string) {
	c.Server.Host = getString(values, "server.host", c.Server.Host)
	c.Server.Port = getInt(values, "server.port", c.Server.Port)
	c.Server.RunMode = getString(values, "server.run_mode", c.Server.RunMode)
	c.Service.Code = getString(values, "service.code", c.Service.Code)
	c.Service.Name = getString(values, "service.name", c.Service.Name)
	c.Service.Version = getString(values, "service.version", c.Service.Version)
	c.Postgres.DSN = getString(values, "postgres.dsn", c.Postgres.DSN)
	c.Postgres.MaxOpenConns = getInt(values, "postgres.max_open_conns", c.Postgres.MaxOpenConns)
	c.Postgres.MaxIdleConns = getInt(values, "postgres.max_idle_conns", c.Postgres.MaxIdleConns)
	c.Postgres.ConnMaxLifetimeSeconds = getInt(values, "postgres.conn_max_lifetime_seconds", c.Postgres.ConnMaxLifetimeSeconds)
	c.Redis.Addr = getString(values, "redis.addr", c.Redis.Addr)
	c.Redis.Username = getString(values, "redis.username", c.Redis.Username)
	c.Redis.Password = getString(values, "redis.password", c.Redis.Password)
	c.Redis.DB = getInt(values, "redis.db", c.Redis.DB)
	c.Redis.DialTimeout = getDuration(values, "redis.dial_timeout", c.Redis.DialTimeout)
	c.Redis.ReadTimeout = getDuration(values, "redis.read_timeout", c.Redis.ReadTimeout)
	c.Redis.WriteTimeout = getDuration(values, "redis.write_timeout", c.Redis.WriteTimeout)
	c.Redis.PoolSize = getInt(values, "redis.pool_size", c.Redis.PoolSize)
	c.JWT.Issuer = getString(values, "jwt.issuer", c.JWT.Issuer)
	c.JWT.AccessExpireMinutes = getInt(values, "jwt.access_expire_minutes", c.JWT.AccessExpireMinutes)
	c.JWT.RefreshExpireHours = getInt(values, "jwt.refresh_expire_hours", c.JWT.RefreshExpireHours)
	c.JWT.AutoRefreshBeforeMinutes = getInt(values, "jwt.auto_refresh_before_minutes", c.JWT.AutoRefreshBeforeMinutes)
	c.JWT.PrivateKeyPath = getString(values, "jwt.private_key_path", c.JWT.PrivateKeyPath)
	c.JWT.PublicKeyPath = getString(values, "jwt.public_key_path", c.JWT.PublicKeyPath)
	c.JWT.RefreshRotate = getBool(values, "jwt.refresh_rotate", c.JWT.RefreshRotate)
	c.OIDC.Enable = getBool(values, "oidc.enable", c.OIDC.Enable)
	c.OIDC.Issuer = getString(values, "oidc.issuer", c.OIDC.Issuer)
	c.OIDC.AuthorizationCodeExpireMinutes = getInt(values, "oidc.authorization_code_expire_minutes", c.OIDC.AuthorizationCodeExpireMinutes)
	c.OIDC.AccessTokenExpireMinutes = getInt(values, "oidc.access_token_expire_minutes", c.OIDC.AccessTokenExpireMinutes)
	c.OIDC.RefreshTokenExpireHours = getInt(values, "oidc.refresh_token_expire_hours", c.OIDC.RefreshTokenExpireHours)
	c.Limit.Enable = getBool(values, "limit.enable", c.Limit.Enable)
	c.Limit.DefaultCapacity = getInt(values, "limit.default_capacity", c.Limit.DefaultCapacity)
	c.Limit.DefaultRatePerSecond = getInt(values, "limit.default_rate_per_second", c.Limit.DefaultRatePerSecond)
	c.Limit.Dimensions = getStringSlice(values, "limit.dimensions", c.Limit.Dimensions)
	c.Limit.LocalFallbackCapacity = getInt(values, "limit.local_fallback_capacity", c.Limit.LocalFallbackCapacity)
	c.Limit.LocalFallbackRatePerSecond = getInt(values, "limit.local_fallback_rate_per_second", c.Limit.LocalFallbackRatePerSecond)
	c.Security.AuthFailMaxCount = getInt(values, "security.auth_fail_max_count", c.Security.AuthFailMaxCount)
	c.Security.AuthFailWindowMinutes = getInt(values, "security.auth_fail_window_minutes", c.Security.AuthFailWindowMinutes)
	c.Security.LockMinutes = getInt(values, "security.lock_minutes", c.Security.LockMinutes)
	c.Security.M2MTimestampSkewSeconds = getInt(values, "security.m2m_timestamp_skew_seconds", c.Security.M2MTimestampSkewSeconds)
	c.Security.PasswordBcryptCost = getInt(values, "security.password_bcrypt_cost", c.Security.PasswordBcryptCost)
	c.Health.DefaultPath = getString(values, "health.default_path", c.Health.DefaultPath)
	c.Health.DefaultIntervalSeconds = getInt(values, "health.default_interval_seconds", c.Health.DefaultIntervalSeconds)
	c.Health.MinIntervalSeconds = getInt(values, "health.min_interval_seconds", c.Health.MinIntervalSeconds)
	c.Health.MaxIntervalSeconds = getInt(values, "health.max_interval_seconds", c.Health.MaxIntervalSeconds)
	c.Health.UnhealthyThreshold = getInt(values, "health.unhealthy_threshold", c.Health.UnhealthyThreshold)
	c.UI.Enable = getBool(values, "ui.enable", c.UI.Enable)
	c.UI.PathPrefix = getString(values, "ui.path_prefix", c.UI.PathPrefix)
}

func getString(values map[string]string, key, fallback string) string {
	if value, ok := values[key]; ok {
		return value
	}
	return fallback
}

func getInt(values map[string]string, key string, fallback int) int {
	if value, ok := values[key]; ok {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return fallback
}

func getBool(values map[string]string, key string, fallback bool) bool {
	if value, ok := values[key]; ok {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return fallback
}

func getDuration(values map[string]string, key string, fallback time.Duration) time.Duration {
	if value, ok := values[key]; ok {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	return fallback
}

func getStringSlice(values map[string]string, key string, fallback []string) []string {
	value, ok := values[key]
	if !ok || value == "" {
		return fallback
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		return fallback
	}
	return result
}
