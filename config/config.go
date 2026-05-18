package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/viper"
	"github.com/subosito/gotenv"
)

const EnvConfigPath = "AUTH_LIMIT_CONFIG"

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Service  ServiceConfig  `mapstructure:"service"`
	Postgres PostgresConfig `mapstructure:"postgres"`
	Redis    RedisConfig    `mapstructure:"redis"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	OIDC     OIDCConfig     `mapstructure:"oidc"`
	Limit    LimitConfig    `mapstructure:"limit"`
	Security SecurityConfig `mapstructure:"security"`
	Health   HealthConfig   `mapstructure:"health"`
	UI       UIConfig       `mapstructure:"ui"`
}

type ServerConfig struct {
	Host    string `mapstructure:"host"`
	Port    int    `mapstructure:"port"`
	RunMode string `mapstructure:"run_mode"`
}

type ServiceConfig struct {
	Code    string `mapstructure:"code"`
	Name    string `mapstructure:"name"`
	Version string `mapstructure:"version"`
}

type PostgresConfig struct {
	DSN                    string `mapstructure:"dsn"`
	MaxOpenConns           int    `mapstructure:"max_open_conns"`
	MaxIdleConns           int    `mapstructure:"max_idle_conns"`
	ConnMaxLifetimeSeconds int    `mapstructure:"conn_max_lifetime_seconds"`
}

type RedisConfig struct {
	Addr         string        `mapstructure:"addr"`
	Username     string        `mapstructure:"username"`
	Password     string        `mapstructure:"password"`
	DB           int           `mapstructure:"db"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	PoolSize     int           `mapstructure:"pool_size"`
}

type JWTConfig struct {
	Issuer                   string `mapstructure:"issuer"`
	AccessExpireMinutes      int    `mapstructure:"access_expire_minutes"`
	RefreshExpireHours       int    `mapstructure:"refresh_expire_hours"`
	AutoRefreshBeforeMinutes int    `mapstructure:"auto_refresh_before_minutes"`
	PrivateKeyPath           string `mapstructure:"private_key_path"`
	PublicKeyPath            string `mapstructure:"public_key_path"`
	RefreshRotate            bool   `mapstructure:"refresh_rotate"`
}

type OIDCConfig struct {
	Enable                         bool   `mapstructure:"enable"`
	Issuer                         string `mapstructure:"issuer"`
	AuthorizationCodeExpireMinutes int    `mapstructure:"authorization_code_expire_minutes"`
	AccessTokenExpireMinutes       int    `mapstructure:"access_token_expire_minutes"`
	RefreshTokenExpireHours        int    `mapstructure:"refresh_token_expire_hours"`
}

type LimitConfig struct {
	Enable                     bool     `mapstructure:"enable"`
	DefaultCapacity            int      `mapstructure:"default_capacity"`
	DefaultRatePerSecond       int      `mapstructure:"default_rate_per_second"`
	Dimensions                 []string `mapstructure:"dimensions"`
	LocalFallbackCapacity      int      `mapstructure:"local_fallback_capacity"`
	LocalFallbackRatePerSecond int      `mapstructure:"local_fallback_rate_per_second"`
}

type SecurityConfig struct {
	AuthFailMaxCount        int `mapstructure:"auth_fail_max_count"`
	AuthFailWindowMinutes   int `mapstructure:"auth_fail_window_minutes"`
	LockMinutes             int `mapstructure:"lock_minutes"`
	M2MTimestampSkewSeconds int `mapstructure:"m2m_timestamp_skew_seconds"`
	PasswordBcryptCost      int `mapstructure:"password_bcrypt_cost"`
}

type HealthConfig struct {
	DefaultPath            string `mapstructure:"default_path"`
	DefaultIntervalSeconds int    `mapstructure:"default_interval_seconds"`
	MinIntervalSeconds     int    `mapstructure:"min_interval_seconds"`
	MaxIntervalSeconds     int    `mapstructure:"max_interval_seconds"`
	UnhealthyThreshold     int    `mapstructure:"unhealthy_threshold"`
}

type UIConfig struct {
	Enable     bool   `mapstructure:"enable"`
	PathPrefix string `mapstructure:"path_prefix"`
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
	loader := viper.New()
	loader.SetConfigFile(path)
	loader.SetEnvPrefix("AUTH_LIMIT")
	loader.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	loader.AutomaticEnv()
	if err := loader.ReadInConfig(); err != nil {
		return nil, err
	}
	expandLoaderSettings(loader)
	if err := loader.Unmarshal(cfg); err != nil {
		return nil, err
	}
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
	return gotenv.Load(path)
}

func expandLoaderSettings(loader *viper.Viper) {
	for _, key := range loader.AllKeys() {
		switch value := loader.Get(key).(type) {
		case string:
			loader.Set(key, os.ExpandEnv(value))
		case []any:
			loader.Set(key, expandSlice(value))
		case []string:
			expanded := make([]string, 0, len(value))
			for _, item := range value {
				expanded = append(expanded, os.ExpandEnv(item))
			}
			loader.Set(key, expanded)
		}
	}
}

func expandSlice(values []any) []any {
	for i, value := range values {
		switch typed := value.(type) {
		case []any:
			values[i] = expandSlice(typed)
		case string:
			values[i] = os.ExpandEnv(typed)
		}
	}
	return values
}
