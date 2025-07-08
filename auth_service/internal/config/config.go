package config

import (
	"fmt"
	"github.com/kelseyhightower/envconfig"
	"encoding/json"
)

type Config struct {
	Port                     int    `envconfig:"PORT" default:"8080"`
	Host                     string `envconfig:"HOST" default:"localhost"`
	Debug                    bool   `envconfig:"DEBUG" default:"false"`
	UserIPChangedWebhookUrl  string `envconfig:"USER_IP_CHANGED_WEBHOOK_URL" default:""`
	Database                 DatabaseConfig
	JWT                      JWTConfig
}

type DatabaseConfig struct {
	Host     string `envconfig:"DB_HOST" default:"127.0.0.1"`
	Port     int    `envconfig:"DB_PORT" default:"5432"`
	User     string `envconfig:"DB_USER" default:"app"`
	Password string `envconfig:"DB_PASSWORD" default:"app"`
	Name     string `envconfig:"DB_NAME" default:"app"`
	DBType   string `envconfig:"DB_TYPE" default:"postgres"`
	Prefix   string `envconfig:"DB_PREFIX" default:""`
}

type JWTConfig struct {
	AccessSecret  string `envconfig:"JWT_ACCESS_SECRET" default:"secret"`
	RefreshSecret string `envconfig:"JWT_REFRESH_SECRET" default:"refresh_secret"`
}

func (c *Config) Load() error {
	if err := envconfig.Process("", c); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	return nil
}

func New() (*Config, error) {
	var cfg Config
	if err := cfg.Load(); err != nil {
		return nil, err
	}

	return &cfg, nil
}
