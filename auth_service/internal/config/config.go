package config

import (
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Port int    `env:"PORT" envDefault:"8080"`
	Host string `env:"HOST" envDefault:"localhost"`
	// Database configuration
	Database DatabaseConfig
	// JWT configuration
	JWT   JWTConfig
	Debug bool `env:"DEBUG" envDefault:"false"`
	UserIPChangedWebhookUrl string `env:"USER_IP_CHANGED_WEBHOOK_URL" envDefault:""`
}

type DatabaseConfig struct {
	Host     string `env:"DB_HOST" envDefault:"localhost"`
	Port     int    `env:"DB_PORT" envDefault:"5432"`
	User     string `env:"DB_USER" envDefault:"user"`
	Password string `env:"DB_PASSWORD" envDefault:"password"`
	Name     string `env:"DB_NAME" envDefault:"dbname"`
	DBType   string `env:"DB_TYPE" envDefault:"postgres"`
	Prefix   string `env:"DB_PREFIX" envDefault:""`
}

// JWT configuration
type JWTConfig struct {
	AccessSecret  string `env:"JWT_ACCESS_SECRET" envDefault:"secret"`
	RefreshSecret string `env:"JWT_REFRESH_SECRET" envDefault:"refresh_secret"`
}

// Load loads the configuration from environment variables
func (c *Config) Load() error {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		return err
	}

	// Unmarshal environment variables into the Config struct
	err = envconfig.Process("", c)
	if err != nil {
		return err
	}

	return nil
}