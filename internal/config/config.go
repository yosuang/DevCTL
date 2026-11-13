package config

import (
	"devctl/pkg/home"
	"fmt"
	"os"
	"path/filepath"

	"github.com/caarlos0/env/v11"
	"github.com/spf13/pflag"
)

const AppName = "devctl"

type Config struct {
	Debug     bool   `env:"DEVCTL_DEBUG"`
	ConfigDir string `env:"DEVCTL_CONFIG_DIR"`
}

func Init() *Config {
	cfg := &Config{}

	if err := env.Parse(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to parse env vars: %v\n", err)
	}

	if cfg.ConfigDir == "" {
		cfg.ConfigDir = defaultConfigDir()
	}

	return cfg
}

func (cfg *Config) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&cfg.Debug, "debug", cfg.Debug, "enable verbose output")
}

func (cfg *Config) LogDir() string {
	return filepath.Join(cfg.ConfigDir, "logs")
}

func defaultConfigDir() string {
	return filepath.Join(home.Dir(), "."+AppName)
}
