package config

import (
	"devctl/pkg/home"
	"fmt"
	"path/filepath"

	"github.com/caarlos0/env/v11"
	"github.com/spf13/pflag"
)

func Init() *Config {
	cfg := loadDefaults()
	cfg = loadFromEnv(cfg)
	cfg = loadFromFile(cfg)
	return cfg
}

func loadDefaults() *Config {
	return &Config{
		Debug:     false,
		DataDir:   filepath.Join(home.Dir(), ".devctl"),
		ConfigDir: filepath.Join(home.Dir(), ".config", "devctl"),
	}
}

func loadFromEnv(base *Config) *Config {
	envCfg, err := env.ParseAs[Config]()
	if err != nil {
		fmt.Printf("Failed to parse config from env: %v", err)
	}

	base.Merge(&envCfg)
	return base
}

func loadFromFile(base *Config) *Config {
	fileCfg, err := LoadFromFile(base.ConfigDir)
	if err != nil {
		return base
	}
	if fileCfg != nil {
		base.Merge(fileCfg)
	}
	return base
}

func (cfg *Config) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&cfg.Debug, "debug", cfg.Debug, "enable verbose output")
}
