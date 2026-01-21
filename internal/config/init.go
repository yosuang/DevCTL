package config

import (
	"devctl/pkg/home"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/pflag"
)

func Init() *Config {
	config := &Config{}
	config.Debug, _ = strconv.ParseBool(os.Getenv("DEVCTL_DEBUG"))
	config.DataDir = envOr("DEVCTL_HOME", filepath.Join(home.Dir(), defaultDataDir))
	config.ConfigDir = envOr("DEVCTL_CONFIG_DIR", filepath.Join(home.Dir(), ".config", "devctl"))

	return config
}

func envOr(name, defaultValue string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return defaultValue
}

func (cfg *Config) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&cfg.Debug, "debug", cfg.Debug, "enable verbose output")
}
