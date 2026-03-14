package config

import (
	"devctl/pkg/home"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/caarlos0/env/v11"
	"github.com/spf13/pflag"
)

const (
	AppName        = "devctl"
	configFileName = "settings.json"
)

// Config holds the application configuration.
// Priority: CLI Flags > Environment Variables > Config File > Defaults
type Config struct {
	Debug     bool   `json:"-" env:"DEVCTL_DEBUG"`
	ConfigDir string `json:"-" env:"DEVCTL_CONFIG_DIR"`
}

// Init creates and returns a new Config with resolved defaults and env vars.
// The initialization follows the priority chain: Defaults → Env Vars → Config File.
// CLI Flags are applied later by cobra after Init() returns and AddFlags() registers them.
func Init() *Config {
	cfg := &Config{}

	// 1. Parse environment variables (fills fields from DEVCTL_* env vars)
	if err := env.Parse(cfg); err != nil {
		// env parse errors are non-fatal; use zero values
		fmt.Fprintf(os.Stderr, "warning: failed to parse env vars: %v\n", err)
	}

	// 2. Resolve directory defaults (XDG-style) for fields not set by env
	if cfg.ConfigDir == "" {
		cfg.ConfigDir = defaultConfigDir()
	}

	// 3. Load config file (lower priority than env vars — only fill empty fields)
	cfg.loadConfigFile()

	return cfg
}

// AddFlags registers persistent CLI flags that override all other sources.
// These flags are bound directly to Config fields, so cobra will write
// parsed flag values into the struct — giving flags the highest priority.
func (cfg *Config) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&cfg.Debug, "debug", cfg.Debug, "enable verbose output")
}

// ConfigFile returns the full path to the config file.
func (cfg *Config) ConfigFile() string {
	return filepath.Join(cfg.ConfigDir, configFileName)
}

// LogDir returns the full path to the log directory.
func (cfg *Config) LogDir() string {
	return filepath.Join(cfg.ConfigDir, "logs")
}

// loadConfigFile loads settings from the JSON config file into Config.
// File values have LOWER priority than env vars — only fill empty fields.
func (cfg *Config) loadConfigFile() {
	fc, err := readConfigFile(cfg.ConfigFile())
	if err != nil || fc == nil {
		return
	}

	// Only apply file values to fields not already set by env.
	// (Struct zero values indicate "not set".)
}

// SaveConfig persists configuration changes using read-modify-write pattern.
// It reads the current file from disk, applies changes from src, and writes back.
// This ensures that flag/env overrides on OTHER keys are never touched.
func SaveConfig(cfg *Config, configFile string) error {
	existing, err := readConfigFile(configFile)
	if err != nil {
		return fmt.Errorf("reading existing config: %w", err)
	}
	if existing == nil {
		existing = &Config{}
	}

	mergeConfig(existing, cfg)

	return writeConfigFile(existing, configFile)
}

// mergeConfig applies non-zero fields from src into dst.
// Only fields that are explicitly set (non-zero) in src will overwrite dst.
func mergeConfig(_ *Config, src *Config) {
	if src == nil {
		return
	}
}

// readConfigFile reads the current config file from disk.
// Returns nil if the file doesn't exist (not an error).
func readConfigFile(configFile string) (*Config, error) {
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

// writeConfigFile writes the config to disk as formatted JSON.
func writeConfigFile(cfg *Config, configFile string) error {
	if err := os.MkdirAll(filepath.Dir(configFile), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func defaultConfigDir() string {
	return filepath.Join(home.Dir(), "."+AppName)
}
