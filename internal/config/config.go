package config

import (
	"devctl/pkg/home"
	"devctl/pkg/pkgmgr"
	"fmt"
	"path/filepath"

	"github.com/caarlos0/env/v11"
	"github.com/spf13/pflag"
)

const (
	AppName = "devctl"
)

// Config holds the configuration for devctl.
type Config struct {
	Debug     bool   `json:"-" env:"DEVCTL_DEBUG"`
	ConfigDir string `json:"-" env:"DEVCTL_CONFIG_DIR"`

	DataDir         string                                      `json:"dataDir,omitempty"`
	PackageManagers map[pkgmgr.ManagerType]PackageManagerConfig `json:"packageManagers,omitempty"`
	Packages        []PackageConfig                             `json:"packages,omitempty"`
}

type PackageConfig struct {
	Name        string             `json:"name,omitempty"`
	Version     string             `json:"version,omitempty"`
	InstalledBy pkgmgr.ManagerType `json:"installedBy,omitempty"`
}

type PackageManagerConfig struct {
	Version        string `json:"version,omitempty"`
	ExecutablePath string `json:"executablePath,omitempty"`
}

func (cfg *Config) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&cfg.Debug, "debug", cfg.Debug, "enable verbose output")
}

func Init() *Config {
	cfg := loadDefaults()

	envConfig := loadFromEnv()
	if envConfig == nil {
		cfg.merge(envConfig)
	}

	fileConfig := loadFromFile(cfg.ConfigDir)
	if fileConfig == nil {
		cfg.merge(fileConfig)
	}

	return cfg
}

func MergePackages(existing, newPkgs []PackageConfig) []PackageConfig {
	pkgMap := make(map[string]PackageConfig)

	for _, pkg := range existing {
		pkgMap[pkg.Name] = pkg
	}

	for _, pkg := range newPkgs {
		pkgMap[pkg.Name] = pkg
	}

	result := make([]PackageConfig, 0, len(pkgMap))
	for _, pkg := range pkgMap {
		result = append(result, pkg)
	}

	return result
}

func loadDefaults() *Config {
	return &Config{
		Debug:     false,
		DataDir:   filepath.Join(home.Dir(), ".devctl"),
		ConfigDir: filepath.Join(home.Dir(), ".config", "devctl"),
	}
}

func loadFromEnv() *Config {
	envCfg, err := env.ParseAs[Config]()
	if err != nil {
		fmt.Printf("Failed to parse config from env: %v", err)
	}
	return &envCfg
}

func loadFromFile(configDir string) *Config {
	fileCfg, err := LoadFromFile(configDir)
	if err != nil {
		return fileCfg
	}
	return fileCfg
}

// Merge merges another config into this one.
// Non-zero values from other override values in this config.
func (cfg *Config) merge(other *Config) {
	if other == nil {
		return
	}

	if other.Debug {
		cfg.Debug = other.Debug
	}
	if other.DataDir != "" {
		cfg.DataDir = other.DataDir
	}
	if other.ConfigDir != "" {
		cfg.ConfigDir = other.ConfigDir
	}
	if other.PackageManagers != nil {
		if cfg.PackageManagers == nil {
			cfg.PackageManagers = make(map[pkgmgr.ManagerType]PackageManagerConfig)
		}
		for k, v := range other.PackageManagers {
			cfg.PackageManagers[k] = v
		}
	}
	if other.Packages != nil {
		cfg.Packages = other.Packages
	}
}
